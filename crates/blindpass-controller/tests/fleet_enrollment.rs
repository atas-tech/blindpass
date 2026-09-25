// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::{
    app::build_app,
    config::Config,
    store::{OperationApprovalDraft, OperationCreateOutcome, OperationRecord, Store},
};
use blindpass_core::canon::parse_json;
use blindpass_core::custody::{RecipientKeyPair, sha256};
use blindpass_core::fleet::{
    ApplicationAck, DocumentKind, Grant, NodeKeyRotation, SignedEnvelope, TimeReply,
    enrollment_proof_message, node_event_message, node_key_fingerprint,
    node_session_challenge_message,
};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use serde_json::{Value, json};
use sqlx::{PgPool, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ORIGIN: &str = "http://127.0.0.1:5175";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-fleet-enrollment-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create enrollment test directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> HttpResponse {
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(&body);

    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect local fleet HTTP server");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send fleet HTTP request");
    stream.flush().await.expect("flush fleet HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read fleet HTTP response");
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    let (header_text, body_text) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("HTTP response header separator missing: {response:?}"));
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("HTTP status code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = if body_text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body_text).expect("response body is JSON")
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn cookie_header(response: &HttpResponse, name: &str) -> String {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .find_map(|(_, value)| {
            let pair = value.split(';').next()?;
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name == name).then(|| format!("{name}={cookie_value}"))
        })
        .expect("expected response cookie")
}

async fn login_operator(
    address: std::net::SocketAddr,
    username: &str,
    password: &str,
) -> (String, String) {
    let response = request(
        address,
        "POST",
        "/api/v3/admin/session/login",
        &[
            ("content-type", "application/json"),
            ("origin", ORIGIN),
            ("cookie", "bp_csrf=fleet-login-pre-session"),
            ("x-csrf-token", "fleet-login-pre-session"),
        ],
        Some(&json!({"username":username,"password":password})),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body);
    (
        format!(
            "{}; {}",
            cookie_header(&response, "bp_session"),
            cookie_header(&response, "bp_csrf")
        ),
        response.body["csrf_token"]
            .as_str()
            .expect("login CSRF token")
            .to_owned(),
    )
}

fn token_hash(token: &str) -> String {
    sha256(token.as_bytes())
        .expect("SHA-256 enrollment token")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct NodeKeys {
    signing: Ed25519KeyPair,
    recipient: RecipientKeyPair,
}

impl NodeKeys {
    fn from_seed(seed: u8) -> Self {
        Self {
            signing: Ed25519KeyPair::from_seed(&[seed; 32]).unwrap(),
            recipient: RecipientKeyPair::from_private_key(&[seed.wrapping_add(1); 32]).unwrap(),
        }
    }

    fn fingerprint(&self) -> String {
        node_key_fingerprint(self.signing.public_key(), self.recipient.public_key()).unwrap()
    }

    fn submission(&self, token: &str) -> Value {
        let message = enrollment_proof_message(
            token,
            self.signing.public_key(),
            self.recipient.public_key(),
        )
        .unwrap();
        let signature = self.signing.sign(&message).unwrap();
        json!({
            "token": token,
            "signing_pub": base64_url_encode(self.signing.public_key()),
            "recipient_pub": base64_url_encode(self.recipient.public_key()),
            "proof": base64_url_encode(&signature),
            "protocol_version": "blindpass-node/1",
            "capabilities": {"protocol_version": "blindpass-node/1"},
            "host_facts": {"os": "linux", "architecture": "x86_64"}
        })
    }
}

async fn open_node_session(
    address: std::net::SocketAddr,
    node_id: &str,
    key_version: u64,
    keys: &NodeKeys,
) -> String {
    let capabilities = json!({"protocol_version":"blindpass-node/1"});
    let challenge = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id":node_id,
            "key_version":key_version,
            "protocol_version":"blindpass-node/1",
            "capabilities":capabilities
        })),
    )
    .await;
    assert_eq!(challenge.status, 200, "{}", challenge.body);
    assert_eq!(challenge.body["key_version"], key_version);
    let message = node_session_challenge_message(
        challenge.body["tenant_id"].as_str().unwrap(),
        node_id,
        "blindpass-node/1",
        challenge.body["nonce"].as_str().unwrap(),
        challenge.body["capabilities_hash"].as_str().unwrap(),
        key_version,
        challenge.body["issuer_epoch"].as_i64().unwrap() as u64,
        challenge.body["controller_time_ms"].as_i64().unwrap(),
        challenge.body["expires_at_ms"].as_i64().unwrap(),
    )
    .unwrap();
    let authenticated = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id":node_id,
            "key_version":key_version,
            "protocol_version":"blindpass-node/1",
            "capabilities":capabilities,
            "nonce":challenge.body["nonce"],
            "signature":base64_url_encode(&keys.signing.sign(&message).unwrap())
        })),
    )
    .await;
    assert_eq!(authenticated.status, 200, "{}", authenticated.body);
    format!("Bearer {}", authenticated.body["token"].as_str().unwrap())
}

fn signed_node_event(
    node_id: &str,
    idempotency_key: &str,
    kind: &str,
    body: Value,
    signing: &Ed25519KeyPair,
) -> Value {
    let body_value = parse_json(&body.to_string()).unwrap();
    let message = node_event_message(node_id, idempotency_key, kind, &body_value).unwrap();
    json!({"events":[{
        "idempotency_key":idempotency_key,
        "kind":kind,
        "body":body,
        "broker_signature":base64_url_encode(&signing.sign(&message).unwrap())
    }]})
}

#[tokio::test]
async fn enrollment_is_one_use_operator_approved_and_key_bound() {
    let directory = TestDirectory::new();
    let (database_url, pg_admin, pg_schema, backend_pool): (
        String,
        Option<PgPool>,
        Option<String>,
        Option<SqlitePool>,
    ) = if std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres") {
        let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
            .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
            .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let schema = format!("p03_enrollment_{}_{nonce}", std::process::id());
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&parent_url)
            .await
            .expect("connect PostgreSQL enrollment fixture");
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&pool)
            .await
            .expect("create isolated PostgreSQL enrollment schema");
        let separator = if parent_url.contains('?') { '&' } else { '?' };
        (
            format!("{parent_url}{separator}options=-c%20search_path%3D{schema}"),
            Some(pool),
            Some(schema),
            None,
        )
    } else {
        assert!(
            matches!(
                std::env::var("P02_TEST_BACKEND").as_deref(),
                Ok("sqlite") | Err(_)
            ),
            "unknown P02_TEST_BACKEND"
        );
        let database_path = directory.file("controller.db");
        let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect SQLite enrollment fixture");
        (database_url, None, None, Some(pool))
    };

    for (name, value) in [
        ("database.url", database_url.clone()),
        ("root.secret", "R".repeat(32)),
        ("agent.secret", "A".repeat(32)),
        ("issuer.seed", "I".repeat(32)),
    ] {
        let path = directory.file(name);
        std::fs::write(&path, value).expect("write protected test configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test configuration");
    }
    let config = Config::from_variables([
        ("BLINDPASS_LISTEN", "127.0.0.1:0"),
        ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
        ("BLINDPASS_UI_BASE_URL", ORIGIN),
        (
            "BLINDPASS_DATABASE_URL_FILE",
            directory.file("database.url").to_str().unwrap(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE",
            directory.file("root.secret").to_str().unwrap(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            directory.file("agent.secret").to_str().unwrap(),
        ),
        (
            "BLINDPASS_ISSUER_KEY_FILE",
            directory.file("issuer.seed").to_str().unwrap(),
        ),
    ])
    .expect("valid enrollment controller config");
    let store = Store::connect(&database_url)
        .await
        .expect("connect enrollment controller database");
    let pg_test_pool = if pg_schema.is_some() {
        Some(
            PgPoolOptions::new()
                .max_connections(2)
                .connect(&database_url)
                .await
                .expect("connect PostgreSQL enrollment test schema"),
        )
    } else {
        None
    };
    if let Some(pool) = pg_test_pool.as_ref() {
        // Recreate the version-9 PostgreSQL column width so this acceptance
        // run proves the upgrade path as well as the fresh-schema path.
        sqlx::query("ALTER TABLE controller_meta ALTER COLUMN issuer_epoch TYPE INTEGER")
            .execute(pool)
            .await
            .expect("restore version-9 issuer epoch type");
        sqlx::query("UPDATE controller_meta SET schema_version = 9 WHERE id = 1")
            .execute(pool)
            .await
            .expect("restore version-9 schema marker");
        drop(store);
        let store = Store::connect(&database_url)
            .await
            .expect("migrate version-9 PostgreSQL fleet schema");
        let epoch_type: String = sqlx::query_scalar(
            "SELECT data_type FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = 'controller_meta'
               AND column_name = 'issuer_epoch'",
        )
        .fetch_one(pool)
        .await
        .expect("read migrated issuer epoch type");
        assert_eq!(epoch_type, "bigint");
        assert_eq!(store.issuer_epoch().await.unwrap(), 1);
        store.close().await;
    }
    let store = Store::connect(&database_url)
        .await
        .expect("connect migrated enrollment controller database");
    let bootstrap_token = "fleet-enrollment-bootstrap-token-with-more-than-32-bytes";
    assert!(
        store
            .issue_bootstrap_token(&token_hash(bootstrap_token), 900)
            .await
            .expect("issue bootstrap capability")
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local enrollment HTTP listener");
    let address = listener.local_addr().expect("resolve HTTP listener");
    let app_store = store.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, build_app(config, Some(app_store)))
            .await
            .unwrap();
    });

    let bootstrap = request(
        address,
        "POST",
        "/api/v3/admin/bootstrap",
        &[
            ("content-type", "application/json"),
            ("origin", ORIGIN),
            ("x-blindpass-bootstrap-token", bootstrap_token),
        ],
        Some(&json!({
            "username": "fleet-admin",
            "display_name": "Fleet Admin",
            "password": "fleet-admin-test-password-long"
        })),
    )
    .await;
    assert_eq!(bootstrap.status, 201);
    let csrf = bootstrap.body["csrf_token"].as_str().unwrap();
    let admin_cookies = format!(
        "{}; {}",
        cookie_header(&bootstrap, "bp_session"),
        cookie_header(&bootstrap, "bp_csrf")
    );
    let write_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
    ];

    let secondary_operator = request(
        address,
        "POST",
        "/api/v3/admin/operators",
        &write_headers,
        Some(&json!({
            "username":"fleet-reviewer",
            "display_name":"Fleet Reviewer",
            "role":"admin",
            "password":"fleet-reviewer-test-password-long"
        })),
    )
    .await;
    assert_eq!(
        secondary_operator.status, 201,
        "{}",
        secondary_operator.body
    );
    let (secondary_cookies, secondary_csrf) = login_operator(
        address,
        "fleet-reviewer",
        "fleet-reviewer-test-password-long",
    )
    .await;

    let unauthenticated_workload_edit = request(
        address,
        "POST",
        "/api/v3/workloads",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id":"node-forged",
            "name":"worker-edit",
            "unit":"blindpass-test.service",
            "account":"root",
            "consumption_mode":"file",
            "local_ceiling_seconds":3600
        })),
    )
    .await;
    assert_eq!(unauthenticated_workload_edit.status, 401);
    let unauthenticated_policy_edit = request(
        address,
        "PUT",
        "/api/v3/policies",
        &[("content-type", "application/json")],
        Some(&json!({"expected_version":1,"rules":[]})),
    )
    .await;
    assert_eq!(unauthenticated_policy_edit.status, 401);

    let unauthenticated = request(
        address,
        "POST",
        "/api/v3/enrollments",
        &[("origin", ORIGIN), ("content-type", "application/json")],
        Some(&json!({"name":"unauthenticated"})),
    )
    .await;
    assert_eq!(unauthenticated.status, 401);

    let first = request(
        address,
        "POST",
        "/api/v3/enrollments",
        &write_headers,
        Some(&json!({"name":"fleet-node-a"})),
    )
    .await;
    assert_eq!(first.status, 201, "{}", first.body);
    let first_id = first.body["id"].as_str().unwrap().to_owned();
    let first_node_id = first.body["node_id"].as_str().unwrap().to_owned();
    let first_token = first.body["token"].as_str().unwrap().to_owned();
    let first_keys = NodeKeys::from_seed(11);
    let first_submission = first_keys.submission(&first_token);

    let second_keys = NodeKeys::from_seed(31);
    let mut substituted = first_keys.submission(&first_token);
    substituted["signing_pub"] = json!(base64_url_encode(second_keys.signing.public_key()));
    let substituted_response = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&substituted),
    )
    .await;
    assert_eq!(substituted_response.status, 400);

    let submitted = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&first_submission),
    )
    .await;
    assert_eq!(submitted.status, 201, "{}", submitted.body);
    assert_eq!(submitted.body["node_id"], first_node_id);
    assert_eq!(submitted.body["fingerprint"], first_keys.fingerprint());
    let replay = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&first_submission),
    )
    .await;
    assert_eq!(replay.status, 410);

    let detail = request(
        address,
        "GET",
        &format!("/api/v3/enrollments/{first_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(detail.status, 200);
    assert_eq!(detail.body["status"], "submitted");
    let version = detail.body["version"].as_i64().unwrap();
    match &backend_pool {
        Some(pool) => {
            sqlx::query("UPDATE enrollment_requests SET expires_at = 1 WHERE id = ?")
                .bind(&first_id)
                .execute(pool)
                .await
                .expect("expire the already submitted SQLite token");
        }
        None => {
            sqlx::query("UPDATE enrollment_requests SET expires_at = 1 WHERE id = $1")
                .bind(&first_id)
                .execute(pg_test_pool.as_ref().unwrap())
                .await
                .expect("expire the already submitted PostgreSQL token");
        }
    }
    let wrong_fingerprint = request(
        address,
        "POST",
        &format!("/api/v3/enrollments/{first_id}/approve"),
        &write_headers,
        Some(&json!({
            "expected_fingerprint": "0".repeat(64),
            "expected_version": version
        })),
    )
    .await;
    assert_eq!(wrong_fingerprint.status, 409);
    let approved = request(
        address,
        "POST",
        &format!("/api/v3/enrollments/{first_id}/approve"),
        &write_headers,
        Some(&json!({
            "expected_fingerprint": first_keys.fingerprint(),
            "expected_version": version
        })),
    )
    .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert_eq!(approved.body["id"], first_node_id);
    assert_eq!(approved.body["name"], "fleet-node-a");
    assert_eq!(approved.body["status"], "offline");
    assert_eq!(
        approved.body["signing_fingerprint"],
        sha256(first_keys.signing.public_key())
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    let unsupported = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id": first_node_id.clone(),
            "key_version": 1,
            "protocol_version": "blindpass-node/2",
            "capabilities": {"protocol_version": "blindpass-node/2"}
        })),
    )
    .await;
    assert_eq!(unsupported.status, 426);

    let issuer = Ed25519KeyPair::from_seed(&[b'I'; 32]).unwrap();
    let issuer_key_id = format!("ed25519-{}", base64_url_encode(issuer.public_key()));
    let now_ms = store.database_now_ms().await.unwrap();
    let inbox_envelopes = (1..=2_u64)
        .map(|seq| {
            let body = TimeReply {
                node_id: first_node_id.clone(),
                challenge: format!("poll-sequence-{seq}"),
                controller_time_ms: u64::try_from(now_ms).unwrap(),
                issuer_epoch: 1,
            }
            .to_value()
            .unwrap();
            SignedEnvelope::sign(DocumentKind::TimeReply, body, &issuer_key_id, 1, &issuer)
                .unwrap()
                .to_json()
                .unwrap()
        })
        .collect::<Vec<_>>();
    match (&backend_pool, &pg_test_pool) {
        (Some(pool), _) => {
            for (index, envelope) in inbox_envelopes.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO node_inbox (node_id, seq, envelope_json, created_at) VALUES (?, ?, ?, ?)",
                )
                .bind(&first_node_id)
                .bind(i64::try_from(index + 1).unwrap())
                .bind(std::str::from_utf8(envelope).unwrap())
                .bind(now_ms)
                .execute(pool)
                .await
                .unwrap();
            }
        }
        (_, Some(pool)) => {
            for (index, envelope) in inbox_envelopes.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO node_inbox (node_id, seq, envelope_json, created_at) VALUES ($1, $2, $3, $4)",
                )
                .bind(&first_node_id)
                .bind(i64::try_from(index + 1).unwrap())
                .bind(std::str::from_utf8(envelope).unwrap())
                .bind(now_ms)
                .execute(pool)
                .await
                .unwrap();
            }
        }
        _ => unreachable!(),
    }

    let channel_capabilities = json!({"protocol_version":"blindpass-node/1"});
    let challenge_response = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id": first_node_id.clone(),
            "key_version": 1,
            "protocol_version": "blindpass-node/1",
            "capabilities": channel_capabilities.clone()
        })),
    )
    .await;
    assert_eq!(
        challenge_response.status, 200,
        "{}",
        challenge_response.body
    );
    let nonce = challenge_response.body["nonce"].as_str().unwrap();
    let tenant_id = challenge_response.body["tenant_id"].as_str().unwrap();
    let capabilities_hash = challenge_response.body["capabilities_hash"]
        .as_str()
        .unwrap();
    let controller_time_ms = challenge_response.body["controller_time_ms"]
        .as_i64()
        .unwrap();
    let expires_at_ms = challenge_response.body["expires_at_ms"].as_i64().unwrap();
    let message = node_session_challenge_message(
        tenant_id,
        &first_node_id,
        "blindpass-node/1",
        nonce,
        capabilities_hash,
        1,
        1,
        controller_time_ms,
        expires_at_ms,
    )
    .unwrap();
    let signature = base64_url_encode(&first_keys.signing.sign(&message).unwrap());
    let authenticate_body = json!({
        "node_id": first_node_id.clone(),
        "key_version": 1,
        "protocol_version": "blindpass-node/1",
        "capabilities": channel_capabilities.clone(),
        "nonce": nonce,
        "signature": signature
    });
    let authenticated = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&authenticate_body),
    )
    .await;
    assert_eq!(authenticated.status, 200, "{}", authenticated.body);
    let node_token = authenticated.body["token"].as_str().unwrap().to_owned();
    let replay_challenge = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&authenticate_body),
    )
    .await;
    assert_eq!(replay_challenge.status, 401);

    let node_bearer = format!("Bearer {node_token}");
    let first_poll = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({
            "ack_seq":1,
            "health":{},
            "time_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        })),
    )
    .await;
    assert_eq!(first_poll.status, 200, "{}", first_poll.body);
    assert_eq!(first_poll.body["documents"][0]["seq"], 1);
    assert_eq!(first_poll.body["documents"][1]["seq"], 2);
    let time_envelope =
        SignedEnvelope::from_json(&first_poll.body["time_reply"].to_string()).unwrap();
    assert_eq!(time_envelope.kind(), DocumentKind::TimeReply);
    assert!(
        time_envelope
            .verify(issuer.public_key(), &issuer_key_id, 1)
            .unwrap()
    );
    let time_reply = blindpass_core::fleet::TimeReply::from_value(time_envelope.body()).unwrap();
    assert_eq!(time_reply.node_id, first_node_id);
    assert_eq!(
        time_reply.challenge,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert!(time_reply.controller_time_ms > 0);
    let acknowledged_poll = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":1,"health":{}})),
    )
    .await;
    assert_eq!(acknowledged_poll.status, 200, "{}", acknowledged_poll.body);
    assert_eq!(
        acknowledged_poll.body["documents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(acknowledged_poll.body["documents"][0]["seq"], 2);

    let event_body = json!({
        "action":"operation_result",
        "grant_id":"gr_dummy",
        "operation_id":"op_dummy",
        "observed_at_ms":1_800_000_000_000_i64,
        "status":"completed"
    });
    let event_value = parse_json(&event_body.to_string()).unwrap();
    let event_message = node_event_message(
        &first_node_id,
        "event-channel-idempotency-01",
        "audit",
        &event_value,
    )
    .unwrap();
    let event_signature = base64_url_encode(&first_keys.signing.sign(&event_message).unwrap());
    let event_input = json!({"events":[{
        "idempotency_key":"event-channel-idempotency-01",
        "kind":"audit",
        "body":event_body,
        "broker_signature":event_signature
    }]});
    let accepted_event = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&event_input),
    )
    .await;
    assert_eq!(accepted_event.status, 200, "{}", accepted_event.body);
    assert_eq!(accepted_event.body["accepted"], 1);
    let application_ack =
        SignedEnvelope::from_json(&accepted_event.body["ack"].to_string()).unwrap();
    assert_eq!(application_ack.kind(), DocumentKind::ApplicationAck);
    assert!(
        application_ack
            .verify(issuer.public_key(), &issuer_key_id, 1)
            .unwrap()
    );
    let application_ack_body = ApplicationAck::from_value(application_ack.body()).unwrap();
    assert_eq!(application_ack_body.node_id, first_node_id);
    assert_eq!(
        application_ack_body.event_keys,
        ["event-channel-idempotency-01"]
    );
    let duplicate_event = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&event_input),
    )
    .await;
    assert_eq!(duplicate_event.status, 200);
    assert_eq!(duplicate_event.body["duplicates"], 1);

    let policy_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("if-match", "\"1\""),
    ];
    let policy = request(
        address,
        "PUT",
        "/api/v3/policies",
        &policy_headers,
        Some(&json!({
            "expected_version": 1,
            "rules": [{
                "id": "approve-noop-file",
                "action": "noop.marker",
                "mode": "file",
                "decision": "pending_approval",
                "approval_required": true,
                "max_ttl_seconds": 120
            }]
        })),
    )
    .await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    assert_eq!(policy.body["version"], 2);

    let workload = request(
        address,
        "POST",
        "/api/v3/workloads",
        &write_headers,
        Some(&json!({
            "node_id": first_node_id,
            "name": "file-worker",
            "unit": "blindpass-test.service",
            "account": "blindpass-test",
            "consumption_mode": "file",
            "local_ceiling_seconds": 120
        })),
    )
    .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    let workload_id = workload.body["id"].as_str().unwrap().to_owned();
    assert_eq!(workload.body["registration_version"], 1);

    let workload_documents: Vec<String> = match (&backend_pool, &pg_test_pool) {
        (Some(pool), _) => sqlx::query_scalar(
            "SELECT envelope_json FROM node_inbox WHERE node_id = ? ORDER BY seq DESC LIMIT 2",
        )
        .bind(&first_node_id)
        .fetch_all(pool)
        .await
        .unwrap(),
        (_, Some(pool)) => sqlx::query_scalar(
            "SELECT envelope_json FROM node_inbox WHERE node_id = $1 ORDER BY seq DESC LIMIT 2",
        )
        .bind(&first_node_id)
        .fetch_all(pool)
        .await
        .unwrap(),
        _ => unreachable!(),
    };
    let inbox_kinds = workload_documents
        .iter()
        .map(|document| SignedEnvelope::from_json(document).unwrap().kind().as_str())
        .collect::<Vec<_>>();
    assert!(inbox_kinds.contains(&"policy_snapshot"));
    assert!(inbox_kinds.contains(&"registration"));

    let operation_now_ms = store.database_now_ms().await.unwrap();
    let operation_event_body = json!({
        "node_id": first_node_id,
        "workload_id": workload_id,
        "unit": "blindpass-test.service",
        "account": "blindpass-test",
        "invocation_id": "invocation-123",
        "action": "noop.marker",
        "mode": "file",
        "purpose": "integration marker",
        "resource_id": "marker-a",
        "ttl_seconds": 60,
        "observed_at_ms": operation_now_ms
    });
    let first_operation_event_key = "operation-event-key-0001";
    let first_operation_event = signed_node_event(
        &first_node_id,
        first_operation_event_key,
        "operation_request",
        operation_event_body.clone(),
        &first_keys.signing,
    );
    let first_operation_event_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&first_operation_event),
    )
    .await;
    assert_eq!(first_operation_event_response.status, 200);

    let first_operation_input = json!({
        "workload_id": workload_id,
        "action": "noop.marker",
        "mode": "file",
        "purpose": "integration marker",
        "resource_id": "marker-a",
        "invocation_id": "invocation-123",
        "ttl_seconds": 60,
        "broker_event_key": first_operation_event_key
    });

    for (index, (field, forged_value)) in [
        ("node_id", json!("node-forged")),
        ("workload_id", json!("workload-forged")),
        ("unit", json!("forged.service")),
        ("account", json!("uid:0")),
        ("invocation_id", json!("invocation-forged")),
    ]
    .into_iter()
    .enumerate()
    {
        let event_key = format!("operation-event-forged-{index:02}");
        let mut forged_body = operation_event_body.clone();
        forged_body[field] = forged_value;
        let forged_event = signed_node_event(
            &first_node_id,
            &event_key,
            "operation_request",
            forged_body,
            &first_keys.signing,
        );
        let accepted_forged_event = request(
            address,
            "POST",
            "/api/v3/node/events",
            &[
                ("authorization", &node_bearer),
                ("content-type", "application/json"),
            ],
            Some(&forged_event),
        )
        .await;
        assert_eq!(accepted_forged_event.status, 200, "{field}");

        let mut forged_operation = first_operation_input.clone();
        forged_operation["broker_event_key"] = json!(event_key);
        let forged_headers = [
            ("origin", ORIGIN),
            ("cookie", admin_cookies.as_str()),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
            ("idempotency-key", "operation-forged-input-0001"),
        ];
        let rejected_forged_operation = request(
            address,
            "POST",
            "/api/v3/operations",
            &forged_headers,
            Some(&forged_operation),
        )
        .await;
        assert_eq!(
            rejected_forged_operation.status, 409,
            "forged {field}: {}",
            rejected_forged_operation.body
        );
        assert_eq!(
            rejected_forged_operation.body["error"], "broker_evidence_mismatch",
            "forged {field} must not authorize an operation"
        );
    }

    let first_operation_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-request-idem-0001"),
    ];
    let first_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &first_operation_headers,
        Some(&first_operation_input),
    )
    .await;
    assert_eq!(first_operation.status, 201, "{}", first_operation.body);
    assert_eq!(first_operation.body["status"], "awaiting_approval");

    let replayed_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &first_operation_headers,
        Some(&first_operation_input),
    )
    .await;
    assert_eq!(replayed_operation.status, 200);
    assert_eq!(replayed_operation.body["id"], first_operation.body["id"]);

    let second_operation_event_key = "operation-event-key-0002";
    let second_operation_event = signed_node_event(
        &first_node_id,
        second_operation_event_key,
        "operation_request",
        operation_event_body.clone(),
        &first_keys.signing,
    );
    let second_operation_event_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&second_operation_event),
    )
    .await;
    assert_eq!(second_operation_event_response.status, 200);
    let mut second_operation_input = first_operation_input.clone();
    second_operation_input["broker_event_key"] = json!(second_operation_event_key);
    let second_operation_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-request-idem-0002"),
    ];
    let second_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &second_operation_headers,
        Some(&second_operation_input),
    )
    .await;
    assert_eq!(second_operation.status, 201, "{}", second_operation.body);
    assert_eq!(
        second_operation.body["approval_id"],
        first_operation.body["approval_id"]
    );

    let unified_count = request(
        address,
        "GET",
        "/api/v3/approvals/count",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(unified_count.status, 200);
    assert_eq!(unified_count.body["count"], 1);
    let unified_approvals = request(
        address,
        "GET",
        "/api/v3/approvals?limit=10",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(unified_approvals.status, 200, "{}", unified_approvals.body);
    assert_eq!(unified_approvals.body["items"].as_array().unwrap().len(), 1);
    let operation_approval = &unified_approvals.body["items"][0];
    assert_eq!(operation_approval["kind"], "operation");
    assert_eq!(
        operation_approval["operation_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        operation_approval["verified_identity"]["invocation_id"],
        "invocation-123"
    );
    let approval_id = operation_approval["id"].as_str().unwrap();
    let approval_version = operation_approval["version"].as_i64().unwrap();
    let approve_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-approve-idem-0001"),
        ("if-match", "\"2\""),
    ];
    assert_eq!(approval_version, 2);
    let approve_body = json!({
        "expected_status":"pending",
        "expected_version":approval_version,
        "operation_ids":operation_approval["operation_ids"]
    });
    let approved_operation_group = request(
        address,
        "POST",
        &format!("/api/v3/approvals/{approval_id}/approve"),
        &approve_headers,
        Some(&approve_body),
    )
    .await;
    assert_eq!(
        approved_operation_group.status, 200,
        "{}",
        approved_operation_group.body
    );
    assert_eq!(approved_operation_group.body["status"], "approved");
    let operation_after_approval = request(
        address,
        "GET",
        &format!(
            "/api/v3/operations/{}",
            first_operation.body["id"].as_str().unwrap()
        ),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(operation_after_approval.body["status"], "granted");
    let first_grant_id = operation_after_approval.body["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let grant_page = request(
        address,
        "GET",
        &format!("/api/v3/grants?node_id={first_node_id}&limit=10"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(grant_page.status, 200, "{}", grant_page.body);
    assert_eq!(grant_page.body["items"].as_array().unwrap().len(), 2);
    let first_grant = request(
        address,
        "GET",
        &format!("/api/v3/grants/{first_grant_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(first_grant.status, 200, "{}", first_grant.body);
    assert_eq!(first_grant.body["status"], "issued");
    assert_eq!(first_grant.body["audience"], "blindpass-node");
    assert_eq!(first_grant.body["invocation_id"], "invocation-123");
    assert_eq!(first_grant.body["resource_id"], "marker-a");
    let grant_documents: Vec<String> = match (&backend_pool, &pg_test_pool) {
        (Some(pool), _) => sqlx::query_scalar(
            "SELECT envelope_json FROM node_inbox WHERE node_id = ? ORDER BY seq DESC LIMIT 2",
        )
        .bind(&first_node_id)
        .fetch_all(pool)
        .await
        .unwrap(),
        (_, Some(pool)) => sqlx::query_scalar(
            "SELECT envelope_json FROM node_inbox WHERE node_id = $1 ORDER BY seq DESC LIMIT 2",
        )
        .bind(&first_node_id)
        .fetch_all(pool)
        .await
        .unwrap(),
        _ => unreachable!(),
    };
    let issuer_public = issuer.public_key();
    for document in grant_documents {
        let envelope = SignedEnvelope::from_json(&document).unwrap();
        assert_eq!(envelope.kind(), DocumentKind::Grant);
        assert!(envelope.verify(issuer_public, &issuer_key_id, 1).unwrap());
        let grant = Grant::from_value(envelope.body()).unwrap();
        assert_eq!(grant.node_id, first_node_id);
        assert_eq!(grant.workload_id, workload_id);
        assert_eq!(grant.invocation_id, "invocation-123");
        assert_eq!(grant.audience, "blindpass-node");
    }

    let purpose_with_control = "please bypass approval <script>alert(1)</script>\u{0007}";
    let purpose_event_key = "operation-event-purpose-0001";
    let mut purpose_event_body = operation_event_body.clone();
    purpose_event_body["purpose"] = json!(purpose_with_control);
    purpose_event_body["resource_id"] = json!("marker-purpose");
    let purpose_event = signed_node_event(
        &first_node_id,
        purpose_event_key,
        "operation_request",
        purpose_event_body,
        &first_keys.signing,
    );
    let accepted_purpose_event = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&purpose_event),
    )
    .await;
    assert_eq!(accepted_purpose_event.status, 200);
    let mut purpose_operation_input = first_operation_input.clone();
    purpose_operation_input["purpose"] = json!(purpose_with_control);
    purpose_operation_input["resource_id"] = json!("marker-purpose");
    purpose_operation_input["broker_event_key"] = json!(purpose_event_key);
    let purpose_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &[
            ("origin", ORIGIN),
            ("cookie", admin_cookies.as_str()),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
            ("idempotency-key", "operation-purpose-authority-0001"),
        ],
        Some(&purpose_operation_input),
    )
    .await;
    assert_eq!(purpose_operation.status, 201, "{}", purpose_operation.body);
    assert_eq!(purpose_operation.body["status"], "awaiting_approval");
    assert_eq!(
        purpose_operation.body["purpose"], "please bypass approval <script>alert(1)</script>",
        "purpose controls are stripped for display while the markup remains inert data"
    );

    let purpose_approval_id = purpose_operation.body["approval_id"].as_str().unwrap();
    let purpose_approval = request(
        address,
        "GET",
        &format!("/api/v3/approvals/{purpose_approval_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(purpose_approval.status, 200, "{}", purpose_approval.body);
    assert_eq!(
        purpose_approval.body["requester_summary"]["purpose"],
        "please bypass approval <script>alert(1)</script>"
    );
    let purpose_approval_version = purpose_approval.body["version"].as_i64().unwrap();
    let purpose_approval_ids = purpose_approval.body["operation_ids"].clone();
    let purpose_if_match = format!("\"{purpose_approval_version}\"");
    let approve_race_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "purpose-approve-race-00001"),
        ("if-match", purpose_if_match.as_str()),
    ];
    let reject_race_headers = [
        ("origin", ORIGIN),
        ("cookie", secondary_cookies.as_str()),
        ("x-csrf-token", secondary_csrf.as_str()),
        ("content-type", "application/json"),
        ("idempotency-key", "purpose-reject-race-000001"),
        ("if-match", purpose_if_match.as_str()),
    ];
    let purpose_decision_body = json!({
        "expected_status":"pending",
        "expected_version":purpose_approval_version,
        "operation_ids":purpose_approval_ids
    });
    let approve_purpose_path = format!("/api/v3/approvals/{purpose_approval_id}/approve");
    let reject_purpose_path = format!("/api/v3/approvals/{purpose_approval_id}/reject");
    let (race_approve, race_reject) = tokio::join!(
        request(
            address,
            "POST",
            &approve_purpose_path,
            &approve_race_headers,
            Some(&purpose_decision_body),
        ),
        request(
            address,
            "POST",
            &reject_purpose_path,
            &reject_race_headers,
            Some(&purpose_decision_body),
        )
    );
    assert!(
        matches!(
            (race_approve.status, race_reject.status),
            (200, 409) | (409, 200)
        ),
        "two distinct operators racing one approval must produce one winner: approve={:?}, reject={:?}",
        race_approve.body,
        race_reject.body
    );
    let purpose_decision = store
        .operation_approval_by_id(purpose_approval_id)
        .await
        .unwrap()
        .unwrap();
    let primary_operator = store
        .operator_by_username("fleet-admin")
        .await
        .unwrap()
        .unwrap();
    let secondary_operator_id = secondary_operator.body["id"].as_str().unwrap();
    assert!(
        purpose_decision.decided_by.as_deref() == Some(primary_operator.id.as_str())
            || purpose_decision.decided_by == Some(secondary_operator_id.to_owned()),
        "a recorded decision must belong to one of the two authenticated operators"
    );

    let third_operation_event_key = "operation-event-key-0003";
    let third_operation_event = signed_node_event(
        &first_node_id,
        third_operation_event_key,
        "operation_request",
        operation_event_body.clone(),
        &first_keys.signing,
    );
    let third_operation_event_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&third_operation_event),
    )
    .await;
    assert_eq!(third_operation_event_response.status, 200);
    let mut third_operation_input = first_operation_input.clone();
    third_operation_input["broker_event_key"] = json!(third_operation_event_key);
    let third_operation_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-request-idem-0003"),
    ];
    let third_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &third_operation_headers,
        Some(&third_operation_input),
    )
    .await;
    assert_eq!(third_operation.status, 201);
    let third_approval_id = third_operation.body["approval_id"].as_str().unwrap();

    let paging_event_key = "operation-event-key-page-01";
    let mut paging_event_body = operation_event_body.clone();
    paging_event_body["purpose"] = json!("queue pagination");
    paging_event_body["resource_id"] = json!("marker-page");
    let paging_event = signed_node_event(
        &first_node_id,
        paging_event_key,
        "operation_request",
        paging_event_body,
        &first_keys.signing,
    );
    let paging_event_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&paging_event),
    )
    .await;
    assert_eq!(paging_event_response.status, 200);
    let mut paging_operation_input = first_operation_input.clone();
    paging_operation_input["purpose"] = json!("queue pagination");
    paging_operation_input["resource_id"] = json!("marker-page");
    paging_operation_input["broker_event_key"] = json!(paging_event_key);
    let paging_operation_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-request-idem-page-01"),
    ];
    let paging_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &paging_operation_headers,
        Some(&paging_operation_input),
    )
    .await;
    assert_eq!(paging_operation.status, 201, "{}", paging_operation.body);
    assert_eq!(paging_operation.body["status"], "awaiting_approval");
    let paging_approval_id = paging_operation.body["approval_id"].as_str().unwrap();
    assert_ne!(paging_approval_id, third_approval_id);

    let count_before_page = request(
        address,
        "GET",
        "/api/v3/approvals/count",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(count_before_page.body["count"], 2);
    let first_approval_page = request(
        address,
        "GET",
        "/api/v3/approvals?limit=1",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(first_approval_page.status, 200);
    assert_eq!(
        first_approval_page.body["items"].as_array().unwrap().len(),
        1
    );
    let next_cursor = first_approval_page.body["next_cursor"]
        .as_str()
        .expect("one pending approval page has a continuation cursor");
    let second_approval_page = request(
        address,
        "GET",
        &format!("/api/v3/approvals?limit=1&cursor={next_cursor}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(second_approval_page.status, 200);
    assert_eq!(
        second_approval_page.body["items"].as_array().unwrap().len(),
        1
    );
    assert_ne!(
        first_approval_page.body["items"][0]["id"],
        second_approval_page.body["items"][0]["id"]
    );

    let paging_approval_detail = request(
        address,
        "GET",
        &format!("/api/v3/approvals/{paging_approval_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    let paging_approval_version = paging_approval_detail.body["version"].as_i64().unwrap();
    let overlap_decision_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-reject-overlap-01"),
        (
            "if-match",
            if paging_approval_version == 1 {
                "\"1\""
            } else {
                "\"2\""
            },
        ),
    ];
    let overlapping_decision = request(
        address,
        "POST",
        &format!("/api/v3/approvals/{paging_approval_id}/reject"),
        &overlap_decision_headers,
        Some(&json!({
            "expected_status":"pending",
            "expected_version":paging_approval_version,
            "operation_ids":[third_operation.body["id"]]
        })),
    )
    .await;
    assert_eq!(overlapping_decision.status, 409);
    let rejected_paging_approval = request(
        address,
        "POST",
        &format!("/api/v3/approvals/{paging_approval_id}/reject"),
        &[
            ("origin", ORIGIN),
            ("cookie", admin_cookies.as_str()),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
            ("idempotency-key", "operation-reject-page-01"),
            (
                "if-match",
                if paging_approval_version == 1 {
                    "\"1\""
                } else {
                    "\"2\""
                },
            ),
        ],
        Some(&json!({
            "expected_status":"pending",
            "expected_version":paging_approval_version,
            "operation_ids":[paging_operation.body["id"]]
        })),
    )
    .await;
    assert_eq!(
        rejected_paging_approval.status, 200,
        "{}",
        rejected_paging_approval.body
    );
    assert_eq!(rejected_paging_approval.body["status"], "rejected");
    let count_after_decision = request(
        address,
        "GET",
        "/api/v3/approvals/count",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(count_after_decision.body["count"], 1);

    let next_policy_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("if-match", "\"2\""),
    ];
    let changed_policy = request(
        address,
        "PUT",
        "/api/v3/policies",
        &next_policy_headers,
        Some(&json!({
            "expected_version":2,
            "rules":[{
                "id":"allow-noop-file",
                "action":"noop.marker",
                "mode":"file",
                "decision":"allow",
                "approval_required":false,
                "max_ttl_seconds":120
            }]
        })),
    )
    .await;
    assert_eq!(changed_policy.status, 200);
    let stale_approval_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-approve-stale-0001"),
        ("if-match", "\"1\""),
    ];
    let stale_approval = request(
        address,
        "POST",
        &format!("/api/v3/approvals/{third_approval_id}/approve"),
        &stale_approval_headers,
        Some(&json!({
            "expected_status":"pending",
            "expected_version":1,
            "operation_ids":[third_operation.body["id"]]
        })),
    )
    .await;
    assert_eq!(stale_approval.status, 409);
    let expired_approval = request(
        address,
        "GET",
        &format!("/api/v3/approvals/{third_approval_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(expired_approval.body["status"], "expired");

    let direct_allow_event_key = "operation-event-key-0004";
    let direct_allow_event = signed_node_event(
        &first_node_id,
        direct_allow_event_key,
        "operation_request",
        operation_event_body.clone(),
        &first_keys.signing,
    );
    let direct_allow_event_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&direct_allow_event),
    )
    .await;
    assert_eq!(direct_allow_event_response.status, 200);
    let mut direct_allow_input = first_operation_input.clone();
    direct_allow_input["broker_event_key"] = json!(direct_allow_event_key);
    let direct_allow_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-request-idem-0004"),
    ];
    let direct_allow = request(
        address,
        "POST",
        "/api/v3/operations",
        &direct_allow_headers,
        Some(&direct_allow_input),
    )
    .await;
    assert_eq!(direct_allow.status, 201, "{}", direct_allow.body);
    assert_eq!(direct_allow.body["status"], "granted");
    let direct_allow_grant_id = direct_allow.body["grant_id"].as_str().unwrap();
    let direct_allow_operation_id = direct_allow.body["id"].as_str().unwrap();

    let cancelled = request(
        address,
        "DELETE",
        &format!("/api/v3/operations/{direct_allow_operation_id}"),
        &write_headers,
        None,
    )
    .await;
    assert_eq!(cancelled.status, 200, "{}", cancelled.body);
    assert_eq!(cancelled.body["status"], "grant_revoked");
    assert_eq!(cancelled.body["grant_id"], direct_allow_grant_id);
    let cancelled_operation = request(
        address,
        "GET",
        &format!("/api/v3/operations/{direct_allow_operation_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(cancelled_operation.status, 200);
    assert_eq!(cancelled_operation.body["status"], "revoked");
    let cancelled_grant = request(
        address,
        "GET",
        &format!("/api/v3/grants/{direct_allow_grant_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(cancelled_grant.status, 200);
    assert_eq!(cancelled_grant.body["status"], "revoked");

    let completed_request_key = "operation-event-key-0005";
    let completed_request_event = signed_node_event(
        &first_node_id,
        completed_request_key,
        "operation_request",
        operation_event_body.clone(),
        &first_keys.signing,
    );
    let completed_request_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&completed_request_event),
    )
    .await;
    assert_eq!(completed_request_response.status, 200);
    let mut completed_operation_input = first_operation_input.clone();
    completed_operation_input["broker_event_key"] = json!(completed_request_key);
    let completed_operation_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-request-idem-0005"),
    ];
    let completed_operation = request(
        address,
        "POST",
        "/api/v3/operations",
        &completed_operation_headers,
        Some(&completed_operation_input),
    )
    .await;
    assert_eq!(
        completed_operation.status, 201,
        "{}",
        completed_operation.body
    );
    let completed_operation_id = completed_operation.body["id"].as_str().unwrap();
    let completed_grant_id = completed_operation.body["grant_id"].as_str().unwrap();
    let result_body = json!({
        "grant_id":completed_grant_id,
        "observed_at_ms":now_ms,
        "operation_id":completed_operation_id,
        "result_code":"marker_created",
        "status":"completed"
    });
    let result_event = signed_node_event(
        &first_node_id,
        "operation-result-event-0005",
        "operation_result",
        result_body,
        &first_keys.signing,
    );
    let result_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&result_event),
    )
    .await;
    assert_eq!(result_response.status, 200, "{}", result_response.body);
    let reconciled_operation = request(
        address,
        "GET",
        &format!("/api/v3/operations/{completed_operation_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(reconciled_operation.body["status"], "completed");
    let reconciled_grant = request(
        address,
        "GET",
        &format!("/api/v3/grants/{completed_grant_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(reconciled_grant.body["status"], "consumed");

    let admin_operator = store
        .operator_by_username("fleet-admin")
        .await
        .unwrap()
        .unwrap();
    let current_policy = store.fleet_policy().await.unwrap();
    let pagination_now_ms = store.database_now_ms().await.unwrap();
    for index in 0..101 {
        let suffix = format!("{index:03}");
        let operation_id = format!("op_p03_page_{suffix}");
        let approval_id = format!("oa_p03_page_{suffix}");
        let purpose = format!("pagination fixture {suffix}");
        let identity = json!({
            "node_id":first_node_id,
            "workload_id":workload_id,
            "unit":"blindpass-test.service",
            "account":"blindpass-test",
            "invocation_id":"invocation-123",
            "observed_at":pagination_now_ms
        });
        let summary = json!({
            "operator_id":admin_operator.id,
            "requester":"fleet-admin",
            "action":"noop.marker",
            "mode":"file",
            "resource_id":format!("marker-page-{suffix}"),
            "purpose":purpose
        });
        let record = OperationRecord {
            id: operation_id.clone(),
            workload_id: workload_id.clone(),
            node_id: first_node_id.clone(),
            invocation_id: "invocation-123".to_owned(),
            action: "noop.marker".to_owned(),
            mode: "file".to_owned(),
            resource_id: format!("marker-page-{suffix}"),
            requested_ttl_seconds: 60,
            broker_event_key: None,
            requested_by: admin_operator.id.clone(),
            purpose,
            policy_version: current_policy.version,
            decision: "pending_approval".to_owned(),
            decision_hash: Some("pagination-fixture-policy-hash".to_owned()),
            status: "awaiting_approval".to_owned(),
            approval_id: None,
            grant_id: None,
            idempotency_key: format!("p03-page-idempotency-{suffix}"),
            request_hash: format!("p03-page-request-hash-{suffix}"),
            result_json: None,
            created_at_ms: pagination_now_ms,
            expires_at_ms: pagination_now_ms + 600_000,
            completed_at_ms: None,
            version: 1,
        };
        let draft = OperationApprovalDraft {
            id: approval_id,
            idempotency_key: format!("oa-p03-page-idempotency-{suffix}"),
            requester_summary_json: summary.to_string(),
            verified_identity_json: identity.to_string(),
            rule_id: "pagination-fixture".to_owned(),
            expires_at_ms: pagination_now_ms + 600_000,
        };
        let created = store
            .create_operation(
                &record,
                "blindpass-test.service",
                "blindpass-test",
                60,
                Some(&draft),
            )
            .await
            .unwrap();
        assert!(
            matches!(created, OperationCreateOutcome::Created(_)),
            "fixture operation must be inserted into the pending queue: {created:?}"
        );
    }

    let page_count_before = request(
        address,
        "GET",
        "/api/v3/approvals/count",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(page_count_before.body["count"], 101);
    let page_one = request(
        address,
        "GET",
        "/api/v3/approvals?status=pending&limit=100",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(page_one.status, 200, "{}", page_one.body);
    assert_eq!(page_one.body["items"].as_array().unwrap().len(), 100);
    let page_cursor = page_one.body["next_cursor"]
        .as_str()
        .expect("100 of 101 pending approvals have a continuation cursor")
        .to_owned();
    let page_one_decision_id = page_one.body["items"][0]["id"].as_str().unwrap().to_owned();
    let page_one_decision_version = page_one.body["items"][0]["version"].as_i64().unwrap();
    let page_one_operation_ids = page_one.body["items"][0]["operation_ids"].clone();
    let page_two_before_change = request(
        address,
        "GET",
        &format!("/api/v3/approvals?status=pending&limit=100&cursor={page_cursor}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(page_two_before_change.status, 200);
    assert_eq!(
        page_two_before_change.body["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let expiring_approval_id = page_two_before_change.body["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let page_decision_if_match = format!("\"{page_one_decision_version}\"");
    let page_rejection = request(
        address,
        "POST",
        &format!("/api/v3/approvals/{page_one_decision_id}/reject"),
        &[
            ("origin", ORIGIN),
            ("cookie", admin_cookies.as_str()),
            ("x-csrf-token", csrf),
            ("content-type", "application/json"),
            ("idempotency-key", "p03-page-concurrent-reject-001"),
            ("if-match", page_decision_if_match.as_str()),
        ],
        Some(&json!({
            "expected_status":"pending",
            "expected_version":page_one_decision_version,
            "operation_ids":page_one_operation_ids
        })),
    )
    .await;
    assert_eq!(page_rejection.status, 200, "{}", page_rejection.body);
    let page_count_after_decision = request(
        address,
        "GET",
        "/api/v3/approvals/count",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(page_count_after_decision.body["count"], 100);

    let expired_at_ms = store.database_now_ms().await.unwrap() - 1;
    match (&backend_pool, &pg_test_pool) {
        (Some(pool), _) => {
            sqlx::query("UPDATE operation_approvals SET expires_at = ? WHERE id = ?")
                .bind(expired_at_ms)
                .bind(&expiring_approval_id)
                .execute(pool)
                .await
                .unwrap();
        }
        (_, Some(pool)) => {
            sqlx::query("UPDATE operation_approvals SET expires_at = $1 WHERE id = $2")
                .bind(expired_at_ms)
                .bind(&expiring_approval_id)
                .execute(pool)
                .await
                .unwrap();
        }
        _ => unreachable!(),
    }
    let page_two_after_change = request(
        address,
        "GET",
        &format!("/api/v3/approvals?status=pending&limit=100&cursor={page_cursor}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(page_two_after_change.status, 200);
    assert_eq!(
        page_two_after_change.body["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(page_two_after_change.body["next_cursor"], Value::Null);
    let page_count_after_expiry = request(
        address,
        "GET",
        "/api/v3/approvals/count",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(page_count_after_expiry.body["count"], 99);

    let workload_update_headers = [
        ("origin", ORIGIN),
        ("cookie", admin_cookies.as_str()),
        ("x-csrf-token", csrf),
        ("content-type", "application/json"),
        ("if-match", "\"1\""),
    ];
    let updated_workload = request(
        address,
        "PATCH",
        &format!("/api/v3/workloads/{workload_id}"),
        &workload_update_headers,
        Some(&json!({
            "expected_version":1,
            "unit":"blindpass-test-updated.service"
        })),
    )
    .await;
    assert_eq!(updated_workload.status, 200, "{}", updated_workload.body);
    assert_eq!(
        updated_workload.body["unit"],
        "blindpass-test-updated.service"
    );
    assert_eq!(updated_workload.body["registration_version"], 2);
    assert_eq!(updated_workload.body["version"], 2);

    let stale_workload_update = request(
        address,
        "PATCH",
        &format!("/api/v3/workloads/{workload_id}"),
        &workload_update_headers,
        Some(&json!({
            "expected_version":1,
            "account":"different-account"
        })),
    )
    .await;
    assert_eq!(stale_workload_update.status, 409);

    let revoked_workload = request(
        address,
        "DELETE",
        &format!("/api/v3/workloads/{workload_id}"),
        &write_headers,
        None,
    )
    .await;
    assert_eq!(revoked_workload.status, 200, "{}", revoked_workload.body);
    assert_eq!(revoked_workload.body["status"], "revoked");
    assert_eq!(revoked_workload.body["registration_version"], 3);

    let changed_event_body = json!({"operation_id":"op_dummy","status":"failed"});
    let changed_event_value = parse_json(&changed_event_body.to_string()).unwrap();
    let changed_event_message = node_event_message(
        &first_node_id,
        "event-channel-idempotency-01",
        "operation_result",
        &changed_event_value,
    )
    .unwrap();
    let changed_event = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"events":[{
            "idempotency_key":"event-channel-idempotency-01",
            "kind":"operation_result",
            "body":changed_event_body,
            "broker_signature":base64_url_encode(&first_keys.signing.sign(&changed_event_message).unwrap())
        }]})),
    )
    .await;
    assert_eq!(changed_event.status, 409);

    match (&backend_pool, &pg_test_pool) {
        (Some(pool), _) => {
            sqlx::query("UPDATE node_sessions SET revoked_at = ? WHERE node_id = ?")
                .bind(now_ms)
                .bind(&first_node_id)
                .execute(pool)
                .await
                .unwrap();
        }
        (_, Some(pool)) => {
            sqlx::query("UPDATE node_sessions SET revoked_at = $1 WHERE node_id = $2")
                .bind(now_ms)
                .bind(&first_node_id)
                .execute(pool)
                .await
                .unwrap();
        }
        _ => unreachable!(),
    }
    let revoked_session = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":null,"health":{}})),
    )
    .await;
    assert_eq!(revoked_session.status, 401);

    let second = request(
        address,
        "POST",
        "/api/v3/enrollments",
        &write_headers,
        Some(&json!({"name":"fleet-node-b"})),
    )
    .await;
    assert_eq!(second.status, 201);
    let second_id = second.body["id"].as_str().unwrap().to_owned();
    let second_token = second.body["token"].as_str().unwrap().to_owned();
    let second_node_id = second.body["node_id"].as_str().unwrap().to_owned();
    let second_submission = second_keys.submission(&second_token);
    let second_submitted = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&second_submission),
    )
    .await;
    assert_eq!(second_submitted.status, 201);
    let second_detail = request(
        address,
        "GET",
        &format!("/api/v3/enrollments/{second_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    let second_approved = request(
        address,
        "POST",
        &format!("/api/v3/enrollments/{second_id}/approve"),
        &write_headers,
        Some(&json!({
            "expected_fingerprint": second_keys.fingerprint(),
            "expected_version": second_detail.body["version"]
        })),
    )
    .await;
    assert_eq!(second_approved.status, 200, "{}", second_approved.body);
    assert_eq!(second_approved.body["id"], second_node_id);

    let second_capabilities = json!({"protocol_version":"blindpass-node/1"});
    let second_challenge = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id":second_node_id,
            "key_version": 1,
            "protocol_version":"blindpass-node/1",
            "capabilities":second_capabilities
        })),
    )
    .await;
    assert_eq!(second_challenge.status, 200, "{}", second_challenge.body);
    let second_nonce = second_challenge.body["nonce"].as_str().unwrap();
    let second_message = node_session_challenge_message(
        second_challenge.body["tenant_id"].as_str().unwrap(),
        &second_node_id,
        "blindpass-node/1",
        second_nonce,
        second_challenge.body["capabilities_hash"].as_str().unwrap(),
        second_challenge.body["key_version"].as_i64().unwrap() as u64,
        second_challenge.body["issuer_epoch"].as_i64().unwrap() as u64,
        second_challenge.body["controller_time_ms"]
            .as_i64()
            .unwrap(),
        second_challenge.body["expires_at_ms"].as_i64().unwrap(),
    )
    .unwrap();
    let second_session = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id":second_node_id,
            "key_version": 1,
            "protocol_version":"blindpass-node/1",
            "capabilities":second_capabilities,
            "nonce":second_nonce,
            "signature":base64_url_encode(&second_keys.signing.sign(&second_message).unwrap())
        })),
    )
    .await;
    assert_eq!(second_session.status, 200, "{}", second_session.body);
    let second_node_bearer = format!("Bearer {}", second_session.body["token"].as_str().unwrap());

    let duplicate_name = request(
        address,
        "POST",
        "/api/v3/enrollments",
        &write_headers,
        Some(&json!({"name":"fleet-node-b"})),
    )
    .await;
    assert_eq!(duplicate_name.status, 201);
    let duplicate_id = duplicate_name.body["id"].as_str().unwrap().to_owned();
    let duplicate_keys = NodeKeys::from_seed(36);
    let duplicate_submit = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&duplicate_keys.submission(duplicate_name.body["token"].as_str().unwrap())),
    )
    .await;
    assert_eq!(duplicate_submit.status, 201);
    let duplicate_detail = request(
        address,
        "GET",
        &format!("/api/v3/enrollments/{duplicate_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    let duplicate_approve = request(
        address,
        "POST",
        &format!("/api/v3/enrollments/{duplicate_id}/approve"),
        &write_headers,
        Some(&json!({
            "expected_fingerprint": duplicate_keys.fingerprint(),
            "expected_version": duplicate_detail.body["version"]
        })),
    )
    .await;
    assert_eq!(duplicate_approve.status, 409);

    let rejected = request(
        address,
        "POST",
        "/api/v3/enrollments",
        &write_headers,
        Some(&json!({"name":"fleet-node-rejected"})),
    )
    .await;
    assert_eq!(rejected.status, 201);
    let rejected_id = rejected.body["id"].as_str().unwrap().to_owned();
    let rejected_token = rejected.body["token"].as_str().unwrap();
    let rejected_keys = NodeKeys::from_seed(41);
    let rejected_submit = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&rejected_keys.submission(rejected_token)),
    )
    .await;
    assert_eq!(rejected_submit.status, 201);
    let rejected_detail = request(
        address,
        "GET",
        &format!("/api/v3/enrollments/{rejected_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    let reject_response = request(
        address,
        "POST",
        &format!("/api/v3/enrollments/{rejected_id}/reject"),
        &write_headers,
        Some(&json!({
            "expected_fingerprint": rejected_keys.fingerprint(),
            "expected_version": rejected_detail.body["version"]
        })),
    )
    .await;
    assert_eq!(reject_response.status, 200);
    assert_eq!(reject_response.body["status"], "rejected");

    let expired = request(
        address,
        "POST",
        "/api/v3/enrollments",
        &write_headers,
        Some(&json!({"name":"fleet-node-expired"})),
    )
    .await;
    assert_eq!(expired.status, 201);
    let expired_id = expired.body["id"].as_str().unwrap();
    match &backend_pool {
        Some(pool) => {
            sqlx::query("UPDATE enrollment_requests SET expires_at = 1 WHERE id = ?")
                .bind(expired_id)
                .execute(pool)
                .await
                .expect("expire SQLite enrollment fixture");
        }
        None => {
            sqlx::query("UPDATE enrollment_requests SET expires_at = 1 WHERE id = $1")
                .bind(expired_id)
                .execute(pg_test_pool.as_ref().unwrap())
                .await
                .expect("expire PostgreSQL enrollment fixture");
        }
    }
    let expired_keys = NodeKeys::from_seed(51);
    let expired_submission = expired_keys.submission(expired.body["token"].as_str().unwrap());
    let expired_response = request(
        address,
        "POST",
        "/api/v3/node/enroll",
        &[("content-type", "application/json")],
        Some(&expired_submission),
    )
    .await;
    assert_eq!(expired_response.status, 410);

    let listed = request(
        address,
        "GET",
        "/api/v3/enrollments?limit=1",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(listed.status, 200);
    assert_eq!(listed.body["items"].as_array().unwrap().len(), 1);
    assert!(listed.body.to_string().find(&first_token).is_none());
    assert!(listed.body["next_cursor"].as_str().is_some());
    let nodes = request(
        address,
        "GET",
        "/api/v3/nodes?limit=10",
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(nodes.status, 200);
    assert_eq!(nodes.body["items"].as_array().unwrap().len(), 2);

    let old_node_bearer = open_node_session(address, &first_node_id, 1, &first_keys).await;
    let replacement_keys = NodeKeys::from_seed(91);
    let rotation_response = request(
        address,
        "POST",
        &format!("/api/v3/nodes/{first_node_id}/rotate-key"),
        &write_headers,
        Some(&json!({
            "expected_key_version": 1,
            "expected_fingerprint": replacement_keys.fingerprint(),
            "signing_pub": base64_url_encode(replacement_keys.signing.public_key()),
            "recipient_pub": base64_url_encode(replacement_keys.recipient.public_key())
        })),
    )
    .await;
    assert_eq!(rotation_response.status, 202, "{}", rotation_response.body);
    assert_eq!(rotation_response.body["key_version"], 1);
    assert_eq!(rotation_response.body["rotation_pending"], true);
    assert_eq!(rotation_response.body["pending_key_version"], 2);
    let rotation_id = rotation_response.body["pending_rotation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let pending_operation = signed_node_event(
        &first_node_id,
        "rotation-pending-operation-event-01",
        "operation_request",
        json!({"node_id":first_node_id,"action":"noop.marker"}),
        &replacement_keys.signing,
    );
    let pending_operation_response = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &old_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&pending_operation),
    )
    .await;
    assert_eq!(pending_operation_response.status, 400);

    let rotation_delivery = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &old_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":null,"health":{}})),
    )
    .await;
    assert_eq!(rotation_delivery.status, 200, "{}", rotation_delivery.body);
    let delivered_rotation = rotation_delivery.body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|document| document["envelope"]["kind"] == "node_key_rotation")
        .expect("rotation must be delivered through the authenticated node channel");
    let rotation_envelope =
        SignedEnvelope::from_json(&delivered_rotation["envelope"].to_string()).unwrap();
    assert!(
        rotation_envelope
            .verify(issuer.public_key(), &issuer_key_id, 1)
            .unwrap()
    );
    let rotation_document = NodeKeyRotation::from_value(rotation_envelope.body()).unwrap();
    assert_eq!(rotation_document.rotation_id, rotation_id);
    assert_eq!(rotation_document.from_key_version, 1);
    assert_eq!(rotation_document.to_key_version, 2);
    assert_eq!(
        rotation_document.fingerprint,
        replacement_keys.fingerprint()
    );

    let replacement_bearer = open_node_session(address, &first_node_id, 2, &replacement_keys).await;
    let rotation_event_key = format!("rotation_{rotation_id}");
    let rotation_ack_event = signed_node_event(
        &first_node_id,
        &rotation_event_key,
        "audit",
        json!({
            "action":"node_key_rotation_applied",
            "fingerprint":replacement_keys.fingerprint(),
            "key_version":2,
            "node_id":first_node_id,
            "rotation_id":rotation_id
        }),
        &replacement_keys.signing,
    );
    let rotation_ack = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &replacement_bearer),
            ("content-type", "application/json"),
        ],
        Some(&rotation_ack_event),
    )
    .await;
    assert_eq!(rotation_ack.status, 200, "{}", rotation_ack.body);
    assert_eq!(rotation_ack.body["accepted"], 1);
    let rotation_application_ack =
        SignedEnvelope::from_json(&rotation_ack.body["ack"].to_string()).unwrap();
    assert_eq!(
        rotation_application_ack.kind(),
        DocumentKind::ApplicationAck
    );
    assert!(
        rotation_application_ack
            .verify(issuer.public_key(), &issuer_key_id, 1)
            .unwrap()
    );
    assert_eq!(
        ApplicationAck::from_value(rotation_application_ack.body())
            .unwrap()
            .event_keys,
        [rotation_event_key]
    );

    let finalized_node = request(
        address,
        "GET",
        &format!("/api/v3/nodes/{first_node_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(finalized_node.status, 200, "{}", finalized_node.body);
    assert_eq!(finalized_node.body["key_version"], 2);
    assert_eq!(finalized_node.body["rotation_pending"], false);
    assert_eq!(finalized_node.body["pending_key_version"], Value::Null);
    assert_eq!(
        finalized_node.body["signing_fingerprint"],
        sha256(replacement_keys.signing.public_key())
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let old_key_reconnect = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id": first_node_id,
            "key_version": 1,
            "protocol_version":"blindpass-node/1",
            "capabilities":{"protocol_version":"blindpass-node/1"}
        })),
    )
    .await;
    assert_eq!(old_key_reconnect.status, 401);
    let recovered_node_bearer =
        open_node_session(address, &first_node_id, 2, &replacement_keys).await;
    let old_session_poll = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &old_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":null,"health":{}})),
    )
    .await;
    assert_eq!(old_session_poll.status, 401);
    let recovered_poll = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &recovered_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":null,"health":{}})),
    )
    .await;
    assert_eq!(recovered_poll.status, 200, "{}", recovered_poll.body);

    let revoked_first_node = request(
        address,
        "DELETE",
        &format!("/api/v3/nodes/{first_node_id}"),
        &write_headers,
        None,
    )
    .await;
    assert_eq!(
        revoked_first_node.status, 200,
        "{}",
        revoked_first_node.body
    );
    assert_eq!(revoked_first_node.body["status"], "revoked");
    let revoked_first_grant = request(
        address,
        "GET",
        &format!("/api/v3/grants/{first_grant_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(
        revoked_first_grant.status, 200,
        "{}",
        revoked_first_grant.body
    );
    assert_eq!(revoked_first_grant.body["status"], "revoked");
    let node_tombstones: i64 = match &backend_pool {
        Some(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM grant_tombstones WHERE node_id = ?")
            .bind(&first_node_id)
            .fetch_one(pool)
            .await
            .unwrap(),
        None => sqlx::query_scalar("SELECT COUNT(*) FROM grant_tombstones WHERE node_id = $1")
            .bind(&first_node_id)
            .fetch_one(pg_test_pool.as_ref().unwrap())
            .await
            .unwrap(),
    };
    assert!(
        node_tombstones >= 2,
        "node revocation must persist grant tombstones"
    );

    let revoked_node = request(
        address,
        "DELETE",
        &format!("/api/v3/nodes/{second_node_id}"),
        &write_headers,
        None,
    )
    .await;
    assert_eq!(revoked_node.status, 200, "{}", revoked_node.body);
    assert_eq!(revoked_node.body["status"], "revoked");
    assert_eq!(revoked_node.body["revocation_pending"], true);
    let revoked_node_again = request(
        address,
        "DELETE",
        &format!("/api/v3/nodes/{second_node_id}"),
        &write_headers,
        None,
    )
    .await;
    assert_eq!(
        revoked_node_again.status, 200,
        "{}",
        revoked_node_again.body
    );
    assert_eq!(revoked_node_again.body["status"], "revoked");
    let revoked_node_poll = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &second_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":null,"health":{}})),
    )
    .await;
    assert_eq!(revoked_node_poll.status, 200, "{}", revoked_node_poll.body);
    let revocation_document = revoked_node_poll.body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|document| document["envelope"]["kind"] == "node_revocation")
        .expect("revocation queue must include the signed node tombstone");
    assert_eq!(
        revocation_document["envelope"]["body"]["node_id"],
        second_node_id
    );
    let revocation_event_key = "node-revocation-applied-event-01";
    let revocation_applied_event = signed_node_event(
        &second_node_id,
        revocation_event_key,
        "audit",
        json!({
            "action":"node_revocation_applied",
            "node_id":second_node_id,
            "observed_at_ms":1_800_000_000_000_u64
        }),
        &second_keys.signing,
    );
    let revocation_ack = request(
        address,
        "POST",
        "/api/v3/node/events",
        &[
            ("authorization", &second_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&revocation_applied_event),
    )
    .await;
    assert_eq!(revocation_ack.status, 200, "{}", revocation_ack.body);
    assert_eq!(revocation_ack.body["accepted"], 1);
    let revocation_ack_document =
        SignedEnvelope::from_json(&revocation_ack.body["ack"].to_string()).unwrap();
    let revocation_ack_body = ApplicationAck::from_value(revocation_ack_document.body()).unwrap();
    assert_eq!(revocation_ack_body.event_keys, [revocation_event_key]);
    let finalized_node = request(
        address,
        "GET",
        &format!("/api/v3/nodes/{second_node_id}"),
        &[("cookie", &admin_cookies)],
        None,
    )
    .await;
    assert_eq!(finalized_node.status, 200, "{}", finalized_node.body);
    assert_eq!(finalized_node.body["revocation_pending"], false);
    let revoked_node_poll_after_ack = request(
        address,
        "POST",
        "/api/v3/node/poll",
        &[
            ("authorization", &second_node_bearer),
            ("content-type", "application/json"),
        ],
        Some(&json!({"ack_seq":revocation_document["seq"],"health":{}})),
    )
    .await;
    assert_eq!(revoked_node_poll_after_ack.status, 401);
    let revoked_node_session = request(
        address,
        "POST",
        "/api/v3/node/session",
        &[("content-type", "application/json")],
        Some(&json!({
            "node_id": second_node_id,
            "key_version": 1,
            "protocol_version": "blindpass-node/1",
            "capabilities": {"protocol_version":"blindpass-node/1"}
        })),
    )
    .await;
    assert_eq!(revoked_node_session.status, 401);

    server.abort();
    if let Some(schema) = pg_schema {
        sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(pg_admin.as_ref().unwrap())
            .await
            .expect("drop PostgreSQL enrollment schema");
    }
}

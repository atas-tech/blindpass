// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::{app::build_app, config::Config, store::Store};
use blindpass_core::custody::{RecipientKeyPair, sha256};
use blindpass_core::fleet::{enrollment_proof_message, node_key_fingerprint};
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
    let server = tokio::spawn(async move {
        axum::serve(listener, build_app(config, Some(store.clone())))
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
                .execute(pg_admin.as_ref().unwrap())
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
                .execute(pg_admin.as_ref().unwrap())
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

    server.abort();
    if let Some(schema) = pg_schema {
        sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
            .execute(pg_admin.as_ref().unwrap())
            .await
            .expect("drop PostgreSQL enrollment schema");
    }
}

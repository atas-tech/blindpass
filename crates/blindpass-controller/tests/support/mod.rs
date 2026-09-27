// SPDX-License-Identifier: AGPL-3.0-only

//! Shared P03 fleet HTTP harness. Each harness runs an isolated controller on
//! loopback over SQLite, or over an isolated PostgreSQL schema when
//! `P02_TEST_BACKEND=postgres` and `P02_TEST_POSTGRES_URL` are set.

#![allow(dead_code)]

use blindpass_controller::{app::build_app, config::Config, store::Store};
use blindpass_core::canon::parse_json;
use blindpass_core::custody::{RecipientKeyPair, sha256};
use blindpass_core::fleet::{
    enrollment_proof_message, node_event_message, node_key_fingerprint,
    node_session_challenge_message,
};
use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};
use serde_json::{Value, json};
use sqlx::{PgPool, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const ORIGIN: &str = "http://127.0.0.1:5175";
pub const ISSUER_SEED: u8 = b'I';
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    format!(
        "{prefix}-{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

pub struct TestDirectory(pub PathBuf);

impl TestDirectory {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(unique("blindpass-p03-harness"));
        std::fs::create_dir_all(&path).expect("create harness directory");
        Self(path)
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

pub async fn raw_request(
    address: SocketAddr,
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
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    let mut stream = TcpStream::connect(address).await.expect("connect harness");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8(response).expect("UTF-8 response");
    let (header_text, body_text) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("response separator missing: {response:?}"));
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("status code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = if body_text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body_text).unwrap_or(Value::String(body_text.to_owned()))
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn cookie(response: &HttpResponse, name: &str) -> String {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .find_map(|(_, value)| {
            let pair = value.split(';').next()?;
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name == name).then(|| format!("{name}={cookie_value}"))
        })
        .expect("response cookie")
}

/// An authenticated operator browser session.
#[derive(Clone, Debug)]
pub struct Operator {
    pub id: String,
    pub username: String,
    pub cookies: String,
    pub csrf: String,
}

pub struct NodeKeys {
    pub signing: Ed25519KeyPair,
    pub recipient: RecipientKeyPair,
}

impl NodeKeys {
    pub fn from_seed(seed: u8) -> Self {
        Self {
            signing: Ed25519KeyPair::from_seed(&[seed; 32]).unwrap(),
            recipient: RecipientKeyPair::from_private_key(&[seed.wrapping_add(1); 32]).unwrap(),
        }
    }

    pub fn fingerprint(&self) -> String {
        node_key_fingerprint(self.signing.public_key(), self.recipient.public_key()).unwrap()
    }

    pub fn submission(&self, token: &str) -> Value {
        let message = enrollment_proof_message(
            token,
            self.signing.public_key(),
            self.recipient.public_key(),
        )
        .unwrap();
        json!({
            "token": token,
            "signing_pub": base64_url_encode(self.signing.public_key()),
            "recipient_pub": base64_url_encode(self.recipient.public_key()),
            "proof": base64_url_encode(&self.signing.sign(&message).unwrap()),
            "protocol_version": "blindpass-node/1",
            "capabilities": {"protocol_version": "blindpass-node/1"},
            "host_facts": {"os": "linux"}
        })
    }
}

pub enum Backend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

pub enum Bind {
    Text(String),
    Int(i64),
}

impl From<&str> for Bind {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<String> for Bind {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&String> for Bind {
    fn from(value: &String) -> Self {
        Self::Text(value.clone())
    }
}

impl From<i64> for Bind {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

fn postgres_placeholders(sql: &str) -> String {
    let mut output = String::new();
    let mut index = 0;
    for character in sql.chars() {
        if character == '?' {
            index += 1;
            output.push_str(&format!("${index}"));
        } else {
            output.push(character);
        }
    }
    output
}

pub struct Harness {
    pub directory: TestDirectory,
    pub address: SocketAddr,
    pub database_url: String,
    pub store: Store,
    pub backend: Backend,
    pub admin: Operator,
    pub issuer: Ed25519KeyPair,
    pub issuer_key_id: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

pub fn postgres_selected() -> bool {
    std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres")
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(&[]).await
    }

    pub async fn start_with(extra: &[(&str, &str)]) -> Self {
        let directory = TestDirectory::new();
        let database_url = if postgres_selected() {
            let parent = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("P02_TEST_POSTGRES_URL is required for the PostgreSQL backend");
            let schema = unique("p03_review").replace('-', "_");
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&parent)
                .await
                .expect("connect PostgreSQL parent");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&pool)
                .await
                .expect("create isolated schema");
            pool.close().await;
            let separator = if parent.contains('?') { '&' } else { '?' };
            format!("{parent}{separator}options=-c%20search_path%3D{schema}")
        } else {
            format!(
                "sqlite://{}?mode=rwc",
                directory.file("controller.db").display()
            )
        };
        for (name, value) in [
            ("database.url", database_url.clone()),
            ("root.secret", "R".repeat(32)),
            ("agent.secret", "A".repeat(32)),
            ("issuer.seed", (ISSUER_SEED as char).to_string().repeat(32)),
        ] {
            let path = directory.file(name);
            std::fs::write(&path, value).expect("write harness secret");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("protect harness secret");
        }
        let database_file = directory.file("database.url");
        let root_file = directory.file("root.secret");
        let agent_file = directory.file("agent.secret");
        let issuer_file = directory.file("issuer.seed");
        let mut variables = vec![
            ("BLINDPASS_LISTEN", "127.0.0.1:0"),
            ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
            ("BLINDPASS_UI_BASE_URL", ORIGIN),
            (
                "BLINDPASS_DATABASE_URL_FILE",
                database_file.to_str().unwrap(),
            ),
            ("BLINDPASS_ROOT_SECRET_FILE", root_file.to_str().unwrap()),
            (
                "BLINDPASS_AGENT_JWT_SECRET_FILE",
                agent_file.to_str().unwrap(),
            ),
            ("BLINDPASS_ISSUER_KEY_FILE", issuer_file.to_str().unwrap()),
        ];
        variables.extend_from_slice(extra);
        let config = Config::from_variables(variables).expect("valid harness config");
        let store = Store::connect(&database_url)
            .await
            .expect("connect harness store");
        let backend = if postgres_selected() {
            Backend::Postgres(
                PgPoolOptions::new()
                    .max_connections(2)
                    .connect(&database_url)
                    .await
                    .expect("connect harness PostgreSQL"),
            )
        } else {
            Backend::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(2)
                    .connect(&database_url)
                    .await
                    .expect("connect harness SQLite"),
            )
        };
        let bootstrap_token = "p03-review-bootstrap-token-with-more-than-32-bytes";
        let token_hash: String = sha256(bootstrap_token.as_bytes())
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(store.issue_bootstrap_token(&token_hash, 900).await.unwrap());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind harness");
        let address = listener.local_addr().unwrap();
        let app_store = store.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_app(config, Some(app_store)))
                .await
                .unwrap();
        });
        let bootstrap = raw_request(
            address,
            "POST",
            "/api/v3/admin/bootstrap",
            &[
                ("content-type", "application/json"),
                ("origin", ORIGIN),
                ("x-blindpass-bootstrap-token", bootstrap_token),
            ],
            Some(&json!({
                "username":"fleet-admin",
                "display_name":"Fleet Admin",
                "password":"fleet-admin-test-password-long"
            })),
        )
        .await;
        assert_eq!(bootstrap.status, 201, "{}", bootstrap.body);
        let admin_id = store
            .operator_by_username("fleet-admin")
            .await
            .unwrap()
            .unwrap()
            .id;
        let admin = Operator {
            id: admin_id,
            username: "fleet-admin".to_owned(),
            cookies: format!(
                "{}; {}",
                cookie(&bootstrap, "bp_session"),
                cookie(&bootstrap, "bp_csrf")
            ),
            csrf: bootstrap.body["csrf_token"].as_str().unwrap().to_owned(),
        };
        let issuer = Ed25519KeyPair::from_seed(&[ISSUER_SEED; 32]).unwrap();
        let issuer_key_id = format!("ed25519-{}", base64_url_encode(issuer.public_key()));
        Self {
            directory,
            address,
            database_url,
            store,
            backend,
            admin,
            issuer,
            issuer_key_id,
            server,
        }
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> HttpResponse {
        raw_request(self.address, method, path, headers, body).await
    }

    /// Issue an operator request. Unsafe methods carry origin and CSRF; extra
    /// headers such as `Idempotency-Key` or `If-Match` are appended.
    pub async fn call(
        &self,
        operator: &Operator,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: Option<&Value>,
    ) -> HttpResponse {
        let mut headers = vec![
            ("cookie", operator.cookies.as_str()),
            ("content-type", "application/json"),
        ];
        if method != "GET" {
            headers.push(("origin", ORIGIN));
            headers.push(("x-csrf-token", operator.csrf.as_str()));
        }
        headers.extend_from_slice(extra);
        self.request(method, path, &headers, body).await
    }

    pub async fn get(&self, operator: &Operator, path: &str) -> HttpResponse {
        self.call(operator, "GET", path, &[], None).await
    }

    pub async fn create_operator(&self, username: &str, role: &str) -> Operator {
        let password = format!("{username}-test-password-long");
        let created = self
            .call(
                &self.admin,
                "POST",
                "/api/v3/admin/operators",
                &[],
                Some(&json!({
                    "username":username,
                    "display_name":username,
                    "role":role,
                    "password":password
                })),
            )
            .await;
        assert_eq!(created.status, 201, "{}", created.body);
        self.login(created.body["id"].as_str().unwrap(), username, &password)
            .await
    }

    /// Log in with the double-submit pre-session CSRF cookie.
    pub async fn login(&self, id: &str, username: &str, password: &str) -> Operator {
        let login = self
            .request(
                "POST",
                "/api/v3/admin/session/login",
                &[
                    ("content-type", "application/json"),
                    ("origin", ORIGIN),
                    ("cookie", "bp_csrf=p03-login-pre-session"),
                    ("x-csrf-token", "p03-login-pre-session"),
                ],
                Some(&json!({"username":username,"password":password})),
            )
            .await;
        assert_eq!(login.status, 200, "{}", login.body);
        Operator {
            id: id.to_owned(),
            username: username.to_owned(),
            cookies: format!(
                "{}; {}",
                cookie(&login, "bp_session"),
                cookie(&login, "bp_csrf")
            ),
            csrf: login.body["csrf_token"].as_str().unwrap().to_owned(),
        }
    }

    /// Create, submit and approve an enrollment; returns the node id.
    pub async fn enroll_node(&self, name: &str, keys: &NodeKeys) -> String {
        let created = self
            .call(
                &self.admin,
                "POST",
                "/api/v3/enrollments",
                &[],
                Some(&json!({"name":name})),
            )
            .await;
        assert_eq!(created.status, 201, "{}", created.body);
        let enrollment_id = created.body["id"].as_str().unwrap().to_owned();
        let token = created.body["token"].as_str().unwrap();
        let submitted = self
            .request(
                "POST",
                "/api/v3/node/enroll",
                &[("content-type", "application/json")],
                Some(&keys.submission(token)),
            )
            .await;
        assert_eq!(submitted.status, 201, "{}", submitted.body);
        let detail = self
            .get(&self.admin, &format!("/api/v3/enrollments/{enrollment_id}"))
            .await;
        let approved = self
            .call(
                &self.admin,
                "POST",
                &format!("/api/v3/enrollments/{enrollment_id}/approve"),
                &[],
                Some(&json!({
                    "expected_fingerprint":keys.fingerprint(),
                    "expected_version":detail.body["version"]
                })),
            )
            .await;
        assert_eq!(approved.status, 200, "{}", approved.body);
        created.body["node_id"].as_str().unwrap().to_owned()
    }

    pub async fn session_challenge(&self, node_id: &str, key_version: u64) -> HttpResponse {
        self.request(
            "POST",
            "/api/v3/node/session",
            &[("content-type", "application/json")],
            Some(&json!({
                "node_id":node_id,
                "key_version":key_version,
                "protocol_version":"blindpass-node/1",
                "capabilities":{"protocol_version":"blindpass-node/1"}
            })),
        )
        .await
    }

    /// Sign a challenge body returned by phase one and submit phase two.
    pub async fn session_authenticate(
        &self,
        node_id: &str,
        key_version: u64,
        keys: &NodeKeys,
        challenge: &Value,
    ) -> HttpResponse {
        let message = node_session_challenge_message(
            challenge["tenant_id"].as_str().unwrap(),
            node_id,
            "blindpass-node/1",
            challenge["nonce"].as_str().unwrap(),
            challenge["capabilities_hash"].as_str().unwrap(),
            key_version,
            challenge["issuer_epoch"].as_u64().unwrap(),
            challenge["controller_time_ms"].as_i64().unwrap(),
            challenge["expires_at_ms"].as_i64().unwrap(),
        )
        .unwrap();
        self.request(
            "POST",
            "/api/v3/node/session",
            &[("content-type", "application/json")],
            Some(&json!({
                "node_id":node_id,
                "key_version":key_version,
                "protocol_version":"blindpass-node/1",
                "capabilities":{"protocol_version":"blindpass-node/1"},
                "nonce":challenge["nonce"],
                "signature":base64_url_encode(&keys.signing.sign(&message).unwrap())
            })),
        )
        .await
    }

    pub async fn open_session(&self, node_id: &str, key_version: u64, keys: &NodeKeys) -> String {
        let challenge = self.session_challenge(node_id, key_version).await;
        assert_eq!(challenge.status, 200, "{}", challenge.body);
        let session = self
            .session_authenticate(node_id, key_version, keys, &challenge.body)
            .await;
        assert_eq!(session.status, 200, "{}", session.body);
        format!("Bearer {}", session.body["token"].as_str().unwrap())
    }

    pub async fn poll(&self, bearer: &str, body: &Value) -> HttpResponse {
        self.request(
            "POST",
            "/api/v3/node/poll",
            &[
                ("authorization", bearer),
                ("content-type", "application/json"),
            ],
            Some(body),
        )
        .await
    }

    pub async fn post_events(&self, bearer: &str, events: &Value) -> HttpResponse {
        self.request(
            "POST",
            "/api/v3/node/events",
            &[
                ("authorization", bearer),
                ("content-type", "application/json"),
            ],
            Some(events),
        )
        .await
    }

    pub async fn execute(&self, sql: &str, binds: Vec<Bind>) -> u64 {
        match &self.backend {
            Backend::Sqlite(pool) => {
                let mut query = sqlx::query(sql);
                for bind in binds {
                    query = match bind {
                        Bind::Text(value) => query.bind(value),
                        Bind::Int(value) => query.bind(value),
                    };
                }
                query
                    .execute(pool)
                    .await
                    .expect("harness SQL")
                    .rows_affected()
            }
            Backend::Postgres(pool) => {
                let sql = postgres_placeholders(sql);
                let mut query = sqlx::query(&sql);
                for bind in binds {
                    query = match bind {
                        Bind::Text(value) => query.bind(value),
                        Bind::Int(value) => query.bind(value),
                    };
                }
                query
                    .execute(pool)
                    .await
                    .expect("harness SQL")
                    .rows_affected()
            }
        }
    }

    pub async fn scalar_i64(&self, sql: &str, binds: Vec<Bind>) -> i64 {
        match &self.backend {
            Backend::Sqlite(pool) => {
                let mut query = sqlx::query_scalar::<_, i64>(sql);
                for bind in binds {
                    query = match bind {
                        Bind::Text(value) => query.bind(value),
                        Bind::Int(value) => query.bind(value),
                    };
                }
                query.fetch_one(pool).await.expect("harness scalar")
            }
            Backend::Postgres(pool) => {
                let sql = postgres_placeholders(sql);
                let mut query = sqlx::query_scalar::<_, i64>(&sql);
                for bind in binds {
                    query = match bind {
                        Bind::Text(value) => query.bind(value),
                        Bind::Int(value) => query.bind(value),
                    };
                }
                query.fetch_one(pool).await.expect("harness scalar")
            }
        }
    }

    pub async fn strings(&self, sql: &str, binds: Vec<Bind>) -> Vec<Option<String>> {
        match &self.backend {
            Backend::Sqlite(pool) => {
                let mut query = sqlx::query_scalar::<_, Option<String>>(sql);
                for bind in binds {
                    query = match bind {
                        Bind::Text(value) => query.bind(value),
                        Bind::Int(value) => query.bind(value),
                    };
                }
                query.fetch_all(pool).await.expect("harness strings")
            }
            Backend::Postgres(pool) => {
                let sql = postgres_placeholders(sql);
                let mut query = sqlx::query_scalar::<_, Option<String>>(&sql);
                for bind in binds {
                    query = match bind {
                        Bind::Text(value) => query.bind(value),
                        Bind::Int(value) => query.bind(value),
                    };
                }
                query.fetch_all(pool).await.expect("harness strings")
            }
        }
    }

    /// Envelopes queued for a node, oldest first.
    pub async fn inbox(&self, node_id: &str) -> Vec<Value> {
        self.strings(
            "SELECT envelope_json FROM node_inbox WHERE node_id = ? ORDER BY seq",
            vec![node_id.into()],
        )
        .await
        .into_iter()
        .map(|envelope| serde_json::from_str(&envelope.unwrap()).unwrap())
        .collect()
    }

    pub async fn now_ms(&self) -> i64 {
        self.store.database_now_ms().await.unwrap()
    }

    /// Mark a node as recently seen without a 30-second empty long poll.
    pub async fn touch_node(&self, node_id: &str) {
        let now_ms = self.now_ms().await;
        self.execute(
            "UPDATE nodes SET last_seen_at = ? WHERE id = ?",
            vec![now_ms.into(), node_id.into()],
        )
        .await;
    }

    /// Enroll a node, open a session and mark it online.
    pub async fn online_node(&self, name: &str, seed: u8) -> FleetNode {
        let keys = NodeKeys::from_seed(seed);
        let id = self.enroll_node(name, &keys).await;
        let bearer = self.open_session(&id, 1, &keys).await;
        self.touch_node(&id).await;
        FleetNode { id, keys, bearer }
    }

    /// Replace the fleet policy with `rules` using the current version.
    pub async fn set_policy(&self, rules: Value) -> HttpResponse {
        let current = self.get(&self.admin, "/api/v3/policies").await;
        assert_eq!(current.status, 200, "{}", current.body);
        let version = current.body["version"].as_i64().unwrap();
        let if_match = format!("\"{version}\"");
        self.call(
            &self.admin,
            "PUT",
            "/api/v3/policies",
            &[("if-match", if_match.as_str())],
            Some(&json!({"expected_version":version,"rules":rules})),
        )
        .await
    }

    pub async fn create_workload(
        &self,
        node_id: &str,
        name: &str,
        unit: &str,
        account: &str,
        mode: &str,
    ) -> HttpResponse {
        self.call(
            &self.admin,
            "POST",
            "/api/v3/workloads",
            &[],
            Some(&json!({
                "node_id":node_id,
                "name":name,
                "unit":unit,
                "account":account,
                "consumption_mode":mode,
                "local_ceiling_seconds":300
            })),
        )
        .await
    }

    /// Submit a broker-signed operation request for `workload` and return
    /// the matching controller operation input.
    pub async fn broker_request(
        &self,
        node: &FleetNode,
        workload: &Value,
        request: &OperationSpec<'_>,
    ) -> Value {
        let now_ms = self.now_ms().await;
        let body = json!({
            "node_id": node.id,
            "workload_id": workload["id"],
            "unit": workload["unit"],
            "account": workload["account"],
            "invocation_id": request.invocation_id,
            "action": "noop.marker",
            "mode": workload["consumption_mode"],
            "purpose": request.purpose,
            "resource_id": request.resource_id,
            "ttl_seconds": 60,
            "observed_at_ms": now_ms
        });
        let events = signed_event(
            &node.id,
            &node.keys.signing,
            request.event_key,
            "operation_request",
            body,
        );
        let posted = self.post_events(&node.bearer, &events).await;
        assert_eq!(posted.status, 200, "{}", posted.body);
        json!({
            "workload_id": workload["id"],
            "action": "noop.marker",
            "mode": workload["consumption_mode"],
            "purpose": request.purpose,
            "resource_id": request.resource_id,
            "invocation_id": request.invocation_id,
            "ttl_seconds": 60,
            "broker_event_key": request.event_key
        })
    }

    /// Broker request plus controller operation creation by `operator`.
    pub async fn request_operation(
        &self,
        operator: &Operator,
        node: &FleetNode,
        workload: &Value,
        request: &OperationSpec<'_>,
    ) -> HttpResponse {
        let input = self.broker_request(node, workload, request).await;
        let idempotency = format!("idem-{}", request.event_key);
        self.call(
            operator,
            "POST",
            "/api/v3/operations",
            &[("idempotency-key", idempotency.as_str())],
            Some(&input),
        )
        .await
    }

    /// Approve or reject an approval using its current version and members.
    pub async fn decide(
        &self,
        operator: &Operator,
        approval_id: &str,
        verb: &str,
        idempotency: &str,
    ) -> HttpResponse {
        let detail = self
            .get(operator, &format!("/api/v3/approvals/{approval_id}"))
            .await;
        assert_eq!(detail.status, 200, "{}", detail.body);
        let version = detail.body["version"].as_i64().unwrap();
        let if_match = format!("\"{version}\"");
        self.call(
            operator,
            "POST",
            &format!("/api/v3/approvals/{approval_id}/{verb}"),
            &[
                ("idempotency-key", idempotency),
                ("if-match", if_match.as_str()),
            ],
            Some(&json!({
                "expected_status":"pending",
                "expected_version":version,
                "operation_ids":detail.body["operation_ids"]
            })),
        )
        .await
    }
}

pub struct FleetNode {
    pub id: String,
    pub keys: NodeKeys,
    pub bearer: String,
}

pub struct OperationSpec<'a> {
    pub event_key: &'a str,
    pub invocation_id: &'a str,
    pub resource_id: &'a str,
    pub purpose: &'a str,
}

impl<'a> OperationSpec<'a> {
    pub fn new(event_key: &'a str) -> Self {
        Self {
            event_key,
            invocation_id: "invocation-1",
            resource_id: "marker-a",
            purpose: "review marker",
        }
    }
}

pub fn signed_events(
    node_id: &str,
    signing: &Ed25519KeyPair,
    events: &[(&str, &str, Value)],
) -> Value {
    let events = events
        .iter()
        .map(|(key, kind, body)| {
            let body_value = parse_json(&body.to_string()).unwrap();
            let message = node_event_message(node_id, key, kind, &body_value).unwrap();
            json!({
                "idempotency_key":key,
                "kind":kind,
                "body":body,
                "broker_signature":base64_url_encode(&signing.sign(&message).unwrap())
            })
        })
        .collect::<Vec<_>>();
    json!({"events": events})
}

pub fn signed_event(
    node_id: &str,
    signing: &Ed25519KeyPair,
    key: &str,
    kind: &str,
    body: Value,
) -> Value {
    signed_events(node_id, signing, &[(key, kind, body)])
}

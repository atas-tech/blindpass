// SPDX-License-Identifier: AGPL-3.0-only

use axum::Router;
use blindpass_controller::{app::build_app, config::Config, store::Store};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx::{PgPool, SqlitePool, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-rate-limit-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create test directory");
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

enum CountPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl CountPool {
    async fn count(&self, table: &str) -> i64 {
        let query = format!("SELECT COUNT(*) FROM {table}");
        match self {
            Self::Sqlite(pool) => sqlx::query_scalar(&query)
                .fetch_one(pool)
                .await
                .expect("count SQLite rows"),
            Self::Postgres(pool) => sqlx::query_scalar(&query)
                .fetch_one(pool)
                .await
                .expect("count PostgreSQL rows"),
        }
    }

    async fn close(self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
            Self::Postgres(pool) => pool.close().await,
        }
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
    text: String,
}

async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> HttpResponse {
    let body_text = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body_text.len()
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str("\r\n");
    request.push_str(&body_text);

    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect HTTP test server");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read HTTP response");
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    let (header_text, body_text) = response
        .split_once("\r\n\r\n")
        .expect("HTTP response headers and body separator");
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("HTTP status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = serde_json::from_str(body_text).expect("response body is JSON");
    HttpResponse {
        status,
        headers,
        body,
        text: body_text.to_owned(),
    }
}

fn workload_token(secret: &[u8], subject: &str, workspace: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let claims = json!({
        "sub":subject,
        "role":"gateway",
        "workspace_id":workspace,
        "workload_mode":"hosted",
        "iss":"sps",
        "aud":"sps-agent",
        "iat":now,
        "exp":now + 300
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("sign workload JWT")
}

#[tokio::test]
async fn authenticated_agent_windows_are_scoped_and_reject_without_writing() {
    let directory = TestDirectory::new();
    let backend = std::env::var("P02_TEST_BACKEND").unwrap_or_else(|_| "sqlite".to_owned());
    let (database_url, count_pool, schema_cleanup) = match backend.as_str() {
        "sqlite" => {
            let url = format!(
                "sqlite://{}?mode=rwc",
                directory.file("controller.db").display()
            );
            let pool = SqlitePoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect SQLite count pool");
            (url, CountPool::Sqlite(pool), None)
        }
        "postgres" => {
            let parent = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required");
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos();
            let schema = format!("p02_rate_{}_{nonce}", std::process::id());
            let admin = PgPoolOptions::new()
                .max_connections(2)
                .connect(&parent)
                .await
                .expect("connect PostgreSQL fixture parent");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&admin)
                .await
                .expect("create isolated PostgreSQL schema");
            let separator = if parent.contains('?') { '&' } else { '?' };
            let url = format!("{parent}{separator}options=-c%20search_path%3D{schema}");
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect PostgreSQL count pool");
            (url, CountPool::Postgres(pool), Some((admin, schema)))
        }
        other => panic!("unknown P02_TEST_BACKEND: {other}"),
    };

    let root_secret = "R".repeat(32);
    let agent_secret = "A".repeat(32);
    for (name, value) in [
        ("root.secret", root_secret.as_str()),
        ("agent.secret", agent_secret.as_str()),
    ] {
        let path = directory.file(name);
        std::fs::write(&path, value).expect("write test credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test credential");
    }
    let config = Config::from_variables([
        ("BLINDPASS_LISTEN", "127.0.0.1:0"),
        ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
        ("BLINDPASS_UI_BASE_URL", "http://127.0.0.1:5175"),
        ("BLINDPASS_DATABASE_URL", database_url.as_str()),
        (
            "BLINDPASS_ROOT_SECRET_FILE",
            directory.file("root.secret").to_str().unwrap(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            directory.file("agent.secret").to_str().unwrap(),
        ),
        ("BLINDPASS_TEST_MODE", "1"),
        ("BLINDPASS_AGENT_REQUEST_RATE_LIMIT", "2"),
        ("BLINDPASS_AGENT_EXCHANGE_RATE_LIMIT", "2"),
        ("BLINDPASS_TEST_AGENT_RATE_WINDOW_MS", "1000"),
    ])
    .expect("valid rate-limit test configuration");
    let store = Store::connect(&database_url)
        .await
        .expect("connect rate-limit store");
    let tenant = store.tenant_id().to_owned();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP test listener");
    let address = listener.local_addr().expect("HTTP test listener address");
    let app: Router = build_app(config, Some(store.clone()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let no_auth = request(
        address,
        "POST",
        "/api/v2/secret/request",
        None,
        Some(&json!({"public_key":"YQ==","description":"request without auth"})),
    )
    .await;
    assert_eq!(no_auth.status, 401);
    let foreign = workload_token(&[b'A'; 32], "rate-agent-a", "foreign-tenant");
    let foreign_scope = request(
        address,
        "POST",
        "/api/v2/secret/request",
        Some(&foreign),
        Some(&json!({"public_key":"YQ==","description":"foreign scope"})),
    )
    .await;
    assert_eq!(foreign_scope.status, 403);
    assert_eq!(count_pool.count("rate_windows").await, 0);

    let agent_a = workload_token(&[b'A'; 32], "rate-agent-a", &tenant);
    for index in 0..2 {
        let response = request(
            address,
            "POST",
            "/api/v2/secret/request",
            Some(&agent_a),
            Some(&json!({"public_key":"YQ==","description":format!("agent request {index}")})),
        )
        .await;
        assert_eq!(
            response.status, 201,
            "allowed request response: {}",
            response.text
        );
    }
    let requests_before_limit = count_pool.count("secret_requests").await;
    let limited = request(
        address,
        "POST",
        "/api/v2/secret/request",
        Some(&agent_a),
        Some(&json!({"public_key":"YQ==","description":"request limit canary"})),
    )
    .await;
    assert_eq!(limited.status, 429);
    let retry_after = limited
        .headers
        .iter()
        .find(|(name, _)| name == "retry-after")
        .expect("Retry-After header")
        .1
        .parse::<u64>()
        .expect("Retry-After seconds");
    assert!(retry_after > 0);
    assert_eq!(limited.body["error"], "Too many secret requests");
    assert_eq!(limited.body["code"], "rate_limited");
    assert_eq!(limited.body["limit"], 2);
    assert_eq!(limited.body["used"], 3);
    assert!(limited.body.get("request_id").is_none());
    assert!(limited.body.get("secret_name").is_none());
    assert_eq!(
        count_pool.count("secret_requests").await,
        requests_before_limit
    );

    let agent_b = workload_token(&[b'A'; 32], "rate-agent-b", &tenant);
    let independent = request(
        address,
        "POST",
        "/api/v2/secret/request",
        Some(&agent_b),
        Some(&json!({"public_key":"YQ==","description":"independent agent"})),
    )
    .await;
    assert_eq!(independent.status, 201);

    let exchange_body = json!({
        "public_key":"YQ==",
        "secret_name":"not-registered.secret",
        "purpose":"rate limit probe",
        "fulfiller_hint":"billing/ring/green"
    });
    for _ in 0..2 {
        let denied = request(
            address,
            "POST",
            "/api/v2/secret/exchange/request",
            Some(&agent_a),
            Some(&exchange_body),
        )
        .await;
        assert_eq!(
            denied.status, 403,
            "policy denial response: {}",
            denied.text
        );
    }
    let exchanges_before_limit = count_pool.count("exchanges").await;
    let exchange_limited = request(
        address,
        "POST",
        "/api/v2/secret/exchange/request",
        Some(&agent_a),
        Some(&exchange_body),
    )
    .await;
    assert_eq!(exchange_limited.status, 429);
    let retry_after = exchange_limited
        .headers
        .iter()
        .find(|(name, _)| name == "retry-after")
        .expect("exchange Retry-After header")
        .1
        .parse::<u64>()
        .expect("exchange Retry-After seconds");
    assert!(retry_after > 0);
    assert_eq!(exchange_limited.body["error"], "Too many exchange requests");
    assert_eq!(exchange_limited.body["limit"], 2);
    assert_eq!(exchange_limited.body["used"], 3);
    assert!(!exchange_limited.text.contains("not-registered.secret"));
    assert_eq!(count_pool.count("exchanges").await, exchanges_before_limit);

    let rate_events: i64 = match &count_pool {
        CountPool::Sqlite(pool) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'agent_rate_limited'",
        )
        .fetch_one(pool)
        .await
        .expect("count SQLite rate audit events"),
        CountPool::Postgres(pool) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'agent_rate_limited'",
        )
        .fetch_one(pool)
        .await
        .expect("count PostgreSQL rate audit events"),
    };
    assert_eq!(rate_events, 2, "one audit event per agent and route window");

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let reset = request(
        address,
        "POST",
        "/api/v2/secret/request",
        Some(&agent_a),
        Some(&json!({"public_key":"YQ==","description":"window reset"})),
    )
    .await;
    assert_eq!(reset.status, 201, "window reset response: {}", reset.text);

    server.abort();
    store.close().await;
    count_pool.close().await;
    if let Some((admin, schema)) = schema_cleanup {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&admin)
            .await
            .expect("drop isolated PostgreSQL rate-limit schema");
        admin.close().await;
    }
}

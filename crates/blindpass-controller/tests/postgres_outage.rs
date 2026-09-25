// SPDX-License-Identifier: AGPL-3.0-only

//! P02-I07 database outage and reconnection. PostgreSQL only: the test
//! creates a dedicated login role, cuts it off mid-run and restores it,
//! so other connections to the shared test database are not affected.
//! Run with `P02_TEST_POSTGRES_URL=... cargo test -p blindpass-controller
//! --test postgres_outage -- --ignored`.

use axum::Router;
use blindpass_controller::{app::build_app, config::Config, store::Store};
use sqlx::postgres::PgPoolOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn readyz(address: std::net::SocketAddr) -> (u16, String) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect local HTTP test server");
    stream
        .write_all(
            format!("GET /readyz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("send readiness request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read readiness response");
    let response = String::from_utf8(response).expect("UTF-8 readiness response");
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("HTTP status code");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

async fn wait_for_readiness(address: std::net::SocketAddr, expected: u16) -> String {
    let mut last = (0, String::new());
    for _ in 0..100 {
        last = readyz(address).await;
        if last.0 == expected {
            return last.1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "readiness did not reach {expected}; last status {} body {}",
        last.0, last.1
    );
}

#[tokio::test]
#[ignore = "PostgreSQL only: set P02_TEST_POSTGRES_URL and run with --ignored"]
async fn readiness_fails_during_postgres_outage_and_recovers_with_state_intact() {
    let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
        .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
        .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let role = format!("p02_outage_{}_{nonce}", std::process::id());
    let password = format!("dummy-outage-{nonce}");
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&parent_url)
        .await
        .expect("connect PostgreSQL administration pool");
    sqlx::query(&format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"
    ))
    .execute(&admin)
    .await
    .expect("create dedicated outage role");
    sqlx::query(&format!(
        "CREATE SCHEMA \"{role}\" AUTHORIZATION \"{role}\""
    ))
    .execute(&admin)
    .await
    .expect("create isolated outage schema");

    let (_, after_scheme) = parent_url
        .split_once("://")
        .expect("PostgreSQL URL has a scheme");
    let host_and_rest = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    let separator = if host_and_rest.contains('?') {
        '&'
    } else {
        '?'
    };
    let database_url = format!(
        "postgresql://{role}:{password}@{host_and_rest}{separator}options=-c%20search_path%3D{role}"
    );

    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "blindpass-postgres-outage-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir_all(&directory.0).expect("create outage test directory");
    for (name, value) in [
        ("database.url", database_url.clone()),
        ("root.secret", "R".repeat(32)),
        ("agent.secret", "A".repeat(32)),
        ("issuer.seed", "I".repeat(32)),
    ] {
        let path = directory.0.join(name);
        std::fs::write(&path, value).expect("write test credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test credential");
    }
    let file = |name: &str| directory.0.join(name).to_str().unwrap().to_owned();
    let config = Config::from_variables([
        ("BLINDPASS_LISTEN", "127.0.0.1:0"),
        ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
        ("BLINDPASS_UI_BASE_URL", "http://127.0.0.1:5175"),
        ("BLINDPASS_DATABASE_URL_FILE", file("database.url").as_str()),
        ("BLINDPASS_ROOT_SECRET_FILE", file("root.secret").as_str()),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            file("agent.secret").as_str(),
        ),
        ("BLINDPASS_ISSUER_KEY_FILE", file("issuer.seed").as_str()),
    ])
    .expect("valid local test config");
    let store = Store::connect(&database_url)
        .await
        .expect("connect controller store as the outage role");
    let request_id = store
        .create_secret_request("outage-agent", "dummy-public-key", "outage", "123456", 120)
        .await
        .expect("create durable state before the outage");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local HTTP test listener");
    let address = listener.local_addr().expect("resolve test address");
    let app: Router = build_app(config, Some(store.clone()));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    wait_for_readiness(address, 200).await;

    sqlx::query(&format!("ALTER ROLE \"{role}\" NOLOGIN"))
        .execute(&admin)
        .await
        .expect("block new controller connections");
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1")
        .bind(&role)
        .execute(&admin)
        .await
        .expect("terminate live controller connections");
    let outage_body = wait_for_readiness(address, 503).await;
    assert!(
        outage_body.contains("\"database\":\"down\""),
        "{outage_body}"
    );
    for sensitive in [
        role.as_str(),
        password.as_str(),
        "postgresql://",
        "RRRR",
        "AAAA",
    ] {
        assert!(
            !outage_body.contains(sensitive),
            "readiness must not disclose connection details: {outage_body}"
        );
    }
    assert!(
        store.secret_request_metadata(&request_id).await.is_err(),
        "store operations fail closed while the database is unavailable"
    );

    sqlx::query(&format!("ALTER ROLE \"{role}\" LOGIN"))
        .execute(&admin)
        .await
        .expect("restore controller connections");
    wait_for_readiness(address, 200).await;
    assert!(
        store
            .secret_request_metadata(&request_id)
            .await
            .expect("read durable state after reconnection")
            .is_some(),
        "durable state survives the outage without a restart"
    );

    server.abort();
    let _ = server.await;
    store.close().await;
    sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{role}\" CASCADE"))
        .execute(&admin)
        .await
        .expect("drop isolated outage schema");
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1")
        .bind(&role)
        .execute(&admin)
        .await
        .expect("terminate remaining outage connections");
    sqlx::query(&format!("DROP ROLE IF EXISTS \"{role}\""))
        .execute(&admin)
        .await
        .expect("drop dedicated outage role");
    admin.close().await;
}

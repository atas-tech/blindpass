// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::{app::build_app, config::Config, store::Store};
use serde_json::Value;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream as BlockingTcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

struct TestFiles(PathBuf);

impl TestFiles {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-controller-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn credential(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write test credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("set private test credential mode");
        path
    }
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn valid_test_config(files: &TestFiles) -> Config {
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let values = BTreeMap::from([
        ("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned()),
        ("BLINDPASS_LISTEN".to_owned(), "127.0.0.1:0".to_owned()),
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "http://127.0.0.1:3200".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "http://127.0.0.1:3100".to_owned(),
        ),
        (
            "BLINDPASS_DATABASE_URL".to_owned(),
            "sqlite::memory:".to_owned(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
            root_secret.display().to_string(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
            agent_secret.display().to_string(),
        ),
    ]);
    Config::from_variables(values).expect("valid test configuration")
}

#[test]
fn test_overrides_are_rejected_unless_test_mode_is_explicit_and_nonproduction() {
    let files = TestFiles::new();
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let base = BTreeMap::from([
        (
            "BLINDPASS_DATABASE_URL".to_owned(),
            "sqlite::memory:".to_owned(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
            root_secret.display().to_string(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
            agent_secret.display().to_string(),
        ),
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "http://127.0.0.1:3200".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "http://127.0.0.1:3100".to_owned(),
        ),
        (
            "BLINDPASS_TEST_REQUEST_TTL_SECONDS".to_owned(),
            "3".to_owned(),
        ),
        (
            "BLINDPASS_TEST_REFRESH_TOKEN_TTL_SECONDS".to_owned(),
            "10".to_owned(),
        ),
    ]);

    assert!(Config::from_variables(base.clone()).is_err());
    let mut production = base.clone();
    production.insert("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned());
    production.insert("NODE_ENV".to_owned(), "production".to_owned());
    assert!(Config::from_variables(production).is_err());
    let mut enabled = base;
    enabled.insert("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned());
    let config = Config::from_variables(enabled).expect("explicit test overrides are accepted");
    assert_eq!(config.request_ttl_seconds(), 3);
    assert_eq!(config.refresh_token_ttl_seconds(), 10);
}

#[test]
fn production_configuration_requires_file_backed_database_and_key_material() {
    let files = TestFiles::new();
    let database = files.credential("database.url", b"sqlite::memory:");
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let base = BTreeMap::from([
        (
            "BLINDPASS_DATABASE_URL_FILE".to_owned(),
            database.display().to_string(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
            root_secret.display().to_string(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
            agent_secret.display().to_string(),
        ),
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "https://blindpass.example".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "https://input.blindpass.example".to_owned(),
        ),
    ]);

    assert!(Config::from_variables(base.clone()).is_ok());
    let mut plain_database = base.clone();
    plain_database.remove("BLINDPASS_DATABASE_URL_FILE");
    plain_database.insert(
        "BLINDPASS_DATABASE_URL".to_owned(),
        "sqlite::memory:".to_owned(),
    );
    assert!(Config::from_variables(plain_database).is_err());
    let mut conflicting = base;
    conflicting.insert(
        "BLINDPASS_DATABASE_URL".to_owned(),
        "sqlite::memory:".to_owned(),
    );
    assert!(Config::from_variables(conflicting).is_err());
}

#[test]
fn missing_or_unsafe_production_credentials_fail_without_disclosing_contents() {
    let files = TestFiles::new();
    let database = files.credential("database.url", b"sqlite::memory:");
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let mut values = BTreeMap::from([
        (
            "BLINDPASS_DATABASE_URL_FILE".to_owned(),
            database.display().to_string(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
            root_secret.display().to_string(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
            agent_secret.display().to_string(),
        ),
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "https://blindpass.example".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "https://input.blindpass.example".to_owned(),
        ),
    ]);

    std::fs::remove_file(&root_secret).expect("remove root credential");
    let missing = Config::from_variables(values.clone())
        .err()
        .expect("missing root credential must fail");
    assert!(missing.to_string().contains("BLINDPASS_ROOT_SECRET_FILE"));
    assert!(!missing.to_string().contains("RRRR"));
    assert!(
        !root_secret.exists(),
        "configuration must not replace a missing key"
    );

    let truncated_root = files.credential("truncated-root.secret", b"bad");
    values.insert(
        "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
        truncated_root.display().to_string(),
    );
    let truncated_error = Config::from_variables(values.clone())
        .err()
        .expect("truncated root credential must fail");
    assert!(
        truncated_error
            .to_string()
            .contains("BLINDPASS_ROOT_SECRET_FILE")
    );
    assert!(!truncated_error.to_string().contains("bad"));
    assert_eq!(
        std::fs::read(&truncated_root).expect("read unchanged key"),
        b"bad"
    );

    let unsafe_root = files.credential("unsafe-root.secret", &[b'R'; 32]);
    std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o644))
        .expect("make root credential unsafe");
    values.insert(
        "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
        unsafe_root.display().to_string(),
    );
    let unsafe_error = Config::from_variables(values)
        .err()
        .expect("unsafe root credential must fail");
    assert!(
        unsafe_error
            .to_string()
            .contains("BLINDPASS_ROOT_SECRET_FILE")
    );
    assert!(!unsafe_error.to_string().contains("RRRR"));
}

#[test]
fn inaccessible_production_database_prevents_startup_with_sanitized_error() {
    let files = TestFiles::new();
    let database_path = files.0.join("missing-parent").join("controller.db");
    let database_url = format!("sqlite://{}", database_path.display());
    let database = files.credential("database.url", database_url.as_bytes());
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .arg("serve")
        .env_clear()
        .env("BLINDPASS_LISTEN", "127.0.0.1:0")
        .env("BLINDPASS_DATABASE_URL_FILE", &database)
        .env("BLINDPASS_ROOT_SECRET_FILE", &root_secret)
        .env("BLINDPASS_AGENT_JWT_SECRET_FILE", &agent_secret)
        .env("BLINDPASS_PUBLIC_URL", "https://blindpass.example")
        .env("BLINDPASS_UI_BASE_URL", "https://input.blindpass.example")
        .output()
        .expect("run controller against an inaccessible database");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 controller error");
    assert!(stderr.contains("controller database initialization failed"));
    assert!(!stderr.contains(&database_url));
    assert!(!stderr.contains("RRRR"));
    assert!(!stderr.contains("AAAA"));
    assert!(!database_path.exists());
}

#[tokio::test]
async fn damaged_existing_schema_prevents_startup_without_recreation() {
    let files = TestFiles::new();
    let database_path = files.0.join("damaged.db");
    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let store = Store::connect(&database_url)
        .await
        .expect("initialize disposable controller database");
    store.close().await;
    let pool = sqlx::SqlitePool::connect(&database_url)
        .await
        .expect("open disposable database for corruption test");
    sqlx::query("DROP TABLE secret_requests")
        .execute(&pool)
        .await
        .expect("remove required table");
    pool.close().await;

    let database = files.credential("database.url", database_url.as_bytes());
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .arg("serve")
        .env_clear()
        .env("BLINDPASS_LISTEN", "127.0.0.1:0")
        .env("BLINDPASS_DATABASE_URL_FILE", &database)
        .env("BLINDPASS_ROOT_SECRET_FILE", &root_secret)
        .env("BLINDPASS_AGENT_JWT_SECRET_FILE", &agent_secret)
        .env("BLINDPASS_PUBLIC_URL", "https://blindpass.example")
        .env("BLINDPASS_UI_BASE_URL", "https://input.blindpass.example")
        .output()
        .expect("run controller against damaged schema");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 controller error");
    assert!(stderr.contains("controller database initialization failed"));
    assert!(!stderr.contains(&database_url));
    assert!(!stderr.contains("RRRR"));
    assert!(!stderr.contains("AAAA"));
    let pool = sqlx::SqlitePool::connect(&database_url)
        .await
        .expect("inspect damaged database after denied startup");
    let recreated: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'secret_requests')",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect schema after denial");
    assert_eq!(recreated, 0);
    pool.close().await;
}

#[test]
fn migrate_command_initializes_database_without_starting_listener() {
    let files = TestFiles::new();
    let database_path = files.0.join("migrated.db");
    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let database = files.credential("database.url", database_url.as_bytes());
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .arg("migrate")
        .env_clear()
        .env("BLINDPASS_DATABASE_URL_FILE", &database)
        .env("BLINDPASS_ROOT_SECRET_FILE", &root_secret)
        .env("BLINDPASS_AGENT_JWT_SECRET_FILE", &agent_secret)
        .env("BLINDPASS_PUBLIC_URL", "https://blindpass.example")
        .env("BLINDPASS_UI_BASE_URL", "https://input.blindpass.example")
        .output()
        .expect("run migration command");
    assert!(
        output.status.success(),
        "migration command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(database_path.exists());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 migration output");
    assert!(stdout.contains("migrations complete"));
    assert!(!stdout.contains(&database_url));
}

#[tokio::test]
async fn seed_command_uses_test_fixture_and_rejects_production_mode() {
    let files = TestFiles::new();
    let database_path = files.0.join("seeded.db");
    let (database_url, postgres_schema): (String, Option<(PgPool, String)>) =
        if std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres") {
            let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("PostgreSQL test URL is required");
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let schema = format!("p02_seed_{}_{nonce}", std::process::id());
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&parent_url)
                .await
                .expect("connect PostgreSQL seed fixture");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&pool)
                .await
                .expect("create isolated seed schema");
            let separator = if parent_url.contains('?') { '&' } else { '?' };
            (
                format!("{parent_url}{separator}options=-c%20search_path%3D{schema}"),
                Some((pool, schema)),
            )
        } else {
            assert!(matches!(
                std::env::var("P02_TEST_BACKEND").as_deref(),
                Ok("sqlite") | Err(_)
            ));
            (
                format!("sqlite://{}?mode=rwc", database_path.display()),
                None,
            )
        };
    let database = files.credential("database.url", database_url.as_bytes());
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let fixture = files.credential(
        "fixture.json",
        br#"{"agents":["seed-agent","rotated-agent","revoked-agent"],"policy":{"secret_registry":[],"exchange_policy":[]},"rotated_agents":["rotated-agent"],"revoked_agents":["revoked-agent"],"local_admin":true}"#,
    );
    let run = |test_mode: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        command
            .arg("seed")
            .arg("--fixture")
            .arg(&fixture)
            .env_clear()
            .env("BLINDPASS_DATABASE_URL_FILE", &database)
            .env("BLINDPASS_ROOT_SECRET_FILE", &root_secret)
            .env("BLINDPASS_AGENT_JWT_SECRET_FILE", &agent_secret)
            .env("BLINDPASS_PUBLIC_URL", "https://blindpass.example")
            .env("BLINDPASS_UI_BASE_URL", "https://input.blindpass.example");
        if test_mode {
            command.env("BLINDPASS_TEST_MODE", "1");
        }
        command.output().expect("run seed command")
    };
    let denied = run(false);
    assert!(!denied.status.success());
    if let Some((pool, schema)) = &postgres_schema {
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1",
        )
        .bind(schema)
        .fetch_one(pool)
        .await
        .expect("inspect denied PostgreSQL seed");
        assert_eq!(tables, 0, "production denial must precede migration");
    } else {
        assert!(
            !database_path.exists(),
            "production denial must precede database access"
        );
    }
    let allowed = run(true);
    assert!(
        allowed.status.success(),
        "test seed failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let response: Value = serde_json::from_slice(&allowed.stdout).expect("seed JSON response");
    assert!(response["access_token"].as_str().is_some());
    assert!(response["agents"]["seed-agent"].as_str().is_some());
    assert!(response["agents"]["rotated-agent"].as_str().is_some());
    assert!(response["agents"]["revoked-agent"].as_str().is_some());
    assert!(
        response["local_admin"]["temporary_password"]
            .as_str()
            .is_some()
    );
    assert!(response["local_admin"]["session_id"].as_str().is_some());
    if postgres_schema.is_none() {
        assert!(database_path.exists());
    }
    let store = Store::connect(&database_url)
        .await
        .expect("reopen seeded controller store");
    assert_eq!(store.list_admin_agents().await.unwrap().len(), 3);
    let rotated = store
        .agent_by_agent_id("rotated-agent")
        .await
        .unwrap()
        .expect("rotated agent");
    assert_eq!(rotated.key_version, 2);
    let revoked = store
        .agent_by_agent_id("revoked-agent")
        .await
        .unwrap()
        .expect("revoked agent");
    assert_eq!(revoked.status, "revoked");
    assert!(store.policy_document().await.unwrap().is_some());
    assert!(store.has_active_admin().await.unwrap());
    store.close().await;
    if let Some((pool, schema)) = postgres_schema {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated seed schema");
        pool.close().await;
    }
}

#[tokio::test]
async fn reconcile_clock_command_repairs_a_regressed_database_without_test_mode() {
    let files = TestFiles::new();
    let database_path = files.0.join("regressed.db");
    let (database_url, postgres_schema): (String, Option<(PgPool, String)>) =
        if std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres") {
            let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("PostgreSQL test URL is required");
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let schema = format!("p02_clock_{}_{nonce}", std::process::id());
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&parent_url)
                .await
                .expect("connect PostgreSQL clock fixture");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&pool)
                .await
                .expect("create isolated clock schema");
            let separator = if parent_url.contains('?') { '&' } else { '?' };
            (
                format!("{parent_url}{separator}options=-c%20search_path%3D{schema}"),
                Some((pool, schema)),
            )
        } else {
            (
                format!("sqlite://{}?mode=rwc", database_path.display()),
                None,
            )
        };
    let store = Store::connect(&database_url)
        .await
        .expect("initialize disposable controller database");
    let request_id = store
        .create_secret_request("clock-agent", "dummy-public-key", "reconcile", "123456", 60)
        .await
        .expect("create request before regression");
    store.close().await;
    if postgres_schema.is_some() {
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect PostgreSQL clock fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = $1 WHERE id = 1")
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .expect("simulate persisted future clock");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&database_url)
            .await
            .expect("connect SQLite clock fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = ? WHERE id = 1")
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .expect("simulate persisted future clock");
        pool.close().await;
    }
    assert!(Store::connect(&database_url).await.is_err());

    let database = files.credential("database.url", database_url.as_bytes());
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .arg("reconcile-clock")
            .env_clear()
            .env("BLINDPASS_DATABASE_URL_FILE", &database)
            .env("BLINDPASS_ROOT_SECRET_FILE", &root_secret)
            .env("BLINDPASS_AGENT_JWT_SECRET_FILE", &agent_secret)
            .env("BLINDPASS_PUBLIC_URL", "https://blindpass.example")
            .env("BLINDPASS_UI_BASE_URL", "https://input.blindpass.example")
            .output()
            .expect("run clock reconciliation")
    };
    let repaired = run();
    assert!(
        repaired.status.success(),
        "reconciliation failed: {}",
        String::from_utf8_lossy(&repaired.stderr)
    );
    let stdout = String::from_utf8(repaired.stdout).expect("UTF-8 reconciliation output");
    assert!(!stdout.contains(&database_url));
    let summary: Value = serde_json::from_str(stdout.trim()).expect("JSON reconciliation summary");
    assert_eq!(summary["regression_detected"], true);
    assert_eq!(summary["removed_secret_requests"], 1);

    let reopened = Store::connect(&database_url)
        .await
        .expect("controller starts after reconciliation");
    assert!(
        reopened
            .secret_request_metadata(&request_id)
            .await
            .expect("read request after reconciliation")
            .is_none(),
        "expiring state created under the regressed clock is removed"
    );
    reopened.close().await;

    let healthy = run();
    assert!(healthy.status.success());
    let summary: Value =
        serde_json::from_slice(&healthy.stdout).expect("JSON summary for a healthy clock");
    assert_eq!(summary["regression_detected"], false);
    if let Some((pool, schema)) = postgres_schema {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated clock schema");
        pool.close().await;
    }
}

#[tokio::test]
async fn production_shell_has_no_seed_route_or_test_override() {
    let files = TestFiles::new();
    let database = files.credential("database.url", b"sqlite::memory:");
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    let values = BTreeMap::from([
        (
            "BLINDPASS_DATABASE_URL_FILE".to_owned(),
            database.display().to_string(),
        ),
        (
            "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
            root_secret.display().to_string(),
        ),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
            agent_secret.display().to_string(),
        ),
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "https://blindpass.example".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "https://input.blindpass.example".to_owned(),
        ),
    ]);
    let config = Config::from_variables(values).expect("valid production configuration");
    assert!(!config.is_test_mode());
    let app = build_app(config, None);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test listener");
    let address = listener.local_addr().expect("resolve local listener");
    let server =
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve shell") });

    let (status, body) = raw_request(&address.to_string(), "POST", "/api/v3/admin/test/seed").await;
    assert_eq!(status, 404);
    assert!(!body.contains("RRRR"));
    assert!(!body.contains("AAAA"));
    server.abort();
}

#[tokio::test]
async fn shell_exposes_liveness_readiness_and_ct19_capability_without_sensitive_details() {
    let files = TestFiles::new();
    let config = valid_test_config(&files);
    let app = build_app(config, None);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test listener");
    let address = listener.local_addr().expect("resolve local listener");
    let server =
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve shell") });

    let address = address.to_string();
    let health = request(&address, "GET", "/healthz").await;
    assert_eq!(health.0, 200);
    assert_eq!(health.1, serde_json::json!({"ok": true}));

    let readiness = request(&address, "GET", "/readyz").await;
    assert_eq!(readiness.0, 503);
    assert_eq!(
        readiness.1,
        serde_json::json!({"ok": false, "checks": {"database": "down"}})
    );
    assert!(!readiness.1.to_string().to_lowercase().contains("secret"));

    let capabilities = request(&address, "GET", "/api/v3/capabilities").await;
    assert_eq!(capabilities.0, 200);
    assert_eq!(capabilities.1["features"]["browser_status"], true);
    assert_eq!(
        capabilities.1["api"],
        serde_json::json!(["compat.v2", "admin.v3"])
    );
    server.abort();
}

#[tokio::test]
async fn readiness_fails_after_live_database_pool_disconnects() {
    let files = TestFiles::new();
    let (database_url, postgres_schema): (String, Option<(PgPool, String)>) =
        if std::env::var("P02_TEST_BACKEND").as_deref() == Ok("postgres") {
            let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                .expect("PostgreSQL test URL is required");
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let schema = format!("p02_readiness_{}_{nonce}", std::process::id());
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&parent_url)
                .await
                .expect("connect PostgreSQL readiness fixture");
            sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                .execute(&pool)
                .await
                .expect("create isolated readiness schema");
            let separator = if parent_url.contains('?') { '&' } else { '?' };
            (
                format!("{parent_url}{separator}options=-c%20search_path%3D{schema}"),
                Some((pool, schema)),
            )
        } else {
            assert!(matches!(
                std::env::var("P02_TEST_BACKEND").as_deref(),
                Ok("sqlite") | Err(_)
            ));
            (
                format!(
                    "sqlite://{}?mode=rwc",
                    files.0.join("controller.db").display()
                ),
                None,
            )
        };
    let mut values = BTreeMap::new();
    let root_secret = files.credential("root.secret", &[b'R'; 32]);
    let agent_secret = files.credential("agent.secret", &[b'A'; 32]);
    values.insert("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned());
    values.insert("BLINDPASS_LISTEN".to_owned(), "127.0.0.1:0".to_owned());
    values.insert(
        "BLINDPASS_PUBLIC_URL".to_owned(),
        "http://127.0.0.1:3200".to_owned(),
    );
    values.insert(
        "BLINDPASS_UI_BASE_URL".to_owned(),
        "http://127.0.0.1:3100".to_owned(),
    );
    values.insert("BLINDPASS_DATABASE_URL".to_owned(), database_url.clone());
    values.insert(
        "BLINDPASS_ROOT_SECRET_FILE".to_owned(),
        root_secret.display().to_string(),
    );
    values.insert(
        "BLINDPASS_AGENT_JWT_SECRET_FILE".to_owned(),
        agent_secret.display().to_string(),
    );
    let config = Config::from_variables(values).expect("valid live readiness fixture");
    let store = Store::connect(&database_url)
        .await
        .expect("connect live database");
    let app = build_app(config, Some(store.clone()));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local readiness test listener");
    let address = listener.local_addr().expect("resolve readiness address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve readiness test")
    });

    let address = address.to_string();
    assert_eq!(request(&address, "GET", "/readyz").await.0, 200);
    store.close().await;
    let (status, body) = request(&address, "GET", "/readyz").await;
    assert_eq!(status, 503);
    assert_eq!(
        body,
        serde_json::json!({"ok":false,"checks":{"database":"down"}})
    );
    assert_eq!(request(&address, "GET", "/healthz").await.0, 200);
    server.abort();
    if let Some((pool, schema)) = postgres_schema {
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated readiness schema");
        pool.close().await;
    }
}

async fn request(address: &str, method: &str, path: &str) -> (u16, Value) {
    let (status, body) = raw_request(address, method, path).await;
    (
        status,
        serde_json::from_str(&body).expect("JSON response body"),
    )
}

async fn raw_request(address: &str, method: &str, path: &str) -> (u16, String) {
    let address = address.to_owned();
    let method = method.to_owned();
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut stream = BlockingTcpStream::connect(address).expect("connect to test server");
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
        )
        .expect("write HTTP request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read HTTP response");
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .expect("HTTP response separator");
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .expect("HTTP status");
        (status, body.to_owned())
    })
    .await
    .expect("HTTP test task")
}

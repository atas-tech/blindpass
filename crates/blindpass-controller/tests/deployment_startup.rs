// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use blindpass_controller::store::{Store, StoreError};
use serde_json::json;
use sqlx::SqlitePool;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::{Harness, TestDirectory, raw_request};

struct Fixture {
    directory: TestDirectory,
    values: BTreeMap<String, String>,
    url: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = TestDirectory::new();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["keys", "data", "run"] {
            fs::create_dir(directory.file(name)).unwrap();
            fs::set_permissions(directory.file(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, byte) in [
            ("root-secret", b'R'),
            ("agent-jwt-secret", b'A'),
            ("issuer-key", b'I'),
        ] {
            let path = directory.file("keys").join(name);
            fs::write(&path, [byte; 32]).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.file("data/controller.db").display()
        );
        let values = BTreeMap::from([
            (
                "BLINDPASS_KEYS_DIR".into(),
                directory.file("keys").display().to_string(),
            ),
            (
                "BLINDPASS_DATA_DIR".into(),
                directory.file("data").display().to_string(),
            ),
            (
                "BLINDPASS_PUBLIC_URL".into(),
                "https://blindpass.example".into(),
            ),
            (
                "BLINDPASS_UI_BASE_URL".into(),
                "https://blindpass.example".into(),
            ),
            (
                "BLINDPASS_ADMIN_SOCKET_PATH".into(),
                directory.file("run/admin.sock").display().to_string(),
            ),
            ("BLINDPASS_LISTEN".into(), "127.0.0.1:0".into()),
        ]);
        Self {
            directory,
            values,
            url,
        }
    }

    // Production startup now needs a separate protected authority even when
    // testing absent/damaged local state. Unavailable authority is not schema proof.
    async fn authority(&mut self, phase: &str, tenant: Option<&str>) {
        let tenant = tenant
            .map(str::to_owned)
            .unwrap_or_else(|| support::unique("P06_DUMMY_STARTUP"));
        let issuer = format!(
            "ed25519-{}",
            blindpass_core::signing::base64_url_encode(
                blindpass_core::signing::ed25519::Ed25519KeyPair::from_seed(&[b'I'; 32])
                    .unwrap()
                    .public_key()
            )
        );
        let admin = sqlx::PgPool::connect(
            &std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").expect("owned authority fixture"),
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO blindpass_authority.recovery_authority (tenant_id,issuer_key_id,owner_id,epoch,revision,phase) VALUES ($1,$2,'P06_DUMMY_STARTUP_OWNER',1,1,$3)")
            .bind(&tenant).bind(issuer).bind(phase).execute(&admin).await.unwrap();
        admin.close().await;
        let path = self.directory.file("authority-url");
        fs::write(
            &path,
            std::env::var("P06_TEST_AUTHORITY_URL").expect("owned authority runtime"),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        self.values.insert(
            "BLINDPASS_AUTHORITY_URL_FILE".into(),
            path.display().to_string(),
        );
        self.values
            .insert("BLINDPASS_CONTROLLER_TENANT_ID".into(), tenant);
        self.values.insert(
            "BLINDPASS_CONTROLLER_OWNER_ID".into(),
            "P06_DUMMY_STARTUP_OWNER".into(),
        );
    }

    async fn next_active_revision(&self) {
        let admin = sqlx::PgPool::connect(&std::env::var("P06_TEST_AUTHORITY_ADMIN_URL").unwrap())
            .await
            .unwrap();
        sqlx::query("UPDATE blindpass_authority.recovery_authority SET phase='active',revision=revision+1 WHERE tenant_id=$1")
            .bind(&self.values["BLINDPASS_CONTROLLER_TENANT_ID"]).execute(&admin).await.unwrap();
        admin.close().await;
    }

    fn command(&self, command: &str) -> Command {
        let mut child = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        child.env_clear().envs(&self.values).arg(command);
        child
    }

    fn refusal(&self, reason: &str) {
        let mut child = self
            .command("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("serve accepted unsafe state");
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(reason), "missing fixed diagnostic: {error}");
        let event: serde_json::Value =
            serde_json::from_str(error.trim()).expect("structured startup failure");
        assert_eq!(event, json!({"event":"startup_failed","reason":reason}));
        assert!(!error.contains(self.directory.0.to_str().unwrap()));
        assert!(!error.contains("RRRRRR"));
        assert!(!error.contains("AAAAAA"));
        assert!(!error.contains("sqlite://"));
    }
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_s01_serve_does_not_create_absent_sqlite_state_even_with_rwc_url() {
    let mut fixture = Fixture::new();
    fixture.authority("active", None).await;
    fixture.refusal("state_missing");
    assert!(!fixture.directory.file("data/controller.db").exists());
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_s02_serve_does_not_initialize_an_empty_existing_database() {
    let mut fixture = Fixture::new();
    fixture.authority("active", None).await;
    let pool = SqlitePool::connect(&fixture.url).await.unwrap();
    fixture.refusal("state_missing");
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name = 'controller_meta'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_s03_serve_does_not_migrate_or_repair_schema_versions() {
    for version in [15, 999] {
        let mut fixture = Fixture::new();
        let store = Store::connect(&fixture.url).await.unwrap();
        fixture.authority("active", Some(store.tenant_id())).await;
        store.close().await;
        let pool = SqlitePool::connect(&fixture.url).await.unwrap();
        sqlx::query("UPDATE controller_meta SET schema_version = ?")
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        fixture.refusal("schema_mismatch");
        let retained: i64 = sqlx::query_scalar("SELECT schema_version FROM controller_meta")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(retained, version);
        pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_s04_explicit_migrate_then_production_serve_preserves_identity_on_restart() {
    let mut fixture = Fixture::new();
    fixture.authority("fenced", None).await;
    let output = fixture.command("migrate").output().unwrap();
    assert!(output.status.success());
    let pool = SqlitePool::connect(&fixture.url).await.unwrap();
    let identity: (String, i64) =
        sqlx::query_as("SELECT tenant_id, issuer_epoch FROM controller_meta")
            .fetch_one(&pool)
            .await
            .unwrap();
    for _ in 0..2 {
        // A used active revision is never replayed, even after process death.
        // This explicit fixture authorization is not a production unfence API.
        fixture.next_active_revision().await;
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        fixture
            .values
            .insert("BLINDPASS_LISTEN".into(), address.to_string());
        let mut server = Server(
            fixture
                .command("serve")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut ready = false;
        for _ in 0..150 {
            assert!(server.0.try_wait().unwrap().is_none(), "serve exited");
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                let response = raw_request(address, "GET", "/readyz", &[], None).await;
                assert_eq!(response.status, 200);
                assert_eq!(
                    response.body,
                    json!({"ok":true,"checks":{"database":"up","authority":"up"}})
                );
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready);
        drop(server);
        // SIGKILL leaves the protected socket inode; the administration binder
        // is responsible for safely replacing a stale same-owner socket.
        let current: (String, i64) =
            sqlx::query_as("SELECT tenant_id, issuer_epoch FROM controller_meta")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(current, identity);
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the owned separate PostgreSQL authority driver"]
async fn p06_s05_serve_does_not_recreate_missing_trust_or_clock_metadata() {
    for table in ["controller_meta", "controller_clock"] {
        let mut fixture = Fixture::new();
        let store = Store::connect(&fixture.url).await.unwrap();
        fixture.authority("active", Some(store.tenant_id())).await;
        store.close().await;
        let pool = SqlitePool::connect(&fixture.url).await.unwrap();
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&pool)
            .await
            .unwrap();
        fixture.refusal("state_missing");
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        pool.close().await;
    }
}

#[tokio::test]
async fn p06_s06_readiness_has_sanitized_outage_and_recovery_reasons() {
    let harness = Harness::start().await;
    harness
        .execute(
            "UPDATE controller_clock SET fenced_at = 1 WHERE id = 1",
            vec![],
        )
        .await;
    let response = harness.request("GET", "/readyz", &[], None).await;
    assert_eq!(response.status, 503);
    assert_eq!(
        response.body,
        json!({"ok":false,"checks":{"database":"down"},"reason":"recovery_required"})
    );
    assert_eq!(
        harness.request("GET", "/healthz", &[], None).await.status,
        200
    );
    harness.store.close().await;
    let response = harness.request("GET", "/readyz", &[], None).await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body["reason"], "store_unavailable");
}

#[tokio::test]
async fn p06_s03_existing_store_rejects_incomplete_schema_on_each_adapter() {
    let harness = Harness::start().await;
    harness
        .execute("DROP TABLE fleet_provisioning_receipts", vec![])
        .await;
    assert!(matches!(
        Store::connect_existing(&harness.database_url, 2_000).await,
        Err(StoreError::UnsupportedSchemaVersion)
    ));
}

#[tokio::test]
async fn p06_s02_existing_store_refuses_absent_schema_on_each_adapter() {
    let harness = Harness::start().await;
    harness.execute("DROP TABLE controller_meta", vec![]).await;
    assert!(matches!(
        Store::connect_existing(&harness.database_url, 2_000).await,
        Err(StoreError::MissingState(_))
    ));
    // A second attempt still sees missing state; neither path invokes migrations.
    assert!(matches!(
        Store::connect_existing(&harness.database_url, 2_000).await,
        Err(StoreError::MissingState(_))
    ));
}

#[tokio::test]
async fn p06_s05_existing_store_never_fills_missing_metadata_on_each_adapter() {
    for table in ["controller_meta", "controller_clock"] {
        let harness = Harness::start().await;
        harness
            .execute(&format!("DELETE FROM {table}"), vec![])
            .await;
        assert!(matches!(
            Store::connect_existing(&harness.database_url, 2_000).await,
            Err(StoreError::MissingState(_))
        ));
        assert_eq!(
            harness
                .scalar_i64(&format!("SELECT count(*) FROM {table}"), vec![])
                .await,
            0
        );
    }
}

#[tokio::test]
async fn p06_s03_readiness_reports_changed_schema_on_each_adapter() {
    let harness = Harness::start().await;
    harness
        .execute(
            "UPDATE controller_meta SET schema_version = 999 WHERE id = 1",
            vec![],
        )
        .await;
    let response = harness.request("GET", "/readyz", &[], None).await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body["reason"], "schema_mismatch");
    assert_eq!(
        harness.request("GET", "/healthz", &[], None).await.status,
        200
    );
}

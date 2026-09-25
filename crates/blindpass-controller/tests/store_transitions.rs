// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::store::{
    ApprovalRecord, ExchangePolicyRecord, ExchangeRecord, SecretRequestStatus, Store, StoreError,
};
use blindpass_core::clock::{ClockError, ClockSample, ClockSource, SystemClock};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct StoreFixture {
    url: String,
    store: Option<Store>,
    sqlite_dir: Option<PathBuf>,
    postgres_schema: Option<String>,
    admin_pool: Option<PgPool>,
}

impl StoreFixture {
    async fn new() -> Self {
        match std::env::var("P02_TEST_BACKEND")
            .as_deref()
            .unwrap_or("sqlite")
        {
            "sqlite" => {
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock after Unix epoch")
                    .as_nanos();
                let directory = std::env::temp_dir()
                    .join(format!("blindpass-store-{}-{nonce}", std::process::id()));
                std::fs::create_dir_all(&directory).expect("create SQLite fixture directory");
                let url = format!(
                    "sqlite://{}?mode=rwc",
                    directory.join("controller.db").display()
                );
                let store = Store::connect(&url)
                    .await
                    .expect("connect SQLite controller store");
                Self {
                    url,
                    store: Some(store),
                    sqlite_dir: Some(directory),
                    postgres_schema: None,
                    admin_pool: None,
                }
            }
            "postgres" => {
                let parent_url = std::env::var("P02_TEST_POSTGRES_URL")
                    .or_else(|_| std::env::var("CONTRACT_DATABASE_URL"))
                    .expect("P02_TEST_POSTGRES_URL or CONTRACT_DATABASE_URL is required for PostgreSQL tests");
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock after Unix epoch")
                    .as_nanos();
                let schema = format!("p02_store_{}_{}", std::process::id(), nonce);
                let admin_pool = PgPoolOptions::new()
                    .max_connections(2)
                    .connect(&parent_url)
                    .await
                    .expect("connect disposable PostgreSQL fixture");
                sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
                    .execute(&admin_pool)
                    .await
                    .expect("create isolated PostgreSQL schema");
                let separator = if parent_url.contains('?') { '&' } else { '?' };
                let url = format!("{parent_url}{separator}options=-c%20search_path%3D{schema}");
                let store = Store::connect(&url)
                    .await
                    .expect("connect PostgreSQL controller store");
                Self {
                    url,
                    store: Some(store),
                    sqlite_dir: None,
                    postgres_schema: Some(schema),
                    admin_pool: Some(admin_pool),
                }
            }
            other => panic!("unknown P02_TEST_BACKEND value: {other}"),
        }
    }

    fn store(&self) -> &Store {
        self.store.as_ref().expect("store is open")
    }

    async fn restart(&mut self) {
        self.store.take();
        self.store = Some(
            Store::connect(&self.url)
                .await
                .expect("reconnect controller store after restart"),
        );
    }

    async fn close(mut self) {
        self.store.take();
        if let (Some(pool), Some(schema)) = (&self.admin_pool, &self.postgres_schema) {
            sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
                .execute(pool)
                .await
                .expect("drop isolated PostgreSQL fixture schema");
            pool.close().await;
        }
        if let Some(directory) = self.sqlite_dir.take() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

struct ManualClock(Mutex<ClockSample>);

impl ManualClock {
    fn new(sample: ClockSample) -> Self {
        Self(Mutex::new(sample))
    }

    fn set(&self, sample: ClockSample) {
        *self.0.lock().expect("manual clock lock") = sample;
    }
}

impl ClockSource for ManualClock {
    fn sample(&self) -> Result<ClockSample, ClockError> {
        Ok(self.0.lock().expect("manual clock lock").clone())
    }
}

async fn fixture_table_count(fixture: &StoreFixture, table: &str) -> i64 {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL count query");
        let count = sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .expect("count PostgreSQL fixture rows");
        pool.close().await;
        count
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite count query");
        let count = sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .expect("count SQLite fixture rows");
        pool.close().await;
        count
    }
}

async fn fixture_active_session_count(fixture: &StoreFixture) -> i64 {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL session query");
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM operator_sessions WHERE revoked_at IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("count active PostgreSQL sessions");
        pool.close().await;
        count
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite session query");
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM operator_sessions WHERE revoked_at IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("count active SQLite sessions");
        pool.close().await;
        count
    }
}

async fn fixture_action_count(fixture: &StoreFixture, action: &str) -> i64 {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL audit query");
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events WHERE action = $1")
                .bind(action)
                .fetch_one(&pool)
                .await
                .expect("count PostgreSQL audit events");
        pool.close().await;
        count
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite audit query");
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events WHERE action = ?")
                .bind(action)
                .fetch_one(&pool)
                .await
                .expect("count SQLite audit events");
        pool.close().await;
        count
    }
}

#[tokio::test]
async fn schema_migrations_are_repeatable_and_tenant_identity_is_stable() {
    let fixture = StoreFixture::new().await;
    let tenant = fixture.store().tenant_id().to_owned();
    let second = Store::connect(&fixture.url)
        .await
        .expect("repeat schema migration and initialization");
    assert_eq!(second.tenant_id(), tenant);
    drop(second);
    fixture.close().await;
}

#[tokio::test]
async fn unsupported_schema_version_fails_closed_before_migration() {
    let fixture = StoreFixture::new().await;
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL schema fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 999 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("set unsupported schema version");
        sqlx::query("DROP TABLE quota_counters")
            .execute(&pool)
            .await
            .expect("remove table to detect an unintended migration");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite schema fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 999 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("set unsupported schema version");
        sqlx::query("DROP TABLE quota_counters")
            .execute(&pool)
            .await
            .expect("remove table to detect an unintended migration");
        pool.close().await;
    }

    let error = Store::connect(&fixture.url)
        .await
        .err()
        .expect("unsupported schema must prevent startup");
    assert_eq!(
        error.to_string(),
        "controller schema version is unsupported"
    );
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL schema fixture");
        let recreated: bool =
            sqlx::query_scalar("SELECT to_regclass('quota_counters') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .expect("inspect PostgreSQL schema");
        assert!(!recreated, "unsupported schema must not be migrated");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite schema fixture");
        let recreated: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'quota_counters')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect SQLite schema");
        assert_eq!(recreated, 0, "unsupported schema must not be migrated");
        pool.close().await;
    }
    fixture.close().await;
}

#[tokio::test]
async fn missing_required_table_is_not_silently_recreated() {
    let fixture = StoreFixture::new().await;
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL schema fixture");
        sqlx::query("DROP TABLE secret_requests")
            .execute(&pool)
            .await
            .expect("remove required PostgreSQL table");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite schema fixture");
        sqlx::query("DROP TABLE secret_requests")
            .execute(&pool)
            .await
            .expect("remove required SQLite table");
        pool.close().await;
    }

    assert!(matches!(
        Store::connect(&fixture.url).await,
        Err(blindpass_controller::store::StoreError::UnsupportedSchemaVersion)
    ));
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL schema fixture");
        let recreated: bool =
            sqlx::query_scalar("SELECT to_regclass('secret_requests') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .expect("inspect PostgreSQL schema");
        assert!(!recreated, "damaged schema must not be migrated");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite schema fixture");
        let recreated: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'secret_requests')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect SQLite schema");
        assert_eq!(recreated, 0, "damaged schema must not be migrated");
        pool.close().await;
    }
    fixture.close().await;
}

#[tokio::test]
async fn persisted_clock_regression_denies_expiring_state_and_readiness() {
    let fixture = StoreFixture::new().await;
    let request_id = fixture
        .store()
        .create_secret_request(
            "clock-agent",
            "dummy-public-key",
            "clock check",
            "123456",
            60,
        )
        .await
        .expect("create request before clock regression");
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = $1 WHERE id = 1")
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .expect("simulate persisted future clock");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = ? WHERE id = 1")
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .expect("simulate persisted future clock");
        pool.close().await;
    }
    assert!(!fixture.store().is_ready().await);
    assert!(matches!(
        fixture.store().secret_request_metadata(&request_id).await,
        Err(StoreError::ClockFenced)
    ));
    assert!(matches!(
        fixture
            .store()
            .create_secret_request("clock-agent", "dummy-public-key", "later", "654321", 60)
            .await,
        Err(StoreError::ClockFenced)
    ));
    assert!(matches!(
        fixture.store().list_admin_agents().await,
        Err(StoreError::ClockFenced)
    ));
    assert!(matches!(
        fixture.store().sweep_expired(0).await,
        Err(StoreError::ClockFenced)
    ));
    let reconnected = Store::connect(&fixture.url)
        .await
        .expect("persistent clock fence remains available for reconciliation");
    assert!(!reconnected.is_ready().await);
    reconnected.close().await;
    fixture.close().await;
}

#[tokio::test]
async fn boot_change_fences_and_purges_transient_authority_but_keeps_sessions() {
    let mut fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    store
        .create_secret_request("clock-agent", "dummy-key", "restart request", "code", 60)
        .await
        .expect("create secret request before simulated reboot");
    store
        .create_exchange(exchange_record(&"b".repeat(64)), 60)
        .await
        .expect("create exchange before simulated reboot");
    store
        .create_approval(&short_lived_approval(&store, "apr_restart_pending"))
        .await
        .expect("create pending approval before simulated reboot");
    store
        .issue_bootstrap_token("dummy-bootstrap-hash", 900)
        .await
        .expect("issue bootstrap token before simulated reboot");
    store
        .consume_rate_limit("rate-window-before-reboot", 10, 60_000)
        .await
        .expect("create rate window before simulated reboot");
    store
        .bootstrap_local_operator(
            "op-restart",
            "admin",
            "Restart Admin",
            "dummy-password-hash",
        )
        .await
        .expect("create local operator");
    store
        .create_browser_session(
            "op-restart",
            "dummy-password-hash",
            "dummy-refresh-hash",
            3_600,
        )
        .await
        .expect("create operator browser session")
        .expect("operator is active");

    let mut sample = SystemClock.sample().expect("sample system clock");
    sample.boot_id = Some("simulated-next-boot".to_owned());
    sample.boottime_ms = sample.boottime_ms.saturating_sub(10_000).max(0);
    let manual_clock = Arc::new(ManualClock::new(sample.clone()));
    fixture.store.take();
    let fenced = Store::connect_with_clock_source(&fixture.url, manual_clock.clone(), 2_000)
        .await
        .expect("boot change fences the process instead of trusting transient authority");
    assert!(!fenced.is_ready().await);
    assert!(matches!(
        fenced.list_admin_agents().await,
        Err(StoreError::ClockFenced)
    ));
    assert_eq!(fixture_table_count(&fixture, "secret_requests").await, 0);
    assert_eq!(fixture_table_count(&fixture, "exchanges").await, 0);
    assert_eq!(fixture_table_count(&fixture, "approvals").await, 0);
    assert_eq!(fixture_table_count(&fixture, "bootstrap_tokens").await, 0);
    assert_eq!(fixture_table_count(&fixture, "rate_windows").await, 0);
    assert_eq!(fixture_active_session_count(&fixture).await, 1);
    assert_eq!(
        fixture_action_count(&fixture, "clock_restart_fence").await,
        1
    );

    sample.boottime_ms = sample.boottime_ms.saturating_add(1_000);
    manual_clock.set(sample);
    drop(fenced);
    let reconnected = Store::connect_with_clock_source(&fixture.url, manual_clock, 2_000)
        .await
        .expect("persistent restart fence survives reconnection");
    assert!(!reconnected.is_ready().await);
    assert_eq!(
        fixture_action_count(&fixture, "clock_restart_fence").await,
        1
    );
    reconnected.close().await;
    fixture.close().await;
}

#[tokio::test]
async fn unreadable_boot_id_fences_and_purges_transient_authority() {
    let mut fixture = StoreFixture::new().await;
    fixture
        .store()
        .create_secret_request("clock-agent", "dummy-key", "unknown boot", "code", 60)
        .await
        .expect("create secret request before unreadable boot check");
    let mut sample = SystemClock.sample().expect("sample system clock");
    sample.boot_id = None;
    let manual_clock = Arc::new(ManualClock::new(sample));
    fixture.store.take();

    let fenced = Store::connect_with_clock_source(&fixture.url, manual_clock, 2_000)
        .await
        .expect("unreadable boot identity fences without accepting transient state");
    assert!(!fenced.is_ready().await);
    assert!(matches!(
        fenced.list_admin_agents().await,
        Err(StoreError::ClockFenced)
    ));
    assert_eq!(fixture_table_count(&fixture, "secret_requests").await, 0);
    assert_eq!(
        fixture_action_count(&fixture, "clock_restart_fence").await,
        1
    );
    fenced.close().await;
    fixture.close().await;
}

#[tokio::test]
async fn same_boot_startup_detects_database_clock_regression_beyond_tolerance() {
    let mut fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    store
        .create_secret_request("clock-agent", "dummy-key", "startup regression", "code", 60)
        .await
        .expect("create request before simulated downtime");
    store
        .bootstrap_local_operator(
            "op-startup",
            "admin",
            "Startup Admin",
            "dummy-password-hash",
        )
        .await
        .expect("create local operator");
    store
        .create_browser_session(
            "op-startup",
            "dummy-password-hash",
            "dummy-refresh-hash",
            3_600,
        )
        .await
        .expect("create browser session")
        .expect("operator is active");

    let mut sample = SystemClock.sample().expect("sample system clock");
    sample.boottime_ms = sample.boottime_ms.saturating_add(10_000);
    sample.host_wall_ms = sample.host_wall_ms.saturating_add(10_000);
    let manual_clock = Arc::new(ManualClock::new(sample));
    fixture.store.take();
    assert!(matches!(
        Store::connect_with_clock_source(&fixture.url, manual_clock, 2_000).await,
        Err(StoreError::ClockRegression)
    ));

    let fenced = Store::connect(&fixture.url)
        .await
        .expect("persistent regression fence is available to reconciliation");
    assert!(!fenced.is_ready().await);
    assert_eq!(fixture_active_session_count(&fixture).await, 1);
    fenced.close().await;

    let reconciled = Store::reconcile_clock(&fixture.url)
        .await
        .expect("reconcile startup clock fence");
    assert!(reconciled.regression_detected);
    assert_eq!(reconciled.removed_secret_requests, 1);
    assert_eq!(reconciled.revoked_sessions, 1);
    let healthy = Store::connect(&fixture.url)
        .await
        .expect("reconciled controller starts");
    assert!(healthy.is_ready().await);
    healthy.close().await;
    fixture.close().await;
}

#[tokio::test]
async fn running_clock_monitor_persists_fence_until_reconciliation() {
    let mut fixture = StoreFixture::new().await;
    let mut sample = SystemClock.sample().expect("sample system clock");
    let manual_clock = Arc::new(ManualClock::new(sample.clone()));
    fixture.store.take();
    let store = Store::connect_with_clock_source(&fixture.url, manual_clock.clone(), 2_000)
        .await
        .expect("connect with injected test clock");

    sample.host_wall_ms = sample.host_wall_ms.saturating_sub(5_000);
    manual_clock.set(sample);
    assert!(matches!(
        store.monitor_clock().await,
        Err(StoreError::ClockFenced)
    ));
    assert!(!store.is_ready().await);
    assert!(matches!(
        store.list_admin_agents().await,
        Err(StoreError::ClockFenced)
    ));
    drop(store);

    let reconnected = Store::connect(&fixture.url)
        .await
        .expect("fenced database remains available for local reconciliation");
    assert!(!reconnected.is_ready().await);
    reconnected.close().await;
    let result = Store::reconcile_clock(&fixture.url)
        .await
        .expect("clock reconciliation clears the persistent fence");
    assert!(result.regression_detected);
    let healthy = Store::connect(&fixture.url)
        .await
        .expect("reconciled clock starts cleanly");
    assert!(healthy.is_ready().await);
    healthy.close().await;
    fixture.close().await;
}

/// Read the persisted clock high-water mark and the database wall clock.
async fn read_clock(fixture: &StoreFixture) -> (i64, i64) {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL fixture");
        let clock = sqlx::query_as(
            "SELECT last_observed_ms, FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
             FROM controller_clock WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("read PostgreSQL clock");
        pool.close().await;
        clock
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite fixture");
        let clock = sqlx::query_as(
            "SELECT last_observed_ms, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
             FROM controller_clock WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("read SQLite clock");
        pool.close().await;
        clock
    }
}

async fn write_clock_mark(fixture: &StoreFixture, mark: i64) {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = $1 WHERE id = 1")
            .bind(mark)
            .execute(&pool)
            .await
            .expect("write PostgreSQL clock mark");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = ? WHERE id = 1")
            .bind(mark)
            .execute(&pool)
            .await
            .expect("write SQLite clock mark");
        pool.close().await;
    }
}

#[tokio::test]
async fn persisted_clock_mark_advances_and_tolerates_small_regressions_but_fences_large_ones() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let (initial, _) = read_clock(&fixture).await;

    // After the one-second interval the next checked operation advances the
    // mark to the database clock; within the interval it writes nothing.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    store
        .list_admin_agents()
        .await
        .expect("read under a healthy clock");
    let (advanced, now) = read_clock(&fixture).await;
    assert!(
        advanced >= initial + 1_000,
        "mark advanced from {initial} to {advanced}"
    );
    assert!(
        advanced <= now,
        "mark {advanced} never passes database time {now}"
    );
    store
        .list_admin_agents()
        .await
        .expect("read within the interval");
    assert_eq!(read_clock(&fixture).await.0, advanced);

    // A 1.5 s regression is within the configured two-second tolerance and
    // resets the checkpoint to the current database time.
    let (_, now) = read_clock(&fixture).await;
    write_clock_mark(&fixture, now + 1_500).await;
    assert!(store.is_ready().await);
    store
        .list_admin_agents()
        .await
        .expect("operations continue within tolerance");

    let (_, now) = read_clock(&fixture).await;
    write_clock_mark(&fixture, now + 2_500).await;
    assert!(!store.is_ready().await);
    assert!(matches!(
        store.list_admin_agents().await,
        Err(StoreError::ClockFenced)
    ));
    let reconnected = Store::connect(&fixture.url)
        .await
        .expect("fenced clock remains available for reconciliation");
    assert!(!reconnected.is_ready().await);
    reconnected.close().await;
    let repaired = Store::reconcile_clock(&fixture.url)
        .await
        .expect("reconcile clock beyond tolerance");
    assert!(repaired.regression_detected);
    assert!(store.is_ready().await, "reconciliation clears the fence");
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conditional_submit_and_consume_allow_one_winner_under_concurrency() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let request_id = store
        .create_secret_request("requester", "public-key", "description", "confirm", 60)
        .await
        .expect("create request");

    let submissions = (0..12).map(|index| {
        let store = store.clone();
        let request_id = request_id.clone();
        tokio::spawn(async move {
            store
                .submit_secret_request(
                    &request_id,
                    "requester",
                    "enc-value",
                    &format!("ciphertext-{index}"),
                    60,
                )
                .await
                .expect("submit concurrently")
        })
    });
    let accepted = futures_join(submissions).await;
    assert_eq!(accepted.iter().filter(|value| **value).count(), 1);
    assert_eq!(
        store
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        Some(SecretRequestStatus::Submitted)
    );

    let readers = (0..12).map(|_| {
        let store = store.clone();
        let request_id = request_id.clone();
        tokio::spawn(async move {
            store
                .consume_secret_request(&request_id, "requester")
                .await
                .expect("consume concurrently")
        })
    });
    let retrieved = futures_join(readers).await;
    assert_eq!(retrieved.iter().filter(|value| value.is_some()).count(), 1);
    assert!(retrieved.into_iter().flatten().all(|payload| {
        payload.enc == "enc-value" && payload.ciphertext.starts_with("ciphertext-")
    }));
    assert_eq!(
        store
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        None
    );
    fixture.close().await;
}

#[tokio::test]
async fn expiry_is_enforced_before_sweep_and_after_database_restart() {
    let mut fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let expiring = store
        .create_secret_request("requester", "key-expiring", "short-lived", "code", 1)
        .await
        .expect("create short-lived request");
    assert_eq!(
        store.request_status(&expiring, "requester").await.unwrap(),
        Some(SecretRequestStatus::Pending)
    );
    let submitted_expiring = store
        .create_secret_request("requester", "key-submitted", "short submit", "code", 60)
        .await
        .expect("create request with a short submitted window");
    assert!(
        store
            .submit_secret_request(&submitted_expiring, "requester", "enc", "ciphertext", 1)
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        store.request_status(&expiring, "requester").await.unwrap(),
        None
    );
    assert_eq!(
        store
            .request_status(&submitted_expiring, "requester")
            .await
            .unwrap(),
        None
    );
    assert!(
        store
            .consume_secret_request(&submitted_expiring, "requester")
            .await
            .unwrap()
            .is_none(),
        "submitted ciphertext past its deadline must not be consumable before the sweep"
    );
    assert!(
        store
            .consume_secret_request(&expiring, "requester")
            .await
            .unwrap()
            .is_none()
    );

    let durable = store
        .create_secret_request("requester", "key-durable", "submitted", "code", 60)
        .await
        .expect("create durable request");
    assert!(
        store
            .submit_secret_request(&durable, "requester", "enc", "ciphertext", 60)
            .await
            .unwrap()
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .request_status(&expiring, "requester")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        fixture
            .store()
            .request_status(&durable, "requester")
            .await
            .unwrap(),
        Some(SecretRequestStatus::Submitted)
    );
    assert!(
        fixture
            .store()
            .consume_secret_request(&submitted_expiring, "requester")
            .await
            .unwrap()
            .is_none(),
        "expired submitted ciphertext stays unconsumable after restart"
    );
    assert!(
        fixture
            .store()
            .consume_secret_request(&durable, "other-requester")
            .await
            .unwrap()
            .is_none(),
        "only the requesting agent can consume its submitted payload"
    );
    let payload = fixture
        .store()
        .consume_secret_request(&durable, "requester")
        .await
        .unwrap()
        .expect("submitted data persists across restart and a foreign attempt");
    assert_eq!(payload.ciphertext, "ciphertext");
    fixture.close().await;
}

#[tokio::test]
async fn p02_i03_committed_one_use_retrieval_stays_consumed_after_store_restart() {
    let mut fixture = StoreFixture::new().await;
    let request_id = fixture
        .store()
        .create_secret_request("requester", "key", "restart recovery", "code", 60)
        .await
        .expect("create request");
    assert!(
        fixture
            .store()
            .submit_secret_request(&request_id, "requester", "enc", "ciphertext", 60)
            .await
            .unwrap()
    );

    let payload = fixture
        .store()
        .consume_secret_request(&request_id, "requester")
        .await
        .unwrap()
        .expect("first retrieval commits");
    assert_eq!(payload.enc, "enc");
    assert_eq!(payload.ciphertext, "ciphertext");

    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        None
    );
    assert!(
        fixture
            .store()
            .consume_secret_request(&request_id, "requester")
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn retention_sweep_removes_expired_ciphertext_only_after_grace() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let request_id = store
        .create_secret_request("requester", "key", "sweep", "code", 1)
        .await
        .expect("create short-lived request");
    assert_eq!(store.sweep_expired(1).await.unwrap(), 0);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert_eq!(
        store
            .request_status(&request_id, "requester")
            .await
            .unwrap(),
        None
    );
    assert_eq!(store.sweep_expired(1).await.unwrap(), 1);
    fixture.close().await;
}

#[tokio::test]
async fn agent_key_rotation_revocation_and_ip_windows_are_atomic() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let agent = store
        .create_agent(
            "contract-agent",
            "Contract Agent",
            Some("blue"),
            "argon2id$old",
        )
        .await
        .expect("create enrolled agent");
    assert_eq!(
        store.agent_by_key_id(&agent.id).await.unwrap(),
        Some(agent.clone())
    );
    let rotated = store
        .replace_agent_api_key_hash("contract-agent", agent.key_version, "argon2id$new")
        .await
        .unwrap()
        .expect("rotate active agent key");
    assert_eq!(rotated.key_version, 2);
    assert_eq!(rotated.api_key_hash, "argon2id$new");
    assert!(
        store
            .replace_agent_api_key_hash("contract-agent", agent.key_version, "argon2id$stale")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.revoke_agent("contract-agent").await.unwrap());
    assert!(!store.revoke_agent("contract-agent").await.unwrap());
    assert_eq!(
        store
            .agent_by_key_id(&agent.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );

    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        1
    );
    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        2
    );
    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        3
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        store
            .consume_rate_limit("token:198.51.100.1", 2, 1_000)
            .await
            .unwrap()
            .count,
        1
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_rate_window_consumes_allow_exactly_the_limit_on_both_stores() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .consume_rate_limit("agent-request:tenant-fixture:agent:concurrent", 7, 60_000)
                .await
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        let result = task
            .await
            .expect("rate-window task completes")
            .expect("atomic rate-window consume succeeds");
        if result.count <= 7 {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 7);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchange_reservation_submit_and_one_use_retrieval_are_durable_and_atomic() {
    let mut fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let exchange_id = "a".repeat(64);
    let created = store
        .create_exchange(exchange_record(&exchange_id), 60)
        .await
        .expect("create exchange");
    assert_eq!(created.status, "pending");
    assert!(created.expires_at_ms > created.created_at_ms);
    assert!(
        store
            .reserve_exchange(&exchange_id, "other-fulfiller")
            .await
            .unwrap()
            .is_none(),
        "only the policy-selected fulfiller can reserve the exchange"
    );

    let reservations = (0..12).map(|_| {
        let store = store.clone();
        let exchange_id = exchange_id.clone();
        tokio::spawn(async move {
            store
                .reserve_exchange(&exchange_id, "fulfiller")
                .await
                .unwrap()
        })
    });
    let reserved = futures_join(reservations).await;
    assert_eq!(reserved.iter().filter(|value| value.is_some()).count(), 1);
    assert_eq!(
        reserved.into_iter().flatten().next().unwrap().status,
        "reserved"
    );

    let submitted = store
        .submit_exchange(&exchange_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60)
        .await
        .unwrap()
        .expect("submit reserved exchange");
    assert_eq!(submitted.status, "submitted");
    fixture.restart().await;

    let readers = (0..12).map(|_| {
        let store = fixture.store().clone();
        let exchange_id = exchange_id.clone();
        tokio::spawn(async move {
            store
                .consume_exchange(&exchange_id, "requester")
                .await
                .unwrap()
        })
    });
    let retrieved = futures_join(readers).await;
    assert_eq!(retrieved.iter().filter(|value| value.is_some()).count(), 1);
    let payload = retrieved.into_iter().flatten().next().unwrap();
    assert_eq!(payload.enc.as_deref(), Some("ZW5j"));
    assert_eq!(payload.ciphertext.as_deref(), Some("Y2lwaGVydGV4dA"));
    assert!(
        fixture
            .store()
            .get_exchange(&exchange_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchange_submit_racing_revocation_never_restores_ciphertext() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let exchange_id = "d".repeat(64);
    store
        .create_exchange(exchange_record(&exchange_id), 60)
        .await
        .expect("create exchange for race");
    store
        .reserve_exchange(&exchange_id, "fulfiller")
        .await
        .expect("reserve exchange")
        .expect("pending exchange is reservable");

    let (submitted, revoked) = tokio::join!(
        store.submit_exchange(&exchange_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60),
        store.revoke_exchange(&exchange_id, Some("requester"), 60),
    );
    let _ = submitted.expect("submit race completes");
    assert_eq!(
        revoked
            .expect("revoke race completes")
            .expect("requester can revoke")
            .status,
        "revoked"
    );
    let record = store
        .get_exchange(&exchange_id)
        .await
        .expect("read raced exchange")
        .expect("revocation marker persists");
    assert_eq!(record.status, "revoked");
    assert!(record.enc.is_none());
    assert!(record.ciphertext.is_none());
    assert!(
        store
            .consume_exchange(&exchange_id, "requester")
            .await
            .expect("retrieval after revocation")
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn foreign_tenant_exchange_cannot_be_read_reserved_revoked_or_retrieved() {
    let fixture = StoreFixture::new().await;
    let exchange_id = "e".repeat(64);
    let submitted_id = "d".repeat(64);
    let inserts = [
        format!(
            "INSERT INTO exchanges
             (id, tenant_id, requester_agent_id, requester_public_key, secret_name,
              purpose, fulfiller_hint, allowed_fulfiller_id, policy_decision_json,
              policy_hash, status, created_at, expires_at)
             VALUES ('{exchange_id}', 'foreign-tenant', 'requester', 'public-key',
                     'dummy.secret', 'tenant boundary', 'fulfiller', 'fulfiller', '{{}}',
                     'hash', 'pending', 0, 4102444800000)"
        ),
        format!(
            "INSERT INTO exchanges
             (id, tenant_id, requester_agent_id, requester_public_key, secret_name,
              purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
              policy_decision_json, policy_hash, status, created_at, expires_at,
              enc, ciphertext)
             VALUES ('{submitted_id}', 'foreign-tenant', 'requester', 'public-key',
                     'dummy.secret', 'tenant boundary', 'fulfiller', 'fulfiller',
                     'fulfiller', '{{}}', 'hash', 'submitted', 0, 4102444800000,
                     'enc', 'foreign-ciphertext')"
        ),
    ];
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL tenant fixture");
        for insert in &inserts {
            sqlx::query(insert)
                .execute(&pool)
                .await
                .expect("insert foreign tenant exchange");
        }
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite tenant fixture");
        for insert in &inserts {
            sqlx::query(insert)
                .execute(&pool)
                .await
                .expect("insert foreign tenant exchange");
        }
        pool.close().await;
    }

    let store = fixture.store();
    assert!(store.get_exchange(&exchange_id).await.unwrap().is_none());
    assert!(
        store
            .reserve_exchange(&exchange_id, "fulfiller")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .revoke_exchange(&exchange_id, Some("requester"), 60)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .consume_exchange(&submitted_id, "requester")
            .await
            .unwrap()
            .is_none(),
        "a matching requester ID cannot retrieve a foreign-tenant payload"
    );
    let select = if fixture.postgres_schema.is_some() {
        "SELECT status, ciphertext FROM exchanges WHERE id = $1"
    } else {
        "SELECT status, ciphertext FROM exchanges WHERE id = ?"
    };
    let rows: Vec<(String, Option<String>)> = if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL tenant fixture");
        let mut rows = Vec::new();
        for id in [&exchange_id, &submitted_id] {
            rows.push(
                sqlx::query_as(select)
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("read foreign tenant exchange"),
            );
        }
        pool.close().await;
        rows
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite tenant fixture");
        let mut rows = Vec::new();
        for id in [&exchange_id, &submitted_id] {
            rows.push(
                sqlx::query_as(select)
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("read foreign tenant exchange"),
            );
        }
        pool.close().await;
        rows
    };
    assert_eq!(rows[0], ("pending".to_owned(), None));
    assert_eq!(
        rows[1],
        (
            "submitted".to_owned(),
            Some("foreign-ciphertext".to_owned())
        )
    );
    fixture.close().await;
}

/// Hold a row lock (PostgreSQL) or the database writer lock (SQLite) while a
/// store transition starts, keep it past the transition's deadline, then
/// release it and return the transition's result.
async fn after_lock_wait<T: Send + 'static>(
    fixture: &StoreFixture,
    postgres_lock_sql: &str,
    key: &str,
    transition: impl std::future::Future<Output = T> + Send + 'static,
) -> T {
    let hold = Duration::from_millis(1_100);
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL lock fixture");
        let mut transaction = pool.begin().await.expect("begin row lock transaction");
        sqlx::query(postgres_lock_sql)
            .bind(key)
            .fetch_one(&mut *transaction)
            .await
            .expect("lock the transition row");
        let task = tokio::spawn(transition);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!task.is_finished(), "transition must wait on the row lock");
        tokio::time::sleep(hold).await;
        transaction.commit().await.expect("release row lock");
        let result = task.await.expect("transition task");
        pool.close().await;
        result
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite lock fixture");
        let mut connection = pool
            .acquire()
            .await
            .expect("acquire SQLite lock connection");
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .expect("hold SQLite writer lock");
        let task = tokio::spawn(transition);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !task.is_finished(),
            "transition must wait on the writer lock"
        );
        tokio::time::sleep(hold).await;
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .expect("release SQLite writer lock");
        let result = task.await.expect("transition task");
        drop(connection);
        pool.close().await;
        result
    }
}

async fn count_rows(fixture: &StoreFixture, table: &str) -> i64 {
    count_query(fixture, &format!("SELECT COUNT(*) FROM {table}")).await
}

async fn count_query(fixture: &StoreFixture, sql: &str) -> i64 {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL fixture");
        let count = sqlx::query_scalar(sql)
            .fetch_one(&pool)
            .await
            .expect("count rows");
        pool.close().await;
        count
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite fixture");
        let count = sqlx::query_scalar(sql)
            .fetch_one(&pool)
            .await
            .expect("count rows");
        pool.close().await;
        count
    }
}

/// Read two text columns of one stored row, bypassing every store filter.
async fn stored_row(fixture: &StoreFixture, sql: &str, key: &str) -> (String, Option<String>) {
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL fixture");
        let row = sqlx::query_as(&sql.replace('?', "$1"))
            .bind(key)
            .fetch_one(&pool)
            .await
            .expect("read stored row");
        pool.close().await;
        row
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite fixture");
        let row = sqlx::query_as(sql)
            .bind(key)
            .fetch_one(&pool)
            .await
            .expect("read stored row");
        pool.close().await;
        row
    }
}

fn short_lived_approval(store: &Store, reference: &str) -> ApprovalRecord {
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_millis(),
    )
    .expect("current time fits i64");
    ApprovalRecord {
        approval_reference: reference.to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: "restricted.secret".to_owned(),
        purpose: "lock wait approval".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        rule_id: Some("approval-rule".to_owned()),
        reason: "requires approval".to_owned(),
        requester_ring: None,
        fulfiller_ring: None,
        approver_ids: vec!["approver".to_owned()],
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        // create_approval stores the database clock plus this one-second TTL.
        expires_at_ms: now_ms + 1_000,
        decided_at_ms: None,
        decided_by: None,
    }
}

/// P02-D9: every expiring transition samples its deadline after any lock
/// wait. The results are re-read through expiry-filtered queries, so each case
/// also checks the stored row: a transition that committed on an expired row
/// would change it even though the store returns nothing.
#[tokio::test]
async fn expiring_transitions_recheck_their_deadline_after_a_lock_wait() {
    const LOCK_EXCHANGE: &str = "SELECT 1 FROM exchanges WHERE id = $1 FOR UPDATE";
    const LOCK_REQUEST: &str = "SELECT 1 FROM secret_requests WHERE id = $1 FOR UPDATE";
    const LOCK_APPROVAL: &str = "SELECT 1 FROM approvals WHERE reference = $1 FOR UPDATE";
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();

    let reserve_id = "f".repeat(64);
    store
        .create_exchange(exchange_record(&reserve_id), 1)
        .await
        .expect("create exchange that expires during the reservation wait");
    let (raced, id) = (store.clone(), reserve_id.clone());
    let reserved = after_lock_wait(&fixture, LOCK_EXCHANGE, &reserve_id, async move {
        raced.reserve_exchange(&id, "fulfiller").await
    })
    .await
    .expect("reservation query");
    assert!(reserved.is_none());
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, fulfilled_by FROM exchanges WHERE id = ?",
            &reserve_id
        )
        .await,
        ("pending".to_owned(), None),
        "an expired exchange must not be reserved after the lock is released"
    );

    let submit_id = "c".repeat(64);
    store
        .create_exchange(exchange_record(&submit_id), 1)
        .await
        .expect("create exchange that expires during the submission wait");
    store
        .reserve_exchange(&submit_id, "fulfiller")
        .await
        .unwrap()
        .expect("reserve before the deadline");
    let (raced, id) = (store.clone(), submit_id.clone());
    let submitted = after_lock_wait(&fixture, LOCK_EXCHANGE, &submit_id, async move {
        raced
            .submit_exchange(&id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60)
            .await
    })
    .await
    .expect("exchange submission query");
    assert!(submitted.is_none());
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, ciphertext FROM exchanges WHERE id = ?",
            &submit_id
        )
        .await,
        ("reserved".to_owned(), None),
        "no ciphertext may be stored on an expired exchange"
    );

    let retrieve_id = "b".repeat(64);
    store
        .create_exchange(exchange_record(&retrieve_id), 60)
        .await
        .expect("create exchange for retrieval");
    store
        .reserve_exchange(&retrieve_id, "fulfiller")
        .await
        .unwrap()
        .expect("reserve exchange for retrieval");
    store
        .submit_exchange(&retrieve_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 1)
        .await
        .unwrap()
        .expect("submit ciphertext that expires during the retrieval wait");
    let (raced, id) = (store.clone(), retrieve_id.clone());
    let retrieved = after_lock_wait(&fixture, LOCK_EXCHANGE, &retrieve_id, async move {
        raced.consume_exchange(&id, "requester").await
    })
    .await
    .expect("exchange retrieval query");
    assert!(
        retrieved.is_none(),
        "expired exchange ciphertext must not be returned after a lock wait"
    );
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, ciphertext FROM exchanges WHERE id = ?",
            &retrieve_id
        )
        .await,
        ("submitted".to_owned(), Some("Y2lwaGVydGV4dA".to_owned()))
    );

    let revoke_id = "9".repeat(64);
    store
        .create_exchange(exchange_record(&revoke_id), 1)
        .await
        .expect("create exchange that expires during the revocation wait");
    let (raced, id) = (store.clone(), revoke_id.clone());
    let revoked = after_lock_wait(&fixture, LOCK_EXCHANGE, &revoke_id, async move {
        raced.revoke_exchange(&id, Some("requester"), 60).await
    })
    .await
    .expect("exchange revocation query");
    assert!(revoked.is_none());
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, fulfilled_by FROM exchanges WHERE id = ?",
            &revoke_id
        )
        .await,
        ("pending".to_owned(), None)
    );

    let pending_request = store
        .create_secret_request("requester", "key-lock-submit", "lock wait", "code", 1)
        .await
        .expect("create request that expires during the submission wait");
    let (raced, id) = (store.clone(), pending_request.clone());
    let accepted = after_lock_wait(&fixture, LOCK_REQUEST, &pending_request, async move {
        raced
            .submit_secret_request(&id, "requester", "enc", "ciphertext", 60)
            .await
    })
    .await
    .expect("secret submission query");
    assert!(!accepted);
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, ciphertext FROM secret_requests WHERE id = ?",
            &pending_request
        )
        .await,
        ("pending".to_owned(), None),
        "no ciphertext may be stored on an expired request"
    );

    let submitted_request = store
        .create_secret_request("requester", "key-lock-retrieve", "lock wait", "code", 60)
        .await
        .expect("create request for retrieval");
    assert!(
        store
            .submit_secret_request(&submitted_request, "requester", "enc", "ciphertext", 1)
            .await
            .unwrap()
    );
    let (raced, id) = (store.clone(), submitted_request.clone());
    let consumed = after_lock_wait(&fixture, LOCK_REQUEST, &submitted_request, async move {
        raced.consume_secret_request(&id, "requester").await
    })
    .await
    .expect("secret retrieval query");
    assert!(
        consumed.is_none(),
        "expired secret ciphertext must not be returned after a lock wait"
    );
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, ciphertext FROM secret_requests WHERE id = ?",
            &submitted_request
        )
        .await,
        ("submitted".to_owned(), Some("ciphertext".to_owned()))
    );

    let idempotent = short_lived_approval(&store, "apr_cccccccccccccccccccccccc");
    store.create_approval(&idempotent).await.unwrap();
    let (raced, reference) = (store.clone(), idempotent.approval_reference.clone());
    let decided = after_lock_wait(
        &fixture,
        LOCK_APPROVAL,
        &idempotent.approval_reference,
        async move {
            raced
                .decide_approval_idempotent(&reference, "approved", "approver", "lock-wait-key")
                .await
        },
    )
    .await
    .expect("idempotent approval decision query");
    assert!(matches!(
        decided,
        blindpass_controller::store::ApprovalDecisionOutcome::NotFound
    ));
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, decided_by FROM approvals WHERE reference = ?",
            &idempotent.approval_reference
        )
        .await,
        ("pending".to_owned(), None),
        "an expired approval must not be decided after the lock is released"
    );

    let plain = short_lived_approval(&store, "apr_dddddddddddddddddddddddd");
    store.create_approval(&plain).await.unwrap();
    let (raced, reference) = (store.clone(), plain.approval_reference.clone());
    let decided = after_lock_wait(
        &fixture,
        LOCK_APPROVAL,
        &plain.approval_reference,
        async move {
            raced
                .decide_approval(&reference, "rejected", "approver")
                .await
        },
    )
    .await
    .expect("approval decision query");
    assert!(decided.is_none());
    assert_eq!(
        stored_row(
            &fixture,
            "SELECT status, decided_by FROM approvals WHERE reference = ?",
            &plain.approval_reference
        )
        .await,
        ("pending".to_owned(), None)
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchange_revocation_and_approval_decision_use_expiry_and_compare_and_set() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let exchange_id = "b".repeat(64);
    store
        .create_exchange(exchange_record(&exchange_id), 60)
        .await
        .unwrap();
    let revoked = store
        .revoke_exchange(&exchange_id, Some("requester"), 1)
        .await
        .unwrap()
        .expect("requester revokes exchange");
    assert_eq!(revoked.status, "revoked");
    assert_eq!(
        store
            .revoke_exchange(&exchange_id, Some("requester"), 1)
            .await
            .unwrap()
            .unwrap()
            .status,
        "revoked"
    );
    assert!(
        store
            .revoke_exchange(&exchange_id, Some("other"), 1)
            .await
            .unwrap()
            .is_none()
    );
    let submitted_id = "c".repeat(64);
    store
        .create_exchange(exchange_record(&submitted_id), 60)
        .await
        .unwrap();
    store
        .reserve_exchange(&submitted_id, "fulfiller")
        .await
        .unwrap()
        .unwrap();
    store
        .submit_exchange(&submitted_id, "fulfiller", "ZW5j", "Y2lwaGVydGV4dA", 60)
        .await
        .unwrap()
        .unwrap();
    let revoked_submission = store
        .revoke_exchange(&submitted_id, Some("requester"), 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked_submission.status, "revoked");
    assert!(revoked_submission.enc.is_none());
    assert!(revoked_submission.ciphertext.is_none());

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let approval = ApprovalRecord {
        approval_reference: "apr_aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: "restricted.secret".to_owned(),
        purpose: "test approval".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        rule_id: Some("approval-rule".to_owned()),
        reason: "requires approval".to_owned(),
        requester_ring: None,
        fulfiller_ring: None,
        approver_ids: vec!["approver".to_owned()],
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
        decided_at_ms: None,
        decided_by: None,
    };
    store.create_approval(&approval).await.unwrap();
    assert_eq!(store.count_pending_approvals().await.unwrap(), 1);
    assert_eq!(
        store
            .list_approvals(Some("pending"), None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let approval_reference = approval.approval_reference.clone();
    let decisions = (0..8).map(|index| {
        let store = store.clone();
        let approval_reference = approval_reference.clone();
        let status = if index % 2 == 0 {
            "approved"
        } else {
            "rejected"
        };
        tokio::spawn(async move {
            store
                .decide_approval(&approval_reference, status, "approver")
                .await
                .unwrap()
        })
    });
    let decisions = futures_join(decisions).await;
    assert_eq!(decisions.iter().filter(|value| value.is_some()).count(), 1);
    let final_approval = store
        .get_approval(&approval_reference)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        final_approval.status.as_str(),
        "approved" | "rejected"
    ));
    assert_eq!(final_approval.decided_by.as_deref(), Some("approver"));
    assert_eq!(store.count_pending_approvals().await.unwrap(), 0);
    assert_eq!(
        store
            .list_approvals(Some(&final_approval.status), None, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    // create_approval stores expires_at as the database clock plus
    // (expires_at_ms - created_at_ms), so this approval lives for one second.
    let expiring = ApprovalRecord {
        approval_reference: "apr_bbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        expires_at_ms: approval.created_at_ms + 1_000,
        ..approval.clone()
    };
    store.create_approval(&expiring).await.unwrap();
    assert_eq!(store.count_pending_approvals().await.unwrap(), 1);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(
        store
            .decide_approval(&expiring.approval_reference, "approved", "approver")
            .await
            .unwrap()
            .is_none(),
        "an expired approval cannot be decided"
    );
    assert!(matches!(
        store
            .decide_approval_idempotent(
                &expiring.approval_reference,
                "approved",
                "approver",
                "expired-approval-key",
            )
            .await
            .unwrap(),
        blindpass_controller::store::ApprovalDecisionOutcome::NotFound
    ));
    assert_eq!(store.count_pending_approvals().await.unwrap(), 0);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_serializes_first_admin_creation_and_consumes_setup_tokens_once() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let bootstrap_attempts = (0..8).map(|index| {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .bootstrap_local_operator(
                    &format!("00000000-0000-4000-8000-{index:012}"),
                    // Distinct usernames: only bootstrap serialization, not a
                    // username constraint, may limit this to one operator.
                    &format!("first-admin-{index}"),
                    "First administrator",
                    "argon2id$fixture-hash",
                )
                .await
                .unwrap()
        })
    });
    assert_eq!(
        futures_join(bootstrap_attempts)
            .await
            .iter()
            .filter(|created| **created)
            .count(),
        1
    );
    assert_eq!(count_rows(&fixture, "operators").await, 1);
    assert!(store.has_active_admin().await.unwrap());
    assert!(
        !store
            .issue_bootstrap_token("another-token-hash", 900)
            .await
            .unwrap()
    );
    fixture.close().await;

    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    assert!(
        store
            .issue_bootstrap_token("single-use-hash", 900)
            .await
            .unwrap()
    );
    assert!(
        store
            .bootstrap_operator_with_token(
                "single-use-hash",
                "00000000-0000-4000-8000-000000000001",
                "first-admin",
                "First administrator",
                "argon2id$fixture-hash",
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .bootstrap_operator_with_token(
                "single-use-hash",
                "00000000-0000-4000-8000-000000000002",
                "second-admin",
                "Second administrator",
                "argon2id$fixture-hash",
            )
            .await
            .unwrap()
    );
    assert_eq!(count_rows(&fixture, "operators").await, 1);
    assert!(store.has_active_admin().await.unwrap());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refresh_replay_revokes_the_family_without_store_errors() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    let operator_id = "00000000-0000-4000-8000-000000000021";
    assert!(
        store
            .bootstrap_local_operator(operator_id, "admin", "Local Admin", "password-hash")
            .await
            .unwrap()
    );
    store
        .create_browser_session(operator_id, "password-hash", "shared-refresh-hash", 3_600)
        .await
        .expect("create session")
        .expect("operator is active");
    // Two tabs, or an attacker replaying a stolen refresh token, present the
    // same token at once: one rotation commits and the replays revoke the
    // whole family instead of failing with a store error. The rotating caller
    // may itself observe that revocation before it returns.
    let attempts = (0..8).map(|index| {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .rotate_browser_session("shared-refresh-hash", &format!("rotated-{index}"), 3_600)
                .await
        })
    });
    let results = futures_join(attempts).await;
    assert!(
        results.iter().all(Result::is_ok),
        "store errors: {:?}",
        results
            .iter()
            .filter(|result| result.is_err())
            .collect::<Vec<_>>()
    );
    let winners = results
        .into_iter()
        .filter_map(|result| result.unwrap())
        .collect::<Vec<_>>();
    assert!(winners.len() <= 1, "at most one rotation succeeds");
    for winner in &winners {
        assert!(
            store
                .browser_session_by_id(&winner.session_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let sessions =
        format!("SELECT COUNT(*) FROM operator_sessions WHERE operator_id = '{operator_id}'");
    assert_eq!(
        count_query(&fixture, &sessions).await,
        2,
        "one rotated row was inserted"
    );
    assert_eq!(
        count_query(&fixture, &format!("{sessions} AND revoked_at IS NULL")).await,
        0,
        "a replayed refresh token revokes the whole session family"
    );
    fixture.close().await;
}

#[tokio::test]
async fn local_browser_sessions_are_operator_bound_idle_checked_and_revocable() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let operator_id = "00000000-0000-4000-8000-000000000011";
    assert!(
        store
            .bootstrap_local_operator(operator_id, "admin", "Local Admin", "password-hash")
            .await
            .unwrap()
    );

    let session = store
        .create_browser_session(operator_id, "password-hash", "refresh-token-hash", 60)
        .await
        .unwrap()
        .expect("active operator receives a browser session");
    let other_session = store
        .create_browser_session(operator_id, "password-hash", "other-refresh-token-hash", 60)
        .await
        .unwrap()
        .expect("active operator can have another browser session");
    assert_eq!(session.operator.id, operator_id);
    assert_eq!(session.operator.role, "admin");
    assert!(!session.csrf_secret.is_empty());

    let idle = store
        .create_browser_session(operator_id, "password-hash", "idle-refresh-token-hash", 60)
        .await
        .unwrap()
        .expect("active operator receives an idle-test session");
    let nearly_idle = store
        .create_browser_session(
            operator_id,
            "password-hash",
            "nearly-idle-refresh-token-hash",
            60,
        )
        .await
        .unwrap()
        .expect("active operator receives a nearly idle session");
    const IDLE_LIMIT_MS: i64 = 12 * 60 * 60 * 1_000;
    let age = [
        (idle.session_id.as_str(), IDLE_LIMIT_MS + 1_000),
        (nearly_idle.session_id.as_str(), IDLE_LIMIT_MS - 60_000),
    ];
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL session fixture");
        for (id, age_ms) in age {
            sqlx::query(
                "UPDATE operator_sessions SET last_seen_at = last_seen_at - $1 WHERE id = $2",
            )
            .bind(age_ms)
            .bind(id)
            .execute(&pool)
            .await
            .expect("age PostgreSQL browser session");
        }
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite session fixture");
        for (id, age_ms) in age {
            sqlx::query(
                "UPDATE operator_sessions SET last_seen_at = last_seen_at - ? WHERE id = ?",
            )
            .bind(age_ms)
            .bind(id)
            .execute(&pool)
            .await
            .expect("age SQLite browser session");
        }
        pool.close().await;
    }
    assert!(
        store
            .browser_session_by_id(&idle.session_id)
            .await
            .unwrap()
            .is_none(),
        "a session idle past 12 hours is rejected"
    );
    assert!(!store.touch_browser_session(&idle.session_id).await.unwrap());
    assert!(
        store
            .rotate_browser_session("idle-refresh-token-hash", "idle-rotated-hash", 60)
            .await
            .unwrap()
            .is_none(),
        "an idle session cannot be refreshed back into use"
    );
    assert!(
        store
            .browser_session_by_id(&nearly_idle.session_id)
            .await
            .unwrap()
            .is_some(),
        "a session inside the 12 hour idle bound stays valid"
    );
    assert!(
        store
            .touch_browser_session(&nearly_idle.session_id)
            .await
            .unwrap()
    );
    assert!(
        store
            .touch_browser_session(&session.session_id)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .unwrap()
            .csrf_secret,
        session.csrf_secret
    );
    assert!(
        store
            .change_operator_password(
                operator_id,
                &session.session_id,
                "password-hash",
                "new-password-hash",
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .browser_session_by_id(&other_session.session_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .operator_by_username("admin")
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        "new-password-hash"
    );
    assert!(
        store
            .revoke_browser_session(&session.session_id)
            .await
            .unwrap()
    );
    assert!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn sessions_and_password_changes_are_bound_to_the_verified_password() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let operator_id = "00000000-0000-4000-8000-000000000031";
    assert!(
        store
            .bootstrap_local_operator(operator_id, "admin", "Local Admin", "original-hash")
            .await
            .unwrap()
    );
    let sessions =
        format!("SELECT COUNT(*) FROM operator_sessions WHERE operator_id = '{operator_id}'");
    let first = store
        .create_browser_session(operator_id, "original-hash", "first-refresh-hash", 60)
        .await
        .unwrap()
        .expect("a login verified against the stored hash receives a session");
    assert!(
        store
            .create_browser_session(operator_id, "stale-hash", "stale-refresh-hash", 60)
            .await
            .unwrap()
            .is_none(),
        "a login verified against another hash receives no session"
    );
    assert_eq!(count_query(&fixture, &sessions).await, 1);

    // An administrator resets the password while a login and a password
    // change, both verified against the original hash, are still in flight.
    assert!(
        store
            .reset_local_operator_password(operator_id, "temporary-hash")
            .await
            .unwrap()
    );
    assert!(
        store
            .create_browser_session(operator_id, "original-hash", "late-refresh-hash", 60)
            .await
            .unwrap()
            .is_none(),
        "a login verified before the reset does not survive it"
    );
    assert_eq!(count_query(&fixture, &sessions).await, 1);
    let temporary = store
        .create_browser_session(operator_id, "temporary-hash", "temporary-refresh-hash", 60)
        .await
        .unwrap()
        .expect("the temporary password signs in");
    assert!(
        !store
            .change_operator_password(
                operator_id,
                &temporary.session_id,
                "original-hash",
                "attacker-chosen-hash",
            )
            .await
            .unwrap(),
        "a change verified before the reset cannot overwrite it"
    );
    assert!(
        !store
            .change_operator_password(
                operator_id,
                &first.session_id,
                "temporary-hash",
                "revoked-session-hash"
            )
            .await
            .unwrap(),
        "a session revoked by the reset cannot change the password"
    );
    let operator = store.operator_by_id(operator_id).await.unwrap().unwrap();
    assert_eq!(operator.password_hash, "temporary-hash");
    assert!(
        operator.must_change_password,
        "the reset still forces a change"
    );

    assert!(
        store
            .change_operator_password(
                operator_id,
                &temporary.session_id,
                "temporary-hash",
                "chosen-hash"
            )
            .await
            .unwrap()
    );
    let operator = store.operator_by_id(operator_id).await.unwrap().unwrap();
    assert_eq!(operator.password_hash, "chosen-hash");
    assert!(!operator.must_change_password);
    assert!(
        store
            .browser_session_by_id(&temporary.session_id)
            .await
            .unwrap()
            .is_some(),
        "the changing session stays signed in"
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_changes_revoke_sessions_created_or_rotated_concurrently() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store().clone();
    for round in 0..20 {
        let operator_id = format!("00000000-0000-4000-8000-{round:012}");
        store
            .create_local_operator(
                &operator_id,
                &format!("race-operator-{round}"),
                "Race Operator",
                "operator",
                "old-hash",
            )
            .await
            .unwrap();
        let current = store
            .create_browser_session(&operator_id, "old-hash", &format!("current-{round}"), 60)
            .await
            .unwrap()
            .unwrap();
        store
            .create_browser_session(&operator_id, "old-hash", &format!("other-{round}"), 60)
            .await
            .unwrap()
            .unwrap();
        // Another tab refreshes and a login verified against the old
        // password finishes while the password changes. Neither may leave a
        // session the change did not revoke.
        let change = {
            let store = store.clone();
            let operator_id = operator_id.clone();
            let session_id = current.session_id.clone();
            tokio::spawn(async move {
                store
                    .change_operator_password(&operator_id, &session_id, "old-hash", "new-hash")
                    .await
            })
        };
        let refresh = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .rotate_browser_session(
                        &format!("other-{round}"),
                        &format!("rotated-{round}"),
                        60,
                    )
                    .await
                    .map(|_| ())
            })
        };
        let login = {
            let store = store.clone();
            let operator_id = operator_id.clone();
            tokio::spawn(async move {
                store
                    .create_browser_session(&operator_id, "old-hash", &format!("login-{round}"), 60)
                    .await
                    .map(|_| ())
            })
        };
        assert!(
            change.await.unwrap().unwrap(),
            "round {round}: the change applies"
        );
        refresh.await.unwrap().unwrap();
        login.await.unwrap().unwrap();
        let survivors = format!(
            "SELECT COUNT(*) FROM operator_sessions WHERE operator_id = '{operator_id}'
            AND id <> '{}' AND revoked_at IS NULL",
            current.session_id
        );
        assert_eq!(
            count_query(&fixture, &survivors).await,
            0,
            "round {round}: a session outlived the password change"
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn browser_refresh_rotation_and_replay_revoke_the_session_family() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let operator_id = "00000000-0000-4000-8000-000000000012";
    assert!(
        store
            .bootstrap_local_operator(operator_id, "admin", "Local Admin", "password-hash")
            .await
            .unwrap()
    );
    let first = store
        .create_browser_session(operator_id, "password-hash", "first-refresh-hash", 60)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .browser_session_by_refresh_hash("first-refresh-hash")
            .await
            .unwrap()
            .is_some()
    );
    let second = store
        .rotate_browser_session("first-refresh-hash", "second-refresh-hash", 60)
        .await
        .unwrap()
        .expect("first refresh rotation wins");
    assert_eq!(second.operator.id, operator_id);
    assert!(
        store
            .browser_session_by_refresh_hash("first-refresh-hash")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .rotate_browser_session("first-refresh-hash", "replay-refresh-hash", 60)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .browser_session_by_id(&first.session_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .browser_session_by_id(&second.session_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn local_operator_management_preserves_a_final_admin_and_revokes_reset_sessions() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let first_admin = "00000000-0000-4000-8000-000000000013";
    let second_admin = "00000000-0000-4000-8000-000000000014";
    assert!(
        store
            .bootstrap_local_operator(first_admin, "first-admin", "First Admin", "hash-1")
            .await
            .unwrap()
    );
    assert_eq!(
        store.delete_local_operator(first_admin).await.unwrap(),
        Some(false),
        "the final admin cannot be deleted"
    );
    store
        .create_local_operator(
            second_admin,
            "second-admin",
            "Second Admin",
            "admin",
            "hash-2",
        )
        .await
        .unwrap();
    assert_eq!(store.list_local_operators().await.unwrap().len(), 2);
    assert_eq!(
        store
            .update_local_operator(first_admin, "First Admin", "viewer")
            .await
            .unwrap(),
        Some(true),
        "an admin may be demoted when another admin remains"
    );
    assert_eq!(
        store.delete_local_operator(first_admin).await.unwrap(),
        Some(true)
    );
    let session = store
        .create_browser_session(second_admin, "hash-2", "reset-refresh-hash", 60)
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .reset_local_operator_password(second_admin, "temporary-password-hash")
            .await
            .unwrap()
    );
    assert!(
        store
            .browser_session_by_id(&session.session_id)
            .await
            .unwrap()
            .is_none()
    );
    let operator = store
        .operator_by_username("second-admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(operator.password_hash, "temporary-password-hash");
    assert!(operator.must_change_password);
    assert_eq!(store.list_local_operators().await.unwrap().len(), 1);
    assert_eq!(
        store.delete_local_operator(second_admin).await.unwrap(),
        Some(false),
        "password reset does not bypass last-admin protection"
    );
    fixture.close().await;
}

#[tokio::test]
async fn p02_i03_policy_compare_and_set_retry_survives_store_restart() {
    let mut fixture = StoreFixture::new().await;
    let first = r#"{"secret_registry":[],"exchange_policy":[]}"#;
    assert_eq!(
        fixture
            .store()
            .replace_policy_document(1, first, "operator")
            .await
            .unwrap(),
        Some(2)
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .replace_policy_document(1, first, "operator")
            .await
            .unwrap(),
        None,
        "a retry using the stale version cannot duplicate a committed update"
    );
    let stored = fixture.store().policy_document().await.unwrap().unwrap();
    assert_eq!(stored.version, 2);
    assert_eq!(stored.document_json, first);
    assert_eq!(
        fixture
            .store()
            .replace_policy_document(2, first, "operator")
            .await
            .unwrap(),
        Some(3)
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .store()
            .policy_document()
            .await
            .unwrap()
            .unwrap()
            .version,
        3
    );
    fixture.close().await;
}

#[tokio::test]
async fn approval_decision_is_audited_and_idempotent_by_actor_and_request() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let approval = ApprovalRecord {
        approval_reference: "apr_idempotent_decision".to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: "restricted.secret".to_owned(),
        purpose: "approval idempotency".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        rule_id: Some("admin-approval".to_owned()),
        reason: "requires approval".to_owned(),
        requester_ring: None,
        fulfiller_ring: None,
        approver_ids: vec!["local-operator".to_owned()],
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
        decided_at_ms: None,
        decided_by: None,
    };
    store.create_approval(&approval).await.unwrap();
    let raw_idempotency_key = "local-idempotency-secret";
    let key_hash = blindpass_core::custody::sha256(raw_idempotency_key.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let applied = store
        .decide_approval_idempotent(
            &approval.approval_reference,
            "approved",
            "local-operator",
            &key_hash,
        )
        .await
        .unwrap();
    assert!(matches!(
        applied,
        blindpass_controller::store::ApprovalDecisionOutcome::Applied(_)
    ));
    let replay = store
        .decide_approval_idempotent(
            &approval.approval_reference,
            "approved",
            "local-operator",
            &key_hash,
        )
        .await
        .unwrap();
    assert!(matches!(
        replay,
        blindpass_controller::store::ApprovalDecisionOutcome::Replayed(_)
    ));
    let conflict = store
        .decide_approval_idempotent(
            &approval.approval_reference,
            "rejected",
            "local-operator",
            &key_hash,
        )
        .await
        .unwrap();
    assert_eq!(
        conflict,
        blindpass_controller::store::ApprovalDecisionOutcome::Conflict
    );
    let audit = store.list_audit(10).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event_type, "exchange_approved");
    assert!(!audit[0].metadata.to_string().contains(raw_idempotency_key));
    fixture.close().await;
}

#[tokio::test]
async fn audit_retention_uses_its_own_day_limit_without_pruning_fresh_events() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    store
        .append_audit(
            "old_event",
            "system",
            None,
            "fixture",
            Some("old"),
            &serde_json::json!({}),
        )
        .await
        .expect("append old audit fixture");
    store
        .append_audit(
            "fresh_event",
            "system",
            None,
            "fixture",
            Some("fresh"),
            &serde_json::json!({}),
        )
        .await
        .expect("append fresh audit fixture");
    let three_days_ago = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as i64
        - 3 * 86_400_000;
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect audit fixture");
        sqlx::query("UPDATE audit_events SET created_at = $1 WHERE target_id = 'old'")
            .bind(three_days_ago)
            .execute(&pool)
            .await
            .expect("age old audit event");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect audit fixture");
        sqlx::query("UPDATE audit_events SET created_at = ? WHERE target_id = 'old'")
            .bind(three_days_ago)
            .execute(&pool)
            .await
            .expect("age old audit event");
        pool.close().await;
    }

    assert_eq!(store.sweep_audit(1).await.expect("sweep old audit"), 1);
    let audit = store.list_audit(10).await.expect("list retained audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event_type, "fresh_event");
    assert_eq!(store.sweep_audit(1).await.expect("repeat sweep"), 0);
    fixture.close().await;
}

fn exchange_record(exchange_id: &str) -> ExchangeRecord {
    ExchangeRecord {
        exchange_id: exchange_id.to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: "tenant-fixture".to_owned(),
        requester_public_key: "cHVibGljLWtleQ==".to_owned(),
        secret_name: "stripe.api_key.prod".to_owned(),
        purpose: "store transition test".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        allowed_fulfiller_id: Some("fulfiller".to_owned()),
        fulfilled_by: None,
        policy: ExchangePolicyRecord {
            mode: "allow".to_owned(),
            approval_required: false,
            rule_id: "test-rule".to_owned(),
            reason: "test policy".to_owned(),
            approval_reference: None,
            requester_ring: None,
            fulfiller_ring: None,
            secret_name: "stripe.api_key.prod".to_owned(),
        },
        policy_hash: "policy-hash".to_owned(),
        status: "pending".to_owned(),
        prior_exchange_id: None,
        supersedes_exchange_id: None,
        created_at_ms: 0,
        expires_at_ms: 0,
        enc: None,
        ciphertext: None,
    }
}

/// Await tasks that are all already running. Collecting first matters: the
/// callers pass a lazy `map` that spawns on iteration, so awaiting inside the
/// same loop would start each task only after the previous one finished.
async fn futures_join<T>(tasks: impl IntoIterator<Item = tokio::task::JoinHandle<T>>) -> Vec<T> {
    let tasks: Vec<_> = tasks.into_iter().collect();
    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        results.push(task.await.expect("concurrent store worker"));
    }
    results
}

#[tokio::test]
async fn later_migration_table_missing_on_current_version_fails_closed() {
    let fixture = StoreFixture::new().await;
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL schema fixture");
        sqlx::query("DROP TABLE controller_clock")
            .execute(&pool)
            .await
            .expect("remove later-migration PostgreSQL table");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite schema fixture");
        sqlx::query("DROP TABLE controller_clock")
            .execute(&pool)
            .await
            .expect("remove later-migration SQLite table");
        pool.close().await;
    }

    assert!(matches!(
        Store::connect(&fixture.url).await,
        Err(StoreError::UnsupportedSchemaVersion)
    ));
    let recreated = if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL schema fixture");
        let present: bool =
            sqlx::query_scalar("SELECT to_regclass('controller_clock') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .expect("inspect PostgreSQL schema");
        pool.close().await;
        present
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite schema fixture");
        let present: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'controller_clock')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect SQLite schema");
        pool.close().await;
        present != 0
    };
    assert!(
        !recreated,
        "a missing clock table must not be recreated with a fresh high-water mark"
    );
    fixture.close().await;
}

#[tokio::test]
async fn older_schema_version_migrates_forward_and_records_current_version() {
    let fixture = StoreFixture::new().await;
    let request_id = fixture
        .store()
        .create_secret_request("upgrade-agent", "dummy-public-key", "upgrade", "123456", 60)
        .await
        .expect("create request before downgrade simulation");
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL schema fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 1 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("simulate a version 1 database");
        sqlx::query("DROP TABLE controller_clock")
            .execute(&pool)
            .await
            .expect("remove version 3 table");
        sqlx::query("DROP TABLE idempotency_keys")
            .execute(&pool)
            .await
            .expect("remove version 2 table");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite schema fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 1 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("simulate a version 1 database");
        sqlx::query("DROP TABLE controller_clock")
            .execute(&pool)
            .await
            .expect("remove version 3 table");
        sqlx::query("DROP TABLE idempotency_keys")
            .execute(&pool)
            .await
            .expect("remove version 2 table");
        pool.close().await;
    }

    let upgraded = Store::connect(&fixture.url)
        .await
        .expect("a supported older schema migrates forward");
    assert!(
        upgraded
            .secret_request_metadata(&request_id)
            .await
            .expect("read request after upgrade")
            .is_some(),
        "durable state survives a forward migration"
    );
    drop(upgraded);
    let (version, clock_present, idempotency_present) = if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("reopen PostgreSQL schema fixture");
        let version: i32 =
            sqlx::query_scalar("SELECT schema_version FROM controller_meta WHERE id = 1")
                .fetch_one(&pool)
                .await
                .expect("read schema version");
        let clock: bool = sqlx::query_scalar("SELECT to_regclass('controller_clock') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("inspect clock table");
        let idempotency: bool =
            sqlx::query_scalar("SELECT to_regclass('idempotency_keys') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .expect("inspect idempotency table");
        pool.close().await;
        (i64::from(version), clock, idempotency)
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("reopen SQLite schema fixture");
        let version: i64 =
            sqlx::query_scalar("SELECT schema_version FROM controller_meta WHERE id = 1")
                .fetch_one(&pool)
                .await
                .expect("read schema version");
        let clock: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'controller_clock')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect clock table");
        let idempotency: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'idempotency_keys')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect idempotency table");
        pool.close().await;
        (version, clock != 0, idempotency != 0)
    };
    // Version 4 adds boot-anchored clock checks to the controller clock table.
    assert_eq!(version, 4);
    assert!(clock_present && idempotency_present);
    fixture.close().await;
}

#[tokio::test]
async fn schema_v3_clock_migrates_to_v4_and_fences_unknown_boot_anchor() {
    let mut fixture = StoreFixture::new().await;
    fixture
        .store()
        .create_secret_request("upgrade-agent", "dummy-key", "v3 upgrade", "code", 60)
        .await
        .expect("create transient authority in the old schema");
    fixture.store.take();
    let columns = ["boot_id", "boottime_ms", "host_wall_ms", "fenced_at"];
    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL migration fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 3 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("mark schema as version 3");
        for column in columns {
            sqlx::query(&format!(
                "ALTER TABLE controller_clock DROP COLUMN {column}"
            ))
            .execute(&pool)
            .await
            .expect("remove v4 column from PostgreSQL fixture");
        }
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite migration fixture");
        sqlx::query("UPDATE controller_meta SET schema_version = 3 WHERE id = 1")
            .execute(&pool)
            .await
            .expect("mark schema as version 3");
        for column in columns {
            sqlx::query(&format!(
                "ALTER TABLE controller_clock DROP COLUMN {column}"
            ))
            .execute(&pool)
            .await
            .expect("remove v4 column from SQLite fixture");
        }
        pool.close().await;
    }

    let upgraded = Store::connect(&fixture.url)
        .await
        .expect("schema v3 upgrades and records unknown boot identity");
    assert!(!upgraded.is_ready().await);
    assert_eq!(fixture_table_count(&fixture, "secret_requests").await, 0);
    assert_eq!(
        fixture_action_count(&fixture, "clock_restart_fence").await,
        1
    );
    upgraded.close().await;
    fixture.close().await;
}

#[tokio::test]
async fn clock_reconciliation_purges_expiring_state_and_restores_startup() {
    let fixture = StoreFixture::new().await;
    let store = fixture.store();
    let request_id = store
        .create_secret_request("clock-agent", "dummy-public-key", "reconcile", "123456", 60)
        .await
        .expect("create request before regression");
    let exchange = store
        .create_exchange(exchange_record(&"e".repeat(64)), 60)
        .await
        .expect("create exchange before regression");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_millis() as i64;
    let approval = ApprovalRecord {
        approval_reference: "apr_clock_reconcile_pending".to_owned(),
        requester_id: "requester".to_owned(),
        workspace_id: store.tenant_id().to_owned(),
        secret_name: "restricted.secret".to_owned(),
        purpose: "clock reconciliation".to_owned(),
        fulfiller_hint: "fulfiller".to_owned(),
        rule_id: Some("approval-rule".to_owned()),
        reason: "requires approval".to_owned(),
        requester_ring: None,
        fulfiller_ring: None,
        approver_ids: vec!["approver".to_owned()],
        approver_rings: Vec::new(),
        status: "pending".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
        decided_at_ms: None,
        decided_by: None,
    };
    store
        .create_approval(&approval)
        .await
        .expect("create pending approval before regression");
    let mut approved = approval.clone();
    approved.approval_reference = "apr_clock_reconcile_approved".to_owned();
    store
        .create_approval(&approved)
        .await
        .expect("create approval to approve");
    store
        .decide_approval(&approved.approval_reference, "approved", "approver")
        .await
        .expect("approve before regression")
        .expect("pending approval is decided");
    let mut rejected = approval.clone();
    rejected.approval_reference = "apr_clock_reconcile_rejected".to_owned();
    store
        .create_approval(&rejected)
        .await
        .expect("create approval to reject");
    store
        .decide_approval(&rejected.approval_reference, "rejected", "approver")
        .await
        .expect("reject before regression")
        .expect("pending approval is decided");
    let mut idempotent = approval.clone();
    idempotent.approval_reference = "apr_clock_reconcile_idempotent".to_owned();
    store
        .create_approval(&idempotent)
        .await
        .expect("create approval to reject idempotently");
    assert!(matches!(
        store
            .decide_approval_idempotent(
                &idempotent.approval_reference,
                "rejected",
                "approver",
                &"d".repeat(64),
            )
            .await
            .expect("idempotent rejection before regression"),
        blindpass_controller::store::ApprovalDecisionOutcome::Applied(_)
    ));
    store
        .consume_rate_limit("agent-token:203.0.113.7", 5, 60_000)
        .await
        .expect("open a rate window before regression");
    assert!(
        store
            .issue_bootstrap_token("dummy-token-hash", 900)
            .await
            .expect("issue bootstrap token")
    );
    assert!(
        store
            .bootstrap_local_operator("op-clock", "admin", "Local Admin", "dummy-hash")
            .await
            .expect("bootstrap operator")
    );
    let session = store
        .create_browser_session("op-clock", "dummy-hash", "dummy-refresh-hash", 3_600)
        .await
        .expect("create session")
        .expect("operator is active");

    let healthy = Store::reconcile_clock(&fixture.url)
        .await
        .expect("reconciliation on a healthy clock");
    assert!(!healthy.regression_detected);
    assert_eq!(healthy.removed_secret_requests, 0);
    assert!(
        store
            .secret_request_metadata(&request_id)
            .await
            .expect("read request")
            .is_some(),
        "a healthy clock leaves state untouched"
    );

    if fixture.postgres_schema.is_some() {
        let pool = PgPool::connect(&fixture.url)
            .await
            .expect("connect PostgreSQL fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = $1 WHERE id = 1")
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .expect("simulate persisted future clock");
        pool.close().await;
    } else {
        let pool = sqlx::SqlitePool::connect(&fixture.url)
            .await
            .expect("connect SQLite fixture");
        sqlx::query("UPDATE controller_clock SET last_observed_ms = ? WHERE id = 1")
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .expect("simulate persisted future clock");
        pool.close().await;
    }
    assert!(matches!(
        Store::connect(&fixture.url).await,
        Err(StoreError::ClockRegression)
    ));

    let repaired = Store::reconcile_clock(&fixture.url)
        .await
        .expect("reconcile the regressed clock");
    assert!(repaired.regression_detected);
    assert_eq!(repaired.removed_secret_requests, 1);
    assert_eq!(repaired.removed_exchanges, 1);
    assert_eq!(repaired.removed_approvals, 2);
    assert_eq!(repaired.removed_bootstrap_tokens, 1);
    assert_eq!(repaired.removed_rate_windows, 1);
    assert_eq!(repaired.removed_idempotency_keys, 1);
    assert_eq!(repaired.revoked_sessions, 1);
    assert_eq!(repaired.persisted_ms, i64::MAX / 2);
    let host_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_millis() as i64;
    assert!(
        (repaired.database_now_ms - host_ms).abs() < 5_000,
        "database clock {} reported near host clock {host_ms}",
        repaired.database_now_ms
    );
    for table in ["rate_windows", "idempotency_keys", "bootstrap_tokens"] {
        assert_eq!(count_rows(&fixture, table).await, 0, "{table} purged");
    }

    let reopened = Store::connect(&fixture.url)
        .await
        .expect("startup succeeds after reconciliation");
    assert!(
        reopened
            .secret_request_metadata(&request_id)
            .await
            .expect("read request")
            .is_none()
    );
    assert!(
        reopened
            .get_exchange(&exchange.exchange_id)
            .await
            .expect("read exchange")
            .is_none()
    );
    assert!(
        reopened
            .get_approval(&approval.approval_reference)
            .await
            .expect("read approval")
            .is_none()
    );
    assert!(
        reopened
            .get_approval(&approved.approval_reference)
            .await
            .expect("read approved approval")
            .is_none(),
        "an approved approval must not keep authorizing exchanges after a regression"
    );
    assert_eq!(
        reopened
            .get_approval(&rejected.approval_reference)
            .await
            .expect("read rejected approval")
            .expect("rejected approval is kept")
            .status,
        "rejected"
    );
    assert_eq!(
        reopened
            .get_approval(&idempotent.approval_reference)
            .await
            .expect("read idempotently rejected approval")
            .expect("rejected approval is kept")
            .status,
        "rejected"
    );
    assert!(
        reopened
            .browser_session_by_id(&session.session_id)
            .await
            .expect("read session")
            .is_none()
    );
    assert!(
        reopened
            .has_active_admin()
            .await
            .expect("operators survive reconciliation")
    );
    let audit = reopened.list_audit(20).await.expect("list audit");
    let event = audit
        .iter()
        .find(|event| event.event_type == "clock_reconciled")
        .expect("reconciliation is audited");
    assert_eq!(event.metadata["removed_secret_requests"], 1);
    assert!(event.metadata.get("persisted_ms").is_some());
    drop(reopened);
    fixture.close().await;
}

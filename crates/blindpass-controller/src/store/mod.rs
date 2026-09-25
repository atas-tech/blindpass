// SPDX-License-Identifier: AGPL-3.0-only

//! Durable, tenant-scoped controller state. Expiry is checked in the same
//! database statement as every read or state transition; the sweeper only
//! bounds retention and is never an authorization mechanism.

use blindpass_core::clock::{
    ClockAnchor, ClockSample, ClockSource, StartupClockCheck, SystemClock, check_running_clock,
    check_startup_clock,
};
use rand::{RngCore, rngs::OsRng};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{PgPool, Row, SqlitePool, postgres::PgPoolOptions};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod authorization;
mod exchanges;
mod fleet;
mod grants;
mod node_channel;
mod operators;
pub use authorization::{
    FleetPolicyRecord, OperationApprovalDraft, OperationApprovalRecord, OperationCreateOutcome,
    OperationDecisionOutcome, OperationRecord, WorkloadRecord,
};
pub use exchanges::{
    ApprovalDecisionOutcome, ApprovalRecord, AuditRecord, ExchangePolicyRecord, ExchangeRecord,
    LifecycleRecord,
};
pub use fleet::{EnrollmentRecord, NodeRecord};
pub use grants::{GrantIssueDraft, GrantIssueOutcome, GrantRecord};
pub use node_channel::{InboxDocument, NodeChallenge, NodeEventInsert, NodeEventRecord};
pub use operators::{LocalOperator, LocalSession};

const SQLITE_WALL_NOW_MS: &str = "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)";
const POSTGRES_WALL_NOW_MS: &str = "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT";
const SQLITE_NOW_MS: &str = "(CASE WHEN CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) >= (SELECT last_observed_ms FROM controller_clock WHERE id = 1) THEN CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) ELSE NULL END)";
const POSTGRES_NOW_MS: &str = "(CASE WHEN FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT >= (SELECT last_observed_ms FROM controller_clock WHERE id = 1) THEN FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT ELSE NULL END)";
/// Current schema version. Versions 5-8 add fleet authorization and channel
/// state incrementally.
pub const SCHEMA_VERSION: i64 = 9;
/// Tables that must exist for a database that reports the given version.
/// A supported older version is migrated forward; a version whose tables
/// are missing is damaged and fails closed instead of being recreated.
const SCHEMA_TABLES: &[(i64, &[&str])] = &[
    (
        1,
        &[
            "controller_meta",
            "operators",
            "bootstrap_tokens",
            "operator_sessions",
            "agents",
            "secret_requests",
            "exchanges",
            "approvals",
            "exchange_lifecycle",
            "policies",
            "audit_events",
            "rate_windows",
            "quota_counters",
        ],
    ),
    (2, &["idempotency_keys"]),
    (3, &["controller_clock"]),
    (4, &["controller_clock"]),
    (
        5,
        &[
            "enrollment_requests",
            "nodes",
            "node_key_history",
            "node_sessions",
            "workloads",
            "fleet_policies",
            "operations",
            "operation_approvals",
            "grants",
            "grant_tombstones",
            "node_inbox",
            "node_events",
        ],
    ),
    (6, &["enrollment_requests"]),
    (7, &["node_challenges"]),
    (8, &["operation_approvals"]),
    (9, &["operations"]),
];
/// The persisted clock high-water mark advances at most this often, so
/// ordinary reads never take a write lock. The independent one-second clock
/// monitor refreshes it while `serve` is running; outside `serve`, store calls
/// (including the retention sweep) are the checkpoints.
const CLOCK_ADVANCE_INTERVAL_MS: i64 = 1_000;

#[derive(Debug)]
pub enum StoreError {
    Database(sqlx::Error),
    InvalidInput(&'static str),
    MissingState(&'static str),
    UnsupportedSchemaVersion,
    ClockRegression,
    ClockFenced,
    ClockSourceUnavailable,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("controller database operation failed"),
            Self::InvalidInput(field) => write!(formatter, "invalid store input: {field}"),
            Self::MissingState(field) => write!(formatter, "controller state is missing: {field}"),
            Self::UnsupportedSchemaVersion => {
                formatter.write_str("controller schema version is unsupported")
            }
            Self::ClockRegression => formatter.write_str("controller database clock regressed"),
            Self::ClockFenced => formatter.write_str("controller clock is fenced"),
            Self::ClockSourceUnavailable => {
                formatter.write_str("controller clock source is unavailable")
            }
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone)]
enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

#[derive(Clone)]
pub struct Store {
    database: Database,
    tenant_id: String,
    clock_source: Arc<dyn ClockSource>,
    clock_tolerance_ms: i64,
    clock_monitor: Arc<Mutex<Option<ClockMonitorSample>>>,
}

#[derive(Clone)]
struct ClockMonitorSample {
    database_ms: i64,
    host_wall_ms: i64,
    measured_at: Instant,
}

struct PersistedClockAnchor {
    last_observed_ms: i64,
    boot_id: Option<String>,
    boottime_ms: Option<i64>,
    host_wall_ms: Option<i64>,
    fenced_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRequestStatus {
    Pending,
    Submitted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub enc: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSecretRequest {
    pub id: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRequestMetadata {
    pub requester_agent_id: String,
    pub public_key: String,
    pub description: String,
    pub confirmation_code: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCredential {
    pub id: String,
    pub agent_id: String,
    pub name: String,
    pub api_key_hash: String,
    pub status: String,
    pub key_version: i64,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAgentRecord {
    pub id: String,
    pub agent_id: String,
    pub name: String,
    pub status: String,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocumentRecord {
    pub version: i64,
    pub document_json: String,
    pub updated_at_ms: i64,
    pub updated_by: Option<String>,
}

/// Outcome of an operator-initiated clock reconciliation (P02-D9).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClockReconciliation {
    pub regression_detected: bool,
    pub persisted_ms: i64,
    pub database_now_ms: i64,
    pub removed_secret_requests: u64,
    pub removed_exchanges: u64,
    pub removed_approvals: u64,
    pub removed_bootstrap_tokens: u64,
    pub removed_rate_windows: u64,
    pub removed_idempotency_keys: u64,
    pub revoked_sessions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitResult {
    pub count: i64,
    pub retry_after_seconds: u64,
}

impl Store {
    pub fn spawn_clock_monitor(&self) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                match store.monitor_clock().await {
                    Ok(()) | Err(StoreError::ClockFenced) => {}
                    Err(_) => tracing::warn!("controller clock monitor could not check the clock"),
                }
            }
        })
    }

    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        Self::connect_with_clock_source(url, Arc::new(SystemClock), 2_000).await
    }

    pub async fn connect_with_tolerance(url: &str, tolerance_ms: u64) -> Result<Self, StoreError> {
        Self::connect_with_clock_source(url, Arc::new(SystemClock), tolerance_ms).await
    }

    pub async fn connect_with_clock_source(
        url: &str,
        clock_source: Arc<dyn ClockSource>,
        tolerance_ms: u64,
    ) -> Result<Self, StoreError> {
        let clock_tolerance_ms = i64::try_from(tolerance_ms)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(StoreError::InvalidInput("clock tolerance"))?;
        let database = Database::connect(url).await?;
        database.validate_existing_schema_version().await?;
        database.migrate().await?;

        let candidate_tenant_id = new_uuid();
        match &database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT OR IGNORE INTO controller_meta
                     (id, schema_version, tenant_id, issuer_epoch, created_at)
                     VALUES (1, {SCHEMA_VERSION}, ?, 1, {SQLITE_WALL_NOW_MS})"
                );
                sqlx::query(&sql)
                    .bind(candidate_tenant_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET schema_version = ? WHERE id = 1 AND schema_version < ?")
                    .bind(SCHEMA_VERSION)
                    .bind(SCHEMA_VERSION)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO controller_meta
                     (id, schema_version, tenant_id, issuer_epoch, created_at)
                     VALUES (1, {SCHEMA_VERSION}, $1, 1, {POSTGRES_WALL_NOW_MS})
                     ON CONFLICT (id) DO NOTHING"
                );
                sqlx::query(&sql)
                    .bind(candidate_tenant_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET schema_version = $1 WHERE id = 1 AND schema_version < $1")
                    .bind(SCHEMA_VERSION)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        let tenant_id = match &database {
            Database::Sqlite(pool) => {
                sqlx::query("SELECT tenant_id FROM controller_meta WHERE id = 1")
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<String, _>(0)
                    .map_err(StoreError::Database)?
            }
            Database::Postgres(pool) => {
                sqlx::query("SELECT tenant_id FROM controller_meta WHERE id = 1")
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<String, _>(0)
                    .map_err(StoreError::Database)?
            }
        };
        let sample = clock_source
            .sample()
            .map_err(|_| StoreError::ClockSourceUnavailable)?;
        match &database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT OR IGNORE INTO controller_clock
                     (id, last_observed_ms, boot_id, boottime_ms, host_wall_ms, fenced_at)
                     VALUES (1, {SQLITE_WALL_NOW_MS}, ?, ?, ?, NULL)"
                );
                sqlx::query(&sql)
                    .bind(&sample.boot_id)
                    .bind(sample.boottime_ms)
                    .bind(sample.host_wall_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO controller_clock
                     (id, last_observed_ms, boot_id, boottime_ms, host_wall_ms, fenced_at)
                     VALUES (1, {POSTGRES_WALL_NOW_MS}, $1, $2, $3, NULL)
                     ON CONFLICT (id) DO NOTHING"
                );
                sqlx::query(&sql)
                    .bind(&sample.boot_id)
                    .bind(sample.boottime_ms)
                    .bind(sample.host_wall_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        let store = Self {
            database,
            tenant_id,
            clock_source,
            clock_tolerance_ms,
            clock_monitor: Arc::new(Mutex::new(None)),
        };
        let database_ms = database_wall_now_ms(&store.database).await?;
        store.initialize_clock(sample, database_ms).await?;
        Ok(store)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub async fn database_now_ms(&self) -> Result<i64, StoreError> {
        self.checkpoint_clock().await?;
        database_wall_now_ms(&self.database).await
    }

    /// Current signing recovery epoch published to enrolled nodes.
    pub async fn issuer_epoch(&self) -> Result<u64, StoreError> {
        let epoch = match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
                "SELECT issuer_epoch FROM controller_meta WHERE id = 1",
            )
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?,
            Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(
                "SELECT issuer_epoch FROM controller_meta WHERE id = 1",
            )
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?,
        };
        u64::try_from(epoch).map_err(|_| StoreError::MissingState("issuer epoch"))
    }

    /// Close the shared connection pool during shutdown. Existing `Store`
    /// clones observe the closure, so readiness fails immediately afterward.
    pub async fn close(&self) {
        match &self.database {
            Database::Sqlite(pool) => pool.close().await,
            Database::Postgres(pool) => pool.close().await,
        }
    }

    async fn initialize_clock(
        &self,
        sample: ClockSample,
        database_now_ms: i64,
    ) -> Result<(), StoreError> {
        let anchor = read_clock_anchor(&self.database).await?;
        if anchor.fenced_at.is_some() {
            self.set_monitor_sample(database_now_ms, sample.host_wall_ms)?;
            return Ok(());
        }
        let previous = ClockAnchor {
            boot_id: anchor.boot_id,
            boottime_ms: anchor.boottime_ms.unwrap_or_default(),
            database_ms: anchor.last_observed_ms,
            host_wall_ms: anchor.host_wall_ms.unwrap_or_default(),
        };
        let current = ClockAnchor {
            boot_id: sample.boot_id.clone(),
            boottime_ms: sample.boottime_ms,
            database_ms: database_now_ms,
            host_wall_ms: sample.host_wall_ms,
        };
        let check = check_startup_clock(&previous, &current, self.clock_tolerance_ms);
        match check {
            StartupClockCheck::SameBoot => {
                update_clock_anchor(&self.database, &sample, database_now_ms).await?;
                self.set_monitor_sample(database_now_ms, sample.host_wall_ms)?;
                Ok(())
            }
            StartupClockCheck::BootChangedOrUnknown => {
                self.fence_after_restart(&sample, database_now_ms).await?;
                self.set_monitor_sample(database_now_ms, sample.host_wall_ms)?;
                Ok(())
            }
            StartupClockCheck::DatabaseRegressed
            | StartupClockCheck::HostRegressed
            | StartupClockCheck::BothRegressed => {
                self.persist_clock_fence(database_now_ms).await?;
                tracing::warn!(event = "clock_regression_detected", check = ?check);
                Err(StoreError::ClockRegression)
            }
        }
    }

    fn set_monitor_sample(&self, database_ms: i64, host_wall_ms: i64) -> Result<(), StoreError> {
        let mut previous = self
            .clock_monitor
            .lock()
            .map_err(|_| StoreError::ClockFenced)?;
        *previous = Some(ClockMonitorSample {
            database_ms,
            host_wall_ms,
            measured_at: Instant::now(),
        });
        Ok(())
    }

    async fn persist_clock_fence(&self, database_now_ms: i64) -> Result<(), StoreError> {
        match &self.database {
            Database::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE controller_clock SET fenced_at = ? WHERE id = 1 AND fenced_at IS NULL",
                )
                .bind(database_now_ms)
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                sqlx::query(
                    "UPDATE controller_clock SET fenced_at = $1 WHERE id = 1 AND fenced_at IS NULL",
                )
                .bind(database_now_ms)
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
            }
        }
        Ok(())
    }

    async fn fence_after_restart(
        &self,
        sample: &ClockSample,
        database_now_ms: i64,
    ) -> Result<(), StoreError> {
        let metadata;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let fenced = sqlx::query(
                    "UPDATE controller_clock SET fenced_at = ? WHERE id = 1 AND fenced_at IS NULL",
                )
                .bind(database_now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if fenced == 0 {
                    transaction.rollback().await.map_err(StoreError::Database)?;
                    return Ok(());
                }
                let removed_secret_requests = sqlx::query("DELETE FROM secret_requests")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_exchanges = sqlx::query("DELETE FROM exchanges")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_approvals =
                    sqlx::query("DELETE FROM approvals WHERE status = 'pending'")
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected();
                let removed_bootstrap_tokens = sqlx::query("DELETE FROM bootstrap_tokens")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_rate_windows = sqlx::query("DELETE FROM rate_windows")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_idempotency_keys = sqlx::query("DELETE FROM idempotency_keys")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let counts = serde_json::json!({
                    "removed_secret_requests":removed_secret_requests,
                    "removed_exchanges":removed_exchanges,
                    "removed_pending_approvals":removed_approvals,
                    "removed_bootstrap_tokens":removed_bootstrap_tokens,
                    "removed_rate_windows":removed_rate_windows,
                    "removed_idempotency_keys":removed_idempotency_keys
                });
                metadata = serde_json::to_string(&counts)
                    .map_err(|_| StoreError::InvalidInput("clock fence audit metadata"))?;
                sqlx::query(
                    "UPDATE controller_clock SET last_observed_ms = ?, boot_id = ?, boottime_ms = ?, host_wall_ms = ? WHERE id = 1",
                )
                .bind(database_now_ms)
                .bind(&sample.boot_id)
                .bind(sample.boottime_ms)
                .bind(sample.host_wall_ms)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at) VALUES (?, ?, 'system', NULL, 'clock_restart_fence', 'controller', NULL, ?, ?)",
                )
                .bind(new_hex_id())
                .bind(&self.tenant_id)
                .bind(&metadata)
                .bind(database_now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let fenced = sqlx::query(
                    "UPDATE controller_clock SET fenced_at = $1 WHERE id = 1 AND fenced_at IS NULL",
                )
                .bind(database_now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if fenced == 0 {
                    transaction.rollback().await.map_err(StoreError::Database)?;
                    return Ok(());
                }
                let removed_secret_requests = sqlx::query("DELETE FROM secret_requests")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_exchanges = sqlx::query("DELETE FROM exchanges")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_approvals =
                    sqlx::query("DELETE FROM approvals WHERE status = 'pending'")
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected();
                let removed_bootstrap_tokens = sqlx::query("DELETE FROM bootstrap_tokens")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_rate_windows = sqlx::query("DELETE FROM rate_windows")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let removed_idempotency_keys = sqlx::query("DELETE FROM idempotency_keys")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let counts = serde_json::json!({
                    "removed_secret_requests":removed_secret_requests,
                    "removed_exchanges":removed_exchanges,
                    "removed_pending_approvals":removed_approvals,
                    "removed_bootstrap_tokens":removed_bootstrap_tokens,
                    "removed_rate_windows":removed_rate_windows,
                    "removed_idempotency_keys":removed_idempotency_keys
                });
                metadata = serde_json::to_string(&counts)
                    .map_err(|_| StoreError::InvalidInput("clock fence audit metadata"))?;
                sqlx::query(
                    "UPDATE controller_clock SET last_observed_ms = $1, boot_id = $2, boottime_ms = $3, host_wall_ms = $4 WHERE id = 1",
                )
                .bind(database_now_ms)
                .bind(&sample.boot_id)
                .bind(sample.boottime_ms)
                .bind(sample.host_wall_ms)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at) VALUES ($1, $2, 'system', NULL, 'clock_restart_fence', 'controller', NULL, $3, $4)",
                )
                .bind(new_hex_id())
                .bind(&self.tenant_id)
                .bind(&metadata)
                .bind(database_now_ms)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
            }
        }
        tracing::warn!(
            event = "clock_restart_fence",
            "controller clock fenced after boot identity changed or became unreadable"
        );
        Ok(())
    }

    /// Compare host and database time against the previous one-second monitor
    /// sample. A regression beyond the configured tolerance is fenced in the
    /// shared database row so every process and store clone refuses writes.
    pub async fn monitor_clock(&self) -> Result<(), StoreError> {
        let database_ms = database_wall_now_ms(&self.database).await?;
        let sample = match self.clock_source.sample() {
            Ok(sample) => sample,
            Err(_) => {
                self.persist_clock_fence(database_ms).await?;
                tracing::warn!(
                    event = "clock_source_unavailable",
                    "controller clock source became unavailable"
                );
                return Err(StoreError::ClockFenced);
            }
        };
        let anchor = read_clock_anchor(&self.database).await?;
        if anchor.fenced_at.is_some() {
            return Err(StoreError::ClockFenced);
        }
        if anchor.boot_id.as_deref() != sample.boot_id.as_deref() || sample.boot_id.is_none() {
            self.fence_after_restart(&sample, database_ms).await?;
            return Err(StoreError::ClockFenced);
        }
        let previous = self
            .clock_monitor
            .lock()
            .map_err(|_| StoreError::ClockFenced)?
            .clone()
            .ok_or(StoreError::ClockFenced)?;
        let elapsed_ms =
            i64::try_from(previous.measured_at.elapsed().as_millis()).unwrap_or(i64::MAX);
        let check = check_running_clock(
            previous.database_ms,
            previous.host_wall_ms,
            database_ms,
            sample.host_wall_ms,
            elapsed_ms,
            self.clock_tolerance_ms,
        );
        if check.database_regressed || check.host_regressed {
            self.persist_clock_fence(database_ms).await?;
            tracing::warn!(
                event = "clock_regression_detected",
                database_regressed = check.database_regressed,
                host_regressed = check.host_regressed,
                "controller clock regression exceeded tolerance"
            );
            return Err(StoreError::ClockFenced);
        }
        if check.database_advanced || check.host_advanced {
            tracing::info!(
                event = "clock_forward_jump",
                database_advanced = check.database_advanced,
                host_advanced = check.host_advanced,
                "controller clock advanced beyond monotonic elapsed time"
            );
        }
        update_clock_anchor(&self.database, &sample, database_ms).await?;
        self.set_monitor_sample(database_ms, sample.host_wall_ms)?;
        Ok(())
    }

    pub async fn is_ready(&self) -> bool {
        if self.checkpoint_clock().await.is_err() {
            return false;
        }
        match &self.database {
            Database::Sqlite(pool) => sqlx::query("SELECT 1")
                .fetch_one(pool)
                .await
                .is_ok_and(|row| row.try_get::<i32, _>(0).ok() == Some(1)),
            Database::Postgres(pool) => sqlx::query("SELECT 1")
                .fetch_one(pool)
                .await
                .is_ok_and(|row| row.try_get::<i32, _>(0).ok() == Some(1)),
        }
    }

    /// Refuse every store operation while the durable clock fence is set.
    /// A separate one-second monitor compares host and database clocks while
    /// `serve` is running; this checkpoint also verifies the running clock on
    /// store calls used by shell commands and test fixtures.
    async fn checkpoint_clock(&self) -> Result<(), StoreError> {
        let anchor = read_clock_anchor(&self.database).await?;
        if anchor.fenced_at.is_some() {
            return Err(StoreError::ClockFenced);
        }
        let now = database_wall_now_ms(&self.database).await?;
        let sample = match self.clock_source.sample() {
            Ok(sample) => sample,
            Err(_) => {
                self.persist_clock_fence(now).await?;
                tracing::warn!(
                    event = "clock_source_unavailable",
                    "controller clock source became unavailable"
                );
                return Err(StoreError::ClockFenced);
            }
        };
        if anchor.boot_id.as_deref() != sample.boot_id.as_deref() || sample.boot_id.is_none() {
            self.fence_after_restart(&sample, now).await?;
            return Err(StoreError::ClockFenced);
        }
        let previous = self
            .clock_monitor
            .lock()
            .map_err(|_| StoreError::ClockFenced)?
            .clone()
            .ok_or(StoreError::ClockFenced)?;
        let elapsed_ms =
            i64::try_from(previous.measured_at.elapsed().as_millis()).unwrap_or(i64::MAX);
        let check = check_running_clock(
            previous.database_ms,
            previous.host_wall_ms,
            now,
            sample.host_wall_ms,
            elapsed_ms,
            self.clock_tolerance_ms,
        );
        let checkpoint_regressed =
            now.saturating_add(self.clock_tolerance_ms) < anchor.last_observed_ms;
        if check.database_regressed || check.host_regressed || checkpoint_regressed {
            self.persist_clock_fence(now).await?;
            tracing::warn!(
                event = "clock_regression_detected",
                database_regressed = check.database_regressed,
                host_regressed = check.host_regressed,
                checkpoint_regressed,
                "controller clock regression exceeded tolerance"
            );
            return Err(StoreError::ClockRegression);
        }
        if check.database_advanced || check.host_advanced {
            tracing::info!(
                event = "clock_forward_jump",
                database_advanced = check.database_advanced,
                host_advanced = check.host_advanced,
                "controller clock advanced beyond monotonic elapsed time"
            );
        }
        if now < anchor.last_observed_ms
            || now.saturating_sub(anchor.last_observed_ms) >= CLOCK_ADVANCE_INTERVAL_MS
        {
            update_clock_anchor(&self.database, &sample, now).await?;
        }
        self.set_monitor_sample(now, sample.host_wall_ms)?;
        Ok(())
    }

    /// Recover a database whose persisted clock high-water mark is ahead of
    /// the database wall clock, for example after a snapshot restore or a
    /// host clock step. Nothing changes unless a regression is present. When
    /// it is, every deadline was computed from a clock ahead of the current
    /// one, so live records would outlive their intended lifetime and
    /// already-expired records would become readable again. Those records
    /// are removed rather than trusted: secret requests, exchanges, pending
    /// and approved approvals, bootstrap tokens, rate windows and
    /// idempotency keys are deleted, operator sessions are revoked, the mark
    /// is reset to the current database clock and one audit event records
    /// the counts. Operators, agents, policy, rejected approvals, lifecycle
    /// and audit history are kept. Run this from the CLI while the controller
    /// is stopped; readiness and all store transitions fail closed until it has run.
    pub async fn reconcile_clock(url: &str) -> Result<ClockReconciliation, StoreError> {
        let database = Database::connect(url).await?;
        database.validate_existing_schema_version().await?;
        if !database.table_exists("controller_clock").await? {
            return Err(StoreError::MissingState("controller clock"));
        }
        let sample = SystemClock
            .sample()
            .map_err(|_| StoreError::ClockSourceUnavailable)?;
        if sample.boot_id.is_none() {
            return Err(StoreError::ClockSourceUnavailable);
        }
        let summary = match &database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query(
                    "UPDATE controller_clock SET last_observed_ms = last_observed_ms WHERE id = 1",
                )
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let sql = format!(
                    "SELECT last_observed_ms, fenced_at, {SQLITE_WALL_NOW_MS} FROM controller_clock WHERE id = 1"
                );
                let row = sqlx::query(&sql)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let persisted_ms: i64 = row.try_get(0).map_err(StoreError::Database)?;
                let fenced_at: Option<i64> = row.try_get(1).map_err(StoreError::Database)?;
                let database_now_ms: i64 = row.try_get(2).map_err(StoreError::Database)?;
                let mut summary = ClockReconciliation {
                    regression_detected: database_now_ms < persisted_ms || fenced_at.is_some(),
                    persisted_ms,
                    database_now_ms,
                    removed_secret_requests: 0,
                    removed_exchanges: 0,
                    removed_approvals: 0,
                    removed_bootstrap_tokens: 0,
                    removed_rate_windows: 0,
                    removed_idempotency_keys: 0,
                    revoked_sessions: 0,
                };
                if !summary.regression_detected {
                    transaction.rollback().await.map_err(StoreError::Database)?;
                    return Ok(summary);
                }
                summary.removed_secret_requests = sqlx::query("DELETE FROM secret_requests")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_exchanges = sqlx::query("DELETE FROM exchanges")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_approvals =
                    sqlx::query("DELETE FROM approvals WHERE status IN ('pending', 'approved')")
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected();
                summary.removed_bootstrap_tokens = sqlx::query("DELETE FROM bootstrap_tokens")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_rate_windows = sqlx::query("DELETE FROM rate_windows")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_idempotency_keys = sqlx::query("DELETE FROM idempotency_keys")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let sql = format!(
                    "UPDATE operator_sessions SET revoked_at = {SQLITE_WALL_NOW_MS} WHERE revoked_at IS NULL"
                );
                summary.revoked_sessions = sqlx::query(&sql)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                sqlx::query(
                    "UPDATE controller_clock SET last_observed_ms = ?, boot_id = ?, boottime_ms = ?, host_wall_ms = ?, fenced_at = NULL WHERE id = 1",
                )
                    .bind(database_now_ms)
                    .bind(&sample.boot_id)
                    .bind(sample.boottime_ms)
                    .bind(sample.host_wall_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let tenant_id: String =
                    sqlx::query_scalar("SELECT tenant_id FROM controller_meta WHERE id = 1")
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                let metadata = serde_json::to_string(&summary)
                    .map_err(|_| StoreError::InvalidInput("reconciliation metadata"))?;
                let sql = format!(
                    "INSERT INTO audit_events
                     (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                     VALUES (?, ?, 'system', NULL, 'clock_reconciled', 'controller', NULL, ?, {SQLITE_WALL_NOW_MS})"
                );
                sqlx::query(&sql)
                    .bind(new_hex_id())
                    .bind(tenant_id)
                    .bind(metadata)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                summary
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let row = sqlx::query(
                    "SELECT last_observed_ms, fenced_at FROM controller_clock WHERE id = 1 FOR UPDATE",
                )
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let persisted_ms: i64 = row.try_get(0).map_err(StoreError::Database)?;
                let fenced_at: Option<i64> = row.try_get(1).map_err(StoreError::Database)?;
                let sql = format!("SELECT {POSTGRES_WALL_NOW_MS}");
                let database_now_ms: i64 = sqlx::query_scalar(&sql)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let mut summary = ClockReconciliation {
                    regression_detected: database_now_ms < persisted_ms || fenced_at.is_some(),
                    persisted_ms,
                    database_now_ms,
                    removed_secret_requests: 0,
                    removed_exchanges: 0,
                    removed_approvals: 0,
                    removed_bootstrap_tokens: 0,
                    removed_rate_windows: 0,
                    removed_idempotency_keys: 0,
                    revoked_sessions: 0,
                };
                if !summary.regression_detected {
                    transaction.rollback().await.map_err(StoreError::Database)?;
                    return Ok(summary);
                }
                summary.removed_secret_requests = sqlx::query("DELETE FROM secret_requests")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_exchanges = sqlx::query("DELETE FROM exchanges")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_approvals =
                    sqlx::query("DELETE FROM approvals WHERE status IN ('pending', 'approved')")
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected();
                summary.removed_bootstrap_tokens = sqlx::query("DELETE FROM bootstrap_tokens")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_rate_windows = sqlx::query("DELETE FROM rate_windows")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                summary.removed_idempotency_keys = sqlx::query("DELETE FROM idempotency_keys")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let sql = format!(
                    "UPDATE operator_sessions SET revoked_at = {POSTGRES_WALL_NOW_MS} WHERE revoked_at IS NULL"
                );
                summary.revoked_sessions = sqlx::query(&sql)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                sqlx::query(
                    "UPDATE controller_clock SET last_observed_ms = $1, boot_id = $2, boottime_ms = $3, host_wall_ms = $4, fenced_at = NULL WHERE id = 1",
                )
                    .bind(database_now_ms)
                    .bind(&sample.boot_id)
                    .bind(sample.boottime_ms)
                    .bind(sample.host_wall_ms)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let tenant_id: String =
                    sqlx::query_scalar("SELECT tenant_id FROM controller_meta WHERE id = 1")
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                let metadata = serde_json::to_string(&summary)
                    .map_err(|_| StoreError::InvalidInput("reconciliation metadata"))?;
                let sql = format!(
                    "INSERT INTO audit_events
                     (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                     VALUES ($1, $2, 'system', NULL, 'clock_reconciled', 'controller', NULL, $3, {POSTGRES_WALL_NOW_MS})"
                );
                sqlx::query(&sql)
                    .bind(new_hex_id())
                    .bind(tenant_id)
                    .bind(metadata)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                summary
            }
        };
        match &database {
            Database::Sqlite(pool) => pool.close().await,
            Database::Postgres(pool) => pool.close().await,
        }
        Ok(summary)
    }

    pub async fn policy_document(&self) -> Result<Option<PolicyDocumentRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT version, document_json, updated_at, updated_by
                    FROM policies WHERE tenant_id = ?",
                )
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref()
                    .map(|row| {
                        Ok(PolicyDocumentRecord {
                            version: row.try_get(0).map_err(StoreError::Database)?,
                            document_json: row.try_get(1).map_err(StoreError::Database)?,
                            updated_at_ms: row.try_get(2).map_err(StoreError::Database)?,
                            updated_by: row.try_get(3).map_err(StoreError::Database)?,
                        })
                    })
                    .transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT version, document_json, updated_at, updated_by
                    FROM policies WHERE tenant_id = $1",
                )
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref()
                    .map(|row| {
                        Ok(PolicyDocumentRecord {
                            version: row
                                .try_get::<i32, _>(0)
                                .map(i64::from)
                                .map_err(StoreError::Database)?,
                            document_json: row.try_get(1).map_err(StoreError::Database)?,
                            updated_at_ms: row.try_get(2).map_err(StoreError::Database)?,
                            updated_by: row.try_get(3).map_err(StoreError::Database)?,
                        })
                    })
                    .transpose()
            }
        }
    }

    /// Replace the persisted policy only when its expected version still matches.
    /// An absent row represents version 1 seeded from local configuration.
    pub async fn replace_policy_document(
        &self,
        expected_version: i64,
        document_json: &str,
        updated_by: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.checkpoint_clock().await?;
        if expected_version < 1 || document_json.is_empty() || updated_by.is_empty() {
            return Err(StoreError::InvalidInput("policy document"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let update = format!("UPDATE policies SET version = version + 1,
                    document_json = ?, source = 'admin', updated_at = {SQLITE_NOW_MS}, updated_by = ?
                    WHERE tenant_id = ? AND version = ? RETURNING version");
                if let Some(row) = sqlx::query(&update)
                    .bind(document_json)
                    .bind(updated_by)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                {
                    let version = row.try_get(0).map_err(StoreError::Database)?;
                    crate::p02_test_failpoint("policy-before-commit");
                    transaction.commit().await.map_err(StoreError::Database)?;
                    crate::p02_test_failpoint("policy-after-commit");
                    return Ok(Some(version));
                }
                if expected_version == 1 {
                    let insert = format!(
                        "INSERT INTO policies
                        (tenant_id, version, document_json, source, updated_at, updated_by)
                        VALUES (?, 2, ?, 'admin', {SQLITE_NOW_MS}, ?)
                        ON CONFLICT(tenant_id) DO NOTHING RETURNING version"
                    );
                    let row = sqlx::query(&insert)
                        .bind(&self.tenant_id)
                        .bind(document_json)
                        .bind(updated_by)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                    if let Some(row) = row {
                        let version = row.try_get(0).map_err(StoreError::Database)?;
                        crate::p02_test_failpoint("policy-before-commit");
                        transaction.commit().await.map_err(StoreError::Database)?;
                        crate::p02_test_failpoint("policy-after-commit");
                        return Ok(Some(version));
                    }
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(None)
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let current =
                    sqlx::query("SELECT version FROM policies WHERE tenant_id = $1 FOR UPDATE")
                        .bind(&self.tenant_id)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                if let Some(current) = current {
                    let version =
                        i64::from(current.try_get::<i32, _>(0).map_err(StoreError::Database)?);
                    if version != expected_version {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(None);
                    }
                    let update = format!("UPDATE policies SET version = version + 1,
                        document_json = $1, source = 'admin', updated_at = {POSTGRES_NOW_MS}, updated_by = $2
                        WHERE tenant_id = $3 AND version = $4 RETURNING version");
                    let row = sqlx::query(&update)
                        .bind(document_json)
                        .bind(updated_by)
                        .bind(&self.tenant_id)
                        .bind(expected_version)
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                    let version =
                        i64::from(row.try_get::<i32, _>(0).map_err(StoreError::Database)?);
                    crate::p02_test_failpoint("policy-before-commit");
                    transaction.commit().await.map_err(StoreError::Database)?;
                    crate::p02_test_failpoint("policy-after-commit");
                    return Ok(Some(version));
                }
                if expected_version == 1 {
                    let insert = format!(
                        "INSERT INTO policies
                        (tenant_id, version, document_json, source, updated_at, updated_by)
                        VALUES ($1, 2, $2, 'admin', {POSTGRES_NOW_MS}, $3)
                        ON CONFLICT(tenant_id) DO NOTHING RETURNING version"
                    );
                    let row = sqlx::query(&insert)
                        .bind(&self.tenant_id)
                        .bind(document_json)
                        .bind(updated_by)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?;
                    if let Some(row) = row {
                        let version =
                            i64::from(row.try_get::<i32, _>(0).map_err(StoreError::Database)?);
                        crate::p02_test_failpoint("policy-before-commit");
                        transaction.commit().await.map_err(StoreError::Database)?;
                        crate::p02_test_failpoint("policy-after-commit");
                        return Ok(Some(version));
                    }
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(None)
            }
        }
    }

    /// Delete expired durable ciphertext after the configured retention grace.
    /// Every public read and transition checks its own expiry, so this worker
    /// controls retention rather than authority.
    pub async fn sweep_expired(&self, retention_grace_seconds: u64) -> Result<u64, StoreError> {
        self.checkpoint_clock().await?;
        let grace_ms = positive_milliseconds(retention_grace_seconds.max(1), "sweep grace")?;
        let mut removed = 0_u64;
        match &self.database {
            Database::Sqlite(pool) => {
                let requests =
                    format!("DELETE FROM secret_requests WHERE expires_at + ? <= {SQLITE_NOW_MS}");
                removed += sqlx::query(&requests)
                    .bind(grace_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let exchanges =
                    format!("DELETE FROM exchanges WHERE expires_at + ? <= {SQLITE_NOW_MS}");
                removed += sqlx::query(&exchanges)
                    .bind(grace_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let approvals =
                    format!("DELETE FROM approvals WHERE expires_at + ? <= {SQLITE_NOW_MS}");
                removed += sqlx::query(&approvals)
                    .bind(grace_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let rate_windows =
                    format!("DELETE FROM rate_windows WHERE expires_at <= {SQLITE_NOW_MS}");
                removed += sqlx::query(&rate_windows)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let idempotency =
                    format!("DELETE FROM idempotency_keys WHERE expires_at <= {SQLITE_NOW_MS}");
                removed += sqlx::query(&idempotency)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
            }
            Database::Postgres(pool) => {
                let requests = format!(
                    "DELETE FROM secret_requests WHERE expires_at + $1::BIGINT <= {POSTGRES_NOW_MS}"
                );
                removed += sqlx::query(&requests)
                    .bind(grace_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let exchanges = format!(
                    "DELETE FROM exchanges WHERE expires_at + $1::BIGINT <= {POSTGRES_NOW_MS}"
                );
                removed += sqlx::query(&exchanges)
                    .bind(grace_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let approvals = format!(
                    "DELETE FROM approvals WHERE expires_at + $1::BIGINT <= {POSTGRES_NOW_MS}"
                );
                removed += sqlx::query(&approvals)
                    .bind(grace_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let rate_windows =
                    format!("DELETE FROM rate_windows WHERE expires_at <= {POSTGRES_NOW_MS}");
                removed += sqlx::query(&rate_windows)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
                let idempotency =
                    format!("DELETE FROM idempotency_keys WHERE expires_at <= {POSTGRES_NOW_MS}");
                removed += sqlx::query(&idempotency)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected();
            }
        }
        Ok(removed)
    }

    /// Apply the audit log's day-based retention separately from ciphertext
    /// expiry. A short ciphertext grace must never prune fresh audit history.
    pub async fn sweep_audit(&self, retention_days: u32) -> Result<u64, StoreError> {
        self.checkpoint_clock().await?;
        let retention_ms = i64::from(retention_days)
            .checked_mul(86_400_000)
            .filter(|value| *value > 0)
            .ok_or(StoreError::InvalidInput("audit retention"))?;
        let affected = match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "DELETE FROM audit_events WHERE tenant_id = ? AND created_at <= {SQLITE_NOW_MS} - ?"
                );
                sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(retention_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "DELETE FROM audit_events WHERE tenant_id = $1 AND created_at <= {POSTGRES_NOW_MS} - $2::BIGINT"
                );
                sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(retention_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected()
            }
        };
        Ok(affected)
    }

    pub async fn create_agent(
        &self,
        agent_id: &str,
        name: &str,
        ring: Option<&str>,
        api_key_hash: &str,
    ) -> Result<AgentCredential, StoreError> {
        self.create_agent_with_id(&new_uuid(), agent_id, name, ring, api_key_hash)
            .await
    }

    pub async fn create_agent_with_id(
        &self,
        id: &str,
        agent_id: &str,
        name: &str,
        ring: Option<&str>,
        api_key_hash: &str,
    ) -> Result<AgentCredential, StoreError> {
        self.checkpoint_clock().await?;
        if agent_id.trim().is_empty() || name.trim().is_empty() || api_key_hash.is_empty() {
            return Err(StoreError::InvalidInput("agent"));
        }
        if id.len() != 36 {
            return Err(StoreError::InvalidInput("agent id"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO agents (id, tenant_id, agent_id, name, ring, api_key_hash,
                                         key_version, status, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, 1, 'active', {SQLITE_NOW_MS})
                     RETURNING id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at"
                );
                let row = sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(agent_id.trim())
                    .bind(name.trim())
                    .bind(ring)
                    .bind(api_key_hash)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?;
                agent_credential_from_sqlite(&row)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO agents (id, tenant_id, agent_id, name, ring, api_key_hash,
                                         key_version, status, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6, 1, 'active', {POSTGRES_NOW_MS})
                     RETURNING id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at"
                );
                let row = sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(agent_id.trim())
                    .bind(name.trim())
                    .bind(ring)
                    .bind(api_key_hash)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?;
                agent_credential_from_postgres(&row)
            }
        }
    }

    pub async fn agent_by_key_id(&self, id: &str) -> Result<Option<AgentCredential>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query("SELECT id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at FROM agents WHERE id = ? AND tenant_id = ?")
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(agent_credential_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query("SELECT id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at FROM agents WHERE id = $1 AND tenant_id = $2")
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(agent_credential_from_postgres).transpose()
            }
        }
    }

    pub async fn agent_by_agent_id(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentCredential>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query("SELECT id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at FROM agents WHERE agent_id = ? AND tenant_id = ?")
                    .bind(agent_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(agent_credential_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let row = sqlx::query("SELECT id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at FROM agents WHERE agent_id = $1 AND tenant_id = $2")
                    .bind(agent_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(agent_credential_from_postgres).transpose()
            }
        }
    }

    pub async fn list_admin_agents(&self) -> Result<Vec<AdminAgentRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT id, agent_id, name, status, created_at, revoked_at
                    FROM agents WHERE tenant_id = ? ORDER BY agent_id, id",
                )
                .bind(&self.tenant_id)
                .fetch_all(pool)
                .await
                .map_err(StoreError::Database)?;
                rows.iter()
                    .map(|row| {
                        Ok(AdminAgentRecord {
                            id: row.try_get(0).map_err(StoreError::Database)?,
                            agent_id: row.try_get(1).map_err(StoreError::Database)?,
                            name: row.try_get(2).map_err(StoreError::Database)?,
                            status: row.try_get(3).map_err(StoreError::Database)?,
                            created_at_ms: row.try_get(4).map_err(StoreError::Database)?,
                            revoked_at_ms: row.try_get(5).map_err(StoreError::Database)?,
                        })
                    })
                    .collect()
            }
            Database::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT id, agent_id, name, status, created_at, revoked_at
                    FROM agents WHERE tenant_id = $1 ORDER BY agent_id, id",
                )
                .bind(&self.tenant_id)
                .fetch_all(pool)
                .await
                .map_err(StoreError::Database)?;
                rows.iter()
                    .map(|row| {
                        Ok(AdminAgentRecord {
                            id: row.try_get(0).map_err(StoreError::Database)?,
                            agent_id: row.try_get(1).map_err(StoreError::Database)?,
                            name: row.try_get(2).map_err(StoreError::Database)?,
                            status: row.try_get(3).map_err(StoreError::Database)?,
                            created_at_ms: row.try_get(4).map_err(StoreError::Database)?,
                            revoked_at_ms: row.try_get(5).map_err(StoreError::Database)?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn replace_agent_api_key_hash(
        &self,
        agent_id: &str,
        expected_key_version: i64,
        api_key_hash: &str,
    ) -> Result<Option<AgentCredential>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE agents SET api_key_hash = ?, key_version = key_version + 1,
                                       rotated_at = {SQLITE_NOW_MS}
                     WHERE agent_id = ? AND tenant_id = ? AND status = 'active' AND key_version = ?
                       AND {SQLITE_NOW_MS} IS NOT NULL
                     RETURNING id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at"
                );
                let row = sqlx::query(&sql)
                    .bind(api_key_hash)
                    .bind(agent_id)
                    .bind(&self.tenant_id)
                    .bind(expected_key_version)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(agent_credential_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "UPDATE agents SET api_key_hash = $1, key_version = key_version + 1,
                                       rotated_at = {POSTGRES_NOW_MS}
                     WHERE agent_id = $2 AND tenant_id = $3 AND status = 'active' AND key_version = $4
                       AND {POSTGRES_NOW_MS} IS NOT NULL
                     RETURNING id, agent_id, name, api_key_hash, status, key_version, created_at, revoked_at"
                );
                let row = sqlx::query(&sql)
                    .bind(api_key_hash)
                    .bind(agent_id)
                    .bind(&self.tenant_id)
                    .bind(expected_key_version)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(agent_credential_from_postgres).transpose()
            }
        }
    }

    pub async fn revoke_agent(&self, agent_id: &str) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE agents SET status = 'revoked', revoked_at = {SQLITE_NOW_MS}
                     WHERE agent_id = ? AND tenant_id = ? AND status = 'active'
                       AND {SQLITE_NOW_MS} IS NOT NULL"
                );
                let result = sqlx::query(&sql)
                    .bind(agent_id)
                    .bind(&self.tenant_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "UPDATE agents SET status = 'revoked', revoked_at = {POSTGRES_NOW_MS}
                     WHERE agent_id = $1 AND tenant_id = $2 AND status = 'active'
                       AND {POSTGRES_NOW_MS} IS NOT NULL"
                );
                let result = sqlx::query(&sql)
                    .bind(agent_id)
                    .bind(&self.tenant_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    pub async fn consume_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_milliseconds: u64,
    ) -> Result<RateLimitResult, StoreError> {
        self.checkpoint_clock().await?;
        if key.is_empty() || limit == 0 {
            return Err(StoreError::InvalidInput("rate limit"));
        }
        let window_ms = i64::try_from(window_milliseconds)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(StoreError::InvalidInput("rate window"))?;
        let (count, expires_at) = match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO rate_windows (key, window_start, count, expires_at)
                     VALUES (?, {SQLITE_NOW_MS}, 1, {SQLITE_NOW_MS} + ?)
                     ON CONFLICT(key) DO UPDATE SET
                       window_start = CASE WHEN rate_windows.expires_at <= {SQLITE_NOW_MS} THEN {SQLITE_NOW_MS} ELSE rate_windows.window_start END,
                       count = CASE WHEN rate_windows.expires_at <= {SQLITE_NOW_MS} THEN 1 ELSE rate_windows.count + 1 END,
                       expires_at = CASE WHEN rate_windows.expires_at <= {SQLITE_NOW_MS} THEN {SQLITE_NOW_MS} + ? ELSE rate_windows.expires_at END
                     RETURNING count, expires_at"
                );
                let row = sqlx::query(&sql)
                    .bind(key)
                    .bind(window_ms)
                    .bind(window_ms)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?;
                (
                    row.try_get::<i64, _>(0).map_err(StoreError::Database)?,
                    row.try_get::<i64, _>(1).map_err(StoreError::Database)?,
                )
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO rate_windows (key, window_start, count, expires_at)
                     VALUES ($1, {POSTGRES_NOW_MS}, 1, {POSTGRES_NOW_MS} + $2::BIGINT)
                     ON CONFLICT(key) DO UPDATE SET
                       window_start = CASE WHEN rate_windows.expires_at <= {POSTGRES_NOW_MS} THEN {POSTGRES_NOW_MS} ELSE rate_windows.window_start END,
                       count = CASE WHEN rate_windows.expires_at <= {POSTGRES_NOW_MS} THEN 1 ELSE rate_windows.count + 1 END,
                       expires_at = CASE WHEN rate_windows.expires_at <= {POSTGRES_NOW_MS} THEN {POSTGRES_NOW_MS} + $2::BIGINT ELSE rate_windows.expires_at END
                     RETURNING count, expires_at"
                );
                let row = sqlx::query(&sql)
                    .bind(key)
                    .bind(window_ms)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?;
                (
                    row.try_get::<i64, _>(0).map_err(StoreError::Database)?,
                    row.try_get::<i64, _>(1).map_err(StoreError::Database)?,
                )
            }
        };
        let now_ms = database_now_ms(&self.database).await?;
        let retry_after_seconds = u64::try_from((expires_at - now_ms).max(0))
            .unwrap_or_default()
            .div_ceil(1_000)
            .max(1);
        Ok(RateLimitResult {
            count,
            retry_after_seconds,
        })
    }

    pub async fn create_secret_request(
        &self,
        requester_agent_id: &str,
        public_key: &str,
        description: &str,
        confirmation_code: &str,
        ttl_seconds: u64,
    ) -> Result<String, StoreError> {
        Ok(self
            .create_secret_request_with_expiry(
                requester_agent_id,
                public_key,
                description,
                confirmation_code,
                ttl_seconds,
            )
            .await?
            .id)
    }

    pub async fn create_secret_request_with_expiry(
        &self,
        requester_agent_id: &str,
        public_key: &str,
        description: &str,
        confirmation_code: &str,
        ttl_seconds: u64,
    ) -> Result<CreatedSecretRequest, StoreError> {
        self.checkpoint_clock().await?;
        if requester_agent_id.is_empty() || public_key.is_empty() || confirmation_code.is_empty() {
            return Err(StoreError::InvalidInput("secret request"));
        }
        let ttl_ms = positive_milliseconds(ttl_seconds, "request TTL")?;
        let id = new_hex_id();
        let expires_at_ms = match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "WITH clock AS (SELECT {SQLITE_NOW_MS} AS now_ms)
                     INSERT INTO secret_requests
                       (id, tenant_id, requester_agent_id, public_key, description, confirmation_code,
                        status, require_user_auth, created_at, expires_at, submitted_at, enc, ciphertext)
                     SELECT ?, ?, ?, ?, ?, ?, 'pending', 0, clock.now_ms, clock.now_ms + ?, NULL, NULL, NULL
                     FROM clock RETURNING expires_at"
                );
                sqlx::query(&sql)
                    .bind(&id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .bind(public_key)
                    .bind(description)
                    .bind(confirmation_code)
                    .bind(ttl_ms)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<i64, _>(0)
                    .map_err(StoreError::Database)?
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "WITH clock AS (SELECT {POSTGRES_NOW_MS} AS now_ms)
                     INSERT INTO secret_requests
                       (id, tenant_id, requester_agent_id, public_key, description, confirmation_code,
                        status, require_user_auth, created_at, expires_at, submitted_at, enc, ciphertext)
                     SELECT $1, $2, $3, $4, $5, $6, 'pending', FALSE, clock.now_ms,
                            clock.now_ms + $7::BIGINT, NULL, NULL, NULL
                     FROM clock RETURNING expires_at"
                );
                sqlx::query(&sql)
                    .bind(&id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .bind(public_key)
                    .bind(description)
                    .bind(confirmation_code)
                    .bind(ttl_ms)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .try_get::<i64, _>(0)
                    .map_err(StoreError::Database)?
            }
        };
        Ok(CreatedSecretRequest { id, expires_at_ms })
    }

    pub async fn secret_request_metadata(
        &self,
        request_id: &str,
    ) -> Result<Option<SecretRequestMetadata>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT requester_agent_id, public_key, description, confirmation_code, expires_at
                     FROM secret_requests WHERE id = ? AND tenant_id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(secret_metadata_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT requester_agent_id, public_key, description, confirmation_code, expires_at
                     FROM secret_requests WHERE id = $1 AND tenant_id = $2 AND expires_at > {POSTGRES_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(secret_metadata_from_postgres).transpose()
            }
        }
    }

    pub async fn browser_request_status(
        &self,
        request_id: &str,
    ) -> Result<Option<SecretRequestStatus>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT status FROM secret_requests
                     WHERE id = ? AND tenant_id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref()
                    .map(|row| row.try_get::<String, _>(0).map_err(StoreError::Database))
                    .transpose()?
                    .map(parse_request_status)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT status FROM secret_requests
                     WHERE id = $1 AND tenant_id = $2 AND expires_at > {POSTGRES_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref()
                    .map(|row| row.try_get::<String, _>(0).map_err(StoreError::Database))
                    .transpose()?
                    .map(parse_request_status)
                    .transpose()
            }
        }
    }

    pub async fn delete_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "DELETE FROM secret_requests WHERE id = ? AND tenant_id = ?
                     AND requester_agent_id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                let result = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "DELETE FROM secret_requests WHERE id = $1 AND tenant_id = $2
                     AND requester_agent_id = $3 AND expires_at > {POSTGRES_NOW_MS}"
                );
                let result = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    pub async fn submit_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
        enc: &str,
        ciphertext: &str,
        submitted_ttl_seconds: u64,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        if enc.is_empty() || ciphertext.is_empty() {
            return Err(StoreError::InvalidInput("encrypted payload"));
        }
        let ttl_ms = positive_milliseconds(submitted_ttl_seconds, "submitted TTL")?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE secret_requests
                     SET status = 'submitted', enc = ?, ciphertext = ?,
                         submitted_at = {SQLITE_NOW_MS},
                         expires_at = {SQLITE_NOW_MS} + ?
                     WHERE id = ? AND tenant_id = ? AND requester_agent_id = ?
                       AND status = 'pending' AND expires_at > {SQLITE_NOW_MS}
                     RETURNING id"
                );
                Ok(sqlx::query(&sql)
                    .bind(enc)
                    .bind(ciphertext)
                    .bind(ttl_ms)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .is_some())
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::SecretRequest,
                    request_id,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!(
                    "UPDATE secret_requests
                     SET status = 'submitted', enc = $1, ciphertext = $2,
                         submitted_at = {POSTGRES_NOW_MS},
                         expires_at = {POSTGRES_NOW_MS} + $3::BIGINT
                     WHERE id = $4 AND tenant_id = $5 AND requester_agent_id = $6
                       AND status = 'pending' AND expires_at > {POSTGRES_NOW_MS}
                     RETURNING id"
                );
                let submitted = sqlx::query(&sql)
                    .bind(enc)
                    .bind(ciphertext)
                    .bind(ttl_ms)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .is_some();
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(submitted)
            }
        }
    }

    pub async fn request_status(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<Option<SecretRequestStatus>, StoreError> {
        self.checkpoint_clock().await?;
        let status = match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT status FROM secret_requests
                     WHERE id = ? AND tenant_id = ? AND requester_agent_id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .map(|row| row.try_get::<String, _>(0))
                    .transpose()
                    .map_err(StoreError::Database)?
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT status FROM secret_requests
                     WHERE id = $1 AND tenant_id = $2 AND requester_agent_id = $3 AND expires_at > {POSTGRES_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .map(|row| row.try_get::<String, _>(0))
                    .transpose()
                    .map_err(StoreError::Database)?
            }
        };
        status.map(parse_request_status).transpose()
    }

    pub async fn consume_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<Option<EncryptedPayload>, StoreError> {
        self.checkpoint_clock().await?;
        let payload = match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let sql = format!(
                    "DELETE FROM secret_requests
                     WHERE id = ? AND tenant_id = ? AND requester_agent_id = ?
                       AND status = 'submitted' AND expires_at > {SQLITE_NOW_MS}
                     RETURNING enc, ciphertext"
                );
                let payload = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .map(|row| {
                        Ok(EncryptedPayload {
                            enc: row.try_get("enc")?,
                            ciphertext: row.try_get("ciphertext")?,
                        })
                    })
                    .transpose()
                    .map_err(StoreError::Database)?;
                if payload.is_some() {
                    crate::p02_test_failpoint("secret-retrieve-before-commit");
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                if payload.is_some() {
                    crate::p02_test_failpoint("secret-retrieve-after-commit");
                }
                payload
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::SecretRequest,
                    request_id,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!(
                    "DELETE FROM secret_requests
                     WHERE id = $1 AND tenant_id = $2 AND requester_agent_id = $3
                       AND status = 'submitted' AND expires_at > {POSTGRES_NOW_MS}
                     RETURNING enc, ciphertext"
                );
                let payload = sqlx::query(&sql)
                    .bind(request_id)
                    .bind(&self.tenant_id)
                    .bind(requester_agent_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .map(|row| {
                        Ok(EncryptedPayload {
                            enc: row.try_get("enc")?,
                            ciphertext: row.try_get("ciphertext")?,
                        })
                    })
                    .transpose()
                    .map_err(StoreError::Database)?;
                if payload.is_some() {
                    crate::p02_test_failpoint("secret-retrieve-before-commit");
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                if payload.is_some() {
                    crate::p02_test_failpoint("secret-retrieve-after-commit");
                }
                payload
            }
        };
        Ok(payload)
    }
}

async fn read_clock_anchor(database: &Database) -> Result<PersistedClockAnchor, StoreError> {
    match database {
        Database::Sqlite(pool) => {
            let row = sqlx::query(
                "SELECT last_observed_ms, boot_id, boottime_ms, host_wall_ms, fenced_at
                 FROM controller_clock WHERE id = 1",
            )
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?;
            Ok(PersistedClockAnchor {
                last_observed_ms: row
                    .try_get("last_observed_ms")
                    .map_err(StoreError::Database)?,
                boot_id: row.try_get("boot_id").map_err(StoreError::Database)?,
                boottime_ms: row.try_get("boottime_ms").map_err(StoreError::Database)?,
                host_wall_ms: row.try_get("host_wall_ms").map_err(StoreError::Database)?,
                fenced_at: row.try_get("fenced_at").map_err(StoreError::Database)?,
            })
        }
        Database::Postgres(pool) => {
            let row = sqlx::query(
                "SELECT last_observed_ms, boot_id, boottime_ms, host_wall_ms, fenced_at
                 FROM controller_clock WHERE id = 1",
            )
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?;
            Ok(PersistedClockAnchor {
                last_observed_ms: row
                    .try_get("last_observed_ms")
                    .map_err(StoreError::Database)?,
                boot_id: row.try_get("boot_id").map_err(StoreError::Database)?,
                boottime_ms: row.try_get("boottime_ms").map_err(StoreError::Database)?,
                host_wall_ms: row.try_get("host_wall_ms").map_err(StoreError::Database)?,
                fenced_at: row.try_get("fenced_at").map_err(StoreError::Database)?,
            })
        }
    }
}

async fn database_wall_now_ms(database: &Database) -> Result<i64, StoreError> {
    match database {
        Database::Sqlite(pool) => sqlx::query_scalar(&format!("SELECT {SQLITE_WALL_NOW_MS}"))
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database),
        Database::Postgres(pool) => sqlx::query_scalar(&format!("SELECT {POSTGRES_WALL_NOW_MS}"))
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database),
    }
}

async fn update_clock_anchor(
    database: &Database,
    sample: &ClockSample,
    database_now_ms: i64,
) -> Result<(), StoreError> {
    let affected = match database {
        Database::Sqlite(pool) => sqlx::query(
            "UPDATE controller_clock SET last_observed_ms = ?, boot_id = ?, boottime_ms = ?, host_wall_ms = ?
             WHERE id = 1 AND fenced_at IS NULL",
        )
        .bind(database_now_ms)
        .bind(&sample.boot_id)
        .bind(sample.boottime_ms)
        .bind(sample.host_wall_ms)
        .execute(pool)
        .await
        .map_err(StoreError::Database)?
        .rows_affected(),
        Database::Postgres(pool) => sqlx::query(
            "UPDATE controller_clock SET last_observed_ms = $1, boot_id = $2, boottime_ms = $3, host_wall_ms = $4
             WHERE id = 1 AND fenced_at IS NULL",
        )
        .bind(database_now_ms)
        .bind(&sample.boot_id)
        .bind(sample.boottime_ms)
        .bind(sample.host_wall_ms)
        .execute(pool)
        .await
        .map_err(StoreError::Database)?
        .rows_affected(),
    };
    if affected == 0 {
        return Err(StoreError::ClockFenced);
    }
    Ok(())
}

impl Database {
    async fn connect(url: &str) -> Result<Self, StoreError> {
        if url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(url)
                .map_err(|_| StoreError::InvalidInput("BLINDPASS_DATABASE_URL"))?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
            let pool = SqlitePoolOptions::new()
                .max_connections(8)
                .connect_with(options)
                .await
                .map_err(StoreError::Database)?;
            return Ok(Self::Sqlite(pool));
        }
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pool = PgPoolOptions::new()
                .max_connections(8)
                .connect(url)
                .await
                .map_err(StoreError::Database)?;
            return Ok(Self::Postgres(pool));
        }
        Err(StoreError::InvalidInput("BLINDPASS_DATABASE_URL"))
    }

    async fn validate_existing_schema_version(&self) -> Result<(), StoreError> {
        let version = match self {
            Self::Sqlite(pool) => {
                let exists: i64 = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'controller_meta')",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                if exists == 0 {
                    return Ok(());
                }
                sqlx::query_scalar::<_, i64>(
                    "SELECT schema_version FROM controller_meta WHERE id = 1",
                )
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
            }
            Self::Postgres(pool) => {
                let exists: bool =
                    sqlx::query_scalar("SELECT to_regclass('controller_meta') IS NOT NULL")
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?;
                if !exists {
                    return Ok(());
                }
                sqlx::query_scalar::<_, i32>(
                    "SELECT schema_version FROM controller_meta WHERE id = 1",
                )
                .fetch_optional(pool)
                .await
                .map(|version| version.map(i64::from))
                .map_err(StoreError::Database)?
            }
        };
        let Some(version) = version else {
            return Err(StoreError::UnsupportedSchemaVersion);
        };
        if !(1..=SCHEMA_VERSION).contains(&version) {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        for (introduced_in, tables) in SCHEMA_TABLES {
            if *introduced_in > version {
                continue;
            }
            for table in *tables {
                if !self.table_exists(table).await? {
                    return Err(StoreError::UnsupportedSchemaVersion);
                }
            }
        }
        if version >= 4 && !self.clock_anchor_columns_present().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        if version >= 6 && !self.enrollment_columns_present().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        if version >= 7 && !self.node_challenge_columns_present().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        if version >= 8 && !self.operation_decision_columns_present().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        if version >= 9 && !self.operation_binding_columns_present().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    async fn node_challenge_columns_present(&self) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("PRAGMA table_info(node_challenges)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                Ok([
                    "nonce_hash",
                    "key_version",
                    "issuer_epoch",
                    "capabilities_json",
                    "capabilities_hash",
                    "consumed_at",
                ]
                .iter()
                .all(|column| columns.contains(*column)))
            }
            Self::Postgres(pool) => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = 'node_challenges'
                       AND column_name IN ('nonce_hash', 'key_version', 'issuer_epoch',
                         'capabilities_json', 'capabilities_hash', 'consumed_at')",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(count == 6)
            }
        }
    }

    async fn operation_decision_columns_present(&self) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("PRAGMA table_info(operation_approvals)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(rows.iter().any(|row| {
                    row.try_get::<String, _>("name").ok().as_deref() == Some("decision_key_hash")
                }))
            }
            Self::Postgres(pool) => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = 'operation_approvals'
                       AND column_name = 'decision_key_hash'",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(count == 1)
            }
        }
    }

    async fn operation_binding_columns_present(&self) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("PRAGMA table_info(operations)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                Ok(["resource_id", "requested_ttl_seconds", "broker_event_key"]
                    .iter()
                    .all(|column| columns.contains(*column)))
            }
            Self::Postgres(pool) => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = 'operations'
                       AND column_name IN ('resource_id', 'requested_ttl_seconds', 'broker_event_key')",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(count == 3)
            }
        }
    }

    async fn enrollment_columns_present(&self) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("PRAGMA table_info(enrollment_requests)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                Ok(["requested_name", "protocol_version", "capabilities_json"]
                    .iter()
                    .all(|column| columns.contains(*column)))
            }
            Self::Postgres(pool) => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = 'enrollment_requests'
                       AND column_name IN ('requested_name', 'protocol_version', 'capabilities_json')",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(count == 3)
            }
        }
    }

    async fn clock_anchor_columns_present(&self) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("PRAGMA table_info(controller_clock)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                Ok(["boot_id", "boottime_ms", "host_wall_ms", "fenced_at"]
                    .iter()
                    .all(|column| columns.contains(*column)))
            }
            Self::Postgres(pool) => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = 'controller_clock'
                       AND column_name IN ('boot_id', 'boottime_ms', 'host_wall_ms', 'fenced_at')",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(count == 4)
            }
        }
    }

    async fn table_exists(&self, table: &str) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let present: i64 = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
                )
                .bind(table)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(present != 0)
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
                    .bind(table)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)
            }
        }
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::raw_sql(include_str!("migrations/sqlite/0001_init.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0002_admin_idempotency.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0003_controller_clock.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let rows = sqlx::query("PRAGMA table_info(controller_clock)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                for (column, definition) in [
                    ("boot_id", "TEXT"),
                    ("boottime_ms", "INTEGER"),
                    ("host_wall_ms", "INTEGER"),
                    ("fenced_at", "INTEGER"),
                ] {
                    if !columns.contains(column) {
                        sqlx::query(&format!(
                            "ALTER TABLE controller_clock ADD COLUMN {column} {definition}"
                        ))
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                    }
                }
                sqlx::raw_sql(include_str!("migrations/sqlite/0005_fleet.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let rows = sqlx::query("PRAGMA table_info(enrollment_requests)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                for (column, definition) in [
                    ("requested_name", "TEXT NOT NULL DEFAULT ''"),
                    ("protocol_version", "TEXT"),
                    ("capabilities_json", "TEXT"),
                ] {
                    if !columns.contains(column) {
                        sqlx::query(&format!(
                            "ALTER TABLE enrollment_requests ADD COLUMN {column} {definition}"
                        ))
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                    }
                }
                sqlx::raw_sql(include_str!("migrations/sqlite/0007_node_channel.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0008_fleet_authorization.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0009_operation_bindings.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(())
            }
            Self::Postgres(pool) => {
                sqlx::raw_sql(include_str!("migrations/postgres/0001_init.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0002_admin_idempotency.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0003_controller_clock.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/postgres/0004_clock_anchor.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/postgres/0005_fleet.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0006_enrollment_submission.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/postgres/0007_node_channel.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0008_fleet_authorization.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0009_operation_bindings.sql"
                ))
                .execute(pool)
                .await
                .map(|_| ())
                .map_err(StoreError::Database)
            }
        }
    }
}

fn agent_credential_from_sqlite(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<AgentCredential, StoreError> {
    Ok(AgentCredential {
        id: row
            .try_get::<String, _>("id")
            .map_err(StoreError::Database)?,
        agent_id: row
            .try_get::<String, _>("agent_id")
            .map_err(StoreError::Database)?,
        name: row
            .try_get::<String, _>("name")
            .map_err(StoreError::Database)?,
        api_key_hash: row
            .try_get::<String, _>("api_key_hash")
            .map_err(StoreError::Database)?,
        status: row
            .try_get::<String, _>("status")
            .map_err(StoreError::Database)?,
        key_version: row
            .try_get::<i64, _>("key_version")
            .map_err(StoreError::Database)?,
        created_at_ms: row
            .try_get::<i64, _>("created_at")
            .map_err(StoreError::Database)?,
        revoked_at_ms: row
            .try_get::<Option<i64>, _>("revoked_at")
            .map_err(StoreError::Database)?,
    })
}

fn agent_credential_from_postgres(
    row: &sqlx::postgres::PgRow,
) -> Result<AgentCredential, StoreError> {
    Ok(AgentCredential {
        id: row
            .try_get::<String, _>("id")
            .map_err(StoreError::Database)?,
        agent_id: row
            .try_get::<String, _>("agent_id")
            .map_err(StoreError::Database)?,
        name: row
            .try_get::<String, _>("name")
            .map_err(StoreError::Database)?,
        api_key_hash: row
            .try_get::<String, _>("api_key_hash")
            .map_err(StoreError::Database)?,
        status: row
            .try_get::<String, _>("status")
            .map_err(StoreError::Database)?,
        key_version: row
            .try_get::<i64, _>("key_version")
            .map_err(StoreError::Database)?,
        created_at_ms: row
            .try_get::<i64, _>("created_at")
            .map_err(StoreError::Database)?,
        revoked_at_ms: row
            .try_get::<Option<i64>, _>("revoked_at")
            .map_err(StoreError::Database)?,
    })
}

fn secret_metadata_from_sqlite(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SecretRequestMetadata, StoreError> {
    Ok(SecretRequestMetadata {
        requester_agent_id: row
            .try_get::<String, _>("requester_agent_id")
            .map_err(StoreError::Database)?,
        public_key: row
            .try_get::<String, _>("public_key")
            .map_err(StoreError::Database)?,
        description: row
            .try_get::<String, _>("description")
            .map_err(StoreError::Database)?,
        confirmation_code: row
            .try_get::<String, _>("confirmation_code")
            .map_err(StoreError::Database)?,
        expires_at_ms: row
            .try_get::<i64, _>("expires_at")
            .map_err(StoreError::Database)?,
    })
}

fn secret_metadata_from_postgres(
    row: &sqlx::postgres::PgRow,
) -> Result<SecretRequestMetadata, StoreError> {
    Ok(SecretRequestMetadata {
        requester_agent_id: row
            .try_get::<String, _>("requester_agent_id")
            .map_err(StoreError::Database)?,
        public_key: row
            .try_get::<String, _>("public_key")
            .map_err(StoreError::Database)?,
        description: row
            .try_get::<String, _>("description")
            .map_err(StoreError::Database)?,
        confirmation_code: row
            .try_get::<String, _>("confirmation_code")
            .map_err(StoreError::Database)?,
        expires_at_ms: row
            .try_get::<i64, _>("expires_at")
            .map_err(StoreError::Database)?,
    })
}

async fn database_now_ms(database: &Database) -> Result<i64, StoreError> {
    match database {
        Database::Sqlite(pool) => {
            let row = sqlx::query(&format!("SELECT {SQLITE_NOW_MS}"))
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
            row.try_get::<i64, _>(0).map_err(StoreError::Database)
        }
        Database::Postgres(pool) => {
            let row = sqlx::query(&format!("SELECT {POSTGRES_NOW_MS}"))
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
            row.try_get::<i64, _>(0).map_err(StoreError::Database)
        }
    }
}

/// Rows whose expiring PostgreSQL transitions lock them before the change.
#[derive(Clone, Copy)]
pub(super) enum LockedRow {
    SecretRequest,
    Exchange,
    Approval,
}

/// Lock one tenant row before a conditional PostgreSQL transition.
///
/// PostgreSQL evaluates an UPDATE or DELETE `WHERE` clause before it waits for
/// a row lock and re-checks it afterwards only when the blocking transaction
/// changed the row. A blocker that only locked the row, or rolled back, would
/// let the transition commit on a row whose deadline passed during the wait.
/// Locking first makes the transition's own statement sample the database
/// clock after any wait (P02-D9). A missing row is not an error: the
/// transition then matches nothing.
pub(super) async fn lock_postgres_row(
    connection: &mut sqlx::PgConnection,
    row: LockedRow,
    key: &str,
    tenant_id: &str,
) -> Result<(), StoreError> {
    let sql = match row {
        LockedRow::SecretRequest => {
            "SELECT 1 FROM secret_requests WHERE id = $1 AND tenant_id = $2 FOR UPDATE"
        }
        LockedRow::Exchange => {
            "SELECT 1 FROM exchanges WHERE id = $1 AND tenant_id = $2 FOR UPDATE"
        }
        LockedRow::Approval => {
            "SELECT 1 FROM approvals WHERE reference = $1 AND tenant_id = $2 FOR UPDATE"
        }
    };
    sqlx::query(sql)
        .bind(key)
        .bind(tenant_id)
        .fetch_optional(connection)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

fn positive_milliseconds(seconds: u64, field: &'static str) -> Result<i64, StoreError> {
    if seconds == 0 {
        return Err(StoreError::InvalidInput(field));
    }
    let milliseconds = seconds
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(StoreError::InvalidInput(field))?;
    Ok(milliseconds)
}

fn parse_request_status(status: String) -> Result<SecretRequestStatus, StoreError> {
    match status.as_str() {
        "pending" => Ok(SecretRequestStatus::Pending),
        "submitted" => Ok(SecretRequestStatus::Submitted),
        _ => Err(StoreError::MissingState("secret request status")),
    }
}

fn new_hex_id() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn new_uuid() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}

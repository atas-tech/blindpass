// SPDX-License-Identifier: AGPL-3.0-only

//! Durable, tenant-scoped controller state. Expiry is checked in the same
//! database statement as every read or state transition; the sweeper only
//! bounds retention and is never an authorization mechanism.

use blindpass_core::clock::{
    ClockAnchor, ClockSample, ClockSource, StartupClockCheck, SystemClock, check_running_clock,
    check_startup_clock,
};
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use rand::{RngCore, rngs::OsRng};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{PgPool, Row, SqlitePool, postgres::PgPoolOptions};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
use std::time::{Duration, Instant};

mod audit;
mod authorization;
pub(crate) mod backup;
mod exchanges;
mod fleet;
mod fleet_lifecycle;
mod grants;
mod login_limits;
use login_limits::account_row_keys;
pub use login_limits::{LoginBlock, OperatorLockState, login_account_key};
pub use operators::SESSION_IDLE_SECONDS;
mod node_channel;
mod operation_approvals;
mod operators;
mod ownership;
mod provisioning;
mod provisioning_links;
mod recovery;
pub use recovery::{
    RecoveryActivationStatus, RecoveryApplicationSummary, RecoveryInvalidationSummary,
    RecoveryNodeStatus, RecoveryReviewCompletion, RecoveryReviewItem, RecoveryStatus,
};
mod workload_authority;
mod workload_cancellation;
pub use audit::AuditDraft;
pub(crate) use authorization::BrokerOperationEvent;
pub use authorization::{
    FleetPolicyRecord, OperationApprovalDraft, OperationApprovalRecord, OperationCreateOutcome,
    OperationDecisionOutcome, OperationRecord, WorkloadRecord,
};
pub use exchanges::{
    ApprovalDecisionOutcome, ApprovalRecord, AuditRecord, ExchangePolicyRecord, ExchangeRecord,
    LifecycleRecord,
};
pub use fleet::{
    ENROLLMENT_EXPIRED, ENROLLMENT_KEY_REUSED, EnrollmentRecord, NodeGrantRevocationDraft,
    NodeKeyRotationDraft, NodeRecord,
};
pub use fleet_lifecycle::{FleetExpirySummary, FleetFencePurge, FleetPruneSummary};
pub use grants::{GrantIssueDraft, GrantIssueOutcome, GrantRecord, GrantRevocationOutcome};
pub use node_channel::{
    InboxDocument, NodeEventInsert, NodeEventRecord, NodeSessionContext, NodeSessionDraft,
};
pub use operation_approvals::{OperationCancelOutcome, OperationDecision};
pub use operators::{LocalOperator, LocalSession, SessionKind};
pub use provisioning::SourceBindingRecord;
pub use provisioning_links::{
    ProvisioningLinkOutcome, ProvisioningLinkRecord, ProvisioningMetadata,
    ProvisioningMetadataOutcome, ProvisioningPhase, ProvisioningReceipt, ProvisioningStatus,
    ProvisioningSubmitOutcome,
};
pub use workload_authority::WORKLOAD_UNIT_CONFLICT;

const SQLITE_WALL_NOW_MS: &str = "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)";
const POSTGRES_WALL_NOW_MS: &str = "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT";
const SQLITE_NOW_MS: &str = "(CASE WHEN CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) >= (SELECT last_observed_ms FROM controller_clock WHERE id = 1) THEN CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) ELSE NULL END)";
const POSTGRES_NOW_MS: &str = "(CASE WHEN FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT >= (SELECT last_observed_ms FROM controller_clock WHERE id = 1) THEN FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT ELSE NULL END)";
/// Current schema version. Versions 5-12 add fleet authorization, node
/// revocation reconciliation, channel state and staged key rotation; version
/// 13 adds approval scoping, revocation outcomes and fleet retention state;
/// 14 expires plaintext session identifiers before hashed-token issuance;
/// 15 adds independent source destinations and public recipient offers;
/// 16 adds scoped Source links and immutable ciphertext receipts;
/// 17 adds durable recovery fences and quarantined reconciliation queues.
/// 18 binds recovery to authenticated archive time and manifest digest.
/// 19 retains reverified protected report intents as quarantine metadata.
pub const SCHEMA_VERSION: i64 = 19;
/// Recovery transactions read one snapshot after taking the `controller_meta`
/// row lock; PostgreSQL's default READ COMMITTED would re-read per statement.
pub(crate) const PG_RECOVERY_ISOLATION: &str = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";
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
    (10, &["controller_meta"]),
    (11, &["node_revocation_queue"]),
    (12, &["node_key_rotations"]),
    (13, &["operation_approvals", "grants", "node_sessions"]),
    (15, &["fleet_source_bindings", "fleet_provisioning_offers"]),
    (
        16,
        &["fleet_provisioning_links", "fleet_provisioning_receipts"],
    ),
    (
        17,
        &[
            "controller_recoveries",
            "controller_recovery_nodes",
            "controller_recovery_operations",
            "controller_recovery_reviews",
        ],
    ),
    (18, &["controller_recovery_snapshots"]),
    (
        19,
        &["controller_recovery_reports", "controller_recovery_intents"],
    ),
];
/// Columns that versioned state tables must carry. `CREATE TABLE IF NOT EXISTS`
/// leaves an existing table untouched, so a pre-existing table of the wrong
/// shape is damage that fails closed rather than something a migration repairs.
const STATE_COLUMNS: &[(i64, &str, &[&str])] = &[
    (
        15,
        "fleet_source_bindings",
        &[
            "tenant_id",
            "node_id",
            "resource_id",
            "source_unit",
            "credential",
            "version",
            "updated_at",
            "updated_by",
        ],
    ),
    (
        15,
        "fleet_provisioning_offers",
        &[
            "id",
            "tenant_id",
            "node_id",
            "operation_id",
            "grant_id",
            "source_binding_version",
            "offer_json",
            "issued_at",
            "expires_at",
            "created_at",
        ],
    ),
    (
        16,
        "fleet_provisioning_links",
        &[
            "id",
            "tenant_id",
            "node_id",
            "operation_id",
            "grant_id",
            "offer_id",
            "operator_id",
            "idempotency_hash",
            "expires_at",
            "created_at",
        ],
    ),
    (
        16,
        "fleet_provisioning_receipts",
        &[
            "link_id",
            "tenant_id",
            "node_id",
            "grant_id",
            "offer_id",
            "operator_id",
            "ciphertext_digest",
            "delivery_digest",
            "submitted_at",
            "expires_at",
        ],
    ),
    (
        17,
        "controller_recoveries",
        &[
            "recovery_id",
            "tenant_id",
            "issuer_key_id",
            "owner_id",
            "snapshot_epoch",
            "target_epoch",
            "authority_revision",
            "phase",
            "prepared_at",
            "invalidated_at",
            "summary_json",
        ],
    ),
    (
        19,
        "controller_recovery_reports",
        &[
            "recovery_id",
            "node_id",
            "report_id",
            "records_digest",
            "trust_revision",
            "node_key_version",
            "matched",
            "unknown_records",
            "conflicting",
            "unmapped",
            "state",
        ],
    ),
    (
        19,
        "controller_recovery_intents",
        &[
            "recovery_id",
            "node_id",
            "grant_id",
            "operation_id",
            "issuer_epoch",
            "expires_at_ms",
            "mapping",
        ],
    ),
    (
        18,
        "controller_recovery_snapshots",
        &[
            "recovery_id",
            "snapshot_epoch",
            "snapshot_time_ms",
            "backup_digest",
            "signature",
        ],
    ),
    (
        17,
        "controller_recovery_nodes",
        &[
            "recovery_id",
            "node_id",
            "snapshot_status",
            "snapshot_key_version",
            "state",
        ],
    ),
    (
        17,
        "controller_recovery_operations",
        &[
            "recovery_id",
            "operation_id",
            "snapshot_status",
            "snapshot_result_json",
            "snapshot_completed_at",
            "state",
        ],
    ),
    (
        17,
        "controller_recovery_reviews",
        &[
            "recovery_id",
            "category",
            "subject_id",
            "related_id",
            "snapshot_version",
            "snapshot_status",
            "state",
        ],
    ),
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
    AuthorityFenced,
    RecoveryRequired,
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
            Self::AuthorityFenced => formatter.write_str("controller ownership is fenced"),
            Self::RecoveryRequired => formatter.write_str("controller recovery is required"),
        }
    }
}

impl std::error::Error for StoreError {}

fn acknowledge_database_work<T>(
    operation: &mut crate::recovery_authority::OwnershipDatabaseWork,
    result: &Result<T, StoreError>,
) {
    // Semantic validation failures are completed local decisions. A database
    // error or lost authority/recovery boundary can leave its server outcome
    // unknown; cancellation never reaches this acknowledgement at all.
    if !matches!(
        result,
        Err(StoreError::Database(_) | StoreError::AuthorityFenced | StoreError::RecoveryRequired)
    ) {
        operation.acknowledge();
    }
}

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
    fleet_signer: Option<FleetSigner>,
    ownership: OwnershipBinding,
    recovery_required: Arc<AtomicBool>,
    snapshot_only: bool,
    /// Absolute operator-session lifetime from sign-in (N-05); rotation can
    /// never extend a family past it.
    session_absolute_ms: i64,
}

/// Default absolute operator-session lifetime, seven days.
const DEFAULT_SESSION_ABSOLUTE_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

type OwnershipBinding = Arc<Mutex<Option<Arc<crate::recovery_authority::ProcessOwnership>>>>;

/// Signs the controller documents that store transitions emit to node inboxes,
/// so a document commits atomically with the state change it announces.
#[derive(Clone)]
pub struct FleetSigner {
    keypair: Arc<Ed25519KeyPair>,
    key_id: String,
    ownership: OwnershipBinding,
    recovery_required: Arc<AtomicBool>,
}

impl FleetSigner {
    #[must_use]
    pub fn new(keypair: Arc<Ed25519KeyPair>) -> Self {
        let key_id = format!("ed25519-{}", base64_url_encode(keypair.public_key()));
        Self {
            keypair,
            key_id,
            ownership: Arc::new(Mutex::new(None)),
            recovery_required: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) fn sign(
        &self,
        kind: DocumentKind,
        body: blindpass_core::canon::Value,
        epoch: u64,
    ) -> Result<String, StoreError> {
        if self
            .recovery_required
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(StoreError::RecoveryRequired);
        }
        let owner = self
            .ownership
            .lock()
            .map_err(|_| StoreError::AuthorityFenced)?
            .clone();
        let _operation = match owner.as_ref() {
            Some(owner) => {
                if !owner.matches_epoch(epoch) || !owner.matches_issuer(&self.key_id) {
                    return Err(StoreError::AuthorityFenced);
                }
                Some(
                    owner
                        .begin_operation()
                        .map_err(|_| StoreError::AuthorityFenced)?,
                )
            }
            None => None,
        };
        let envelope = SignedEnvelope::sign(kind, body, &self.key_id, epoch, &self.keypair)
            .map_err(|_| StoreError::InvalidInput("signed node document"))?;
        let bytes = envelope
            .to_json()
            .map_err(|_| StoreError::InvalidInput("signed node document"))?;
        if self
            .recovery_required
            .load(std::sync::atomic::Ordering::Acquire)
            || owner.as_ref().is_some_and(|owner| owner.is_fenced())
        {
            return Err(StoreError::AuthorityFenced);
        }
        String::from_utf8(bytes).map_err(|_| StoreError::InvalidInput("signed node document"))
    }
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
    /// Fleet authority withdrawn because its deadlines came from the
    /// regressed clock.
    pub fleet: FleetFencePurge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitResult {
    pub count: i64,
    pub retry_after_seconds: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExistingPurpose {
    Ordinary,
    Snapshot,
    Recovery,
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
                    Ok(())
                    | Err(
                        StoreError::ClockFenced
                        | StoreError::AuthorityFenced
                        | StoreError::RecoveryRequired,
                    ) => {}
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

    /// Production serving opens initialized state only. Schema creation and
    /// upgrades belong to the explicit migration command; lost metadata is
    /// never filled in with a new tenant, issuer epoch or clock anchor.
    pub async fn connect_existing(url: &str, tolerance_ms: u64) -> Result<Self, StoreError> {
        Self::connect_existing_inner(url, tolerance_ms, None, ExistingPurpose::Ordinary).await
    }

    /// Nonissuing offline capture never updates the source clock. Ordinary
    /// Store operations remain disabled on this private immutable snapshot mode.
    pub(crate) async fn connect_existing_for_snapshot(
        url: &str,
        tolerance_ms: u64,
    ) -> Result<Self, StoreError> {
        Self::connect_existing_inner(url, tolerance_ms, None, ExistingPurpose::Snapshot).await
    }

    async fn connect_existing_inner(
        url: &str,
        tolerance_ms: u64,
        ownership: Option<(Arc<crate::recovery_authority::ProcessOwnership>, &str)>,
        purpose: ExistingPurpose,
    ) -> Result<Self, StoreError> {
        let clock_tolerance_ms = i64::try_from(tolerance_ms)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(StoreError::InvalidInput("clock tolerance"))?;
        let database = Database::connect_existing(url).await?;
        if !database.table_exists("controller_meta").await? {
            return Err(StoreError::MissingState("controller metadata"));
        }
        let metadata = match &database {
            Database::Sqlite(pool) => sqlx::query_as::<_, (i64, String, i64)>(
                "SELECT schema_version, tenant_id, issuer_epoch FROM controller_meta WHERE id = 1 AND typeof(schema_version)='integer' AND typeof(tenant_id)='text' AND typeof(issuer_epoch)='integer'",
            )
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?,
            Database::Postgres(pool) => sqlx::query_as::<_, (i32, String, i64)>(
                "SELECT schema_version, tenant_id, issuer_epoch FROM controller_meta WHERE id = 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?
            .map(|(version, tenant, epoch)| (i64::from(version), tenant, epoch)),
        };
        let Some((version, tenant_id, epoch)) = metadata else {
            return Err(StoreError::MissingState("controller metadata"));
        };
        // Only a read-only snapshot may open a supported older schema, so the
        // pre-upgrade backup can capture it; nothing else serves old state.
        if version != SCHEMA_VERSION
            && !(purpose == ExistingPurpose::Snapshot
                && crate::backup::supported_snapshot_schema(version))
        {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        if tenant_id.is_empty()
            || !u64::try_from(epoch).is_ok_and(crate::legacy_authority::safe_epoch)
        {
            return Err(StoreError::MissingState("controller metadata"));
        }
        if let Some((owner, key_id)) = ownership.as_ref()
            && (!owner.matches_controller(&tenant_id, key_id)
                || match purpose {
                    ExistingPurpose::Recovery => {
                        !owner.is_recovering() || owner.recovery_context().1.epoch <= epoch as u64
                    }
                    _ => !owner.matches_epoch(epoch as u64),
                })
        {
            return Err(StoreError::AuthorityFenced);
        }
        database.validate_existing_schema_version().await?;
        // Read before initialize_clock, which updates only an existing anchor.
        // RowNotFound represents lost state, not an instruction to create it.
        read_clock_anchor(&database)
            .await
            .map_err(|error| match error {
                StoreError::Database(sqlx::Error::RowNotFound) => {
                    StoreError::MissingState("controller clock")
                }
                error => error,
            })?;
        let clock_source = Arc::new(SystemClock);
        let sample = clock_source
            .sample()
            .map_err(|_| StoreError::ClockSourceUnavailable)?;
        let store = Self {
            database,
            tenant_id,
            clock_source,
            clock_tolerance_ms,
            clock_monitor: Arc::new(Mutex::new(None)),
            fleet_signer: None,
            ownership: Arc::new(Mutex::new(
                ownership.as_ref().map(|(owner, _)| owner.clone()),
            )),
            recovery_required: Arc::new(AtomicBool::new(false)),
            snapshot_only: purpose == ExistingPurpose::Snapshot,
            session_absolute_ms: DEFAULT_SESSION_ABSOLUTE_MS,
        };
        // Recovery tables first exist in schema 17.
        if version >= 17 {
            store
                .load_recovery_fence(ownership.as_ref().map(|(owner, _)| owner))
                .await?;
        }
        // Nonactive owners and durable recovery intents open diagnostics only.
        // Their clocks cannot be reconciled implicitly through startup.
        if purpose == ExistingPurpose::Ordinary
            && ownership
                .as_ref()
                .is_none_or(|(owner, _)| owner.is_active())
            && !store.recovery_required()
        {
            let database_ms = database_wall_now_ms(&store.database).await?;
            store.initialize_clock(sample, database_ms).await?;
        }
        Ok(store)
    }

    pub async fn connect_with_clock_source(
        url: &str,
        clock_source: Arc<dyn ClockSource>,
        tolerance_ms: u64,
    ) -> Result<Self, StoreError> {
        Self::connect_with_clock_source_for_tenant(url, clock_source, tolerance_ms, None).await
    }

    async fn connect_with_clock_source_for_tenant(
        url: &str,
        clock_source: Arc<dyn ClockSource>,
        tolerance_ms: u64,
        tenant: Option<&str>,
    ) -> Result<Self, StoreError> {
        let clock_tolerance_ms = i64::try_from(tolerance_ms)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(StoreError::InvalidInput("clock tolerance"))?;
        let database = Database::connect(url).await?;
        database.validate_existing_schema_version().await?;
        database.migrate().await?;
        // A table that already existed with the wrong columns survives the
        // idempotent migration; the version marker is never advanced over it.
        if !database.state_columns_present(SCHEMA_VERSION).await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }

        let candidate_tenant_id = tenant.map(str::to_owned).unwrap_or_else(new_uuid);
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
            fleet_signer: None,
            ownership: Arc::new(Mutex::new(None)),
            recovery_required: Arc::new(AtomicBool::new(false)),
            snapshot_only: false,
            session_absolute_ms: DEFAULT_SESSION_ABSOLUTE_MS,
        };
        store.load_recovery_fence(None).await?;
        let database_ms = database_wall_now_ms(&store.database).await?;
        store.initialize_clock(sample, database_ms).await?;
        Ok(store)
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Set the absolute operator-session lifetime. Sign-in and every refresh
    /// rotation are capped so no session outlives its first sign-in by more
    /// than this.
    #[must_use]
    pub fn with_session_absolute_seconds(mut self, seconds: u64) -> Self {
        self.session_absolute_ms = i64::try_from(seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .unwrap_or(DEFAULT_SESSION_ABSOLUTE_MS);
        self
    }

    /// Attach the issuer signer used for documents emitted by fleet
    /// transitions such as operation closures and grant revocations.
    #[must_use]
    pub fn with_fleet_signer(mut self, mut signer: FleetSigner) -> Self {
        signer.ownership = self.ownership.clone();
        signer.recovery_required = self.recovery_required.clone();
        self.fleet_signer = Some(signer);
        self
    }

    /// One binding is shared by every existing Store and attached signer clone.
    /// Rebinding cannot reset a lost holder; recovery requires a fresh Store.
    pub fn bind_ownership(
        &self,
        owner: Arc<crate::recovery_authority::ProcessOwnership>,
        issuer_key_id: &str,
    ) -> Result<(), StoreError> {
        let mut binding = self
            .ownership
            .lock()
            .map_err(|_| StoreError::AuthorityFenced)?;
        if let Some(current) = binding.as_ref()
            && !Arc::ptr_eq(current, &owner)
        {
            current.fence();
            owner.fence();
            return Err(StoreError::AuthorityFenced);
        }
        let matches = owner.matches_controller(&self.tenant_id, issuer_key_id);
        if !matches {
            owner.fence();
        }
        *binding = Some(owner);
        if matches {
            Ok(())
        } else {
            Err(StoreError::AuthorityFenced)
        }
    }

    pub(crate) fn ownership_holder(
        &self,
    ) -> Result<Option<Arc<crate::recovery_authority::ProcessOwnership>>, StoreError> {
        if self.snapshot_only {
            return Err(StoreError::AuthorityFenced);
        }
        self.ownership
            .lock()
            .map(|binding| binding.clone())
            .map_err(|_| StoreError::AuthorityFenced)
    }

    /// Direct node replies and transactional inbox documents use the same
    /// signer and ownership latch. Bodies here contain protocol metadata.
    pub async fn sign_node_document(
        &self,
        kind: DocumentKind,
        body: blindpass_core::canon::Value,
        epoch: u64,
    ) -> Result<String, StoreError> {
        // Reject a known local input mismatch before admitting a database
        // boundary. No SQL command or signing work has started at this point.
        if self
            .ownership_holder()?
            .is_some_and(|owner| !owner.matches_epoch(epoch))
        {
            return Err(StoreError::AuthorityFenced);
        }
        self.run_owned(async {
            self.fleet_signer
                .as_ref()
                .ok_or(StoreError::MissingState("issuer signer"))?
                .sign(kind, body, epoch)
        })
        .await
    }

    async fn run_owned<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        if self.snapshot_only {
            return Err(StoreError::AuthorityFenced);
        }
        if self.recovery_required() {
            return Err(StoreError::RecoveryRequired);
        }
        let owner = self
            .ownership
            .lock()
            .map_err(|_| StoreError::AuthorityFenced)?
            .clone();
        let Some(owner) = owner else {
            return future.await;
        };
        if !owner.is_active() || owner.check().await.is_err() {
            return Err(StoreError::AuthorityFenced);
        }
        let epoch = tokio::time::timeout(Duration::from_secs(3), self.issuer_epoch()).await;
        if !matches!(epoch, Ok(Ok(epoch)) if owner.matches_epoch(epoch)) {
            owner.fence();
            return Err(StoreError::AuthorityFenced);
        }
        let mut operation = owner
            .begin_operation()
            .map_err(|_| StoreError::AuthorityFenced)?
            .database_work();
        tokio::select! {
            biased;
            _ = owner.wait_fenced() => Err(StoreError::AuthorityFenced),
            result = future => {
                acknowledge_database_work(&mut operation, &result);
                if owner.is_fenced() { Err(StoreError::AuthorityFenced) } else { result }
            }
        }
    }

    pub async fn database_now_ms(&self) -> Result<i64, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            database_wall_now_ms(&self.database).await
        })
        .await
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

    /// Legacy signing/verification must use current guarded state, never a
    /// startup-cached epoch or a raw-key fallback after recovery.
    pub(crate) async fn legacy_authority_epoch(&self) -> Result<u64, StoreError> {
        let result = tokio::time::timeout(Duration::from_secs(3), self.run_owned(async {
            let (schema, tenant, epoch): (i64, String, i64) = match &self.database {
                // SQLite casts can normalize damaged text/real metadata. Read
                // only values whose persisted types match the authority context.
                Database::Sqlite(pool) => sqlx::query_as("SELECT schema_version,tenant_id,issuer_epoch FROM controller_meta WHERE id=1 AND typeof(schema_version)='integer' AND typeof(tenant_id)='text' AND typeof(issuer_epoch)='integer'").fetch_one(pool).await.map_err(StoreError::Database)?,
                // PostgreSQL enforces column types; widen INT4 for the i64 decoder.
                Database::Postgres(pool) => sqlx::query_as("SELECT CAST(schema_version AS BIGINT),tenant_id,issuer_epoch FROM controller_meta WHERE id=1").fetch_one(pool).await.map_err(StoreError::Database)?,
            };
            if schema != SCHEMA_VERSION {
                return Err(StoreError::UnsupportedSchemaVersion);
            }
            let epoch = u64::try_from(epoch).map_err(|_| StoreError::MissingState("issuer epoch"))?;
            if tenant != self.tenant_id || !crate::legacy_authority::safe_epoch(epoch) {
                return Err(StoreError::MissingState("legacy authority context"));
            }
            self.checkpoint_clock().await?;
            Ok(epoch)
        })).await.unwrap_or(Err(StoreError::AuthorityFenced));
        if result.is_err()
            && let Some(owner) = self
                .ownership
                .lock()
                .map_err(|_| StoreError::AuthorityFenced)?
                .as_ref()
        {
            owner.fence();
        }
        result
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
                let fleet =
                    fleet_lifecycle::fleet_fence_purge_sqlite(&mut transaction, database_now_ms)
                        .await?;
                let counts = serde_json::json!({
                    "removed_secret_requests":removed_secret_requests,
                    "removed_exchanges":removed_exchanges,
                    "removed_pending_approvals":removed_approvals,
                    "removed_bootstrap_tokens":removed_bootstrap_tokens,
                    "removed_rate_windows":removed_rate_windows,
                    "removed_idempotency_keys":removed_idempotency_keys,
                    "fleet":fleet
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
                let fleet =
                    fleet_lifecycle::fleet_fence_purge_postgres(&mut transaction, database_now_ms)
                        .await?;
                let counts = serde_json::json!({
                    "removed_secret_requests":removed_secret_requests,
                    "removed_exchanges":removed_exchanges,
                    "removed_pending_approvals":removed_approvals,
                    "removed_bootstrap_tokens":removed_bootstrap_tokens,
                    "removed_rate_windows":removed_rate_windows,
                    "removed_idempotency_keys":removed_idempotency_keys,
                    "fleet":fleet
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
        self.run_owned(async {
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
        })
        .await
    }

    /// True when the durable controller clock fence is set. An unreadable
    /// anchor also counts as fenced, so callers report an outage.
    pub async fn clock_is_fenced(&self) -> bool {
        read_clock_anchor(&self.database)
            .await
            .map_or(true, |anchor| anchor.fenced_at.is_some())
    }

    pub async fn is_ready(&self) -> bool {
        self.readiness().await.is_ok()
    }

    /// Bounded public diagnostics are derived from actual database/clock
    /// checks. Never include a driver error, URL, path or query in a response.
    pub async fn readiness(&self) -> Result<(), StoreError> {
        self.run_owned(self.database_readiness()).await
    }

    pub(crate) async fn database_readiness(&self) -> Result<(), StoreError> {
        self.check_clock().await?;
        let version = match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
                "SELECT schema_version FROM controller_meta WHERE id = 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?,
            Database::Postgres(pool) => sqlx::query_scalar::<_, i32>(
                "SELECT schema_version FROM controller_meta WHERE id = 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Database)?
            .map(i64::from),
        };
        if version != Some(SCHEMA_VERSION) {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    /// Refuse every store operation while the durable clock fence is set.
    /// A separate one-second monitor compares host and database clocks while
    /// `serve` is running; this checkpoint also verifies the running clock on
    /// store calls used by shell commands and test fixtures.
    async fn checkpoint_clock(&self) -> Result<(), StoreError> {
        if self.recovery_required() {
            return Err(StoreError::RecoveryRequired);
        }
        self.check_clock().await
    }

    async fn check_clock(&self) -> Result<(), StoreError> {
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
                    "SELECT last_observed_ms, fenced_at, {SQLITE_WALL_NOW_MS}, boot_id FROM controller_clock WHERE id = 1"
                );
                let row = sqlx::query(&sql)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let persisted_ms: i64 = row.try_get(0).map_err(StoreError::Database)?;
                let fenced_at: Option<i64> = row.try_get(1).map_err(StoreError::Database)?;
                let database_now_ms: i64 = row.try_get(2).map_err(StoreError::Database)?;
                let anchor_boot: Option<String> = row.try_get(3).map_err(StoreError::Database)?;
                // A stale boot anchor is the regression the next start would
                // fence on; reconcile it here even when nothing opened the
                // database since the reboot (an authority-refused start never does).
                let boot_changed = anchor_boot.as_deref() != sample.boot_id.as_deref();
                let mut summary = ClockReconciliation {
                    regression_detected: database_now_ms < persisted_ms
                        || fenced_at.is_some()
                        || boot_changed,
                    persisted_ms,
                    database_now_ms,
                    removed_secret_requests: 0,
                    removed_exchanges: 0,
                    removed_approvals: 0,
                    removed_bootstrap_tokens: 0,
                    removed_rate_windows: 0,
                    removed_idempotency_keys: 0,
                    revoked_sessions: 0,
                    fleet: FleetFencePurge::default(),
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
                summary.fleet =
                    fleet_lifecycle::fleet_fence_purge_sqlite(&mut transaction, database_now_ms)
                        .await?;
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
                    "SELECT last_observed_ms, fenced_at, boot_id FROM controller_clock WHERE id = 1 FOR UPDATE",
                )
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                let persisted_ms: i64 = row.try_get(0).map_err(StoreError::Database)?;
                let fenced_at: Option<i64> = row.try_get(1).map_err(StoreError::Database)?;
                let anchor_boot: Option<String> = row.try_get(2).map_err(StoreError::Database)?;
                let boot_changed = anchor_boot.as_deref() != sample.boot_id.as_deref();
                let sql = format!("SELECT {POSTGRES_WALL_NOW_MS}");
                let database_now_ms: i64 = sqlx::query_scalar(&sql)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let mut summary = ClockReconciliation {
                    regression_detected: database_now_ms < persisted_ms
                        || fenced_at.is_some()
                        || boot_changed,
                    persisted_ms,
                    database_now_ms,
                    removed_secret_requests: 0,
                    removed_exchanges: 0,
                    removed_approvals: 0,
                    removed_bootstrap_tokens: 0,
                    removed_rate_windows: 0,
                    removed_idempotency_keys: 0,
                    revoked_sessions: 0,
                    fleet: FleetFencePurge::default(),
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
                summary.fleet =
                    fleet_lifecycle::fleet_fence_purge_postgres(&mut transaction, database_now_ms)
                        .await?;
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
        self.run_owned(async {
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
        })
        .await
    }

    /// Replace the persisted policy only when its expected version still matches.
    /// An absent row represents version 1 seeded from local configuration.
    pub async fn replace_policy_document(
        &self,
        expected_version: i64,
        document_json: &str,
        updated_by: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    /// Delete expired durable ciphertext after the configured retention grace.
    /// Every public read and transition checks its own expiry, so this worker
    /// controls retention rather than authority.
    pub async fn sweep_expired(&self, retention_grace_seconds: u64) -> Result<u64, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    /// Apply the audit log's day-based retention separately from ciphertext
    /// expiry. A short ciphertext grace must never prune fresh audit history.
    pub async fn sweep_audit(&self, retention_days: u32) -> Result<u64, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn create_agent(
        &self,
        agent_id: &str,
        name: &str,
        ring: Option<&str>,
        api_key_hash: &str,
    ) -> Result<AgentCredential, StoreError> {
        self.run_owned(async {
            self.create_agent_with_id(&new_uuid(), agent_id, name, ring, api_key_hash)
                .await
        })
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
        self.run_owned(async {
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
        }).await
    }

    pub async fn agent_by_key_id(&self, id: &str) -> Result<Option<AgentCredential>, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn agent_by_agent_id(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentCredential>, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn list_admin_agents(&self) -> Result<Vec<AdminAgentRecord>, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    pub async fn replace_agent_api_key_hash(
        &self,
        agent_id: &str,
        expected_key_version: i64,
        api_key_hash: &str,
    ) -> Result<Option<AgentCredential>, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn revoke_agent(&self, agent_id: &str) -> Result<bool, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    pub async fn consume_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_milliseconds: u64,
    ) -> Result<RateLimitResult, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn create_secret_request(
        &self,
        requester_agent_id: &str,
        public_key: &str,
        description: &str,
        confirmation_code: &str,
        ttl_seconds: u64,
    ) -> Result<String, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    pub async fn create_secret_request_with_expiry(
        &self,
        requester_agent_id: &str,
        public_key: &str,
        description: &str,
        confirmation_code: &str,
        ttl_seconds: u64,
    ) -> Result<CreatedSecretRequest, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn secret_request_metadata(
        &self,
        request_id: &str,
    ) -> Result<Option<SecretRequestMetadata>, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn browser_request_status(
        &self,
        request_id: &str,
    ) -> Result<Option<SecretRequestStatus>, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    pub async fn delete_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<bool, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    pub async fn submit_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
        enc: &str,
        ciphertext: &str,
        submitted_ttl_seconds: u64,
    ) -> Result<bool, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    pub async fn request_status(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<Option<SecretRequestStatus>, StoreError> {
        self.run_owned(async {
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
        }).await
    }

    pub async fn consume_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<Option<EncryptedPayload>, StoreError> {
        self.run_owned(async {
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
        })
        .await
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
        Self::connect_mode(url, true).await
    }

    async fn connect_existing(url: &str) -> Result<Self, StoreError> {
        Self::connect_mode(url, false).await
    }

    async fn connect_mode(url: &str, create: bool) -> Result<Self, StoreError> {
        if url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(url)
                .map_err(|_| StoreError::InvalidInput("BLINDPASS_DATABASE_URL"))?
                .create_if_missing(create)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
            if !create {
                let path = options.get_filename();
                let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        StoreError::MissingState("controller database")
                    } else {
                        StoreError::InvalidInput("controller database permissions")
                    }
                })?;
                use std::os::unix::fs::MetadataExt;
                if !metadata.is_file() || metadata.nlink() != 1 {
                    return Err(StoreError::InvalidInput("controller database permissions"));
                }
                // SQLx opens by pathname, so reject linked ancestors as well.
                // The service account must retain exclusive custody of the
                // configured data directory while serving.
                let absolute = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map_err(|_| StoreError::InvalidInput("controller database permissions"))?
                        .join(path)
                };
                blindpass_core::deployment::Directory::open(
                    absolute
                        .parent()
                        .ok_or(StoreError::InvalidInput("controller database permissions"))?,
                )
                .map_err(|_| StoreError::InvalidInput("controller database permissions"))?;
            }
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
        if version >= 10 && !self.issuer_epoch_column_is_wide_enough().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        if version >= 13 && !self.review_columns_present().await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        // Whatever the marker says, an existing state table of the wrong
        // shape is damage: the idempotent migration would never repair it.
        if !self.state_columns_present(SCHEMA_VERSION).await? {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    /// Whether every state table introduced at or before `version`
    /// carries all of its expected columns. A table that does not exist is
    /// skipped here: presence is `SCHEMA_TABLES`' concern, and migration
    /// creates tables a database predates.
    async fn state_columns_present(&self, version: i64) -> Result<bool, StoreError> {
        for (introduced_in, table, columns) in STATE_COLUMNS {
            if *introduced_in > version || !self.table_exists(table).await? {
                continue;
            }
            match self {
                Self::Sqlite(pool) => {
                    let present = sqlite_columns(pool, table).await?;
                    if columns.iter().any(|column| !present.contains(*column)) {
                        return Ok(false);
                    }
                }
                Self::Postgres(pool) => {
                    for column in *columns {
                        let count: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM information_schema.columns
                             WHERE table_schema = current_schema() AND table_name = $1
                               AND column_name = $2",
                        )
                        .bind(table)
                        .bind(column)
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?;
                        if count != 1 {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    async fn review_columns_present(&self) -> Result<bool, StoreError> {
        for (table, columns) in REVIEW_COLUMNS {
            match self {
                Self::Sqlite(pool) => {
                    let present = sqlite_columns(pool, table).await?;
                    if columns.iter().any(|(column, _)| !present.contains(*column)) {
                        return Ok(false);
                    }
                }
                Self::Postgres(pool) => {
                    for (column, _) in *columns {
                        let count: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM information_schema.columns
                             WHERE table_schema = current_schema() AND table_name = $1
                               AND column_name = $2",
                        )
                        .bind(table)
                        .bind(column)
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?;
                        if count != 1 {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    async fn issuer_epoch_column_is_wide_enough(&self) -> Result<bool, StoreError> {
        match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("PRAGMA table_info(controller_meta)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(rows.iter().any(|row| {
                    row.try_get::<String, _>("name").ok().as_deref() == Some("issuer_epoch")
                        && row
                            .try_get::<String, _>("type")
                            .is_ok_and(|kind| kind.eq_ignore_ascii_case("INTEGER"))
                }))
            }
            Self::Postgres(pool) => {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = 'controller_meta'
                       AND column_name = 'issuer_epoch' AND data_type = 'bigint'",
                )
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
                Ok(count == 1)
            }
        }
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
                let rows = sqlx::query("PRAGMA table_info(operation_approvals)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                if !columns.contains("decision_key_hash") {
                    sqlx::query(
                        "ALTER TABLE operation_approvals ADD COLUMN decision_key_hash TEXT",
                    )
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                }
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0008_fleet_authorization.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                let rows = sqlx::query("PRAGMA table_info(operations)")
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let columns = rows
                    .iter()
                    .filter_map(|row| row.try_get::<String, _>("name").ok())
                    .collect::<std::collections::BTreeSet<_>>();
                for (column, definition) in [
                    ("resource_id", "TEXT NOT NULL DEFAULT ''"),
                    ("requested_ttl_seconds", "BIGINT NOT NULL DEFAULT 1"),
                    ("broker_event_key", "TEXT"),
                ] {
                    if !columns.contains(column) {
                        sqlx::query(&format!(
                            "ALTER TABLE operations ADD COLUMN {column} {definition}"
                        ))
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                    }
                }
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0009_operation_bindings.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0011_node_revocation_queue.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0012_node_key_rotation.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                for (table, columns) in REVIEW_COLUMNS {
                    let present = sqlite_columns(pool, table).await?;
                    for (column, definition) in *columns {
                        if !present.contains(*column) {
                            sqlx::query(&format!(
                                "ALTER TABLE {table} ADD COLUMN {column} {definition}"
                            ))
                            .execute(pool)
                            .await
                            .map_err(StoreError::Database)?;
                        }
                    }
                }
                rebuild_sqlite_nodes_without_name_constraint(pool).await?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0013_fleet_review.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0014_session_tokens.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0015_provisioning_offers.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0016_provisioning_links.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0017_recovery.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/sqlite/0018_recovery_snapshot.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/sqlite/0019_recovery_application.sql"
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
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0010_issuer_epoch_bigint.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0011_node_revocation_queue.sql"
                ))
                .execute(pool)
                .await
                .map(|_| ())
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0012_node_key_rotation.sql"
                ))
                .execute(pool)
                .await
                .map(|_| ())
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/postgres/0013_fleet_review.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/postgres/0014_session_tokens.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0015_provisioning_offers.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0016_provisioning_links.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!("migrations/postgres/0017_recovery.sql"))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0018_recovery_snapshot.sql"
                ))
                .execute(pool)
                .await
                .map_err(StoreError::Database)?;
                sqlx::raw_sql(include_str!(
                    "migrations/postgres/0019_recovery_application.sql"
                ))
                .execute(pool)
                .await
                .map(|_| ())
                .map_err(StoreError::Database)
            }
        }
    }
}

/// Columns added by schema version 13. SQLite has no `ADD COLUMN IF NOT
/// EXISTS`, so both the migration and the version check use this list.
const REVIEW_COLUMNS: &[(&str, &[(&str, &str)])] = &[
    (
        "operation_approvals",
        &[
            ("approver_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("group_scope_hash", "TEXT"),
        ],
    ),
    (
        "grants",
        &[
            ("broker_revocation_outcome", "TEXT"),
            ("revoked_by", "TEXT"),
        ],
    ),
    ("nodes", &[("revoked_by", "TEXT")]),
    (
        "node_sessions",
        &[("delivered_seq", "BIGINT NOT NULL DEFAULT 0")],
    ),
    ("grant_tombstones", &[("envelope_json", "TEXT")]),
];

async fn sqlite_columns(
    pool: &SqlitePool,
    table: &str,
) -> Result<std::collections::BTreeSet<String>, StoreError> {
    let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(pool)
        .await
        .map_err(StoreError::Database)?;
    Ok(rows
        .iter()
        .filter_map(|row| row.try_get::<String, _>("name").ok())
        .collect())
}

/// Version 5 declared `UNIQUE (tenant_id, name)` on `nodes`, which prevents
/// re-enrolling a revoked node's name. SQLite cannot drop a table constraint,
/// so the table is rebuilt once with foreign-key enforcement suspended on a
/// dedicated connection; a partial unique index on active names replaces it.
async fn rebuild_sqlite_nodes_without_name_constraint(pool: &SqlitePool) -> Result<(), StoreError> {
    let indexes = sqlx::query("PRAGMA index_list(nodes)")
        .fetch_all(pool)
        .await
        .map_err(StoreError::Database)?;
    let constrained = indexes
        .iter()
        .any(|row| row.try_get::<String, _>("origin").ok().as_deref() == Some("u"));
    if !constrained {
        return Ok(());
    }
    let mut connection = pool.acquire().await.map_err(StoreError::Database)?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *connection)
        .await
        .map_err(StoreError::Database)?;
    let rebuilt = sqlx::raw_sql(
        "BEGIN IMMEDIATE;
         CREATE TABLE nodes_rebuild (
             id TEXT PRIMARY KEY,
             tenant_id TEXT NOT NULL,
             name TEXT NOT NULL,
             signing_pub TEXT NOT NULL,
             recipient_pub TEXT NOT NULL,
             key_version BIGINT NOT NULL CHECK (key_version > 0),
             status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
             protocol_version TEXT NOT NULL,
             capabilities_json TEXT NOT NULL,
             last_seen_at BIGINT,
             last_poll_at BIGINT,
             created_at BIGINT NOT NULL,
             revoked_at BIGINT,
             version BIGINT NOT NULL DEFAULT 1,
             revoked_by TEXT
         );
         INSERT INTO nodes_rebuild (id, tenant_id, name, signing_pub, recipient_pub, key_version,
             status, protocol_version, capabilities_json, last_seen_at, last_poll_at, created_at,
             revoked_at, version, revoked_by)
         SELECT id, tenant_id, name, signing_pub, recipient_pub, key_version, status,
             protocol_version, capabilities_json, last_seen_at, last_poll_at, created_at,
             revoked_at, version, revoked_by FROM nodes;
         DROP TABLE nodes;
         ALTER TABLE nodes_rebuild RENAME TO nodes;
         CREATE INDEX IF NOT EXISTS nodes_liveness_idx ON nodes (tenant_id, status, last_seen_at, id);
         COMMIT;",
    )
    .execute(&mut *connection)
    .await;
    if rebuilt.is_err() {
        let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
    }
    let violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *connection)
        .await;
    let restored = sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *connection)
        .await;
    rebuilt.map_err(StoreError::Database)?;
    restored.map_err(StoreError::Database)?;
    if !violations.map_err(StoreError::Database)?.is_empty() {
        return Err(StoreError::MissingState("node foreign keys after rebuild"));
    }
    Ok(())
}

/// Rewrite `?` placeholders as PostgreSQL `$n` parameters so a statement is
/// written once for both backends. Statements passed here must not contain
/// literal question marks.
pub(super) fn pg(sql: &str) -> String {
    let mut output = String::with_capacity(sql.len() + 16);
    let mut index = 0;
    for character in sql.chars() {
        if character == '?' {
            index += 1;
            output.push('$');
            output.push_str(&index.to_string());
        } else {
            output.push(character);
        }
    }
    output
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

// SPDX-License-Identifier: AGPL-3.0-only

//! Independently protected recovery metadata and dedicated process guards.
//! A held connection excludes another cooperating connection, but neither a
//! reservation nor a guard proves source shutdown, broker coverage, complete
//! reconciliation or activation. Startup never provisions its database.

use blindpass_core::custody::sha256;
use blindpass_core::secret::{SecretBytes, wipe};
use rand::{RngCore, rngs::OsRng};
use sqlx::{PgConnection, PgPool, postgres::PgPoolOptions};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

mod activation;
mod broker_trust;
mod receipts;
mod report_reader;
pub use activation::{CATEGORIES, DECISIONS, NodeCoverage, RecoveryDecision, ReviewKey};
pub use broker_trust::{BrokerTrustDraft, BrokerTrustRecord, BrokerTrustState, PendingBrokerKey};
pub use receipts::{RecoveryChallenge, RecoveryReceiptScope, RecoveryReceiptState};

const AUTHORITY_DEADLINE: Duration = Duration::from_secs(3);

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    InvalidInput,
    Unavailable,
    Conflict,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid recovery authority input",
            Self::Unavailable => "recovery authority unavailable",
            Self::Conflict => "recovery authority context or revision differs",
        })
    }
}

impl std::error::Error for AuthorityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityContext {
    pub tenant_id: String,
    pub issuer_key_id: String,
    pub owner_id: String,
}

impl AuthorityContext {
    fn validate(&self) -> Result<(), AuthorityError> {
        for value in [&self.tenant_id, &self.issuer_key_id, &self.owner_id] {
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(AuthorityError::InvalidInput);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRecord {
    pub epoch: u64,
    pub revision: u64,
    pub phase: String,
}

impl AuthorityRecord {
    fn from_row(row: (i64, i64, String)) -> Result<Self, AuthorityError> {
        let epoch = u64::try_from(row.0).map_err(|_| AuthorityError::Unavailable)?;
        let revision = u64::try_from(row.1).map_err(|_| AuthorityError::Unavailable)?;
        if !safe_integer(epoch)
            || !safe_integer(revision)
            || !matches!(row.2.as_str(), "fenced" | "recovering" | "active")
        {
            return Err(AuthorityError::Unavailable);
        }
        Ok(Self {
            epoch,
            revision,
            phase: row.2,
        })
    }
}

fn safe_integer(value: u64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&value)
}

pub struct Authority {
    pool: PgPool,
}

impl Authority {
    /// Credentials remain in SQLx's private process memory and are never
    /// copied into recovery archives, diagnostics or this adapter's errors.
    pub async fn connect_existing(url: &str) -> Result<Self, AuthorityError> {
        if url.len() > 16 * 1024
            || !(url.starts_with("postgres://") || url.starts_with("postgresql://"))
            || crate::config::validate_postgres_query_parameters(url).is_err()
        {
            return Err(AuthorityError::InvalidInput);
        }
        // The authority carries ownership proof and its credential: a remote
        // path must verify the server instead of sqlx's silent plaintext
        // fallback. Loopback and Unix-socket paths are not on a network.
        let options = url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .map_err(|_| AuthorityError::InvalidInput)?;
        let host = options.get_host();
        let local = host.starts_with('/')
            || host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !local
            && !matches!(
                options.get_ssl_mode(),
                sqlx::postgres::PgSslMode::VerifyCa | sqlx::postgres::PgSslMode::VerifyFull
            )
        {
            return Err(AuthorityError::InvalidInput);
        }
        deadline(async {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(AUTHORITY_DEADLINE)
            .after_connect(|connection, _| Box::pin(async move {
                sqlx::query("SELECT set_config('statement_timeout','2000ms',false), set_config('lock_timeout','1000ms',false)")
                    .execute(connection).await?;
                Ok(())
            }))
            .connect(url)
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        // A controller schema anywhere in this database rules out the intended
        // separate database. This check neither creates nor migrates anything.
        // Check every membership too: NOINHERIT can hide owner privileges from
        // current_user while retaining the ability to acquire them with SET ROLE.
        let layout: Result<(i64, bool, bool), _> = sqlx::query_as(
            "SELECT version, EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relname = 'controller_meta'),
             EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS role
                 WHERE pg_has_role(current_user, role.oid, 'MEMBER') AND (
                     role.rolsuper OR role.rolcreaterole OR role.rolcreatedb
                     OR has_schema_privilege(role.oid, 'blindpass_authority', 'CREATE')
                     OR has_table_privilege(role.oid, 'blindpass_authority.recovery_authority', 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                     OR has_any_column_privilege(role.oid, 'blindpass_authority.recovery_authority', 'UPDATE')
                     OR has_table_privilege(role.oid, 'blindpass_authority.authority_layout', 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                     OR has_any_column_privilege(role.oid, 'blindpass_authority.authority_layout', 'UPDATE')
                     OR has_table_privilege(role.oid, 'blindpass_authority.process_guard', 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                     OR has_any_column_privilege(role.oid, 'blindpass_authority.process_guard', 'UPDATE')
                     OR has_table_privilege(role.oid, 'blindpass_authority.active_process', 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                     OR has_any_column_privilege(role.oid, 'blindpass_authority.active_process', 'UPDATE')))
             OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS role WHERE pg_has_role(current_user,role.oid,'MEMBER') AND (
                 has_table_privilege(role.oid,'blindpass_authority.broker_trust','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.broker_trust','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.broker_key_history','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.broker_key_history','UPDATE')))
             OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS role WHERE pg_has_role(current_user,role.oid,'MEMBER') AND (
                 has_table_privilege(role.oid,'blindpass_authority.broker_observations','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.broker_observations','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_challenges','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_challenges','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_pages','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_pages','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_source_stop','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_source_stop','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_node_waivers','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_node_waivers','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_review_decisions','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_review_decisions','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_review_complete','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_review_complete','UPDATE')
                 OR has_table_privilege(role.oid,'blindpass_authority.recovery_activations','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                 OR has_any_column_privilege(role.oid,'blindpass_authority.recovery_activations','UPDATE')))
             OR NOT has_table_privilege(current_user,'blindpass_authority.broker_observations','SELECT')
             OR NOT has_table_privilege(current_user,'blindpass_authority.recovery_challenges','SELECT')
             OR NOT has_table_privilege(current_user,'blindpass_authority.recovery_pages','SELECT')
             OR NOT has_function_privilege(current_user,'blindpass_authority.open_recovery_challenge(text,text,text,bigint,bigint,integer,bytea,text,text,bigint,bigint,bigint,text,text)','EXECUTE')
             OR NOT has_function_privilege(current_user,'blindpass_authority.stage_recovery_page(text,text,text,bigint,bigint,integer,bytea,text,text,text,bigint,bigint,text,text,text)','EXECUTE')
             OR NOT has_function_privilege(current_user,'blindpass_authority.finish_recovery_challenge(text,text,text,bigint,bigint,integer,bytea,text,text,text,bigint,bigint,bytea,boolean,bigint)','EXECUTE')
             OR NOT has_function_privilege(current_user, 'blindpass_authority.reserve_recovery(text,text,text,bigint,bigint)', 'EXECUTE')
             OR NOT has_function_privilege(current_user,'blindpass_authority.decide_recovery_item(text,text,text,bigint,bigint,integer,bytea,text,text,text,text,text,text)','EXECUTE')
             OR NOT has_function_privilege(current_user,'blindpass_authority.waive_recovery_node(text,text,text,bigint,bigint,integer,bytea,text,text,text)','EXECUTE')
             OR NOT has_function_privilege(current_user,'blindpass_authority.complete_recovery_review(text,text,text,bigint,bigint,integer,bytea,bigint)','EXECUTE')
             OR NOT has_function_privilege(current_user,'blindpass_authority.recovery_activation_gaps(text,text,text,boolean)','EXECUTE')
             OR has_function_privilege(current_user,'blindpass_authority.attest_source_stop(text,text,text,text,text,text)','EXECUTE')
             OR has_function_privilege(current_user,'blindpass_authority.activate_recovery(text,text,text,bigint)','EXECUTE')
             OR NOT has_function_privilege(current_user, 'blindpass_authority.claim_process(text,text,text,bigint,bigint,text,bytea)', 'EXECUTE')
             OR NOT has_function_privilege(current_user, 'blindpass_authority.register_active_process(text,text,text,bigint,bigint,integer,bytea)', 'EXECUTE')
             OR NOT has_function_privilege(current_user, 'blindpass_authority.publish_broker_trust(text,text,text,bigint,bigint,integer,bytea,bigint,text,bigint,text,text,text,bigint,text,text,text)', 'EXECUTE')
             FROM blindpass_authority.authority_layout WHERE singleton = TRUE",
        ).fetch_one(&pool).await;
        if !matches!(layout, Ok((5, false, false))) {
            pool.close().await;
            return Err(AuthorityError::Unavailable);
        }
        Ok(Self { pool })
        }).await
    }

    pub async fn read(
        &self,
        context: &AuthorityContext,
    ) -> Result<AuthorityRecord, AuthorityError> {
        context.validate()?;
        let row = deadline(async { sqlx::query_as::<_, (i64, i64, String)>(
            "SELECT epoch, revision, phase FROM blindpass_authority.recovery_authority WHERE tenant_id=$1 AND issuer_key_id=$2 AND owner_id=$3",
        )
        .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
        .fetch_optional(&self.pool).await.map_err(|_| AuthorityError::Unavailable)?
        .ok_or(AuthorityError::Conflict) }).await?;
        AuthorityRecord::from_row(row)
    }

    /// Compare-and-reserve a new recovery epoch while externally fenced. No
    /// retry hides an ambiguous commit: read current authority after a failure,
    /// remain fenced, then reconcile that committed reservation explicitly.
    pub async fn reserve_recovery(
        &self,
        context: &AuthorityContext,
        expected_revision: u64,
        trusted_observed_epoch: u64,
    ) -> Result<AuthorityRecord, AuthorityError> {
        context.validate()?;
        if !safe_integer(expected_revision) || !safe_integer(trusted_observed_epoch) {
            return Err(AuthorityError::InvalidInput);
        }
        let row = deadline(async { sqlx::query_as::<_, (i64, i64, String)>(
            "SELECT epoch, revision, phase FROM blindpass_authority.reserve_recovery($1,$2,$3,$4,$5)",
        )
        .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
        .bind(expected_revision as i64).bind(trusted_observed_epoch as i64)
        .fetch_optional(&self.pool).await.map_err(|_| AuthorityError::Unavailable)?
        .ok_or(AuthorityError::Conflict) }).await?;
        AuthorityRecord::from_row(row)
    }

    /// Keep one detached socket and transaction; never return a live guard to
    /// the pool. The exact current record is required, including its phase.
    /// Claiming fenced/recovering metadata does not allow protected operations.
    pub async fn claim_process(
        &self,
        context: &AuthorityContext,
        expected: &AuthorityRecord,
    ) -> Result<ProcessOwnership, AuthorityError> {
        context.validate()?;
        if !safe_integer(expected.epoch)
            || !safe_integer(expected.revision)
            || !matches!(expected.phase.as_str(), "fenced" | "recovering" | "active")
        {
            return Err(AuthorityError::InvalidInput);
        }
        deadline(async {
            let process_token = fresh_process_token()?;
            let mut connection = self.pool.acquire().await
                .map_err(|_| AuthorityError::Unavailable)?.detach();
            sqlx::query("BEGIN ISOLATION LEVEL READ COMMITTED")
                .execute(&mut connection).await.map_err(|_| AuthorityError::Unavailable)?;
            let row = sqlx::query_as::<_, (i64, i64, String, i32)>(
                "SELECT epoch, revision, phase, backend_pid FROM blindpass_authority.claim_process($1,$2,$3,$4,$5,$6,$7)",
            ).bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
                .bind(expected.epoch as i64).bind(expected.revision as i64).bind(&expected.phase)
                .bind(process_token.as_bytes())
                .fetch_optional(&mut connection).await.map_err(|_| AuthorityError::Unavailable)?
                .ok_or(AuthorityError::Conflict)?;
            let record = AuthorityRecord::from_row((row.0, row.1, row.2))?;
            if record != *expected || row.3 <= 0 {
                return Err(AuthorityError::Unavailable);
            }
            if record.phase == "active" {
                let registered: bool = sqlx::query_scalar(
                    "SELECT blindpass_authority.register_active_process($1,$2,$3,$4,$5,$6,$7)",
                ).bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
                    .bind(record.epoch as i64).bind(record.revision as i64).bind(row.3)
                    .bind(process_token.as_bytes())
                    .fetch_one(&self.pool).await.map_err(|_| AuthorityError::Unavailable)?;
                if !registered { return Err(AuthorityError::Conflict); }
            }
            let ownership = ProcessOwnership {
                context: context.clone(), record, backend_pid: row.3, process_token,
                pool: self.pool.clone(),
                connection: Mutex::new(Some(connection)), fenced: AtomicBool::new(false),
                uncertain_database_work: AtomicBool::new(false),
                fence_notification: Notify::new(),
                operations: std::sync::Mutex::new(0),
                operations_drained: Notify::new(),
            };
            ownership.check().await?;
            Ok(ownership)
        }).await
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

fn fresh_process_token() -> Result<SecretBytes, AuthorityError> {
    for _ in 0..4 {
        let mut bytes = vec![0_u8; 32];
        if OsRng.try_fill_bytes(&mut bytes).is_err() {
            wipe(&mut bytes);
            return Err(AuthorityError::Unavailable);
        }
        let token = SecretBytes::new(bytes);
        let digest = sha256(token.as_bytes()).map_err(|_| AuthorityError::Unavailable)?;
        let mut words = [0_i32; 4];
        for (index, word) in words.iter_mut().enumerate() {
            *word = i32::from_be_bytes(
                digest[index * 4..index * 4 + 4]
                    .try_into()
                    .map_err(|_| AuthorityError::Unavailable)?,
            );
        }
        if words[..2] != words[2..] {
            return Ok(token);
        }
    }
    Err(AuthorityError::Unavailable)
}

async fn deadline<T>(
    future: impl std::future::Future<Output = Result<T, AuthorityError>>,
) -> Result<T, AuthorityError> {
    tokio::time::timeout(AUTHORITY_DEADLINE, future)
        .await
        .map_err(|_| AuthorityError::Unavailable)?
}

/// Not cloneable: shared callers must use one Arc around the same held socket.
/// No method reconnects, resets the latch or enables issuer activation.
pub struct ProcessOwnership {
    context: AuthorityContext,
    record: AuthorityRecord,
    backend_pid: i32,
    process_token: SecretBytes,
    pool: PgPool,
    connection: Mutex<Option<PgConnection>>,
    fenced: AtomicBool,
    uncertain_database_work: AtomicBool,
    fence_notification: Notify,
    operations: std::sync::Mutex<usize>,
    operations_drained: Notify,
}

impl ProcessOwnership {
    pub(crate) fn matches_controller(&self, tenant_id: &str, issuer_key_id: &str) -> bool {
        self.context.tenant_id == tenant_id && self.context.issuer_key_id == issuer_key_id
    }

    pub(crate) fn matches_epoch(&self, epoch: u64) -> bool {
        self.record.epoch == epoch
    }

    pub(crate) fn matches_issuer(&self, issuer_key_id: &str) -> bool {
        self.context.issuer_key_id == issuer_key_id
    }

    /// Metadata only, useful for exact operational/test diagnostics.
    pub fn backend_pid(&self) -> i32 {
        self.backend_pid
    }

    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }

    pub fn is_active(&self) -> bool {
        !self.is_fenced() && self.record.phase == "active"
    }

    /// An abandoned database future or failed database acknowledgement cannot
    /// establish server completion. No local outcome read or pool close clears
    /// this latch; it is not durable proof after this process/socket disappears.
    pub fn has_uncertain_database_work(&self) -> bool {
        self.uncertain_database_work.load(Ordering::Acquire)
    }

    fn mark_uncertain_database_work(&self) {
        let operations = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.uncertain_database_work.store(true, Ordering::Release);
        self.fenced.store(true, Ordering::Release);
        self.fence_notification.notify_waiters();
        drop(operations);
    }

    pub(crate) fn is_recovering(&self) -> bool {
        !self.is_fenced() && self.record.phase == "recovering"
    }

    pub(crate) fn begin_maintenance_operation(
        self: &Arc<Self>,
    ) -> Result<OwnershipOperation, AuthorityError> {
        self.admit_phase("fenced")
    }

    pub(crate) fn recovery_context(&self) -> (&AuthorityContext, &AuthorityRecord) {
        (&self.context, &self.record)
    }

    /// Permanently refuse admission. Retain the socket until admitted work
    /// ends; this does not prove source shutdown or delivered grants ended.
    pub fn fence(&self) {
        let operations = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.fenced.store(true, Ordering::Release);
        self.fence_notification.notify_waiters();
        if *operations == 0
            && !self.has_uncertain_database_work()
            && let Ok(mut connection) = self.connection.try_lock()
        {
            connection.take();
        }
    }

    /// Admission and fencing share a mutex, so no operation can enter after
    /// the latch. The caller must check live authority before admission.
    pub fn begin_operation(self: &Arc<Self>) -> Result<OwnershipOperation, AuthorityError> {
        self.admit_phase("active")
    }

    pub(crate) fn begin_recovery_operation(
        self: &Arc<Self>,
    ) -> Result<OwnershipOperation, AuthorityError> {
        self.admit_phase("recovering")
    }

    fn admit_phase(self: &Arc<Self>, phase: &str) -> Result<OwnershipOperation, AuthorityError> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| AuthorityError::Unavailable)?;
        if self.is_fenced() || self.record.phase != phase {
            return Err(AuthorityError::Unavailable);
        }
        *operations = operations
            .checked_add(1)
            .ok_or(AuthorityError::Unavailable)?;
        Ok(OwnershipOperation {
            owner: self.clone(),
        })
    }

    /// Local counted work only. A timeout or uncertain database outcome never
    /// releases the retained guard or resets fencing. This is not server-side
    /// absence or authenticated source-stop evidence after process exit.
    pub async fn quiesce(&self) -> Result<(), AuthorityError> {
        self.fence();
        deadline(async {
            loop {
                let drained = self.operations_drained.notified();
                tokio::pin!(drained);
                drained.as_mut().enable();
                let count = *self
                    .operations
                    .lock()
                    .map_err(|_| AuthorityError::Unavailable)?;
                if count == 0 {
                    if self.has_uncertain_database_work() {
                        return Err(AuthorityError::Unavailable);
                    }
                    self.connection.lock().await.take();
                    return Ok(());
                }
                drained.await;
            }
        })
        .await
    }

    /// A cancelled check is also a loss of proof; its drop guard fences. A
    /// mutex wait counts against the deadline, as do all network operations.
    pub async fn check(&self) -> Result<(), AuthorityError> {
        if self.is_fenced() {
            return Err(AuthorityError::Unavailable);
        }
        let mut attempt = OwnershipCheck {
            owner: self,
            completed: false,
        };
        let result = deadline(async {
            let mut connection = self.connection.lock().await;
            if self.is_fenced() { return Err(AuthorityError::Unavailable); }
            let held = connection.as_mut().ok_or(AuthorityError::Unavailable)?;
            let row = sqlx::query_scalar::<_,i32>(
                "SELECT pg_backend_pid() FROM blindpass_authority.recovery_authority AS ledger WHERE tenant_id=$1 AND issuer_key_id=$2 AND owner_id=$3 AND epoch=$4 AND revision=$5 AND phase=$6 AND (ledger.phase<>'active' OR EXISTS (SELECT 1 FROM blindpass_authority.active_process AS attempt WHERE attempt.tenant_id=ledger.tenant_id AND attempt.epoch=ledger.epoch AND attempt.revision=ledger.revision AND attempt.backend_pid=pg_backend_pid() AND attempt.holder_token_sha256=$7))",
            ).bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id)
                .bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(&self.record.phase)
                .bind(sha256(self.process_token.as_bytes()).map_err(|_| AuthorityError::Unavailable)?.as_slice())
                .fetch_optional(held).await.map_err(|_| AuthorityError::Unavailable)?;
            if self.is_fenced() || row != Some(self.backend_pid) {
                return Err(AuthorityError::Conflict);
            }
            Ok(())
        }).await;
        if result.is_ok() && !self.is_fenced() {
            attempt.completed = true;
            Ok(())
        } else {
            self.fence();
            result.and(Err(AuthorityError::Unavailable))
        }
    }

    /// Run [`Self::check`] on its own task. Unauthenticated HTTP callers may
    /// disconnect at any time; their dropped handler future must not count as
    /// a lost proof. The check keeps its own deadline and fences on a real
    /// failure, panic or timeout.
    pub async fn check_detached(self: &Arc<Self>) -> Result<(), AuthorityError> {
        let owner = self.clone();
        match tokio::spawn(async move { owner.check().await }).await {
            Ok(result) => result,
            Err(_) => {
                self.fence();
                Err(AuthorityError::Unavailable)
            }
        }
    }

    pub async fn wait_fenced(&self) {
        loop {
            let notified = self.fence_notification.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_fenced() {
                return;
            }
            notified.await;
        }
    }

    /// The task keeps only a Weak between checks, so dropping the last caller
    /// cannot leave a background task retaining ownership indefinitely.
    pub fn spawn_monitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(owner) = weak.upgrade() else {
                    return;
                };
                if owner.check().await.is_err() {
                    return;
                }
            }
        })
    }
}

/// Drop only after the admitted future has ended or been cancelled. Keeping
/// an Arc here prevents an owner drop from releasing a live operation's guard.
pub struct OwnershipOperation {
    owner: Arc<ProcessOwnership>,
}

impl OwnershipOperation {
    pub(crate) fn database_work(self) -> OwnershipDatabaseWork {
        OwnershipDatabaseWork {
            operation: self,
            acknowledged: false,
        }
    }
}

/// The permit still drains locally, but uncertain work retains the separate
/// authority socket. Dropping a SQLx future/connection is not a rollback receipt.
pub(crate) struct OwnershipDatabaseWork {
    operation: OwnershipOperation,
    acknowledged: bool,
}

impl OwnershipDatabaseWork {
    pub(crate) fn acknowledge(&mut self) {
        self.acknowledged = true;
    }
}

impl Drop for OwnershipDatabaseWork {
    fn drop(&mut self) {
        if !self.acknowledged {
            // Mark before the operation field drops and can reach zero.
            self.operation.owner.mark_uncertain_database_work();
        }
    }
}

impl Drop for OwnershipOperation {
    fn drop(&mut self) {
        let mut operations = self
            .owner
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *operations -= 1;
        if *operations == 0 {
            self.owner.operations_drained.notify_waiters();
            if self.owner.is_fenced()
                && !self.owner.has_uncertain_database_work()
                && let Ok(mut connection) = self.owner.connection.try_lock()
            {
                connection.take();
            }
        }
    }
}

struct OwnershipCheck<'a> {
    owner: &'a ProcessOwnership,
    completed: bool,
}
impl Drop for OwnershipCheck<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.fence();
        }
    }
}

/// The candidate HTTP gate protects every path except exact health/readiness.
/// It cancels pending handlers on loss; this is not proof of mutation rollback,
/// streamed-body drainage or source shutdown. Local administration is separate.
pub async fn ownership_gate(
    axum::extract::State(owner): axum::extract::State<Arc<ProcessOwnership>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if matches!(request.uri().path(), "/healthz" | "/readyz") {
        return next.run(request).await;
    }
    if owner.check_detached().await.is_err() || !owner.is_active() {
        return fenced_response();
    }
    let Ok(_operation) = owner.begin_operation() else {
        return fenced_response();
    };
    tokio::select! {
        biased;
        _ = owner.wait_fenced() => fenced_response(),
        response = next.run(request) => {
            if owner.is_fenced() { fenced_response() } else { response }
        }
    }
}

pub(crate) fn fenced_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (
                axum::http::HeaderName::from_static("x-content-type-options"),
                "nosniff",
            ),
            (
                axum::http::HeaderName::from_static("referrer-policy"),
                "no-referrer",
            ),
        ],
        axum::Json(serde_json::json!({"error":"recovery_required"})),
    )
        .into_response()
}

// SPDX-License-Identifier: AGPL-3.0-only

//! Fleet lifecycle maintenance: revocation redelivery, expiry transitions,
//! operation closure documents and bounded retention.

use super::grants::with_revocation_result;
use super::{
    Database, FleetSigner, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
};
use blindpass_core::fleet::{DocumentKind, Revocation};
use sqlx::{Postgres, Row, Sqlite, Transaction};

/// Maximum revocation documents re-queued for one node session.
const REQUEUE_LIMIT: i64 = 100;

/// Counts of records moved to terminal states by one expiry sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FleetExpirySummary {
    pub expired_approvals: u64,
    pub expired_operations: u64,
    pub expired_grants: u64,
    /// Executing operations whose grant deadline passed without a completed
    /// broker result; they become `uncertain`.
    pub unconfirmed_operations: u64,
    /// Clock-fence tombstones given a signed revocation this pass.
    pub signed_tombstones: u64,
}

/// Counts of retention rows removed by one bounded maintenance pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FleetPruneSummary {
    pub acknowledged_inbox_rows: u64,
    pub node_events: u64,
    pub node_sessions: u64,
    pub node_challenges: u64,
    pub grant_tombstones: u64,
}

const REQUEUE_SELECT: &str = "SELECT t.envelope_json FROM grant_tombstones t
    JOIN grants g ON g.id = t.grant_id
    WHERE t.node_id = ? AND g.tenant_id = ? AND t.envelope_json IS NOT NULL
      AND t.retain_until > {now} AND g.broker_revocation_outcome IS NULL
      AND NOT EXISTS (SELECT 1 FROM node_inbox i WHERE i.node_id = t.node_id
        AND i.acked_at IS NULL AND i.envelope_json = t.envelope_json)
    ORDER BY t.created_at, t.grant_id LIMIT ?";

/// Re-queue signed grant revocations that the broker has not yet reported
/// applying and whose tombstones are still retained (P03-D11: pushed on
/// reconnect). A copy still waiting in the inbox is not duplicated.
pub(super) async fn requeue_revocations_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    node_id: &str,
) -> Result<u64, StoreError> {
    let sql = REQUEUE_SELECT.replace("{now}", SQLITE_NOW_MS);
    let envelopes: Vec<String> = sqlx::query_scalar(&sql)
        .bind(node_id)
        .bind(tenant_id)
        .bind(REQUEUE_LIMIT)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    for envelope in &envelopes {
        enqueue_node_document_sqlite(tx, node_id, envelope).await?;
    }
    Ok(envelopes.len() as u64)
}

pub(super) async fn requeue_revocations_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    node_id: &str,
) -> Result<u64, StoreError> {
    let sql = super::pg(&REQUEUE_SELECT.replace("{now}", POSTGRES_NOW_MS));
    let envelopes: Vec<String> = sqlx::query_scalar(&sql)
        .bind(node_id)
        .bind(tenant_id)
        .bind(REQUEUE_LIMIT)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    for envelope in &envelopes {
        enqueue_node_document_postgres(tx, node_id, envelope).await?;
    }
    Ok(envelopes.len() as u64)
}

impl Store {
    /// Metadata of an already-recorded node audit row, if any.
    pub(super) async fn node_audit_metadata(&self, id: &str) -> Result<Option<String>, StoreError> {
        let sql = "SELECT metadata_json FROM audit_events WHERE id = ? AND tenant_id = ?";
        match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar(sql)
                .bind(id)
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database),
            Database::Postgres(pool) => sqlx::query_scalar(&super::pg(sql))
                .bind(id)
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database),
        }
    }

    /// Record the broker-reported outcome of a grant revocation. Only a
    /// revoked grant of this node accepts an outcome, and a recorded outcome
    /// never changes. `already_consumed` marks the grant consumed and gives
    /// its operation the typed post-consumption revocation result.
    pub(super) async fn apply_grant_revocation_outcome(
        &self,
        node_id: &str,
        grant_id: &str,
        outcome: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        let (now, lock) = match &self.database {
            Database::Sqlite(_) => (SQLITE_NOW_MS, ""),
            Database::Postgres(_) => (POSTGRES_NOW_MS, " FOR UPDATE OF g, o"),
        };
        let select_sql = format!(
            "SELECT g.status, g.broker_revocation_outcome, g.operation_id,
                    o.status AS operation_status, o.result_json
             FROM grants g JOIN operations o ON o.id = g.operation_id AND o.tenant_id = g.tenant_id
             WHERE g.id = ? AND g.node_id = ? AND g.tenant_id = ?{lock}"
        );
        let grant_sql = format!(
            "UPDATE grants SET broker_revocation_outcome = ?,
               consumed_at = CASE WHEN ? = 'already_consumed'
                 THEN COALESCE(consumed_at, {now}) ELSE consumed_at END
             WHERE id = ? AND tenant_id = ? AND broker_revocation_outcome IS NULL"
        );
        let operation_sql = "UPDATE operations SET result_json = ?, version = version + 1
             WHERE id = ? AND tenant_id = ? AND status = 'revoked'";
        macro_rules! apply {
            ($pool:expr, $convert:expr) => {{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                let Some(row) = sqlx::query(&$convert(&select_sql))
                    .bind(grant_id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?
                else {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                };
                let status: String = row.try_get("status").map_err(StoreError::Database)?;
                let recorded: Option<String> = row
                    .try_get("broker_revocation_outcome")
                    .map_err(StoreError::Database)?;
                let operation_id: String =
                    row.try_get("operation_id").map_err(StoreError::Database)?;
                let operation_status: String = row
                    .try_get("operation_status")
                    .map_err(StoreError::Database)?;
                let result_json: Option<String> =
                    row.try_get("result_json").map_err(StoreError::Database)?;
                if status != "revoked" {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                if let Some(recorded) = recorded {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(recorded == outcome);
                }
                sqlx::query(&$convert(&grant_sql))
                    .bind(outcome)
                    .bind(outcome)
                    .bind(grant_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if outcome == "already_consumed" && operation_status == "revoked" {
                    let merged = with_revocation_result(result_json.as_deref(), None);
                    if result_json.as_deref() != Some(merged.as_str()) {
                        sqlx::query(&$convert(operation_sql))
                            .bind(merged)
                            .bind(&operation_id)
                            .bind(&self.tenant_id)
                            .execute(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?;
                    }
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }};
        }
        match &self.database {
            Database::Sqlite(pool) => apply!(pool, |sql: &str| sql.to_owned()),
            Database::Postgres(pool) => apply!(pool, super::pg),
        }
    }
}

/// Rows removed per retention category by one maintenance pass.
const PRUNE_BATCH: i64 = 1_000;
/// Acknowledged inbox rows are kept this long for diagnosis.
const ACKED_INBOX_RETENTION_MS: i64 = 60 * 60 * 1_000;
/// Broker events are kept this long for idempotent replay and audit joins.
const NODE_EVENT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
/// Expired node sessions are kept this long after expiry.
const NODE_SESSION_RETENTION_MS: i64 = 60 * 60 * 1_000;

/// Bounded retention statements. Each keeps the rows a live channel still
/// needs: the highest inbox sequence per node (sequence allocation) and the
/// newest session per node (delivered high-water mark inheritance).
const PRUNE_STATEMENTS: [&str; 5] = [
    "DELETE FROM node_inbox WHERE (node_id, seq) IN (
       SELECT i.node_id, i.seq FROM node_inbox i JOIN nodes n ON n.id = i.node_id
       WHERE n.tenant_id = ? AND i.acked_at IS NOT NULL AND i.acked_at < {now} - ?
         AND i.seq < (SELECT MAX(m.seq) FROM node_inbox m WHERE m.node_id = i.node_id)
       LIMIT ?)",
    "DELETE FROM node_events WHERE id IN (
       SELECT e.id FROM node_events e JOIN nodes n ON n.id = e.node_id
       WHERE n.tenant_id = ? AND e.received_at < {now} - ? LIMIT ?)",
    "DELETE FROM node_sessions WHERE id IN (
       SELECT s.id FROM node_sessions s JOIN nodes n ON n.id = s.node_id
       WHERE n.tenant_id = ? AND s.expires_at < {now} - ?
         AND s.created_at < (SELECT MAX(l.created_at) FROM node_sessions l WHERE l.node_id = s.node_id)
       LIMIT ?)",
    "DELETE FROM node_challenges WHERE id IN (
       SELECT id FROM node_challenges WHERE tenant_id = ? AND expires_at < {now} + ? LIMIT ?)",
    "DELETE FROM grant_tombstones WHERE grant_id IN (
       SELECT t.grant_id FROM grant_tombstones t JOIN nodes n ON n.id = t.node_id
       WHERE n.tenant_id = ? AND t.retain_until < {now} - ? LIMIT ?)",
];

impl Store {
    /// Remove bounded batches of retention rows: acknowledged inbox rows,
    /// old broker events, expired sessions, unused legacy challenges and
    /// tombstones past their retention. Runs from the periodic maintenance
    /// task and is directly callable.
    pub async fn prune_fleet_state(&self) -> Result<FleetPruneSummary, StoreError> {
        self.checkpoint_clock().await?;
        // Legacy challenge rows are no longer written; remove all of them.
        let retention = [
            ACKED_INBOX_RETENTION_MS,
            NODE_EVENT_RETENTION_MS,
            NODE_SESSION_RETENTION_MS,
            i64::MAX / 4,
            0,
        ];
        let mut counts = [0_u64; 5];
        for (index, statement) in PRUNE_STATEMENTS.iter().enumerate() {
            counts[index] = match &self.database {
                Database::Sqlite(pool) => sqlx::query(&statement.replace("{now}", SQLITE_NOW_MS))
                    .bind(&self.tenant_id)
                    .bind(retention[index])
                    .bind(PRUNE_BATCH)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .rows_affected(),
                Database::Postgres(pool) => {
                    sqlx::query(&super::pg(&statement.replace("{now}", POSTGRES_NOW_MS)))
                        .bind(&self.tenant_id)
                        .bind(retention[index])
                        .bind(PRUNE_BATCH)
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?
                        .rows_affected()
                }
            };
        }
        Ok(FleetPruneSummary {
            acknowledged_inbox_rows: counts[0],
            node_events: counts[1],
            node_sessions: counts[2],
            node_challenges: counts[3],
            grant_tombstones: counts[4],
        })
    }
}

/// Counts of fleet authority withdrawn when the controller clock is fenced
/// or reconciled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct FleetFencePurge {
    pub expired_operation_approvals: u64,
    pub denied_operations: u64,
    pub revoked_grants: u64,
    pub expired_enrollments: u64,
    pub revoked_node_sessions: u64,
}

/// Actor recorded on grants withdrawn by a clock fence.
const CLOCK_FENCE_ACTOR: &str = "system:clock_fence";

macro_rules! fence_purge {
    ($name:ident, $db:ty, $convert:expr) => {
        /// Withdraw fleet authority whose deadlines came from an untrusted
        /// clock (P02-D9 applied to P03): pending approval groups expire,
        /// ungranted operations are denied, issued and delivered grants are
        /// revoked with tombstones (their signed revocations are produced by
        /// the next maintenance pass), unapproved enrollments expire, node
        /// sessions are revoked and legacy challenges are removed.
        pub(super) async fn $name(
            tx: &mut Transaction<'_, $db>,
            now_ms: i64,
        ) -> Result<FleetFencePurge, StoreError> {
            let mut purge = FleetFencePurge::default();
            let fence_result = r#"{"reason":"clock_fence"}"#;
            purge.expired_operation_approvals = sqlx::query(&$convert(
                "UPDATE operation_approvals SET status = 'expired', decided_at = ?,
                   version = version + 1 WHERE status = 'pending'",
            ))
            .bind(now_ms)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            purge.denied_operations = sqlx::query(&$convert(
                "UPDATE operations SET status = 'denied', result_json = ?, completed_at = ?,
                   version = version + 1 WHERE status IN ('requested', 'awaiting_approval')",
            ))
            .bind(fence_result)
            .bind(now_ms)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            sqlx::query(&$convert(
                "INSERT INTO grant_tombstones
                   (grant_id, node_id, reason, created_at, retain_until, envelope_json)
                 SELECT id, node_id, 'policy', ?,
                   (CASE WHEN expires_at > ? THEN expires_at ELSE ? END) + ?, NULL
                 FROM grants WHERE status IN ('issued', 'delivered')
                 ON CONFLICT (grant_id) DO NOTHING",
            ))
            .bind(now_ms)
            .bind(now_ms)
            .bind(now_ms)
            .bind(TOMBSTONE_RETENTION_MS)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            sqlx::query(&$convert(
                "UPDATE operations SET status = 'revoked', result_json = ?, completed_at = ?,
                   version = version + 1
                 WHERE status = 'granted' AND grant_id IN (
                   SELECT id FROM grants WHERE status IN ('issued', 'delivered'))",
            ))
            .bind(fence_result)
            .bind(now_ms)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            purge.revoked_grants = sqlx::query(&$convert(
                "UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ?
                 WHERE status IN ('issued', 'delivered')",
            ))
            .bind(now_ms)
            .bind(CLOCK_FENCE_ACTOR)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            purge.expired_enrollments = sqlx::query(&$convert(
                "UPDATE enrollment_requests SET status = 'expired', version = version + 1
                 WHERE status IN ('issued', 'submitted')",
            ))
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            purge.revoked_node_sessions = sqlx::query(&$convert(
                "UPDATE node_sessions SET revoked_at = ? WHERE revoked_at IS NULL",
            ))
            .bind(now_ms)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            sqlx::query("DELETE FROM node_challenges")
                .execute(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
            Ok(purge)
        }
    };
}

fence_purge!(fleet_fence_purge_sqlite, Sqlite, |sql: &str| sql.to_owned());
fence_purge!(fleet_fence_purge_postgres, Postgres, super::pg);

/// Tombstone retention used for fence-withdrawn grants.
const TOMBSTONE_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Upper bound on tombstones signed by one maintenance pass.
const SIGN_BATCH: i64 = 200;

macro_rules! sign_pending_tombstones {
    ($name:ident, $db:ty, $convert:expr, $now:expr, $enqueue:path) => {
        /// Sign and queue revocations for tombstones written without a
        /// signed document (clock-fence withdrawals), for active nodes.
        pub(super) async fn $name(
            tx: &mut Transaction<'_, $db>,
            signer: &FleetSigner,
            tenant_id: &str,
        ) -> Result<u64, StoreError> {
            let epoch: i64 =
                sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(StoreError::Database)?;
            let rows = sqlx::query(&$convert(&format!(
                "SELECT t.grant_id, t.node_id, t.created_at, t.retain_until
                 FROM grant_tombstones t JOIN nodes n ON n.id = t.node_id
                 WHERE n.tenant_id = ? AND n.status = 'active' AND t.envelope_json IS NULL
                   AND t.retain_until > {}
                 ORDER BY t.created_at, t.grant_id LIMIT ?",
                $now
            )))
            .bind(tenant_id)
            .bind(SIGN_BATCH)
            .fetch_all(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            let epoch =
                u64::try_from(epoch).map_err(|_| StoreError::InvalidInput("issuer epoch"))?;
            for row in &rows {
                let grant_id: String = row.try_get("grant_id").map_err(StoreError::Database)?;
                let node_id: String = row.try_get("node_id").map_err(StoreError::Database)?;
                let created_at: i64 = row.try_get("created_at").map_err(StoreError::Database)?;
                let retain_until: i64 =
                    row.try_get("retain_until").map_err(StoreError::Database)?;
                let body = Revocation {
                    grant_id: grant_id.clone(),
                    node_id: node_id.clone(),
                    reason: "policy".to_owned(),
                    revoked_at_ms: u64::try_from(created_at)
                        .map_err(|_| StoreError::InvalidInput("revocation time"))?,
                    retain_until_ms: u64::try_from(retain_until)
                        .map_err(|_| StoreError::InvalidInput("tombstone retention"))?,
                    issuer_epoch: epoch,
                }
                .to_value()
                .map_err(|_| StoreError::InvalidInput("revocation"))?;
                let envelope = signer.sign(DocumentKind::Revocation, body, epoch)?;
                sqlx::query(&$convert(
                    "UPDATE grant_tombstones SET envelope_json = ?
                     WHERE grant_id = ? AND envelope_json IS NULL",
                ))
                .bind(&envelope)
                .bind(&grant_id)
                .execute(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
                $enqueue(tx, &node_id, &envelope).await?;
            }
            Ok(rows.len() as u64)
        }
    };
}

sign_pending_tombstones!(
    sign_pending_tombstones_sqlite,
    Sqlite,
    |sql: &str| sql.to_owned(),
    SQLITE_NOW_MS,
    enqueue_node_document_sqlite
);
sign_pending_tombstones!(
    sign_pending_tombstones_postgres,
    Postgres,
    super::pg,
    POSTGRES_NOW_MS,
    enqueue_node_document_postgres
);

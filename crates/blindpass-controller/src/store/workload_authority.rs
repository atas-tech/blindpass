// SPDX-License-Identifier: AGPL-3.0-only

//! Authority retirement when a workload registration is revoked or its
//! identity (unit, account or consumption mode) changes, and the one
//! active registration per node unit invariant.

use super::{
    FleetSigner, POSTGRES_NOW_MS, SQLITE_NOW_MS, StoreError,
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
    operation_approvals::{
        closure_targets_postgres, closure_targets_sqlite, enqueue_closures_postgres,
        enqueue_closures_sqlite,
    },
};
use blindpass_core::fleet::{DocumentKind, Revocation};
use sqlx::{Postgres, Row, Sqlite, Transaction};

/// `StoreError::InvalidInput` message for a second active registration of
/// the same node unit; routes map it to 409 `workload_unit_conflict`.
pub const WORKLOAD_UNIT_CONFLICT: &str = "workload unit conflict";

const TOMBSTONE_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Map a unique-index violation on the active unit index to the typed
/// conflict; other errors stay database errors.
pub(super) fn unit_conflict_error(error: sqlx::Error) -> StoreError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        StoreError::InvalidInput(WORKLOAD_UNIT_CONFLICT)
    } else {
        StoreError::Database(error)
    }
}

fn revocation_envelope(
    signer: &FleetSigner,
    grant_id: &str,
    node_id: &str,
    now_ms: i64,
    expires_at_ms: i64,
    epoch: i64,
) -> Result<(String, i64), StoreError> {
    let retain_until = now_ms
        .max(expires_at_ms)
        .checked_add(TOMBSTONE_RETENTION_MS)
        .ok_or(StoreError::InvalidInput("tombstone retention"))?;
    let epoch = u64::try_from(epoch).map_err(|_| StoreError::InvalidInput("issuer epoch"))?;
    let body = Revocation {
        grant_id: grant_id.to_owned(),
        node_id: node_id.to_owned(),
        reason: "policy".to_owned(),
        revoked_at_ms: u64::try_from(now_ms)
            .map_err(|_| StoreError::InvalidInput("revocation time"))?,
        retain_until_ms: u64::try_from(retain_until)
            .map_err(|_| StoreError::InvalidInput("tombstone retention"))?,
        issuer_epoch: epoch,
    }
    .to_value()
    .map_err(|_| StoreError::InvalidInput("revocation"))?;
    Ok((
        signer.sign(DocumentKind::Revocation, body, epoch)?,
        retain_until,
    ))
}

macro_rules! workload_helpers {
    ($conflict:ident, $retire:ident, $db:ty, $convert:expr, $now:expr, $enqueue:path,
     $targets:ident, $closures:ident) => {
        /// Whether another active registration already claims this unit.
        pub(super) async fn $conflict(
            tx: &mut Transaction<'_, $db>,
            tenant_id: &str,
            node_id: &str,
            unit: &str,
            exclude_id: &str,
        ) -> Result<bool, StoreError> {
            let count: i64 = sqlx::query_scalar(&$convert(
                "SELECT COUNT(*) FROM workloads WHERE tenant_id = ? AND node_id = ? AND unit = ?
                   AND status = 'active' AND id <> ?",
            ))
            .bind(tenant_id)
            .bind(node_id)
            .bind(unit)
            .bind(exclude_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            Ok(count > 0)
        }

        /// Revoke the workload's issued and delivered grants with signed
        /// `policy` revocations and tombstones, and cancel its operations
        /// that are not yet granted, closing their broker requests.
        pub(super) async fn $retire(
            tx: &mut Transaction<'_, $db>,
            signer: Option<&FleetSigner>,
            tenant_id: &str,
            workload_id: &str,
            reason: &str,
            revoked_by: &str,
        ) -> Result<(), StoreError> {
            let result_json = serde_json::json!({ "reason": reason }).to_string();
            let meta = sqlx::query(&format!(
                "SELECT issuer_epoch, {} AS now_ms FROM controller_meta WHERE id = 1",
                $now
            ))
            .fetch_one(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
            let now_ms: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
            let grants = sqlx::query(&$convert(
                "SELECT id, node_id, operation_id, expires_at FROM grants
                 WHERE workload_id = ? AND tenant_id = ? AND status IN ('issued', 'delivered')
                 ORDER BY id",
            ))
            .bind(workload_id)
            .bind(tenant_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            if !grants.is_empty() && signer.is_none() {
                return Err(StoreError::InvalidInput("fleet issuer is not configured"));
            }
            for grant in &grants {
                let grant_id: String = grant.try_get("id").map_err(StoreError::Database)?;
                let node_id: String = grant.try_get("node_id").map_err(StoreError::Database)?;
                let operation_id: String =
                    grant.try_get("operation_id").map_err(StoreError::Database)?;
                let expires_at: i64 = grant.try_get("expires_at").map_err(StoreError::Database)?;
                let Some(signer) = signer else {
                    break;
                };
                let (envelope, retain_until) =
                    revocation_envelope(signer, &grant_id, &node_id, now_ms, expires_at, epoch)?;
                sqlx::query(&$convert(
                    "UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ?
                     WHERE id = ? AND tenant_id = ? AND status IN ('issued', 'delivered')",
                ))
                .bind(now_ms)
                .bind(revoked_by)
                .bind(&grant_id)
                .bind(tenant_id)
                .execute(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(&$convert(
                    "UPDATE operations SET status = 'revoked', result_json = ?, completed_at = ?,
                       version = version + 1
                     WHERE id = ? AND tenant_id = ? AND status IN ('granted', 'executing')",
                ))
                .bind(&result_json)
                .bind(now_ms)
                .bind(&operation_id)
                .bind(tenant_id)
                .execute(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(&$convert(
                    "INSERT INTO grant_tombstones
                       (grant_id, node_id, reason, created_at, retain_until, envelope_json)
                     VALUES (?, ?, 'policy', ?, ?, ?)",
                ))
                .bind(&grant_id)
                .bind(&node_id)
                .bind(now_ms)
                .bind(retain_until)
                .bind(&envelope)
                .execute(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
                $enqueue(tx, &node_id, &envelope).await?;
            }
            let pending = $targets(
                tx,
                tenant_id,
                "o.workload_id = ? AND o.status IN ('requested', 'awaiting_approval')",
                &[workload_id],
            )
            .await?;
            // Approval groups are scoped to one workload, so every pending
            // group holding its operations ends with them.
            sqlx::query(&$convert(
                "UPDATE operation_approvals SET status = 'expired', decided_at = ?,
                   version = version + 1
                 WHERE tenant_id = ? AND status = 'pending' AND id IN (
                   SELECT approval_id FROM operations
                   WHERE workload_id = ? AND tenant_id = ? AND status = 'awaiting_approval'
                     AND approval_id IS NOT NULL)",
            ))
            .bind(now_ms)
            .bind(tenant_id)
            .bind(workload_id)
            .bind(tenant_id)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            sqlx::query(&$convert(
                "UPDATE operations SET status = 'cancelled', result_json = ?, completed_at = ?,
                   version = version + 1
                 WHERE workload_id = ? AND tenant_id = ?
                   AND status IN ('requested', 'awaiting_approval')",
            ))
            .bind(&result_json)
            .bind(now_ms)
            .bind(workload_id)
            .bind(tenant_id)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
            $closures(tx, signer, &pending, "cancelled").await
        }
    };
}

workload_helpers!(
    unit_conflict_sqlite,
    retire_workload_authority_sqlite,
    Sqlite,
    |sql: &str| sql.to_owned(),
    SQLITE_NOW_MS,
    enqueue_node_document_sqlite,
    closure_targets_sqlite,
    enqueue_closures_sqlite
);
workload_helpers!(
    unit_conflict_postgres,
    retire_workload_authority_postgres,
    Postgres,
    super::pg,
    POSTGRES_NOW_MS,
    enqueue_node_document_postgres,
    closure_targets_postgres,
    enqueue_closures_postgres
);

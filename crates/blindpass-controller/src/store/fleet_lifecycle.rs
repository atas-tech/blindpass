// SPDX-License-Identifier: AGPL-3.0-only

//! Fleet lifecycle maintenance: revocation redelivery, expiry transitions,
//! operation closure documents and bounded retention.

use super::grants::with_revocation_result;
use super::{
    Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
};
use sqlx::{Postgres, Row, Sqlite, Transaction};

/// Maximum revocation documents re-queued for one node session.
const REQUEUE_LIMIT: i64 = 100;

/// Counts of records moved to terminal states by one expiry sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FleetExpirySummary {
    pub expired_approvals: u64,
    pub expired_operations: u64,
    pub expired_grants: u64,
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

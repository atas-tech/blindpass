// SPDX-License-Identifier: AGPL-3.0-only

//! Fleet lifecycle maintenance: revocation redelivery, expiry transitions,
//! operation closure documents and bounded retention.

use super::{
    POSTGRES_NOW_MS, SQLITE_NOW_MS, StoreError,
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
};
use sqlx::{Postgres, Sqlite, Transaction};

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

// SPDX-License-Identifier: AGPL-3.0-only

//! Workload, policy, operation and operation-approval persistence.

use super::{Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError};
use sqlx::{
    Row, Transaction,
    postgres::{PgRow, Postgres},
    sqlite::{Sqlite, SqliteRow},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRecord {
    pub id: String,
    pub node_id: String,
    pub name: String,
    pub unit: String,
    pub account: String,
    pub consumption_mode: String,
    pub local_ceiling_seconds: i64,
    pub registration_version: i64,
    pub status: String,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub version: i64,
}

pub(super) async fn enqueue_node_document_sqlite(
    transaction: &mut Transaction<'_, Sqlite>,
    node_id: &str,
    envelope_json: &str,
) -> Result<(), StoreError> {
    if envelope_json.is_empty() || envelope_json.len() > 64 * 1024 {
        return Err(StoreError::InvalidInput("signed node document size"));
    }
    let current: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM node_inbox WHERE node_id = ?")
            .bind(node_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(StoreError::Database)?;
    let sequence = current
        .checked_add(1)
        .ok_or(StoreError::InvalidInput("node inbox sequence"))?;
    let sql = format!(
        "INSERT INTO node_inbox (node_id, seq, envelope_json, created_at) VALUES (?, ?, ?, {SQLITE_NOW_MS})"
    );
    sqlx::query(&sql)
        .bind(node_id)
        .bind(sequence)
        .bind(envelope_json)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) async fn enqueue_node_document_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    node_id: &str,
    envelope_json: &str,
) -> Result<(), StoreError> {
    if envelope_json.is_empty() || envelope_json.len() > 64 * 1024 {
        return Err(StoreError::InvalidInput("signed node document size"));
    }
    let current: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM node_inbox WHERE node_id = $1")
            .bind(node_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(StoreError::Database)?;
    let sequence = current
        .checked_add(1)
        .ok_or(StoreError::InvalidInput("node inbox sequence"))?;
    let sql = format!(
        "INSERT INTO node_inbox (node_id, seq, envelope_json, created_at) VALUES ($1, $2, $3, {POSTGRES_NOW_MS})"
    );
    sqlx::query(&sql)
        .bind(node_id)
        .bind(sequence)
        .bind(envelope_json)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetPolicyRecord {
    pub version: i64,
    pub document_json: String,
    pub updated_at_ms: i64,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    pub id: String,
    pub workload_id: String,
    pub node_id: String,
    pub invocation_id: String,
    pub action: String,
    pub mode: String,
    pub resource_id: String,
    pub requested_ttl_seconds: i64,
    pub broker_event_key: Option<String>,
    pub requested_by: String,
    pub purpose: String,
    pub policy_version: i64,
    pub decision: String,
    pub decision_hash: Option<String>,
    pub status: String,
    pub approval_id: Option<String>,
    pub grant_id: Option<String>,
    pub idempotency_key: String,
    pub request_hash: String,
    pub result_json: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationApprovalRecord {
    pub id: String,
    pub operation_ids_json: String,
    pub requester_summary_json: String,
    pub verified_identity_json: String,
    pub rule_id: String,
    pub status: String,
    pub decided_by: Option<String>,
    pub decided_at_ms: Option<i64>,
    pub expires_at_ms: i64,
    pub idempotency_key: String,
    pub decision_key_hash: Option<String>,
    pub version: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationApprovalDraft {
    pub id: String,
    pub idempotency_key: String,
    pub requester_summary_json: String,
    pub verified_identity_json: String,
    pub rule_id: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationCreateOutcome {
    Created(OperationRecord),
    Existing(OperationRecord),
    Conflict,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationDecisionOutcome {
    Applied(OperationApprovalRecord),
    Replayed(OperationApprovalRecord),
    Conflict,
    NotFound,
    StalePolicy,
}

const WORKLOAD_COLUMNS: &str = "id, node_id, name, unit, account, consumption_mode,
    local_ceiling_seconds, registration_version, status, created_at, revoked_at, version";
const OPERATION_COLUMNS: &str = "id, workload_id, node_id, invocation_id, action, mode,
    resource_id, requested_ttl_seconds, broker_event_key,
    requested_by, purpose, policy_version, decision, decision_hash, status, approval_id,
    grant_id, idempotency_key, request_hash, result_json, created_at, expires_at,
    completed_at, version";
const OPERATION_APPROVAL_COLUMNS: &str = "id, operation_ids_json, requester_summary_json,
    verified_identity_json, rule_id, status, decided_by, decided_at, expires_at,
    idempotency_key, decision_key_hash, version, created_at";

impl Store {
    pub async fn list_workloads(
        &self,
        node_id: Option<&str>,
        limit: u32,
        cursor: Option<(i64, String)>,
    ) -> Result<Vec<WorkloadRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 101));
        match &self.database {
            Database::Sqlite(pool) => {
                let rows = match (node_id, cursor) {
                    (Some(node_id), Some((created_at, id))) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = ? AND node_id = ?
                             AND (created_at < ? OR (created_at = ? AND id < ?))
                             ORDER BY created_at DESC, id DESC LIMIT ?"
                        );
                        sqlx::query(&sql)
                            .bind(&self.tenant_id).bind(node_id).bind(created_at).bind(created_at)
                            .bind(id).bind(limit).fetch_all(pool).await
                    }
                    (Some(node_id), None) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = ? AND node_id = ?
                             ORDER BY created_at DESC, id DESC LIMIT ?"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(node_id).bind(limit)
                            .fetch_all(pool).await
                    }
                    (None, Some((created_at, id))) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = ?
                             AND (created_at < ? OR (created_at = ? AND id < ?))
                             ORDER BY created_at DESC, id DESC LIMIT ?"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(created_at).bind(created_at)
                            .bind(id).bind(limit).fetch_all(pool).await
                    }
                    (None, None) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = ?
                             ORDER BY created_at DESC, id DESC LIMIT ?"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(limit).fetch_all(pool).await
                    }
                }.map_err(StoreError::Database)?;
                rows.iter().map(workload_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let rows = match (node_id, cursor) {
                    (Some(node_id), Some((created_at, id))) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = $1 AND node_id = $2
                             AND (created_at < $3 OR (created_at = $3 AND id < $4))
                             ORDER BY created_at DESC, id DESC LIMIT $5"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(node_id).bind(created_at)
                            .bind(id).bind(limit).fetch_all(pool).await
                    }
                    (Some(node_id), None) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = $1 AND node_id = $2
                             ORDER BY created_at DESC, id DESC LIMIT $3"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(node_id).bind(limit)
                            .fetch_all(pool).await
                    }
                    (None, Some((created_at, id))) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = $1
                             AND (created_at < $2 OR (created_at = $2 AND id < $3))
                             ORDER BY created_at DESC, id DESC LIMIT $4"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(created_at).bind(id)
                            .bind(limit).fetch_all(pool).await
                    }
                    (None, None) => {
                        let sql = format!(
                            "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE tenant_id = $1
                             ORDER BY created_at DESC, id DESC LIMIT $2"
                        );
                        sqlx::query(&sql).bind(&self.tenant_id).bind(limit).fetch_all(pool).await
                    }
                }.map_err(StoreError::Database)?;
                rows.iter().map(workload_from_postgres).collect()
            }
        }
    }

    pub async fn workload_by_id(&self, id: &str) -> Result<Option<WorkloadRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let sql =
            format!("SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE id = ? AND tenant_id = ?");
        match &self.database {
            Database::Sqlite(pool) => sqlx::query(&sql)
                .bind(id)
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?
                .as_ref()
                .map(workload_from_sqlite)
                .transpose(),
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT {WORKLOAD_COLUMNS} FROM workloads WHERE id = $1 AND tenant_id = $2"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(workload_from_postgres)
                    .transpose()
            }
        }
    }

    pub async fn create_workload(
        &self,
        record: &WorkloadRecord,
        created_by: &str,
        registration_envelope_json: &str,
        policy_envelope_json: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                let locked = sqlx::query(
                    "UPDATE nodes SET version = version WHERE id = ? AND tenant_id = ? AND status = 'active'",
                )
                .bind(&record.node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if locked.rows_affected() != 1 {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "INSERT INTO workloads (id, tenant_id, node_id, name, unit, account,
                     consumption_mode, local_ceiling_seconds, registration_version, status,
                     created_by, created_at, version)
                     SELECT ?, ?, n.id, ?, ?, ?, ?, ?, 1, 'active', ?, {SQLITE_NOW_MS}, 1
                     FROM nodes n WHERE n.id = ? AND n.tenant_id = ? AND n.status = 'active'"
                );
                let result = sqlx::query(&sql)
                    .bind(&record.id)
                    .bind(&self.tenant_id)
                    .bind(&record.name)
                    .bind(&record.unit)
                    .bind(&record.account)
                    .bind(&record.consumption_mode)
                    .bind(record.local_ceiling_seconds)
                    .bind(created_by)
                    .bind(&record.node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    enqueue_node_document_sqlite(&mut tx, &record.node_id, policy_envelope_json)
                        .await?;
                    enqueue_node_document_sqlite(
                        &mut tx,
                        &record.node_id,
                        registration_envelope_json,
                    )
                    .await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                let locked: Option<String> = sqlx::query_scalar(
                    "SELECT id FROM nodes WHERE id = $1 AND tenant_id = $2 AND status = 'active' FOR UPDATE",
                )
                .bind(&record.node_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if locked.is_none() {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let sql = format!(
                    "INSERT INTO workloads (id, tenant_id, node_id, name, unit, account,
                     consumption_mode, local_ceiling_seconds, registration_version, status,
                     created_by, created_at, version)
                     SELECT $1, $2, n.id, $3, $4, $5, $6, $7, 1, 'active', $8,
                            {POSTGRES_NOW_MS}, 1
                     FROM nodes n WHERE n.id = $9 AND n.tenant_id = $2 AND n.status = 'active'"
                );
                let result = sqlx::query(&sql)
                    .bind(&record.id)
                    .bind(&self.tenant_id)
                    .bind(&record.name)
                    .bind(&record.unit)
                    .bind(&record.account)
                    .bind(&record.consumption_mode)
                    .bind(record.local_ceiling_seconds)
                    .bind(created_by)
                    .bind(&record.node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    enqueue_node_document_postgres(&mut tx, &record.node_id, policy_envelope_json)
                        .await?;
                    enqueue_node_document_postgres(
                        &mut tx,
                        &record.node_id,
                        registration_envelope_json,
                    )
                    .await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // Update inputs and their signed snapshots are explicit.
    pub async fn update_workload(
        &self,
        id: &str,
        expected_version: i64,
        unit: &str,
        account: &str,
        consumption_mode: &str,
        local_ceiling_seconds: i64,
        node_id: &str,
        registration_envelope_json: &str,
        policy_envelope_json: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE nodes SET version = version WHERE id = ? AND tenant_id = ? AND status = 'active'")
                    .bind(node_id).bind(&self.tenant_id).execute(&mut *tx).await
                    .map_err(StoreError::Database)?;
                let sql = "UPDATE workloads SET unit = ?, account = ?, consumption_mode = ?,
                     local_ceiling_seconds = ?, registration_version = registration_version + 1,
                     version = version + 1 WHERE id = ? AND tenant_id = ? AND status = 'active'
                     AND version = ? AND EXISTS (SELECT 1 FROM nodes n WHERE n.id = node_id
                     AND n.tenant_id = ? AND n.status = 'active')";
                let result = sqlx::query(sql)
                    .bind(unit)
                    .bind(account)
                    .bind(consumption_mode)
                    .bind(local_ceiling_seconds)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    enqueue_node_document_sqlite(&mut tx, node_id, policy_envelope_json).await?;
                    enqueue_node_document_sqlite(&mut tx, node_id, registration_envelope_json)
                        .await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM nodes WHERE id = $1 AND tenant_id = $2 AND status = 'active' FOR UPDATE")
                    .bind(node_id).bind(&self.tenant_id).fetch_optional(&mut *tx).await
                    .map_err(StoreError::Database)?;
                let sql = "UPDATE workloads SET unit = $1, account = $2, consumption_mode = $3,
                     local_ceiling_seconds = $4, registration_version = registration_version + 1,
                     version = version + 1 WHERE id = $5 AND tenant_id = $6 AND status = 'active'
                     AND version = $7 AND EXISTS (SELECT 1 FROM nodes n WHERE n.id = node_id
                     AND n.tenant_id = $6 AND n.status = 'active')";
                let result = sqlx::query(sql)
                    .bind(unit)
                    .bind(account)
                    .bind(consumption_mode)
                    .bind(local_ceiling_seconds)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    enqueue_node_document_postgres(&mut tx, node_id, policy_envelope_json).await?;
                    enqueue_node_document_postgres(&mut tx, node_id, registration_envelope_json)
                        .await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    pub async fn revoke_workload(
        &self,
        id: &str,
        node_id: &str,
        expected_version: i64,
        registration_envelope_json: &str,
        policy_envelope_json: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE nodes SET version = version WHERE id = ? AND tenant_id = ?")
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let sql = format!(
                    "UPDATE workloads SET status = 'revoked', revoked_at = {SQLITE_NOW_MS},
                     registration_version = registration_version + 1, version = version + 1
                     WHERE id = ? AND tenant_id = ? AND status = 'active' AND version = ?"
                );
                let result = sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    enqueue_node_document_sqlite(&mut tx, node_id, policy_envelope_json).await?;
                    enqueue_node_document_sqlite(&mut tx, node_id, registration_envelope_json)
                        .await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM nodes WHERE id = $1 AND tenant_id = $2 FOR UPDATE")
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let sql = format!(
                    "UPDATE workloads SET status = 'revoked', revoked_at = {POSTGRES_NOW_MS},
                     registration_version = registration_version + 1, version = version + 1
                     WHERE id = $1 AND tenant_id = $2 AND status = 'active' AND version = $3"
                );
                let result = sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                if result.rows_affected() == 1 {
                    enqueue_node_document_postgres(&mut tx, node_id, policy_envelope_json).await?;
                    enqueue_node_document_postgres(&mut tx, node_id, registration_envelope_json)
                        .await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    pub async fn fleet_policy(&self) -> Result<FleetPolicyRecord, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT version, document_json, updated_at, updated_by
                    FROM fleet_policies WHERE tenant_id = ?",
                )
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref()
                    .map(fleet_policy_from_sqlite)
                    .transpose()
                    .map(|record| {
                        record.unwrap_or(FleetPolicyRecord {
                            version: 1,
                            document_json: "{\"rules\":[]}".to_owned(),
                            updated_at_ms: 0,
                            updated_by: String::new(),
                        })
                    })
            }
            Database::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT version, document_json, updated_at, updated_by
                    FROM fleet_policies WHERE tenant_id = $1",
                )
                .bind(&self.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Database)?;
                row.as_ref()
                    .map(fleet_policy_from_postgres)
                    .transpose()
                    .map(|record| {
                        record.unwrap_or(FleetPolicyRecord {
                            version: 1,
                            document_json: "{\"rules\":[]}".to_owned(),
                            updated_at_ms: 0,
                            updated_by: String::new(),
                        })
                    })
            }
        }
    }

    pub async fn replace_fleet_policy(
        &self,
        expected_version: i64,
        document_json: &str,
        updated_by: &str,
        node_documents: &[(String, String)],
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        if expected_version <= 0 {
            return Err(StoreError::InvalidInput("policy version"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let current: Option<i64> =
                    sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = ?")
                        .bind(&self.tenant_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                let current = current.unwrap_or(1);
                if current != expected_version {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let next = current
                    .checked_add(1)
                    .ok_or(StoreError::InvalidInput("policy version"))?;
                let sql = format!("INSERT INTO fleet_policies (tenant_id, version, document_json, updated_at, updated_by)
                    VALUES (?, ?, ?, {SQLITE_NOW_MS}, ?) ON CONFLICT(tenant_id) DO UPDATE SET
                    version = excluded.version, document_json = excluded.document_json,
                    updated_at = excluded.updated_at, updated_by = excluded.updated_by");
                sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(next)
                    .bind(document_json)
                    .bind(updated_by)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                for (node_id, envelope_json) in node_documents {
                    enqueue_node_document_sqlite(&mut tx, node_id, envelope_json).await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let current: Option<i64> = sqlx::query_scalar(
                    "SELECT version FROM fleet_policies WHERE tenant_id = $1 FOR UPDATE",
                )
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let current = current.unwrap_or(1);
                if current != expected_version {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let next = current
                    .checked_add(1)
                    .ok_or(StoreError::InvalidInput("policy version"))?;
                let sql = format!("INSERT INTO fleet_policies (tenant_id, version, document_json, updated_at, updated_by)
                    VALUES ($1, $2, $3, {POSTGRES_NOW_MS}, $4) ON CONFLICT(tenant_id) DO UPDATE SET
                    version = EXCLUDED.version, document_json = EXCLUDED.document_json,
                    updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by");
                sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(next)
                    .bind(document_json)
                    .bind(updated_by)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                for (node_id, envelope_json) in node_documents {
                    enqueue_node_document_postgres(&mut tx, node_id, envelope_json).await?;
                }
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    pub async fn active_node_ids(&self) -> Result<Vec<String>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => sqlx::query_scalar(
                "SELECT id FROM nodes WHERE tenant_id = ? AND status = 'active' ORDER BY id",
            )
            .bind(&self.tenant_id)
            .fetch_all(pool)
            .await
            .map_err(StoreError::Database),
            Database::Postgres(pool) => sqlx::query_scalar(
                "SELECT id FROM nodes WHERE tenant_id = $1 AND status = 'active' ORDER BY id",
            )
            .bind(&self.tenant_id)
            .fetch_all(pool)
            .await
            .map_err(StoreError::Database),
        }
    }
}

async fn create_operation_sqlite(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    record: &OperationRecord,
    expected_unit: &str,
    expected_account: &str,
    effective_ttl_seconds: i64,
    approval: Option<&OperationApprovalDraft>,
) -> Result<OperationCreateOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let lookup = format!(
        "SELECT {OPERATION_COLUMNS} FROM operations WHERE tenant_id = ? AND requested_by = ? AND idempotency_key = ?"
    );
    if let Some(row) = sqlx::query(&lookup)
        .bind(tenant_id)
        .bind(&record.requested_by)
        .bind(&record.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
    {
        let existing = operation_from_sqlite(&row)?;
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(if existing.request_hash == record.request_hash {
            OperationCreateOutcome::Existing(existing)
        } else {
            OperationCreateOutcome::Conflict
        });
    }
    if let Some(event_key) = record.broker_event_key.as_deref() {
        let used: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE tenant_id = ? AND node_id = ? AND broker_event_key = ?)",
        )
        .bind(tenant_id)
        .bind(&record.node_id)
        .bind(event_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if used {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationCreateOutcome::Conflict);
        }
    }
    let policy_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
    if policy_version.unwrap_or(1) != record.policy_version {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationCreateOutcome::Stale);
    }
    let current_now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    if record.expires_at_ms <= current_now {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationCreateOutcome::Stale);
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workloads w JOIN nodes n ON n.id = w.node_id
        WHERE w.id = ? AND w.tenant_id = ? AND w.node_id = ? AND w.unit = ? AND w.account = ?
          AND w.consumption_mode = ? AND w.local_ceiling_seconds >= ? AND w.status = 'active'
          AND n.tenant_id = ? AND n.status = 'active')",
    )
    .bind(&record.workload_id)
    .bind(tenant_id)
    .bind(&record.node_id)
    .bind(expected_unit)
    .bind(expected_account)
    .bind(&record.mode)
    .bind(effective_ttl_seconds)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    if !active {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationCreateOutcome::Stale);
    }
    let approval_id = if let Some(draft) = approval {
        Some(create_or_extend_approval_sqlite(&mut tx, tenant_id, &record.id, draft).await?)
    } else {
        None
    };
    insert_operation_sqlite(&mut tx, tenant_id, record, approval_id.as_deref()).await?;
    let sql = format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE id = ? AND tenant_id = ?");
    let row = sqlx::query(&sql)
        .bind(&record.id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let created = operation_from_sqlite(&row)?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(OperationCreateOutcome::Created(created))
}

async fn create_operation_postgres(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    record: &OperationRecord,
    expected_unit: &str,
    expected_account: &str,
    effective_ttl_seconds: i64,
    approval: Option<&OperationApprovalDraft>,
) -> Result<OperationCreateOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let lookup = format!(
        "SELECT {OPERATION_COLUMNS} FROM operations WHERE tenant_id = $1 AND requested_by = $2 AND idempotency_key = $3"
    );
    if let Some(row) = sqlx::query(&lookup)
        .bind(tenant_id)
        .bind(&record.requested_by)
        .bind(&record.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
    {
        let existing = operation_from_postgres(&row)?;
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(if existing.request_hash == record.request_hash {
            OperationCreateOutcome::Existing(existing)
        } else {
            OperationCreateOutcome::Conflict
        });
    }
    if let Some(event_key) = record.broker_event_key.as_deref() {
        let used: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE tenant_id = $1 AND node_id = $2 AND broker_event_key = $3)",
        )
        .bind(tenant_id)
        .bind(&record.node_id)
        .bind(event_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if used {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationCreateOutcome::Conflict);
        }
    }
    let policy_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = $1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
    if policy_version.unwrap_or(1) != record.policy_version {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationCreateOutcome::Stale);
    }
    let current_now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    if record.expires_at_ms <= current_now {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationCreateOutcome::Stale);
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workloads w JOIN nodes n ON n.id = w.node_id
        WHERE w.id = $1 AND w.tenant_id = $2 AND w.node_id = $3 AND w.unit = $4 AND w.account = $5
          AND w.consumption_mode = $6 AND w.local_ceiling_seconds >= $7 AND w.status = 'active'
          AND n.tenant_id = $2 AND n.status = 'active')",
    )
    .bind(&record.workload_id)
    .bind(tenant_id)
    .bind(&record.node_id)
    .bind(expected_unit)
    .bind(expected_account)
    .bind(&record.mode)
    .bind(effective_ttl_seconds)
    .fetch_one(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    if !active {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationCreateOutcome::Stale);
    }
    let approval_id = if let Some(draft) = approval {
        Some(create_or_extend_approval_postgres(&mut tx, tenant_id, &record.id, draft).await?)
    } else {
        None
    };
    insert_operation_postgres(&mut tx, tenant_id, record, approval_id.as_deref()).await?;
    let sql =
        format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE id = $1 AND tenant_id = $2");
    let row = sqlx::query(&sql)
        .bind(&record.id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let created = operation_from_postgres(&row)?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(OperationCreateOutcome::Created(created))
}

async fn create_or_extend_approval_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: &str,
    operation_id: &str,
    draft: &OperationApprovalDraft,
) -> Result<String, StoreError> {
    let sql = format!(
        "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
        WHERE tenant_id = ? AND status = 'pending' AND rule_id = ?
          AND requester_summary_json = ? AND verified_identity_json = ?
          AND expires_at > {SQLITE_NOW_MS} ORDER BY created_at DESC, id DESC LIMIT 50"
    );
    let candidates = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(&draft.rule_id)
        .bind(&draft.requester_summary_json)
        .bind(&draft.verified_identity_json)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    for row in candidates {
        let candidate = operation_approval_from_sqlite(&row)?;
        let mut operation_ids: Vec<String> = serde_json::from_str(&candidate.operation_ids_json)
            .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
        if operation_ids.len() >= 10 || operation_ids.contains(&operation_id.to_owned()) {
            continue;
        }
        operation_ids.push(operation_id.to_owned());
        let encoded = serde_json::to_string(&operation_ids)
            .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
        let changed = sqlx::query(
            "UPDATE operation_approvals SET operation_ids_json = ?, version = version + 1
            WHERE id = ? AND tenant_id = ? AND status = 'pending' AND version = ?",
        )
        .bind(encoded)
        .bind(&candidate.id)
        .bind(tenant_id)
        .bind(candidate.version)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
        if changed.rows_affected() == 1 {
            return Ok(candidate.id);
        }
    }
    let operation_ids = serde_json::to_string(&vec![operation_id])
        .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
    let expires_at = draft.expires_at_ms;
    let sql = format!("INSERT INTO operation_approvals (id, tenant_id, operation_ids_json,
        requester_summary_json, verified_identity_json, rule_id, status, expires_at,
        idempotency_key, version, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, 1, {SQLITE_NOW_MS})");
    sqlx::query(&sql)
        .bind(&draft.id)
        .bind(tenant_id)
        .bind(operation_ids)
        .bind(&draft.requester_summary_json)
        .bind(&draft.verified_identity_json)
        .bind(&draft.rule_id)
        .bind(expires_at)
        .bind(&draft.idempotency_key)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    Ok(draft.id.clone())
}

async fn create_or_extend_approval_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    operation_id: &str,
    draft: &OperationApprovalDraft,
) -> Result<String, StoreError> {
    let sql = format!(
        "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
        WHERE tenant_id = $1 AND status = 'pending' AND rule_id = $2
          AND requester_summary_json = $3 AND verified_identity_json = $4
          AND expires_at > {POSTGRES_NOW_MS} ORDER BY created_at DESC, id DESC LIMIT 50 FOR UPDATE"
    );
    let candidates = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(&draft.rule_id)
        .bind(&draft.requester_summary_json)
        .bind(&draft.verified_identity_json)
        .fetch_all(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    for row in candidates {
        let candidate = operation_approval_from_postgres(&row)?;
        let mut operation_ids: Vec<String> = serde_json::from_str(&candidate.operation_ids_json)
            .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
        if operation_ids.len() >= 10 || operation_ids.contains(&operation_id.to_owned()) {
            continue;
        }
        operation_ids.push(operation_id.to_owned());
        let encoded = serde_json::to_string(&operation_ids)
            .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
        let changed = sqlx::query(
            "UPDATE operation_approvals SET operation_ids_json = $1, version = version + 1
            WHERE id = $2 AND tenant_id = $3 AND status = 'pending' AND version = $4",
        )
        .bind(encoded)
        .bind(&candidate.id)
        .bind(tenant_id)
        .bind(candidate.version)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
        if changed.rows_affected() == 1 {
            return Ok(candidate.id);
        }
    }
    let operation_ids = serde_json::to_string(&vec![operation_id])
        .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
    let sql = format!("INSERT INTO operation_approvals (id, tenant_id, operation_ids_json,
        requester_summary_json, verified_identity_json, rule_id, status, expires_at,
        idempotency_key, version, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, 1, {POSTGRES_NOW_MS})");
    sqlx::query(&sql)
        .bind(&draft.id)
        .bind(tenant_id)
        .bind(operation_ids)
        .bind(&draft.requester_summary_json)
        .bind(&draft.verified_identity_json)
        .bind(&draft.rule_id)
        .bind(draft.expires_at_ms)
        .bind(&draft.idempotency_key)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    Ok(draft.id.clone())
}

#[allow(clippy::too_many_arguments)] // Decision persistence names every CAS and audit binding.
async fn decide_operation_approval_sqlite(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    id: &str,
    expected_version: i64,
    expected_operation_ids: &[String],
    decision: &str,
    decided_by: &str,
    decision_key_hash: &str,
) -> Result<OperationDecisionOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let sql = format!(
        "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals WHERE id = ? AND tenant_id = ?"
    );
    let Some(row) = sqlx::query(&sql)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
    else {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::NotFound);
    };
    let approval = operation_approval_from_sqlite(&row)?;
    let target_status = if decision == "approved" {
        "approved"
    } else {
        "rejected"
    };
    let stored_ids: Vec<String> = serde_json::from_str(&approval.operation_ids_json)
        .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
    if approval.status == target_status
        && approval.version == expected_version.saturating_add(1)
        && approval.decided_by.as_deref() == Some(decided_by)
        && approval.decision_key_hash.as_deref() == Some(decision_key_hash)
        && stored_ids == expected_operation_ids
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::Replayed(approval));
    }
    if !matches!(decision, "approved" | "rejected")
        || approval.status != "pending"
        || approval.version != expected_version
        || stored_ids != expected_operation_ids
        || stored_ids.is_empty()
        || stored_ids.len() > 10
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::Conflict);
    }
    let now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    if approval.expires_at_ms <= now {
        sqlx::query("UPDATE operation_approvals SET status = 'expired', version = version + 1 WHERE id = ? AND tenant_id = ? AND status = 'pending'")
            .bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        sqlx::query("UPDATE operations SET status = 'denied', version = version + 1 WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'")
            .bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::StalePolicy);
    }
    let policy_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
    let current_policy = policy_version.unwrap_or(1);
    let mut stale = false;
    for operation_id in &stored_ids {
        let row = sqlx::query("SELECT o.policy_version, o.status, o.expires_at, w.status AS workload_status, n.status AS node_status
            FROM operations o JOIN workloads w ON w.id = o.workload_id JOIN nodes n ON n.id = o.node_id
            WHERE o.id = ? AND o.tenant_id = ? AND o.approval_id = ?")
            .bind(operation_id).bind(tenant_id).bind(id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
        let Some(row) = row else {
            stale = true;
            break;
        };
        let operation_policy: i64 = row
            .try_get("policy_version")
            .map_err(StoreError::Database)?;
        let operation_status: String = row.try_get("status").map_err(StoreError::Database)?;
        let operation_expiry: i64 = row.try_get("expires_at").map_err(StoreError::Database)?;
        let workload_status: String = row
            .try_get("workload_status")
            .map_err(StoreError::Database)?;
        let node_status: String = row.try_get("node_status").map_err(StoreError::Database)?;
        if operation_policy != current_policy
            || operation_status != "awaiting_approval"
            || operation_expiry <= now
            || workload_status != "active"
            || node_status != "active"
        {
            stale = true;
            break;
        }
    }
    if stale {
        sqlx::query(&format!("UPDATE operation_approvals SET status = 'expired', decided_by = ?, decided_at = {SQLITE_NOW_MS}, decision_key_hash = ?, version = version + 1 WHERE id = ? AND tenant_id = ? AND status = 'pending'"))
            .bind(decided_by).bind(decision_key_hash).bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        sqlx::query("UPDATE operations SET status = 'denied', version = version + 1 WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'")
            .bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::StalePolicy);
    }
    let operation_status = if decision == "approved" {
        "requested"
    } else {
        "denied"
    };
    sqlx::query(&format!("UPDATE operation_approvals SET status = ?, decided_by = ?, decided_at = {SQLITE_NOW_MS}, decision_key_hash = ?, version = version + 1 WHERE id = ? AND tenant_id = ? AND status = 'pending' AND version = ?"))
        .bind(target_status).bind(decided_by).bind(decision_key_hash).bind(id).bind(tenant_id).bind(expected_version)
        .execute(&mut *tx).await.map_err(StoreError::Database)?;
    sqlx::query(&format!("UPDATE operations SET status = ?,
        expires_at = CASE WHEN ? = 'requested' THEN {SQLITE_NOW_MS} + requested_ttl_seconds * 1000 ELSE expires_at END,
        version = version + 1 WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'"))
        .bind(operation_status).bind(operation_status).bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let updated = operation_approval_from_sqlite(&row)?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(OperationDecisionOutcome::Applied(updated))
}

#[allow(clippy::too_many_arguments)] // Decision persistence names every CAS and audit binding.
async fn decide_operation_approval_postgres(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    id: &str,
    expected_version: i64,
    expected_operation_ids: &[String],
    decision: &str,
    decided_by: &str,
    decision_key_hash: &str,
) -> Result<OperationDecisionOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let sql = format!(
        "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals WHERE id = $1 AND tenant_id = $2 FOR UPDATE"
    );
    let Some(row) = sqlx::query(&sql)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?
    else {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::NotFound);
    };
    let approval = operation_approval_from_postgres(&row)?;
    let target_status = if decision == "approved" {
        "approved"
    } else {
        "rejected"
    };
    let stored_ids: Vec<String> = serde_json::from_str(&approval.operation_ids_json)
        .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
    if approval.status == target_status
        && approval.version == expected_version.saturating_add(1)
        && approval.decided_by.as_deref() == Some(decided_by)
        && approval.decision_key_hash.as_deref() == Some(decision_key_hash)
        && stored_ids == expected_operation_ids
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::Replayed(approval));
    }
    if !matches!(decision, "approved" | "rejected")
        || approval.status != "pending"
        || approval.version != expected_version
        || stored_ids != expected_operation_ids
        || stored_ids.is_empty()
        || stored_ids.len() > 10
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::Conflict);
    }
    let now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    if approval.expires_at_ms <= now {
        sqlx::query("UPDATE operation_approvals SET status = 'expired', version = version + 1 WHERE id = $1 AND tenant_id = $2 AND status = 'pending'")
            .bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        sqlx::query("UPDATE operations SET status = 'denied', version = version + 1 WHERE approval_id = $1 AND tenant_id = $2 AND status = 'awaiting_approval'")
            .bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::StalePolicy);
    }
    let policy_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
    let current_policy = policy_version.unwrap_or(1);
    let mut stale = false;
    for operation_id in &stored_ids {
        let row = sqlx::query("SELECT o.policy_version, o.status, o.expires_at, w.status AS workload_status, n.status AS node_status
            FROM operations o JOIN workloads w ON w.id = o.workload_id JOIN nodes n ON n.id = o.node_id
            WHERE o.id = $1 AND o.tenant_id = $2 AND o.approval_id = $3 FOR UPDATE")
            .bind(operation_id).bind(tenant_id).bind(id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
        let Some(row) = row else {
            stale = true;
            break;
        };
        let operation_policy: i64 = row
            .try_get("policy_version")
            .map_err(StoreError::Database)?;
        let operation_status: String = row.try_get("status").map_err(StoreError::Database)?;
        let operation_expiry: i64 = row.try_get("expires_at").map_err(StoreError::Database)?;
        let workload_status: String = row
            .try_get("workload_status")
            .map_err(StoreError::Database)?;
        let node_status: String = row.try_get("node_status").map_err(StoreError::Database)?;
        if operation_policy != current_policy
            || operation_status != "awaiting_approval"
            || operation_expiry <= now
            || workload_status != "active"
            || node_status != "active"
        {
            stale = true;
            break;
        }
    }
    if stale {
        sqlx::query(&format!("UPDATE operation_approvals SET status = 'expired', decided_by = $1, decided_at = {POSTGRES_NOW_MS}, decision_key_hash = $2, version = version + 1 WHERE id = $3 AND tenant_id = $4 AND status = 'pending'"))
            .bind(decided_by).bind(decision_key_hash).bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        sqlx::query("UPDATE operations SET status = 'denied', version = version + 1 WHERE approval_id = $1 AND tenant_id = $2 AND status = 'awaiting_approval'")
            .bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(OperationDecisionOutcome::StalePolicy);
    }
    let operation_status = if decision == "approved" {
        "requested"
    } else {
        "denied"
    };
    sqlx::query(&format!("UPDATE operation_approvals SET status = $1, decided_by = $2, decided_at = {POSTGRES_NOW_MS}, decision_key_hash = $3, version = version + 1 WHERE id = $4 AND tenant_id = $5 AND status = 'pending' AND version = $6"))
        .bind(target_status).bind(decided_by).bind(decision_key_hash).bind(id).bind(tenant_id).bind(expected_version)
        .execute(&mut *tx).await.map_err(StoreError::Database)?;
    sqlx::query(&format!("UPDATE operations SET status = $1,
        expires_at = CASE WHEN $2 = 'requested' THEN {POSTGRES_NOW_MS} + requested_ttl_seconds * 1000 ELSE expires_at END,
        version = version + 1 WHERE approval_id = $3 AND tenant_id = $4 AND status = 'awaiting_approval'"))
        .bind(operation_status).bind(operation_status).bind(id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let updated = operation_approval_from_postgres(&row)?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(OperationDecisionOutcome::Applied(updated))
}

async fn insert_operation_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: &str,
    record: &OperationRecord,
    approval_id: Option<&str>,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO operations (id, tenant_id, workload_id, node_id, invocation_id,
        action, mode, resource_id, requested_ttl_seconds, broker_event_key,
        requested_by, purpose, policy_version, decision, decision_hash, status,
        approval_id, grant_id, idempotency_key, request_hash, result_json, created_at, expires_at,
        completed_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        {SQLITE_NOW_MS}, ?, NULL, 1)"
    );
    sqlx::query(&sql)
        .bind(&record.id)
        .bind(tenant_id)
        .bind(&record.workload_id)
        .bind(&record.node_id)
        .bind(&record.invocation_id)
        .bind(&record.action)
        .bind(&record.mode)
        .bind(&record.resource_id)
        .bind(record.requested_ttl_seconds)
        .bind(&record.broker_event_key)
        .bind(&record.requested_by)
        .bind(&record.purpose)
        .bind(record.policy_version)
        .bind(&record.decision)
        .bind(&record.decision_hash)
        .bind(&record.status)
        .bind(approval_id)
        .bind(&record.grant_id)
        .bind(&record.idempotency_key)
        .bind(&record.request_hash)
        .bind(&record.result_json)
        .bind(record.expires_at_ms)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

async fn insert_operation_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    record: &OperationRecord,
    approval_id: Option<&str>,
) -> Result<(), StoreError> {
    let sql = format!(
        "INSERT INTO operations (id, tenant_id, workload_id, node_id, invocation_id,
        action, mode, resource_id, requested_ttl_seconds, broker_event_key,
        requested_by, purpose, policy_version, decision, decision_hash, status,
        approval_id, grant_id, idempotency_key, request_hash, result_json, created_at, expires_at,
        completed_at, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
        $13, $14, $15, $16, $17, $18, $19, $20, $21, {POSTGRES_NOW_MS}, $22, NULL, 1)"
    );
    sqlx::query(&sql)
        .bind(&record.id)
        .bind(tenant_id)
        .bind(&record.workload_id)
        .bind(&record.node_id)
        .bind(&record.invocation_id)
        .bind(&record.action)
        .bind(&record.mode)
        .bind(&record.resource_id)
        .bind(record.requested_ttl_seconds)
        .bind(&record.broker_event_key)
        .bind(&record.requested_by)
        .bind(&record.purpose)
        .bind(record.policy_version)
        .bind(&record.decision)
        .bind(&record.decision_hash)
        .bind(&record.status)
        .bind(approval_id)
        .bind(&record.grant_id)
        .bind(&record.idempotency_key)
        .bind(&record.request_hash)
        .bind(&record.result_json)
        .bind(record.expires_at_ms)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

pub(super) fn operation_from_sqlite(row: &SqliteRow) -> Result<OperationRecord, StoreError> {
    Ok(OperationRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        workload_id: row.try_get("workload_id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        invocation_id: row.try_get("invocation_id").map_err(StoreError::Database)?,
        action: row.try_get("action").map_err(StoreError::Database)?,
        mode: row.try_get("mode").map_err(StoreError::Database)?,
        resource_id: row.try_get("resource_id").map_err(StoreError::Database)?,
        requested_ttl_seconds: row
            .try_get("requested_ttl_seconds")
            .map_err(StoreError::Database)?,
        broker_event_key: row
            .try_get("broker_event_key")
            .map_err(StoreError::Database)?,
        requested_by: row.try_get("requested_by").map_err(StoreError::Database)?,
        purpose: row.try_get("purpose").map_err(StoreError::Database)?,
        policy_version: row
            .try_get("policy_version")
            .map_err(StoreError::Database)?,
        decision: row.try_get("decision").map_err(StoreError::Database)?,
        decision_hash: row.try_get("decision_hash").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        approval_id: row.try_get("approval_id").map_err(StoreError::Database)?,
        grant_id: row.try_get("grant_id").map_err(StoreError::Database)?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?,
        request_hash: row.try_get("request_hash").map_err(StoreError::Database)?,
        result_json: row.try_get("result_json").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        completed_at_ms: row.try_get("completed_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

pub(super) fn operation_from_postgres(row: &PgRow) -> Result<OperationRecord, StoreError> {
    Ok(OperationRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        workload_id: row.try_get("workload_id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        invocation_id: row.try_get("invocation_id").map_err(StoreError::Database)?,
        action: row.try_get("action").map_err(StoreError::Database)?,
        mode: row.try_get("mode").map_err(StoreError::Database)?,
        resource_id: row.try_get("resource_id").map_err(StoreError::Database)?,
        requested_ttl_seconds: row
            .try_get("requested_ttl_seconds")
            .map_err(StoreError::Database)?,
        broker_event_key: row
            .try_get("broker_event_key")
            .map_err(StoreError::Database)?,
        requested_by: row.try_get("requested_by").map_err(StoreError::Database)?,
        purpose: row.try_get("purpose").map_err(StoreError::Database)?,
        policy_version: row
            .try_get("policy_version")
            .map_err(StoreError::Database)?,
        decision: row.try_get("decision").map_err(StoreError::Database)?,
        decision_hash: row.try_get("decision_hash").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        approval_id: row.try_get("approval_id").map_err(StoreError::Database)?,
        grant_id: row.try_get("grant_id").map_err(StoreError::Database)?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?,
        request_hash: row.try_get("request_hash").map_err(StoreError::Database)?,
        result_json: row.try_get("result_json").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        completed_at_ms: row.try_get("completed_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

fn operation_approval_from_sqlite(row: &SqliteRow) -> Result<OperationApprovalRecord, StoreError> {
    Ok(OperationApprovalRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        operation_ids_json: row
            .try_get("operation_ids_json")
            .map_err(StoreError::Database)?,
        requester_summary_json: row
            .try_get("requester_summary_json")
            .map_err(StoreError::Database)?,
        verified_identity_json: row
            .try_get("verified_identity_json")
            .map_err(StoreError::Database)?,
        rule_id: row.try_get("rule_id").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        decided_by: row.try_get("decided_by").map_err(StoreError::Database)?,
        decided_at_ms: row.try_get("decided_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?,
        decision_key_hash: row
            .try_get("decision_key_hash")
            .map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
    })
}

fn operation_approval_from_postgres(row: &PgRow) -> Result<OperationApprovalRecord, StoreError> {
    Ok(OperationApprovalRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        operation_ids_json: row
            .try_get("operation_ids_json")
            .map_err(StoreError::Database)?,
        requester_summary_json: row
            .try_get("requester_summary_json")
            .map_err(StoreError::Database)?,
        verified_identity_json: row
            .try_get("verified_identity_json")
            .map_err(StoreError::Database)?,
        rule_id: row.try_get("rule_id").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        decided_by: row.try_get("decided_by").map_err(StoreError::Database)?,
        decided_at_ms: row.try_get("decided_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        idempotency_key: row
            .try_get("idempotency_key")
            .map_err(StoreError::Database)?,
        decision_key_hash: row
            .try_get("decision_key_hash")
            .map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
    })
}

fn workload_from_sqlite(row: &SqliteRow) -> Result<WorkloadRecord, StoreError> {
    Ok(WorkloadRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        name: row.try_get("name").map_err(StoreError::Database)?,
        unit: row.try_get("unit").map_err(StoreError::Database)?,
        account: row.try_get("account").map_err(StoreError::Database)?,
        consumption_mode: row
            .try_get("consumption_mode")
            .map_err(StoreError::Database)?,
        local_ceiling_seconds: row
            .try_get("local_ceiling_seconds")
            .map_err(StoreError::Database)?,
        registration_version: row
            .try_get("registration_version")
            .map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        revoked_at_ms: row.try_get("revoked_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

fn workload_from_postgres(row: &PgRow) -> Result<WorkloadRecord, StoreError> {
    Ok(WorkloadRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        name: row.try_get("name").map_err(StoreError::Database)?,
        unit: row.try_get("unit").map_err(StoreError::Database)?,
        account: row.try_get("account").map_err(StoreError::Database)?,
        consumption_mode: row
            .try_get("consumption_mode")
            .map_err(StoreError::Database)?,
        local_ceiling_seconds: row
            .try_get("local_ceiling_seconds")
            .map_err(StoreError::Database)?,
        registration_version: row
            .try_get("registration_version")
            .map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        revoked_at_ms: row.try_get("revoked_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

fn fleet_policy_from_sqlite(row: &SqliteRow) -> Result<FleetPolicyRecord, StoreError> {
    Ok(FleetPolicyRecord {
        version: row.try_get("version").map_err(StoreError::Database)?,
        document_json: row.try_get("document_json").map_err(StoreError::Database)?,
        updated_at_ms: row.try_get("updated_at").map_err(StoreError::Database)?,
        updated_by: row.try_get("updated_by").map_err(StoreError::Database)?,
    })
}

fn fleet_policy_from_postgres(row: &PgRow) -> Result<FleetPolicyRecord, StoreError> {
    Ok(FleetPolicyRecord {
        version: row.try_get("version").map_err(StoreError::Database)?,
        document_json: row.try_get("document_json").map_err(StoreError::Database)?,
        updated_at_ms: row.try_get("updated_at").map_err(StoreError::Database)?,
        updated_by: row.try_get("updated_by").map_err(StoreError::Database)?,
    })
}

impl Store {
    pub async fn create_operation(
        &self,
        record: &OperationRecord,
        expected_unit: &str,
        expected_account: &str,
        effective_ttl_seconds: i64,
        approval: Option<&OperationApprovalDraft>,
    ) -> Result<OperationCreateOutcome, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                create_operation_sqlite(
                    pool,
                    &self.tenant_id,
                    record,
                    expected_unit,
                    expected_account,
                    effective_ttl_seconds,
                    approval,
                )
                .await
            }
            Database::Postgres(pool) => {
                create_operation_postgres(
                    pool,
                    &self.tenant_id,
                    record,
                    expected_unit,
                    expected_account,
                    effective_ttl_seconds,
                    approval,
                )
                .await
            }
        }
    }

    pub async fn operation_by_id(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT {OPERATION_COLUMNS} FROM operations WHERE id = ? AND tenant_id = ?"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(operation_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT {OPERATION_COLUMNS} FROM operations WHERE id = $1 AND tenant_id = $2"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(operation_from_postgres)
                    .transpose()
            }
        }
    }

    pub async fn list_operations(
        &self,
        status: Option<&str>,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 101));
        let status = status.unwrap_or("");
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE tenant_id = ?
                    AND (? = '' OR status = ?) AND (? IS NULL OR created_at > ? OR (created_at = ? AND id > ?))
                    ORDER BY created_at, id LIMIT ?");
                let rows = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(status)
                    .bind(status)
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.1.as_str()))
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(operation_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let sql = format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE tenant_id = $1
                    AND ($2 = '' OR status = $3) AND ($4::BIGINT IS NULL OR created_at > $5 OR (created_at = $6 AND id > $7))
                    ORDER BY created_at, id LIMIT $8");
                let rows = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(status)
                    .bind(status)
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.1.as_str()))
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(operation_from_postgres).collect()
            }
        }
    }

    pub async fn operation_approval_by_id(
        &self,
        id: &str,
    ) -> Result<Option<OperationApprovalRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals WHERE id = ? AND tenant_id = ?"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(operation_approval_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals WHERE id = $1 AND tenant_id = $2"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(operation_approval_from_postgres)
                    .transpose()
            }
        }
    }

    pub async fn list_operation_approvals(
        &self,
        status: Option<&str>,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<OperationApprovalRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 101));
        let status = status.unwrap_or("");
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!("SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
                    WHERE tenant_id = ? AND (? = '' OR status = ?) AND (? IS NULL OR created_at > ? OR (created_at = ? AND id > ?))
                    AND (status <> 'pending' OR expires_at > {SQLITE_NOW_MS}) ORDER BY created_at, id LIMIT ?");
                let rows = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(status)
                    .bind(status)
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.1.as_str()))
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(operation_approval_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let sql = format!("SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
                    WHERE tenant_id = $1 AND ($2 = '' OR status = $3) AND ($4::BIGINT IS NULL OR created_at > $5 OR (created_at = $6 AND id > $7))
                    AND (status <> 'pending' OR expires_at > {POSTGRES_NOW_MS}) ORDER BY created_at, id LIMIT $8");
                let rows = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(status)
                    .bind(status)
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.1.as_str()))
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(operation_approval_from_postgres).collect()
            }
        }
    }

    pub async fn count_pending_operation_approvals(&self) -> Result<i64, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT COUNT(*) FROM operation_approvals WHERE tenant_id = ? AND status = 'pending' AND expires_at > {SQLITE_NOW_MS}"
                );
                sqlx::query_scalar(&sql)
                    .bind(&self.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT COUNT(*) FROM operation_approvals WHERE tenant_id = $1 AND status = 'pending' AND expires_at > {POSTGRES_NOW_MS}"
                );
                sqlx::query_scalar(&sql)
                    .bind(&self.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)
            }
        }
    }

    pub async fn decide_operation_approval(
        &self,
        id: &str,
        expected_version: i64,
        expected_operation_ids: &[String],
        decision: &str,
        decided_by: &str,
        decision_key_hash: &str,
    ) -> Result<OperationDecisionOutcome, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                decide_operation_approval_sqlite(
                    pool,
                    &self.tenant_id,
                    id,
                    expected_version,
                    expected_operation_ids,
                    decision,
                    decided_by,
                    decision_key_hash,
                )
                .await
            }
            Database::Postgres(pool) => {
                decide_operation_approval_postgres(
                    pool,
                    &self.tenant_id,
                    id,
                    expected_version,
                    expected_operation_ids,
                    decision,
                    decided_by,
                    decision_key_hash,
                )
                .await
            }
        }
    }
}

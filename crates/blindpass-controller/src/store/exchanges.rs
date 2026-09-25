// SPDX-License-Identifier: AGPL-3.0-only

//! Durable exchange, approval, lifecycle, and metadata-only audit transitions.

use super::{
    Database, LockedRow, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError, lock_postgres_row,
    new_hex_id, positive_milliseconds,
};
use blindpass_core::custody::sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgRow;
use sqlx::sqlite::SqliteRow;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangePolicyRecord {
    pub mode: String,
    pub approval_required: bool,
    pub rule_id: String,
    pub reason: String,
    pub approval_reference: Option<String>,
    pub requester_ring: Option<String>,
    pub fulfiller_ring: Option<String>,
    pub secret_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangeRecord {
    pub exchange_id: String,
    pub requester_id: String,
    pub workspace_id: String,
    pub requester_public_key: String,
    pub secret_name: String,
    pub purpose: String,
    pub fulfiller_hint: String,
    pub allowed_fulfiller_id: Option<String>,
    pub fulfilled_by: Option<String>,
    pub policy: ExchangePolicyRecord,
    pub policy_hash: String,
    pub status: String,
    pub prior_exchange_id: Option<String>,
    pub supersedes_exchange_id: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub enc: Option<String>,
    pub ciphertext: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub approval_reference: String,
    pub requester_id: String,
    pub workspace_id: String,
    pub secret_name: String,
    pub purpose: String,
    pub fulfiller_hint: String,
    pub rule_id: Option<String>,
    pub reason: String,
    pub requester_ring: Option<String>,
    pub fulfiller_ring: Option<String>,
    pub approver_ids: Vec<String>,
    pub approver_rings: Vec<String>,
    pub status: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub decided_at_ms: Option<i64>,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleRecord {
    pub record_id: String,
    pub event_type: String,
    pub exchange_id: Option<String>,
    pub approval_reference: Option<String>,
    pub requester_id: String,
    pub workspace_id: String,
    pub secret_name: String,
    pub purpose: String,
    pub fulfiller_hint: Option<String>,
    pub actor_id: Option<String>,
    pub status: Option<String>,
    pub prior_status: Option<String>,
    pub reason: Option<String>,
    pub policy_rule_id: Option<String>,
    pub metadata: Option<Value>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    pub id: String,
    pub workspace_id: String,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub resource_id: Option<String>,
    pub metadata: Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecisionOutcome {
    Applied(ApprovalRecord),
    Replayed(ApprovalRecord),
    Conflict,
    NotFound,
}

impl Store {
    pub async fn create_exchange(
        &self,
        mut exchange: ExchangeRecord,
        ttl_seconds: u64,
    ) -> Result<ExchangeRecord, StoreError> {
        self.checkpoint_clock().await?;
        if exchange.exchange_id.len() != 64 || exchange.secret_name.is_empty() {
            return Err(StoreError::InvalidInput("exchange"));
        }
        let ttl_ms = positive_milliseconds(ttl_seconds, "exchange TTL")?;
        let policy_json = serde_json::to_string(&exchange.policy)
            .map_err(|_| StoreError::InvalidInput("exchange policy"))?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO exchanges
                     (id, tenant_id, requester_agent_id, requester_public_key, secret_name,
                      purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
                      policy_decision_json, policy_hash, status, prior_exchange_id,
                      supersedes_exchange_id, created_at, expires_at, enc, ciphertext)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, 'pending', ?, ?,
                             {SQLITE_NOW_MS}, {SQLITE_NOW_MS} + ?, NULL, NULL)"
                );
                sqlx::query(&sql)
                    .bind(&exchange.exchange_id)
                    .bind(&self.tenant_id)
                    .bind(&exchange.requester_id)
                    .bind(&exchange.requester_public_key)
                    .bind(&exchange.secret_name)
                    .bind(&exchange.purpose)
                    .bind(&exchange.fulfiller_hint)
                    .bind(&exchange.allowed_fulfiller_id)
                    .bind(policy_json)
                    .bind(&exchange.policy_hash)
                    .bind(&exchange.prior_exchange_id)
                    .bind(&exchange.supersedes_exchange_id)
                    .bind(ttl_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO exchanges
                     (id, tenant_id, requester_agent_id, requester_public_key, secret_name,
                      purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
                      policy_decision_json, policy_hash, status, prior_exchange_id,
                      supersedes_exchange_id, created_at, expires_at, enc, ciphertext)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10, 'pending',
                             $11, $12, {POSTGRES_NOW_MS}, {POSTGRES_NOW_MS} + $13::BIGINT, NULL, NULL)"
                );
                sqlx::query(&sql)
                    .bind(&exchange.exchange_id)
                    .bind(&self.tenant_id)
                    .bind(&exchange.requester_id)
                    .bind(&exchange.requester_public_key)
                    .bind(&exchange.secret_name)
                    .bind(&exchange.purpose)
                    .bind(&exchange.fulfiller_hint)
                    .bind(&exchange.allowed_fulfiller_id)
                    .bind(policy_json)
                    .bind(&exchange.policy_hash)
                    .bind(&exchange.prior_exchange_id)
                    .bind(&exchange.supersedes_exchange_id)
                    .bind(ttl_ms)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        exchange.created_at_ms = 0;
        exchange.expires_at_ms = 0;
        self.get_exchange(&exchange.exchange_id)
            .await?
            .ok_or(StoreError::MissingState("created exchange"))
    }

    pub async fn get_exchange(
        &self,
        exchange_id: &str,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT id, requester_agent_id, tenant_id, requester_public_key,
                     secret_name, purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
                     policy_decision_json, policy_hash, status, prior_exchange_id,
                     supersedes_exchange_id, created_at, expires_at, enc, ciphertext
                     FROM exchanges WHERE id = ? AND tenant_id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(exchange_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT id, requester_agent_id, tenant_id, requester_public_key,
                     secret_name, purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
                     policy_decision_json, policy_hash, status, prior_exchange_id,
                     supersedes_exchange_id, created_at, expires_at, enc, ciphertext
                     FROM exchanges WHERE id = $1 AND tenant_id = $2 AND expires_at > {POSTGRES_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(exchange_from_postgres).transpose()
            }
        }
    }

    pub async fn reserve_exchange(
        &self,
        exchange_id: &str,
        fulfiller_id: &str,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE exchanges SET status = 'reserved', fulfilled_by = ?
                     WHERE id = ? AND tenant_id = ? AND status = 'pending'
                       AND allowed_fulfiller_id = ? AND expires_at > {SQLITE_NOW_MS}
                     RETURNING id"
                );
                let row = sqlx::query(&sql)
                    .bind(fulfiller_id)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(fulfiller_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                if row.is_none() {
                    return Ok(None);
                }
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::Exchange,
                    exchange_id,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!(
                    "UPDATE exchanges SET status = 'reserved', fulfilled_by = $1
                     WHERE id = $2 AND tenant_id = $3 AND status = 'pending'
                       AND allowed_fulfiller_id = $1 AND expires_at > {POSTGRES_NOW_MS}
                     RETURNING id"
                );
                let row = sqlx::query(&sql)
                    .bind(fulfiller_id)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                if row.is_none() {
                    return Ok(None);
                }
            }
        }
        self.get_exchange(exchange_id).await
    }

    pub async fn submit_exchange(
        &self,
        exchange_id: &str,
        fulfiller_id: &str,
        enc: &str,
        ciphertext: &str,
        ttl_seconds: u64,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        if enc.is_empty() || ciphertext.is_empty() {
            return Err(StoreError::InvalidInput("exchange payload"));
        }
        let ttl_ms = positive_milliseconds(ttl_seconds, "submitted exchange TTL")?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE exchanges SET status = 'submitted', enc = ?, ciphertext = ?,
                         expires_at = {SQLITE_NOW_MS} + ?
                     WHERE id = ? AND tenant_id = ? AND status = 'reserved'
                       AND fulfilled_by = ? AND expires_at > {SQLITE_NOW_MS}
                     RETURNING id"
                );
                let row = sqlx::query(&sql)
                    .bind(enc)
                    .bind(ciphertext)
                    .bind(ttl_ms)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(fulfiller_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                if row.is_none() {
                    return Ok(None);
                }
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::Exchange,
                    exchange_id,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!(
                    "UPDATE exchanges SET status = 'submitted', enc = $1, ciphertext = $2,
                         expires_at = {POSTGRES_NOW_MS} + $3::BIGINT
                     WHERE id = $4 AND tenant_id = $5 AND status = 'reserved'
                       AND fulfilled_by = $6 AND expires_at > {POSTGRES_NOW_MS}
                     RETURNING id"
                );
                let row = sqlx::query(&sql)
                    .bind(enc)
                    .bind(ciphertext)
                    .bind(ttl_ms)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(fulfiller_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                if row.is_none() {
                    return Ok(None);
                }
            }
        }
        self.get_exchange(exchange_id).await
    }

    /// Atomically return and delete submitted ciphertext for its requester.
    pub async fn consume_exchange(
        &self,
        exchange_id: &str,
        requester_id: &str,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let row = match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                let sql = format!(
                    "DELETE FROM exchanges WHERE id = ? AND tenant_id = ?
                     AND requester_agent_id = ? AND status = 'submitted'
                     AND expires_at > {SQLITE_NOW_MS}
                     RETURNING id, requester_agent_id, tenant_id, requester_public_key,
                     secret_name, purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
                     policy_decision_json, policy_hash, status, prior_exchange_id,
                     supersedes_exchange_id, created_at, expires_at, enc, ciphertext"
                );
                let exchange = sqlx::query(&sql)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(requester_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(exchange_from_sqlite)
                    .transpose()?;
                if exchange.is_some() {
                    crate::p02_test_failpoint("exchange-retrieve-before-commit");
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                if exchange.is_some() {
                    crate::p02_test_failpoint("exchange-retrieve-after-commit");
                }
                exchange
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::Exchange,
                    exchange_id,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!(
                    "DELETE FROM exchanges WHERE id = $1 AND tenant_id = $2
                     AND requester_agent_id = $3 AND status = 'submitted'
                     AND expires_at > {POSTGRES_NOW_MS}
                     RETURNING id, requester_agent_id, tenant_id, requester_public_key,
                     secret_name, purpose, fulfiller_hint, allowed_fulfiller_id, fulfilled_by,
                     policy_decision_json, policy_hash, status, prior_exchange_id,
                     supersedes_exchange_id, created_at, expires_at, enc, ciphertext"
                );
                let exchange = sqlx::query(&sql)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(requester_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(exchange_from_postgres)
                    .transpose()?;
                if exchange.is_some() {
                    crate::p02_test_failpoint("exchange-retrieve-before-commit");
                }
                transaction.commit().await.map_err(StoreError::Database)?;
                if exchange.is_some() {
                    crate::p02_test_failpoint("exchange-retrieve-after-commit");
                }
                exchange
            }
        };
        Ok(row)
    }

    pub async fn revoke_exchange(
        &self,
        exchange_id: &str,
        requester_id: Option<&str>,
        revoked_ttl_seconds: u64,
    ) -> Result<Option<ExchangeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let ttl_ms = positive_milliseconds(revoked_ttl_seconds, "revoked exchange TTL")?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE exchanges SET status = 'revoked', enc = NULL, ciphertext = NULL,
                         expires_at = CASE WHEN status = 'revoked' THEN expires_at ELSE {SQLITE_NOW_MS} + ? END
                     WHERE id = ? AND tenant_id = ? AND status IN ('pending', 'reserved', 'submitted', 'revoked')
                       AND expires_at > {SQLITE_NOW_MS}
                       AND (? IS NULL OR requester_agent_id = ?)
                     RETURNING id"
                );
                let result = sqlx::query(&sql)
                    .bind(ttl_ms)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(requester_id)
                    .bind(requester_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                if result.is_none() {
                    return Ok(None);
                }
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::Exchange,
                    exchange_id,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!(
                    "UPDATE exchanges SET status = 'revoked', enc = NULL, ciphertext = NULL,
                         expires_at = CASE WHEN status = 'revoked' THEN expires_at ELSE {POSTGRES_NOW_MS} + $1::BIGINT END
                     WHERE id = $2 AND tenant_id = $3 AND status IN ('pending', 'reserved', 'submitted', 'revoked')
                       AND expires_at > {POSTGRES_NOW_MS}
                       AND ($4::TEXT IS NULL OR requester_agent_id = $4)
                     RETURNING id"
                );
                let result = sqlx::query(&sql)
                    .bind(ttl_ms)
                    .bind(exchange_id)
                    .bind(&self.tenant_id)
                    .bind(requester_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                if result.is_none() {
                    return Ok(None);
                }
            }
        }
        self.get_exchange(exchange_id).await
    }

    pub async fn create_approval(&self, approval: &ApprovalRecord) -> Result<(), StoreError> {
        self.checkpoint_clock().await?;
        let approver_ids = serde_json::to_string(&approval.approver_ids)
            .map_err(|_| StoreError::InvalidInput("approver ids"))?;
        let approver_rings = serde_json::to_string(&approval.approver_rings)
            .map_err(|_| StoreError::InvalidInput("approver rings"))?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO approvals (reference, tenant_id, requester_agent_id, secret_name,
                     purpose, fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                     approver_ids_json, approver_rings_json, status, created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending',
                     {SQLITE_NOW_MS}, {SQLITE_NOW_MS} + ?) ON CONFLICT(reference) DO NOTHING"
                );
                sqlx::query(&sql)
                    .bind(&approval.approval_reference)
                    .bind(&self.tenant_id)
                    .bind(&approval.requester_id)
                    .bind(&approval.secret_name)
                    .bind(&approval.purpose)
                    .bind(&approval.fulfiller_hint)
                    .bind(&approval.rule_id)
                    .bind(&approval.reason)
                    .bind(&approval.requester_ring)
                    .bind(&approval.fulfiller_ring)
                    .bind(approver_ids)
                    .bind(approver_rings)
                    .bind((approval.expires_at_ms - approval.created_at_ms).max(1))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO approvals (reference, tenant_id, requester_agent_id, secret_name,
                     purpose, fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                     approver_ids_json, approver_rings_json, status, created_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending',
                     {POSTGRES_NOW_MS}, {POSTGRES_NOW_MS} + $13::BIGINT)
                     ON CONFLICT(reference) DO NOTHING"
                );
                sqlx::query(&sql)
                    .bind(&approval.approval_reference)
                    .bind(&self.tenant_id)
                    .bind(&approval.requester_id)
                    .bind(&approval.secret_name)
                    .bind(&approval.purpose)
                    .bind(&approval.fulfiller_hint)
                    .bind(&approval.rule_id)
                    .bind(&approval.reason)
                    .bind(&approval.requester_ring)
                    .bind(&approval.fulfiller_ring)
                    .bind(approver_ids)
                    .bind(approver_rings)
                    .bind((approval.expires_at_ms - approval.created_at_ms).max(1))
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        Ok(())
    }

    pub async fn get_approval(
        &self,
        reference: &str,
    ) -> Result<Option<ApprovalRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT reference, requester_agent_id, tenant_id, secret_name,
                    purpose, fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                    approver_ids_json, approver_rings_json, status, created_at, expires_at,
                    decided_at, decided_by FROM approvals WHERE reference = ? AND tenant_id = ?
                    AND expires_at > {SQLITE_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(reference)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(approval_from_sqlite).transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT reference, requester_agent_id, tenant_id, secret_name,
                    purpose, fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                    approver_ids_json, approver_rings_json, status, created_at, expires_at,
                    decided_at, decided_by FROM approvals WHERE reference = $1 AND tenant_id = $2
                    AND expires_at > {POSTGRES_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(reference)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.as_ref().map(approval_from_postgres).transpose()
            }
        }
    }

    pub async fn list_approvals(
        &self,
        status: Option<&str>,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<ApprovalRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 101));
        let status = status.unwrap_or("");
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!("SELECT reference, requester_agent_id, tenant_id, secret_name, purpose,
                    fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                    approver_ids_json, approver_rings_json, status, created_at, expires_at, decided_at, decided_by
                    FROM approvals WHERE tenant_id = ? AND (? = '' OR status = ?)
                    AND (? IS NULL OR created_at > ? OR (created_at = ? AND reference > ?))
                    AND (status <> 'pending' OR expires_at > {SQLITE_NOW_MS})
                    ORDER BY created_at, reference LIMIT ?");
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
                rows.iter().map(approval_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let sql = format!("SELECT reference, requester_agent_id, tenant_id, secret_name, purpose,
                    fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                    approver_ids_json, approver_rings_json, status, created_at, expires_at, decided_at, decided_by
                    FROM approvals WHERE tenant_id = $1 AND ($2 = '' OR status = $3)
                    AND ($4::BIGINT IS NULL OR created_at > $5 OR (created_at = $6 AND reference > $7))
                    AND (status <> 'pending' OR expires_at > {POSTGRES_NOW_MS})
                    ORDER BY created_at, reference LIMIT $8");
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
                rows.iter().map(approval_from_postgres).collect()
            }
        }
    }

    pub async fn count_pending_approvals(&self) -> Result<i64, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT COUNT(*) FROM approvals WHERE tenant_id = ?
                    AND status = 'pending' AND expires_at > {SQLITE_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.try_get(0).map_err(StoreError::Database)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT COUNT(*) FROM approvals WHERE tenant_id = $1
                    AND status = 'pending' AND expires_at > {POSTGRES_NOW_MS}"
                );
                let row = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)?;
                row.try_get(0).map_err(StoreError::Database)
            }
        }
    }

    pub async fn list_exchange_lifecycle(
        &self,
        exchange_id: &str,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 200));
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = "SELECT id, tenant_id, event, actor_id, metadata_json, created_at
                    FROM exchange_lifecycle WHERE tenant_id = ? AND exchange_id = ?
                    ORDER BY created_at, id LIMIT ?";
                let rows = sqlx::query(sql)
                    .bind(&self.tenant_id)
                    .bind(exchange_id)
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter()
                    .map(|row| {
                        let metadata: String = row.try_get(4).map_err(StoreError::Database)?;
                        Ok(AuditRecord {
                            id: row.try_get(0).map_err(StoreError::Database)?,
                            workspace_id: row.try_get(1).map_err(StoreError::Database)?,
                            event_type: row.try_get(2).map_err(StoreError::Database)?,
                            actor_id: row.try_get(3).map_err(StoreError::Database)?,
                            actor_type: "local".to_owned(),
                            resource_id: Some(exchange_id.to_owned()),
                            metadata: serde_json::from_str(&metadata).unwrap_or(Value::Null),
                            created_at_ms: row.try_get(5).map_err(StoreError::Database)?,
                        })
                    })
                    .collect()
            }
            Database::Postgres(pool) => {
                let sql = "SELECT id, tenant_id, event, actor_id, metadata_json, created_at
                    FROM exchange_lifecycle WHERE tenant_id = $1 AND exchange_id = $2
                    ORDER BY created_at, id LIMIT $3";
                let rows = sqlx::query(sql)
                    .bind(&self.tenant_id)
                    .bind(exchange_id)
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter()
                    .map(|row| {
                        let metadata: String = row.try_get(4).map_err(StoreError::Database)?;
                        Ok(AuditRecord {
                            id: row.try_get(0).map_err(StoreError::Database)?,
                            workspace_id: row.try_get(1).map_err(StoreError::Database)?,
                            event_type: row.try_get(2).map_err(StoreError::Database)?,
                            actor_id: row.try_get(3).map_err(StoreError::Database)?,
                            actor_type: "local".to_owned(),
                            resource_id: Some(exchange_id.to_owned()),
                            metadata: serde_json::from_str(&metadata).unwrap_or(Value::Null),
                            created_at_ms: row.try_get(5).map_err(StoreError::Database)?,
                        })
                    })
                    .collect()
            }
        }
    }

    pub async fn decide_approval_idempotent(
        &self,
        reference: &str,
        status: &str,
        actor_id: &str,
        idempotency_key_hash: &str,
    ) -> Result<ApprovalDecisionOutcome, StoreError> {
        self.checkpoint_clock().await?;
        if !matches!(status, "approved" | "rejected") || idempotency_key_hash.is_empty() {
            return Err(StoreError::InvalidInput("approval decision"));
        }
        let request_hash = sha256(format!("{reference}\0{status}").as_bytes())
            .map(|digest| {
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .map_err(|_| StoreError::MissingState("approval request hash"))?;
        let metadata_json = serde_json::json!({
            "decision": status,
            "idempotency_key_hash": idempotency_key_hash
        })
        .to_string();
        let audit_id = new_hex_id();

        match &self.database {
            Database::Sqlite(pool) => {
                // Acquire the writer lock before the idempotency read so two
                // decisions cannot race against the same SQLite snapshot.
                let mut transaction = pool
                    .begin_with("BEGIN IMMEDIATE")
                    .await
                    .map_err(StoreError::Database)?;
                let existing_sql = format!(
                    "SELECT request_hash, response_json FROM idempotency_keys
                    WHERE tenant_id = ? AND actor_id = ? AND operation = 'approval_decision'
                    AND key_hash = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                if let Some(existing) = sqlx::query(&existing_sql)
                    .bind(&self.tenant_id)
                    .bind(actor_id)
                    .bind(idempotency_key_hash)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                {
                    let prior_hash: String = existing.try_get(0).map_err(StoreError::Database)?;
                    if prior_hash != request_hash {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(ApprovalDecisionOutcome::Conflict);
                    }
                    let response: String = existing.try_get(1).map_err(StoreError::Database)?;
                    let record = serde_json::from_str(&response)
                        .map_err(|_| StoreError::MissingState("approval idempotency response"))?;
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(ApprovalDecisionOutcome::Replayed(record));
                }
                let update = format!("UPDATE approvals SET status = ?, decided_at = {SQLITE_NOW_MS}, decided_by = ?
                    WHERE reference = ? AND tenant_id = ? AND status = 'pending' AND expires_at > {SQLITE_NOW_MS}
                    RETURNING reference, requester_agent_id, tenant_id, secret_name, purpose,
                    fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                    approver_ids_json, approver_rings_json, status, created_at, expires_at, decided_at, decided_by");
                let row = sqlx::query(&update)
                    .bind(status)
                    .bind(actor_id)
                    .bind(reference)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    if let Some(existing) = sqlx::query(&existing_sql)
                        .bind(&self.tenant_id)
                        .bind(actor_id)
                        .bind(idempotency_key_hash)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                    {
                        let prior_hash: String =
                            existing.try_get(0).map_err(StoreError::Database)?;
                        if prior_hash == request_hash {
                            let response: String =
                                existing.try_get(1).map_err(StoreError::Database)?;
                            let record = serde_json::from_str(&response).map_err(|_| {
                                StoreError::MissingState("approval idempotency response")
                            })?;
                            transaction.commit().await.map_err(StoreError::Database)?;
                            return Ok(ApprovalDecisionOutcome::Replayed(record));
                        }
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(ApprovalDecisionOutcome::Conflict);
                    }
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(ApprovalDecisionOutcome::NotFound);
                };
                let record = approval_from_sqlite(&row)?;
                let response_json = serde_json::to_string(&record)
                    .map_err(|_| StoreError::InvalidInput("approval response"))?;
                let insert_key = format!("INSERT INTO idempotency_keys
                    (tenant_id, actor_id, operation, key_hash, request_hash, response_json, created_at, expires_at)
                    VALUES (?, ?, 'approval_decision', ?, ?, ?, {SQLITE_NOW_MS}, {SQLITE_NOW_MS} + 86400000)");
                sqlx::query(&insert_key)
                    .bind(&self.tenant_id)
                    .bind(actor_id)
                    .bind(idempotency_key_hash)
                    .bind(&request_hash)
                    .bind(response_json)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let insert_audit = format!("INSERT INTO audit_events
                    (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES (?, ?, 'operator', ?, 'approval_decided', 'approval', ?, ?, {SQLITE_NOW_MS})");
                sqlx::query(&insert_audit)
                    .bind(audit_id)
                    .bind(&self.tenant_id)
                    .bind(actor_id)
                    .bind(reference)
                    .bind(metadata_json)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                crate::p02_test_failpoint("approval-after-audit-before-commit");
                transaction.commit().await.map_err(StoreError::Database)?;
                crate::p02_test_failpoint("approval-after-commit");
                Ok(ApprovalDecisionOutcome::Applied(record))
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::Approval,
                    reference,
                    &self.tenant_id,
                )
                .await?;
                let existing_sql = format!(
                    "SELECT request_hash, response_json FROM idempotency_keys
                    WHERE tenant_id = $1 AND actor_id = $2 AND operation = 'approval_decision'
                    AND key_hash = $3 AND expires_at > {POSTGRES_NOW_MS}"
                );
                if let Some(existing) = sqlx::query(&existing_sql)
                    .bind(&self.tenant_id)
                    .bind(actor_id)
                    .bind(idempotency_key_hash)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?
                {
                    let prior_hash: String = existing.try_get(0).map_err(StoreError::Database)?;
                    if prior_hash != request_hash {
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(ApprovalDecisionOutcome::Conflict);
                    }
                    let response: String = existing.try_get(1).map_err(StoreError::Database)?;
                    let record = serde_json::from_str(&response)
                        .map_err(|_| StoreError::MissingState("approval idempotency response"))?;
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(ApprovalDecisionOutcome::Replayed(record));
                }
                let update = format!("UPDATE approvals SET status = $1, decided_at = {POSTGRES_NOW_MS}, decided_by = $2
                    WHERE reference = $3 AND tenant_id = $4 AND status = 'pending' AND expires_at > {POSTGRES_NOW_MS}
                    RETURNING reference, requester_agent_id, tenant_id, secret_name, purpose,
                    fulfiller_hint, rule_id, reason, requester_ring, fulfiller_ring,
                    approver_ids_json, approver_rings_json, status, created_at, expires_at, decided_at, decided_by");
                let row = sqlx::query(&update)
                    .bind(status)
                    .bind(actor_id)
                    .bind(reference)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    if let Some(existing) = sqlx::query(&existing_sql)
                        .bind(&self.tenant_id)
                        .bind(actor_id)
                        .bind(idempotency_key_hash)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Database)?
                    {
                        let prior_hash: String =
                            existing.try_get(0).map_err(StoreError::Database)?;
                        if prior_hash == request_hash {
                            let response: String =
                                existing.try_get(1).map_err(StoreError::Database)?;
                            let record = serde_json::from_str(&response).map_err(|_| {
                                StoreError::MissingState("approval idempotency response")
                            })?;
                            transaction.commit().await.map_err(StoreError::Database)?;
                            return Ok(ApprovalDecisionOutcome::Replayed(record));
                        }
                        transaction.commit().await.map_err(StoreError::Database)?;
                        return Ok(ApprovalDecisionOutcome::Conflict);
                    }
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(ApprovalDecisionOutcome::NotFound);
                };
                let record = approval_from_postgres(&row)?;
                let response_json = serde_json::to_string(&record)
                    .map_err(|_| StoreError::InvalidInput("approval response"))?;
                let insert_key = format!("INSERT INTO idempotency_keys
                    (tenant_id, actor_id, operation, key_hash, request_hash, response_json, created_at, expires_at)
                    VALUES ($1, $2, 'approval_decision', $3, $4, $5, {POSTGRES_NOW_MS}, {POSTGRES_NOW_MS} + 86400000)");
                sqlx::query(&insert_key)
                    .bind(&self.tenant_id)
                    .bind(actor_id)
                    .bind(idempotency_key_hash)
                    .bind(&request_hash)
                    .bind(response_json)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let insert_audit = format!("INSERT INTO audit_events
                    (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES ($1, $2, 'operator', $3, 'approval_decided', 'approval', $4, $5, {POSTGRES_NOW_MS})");
                sqlx::query(&insert_audit)
                    .bind(audit_id)
                    .bind(&self.tenant_id)
                    .bind(actor_id)
                    .bind(reference)
                    .bind(metadata_json)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                crate::p02_test_failpoint("approval-after-audit-before-commit");
                transaction.commit().await.map_err(StoreError::Database)?;
                crate::p02_test_failpoint("approval-after-commit");
                Ok(ApprovalDecisionOutcome::Applied(record))
            }
        }
    }

    pub async fn decide_approval(
        &self,
        reference: &str,
        status: &str,
        decided_by: &str,
    ) -> Result<Option<ApprovalRecord>, StoreError> {
        self.checkpoint_clock().await?;
        if status != "approved" && status != "rejected" {
            return Err(StoreError::InvalidInput("approval status"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE approvals SET status = ?, decided_at = {SQLITE_NOW_MS}, decided_by = ?
                    WHERE reference = ? AND tenant_id = ? AND status = 'pending'
                    AND expires_at > {SQLITE_NOW_MS} RETURNING reference"
                );
                let row = sqlx::query(&sql)
                    .bind(status)
                    .bind(decided_by)
                    .bind(reference)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?;
                if row.is_none() {
                    return Ok(None);
                }
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                lock_postgres_row(
                    &mut transaction,
                    LockedRow::Approval,
                    reference,
                    &self.tenant_id,
                )
                .await?;
                let sql = format!("UPDATE approvals SET status = $1, decided_at = {POSTGRES_NOW_MS}, decided_by = $2
                    WHERE reference = $3 AND tenant_id = $4 AND status = 'pending'
                    AND expires_at > {POSTGRES_NOW_MS} RETURNING reference");
                let row = sqlx::query(&sql)
                    .bind(status)
                    .bind(decided_by)
                    .bind(reference)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                transaction.commit().await.map_err(StoreError::Database)?;
                if row.is_none() {
                    return Ok(None);
                }
            }
        }
        self.get_approval(reference).await
    }

    pub async fn append_lifecycle(&self, record: &LifecycleRecord) -> Result<(), StoreError> {
        self.checkpoint_clock().await?;
        let metadata = serde_json::to_string(&record.metadata)
            .map_err(|_| StoreError::InvalidInput("lifecycle metadata"))?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO exchange_lifecycle
                    (id, tenant_id, exchange_id, event, actor_id, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, {SQLITE_NOW_MS})"
                );
                sqlx::query(&sql)
                    .bind(&record.record_id)
                    .bind(&self.tenant_id)
                    .bind(&record.exchange_id)
                    .bind(&record.event_type)
                    .bind(&record.actor_id)
                    .bind(metadata)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO exchange_lifecycle
                    (id, tenant_id, exchange_id, event, actor_id, metadata_json, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, {POSTGRES_NOW_MS})"
                );
                sqlx::query(&sql)
                    .bind(&record.record_id)
                    .bind(&self.tenant_id)
                    .bind(&record.exchange_id)
                    .bind(&record.event_type)
                    .bind(&record.actor_id)
                    .bind(metadata)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        Ok(())
    }

    pub async fn append_audit(
        &self,
        event_type: &str,
        actor_type: &str,
        actor_id: Option<&str>,
        target_type: &str,
        target_id: Option<&str>,
        metadata: &Value,
    ) -> Result<(), StoreError> {
        self.checkpoint_clock().await?;
        let id = new_hex_id();
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|_| StoreError::InvalidInput("audit metadata"))?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!("INSERT INTO audit_events
                    (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, {SQLITE_NOW_MS})");
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(actor_type)
                    .bind(actor_id)
                    .bind(event_type)
                    .bind(target_type)
                    .bind(target_id)
                    .bind(metadata_json)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!("INSERT INTO audit_events
                    (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, {POSTGRES_NOW_MS})");
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(actor_type)
                    .bind(actor_id)
                    .bind(event_type)
                    .bind(target_type)
                    .bind(target_id)
                    .bind(metadata_json)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
        }
        Ok(())
    }

    pub async fn list_audit(&self, limit: u32) -> Result<Vec<AuditRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 200));
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = "SELECT id, tenant_id, action, actor_id, actor_type, target_id,
                    metadata_json, created_at FROM audit_events WHERE tenant_id = ?
                    ORDER BY created_at DESC, id DESC LIMIT ?";
                let rows = sqlx::query(sql)
                    .bind(&self.tenant_id)
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(audit_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let sql = "SELECT id, tenant_id, action, actor_id, actor_type, target_id,
                    metadata_json, created_at FROM audit_events WHERE tenant_id = $1
                    ORDER BY created_at DESC, id DESC LIMIT $2";
                let rows = sqlx::query(sql)
                    .bind(&self.tenant_id)
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(audit_from_postgres).collect()
            }
        }
    }

    pub async fn list_audit_after_cursor(
        &self,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 101));
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = "SELECT id, tenant_id, action, actor_id, actor_type, target_id,
                    metadata_json, created_at FROM audit_events WHERE tenant_id = ?
                    AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
                    ORDER BY created_at DESC, id DESC LIMIT ?";
                let rows = sqlx::query(sql)
                    .bind(&self.tenant_id)
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.1.as_str()))
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(audit_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let sql = "SELECT id, tenant_id, action, actor_id, actor_type, target_id,
                    metadata_json, created_at FROM audit_events WHERE tenant_id = $1
                    AND ($2::BIGINT IS NULL OR created_at < $3 OR (created_at = $4 AND id < $5))
                    ORDER BY created_at DESC, id DESC LIMIT $6";
                let rows = sqlx::query(sql)
                    .bind(&self.tenant_id)
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.0))
                    .bind(cursor.as_ref().map(|value| value.1.as_str()))
                    .bind(limit)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Database)?;
                rows.iter().map(audit_from_postgres).collect()
            }
        }
    }
}

fn exchange_from_sqlite(row: &SqliteRow) -> Result<ExchangeRecord, StoreError> {
    let policy_json: String = row.try_get(9).map_err(StoreError::Database)?;
    Ok(ExchangeRecord {
        exchange_id: row.try_get(0).map_err(StoreError::Database)?,
        requester_id: row.try_get(1).map_err(StoreError::Database)?,
        workspace_id: row.try_get(2).map_err(StoreError::Database)?,
        requester_public_key: row.try_get(3).map_err(StoreError::Database)?,
        secret_name: row.try_get(4).map_err(StoreError::Database)?,
        purpose: row.try_get(5).map_err(StoreError::Database)?,
        fulfiller_hint: row.try_get(6).map_err(StoreError::Database)?,
        allowed_fulfiller_id: row.try_get(7).map_err(StoreError::Database)?,
        fulfilled_by: row.try_get(8).map_err(StoreError::Database)?,
        policy: serde_json::from_str(&policy_json)
            .map_err(|_| StoreError::MissingState("exchange policy"))?,
        policy_hash: row.try_get(10).map_err(StoreError::Database)?,
        status: row.try_get(11).map_err(StoreError::Database)?,
        prior_exchange_id: row.try_get(12).map_err(StoreError::Database)?,
        supersedes_exchange_id: row.try_get(13).map_err(StoreError::Database)?,
        created_at_ms: row.try_get(14).map_err(StoreError::Database)?,
        expires_at_ms: row.try_get(15).map_err(StoreError::Database)?,
        enc: row.try_get(16).map_err(StoreError::Database)?,
        ciphertext: row.try_get(17).map_err(StoreError::Database)?,
    })
}

fn exchange_from_postgres(row: &PgRow) -> Result<ExchangeRecord, StoreError> {
    let policy_json: String = row.try_get(9).map_err(StoreError::Database)?;
    Ok(ExchangeRecord {
        exchange_id: row.try_get(0).map_err(StoreError::Database)?,
        requester_id: row.try_get(1).map_err(StoreError::Database)?,
        workspace_id: row.try_get(2).map_err(StoreError::Database)?,
        requester_public_key: row.try_get(3).map_err(StoreError::Database)?,
        secret_name: row.try_get(4).map_err(StoreError::Database)?,
        purpose: row.try_get(5).map_err(StoreError::Database)?,
        fulfiller_hint: row.try_get(6).map_err(StoreError::Database)?,
        allowed_fulfiller_id: row.try_get(7).map_err(StoreError::Database)?,
        fulfilled_by: row.try_get(8).map_err(StoreError::Database)?,
        policy: serde_json::from_str(&policy_json)
            .map_err(|_| StoreError::MissingState("exchange policy"))?,
        policy_hash: row.try_get(10).map_err(StoreError::Database)?,
        status: row.try_get(11).map_err(StoreError::Database)?,
        prior_exchange_id: row.try_get(12).map_err(StoreError::Database)?,
        supersedes_exchange_id: row.try_get(13).map_err(StoreError::Database)?,
        created_at_ms: row.try_get(14).map_err(StoreError::Database)?,
        expires_at_ms: row.try_get(15).map_err(StoreError::Database)?,
        enc: row.try_get(16).map_err(StoreError::Database)?,
        ciphertext: row.try_get(17).map_err(StoreError::Database)?,
    })
}

fn approval_from_sqlite(row: &SqliteRow) -> Result<ApprovalRecord, StoreError> {
    let ids: String = row.try_get(10).map_err(StoreError::Database)?;
    let rings: String = row.try_get(11).map_err(StoreError::Database)?;
    Ok(ApprovalRecord {
        approval_reference: row.try_get(0).map_err(StoreError::Database)?,
        requester_id: row.try_get(1).map_err(StoreError::Database)?,
        workspace_id: row.try_get(2).map_err(StoreError::Database)?,
        secret_name: row.try_get(3).map_err(StoreError::Database)?,
        purpose: row.try_get(4).map_err(StoreError::Database)?,
        fulfiller_hint: row.try_get(5).map_err(StoreError::Database)?,
        rule_id: row.try_get(6).map_err(StoreError::Database)?,
        reason: row.try_get(7).map_err(StoreError::Database)?,
        requester_ring: row.try_get(8).map_err(StoreError::Database)?,
        fulfiller_ring: row.try_get(9).map_err(StoreError::Database)?,
        approver_ids: serde_json::from_str(&ids).unwrap_or_default(),
        approver_rings: serde_json::from_str(&rings).unwrap_or_default(),
        status: row.try_get(12).map_err(StoreError::Database)?,
        created_at_ms: row.try_get(13).map_err(StoreError::Database)?,
        expires_at_ms: row.try_get(14).map_err(StoreError::Database)?,
        decided_at_ms: row.try_get(15).map_err(StoreError::Database)?,
        decided_by: row.try_get(16).map_err(StoreError::Database)?,
    })
}

fn approval_from_postgres(row: &PgRow) -> Result<ApprovalRecord, StoreError> {
    let ids: String = row.try_get(10).map_err(StoreError::Database)?;
    let rings: String = row.try_get(11).map_err(StoreError::Database)?;
    Ok(ApprovalRecord {
        approval_reference: row.try_get(0).map_err(StoreError::Database)?,
        requester_id: row.try_get(1).map_err(StoreError::Database)?,
        workspace_id: row.try_get(2).map_err(StoreError::Database)?,
        secret_name: row.try_get(3).map_err(StoreError::Database)?,
        purpose: row.try_get(4).map_err(StoreError::Database)?,
        fulfiller_hint: row.try_get(5).map_err(StoreError::Database)?,
        rule_id: row.try_get(6).map_err(StoreError::Database)?,
        reason: row.try_get(7).map_err(StoreError::Database)?,
        requester_ring: row.try_get(8).map_err(StoreError::Database)?,
        fulfiller_ring: row.try_get(9).map_err(StoreError::Database)?,
        approver_ids: serde_json::from_str(&ids).unwrap_or_default(),
        approver_rings: serde_json::from_str(&rings).unwrap_or_default(),
        status: row.try_get(12).map_err(StoreError::Database)?,
        created_at_ms: row.try_get(13).map_err(StoreError::Database)?,
        expires_at_ms: row.try_get(14).map_err(StoreError::Database)?,
        decided_at_ms: row.try_get(15).map_err(StoreError::Database)?,
        decided_by: row.try_get(16).map_err(StoreError::Database)?,
    })
}

fn audit_from_sqlite(row: &SqliteRow) -> Result<AuditRecord, StoreError> {
    let metadata: String = row.try_get(6).map_err(StoreError::Database)?;
    Ok(AuditRecord {
        id: row.try_get(0).map_err(StoreError::Database)?,
        workspace_id: row.try_get(1).map_err(StoreError::Database)?,
        event_type: row.try_get(2).map_err(StoreError::Database)?,
        actor_id: row.try_get(3).map_err(StoreError::Database)?,
        actor_type: row.try_get(4).map_err(StoreError::Database)?,
        resource_id: row.try_get(5).map_err(StoreError::Database)?,
        metadata: serde_json::from_str(&metadata).unwrap_or(Value::Null),
        created_at_ms: row.try_get(7).map_err(StoreError::Database)?,
    })
}

fn audit_from_postgres(row: &PgRow) -> Result<AuditRecord, StoreError> {
    let metadata: String = row.try_get(6).map_err(StoreError::Database)?;
    Ok(AuditRecord {
        id: row.try_get(0).map_err(StoreError::Database)?,
        workspace_id: row.try_get(1).map_err(StoreError::Database)?,
        event_type: row.try_get(2).map_err(StoreError::Database)?,
        actor_id: row.try_get(3).map_err(StoreError::Database)?,
        actor_type: row.try_get(4).map_err(StoreError::Database)?,
        resource_id: row.try_get(5).map_err(StoreError::Database)?,
        metadata: serde_json::from_str(&metadata).unwrap_or(Value::Null),
        created_at_ms: row.try_get(7).map_err(StoreError::Database)?,
    })
}

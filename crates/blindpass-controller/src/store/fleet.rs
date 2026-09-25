// SPDX-License-Identifier: AGPL-3.0-only

//! Durable fleet enrollment and node identity state.

use super::{
    Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    authorization::{enqueue_node_document_postgres, enqueue_node_document_sqlite},
    positive_milliseconds,
};
use blindpass_core::fleet::{DocumentKind, NodeKeyRotation, Revocation, SignedEnvelope};
use sqlx::{
    Row, Transaction,
    postgres::{PgRow, Postgres},
    sqlite::{Sqlite, SqliteRow},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub id: String,
    pub node_id: String,
    pub requested_name: String,
    pub created_by: String,
    pub status: String,
    pub fingerprint: Option<String>,
    pub signing_pub: Option<String>,
    pub recipient_pub: Option<String>,
    pub protocol_version: Option<String>,
    pub capabilities_json: Option<String>,
    pub host_facts_json: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub id: String,
    pub name: String,
    pub signing_pub: String,
    pub recipient_pub: String,
    pub key_version: i64,
    pub status: String,
    pub revocation_pending: bool,
    pub rotation_pending: bool,
    pub pending_key_version: Option<i64>,
    pub pending_rotation_id: Option<String>,
    pub protocol_version: String,
    pub capabilities_json: String,
    pub last_seen_at_ms: Option<i64>,
    pub last_poll_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeGrantRevocationDraft {
    pub grant_id: String,
    pub reason: String,
    pub envelope_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeyRotationDraft {
    pub rotation: NodeKeyRotation,
    pub grant_revocations: Vec<NodeGrantRevocationDraft>,
    pub rotation_document_json: String,
}

impl Store {
    pub async fn create_enrollment(
        &self,
        id: &str,
        node_id: &str,
        requested_name: &str,
        token_hash: &str,
        created_by: &str,
        ttl_seconds: u64,
    ) -> Result<i64, StoreError> {
        self.checkpoint_clock().await?;
        let ttl_ms = positive_milliseconds(ttl_seconds, "enrollment TTL")?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT INTO enrollment_requests
                     (id, tenant_id, token_hash, created_by, created_at, expires_at, status,
                      node_id, requested_name, version)
                     VALUES (?, ?, ?, ?, {SQLITE_NOW_MS}, {SQLITE_NOW_MS} + ?, 'issued', ?, ?, 1)"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(token_hash)
                    .bind(created_by)
                    .bind(ttl_ms)
                    .bind(node_id)
                    .bind(requested_name)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let sql = format!(
                    "SELECT expires_at FROM enrollment_requests
                     WHERE id = ? AND expires_at > {SQLITE_NOW_MS}"
                );
                sqlx::query_scalar::<_, i64>(&sql)
                    .bind(id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO enrollment_requests
                     (id, tenant_id, token_hash, created_by, created_at, expires_at, status,
                      node_id, requested_name, version)
                     VALUES ($1, $2, $3, $4, {POSTGRES_NOW_MS}, {POSTGRES_NOW_MS} + $5::BIGINT,
                             'issued', $6, $7, 1)"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(token_hash)
                    .bind(created_by)
                    .bind(ttl_ms)
                    .bind(node_id)
                    .bind(requested_name)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                let sql = format!(
                    "SELECT expires_at FROM enrollment_requests
                     WHERE id = $1 AND expires_at > {POSTGRES_NOW_MS}"
                );
                sqlx::query_scalar::<_, i64>(&sql)
                    .bind(id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Database)
            }
        }
    }

    pub async fn issued_enrollment_by_token_hash(
        &self,
        id: &str,
        token_hash: &str,
    ) -> Result<Option<EnrollmentRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                     WHERE id = ? AND tenant_id = ? AND token_hash = ? AND status = 'issued'
                       AND expires_at > {SQLITE_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(token_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(enrollment_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                     WHERE id = $1 AND tenant_id = $2 AND token_hash = $3 AND status = 'issued'
                       AND expires_at > {POSTGRES_NOW_MS}"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(token_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(enrollment_from_postgres)
                    .transpose()
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // The one-use submission stores each verified enrollment field.
    pub async fn submit_enrollment(
        &self,
        id: &str,
        node_id: &str,
        token_hash: &str,
        requested_name: &str,
        signing_pub: &str,
        recipient_pub: &str,
        fingerprint: &str,
        protocol_version: &str,
        capabilities_json: &str,
        host_facts_json: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE enrollment_requests
                     SET status = 'submitted', used_at = {SQLITE_NOW_MS},
                         submitted_signing_pub = ?, submitted_recipient_pub = ?, fingerprint = ?,
                         protocol_version = ?, capabilities_json = ?, host_facts_json = ?,
                         version = version + 1
                     WHERE id = ? AND node_id = ? AND tenant_id = ? AND token_hash = ?
                       AND requested_name = ? AND status = 'issued' AND expires_at > {SQLITE_NOW_MS}"
                );
                let result = sqlx::query(&sql)
                    .bind(signing_pub)
                    .bind(recipient_pub)
                    .bind(fingerprint)
                    .bind(protocol_version)
                    .bind(capabilities_json)
                    .bind(host_facts_json)
                    .bind(id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(token_hash)
                    .bind(requested_name)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "UPDATE enrollment_requests
                     SET status = 'submitted', used_at = {POSTGRES_NOW_MS},
                         submitted_signing_pub = $1, submitted_recipient_pub = $2, fingerprint = $3,
                         protocol_version = $4, capabilities_json = $5, host_facts_json = $6,
                         version = version + 1
                     WHERE id = $7 AND node_id = $8 AND tenant_id = $9 AND token_hash = $10
                       AND requested_name = $11 AND status = 'issued'
                       AND expires_at > {POSTGRES_NOW_MS}"
                );
                let result = sqlx::query(&sql)
                    .bind(signing_pub)
                    .bind(recipient_pub)
                    .bind(fingerprint)
                    .bind(protocol_version)
                    .bind(capabilities_json)
                    .bind(host_facts_json)
                    .bind(id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .bind(token_hash)
                    .bind(requested_name)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    pub async fn enrollment_by_id(&self, id: &str) -> Result<Option<EnrollmentRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                     WHERE id = ? AND tenant_id = ?"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(enrollment_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                     WHERE id = $1 AND tenant_id = $2"
                );
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(enrollment_from_postgres)
                    .transpose()
            }
        }
    }

    pub async fn list_enrollments(
        &self,
        limit: u32,
        cursor: Option<(i64, String)>,
    ) -> Result<Vec<EnrollmentRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 100));
        match &self.database {
            Database::Sqlite(pool) => {
                let rows = if let Some((created_at, id)) = cursor {
                    let sql = format!(
                        "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                         WHERE tenant_id = ? AND (created_at < ? OR (created_at = ? AND id < ?))
                         ORDER BY created_at DESC, id DESC LIMIT ?"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(created_at)
                        .bind(created_at)
                        .bind(id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                } else {
                    let sql = format!(
                        "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                         WHERE tenant_id = ? ORDER BY created_at DESC, id DESC LIMIT ?"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                }
                .map_err(StoreError::Database)?;
                rows.iter().map(enrollment_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let rows = if let Some((created_at, id)) = cursor {
                    let sql = format!(
                        "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                         WHERE tenant_id = $1 AND (created_at < $2 OR (created_at = $2 AND id < $3))
                         ORDER BY created_at DESC, id DESC LIMIT $4"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(created_at)
                        .bind(id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                } else {
                    let sql = format!(
                        "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                         WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                }
                .map_err(StoreError::Database)?;
                rows.iter().map(enrollment_from_postgres).collect()
            }
        }
    }

    pub async fn approve_enrollment(
        &self,
        id: &str,
        expected_version: i64,
        expected_fingerprint: &str,
    ) -> Result<Option<NodeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let sql = format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                     WHERE id = ? AND tenant_id = ? AND status = 'submitted'
                       AND version = ? AND fingerprint = ?"
                );
                let row = sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .bind(expected_fingerprint)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let enrollment = enrollment_from_sqlite(&row)?;
                let name_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM nodes WHERE tenant_id = ? AND name = ?)",
                )
                .bind(&self.tenant_id)
                .bind(&enrollment.requested_name)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                if name_exists {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                let node =
                    insert_approved_node_sqlite(&mut transaction, &self.tenant_id, &enrollment)
                        .await?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(Some(node))
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let sql = format!(
                    "SELECT {ENROLLMENT_COLUMNS} FROM enrollment_requests
                     WHERE id = $1 AND tenant_id = $2 AND status = 'submitted'
                       AND version = $3 AND fingerprint = $4
                     FOR UPDATE"
                );
                let row = sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .bind(expected_fingerprint)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                };
                let enrollment = enrollment_from_postgres(&row)?;
                let name_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM nodes WHERE tenant_id = $1 AND name = $2)",
                )
                .bind(&self.tenant_id)
                .bind(&enrollment.requested_name)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
                if name_exists {
                    transaction.commit().await.map_err(StoreError::Database)?;
                    return Ok(None);
                }
                let node =
                    insert_approved_node_postgres(&mut transaction, &self.tenant_id, &enrollment)
                        .await?;
                transaction.commit().await.map_err(StoreError::Database)?;
                Ok(Some(node))
            }
        }
    }

    pub async fn reject_enrollment(
        &self,
        id: &str,
        expected_version: i64,
        expected_fingerprint: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql =
                    "UPDATE enrollment_requests SET status = 'rejected', version = version + 1
                     WHERE id = ? AND tenant_id = ? AND status = 'submitted' AND version = ?
                       AND fingerprint = ?";
                let result = sqlx::query(sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .bind(expected_fingerprint)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
            Database::Postgres(pool) => {
                let sql =
                    "UPDATE enrollment_requests SET status = 'rejected', version = version + 1
                     WHERE id = $1 AND tenant_id = $2 AND status = 'submitted' AND version = $3
                       AND fingerprint = $4";
                let result = sqlx::query(sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .bind(expected_version)
                    .bind(expected_fingerprint)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    pub async fn node_by_id(&self, id: &str) -> Result<Option<NodeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql =
                    format!("SELECT {NODE_COLUMNS} FROM nodes WHERE id = ? AND tenant_id = ?");
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(node_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql =
                    format!("SELECT {NODE_COLUMNS} FROM nodes WHERE id = $1 AND tenant_id = $2");
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(node_from_postgres)
                    .transpose()
            }
        }
    }

    /// Revoke node authority and persist signed tombstones for its unexpired grants.
    /// Grant issuance and revocation share the controller metadata lock so a grant
    /// cannot be issued between the caller's tombstone snapshot and this transaction.
    pub async fn revoke_node(
        &self,
        node_id: &str,
        revocations: &[NodeGrantRevocationDraft],
        node_revocation_json: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let node_status = sqlx::query_scalar::<_, String>(
                    "SELECT status FROM nodes WHERE id = ? AND tenant_id = ?",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(node_status) = node_status else {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                };
                if node_status == "revoked" {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(true);
                }
                let epoch: i64 =
                    sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                validate_node_revocation_document(node_revocation_json, node_id, now, epoch)?;
                let rows = sqlx::query(
                    "SELECT id, expires_at FROM grants WHERE node_id = ? AND tenant_id = ?
                     AND status IN ('issued', 'delivered') AND expires_at > ? ORDER BY id",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let mut validated = Vec::with_capacity(rows.len());
                for row in &rows {
                    let grant_id: String = row.try_get("id").map_err(StoreError::Database)?;
                    let expires_at: i64 =
                        row.try_get("expires_at").map_err(StoreError::Database)?;
                    let draft = revocations
                        .iter()
                        .find(|draft| draft.grant_id == grant_id)
                        .ok_or(StoreError::InvalidInput("node grant set changed"))?;
                    let revocation = validate_node_revocation(
                        &draft.envelope_json,
                        &grant_id,
                        node_id,
                        now,
                        expires_at,
                        epoch,
                        &draft.reason,
                    )?;
                    validated.push((draft, revocation));
                }
                if validated.len() != revocations.len()
                    || revocations.iter().any(|draft| {
                        validated
                            .iter()
                            .filter(|(candidate, _)| candidate.grant_id == draft.grant_id)
                            .count()
                            != 1
                    })
                {
                    return Err(StoreError::InvalidInput("node grant set changed"));
                }
                for (draft, revocation) in validated {
                    sqlx::query(
                        "UPDATE grants SET status = 'revoked', revoked_at = ?
                         WHERE id = ? AND node_id = ? AND tenant_id = ?
                           AND status IN ('issued', 'delivered')",
                    )
                    .bind(now)
                    .bind(&draft.grant_id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "UPDATE operations SET status = 'revoked', result_json = '{\"reason\":\"operator\"}',
                         completed_at = ?, version = version + 1
                         WHERE grant_id = ? AND tenant_id = ? AND status IN ('granted', 'executing')"
                    )
                    .bind(now)
                    .bind(&draft.grant_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until)
                         VALUES (?, ?, 'operator', ?, ?)",
                    )
                    .bind(&draft.grant_id)
                    .bind(node_id)
                    .bind(now)
                    .bind(i64::try_from(revocation.retain_until_ms)
                        .map_err(|_| StoreError::InvalidInput("tombstone retention"))?)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    enqueue_node_document_sqlite(&mut tx, node_id, &draft.envelope_json).await?;
                }
                enqueue_node_document_sqlite(&mut tx, node_id, node_revocation_json).await?;
                sqlx::query(
                    "INSERT INTO node_revocation_queue (node_id, created_at) VALUES (?, ?)
                     ON CONFLICT(node_id) DO NOTHING",
                )
                .bind(node_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                cancel_node_operations_sqlite(
                    &mut tx,
                    node_id,
                    &self.tenant_id,
                    now,
                    "node_revoked",
                )
                .await?;
                sqlx::query(&format!(
                    "UPDATE operations SET status = 'failed', result_json = '{{\"reason\":\"expired\"}}',
                     completed_at = {SQLITE_NOW_MS}, version = version + 1
                     WHERE tenant_id = ? AND status IN ('granted', 'executing') AND grant_id IN
                       (SELECT id FROM grants WHERE node_id = ? AND tenant_id = ? AND status IN ('issued', 'delivered') AND expires_at <= ?)
                    "
                ))
                .bind(&self.tenant_id)
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "UPDATE grants SET status = 'expired' WHERE node_id = ? AND tenant_id = ?
                     AND status IN ('issued', 'delivered') AND expires_at <= ?",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(&format!(
                    "UPDATE workloads SET status = 'revoked', revoked_at = {SQLITE_NOW_MS},
                     registration_version = registration_version + 1, version = version + 1
                     WHERE node_id = ? AND tenant_id = ? AND status = 'active'"
                ))
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(&format!(
                    "UPDATE nodes SET status = 'revoked', revoked_at = {SQLITE_NOW_MS}, version = version + 1
                     WHERE id = ? AND tenant_id = ? AND status = 'active'"
                ))
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let node_status = sqlx::query_scalar::<_, String>(
                    "SELECT status FROM nodes WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(node_status) = node_status else {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                };
                if node_status == "revoked" {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(true);
                }
                let epoch: i64 =
                    sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                validate_node_revocation_document(node_revocation_json, node_id, now, epoch)?;
                let rows = sqlx::query(
                    "SELECT id, expires_at FROM grants WHERE node_id = $1 AND tenant_id = $2
                     AND status IN ('issued', 'delivered') AND expires_at > $3 ORDER BY id FOR UPDATE",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let mut validated = Vec::with_capacity(rows.len());
                for row in &rows {
                    let grant_id: String = row.try_get("id").map_err(StoreError::Database)?;
                    let expires_at: i64 =
                        row.try_get("expires_at").map_err(StoreError::Database)?;
                    let draft = revocations
                        .iter()
                        .find(|draft| draft.grant_id == grant_id)
                        .ok_or(StoreError::InvalidInput("node grant set changed"))?;
                    let revocation = validate_node_revocation(
                        &draft.envelope_json,
                        &grant_id,
                        node_id,
                        now,
                        expires_at,
                        epoch,
                        &draft.reason,
                    )?;
                    validated.push((draft, revocation));
                }
                if validated.len() != revocations.len()
                    || revocations.iter().any(|draft| {
                        validated
                            .iter()
                            .filter(|(candidate, _)| candidate.grant_id == draft.grant_id)
                            .count()
                            != 1
                    })
                {
                    return Err(StoreError::InvalidInput("node grant set changed"));
                }
                for (draft, revocation) in validated {
                    sqlx::query(
                        "UPDATE grants SET status = 'revoked', revoked_at = $1
                         WHERE id = $2 AND node_id = $3 AND tenant_id = $4
                           AND status IN ('issued', 'delivered')",
                    )
                    .bind(now)
                    .bind(&draft.grant_id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "UPDATE operations SET status = 'revoked', result_json = '{\"reason\":\"operator\"}',
                         completed_at = $1, version = version + 1
                         WHERE grant_id = $2 AND tenant_id = $3 AND status IN ('granted', 'executing')"
                    )
                    .bind(now)
                    .bind(&draft.grant_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until)
                         VALUES ($1, $2, 'operator', $3, $4)",
                    )
                    .bind(&draft.grant_id)
                    .bind(node_id)
                    .bind(now)
                    .bind(i64::try_from(revocation.retain_until_ms)
                        .map_err(|_| StoreError::InvalidInput("tombstone retention"))?)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    enqueue_node_document_postgres(&mut tx, node_id, &draft.envelope_json).await?;
                }
                enqueue_node_document_postgres(&mut tx, node_id, node_revocation_json).await?;
                sqlx::query(
                    "INSERT INTO node_revocation_queue (node_id, created_at) VALUES ($1, $2)
                     ON CONFLICT(node_id) DO NOTHING",
                )
                .bind(node_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                cancel_node_operations_postgres(
                    &mut tx,
                    node_id,
                    &self.tenant_id,
                    now,
                    "node_revoked",
                )
                .await?;
                sqlx::query(&format!(
                    "UPDATE operations SET status = 'failed', result_json = '{{\"reason\":\"expired\"}}',
                     completed_at = {POSTGRES_NOW_MS}, version = version + 1
                     WHERE tenant_id = $1 AND status IN ('granted', 'executing') AND grant_id IN
                       (SELECT id FROM grants WHERE node_id = $2 AND tenant_id = $3 AND status IN ('issued', 'delivered') AND expires_at <= $4)"
                ))
                .bind(&self.tenant_id)
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "UPDATE grants SET status = 'expired' WHERE node_id = $1 AND tenant_id = $2
                     AND status IN ('issued', 'delivered') AND expires_at <= $3",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(&format!(
                    "UPDATE workloads SET status = 'revoked', revoked_at = {POSTGRES_NOW_MS},
                     registration_version = registration_version + 1, version = version + 1
                     WHERE node_id = $1 AND tenant_id = $2 AND status = 'active'"
                ))
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(&format!(
                    "UPDATE nodes SET status = 'revoked', revoked_at = {POSTGRES_NOW_MS}, version = version + 1
                     WHERE id = $1 AND tenant_id = $2 AND status = 'active'"
                ))
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    /// Stage a controller-approved node key rotation and revoke every unused
    /// grant bound to the old recipient key in the same transaction. The old
    /// key remains current until the broker reports applying the signed
    /// rotation document with the candidate key.
    pub async fn stage_node_key_rotation(
        &self,
        node_id: &str,
        expected_key_version: i64,
        draft: &NodeKeyRotationDraft,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let node = sqlx::query(
                    "SELECT signing_pub, recipient_pub, key_version, status FROM nodes
                     WHERE id = ? AND tenant_id = ?",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(node) = node else {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                };
                let current_signing: String =
                    node.try_get("signing_pub").map_err(StoreError::Database)?;
                let current_recipient: String = node
                    .try_get("recipient_pub")
                    .map_err(StoreError::Database)?;
                let current_version: i64 =
                    node.try_get("key_version").map_err(StoreError::Database)?;
                let node_status: String = node.try_get("status").map_err(StoreError::Database)?;
                let pending: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM node_key_rotations WHERE node_id = ?)",
                )
                .bind(node_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if node_status != "active"
                    || pending
                    || current_version != expected_key_version
                    || draft.rotation.from_key_version
                        != u64::try_from(current_version).unwrap_or_default()
                    || draft.rotation.to_key_version
                        != u64::try_from(current_version.saturating_add(1)).unwrap_or_default()
                    || draft.rotation.node_id != node_id
                    || draft.rotation.signing_public == current_signing
                    || draft.rotation.recipient_public == current_recipient
                {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let epoch: i64 =
                    sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                validate_node_key_rotation_document(
                    &draft.rotation_document_json,
                    &draft.rotation,
                    node_id,
                    now,
                    epoch,
                )?;
                let rows = sqlx::query(
                    "SELECT id, expires_at FROM grants WHERE node_id = ? AND tenant_id = ?
                     AND status IN ('issued', 'delivered') AND expires_at > ? ORDER BY id",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let mut validated = Vec::with_capacity(rows.len());
                for row in &rows {
                    let grant_id: String = row.try_get("id").map_err(StoreError::Database)?;
                    let expires_at: i64 =
                        row.try_get("expires_at").map_err(StoreError::Database)?;
                    let grant_draft = draft
                        .grant_revocations
                        .iter()
                        .find(|candidate| candidate.grant_id == grant_id)
                        .ok_or(StoreError::InvalidInput("node grant set changed"))?;
                    let revocation = validate_node_revocation(
                        &grant_draft.envelope_json,
                        &grant_id,
                        node_id,
                        now,
                        expires_at,
                        epoch,
                        "key_rotation",
                    )?;
                    validated.push((grant_draft, revocation));
                }
                validate_revocation_draft_set(&draft.grant_revocations, &validated)?;
                for (grant_draft, revocation) in validated {
                    sqlx::query(
                        "UPDATE grants SET status = 'revoked', revoked_at = ?
                         WHERE id = ? AND node_id = ? AND tenant_id = ?
                           AND status IN ('issued', 'delivered')",
                    )
                    .bind(now)
                    .bind(&grant_draft.grant_id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "UPDATE operations SET status = 'revoked', result_json = '{\"reason\":\"key_rotation\"}',
                         completed_at = ?, version = version + 1
                         WHERE grant_id = ? AND tenant_id = ? AND status IN ('granted', 'executing')",
                    )
                    .bind(now)
                    .bind(&grant_draft.grant_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until)
                         VALUES (?, ?, 'key_rotation', ?, ?)",
                    )
                    .bind(&grant_draft.grant_id)
                    .bind(node_id)
                    .bind(now)
                    .bind(i64::try_from(revocation.retain_until_ms)
                        .map_err(|_| StoreError::InvalidInput("tombstone retention"))?)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    enqueue_node_document_sqlite(&mut tx, node_id, &grant_draft.envelope_json)
                        .await?;
                }
                sqlx::query(&format!(
                    "UPDATE grants SET status = 'expired' WHERE node_id = ? AND tenant_id = ?
                     AND status IN ('issued', 'delivered') AND expires_at <= {SQLITE_NOW_MS}"
                ))
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                cancel_node_operations_sqlite(
                    &mut tx,
                    node_id,
                    &self.tenant_id,
                    now,
                    "node_key_rotation",
                )
                .await?;
                sqlx::query(
                    "INSERT INTO node_key_rotations
                     (node_id, rotation_id, from_key_version, to_key_version, signing_pub,
                      recipient_pub, fingerprint, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(node_id)
                .bind(&draft.rotation.rotation_id)
                .bind(current_version)
                .bind(
                    i64::try_from(draft.rotation.to_key_version)
                        .map_err(|_| StoreError::InvalidInput("node key version"))?,
                )
                .bind(&draft.rotation.signing_public)
                .bind(&draft.rotation.recipient_public)
                .bind(&draft.rotation.fingerprint)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "INSERT INTO node_key_history
                     (node_id, key_version, signing_pub, recipient_pub, created_at, retired_at)
                     VALUES (?, ?, ?, ?, ?, NULL)",
                )
                .bind(node_id)
                .bind(
                    i64::try_from(draft.rotation.to_key_version)
                        .map_err(|_| StoreError::InvalidInput("node key version"))?,
                )
                .bind(&draft.rotation.signing_public)
                .bind(&draft.rotation.recipient_public)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                enqueue_node_document_sqlite(&mut tx, node_id, &draft.rotation_document_json)
                    .await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let node = sqlx::query(
                    "SELECT signing_pub, recipient_pub, key_version, status FROM nodes
                     WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(node) = node else {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                };
                let current_signing: String =
                    node.try_get("signing_pub").map_err(StoreError::Database)?;
                let current_recipient: String = node
                    .try_get("recipient_pub")
                    .map_err(StoreError::Database)?;
                let current_version: i64 =
                    node.try_get("key_version").map_err(StoreError::Database)?;
                let node_status: String = node.try_get("status").map_err(StoreError::Database)?;
                let pending: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM node_key_rotations WHERE node_id = $1)",
                )
                .bind(node_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if node_status != "active"
                    || pending
                    || current_version != expected_key_version
                    || draft.rotation.from_key_version
                        != u64::try_from(current_version).unwrap_or_default()
                    || draft.rotation.to_key_version
                        != u64::try_from(current_version.saturating_add(1)).unwrap_or_default()
                    || draft.rotation.node_id != node_id
                    || draft.rotation.signing_public == current_signing
                    || draft.rotation.recipient_public == current_recipient
                {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let epoch: i64 =
                    sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                validate_node_key_rotation_document(
                    &draft.rotation_document_json,
                    &draft.rotation,
                    node_id,
                    now,
                    epoch,
                )?;
                let rows = sqlx::query(
                    "SELECT id, expires_at FROM grants WHERE node_id = $1 AND tenant_id = $2
                     AND status IN ('issued', 'delivered') AND expires_at > $3 ORDER BY id FOR UPDATE",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(now)
                .fetch_all(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let mut validated = Vec::with_capacity(rows.len());
                for row in &rows {
                    let grant_id: String = row.try_get("id").map_err(StoreError::Database)?;
                    let expires_at: i64 =
                        row.try_get("expires_at").map_err(StoreError::Database)?;
                    let grant_draft = draft
                        .grant_revocations
                        .iter()
                        .find(|candidate| candidate.grant_id == grant_id)
                        .ok_or(StoreError::InvalidInput("node grant set changed"))?;
                    let revocation = validate_node_revocation(
                        &grant_draft.envelope_json,
                        &grant_id,
                        node_id,
                        now,
                        expires_at,
                        epoch,
                        "key_rotation",
                    )?;
                    validated.push((grant_draft, revocation));
                }
                validate_revocation_draft_set(&draft.grant_revocations, &validated)?;
                for (grant_draft, revocation) in validated {
                    sqlx::query(
                        "UPDATE grants SET status = 'revoked', revoked_at = $1
                         WHERE id = $2 AND node_id = $3 AND tenant_id = $4
                           AND status IN ('issued', 'delivered')",
                    )
                    .bind(now)
                    .bind(&grant_draft.grant_id)
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "UPDATE operations SET status = 'revoked', result_json = '{\"reason\":\"key_rotation\"}',
                         completed_at = $1, version = version + 1
                         WHERE grant_id = $2 AND tenant_id = $3 AND status IN ('granted', 'executing')",
                    )
                    .bind(now)
                    .bind(&grant_draft.grant_id)
                    .bind(&self.tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(
                        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until)
                         VALUES ($1, $2, 'key_rotation', $3, $4)",
                    )
                    .bind(&grant_draft.grant_id)
                    .bind(node_id)
                    .bind(now)
                    .bind(i64::try_from(revocation.retain_until_ms)
                        .map_err(|_| StoreError::InvalidInput("tombstone retention"))?)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    enqueue_node_document_postgres(&mut tx, node_id, &grant_draft.envelope_json)
                        .await?;
                }
                sqlx::query(&format!(
                    "UPDATE grants SET status = 'expired' WHERE node_id = $1 AND tenant_id = $2
                     AND status IN ('issued', 'delivered') AND expires_at <= {POSTGRES_NOW_MS}"
                ))
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                cancel_node_operations_postgres(
                    &mut tx,
                    node_id,
                    &self.tenant_id,
                    now,
                    "node_key_rotation",
                )
                .await?;
                sqlx::query(
                    "INSERT INTO node_key_rotations
                     (node_id, rotation_id, from_key_version, to_key_version, signing_pub,
                      recipient_pub, fingerprint, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(node_id)
                .bind(&draft.rotation.rotation_id)
                .bind(current_version)
                .bind(
                    i64::try_from(draft.rotation.to_key_version)
                        .map_err(|_| StoreError::InvalidInput("node key version"))?,
                )
                .bind(&draft.rotation.signing_public)
                .bind(&draft.rotation.recipient_public)
                .bind(&draft.rotation.fingerprint)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "INSERT INTO node_key_history
                     (node_id, key_version, signing_pub, recipient_pub, created_at, retired_at)
                     VALUES ($1, $2, $3, $4, $5, NULL)",
                )
                .bind(node_id)
                .bind(
                    i64::try_from(draft.rotation.to_key_version)
                        .map_err(|_| StoreError::InvalidInput("node key version"))?,
                )
                .bind(&draft.rotation.signing_public)
                .bind(&draft.rotation.recipient_public)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                enqueue_node_document_postgres(&mut tx, node_id, &draft.rotation_document_json)
                    .await?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    /// Finalize rotation only after the broker signs the matching application
    /// event with the staged key. Old node sessions are revoked atomically.
    pub async fn complete_node_key_rotation(
        &self,
        node_id: &str,
        rotation_id: &str,
        key_version: i64,
        fingerprint: &str,
    ) -> Result<bool, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let pending = sqlx::query(
                    "SELECT from_key_version, to_key_version, signing_pub, recipient_pub, fingerprint
                     FROM node_key_rotations WHERE node_id = ? AND rotation_id = ?",
                )
                .bind(node_id)
                .bind(rotation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(pending) = pending else {
                    let current: Option<i64> = sqlx::query_scalar(
                        "SELECT key_version FROM nodes WHERE id = ? AND tenant_id = ?",
                    )
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let history_fingerprint = sqlx::query(
                        "SELECT signing_pub, recipient_pub FROM node_key_history
                         WHERE node_id = ? AND key_version = ?",
                    )
                    .bind(node_id)
                    .bind(key_version)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let already_complete = if let Some(row) = history_fingerprint {
                        let signing: String =
                            row.try_get("signing_pub").map_err(StoreError::Database)?;
                        let recipient: String =
                            row.try_get("recipient_pub").map_err(StoreError::Database)?;
                        let signing = blindpass_core::signing::base64_url_decode(&signing, 32);
                        let recipient = blindpass_core::signing::base64_url_decode(&recipient, 32);
                        signing.zip(recipient).is_some_and(|(signing, recipient)| {
                            blindpass_core::fleet::node_key_fingerprint(&signing, &recipient)
                                .is_ok_and(|value| value == fingerprint)
                        })
                    } else {
                        false
                    };
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(current == Some(key_version) && already_complete);
                };
                let from_version: i64 = pending
                    .try_get("from_key_version")
                    .map_err(StoreError::Database)?;
                let to_version: i64 = pending
                    .try_get("to_key_version")
                    .map_err(StoreError::Database)?;
                let signing: String = pending
                    .try_get("signing_pub")
                    .map_err(StoreError::Database)?;
                let recipient: String = pending
                    .try_get("recipient_pub")
                    .map_err(StoreError::Database)?;
                let expected_fingerprint: String = pending
                    .try_get("fingerprint")
                    .map_err(StoreError::Database)?;
                if key_version != to_version || fingerprint != expected_fingerprint {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let updated = sqlx::query(
                    "UPDATE nodes SET signing_pub = ?, recipient_pub = ?, key_version = ?, version = version + 1
                     WHERE id = ? AND tenant_id = ? AND key_version = ?
                       AND (status = 'active' OR (status = 'revoked' AND EXISTS (
                         SELECT 1 FROM node_revocation_queue q WHERE q.node_id = nodes.id
                       )))",
                )
                .bind(&signing)
                .bind(&recipient)
                .bind(to_version)
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(from_version)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if updated.rows_affected() != 1 {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                sqlx::query(
                    "UPDATE node_key_history SET retired_at = ?
                     WHERE node_id = ? AND key_version = ? AND retired_at IS NULL",
                )
                .bind(now)
                .bind(node_id)
                .bind(from_version)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "UPDATE node_sessions SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL",
                )
                .bind(now)
                .bind(node_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query("DELETE FROM node_key_rotations WHERE node_id = ? AND rotation_id = ?")
                    .bind(node_id)
                    .bind(rotation_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let pending = sqlx::query(
                    "SELECT from_key_version, to_key_version, signing_pub, recipient_pub, fingerprint
                     FROM node_key_rotations WHERE node_id = $1 AND rotation_id = $2 FOR UPDATE",
                )
                .bind(node_id)
                .bind(rotation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                let Some(pending) = pending else {
                    let current: Option<i64> = sqlx::query_scalar(
                        "SELECT key_version FROM nodes WHERE id = $1 AND tenant_id = $2",
                    )
                    .bind(node_id)
                    .bind(&self.tenant_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let history_fingerprint = sqlx::query(
                        "SELECT signing_pub, recipient_pub FROM node_key_history
                         WHERE node_id = $1 AND key_version = $2",
                    )
                    .bind(node_id)
                    .bind(key_version)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    let already_complete = if let Some(row) = history_fingerprint {
                        let signing: String =
                            row.try_get("signing_pub").map_err(StoreError::Database)?;
                        let recipient: String =
                            row.try_get("recipient_pub").map_err(StoreError::Database)?;
                        let signing = blindpass_core::signing::base64_url_decode(&signing, 32);
                        let recipient = blindpass_core::signing::base64_url_decode(&recipient, 32);
                        signing.zip(recipient).is_some_and(|(signing, recipient)| {
                            blindpass_core::fleet::node_key_fingerprint(&signing, &recipient)
                                .is_ok_and(|value| value == fingerprint)
                        })
                    } else {
                        false
                    };
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(current == Some(key_version) && already_complete);
                };
                let from_version: i64 = pending
                    .try_get("from_key_version")
                    .map_err(StoreError::Database)?;
                let to_version: i64 = pending
                    .try_get("to_key_version")
                    .map_err(StoreError::Database)?;
                let signing: String = pending
                    .try_get("signing_pub")
                    .map_err(StoreError::Database)?;
                let recipient: String = pending
                    .try_get("recipient_pub")
                    .map_err(StoreError::Database)?;
                let expected_fingerprint: String = pending
                    .try_get("fingerprint")
                    .map_err(StoreError::Database)?;
                if key_version != to_version || fingerprint != expected_fingerprint {
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                let updated = sqlx::query(
                    "UPDATE nodes SET signing_pub = $1, recipient_pub = $2, key_version = $3, version = version + 1
                     WHERE id = $4 AND tenant_id = $5 AND key_version = $6
                       AND (status = 'active' OR (status = 'revoked' AND EXISTS (
                         SELECT 1 FROM node_revocation_queue q WHERE q.node_id = nodes.id
                       )))",
                )
                .bind(&signing)
                .bind(&recipient)
                .bind(to_version)
                .bind(node_id)
                .bind(&self.tenant_id)
                .bind(from_version)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                if updated.rows_affected() != 1 {
                    tx.rollback().await.map_err(StoreError::Database)?;
                    return Ok(false);
                }
                sqlx::query(
                    "UPDATE node_key_history SET retired_at = $1
                     WHERE node_id = $2 AND key_version = $3 AND retired_at IS NULL",
                )
                .bind(now)
                .bind(node_id)
                .bind(from_version)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "UPDATE node_sessions SET revoked_at = $1 WHERE node_id = $2 AND revoked_at IS NULL",
                )
                .bind(now)
                .bind(node_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                sqlx::query(
                    "DELETE FROM node_key_rotations WHERE node_id = $1 AND rotation_id = $2",
                )
                .bind(node_id)
                .bind(rotation_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(true)
            }
        }
    }

    pub async fn list_nodes(
        &self,
        limit: u32,
        cursor: Option<(i64, String)>,
    ) -> Result<Vec<NodeRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 100));
        match &self.database {
            Database::Sqlite(pool) => {
                let rows = if let Some((created_at, id)) = cursor {
                    let sql = format!(
                        "SELECT {NODE_COLUMNS} FROM nodes WHERE tenant_id = ?
                         AND (created_at < ? OR (created_at = ? AND id < ?))
                         ORDER BY created_at DESC, id DESC LIMIT ?"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(created_at)
                        .bind(created_at)
                        .bind(id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                } else {
                    let sql = format!(
                        "SELECT {NODE_COLUMNS} FROM nodes WHERE tenant_id = ?
                         ORDER BY created_at DESC, id DESC LIMIT ?"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                }
                .map_err(StoreError::Database)?;
                rows.iter().map(node_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let rows = if let Some((created_at, id)) = cursor {
                    let sql = format!(
                        "SELECT {NODE_COLUMNS} FROM nodes WHERE tenant_id = $1
                         AND (created_at < $2 OR (created_at = $2 AND id < $3))
                         ORDER BY created_at DESC, id DESC LIMIT $4"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(created_at)
                        .bind(id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                } else {
                    let sql = format!(
                        "SELECT {NODE_COLUMNS} FROM nodes WHERE tenant_id = $1
                         ORDER BY created_at DESC, id DESC LIMIT $2"
                    );
                    sqlx::query(&sql)
                        .bind(&self.tenant_id)
                        .bind(limit)
                        .fetch_all(pool)
                        .await
                }
                .map_err(StoreError::Database)?;
                rows.iter().map(node_from_postgres).collect()
            }
        }
    }
}

const NODE_TOMBSTONE_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

fn validate_node_revocation(
    envelope_json: &str,
    grant_id: &str,
    node_id: &str,
    now_ms: i64,
    expires_at_ms: i64,
    issuer_epoch: i64,
    expected_reason: &str,
) -> Result<Revocation, StoreError> {
    if envelope_json.is_empty() || envelope_json.len() > 64 * 1024 {
        return Err(StoreError::InvalidInput("node revocation document size"));
    }
    let envelope = SignedEnvelope::from_json(envelope_json)
        .map_err(|_| StoreError::InvalidInput("node revocation document"))?;
    let revocation = Revocation::from_value(envelope.body())
        .map_err(|_| StoreError::InvalidInput("node revocation body"))?;
    let revoked_at_ms = i64::try_from(revocation.revoked_at_ms)
        .map_err(|_| StoreError::InvalidInput("node revocation time"))?;
    let retain_until_ms = i64::try_from(revocation.retain_until_ms)
        .map_err(|_| StoreError::InvalidInput("node revocation retention"))?;
    let minimum_retention = now_ms
        .max(expires_at_ms)
        .checked_add(NODE_TOMBSTONE_RETENTION_MS)
        .ok_or(StoreError::InvalidInput("node revocation retention"))?;
    let expected_epoch =
        u64::try_from(issuer_epoch).map_err(|_| StoreError::InvalidInput("issuer epoch"))?;
    if envelope.kind() != DocumentKind::Revocation
        || envelope.epoch() != expected_epoch
        || revocation.issuer_epoch != expected_epoch
        || revocation.grant_id != grant_id
        || revocation.node_id != node_id
        || revocation.reason != expected_reason
        || revoked_at_ms < now_ms.saturating_sub(60_000)
        || revoked_at_ms > now_ms.saturating_add(5_000)
        || retain_until_ms < minimum_retention
    {
        return Err(StoreError::InvalidInput("node revocation binding"));
    }
    Ok(revocation)
}

fn validate_revocation_draft_set(
    drafts: &[NodeGrantRevocationDraft],
    validated: &[(&NodeGrantRevocationDraft, Revocation)],
) -> Result<(), StoreError> {
    if validated.len() != drafts.len()
        || drafts.iter().any(|draft| {
            draft.reason != "key_rotation"
                || validated
                    .iter()
                    .filter(|(candidate, _)| candidate.grant_id == draft.grant_id)
                    .count()
                    != 1
        })
    {
        return Err(StoreError::InvalidInput("node grant set changed"));
    }
    Ok(())
}

fn validate_node_key_rotation_document(
    envelope_json: &str,
    expected_rotation: &NodeKeyRotation,
    node_id: &str,
    now_ms: i64,
    issuer_epoch: i64,
) -> Result<(), StoreError> {
    if envelope_json.is_empty() || envelope_json.len() > 64 * 1024 {
        return Err(StoreError::InvalidInput("node key rotation document size"));
    }
    let envelope = SignedEnvelope::from_json(envelope_json)
        .map_err(|_| StoreError::InvalidInput("node key rotation document"))?;
    let rotation = NodeKeyRotation::from_value(envelope.body())
        .map_err(|_| StoreError::InvalidInput("node key rotation body"))?;
    let expected_epoch =
        u64::try_from(issuer_epoch).map_err(|_| StoreError::InvalidInput("issuer epoch"))?;
    if envelope.kind() != DocumentKind::NodeKeyRotation
        || envelope.epoch() != expected_epoch
        || rotation.issuer_epoch != expected_epoch
        || rotation.node_id != node_id
        || &rotation != expected_rotation
        || now_ms <= 0
    {
        return Err(StoreError::InvalidInput("node key rotation binding"));
    }
    Ok(())
}

fn validate_node_revocation_document(
    envelope_json: &str,
    node_id: &str,
    now_ms: i64,
    issuer_epoch: i64,
) -> Result<(), StoreError> {
    use blindpass_core::fleet::NodeRevocation;

    if envelope_json.is_empty() || envelope_json.len() > 64 * 1024 {
        return Err(StoreError::InvalidInput("node revocation document size"));
    }
    let envelope = SignedEnvelope::from_json(envelope_json)
        .map_err(|_| StoreError::InvalidInput("node revocation document"))?;
    let revocation = NodeRevocation::from_value(envelope.body())
        .map_err(|_| StoreError::InvalidInput("node revocation body"))?;
    let revoked_at_ms = i64::try_from(revocation.revoked_at_ms)
        .map_err(|_| StoreError::InvalidInput("node revocation time"))?;
    let expected_epoch =
        u64::try_from(issuer_epoch).map_err(|_| StoreError::InvalidInput("issuer epoch"))?;
    if envelope.kind() != DocumentKind::NodeRevocation
        || envelope.epoch() != expected_epoch
        || revocation.issuer_epoch != expected_epoch
        || revocation.node_id != node_id
        || revoked_at_ms < now_ms.saturating_sub(60_000)
        || revoked_at_ms > now_ms.saturating_add(5_000)
    {
        return Err(StoreError::InvalidInput("node revocation binding"));
    }
    Ok(())
}

async fn cancel_node_operations_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: &str,
    tenant_id: &str,
    now_ms: i64,
    reason: &str,
) -> Result<(), StoreError> {
    let result_json = match reason {
        "node_revoked" => r#"{"reason":"node_revoked"}"#,
        "node_key_rotation" => r#"{"reason":"node_key_rotation"}"#,
        _ => return Err(StoreError::InvalidInput("node cancellation reason")),
    };
    let rows = sqlx::query(
        "SELECT DISTINCT approval_id FROM operations WHERE node_id = ? AND tenant_id = ?
         AND status = 'awaiting_approval' AND approval_id IS NOT NULL",
    )
    .bind(node_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::Database)?;
    for row in rows {
        let approval_id: String = row.try_get("approval_id").map_err(StoreError::Database)?;
        sqlx::query(
            "UPDATE operation_approvals SET status = 'expired', decided_at = ?, version = version + 1
             WHERE id = ? AND tenant_id = ? AND status = 'pending'",
        )
        .bind(now_ms)
        .bind(&approval_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
        sqlx::query(
            "UPDATE operations SET status = 'cancelled', result_json = ?,
             completed_at = ?, version = version + 1
             WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'",
        )
        .bind(result_json)
        .bind(now_ms)
        .bind(&approval_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    }
    sqlx::query(
        "UPDATE operations SET status = 'cancelled', result_json = ?,
         completed_at = ?, version = version + 1
         WHERE node_id = ? AND tenant_id = ? AND status IN ('requested', 'awaiting_approval')",
    )
    .bind(result_json)
    .bind(now_ms)
    .bind(node_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

async fn cancel_node_operations_postgres(
    tx: &mut Transaction<'_, Postgres>,
    node_id: &str,
    tenant_id: &str,
    now_ms: i64,
    reason: &str,
) -> Result<(), StoreError> {
    let result_json = match reason {
        "node_revoked" => r#"{"reason":"node_revoked"}"#,
        "node_key_rotation" => r#"{"reason":"node_key_rotation"}"#,
        _ => return Err(StoreError::InvalidInput("node cancellation reason")),
    };
    let rows = sqlx::query(
        "SELECT DISTINCT approval_id FROM operations WHERE node_id = $1 AND tenant_id = $2
         AND status = 'awaiting_approval' AND approval_id IS NOT NULL",
    )
    .bind(node_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(StoreError::Database)?;
    for row in rows {
        let approval_id: String = row.try_get("approval_id").map_err(StoreError::Database)?;
        sqlx::query(
            "UPDATE operation_approvals SET status = 'expired', decided_at = $1, version = version + 1
             WHERE id = $2 AND tenant_id = $3 AND status = 'pending'",
        )
        .bind(now_ms)
        .bind(&approval_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
        sqlx::query(
            "UPDATE operations SET status = 'cancelled', result_json = $1,
             completed_at = $2, version = version + 1
             WHERE approval_id = $3 AND tenant_id = $4 AND status = 'awaiting_approval'",
        )
        .bind(result_json)
        .bind(now_ms)
        .bind(&approval_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    }
    sqlx::query(
        "UPDATE operations SET status = 'cancelled', result_json = $1,
         completed_at = $2, version = version + 1
         WHERE node_id = $3 AND tenant_id = $4 AND status IN ('requested', 'awaiting_approval')",
    )
    .bind(result_json)
    .bind(now_ms)
    .bind(node_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(StoreError::Database)?;
    Ok(())
}

const ENROLLMENT_COLUMNS: &str = "id, node_id, requested_name, created_by, status,
    fingerprint, submitted_signing_pub AS signing_pub,
    submitted_recipient_pub AS recipient_pub, protocol_version, capabilities_json,
    host_facts_json, created_at, expires_at, used_at, version";
const NODE_COLUMNS: &str = "id, name, signing_pub, recipient_pub, key_version, status,
    EXISTS (SELECT 1 FROM node_revocation_queue q WHERE q.node_id = nodes.id) AS revocation_pending,
    EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id = nodes.id) AS rotation_pending,
    (SELECT to_key_version FROM node_key_rotations r WHERE r.node_id = nodes.id) AS pending_key_version,
    (SELECT rotation_id FROM node_key_rotations r WHERE r.node_id = nodes.id) AS pending_rotation_id,
    protocol_version, capabilities_json, last_seen_at, last_poll_at, created_at, revoked_at, version";

fn enrollment_from_sqlite(row: &SqliteRow) -> Result<EnrollmentRecord, StoreError> {
    Ok(EnrollmentRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        requested_name: row
            .try_get("requested_name")
            .map_err(StoreError::Database)?,
        created_by: row.try_get("created_by").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        fingerprint: row.try_get("fingerprint").map_err(StoreError::Database)?,
        signing_pub: row.try_get("signing_pub").map_err(StoreError::Database)?,
        recipient_pub: row.try_get("recipient_pub").map_err(StoreError::Database)?,
        protocol_version: row
            .try_get("protocol_version")
            .map_err(StoreError::Database)?,
        capabilities_json: row
            .try_get("capabilities_json")
            .map_err(StoreError::Database)?,
        host_facts_json: row
            .try_get("host_facts_json")
            .map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        used_at_ms: row.try_get("used_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

fn enrollment_from_postgres(row: &PgRow) -> Result<EnrollmentRecord, StoreError> {
    Ok(EnrollmentRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        requested_name: row
            .try_get("requested_name")
            .map_err(StoreError::Database)?,
        created_by: row.try_get("created_by").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        fingerprint: row.try_get("fingerprint").map_err(StoreError::Database)?,
        signing_pub: row.try_get("signing_pub").map_err(StoreError::Database)?,
        recipient_pub: row.try_get("recipient_pub").map_err(StoreError::Database)?,
        protocol_version: row
            .try_get("protocol_version")
            .map_err(StoreError::Database)?,
        capabilities_json: row
            .try_get("capabilities_json")
            .map_err(StoreError::Database)?,
        host_facts_json: row
            .try_get("host_facts_json")
            .map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        used_at_ms: row.try_get("used_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

fn node_from_sqlite(row: &SqliteRow) -> Result<NodeRecord, StoreError> {
    Ok(NodeRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        name: row.try_get("name").map_err(StoreError::Database)?,
        signing_pub: row.try_get("signing_pub").map_err(StoreError::Database)?,
        recipient_pub: row.try_get("recipient_pub").map_err(StoreError::Database)?,
        key_version: row.try_get("key_version").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        revocation_pending: row
            .try_get("revocation_pending")
            .map_err(StoreError::Database)?,
        rotation_pending: row
            .try_get("rotation_pending")
            .map_err(StoreError::Database)?,
        pending_key_version: row
            .try_get("pending_key_version")
            .map_err(StoreError::Database)?,
        pending_rotation_id: row
            .try_get("pending_rotation_id")
            .map_err(StoreError::Database)?,
        protocol_version: row
            .try_get("protocol_version")
            .map_err(StoreError::Database)?,
        capabilities_json: row
            .try_get("capabilities_json")
            .map_err(StoreError::Database)?,
        last_seen_at_ms: row.try_get("last_seen_at").map_err(StoreError::Database)?,
        last_poll_at_ms: row.try_get("last_poll_at").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        revoked_at_ms: row.try_get("revoked_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

fn node_from_postgres(row: &PgRow) -> Result<NodeRecord, StoreError> {
    Ok(NodeRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        name: row.try_get("name").map_err(StoreError::Database)?,
        signing_pub: row.try_get("signing_pub").map_err(StoreError::Database)?,
        recipient_pub: row.try_get("recipient_pub").map_err(StoreError::Database)?,
        key_version: row.try_get("key_version").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        revocation_pending: row
            .try_get("revocation_pending")
            .map_err(StoreError::Database)?,
        rotation_pending: row
            .try_get("rotation_pending")
            .map_err(StoreError::Database)?,
        pending_key_version: row
            .try_get("pending_key_version")
            .map_err(StoreError::Database)?,
        pending_rotation_id: row
            .try_get("pending_rotation_id")
            .map_err(StoreError::Database)?,
        protocol_version: row
            .try_get("protocol_version")
            .map_err(StoreError::Database)?,
        capabilities_json: row
            .try_get("capabilities_json")
            .map_err(StoreError::Database)?,
        last_seen_at_ms: row.try_get("last_seen_at").map_err(StoreError::Database)?,
        last_poll_at_ms: row.try_get("last_poll_at").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
        revoked_at_ms: row.try_get("revoked_at").map_err(StoreError::Database)?,
        version: row.try_get("version").map_err(StoreError::Database)?,
    })
}

async fn insert_approved_node_sqlite(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: &str,
    enrollment: &EnrollmentRecord,
) -> Result<NodeRecord, StoreError> {
    let sql = format!(
        "INSERT INTO nodes
         (id, tenant_id, name, signing_pub, recipient_pub, key_version, status,
          protocol_version, capabilities_json, last_seen_at, last_poll_at, created_at,
          revoked_at, version)
         VALUES (?, ?, ?, ?, ?, 1, 'active', ?, ?, NULL, NULL, {SQLITE_NOW_MS}, NULL, 1)"
    );
    sqlx::query(&sql)
        .bind(&enrollment.node_id)
        .bind(tenant_id)
        .bind(&enrollment.requested_name)
        .bind(
            enrollment
                .signing_pub
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment signing key"))?,
        )
        .bind(
            enrollment
                .recipient_pub
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment recipient key"))?,
        )
        .bind(
            enrollment
                .protocol_version
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment protocol version"))?,
        )
        .bind(
            enrollment
                .capabilities_json
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment capabilities"))?,
        )
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    sqlx::query(&format!(
        "INSERT INTO node_key_history (node_id, key_version, signing_pub, recipient_pub, created_at, retired_at)
         VALUES (?, 1, ?, ?, {SQLITE_NOW_MS}, NULL)"
    ))
    .bind(&enrollment.node_id)
    .bind(enrollment.signing_pub.as_deref().ok_or(StoreError::MissingState("enrollment signing key"))?)
    .bind(enrollment.recipient_pub.as_deref().ok_or(StoreError::MissingState("enrollment recipient key"))?)
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    let update = sqlx::query(
        "UPDATE enrollment_requests SET status = 'approved', version = version + 1
         WHERE id = ? AND status = 'submitted' AND version = ? AND fingerprint = ?",
    )
    .bind(&enrollment.id)
    .bind(enrollment.version)
    .bind(
        enrollment
            .fingerprint
            .as_deref()
            .ok_or(StoreError::MissingState("enrollment fingerprint"))?,
    )
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    if update.rows_affected() != 1 {
        return Err(StoreError::InvalidInput("enrollment approval changed"));
    }
    let row = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM nodes WHERE id = ? AND tenant_id = ?"
    ))
    .bind(&enrollment.node_id)
    .bind(tenant_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    node_from_sqlite(&row)
}

async fn insert_approved_node_postgres(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    enrollment: &EnrollmentRecord,
) -> Result<NodeRecord, StoreError> {
    let sql = format!(
        "INSERT INTO nodes
         (id, tenant_id, name, signing_pub, recipient_pub, key_version, status,
          protocol_version, capabilities_json, last_seen_at, last_poll_at, created_at,
          revoked_at, version)
         VALUES ($1, $2, $3, $4, $5, 1, 'active', $6, $7, NULL, NULL, {POSTGRES_NOW_MS}, NULL, 1)"
    );
    sqlx::query(&sql)
        .bind(&enrollment.node_id)
        .bind(tenant_id)
        .bind(&enrollment.requested_name)
        .bind(
            enrollment
                .signing_pub
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment signing key"))?,
        )
        .bind(
            enrollment
                .recipient_pub
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment recipient key"))?,
        )
        .bind(
            enrollment
                .protocol_version
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment protocol version"))?,
        )
        .bind(
            enrollment
                .capabilities_json
                .as_deref()
                .ok_or(StoreError::MissingState("enrollment capabilities"))?,
        )
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    sqlx::query(&format!(
        "INSERT INTO node_key_history (node_id, key_version, signing_pub, recipient_pub, created_at, retired_at)
         VALUES ($1, 1, $2, $3, {POSTGRES_NOW_MS}, NULL)"
    ))
    .bind(&enrollment.node_id)
    .bind(enrollment.signing_pub.as_deref().ok_or(StoreError::MissingState("enrollment signing key"))?)
    .bind(enrollment.recipient_pub.as_deref().ok_or(StoreError::MissingState("enrollment recipient key"))?)
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    let update = sqlx::query(
        "UPDATE enrollment_requests SET status = 'approved', version = version + 1
         WHERE id = $1 AND tenant_id = $2 AND status = 'submitted' AND version = $3
           AND fingerprint = $4",
    )
    .bind(&enrollment.id)
    .bind(tenant_id)
    .bind(enrollment.version)
    .bind(
        enrollment
            .fingerprint
            .as_deref()
            .ok_or(StoreError::MissingState("enrollment fingerprint"))?,
    )
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    if update.rows_affected() != 1 {
        return Err(StoreError::InvalidInput("enrollment approval changed"));
    }
    let row = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM nodes WHERE id = $1 AND tenant_id = $2"
    ))
    .bind(&enrollment.node_id)
    .bind(tenant_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    node_from_postgres(&row)
}

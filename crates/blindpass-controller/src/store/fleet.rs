// SPDX-License-Identifier: AGPL-3.0-only

//! Durable fleet enrollment and node identity state.

use super::{Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError, positive_milliseconds};
use sqlx::{Row, postgres::PgRow, sqlite::SqliteRow};

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
    pub protocol_version: String,
    pub capabilities_json: String,
    pub last_seen_at_ms: Option<i64>,
    pub last_poll_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub version: i64,
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
                let sql = format!(
                    "UPDATE enrollment_requests SET status = 'rejected', version = version + 1
                     WHERE id = ? AND tenant_id = ? AND status = 'submitted' AND version = ?
                       AND fingerprint = ?"
                );
                let result = sqlx::query(&sql)
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
                let sql = format!(
                    "UPDATE enrollment_requests SET status = 'rejected', version = version + 1
                     WHERE id = $1 AND tenant_id = $2 AND status = 'submitted' AND version = $3
                       AND fingerprint = $4"
                );
                let result = sqlx::query(&sql)
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

const ENROLLMENT_COLUMNS: &str = "id, node_id, requested_name, created_by, status,
    fingerprint, submitted_signing_pub AS signing_pub,
    submitted_recipient_pub AS recipient_pub, protocol_version, capabilities_json,
    host_facts_json, created_at, expires_at, used_at, version";
const NODE_COLUMNS: &str = "id, name, signing_pub, recipient_pub, key_version, status,
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
    let update = sqlx::query(&format!(
        "UPDATE enrollment_requests SET status = 'approved', version = version + 1
         WHERE id = ? AND status = 'submitted' AND version = ? AND fingerprint = ?"
    ))
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
    let update = sqlx::query(&format!(
        "UPDATE enrollment_requests SET status = 'approved', version = version + 1
         WHERE id = $1 AND tenant_id = $2 AND status = 'submitted' AND version = $3
           AND fingerprint = $4"
    ))
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

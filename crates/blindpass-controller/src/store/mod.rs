// SPDX-License-Identifier: AGPL-3.0-only

//! Durable, tenant-scoped controller state. Expiry is checked in the same
//! database statement as every read or state transition; the sweeper only
//! bounds retention and is never an authorization mechanism.

use rand::{RngCore, rngs::OsRng};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{PgPool, Row, SqlitePool, postgres::PgPoolOptions};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

mod exchanges;
mod operators;
pub use exchanges::{
    ApprovalDecisionOutcome, ApprovalRecord, AuditRecord, ExchangePolicyRecord, ExchangeRecord,
    LifecycleRecord,
};
pub use operators::{LocalOperator, LocalSession};

const SQLITE_NOW_MS: &str = "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)";
const POSTGRES_NOW_MS: &str = "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT";

#[derive(Debug)]
pub enum StoreError {
    Database(sqlx::Error),
    InvalidInput(&'static str),
    MissingState(&'static str),
    UnsupportedSchemaVersion,
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
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone)]
enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

#[derive(Clone)]
pub struct Store {
    database: Database,
    tenant_id: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitResult {
    pub count: i64,
    pub retry_after_seconds: u64,
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let database = Database::connect(url).await?;
        database.validate_existing_schema_version().await?;
        database.migrate().await?;

        let candidate_tenant_id = new_uuid();
        match &database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "INSERT OR IGNORE INTO controller_meta
                     (id, schema_version, tenant_id, issuer_epoch, created_at)
                     VALUES (1, 1, ?, 1, {SQLITE_NOW_MS})"
                );
                sqlx::query(&sql)
                    .bind(candidate_tenant_id)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Database)?;
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "INSERT INTO controller_meta
                     (id, schema_version, tenant_id, issuer_epoch, created_at)
                     VALUES (1, 1, $1, 1, {POSTGRES_NOW_MS})
                     ON CONFLICT (id) DO NOTHING"
                );
                sqlx::query(&sql)
                    .bind(candidate_tenant_id)
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

        Ok(Self {
            database,
            tenant_id,
        })
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Close the shared connection pool during shutdown. Existing `Store`
    /// clones observe the closure, so readiness fails immediately afterward.
    pub async fn close(&self) {
        match &self.database {
            Database::Sqlite(pool) => pool.close().await,
            Database::Postgres(pool) => pool.close().await,
        }
    }

    pub async fn is_ready(&self) -> bool {
        match &self.database {
            Database::Sqlite(pool) => sqlx::query("SELECT 1")
                .fetch_one(pool)
                .await
                .is_ok_and(|row| row.try_get::<i32, _>(0).ok() == Some(1)),
            Database::Postgres(pool) => sqlx::query("SELECT 1")
                .fetch_one(pool)
                .await
                .is_ok_and(|row| row.try_get::<i32, _>(0).ok() == Some(1)),
        }
    }

    pub async fn policy_document(&self) -> Result<Option<PolicyDocumentRecord>, StoreError> {
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
    }

    /// Replace the persisted policy only when its expected version still matches.
    /// An absent row represents version 1 seeded from local configuration.
    pub async fn replace_policy_document(
        &self,
        expected_version: i64,
        document_json: &str,
        updated_by: &str,
    ) -> Result<Option<i64>, StoreError> {
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
    }

    /// Delete expired durable ciphertext after the configured retention grace.
    /// Every public read and transition checks its own expiry, so this worker
    /// controls retention rather than authority.
    pub async fn sweep_expired(&self, retention_grace_seconds: u64) -> Result<u64, StoreError> {
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
            }
        }
        Ok(removed)
    }

    /// Apply the audit log's day-based retention separately from ciphertext
    /// expiry. A short ciphertext grace must never prune fresh audit history.
    pub async fn sweep_audit(&self, retention_days: u32) -> Result<u64, StoreError> {
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
    }

    pub async fn create_agent(
        &self,
        agent_id: &str,
        name: &str,
        ring: Option<&str>,
        api_key_hash: &str,
    ) -> Result<AgentCredential, StoreError> {
        self.create_agent_with_id(&new_uuid(), agent_id, name, ring, api_key_hash)
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
    }

    pub async fn agent_by_key_id(&self, id: &str) -> Result<Option<AgentCredential>, StoreError> {
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
    }

    pub async fn agent_by_agent_id(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentCredential>, StoreError> {
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
    }

    pub async fn list_admin_agents(&self) -> Result<Vec<AdminAgentRecord>, StoreError> {
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
    }

    pub async fn replace_agent_api_key_hash(
        &self,
        agent_id: &str,
        expected_key_version: i64,
        api_key_hash: &str,
    ) -> Result<Option<AgentCredential>, StoreError> {
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE agents SET api_key_hash = ?, key_version = key_version + 1,
                                       rotated_at = {SQLITE_NOW_MS}
                     WHERE agent_id = ? AND tenant_id = ? AND status = 'active' AND key_version = ?
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
    }

    pub async fn revoke_agent(&self, agent_id: &str) -> Result<bool, StoreError> {
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "UPDATE agents SET status = 'revoked', revoked_at = {SQLITE_NOW_MS}
                     WHERE agent_id = ? AND tenant_id = ? AND status = 'active'"
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
                     WHERE agent_id = $1 AND tenant_id = $2 AND status = 'active'"
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
    }

    pub async fn consume_rate_limit(
        &self,
        key: &str,
        limit: u32,
        window_milliseconds: u64,
    ) -> Result<RateLimitResult, StoreError> {
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
    }

    pub async fn create_secret_request(
        &self,
        requester_agent_id: &str,
        public_key: &str,
        description: &str,
        confirmation_code: &str,
        ttl_seconds: u64,
    ) -> Result<String, StoreError> {
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
    }

    pub async fn create_secret_request_with_expiry(
        &self,
        requester_agent_id: &str,
        public_key: &str,
        description: &str,
        confirmation_code: &str,
        ttl_seconds: u64,
    ) -> Result<CreatedSecretRequest, StoreError> {
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
    }

    pub async fn secret_request_metadata(
        &self,
        request_id: &str,
    ) -> Result<Option<SecretRequestMetadata>, StoreError> {
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
    }

    pub async fn browser_request_status(
        &self,
        request_id: &str,
    ) -> Result<Option<SecretRequestStatus>, StoreError> {
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
    }

    pub async fn delete_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<bool, StoreError> {
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
    }

    pub async fn submit_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
        enc: &str,
        ciphertext: &str,
        submitted_ttl_seconds: u64,
    ) -> Result<bool, StoreError> {
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
                let sql = format!(
                    "UPDATE secret_requests
                     SET status = 'submitted', enc = $1, ciphertext = $2,
                         submitted_at = {POSTGRES_NOW_MS},
                         expires_at = {POSTGRES_NOW_MS} + $3::BIGINT
                     WHERE id = $4 AND tenant_id = $5 AND requester_agent_id = $6
                       AND status = 'pending' AND expires_at > {POSTGRES_NOW_MS}
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
        }
    }

    pub async fn request_status(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<Option<SecretRequestStatus>, StoreError> {
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
    }

    pub async fn consume_secret_request(
        &self,
        request_id: &str,
        requester_agent_id: &str,
    ) -> Result<Option<EncryptedPayload>, StoreError> {
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
    }
}

impl Database {
    async fn connect(url: &str) -> Result<Self, StoreError> {
        if url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(url)
                .map_err(|_| StoreError::InvalidInput("BLINDPASS_DATABASE_URL"))?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
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
        if version != Some(1) {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
        Ok(())
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
                    .map(|_| ())
                    .map_err(StoreError::Database)
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
                .map(|_| ())
                .map_err(StoreError::Database)
            }
        }
    }
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

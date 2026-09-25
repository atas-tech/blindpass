// SPDX-License-Identifier: AGPL-3.0-only

//! Durable grant issuance and metadata queries.

use super::{
    Database, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    authorization::{
        OperationRecord, enqueue_node_document_postgres, enqueue_node_document_sqlite,
    },
};
use blindpass_core::canon::canonicalize_value;
use blindpass_core::fleet::{DocumentKind, Grant, Revocation, SignedEnvelope};
use sqlx::{Row, postgres::PgRow, sqlite::SqliteRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub id: String,
    pub operation_id: String,
    pub node_id: String,
    pub workload_id: String,
    pub invocation_id: String,
    pub unit: String,
    pub account: String,
    pub resource_id: String,
    pub recipient_key_id: String,
    pub policy_version: i64,
    pub approval_reference: Option<String>,
    pub action: String,
    pub mode: String,
    pub audience: String,
    pub issuer_epoch: i64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub status: String,
    pub consumed_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIssueDraft {
    pub grant: Grant,
    pub expected_operation_version: i64,
    pub envelope_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantIssueOutcome {
    Issued(Vec<String>),
    Existing(Vec<String>),
    Stale,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRevocationOutcome {
    Revoked {
        grant_id: String,
        offline: bool,
    },
    Consumed {
        grant_id: String,
        consumer_lifetime_seconds: i64,
    },
    NotFound,
    Conflict,
}

const TOMBSTONE_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
const NODE_OFFLINE_MS: i64 = 120_000;

#[derive(Debug)]
struct GrantContext {
    operation: OperationRecord,
    workload_id: String,
    node_id: String,
    unit: String,
    account: String,
    mode: String,
    workload_ceiling: i64,
    workload_status: String,
    node_status: String,
    recipient_key_version: i64,
    approval_status: Option<String>,
}

const GRANT_COLUMNS: &str = "id, operation_id, node_id, workload_id, invocation_id, unit,
    account, resource_id, recipient_key_id, policy_version, approval_reference, action, mode,
    audience, issuer_epoch, issued_at, expires_at, status, consumed_at, revoked_at, created_at";

impl Store {
    pub async fn grant_by_id(&self, id: &str) -> Result<Option<GrantRecord>, StoreError> {
        self.checkpoint_clock().await?;
        match &self.database {
            Database::Sqlite(pool) => {
                let sql =
                    format!("SELECT {GRANT_COLUMNS} FROM grants WHERE id = ? AND tenant_id = ?");
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(grant_from_sqlite)
                    .transpose()
            }
            Database::Postgres(pool) => {
                let sql =
                    format!("SELECT {GRANT_COLUMNS} FROM grants WHERE id = $1 AND tenant_id = $2");
                sqlx::query(&sql)
                    .bind(id)
                    .bind(&self.tenant_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Database)?
                    .as_ref()
                    .map(grant_from_postgres)
                    .transpose()
            }
        }
    }

    pub async fn list_grants(
        &self,
        node_id: Option<&str>,
        status: Option<&str>,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<GrantRecord>, StoreError> {
        self.checkpoint_clock().await?;
        let limit = i64::from(limit.clamp(1, 101));
        let status = status.unwrap_or("");
        match &self.database {
            Database::Sqlite(pool) => {
                let sql = format!(
                    "SELECT {GRANT_COLUMNS} FROM grants WHERE tenant_id = ?
                    AND (? = '' OR node_id = ?) AND (? = '' OR status = ?)
                    AND (? IS NULL OR created_at > ? OR (created_at = ? AND id > ?))
                    ORDER BY created_at, id LIMIT ?"
                );
                let rows = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(node_id.unwrap_or(""))
                    .bind(node_id.unwrap_or(""))
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
                rows.iter().map(grant_from_sqlite).collect()
            }
            Database::Postgres(pool) => {
                let sql = format!(
                    "SELECT {GRANT_COLUMNS} FROM grants WHERE tenant_id = $1
                    AND ($2 = '' OR node_id = $3) AND ($4 = '' OR status = $5)
                    AND ($6::BIGINT IS NULL OR created_at > $7 OR (created_at = $8 AND id > $9))
                    ORDER BY created_at, id LIMIT $10"
                );
                let rows = sqlx::query(&sql)
                    .bind(&self.tenant_id)
                    .bind(node_id.unwrap_or(""))
                    .bind(node_id.unwrap_or(""))
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
                rows.iter().map(grant_from_postgres).collect()
            }
        }
    }

    /// Issue a bounded group of already-authorized operation grants. Every
    /// operation transition, grant row and node inbox entry commits together.
    pub async fn issue_operation_grants(
        &self,
        drafts: &[GrantIssueDraft],
    ) -> Result<GrantIssueOutcome, StoreError> {
        self.checkpoint_clock().await?;
        if drafts.is_empty() || drafts.len() > 10 {
            return Err(StoreError::InvalidInput("grant group size"));
        }
        let mut operation_ids = std::collections::HashSet::new();
        for draft in drafts {
            let value = draft
                .grant
                .to_value()
                .map_err(|_| StoreError::InvalidInput("grant document"))?;
            let envelope = SignedEnvelope::from_json(&draft.envelope_json)
                .map_err(|_| StoreError::InvalidInput("signed grant envelope"))?;
            let expected_body =
                canonicalize_value(&value).map_err(|_| StoreError::InvalidInput("grant body"))?;
            let signed_body = envelope
                .body_json()
                .map_err(|_| StoreError::InvalidInput("grant body"))?;
            if draft.expected_operation_version <= 0
                || !operation_ids.insert(draft.grant.operation_id.as_str())
                || envelope.kind() != DocumentKind::Grant
                || envelope.epoch() != draft.grant.issuer_epoch
                || signed_body != expected_body
                || draft.envelope_json.is_empty()
                || draft.envelope_json.len() > 64 * 1024
            {
                return Err(StoreError::InvalidInput("grant envelope binding"));
            }
        }
        match &self.database {
            Database::Sqlite(pool) => {
                issue_operation_grants_sqlite(pool, &self.tenant_id, drafts).await
            }
            Database::Postgres(pool) => {
                issue_operation_grants_postgres(pool, &self.tenant_id, drafts).await
            }
        }
    }

    /// Revoke an active grant and atomically persist its signed tombstone for
    /// node delivery. A consumed grant reports its registered consumer bound.
    pub async fn revoke_grant(
        &self,
        grant_id: &str,
        reason: &str,
        envelope_json: &str,
    ) -> Result<GrantRevocationOutcome, StoreError> {
        self.checkpoint_clock().await?;
        if !matches!(reason, "operator" | "cancelled") {
            return Err(StoreError::InvalidInput("grant revocation reason"));
        }
        match &self.database {
            Database::Sqlite(pool) => {
                revoke_grant_sqlite(pool, &self.tenant_id, grant_id, reason, envelope_json).await
            }
            Database::Postgres(pool) => {
                revoke_grant_postgres(pool, &self.tenant_id, grant_id, reason, envelope_json).await
            }
        }
    }
}

async fn revoke_grant_sqlite(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    grant_id: &str,
    reason: &str,
    envelope_json: &str,
) -> Result<GrantRevocationOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let row = sqlx::query(
        "SELECT g.status, g.node_id, g.workload_id, g.operation_id, g.expires_at,
                w.local_ceiling_seconds, n.last_seen_at, o.status AS operation_status
         FROM grants g JOIN workloads w ON w.id = g.workload_id
         JOIN nodes n ON n.id = g.node_id JOIN operations o ON o.id = g.operation_id
         WHERE g.id = ? AND g.tenant_id = ?",
    )
    .bind(grant_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    let Some(row) = row else {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::NotFound);
    };
    let status: String = row.try_get("status").map_err(StoreError::Database)?;
    let node_id: String = row.try_get("node_id").map_err(StoreError::Database)?;
    let operation_id: String = row.try_get("operation_id").map_err(StoreError::Database)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(StoreError::Database)?;
    let consumer_lifetime: i64 = row
        .try_get("local_ceiling_seconds")
        .map_err(StoreError::Database)?;
    let last_seen_at: Option<i64> = row.try_get("last_seen_at").map_err(StoreError::Database)?;
    let operation_status: String = row
        .try_get("operation_status")
        .map_err(StoreError::Database)?;
    let offline =
        last_seen_at.is_none_or(|last_seen| now.saturating_sub(last_seen) > NODE_OFFLINE_MS);
    if status == "consumed" {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Consumed {
            grant_id: grant_id.to_owned(),
            consumer_lifetime_seconds: consumer_lifetime,
        });
    }
    if status == "revoked" {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Revoked {
            grant_id: grant_id.to_owned(),
            offline,
        });
    }
    if status != "issued" && status != "delivered"
        || now >= expires_at
        || !matches!(operation_status.as_str(), "granted" | "executing")
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Conflict);
    }
    let revocation = validate_revocation_envelope(envelope_json, grant_id, &node_id, reason)?;
    validate_revocation_time(&revocation, now, expires_at)?;
    let result_json = format!("{{\"reason\":\"{reason}\"}}");
    let updated_grant = sqlx::query(
        "UPDATE grants SET status = 'revoked', revoked_at = ?
        WHERE id = ? AND tenant_id = ? AND status IN ('issued', 'delivered')",
    )
    .bind(now)
    .bind(grant_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    let updated_operation = sqlx::query("UPDATE operations SET status = 'revoked', result_json = ?, completed_at = ?, version = version + 1
        WHERE id = ? AND tenant_id = ? AND status IN ('granted', 'executing')")
        .bind(&result_json)
        .bind(now)
        .bind(&operation_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    if updated_grant.rows_affected() != 1 || updated_operation.rows_affected() != 1 {
        tx.rollback().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Conflict);
    }
    sqlx::query(
        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until)
        VALUES (?, ?, ?, ?, ?)",
    )
    .bind(grant_id)
    .bind(&node_id)
    .bind(reason)
    .bind(now)
    .bind(to_i64(revocation.retain_until_ms, "tombstone retention")?)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    enqueue_node_document_sqlite(&mut tx, &node_id, envelope_json).await?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(GrantRevocationOutcome::Revoked {
        grant_id: grant_id.to_owned(),
        offline,
    })
}

async fn revoke_grant_postgres(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    grant_id: &str,
    reason: &str,
    envelope_json: &str,
) -> Result<GrantRevocationOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let row = sqlx::query(
        "SELECT g.status, g.node_id, g.workload_id, g.operation_id, g.expires_at,
                w.local_ceiling_seconds, n.last_seen_at, o.status AS operation_status
         FROM grants g JOIN workloads w ON w.id = g.workload_id
         JOIN nodes n ON n.id = g.node_id JOIN operations o ON o.id = g.operation_id
         WHERE g.id = $1 AND g.tenant_id = $2 FOR UPDATE OF g",
    )
    .bind(grant_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    let Some(row) = row else {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::NotFound);
    };
    let status: String = row.try_get("status").map_err(StoreError::Database)?;
    let node_id: String = row.try_get("node_id").map_err(StoreError::Database)?;
    let operation_id: String = row.try_get("operation_id").map_err(StoreError::Database)?;
    let expires_at: i64 = row.try_get("expires_at").map_err(StoreError::Database)?;
    let consumer_lifetime: i64 = row
        .try_get("local_ceiling_seconds")
        .map_err(StoreError::Database)?;
    let last_seen_at: Option<i64> = row.try_get("last_seen_at").map_err(StoreError::Database)?;
    let operation_status: String = row
        .try_get("operation_status")
        .map_err(StoreError::Database)?;
    let offline =
        last_seen_at.is_none_or(|last_seen| now.saturating_sub(last_seen) > NODE_OFFLINE_MS);
    if status == "consumed" {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Consumed {
            grant_id: grant_id.to_owned(),
            consumer_lifetime_seconds: consumer_lifetime,
        });
    }
    if status == "revoked" {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Revoked {
            grant_id: grant_id.to_owned(),
            offline,
        });
    }
    if status != "issued" && status != "delivered"
        || now >= expires_at
        || !matches!(operation_status.as_str(), "granted" | "executing")
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Conflict);
    }
    let revocation = validate_revocation_envelope(envelope_json, grant_id, &node_id, reason)?;
    validate_revocation_time(&revocation, now, expires_at)?;
    let result_json = format!("{{\"reason\":\"{reason}\"}}");
    let updated_grant = sqlx::query(
        "UPDATE grants SET status = 'revoked', revoked_at = $1
        WHERE id = $2 AND tenant_id = $3 AND status IN ('issued', 'delivered')",
    )
    .bind(now)
    .bind(grant_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    let updated_operation = sqlx::query("UPDATE operations SET status = 'revoked', result_json = $1, completed_at = $2, version = version + 1
        WHERE id = $3 AND tenant_id = $4 AND status IN ('granted', 'executing')")
        .bind(&result_json)
        .bind(now)
        .bind(&operation_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    if updated_grant.rows_affected() != 1 || updated_operation.rows_affected() != 1 {
        tx.rollback().await.map_err(StoreError::Database)?;
        return Ok(GrantRevocationOutcome::Conflict);
    }
    sqlx::query(
        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until)
        VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(grant_id)
    .bind(&node_id)
    .bind(reason)
    .bind(now)
    .bind(to_i64(revocation.retain_until_ms, "tombstone retention")?)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    enqueue_node_document_postgres(&mut tx, &node_id, envelope_json).await?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(GrantRevocationOutcome::Revoked {
        grant_id: grant_id.to_owned(),
        offline,
    })
}

fn validate_revocation_envelope(
    envelope_json: &str,
    grant_id: &str,
    node_id: &str,
    reason: &str,
) -> Result<Revocation, StoreError> {
    if envelope_json.is_empty() || envelope_json.len() > 64 * 1024 {
        return Err(StoreError::InvalidInput("revocation document size"));
    }
    let envelope = SignedEnvelope::from_json(envelope_json)
        .map_err(|_| StoreError::InvalidInput("revocation document"))?;
    let revocation = Revocation::from_value(envelope.body())
        .map_err(|_| StoreError::InvalidInput("revocation body"))?;
    if envelope.kind() != DocumentKind::Revocation
        || envelope.epoch() != revocation.issuer_epoch
        || revocation.grant_id != grant_id
        || revocation.node_id != node_id
        || revocation.reason != reason
    {
        return Err(StoreError::InvalidInput("revocation document binding"));
    }
    Ok(revocation)
}

fn validate_revocation_time(
    revocation: &Revocation,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<(), StoreError> {
    let revoked_at = i64::try_from(revocation.revoked_at_ms)
        .map_err(|_| StoreError::InvalidInput("revocation time"))?;
    let retain_until = i64::try_from(revocation.retain_until_ms)
        .map_err(|_| StoreError::InvalidInput("tombstone retention"))?;
    let minimum_retain = now_ms
        .max(expires_at_ms)
        .checked_add(TOMBSTONE_RETENTION_MS)
        .ok_or(StoreError::InvalidInput("tombstone retention"))?;
    if revoked_at < now_ms.saturating_sub(60_000)
        || revoked_at > now_ms.saturating_add(5_000)
        || retain_until < minimum_retain
    {
        return Err(StoreError::InvalidInput("revocation time or retention"));
    }
    Ok(())
}

async fn issue_operation_grants_sqlite(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    drafts: &[GrantIssueDraft],
) -> Result<GrantIssueOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let now: i64 = sqlx::query_scalar(&format!("SELECT {SQLITE_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let epoch: i64 = sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let contexts = load_sqlite_contexts(&mut tx, tenant_id, drafts).await?;
    let already = already_issued(&contexts);
    if let Some(ids) = already {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantIssueOutcome::Existing(ids));
    }
    if contexts.len() != drafts.len()
        || contexts.iter().any(|context| {
            context.operation.status != "requested"
                || context.operation.grant_id.is_some()
                || context.operation.version <= 0
        })
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantIssueOutcome::Conflict);
    }
    let policy_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
    if drafts.iter().zip(&contexts).any(|(draft, context)| {
        !grant_matches_context(draft, context, policy_version.unwrap_or(1), epoch, now)
    }) {
        for context in &contexts {
            sqlx::query("UPDATE operations SET status = 'denied', version = version + 1 WHERE id = ? AND tenant_id = ? AND status = 'requested'")
                .bind(&context.operation.id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantIssueOutcome::Stale);
    }
    let mut grant_ids = Vec::with_capacity(drafts.len());
    for draft in drafts {
        insert_grant_sqlite(&mut tx, tenant_id, draft).await?;
        let updated = sqlx::query("UPDATE operations SET status = 'granted', grant_id = ?, expires_at = ?, version = version + 1
            WHERE id = ? AND tenant_id = ? AND status = 'requested' AND version = ?")
            .bind(&draft.grant.id).bind(to_i64(draft.grant.expires_at_ms, "grant expiry")?)
            .bind(&draft.grant.operation_id).bind(tenant_id).bind(draft.expected_operation_version)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::InvalidInput(
                "grant operation changed during issuance",
            ));
        }
        enqueue_node_document_sqlite(&mut tx, &draft.grant.node_id, &draft.envelope_json).await?;
        grant_ids.push(draft.grant.id.clone());
    }
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(GrantIssueOutcome::Issued(grant_ids))
}

async fn issue_operation_grants_postgres(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    drafts: &[GrantIssueDraft],
) -> Result<GrantIssueOutcome, StoreError> {
    let mut tx = pool.begin().await.map_err(StoreError::Database)?;
    sqlx::query("SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let now: i64 = sqlx::query_scalar(&format!("SELECT {POSTGRES_NOW_MS}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let epoch: i64 = sqlx::query_scalar("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
    let contexts = load_postgres_contexts(&mut tx, tenant_id, drafts).await?;
    let already = already_issued(&contexts);
    if let Some(ids) = already {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantIssueOutcome::Existing(ids));
    }
    if contexts.len() != drafts.len()
        || contexts.iter().any(|context| {
            context.operation.status != "requested"
                || context.operation.grant_id.is_some()
                || context.operation.version <= 0
        })
    {
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantIssueOutcome::Conflict);
    }
    let policy_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM fleet_policies WHERE tenant_id = $1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
    if drafts.iter().zip(&contexts).any(|(draft, context)| {
        !grant_matches_context(draft, context, policy_version.unwrap_or(1), epoch, now)
    }) {
        for context in &contexts {
            sqlx::query("UPDATE operations SET status = 'denied', version = version + 1 WHERE id = $1 AND tenant_id = $2 AND status = 'requested'")
                .bind(&context.operation.id).bind(tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        return Ok(GrantIssueOutcome::Stale);
    }
    let mut grant_ids = Vec::with_capacity(drafts.len());
    for draft in drafts {
        insert_grant_postgres(&mut tx, tenant_id, draft).await?;
        let updated = sqlx::query("UPDATE operations SET status = 'granted', grant_id = $1, expires_at = $2, version = version + 1
            WHERE id = $3 AND tenant_id = $4 AND status = 'requested' AND version = $5")
            .bind(&draft.grant.id).bind(to_i64(draft.grant.expires_at_ms, "grant expiry")?)
            .bind(&draft.grant.operation_id).bind(tenant_id).bind(draft.expected_operation_version)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::InvalidInput(
                "grant operation changed during issuance",
            ));
        }
        enqueue_node_document_postgres(&mut tx, &draft.grant.node_id, &draft.envelope_json).await?;
        grant_ids.push(draft.grant.id.clone());
    }
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(GrantIssueOutcome::Issued(grant_ids))
}

fn already_issued(contexts: &[GrantContext]) -> Option<Vec<String>> {
    if contexts.is_empty()
        || contexts
            .iter()
            .any(|context| context.operation.status != "granted")
    {
        return None;
    }
    contexts
        .iter()
        .map(|context| context.operation.grant_id.clone())
        .collect()
}

fn grant_matches_context(
    draft: &GrantIssueDraft,
    context: &GrantContext,
    current_policy: i64,
    current_epoch: i64,
    now_ms: i64,
) -> bool {
    let grant = &draft.grant;
    let issued_at = i64::try_from(grant.issued_at_ms).ok();
    let expires_at = i64::try_from(grant.expires_at_ms).ok();
    let Some(issued_at) = issued_at else {
        return false;
    };
    let Some(expires_at) = expires_at else {
        return false;
    };
    let expected_key_id = format!("{}-{}", context.node_id, context.recipient_key_version);
    let ttl_ms = context
        .operation
        .requested_ttl_seconds
        .checked_mul(1_000)
        .unwrap_or_default();
    issued_at > 0
        && issued_at <= now_ms.saturating_add(5_000)
        && now_ms.saturating_sub(issued_at) <= 60_000
        && context.operation.expires_at_ms > now_ms
        && expires_at > now_ms
        && expires_at <= issued_at.saturating_add(ttl_ms)
        && expires_at <= issued_at.saturating_add(context.workload_ceiling.saturating_mul(1_000))
        && grant.id != grant.operation_id
        && grant.operation_id == context.operation.id
        && grant.node_id == context.node_id
        && grant.workload_id == context.workload_id
        && grant.invocation_id == context.operation.invocation_id
        && grant.unit == context.unit
        && grant.account == context.account
        && grant.resource_id == context.operation.resource_id
        && grant.policy_version == current_policy as u64
        && context.operation.policy_version == current_policy
        && grant.action == context.operation.action
        && grant.mode.as_str() == context.mode
        && grant.audience == "blindpass-node"
        && grant.issuer_epoch == current_epoch as u64
        && grant.recipient_key_id == expected_key_id
        && grant.local_ceiling_seconds == context.workload_ceiling as u64
        && grant.approval_reference == context.operation.approval_id
        && context.operation.version == draft.expected_operation_version
        && context.operation.decision != "deny"
        && context.operation.status == "requested"
        && context.workload_status == "active"
        && context.node_status == "active"
        && context
            .approval_status
            .as_deref()
            .is_none_or(|status| status == "approved")
}

async fn load_sqlite_contexts(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: &str,
    drafts: &[GrantIssueDraft],
) -> Result<Vec<GrantContext>, StoreError> {
    let columns = operation_columns_prefixed();
    let sql = format!(
        "SELECT {columns} FROM operations o
        JOIN workloads w ON w.id = o.workload_id AND w.tenant_id = o.tenant_id
        JOIN nodes n ON n.id = o.node_id AND n.tenant_id = o.tenant_id
        LEFT JOIN operation_approvals a ON a.id = o.approval_id AND a.tenant_id = o.tenant_id
        WHERE o.id = ? AND o.tenant_id = ?"
    );
    let mut contexts = Vec::with_capacity(drafts.len());
    for draft in drafts {
        let Some(row) = sqlx::query(&sql)
            .bind(&draft.grant.operation_id)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(StoreError::Database)?
        else {
            continue;
        };
        contexts.push(context_from_sqlite(&row)?);
    }
    Ok(contexts)
}

async fn load_postgres_contexts(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    drafts: &[GrantIssueDraft],
) -> Result<Vec<GrantContext>, StoreError> {
    let columns = operation_columns_prefixed();
    let sql = format!(
        "SELECT {columns} FROM operations o
        JOIN workloads w ON w.id = o.workload_id AND w.tenant_id = o.tenant_id
        JOIN nodes n ON n.id = o.node_id AND n.tenant_id = o.tenant_id
        LEFT JOIN operation_approvals a ON a.id = o.approval_id AND a.tenant_id = o.tenant_id
        WHERE o.id = $1 AND o.tenant_id = $2 FOR UPDATE OF o, w, n"
    );
    let mut contexts = Vec::with_capacity(drafts.len());
    for draft in drafts {
        let Some(row) = sqlx::query(&sql)
            .bind(&draft.grant.operation_id)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(StoreError::Database)?
        else {
            continue;
        };
        contexts.push(context_from_postgres(&row)?);
    }
    Ok(contexts)
}

fn operation_columns_prefixed() -> String {
    "o.id, o.workload_id, o.node_id, o.invocation_id, o.action, o.mode, o.resource_id,
     o.requested_ttl_seconds, o.broker_event_key, o.requested_by, o.purpose, o.policy_version,
     o.decision, o.decision_hash, o.status, o.approval_id, o.grant_id, o.idempotency_key,
     o.request_hash, o.result_json, o.created_at, o.expires_at, o.completed_at, o.version,
     w.id AS joined_workload_id, w.node_id AS joined_node_id, w.unit, w.account,
     w.consumption_mode, w.local_ceiling_seconds, w.status AS workload_status,
     n.status AS node_status, n.key_version AS recipient_key_version, a.status AS approval_status"
        .to_owned()
}

fn context_from_sqlite(row: &SqliteRow) -> Result<GrantContext, StoreError> {
    Ok(GrantContext {
        operation: super::authorization::operation_from_sqlite(row)?,
        workload_id: row
            .try_get("joined_workload_id")
            .map_err(StoreError::Database)?,
        node_id: row
            .try_get("joined_node_id")
            .map_err(StoreError::Database)?,
        unit: row.try_get("unit").map_err(StoreError::Database)?,
        account: row.try_get("account").map_err(StoreError::Database)?,
        mode: row
            .try_get("consumption_mode")
            .map_err(StoreError::Database)?,
        workload_ceiling: row
            .try_get("local_ceiling_seconds")
            .map_err(StoreError::Database)?,
        workload_status: row
            .try_get("workload_status")
            .map_err(StoreError::Database)?,
        node_status: row.try_get("node_status").map_err(StoreError::Database)?,
        recipient_key_version: row
            .try_get("recipient_key_version")
            .map_err(StoreError::Database)?,
        approval_status: row
            .try_get("approval_status")
            .map_err(StoreError::Database)?,
    })
}

fn context_from_postgres(row: &PgRow) -> Result<GrantContext, StoreError> {
    Ok(GrantContext {
        operation: super::authorization::operation_from_postgres(row)?,
        workload_id: row
            .try_get("joined_workload_id")
            .map_err(StoreError::Database)?,
        node_id: row
            .try_get("joined_node_id")
            .map_err(StoreError::Database)?,
        unit: row.try_get("unit").map_err(StoreError::Database)?,
        account: row.try_get("account").map_err(StoreError::Database)?,
        mode: row
            .try_get("consumption_mode")
            .map_err(StoreError::Database)?,
        workload_ceiling: row
            .try_get("local_ceiling_seconds")
            .map_err(StoreError::Database)?,
        workload_status: row
            .try_get("workload_status")
            .map_err(StoreError::Database)?,
        node_status: row.try_get("node_status").map_err(StoreError::Database)?,
        recipient_key_version: row
            .try_get("recipient_key_version")
            .map_err(StoreError::Database)?,
        approval_status: row
            .try_get("approval_status")
            .map_err(StoreError::Database)?,
    })
}

async fn insert_grant_sqlite(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant_id: &str,
    draft: &GrantIssueDraft,
) -> Result<(), StoreError> {
    let envelope = SignedEnvelope::from_json(&draft.envelope_json)
        .map_err(|_| StoreError::InvalidInput("signed grant envelope"))?;
    let body_json = String::from_utf8(
        envelope
            .body_json()
            .map_err(|_| StoreError::InvalidInput("grant body"))?,
    )
    .map_err(|_| StoreError::InvalidInput("grant body"))?;
    let signature = serde_json::from_str::<serde_json::Value>(&draft.envelope_json)
        .ok()
        .and_then(|value| {
            value
                .get("sig")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .ok_or(StoreError::InvalidInput("grant signature"))?;
    let sql = format!("INSERT INTO grants (id, tenant_id, operation_id, node_id, workload_id,
        invocation_id, service_delivery_binding, account, resource_id, recipient_key_id,
        policy_version, approval_reference, request_use_id, unit, action, mode, audience,
        issuer_epoch, issued_at, expires_at, body_json, signature, status, consumed_at, revoked_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', NULL, NULL, {SQLITE_NOW_MS})");
    sqlx::query(&sql)
        .bind(&draft.grant.id)
        .bind(tenant_id)
        .bind(&draft.grant.operation_id)
        .bind(&draft.grant.node_id)
        .bind(&draft.grant.workload_id)
        .bind(&draft.grant.invocation_id)
        .bind(&draft.grant.account)
        .bind(&draft.grant.resource_id)
        .bind(&draft.grant.recipient_key_id)
        .bind(
            i64::try_from(draft.grant.policy_version)
                .map_err(|_| StoreError::InvalidInput("policy version"))?,
        )
        .bind(&draft.grant.approval_reference)
        .bind(&draft.grant.id)
        .bind(&draft.grant.unit)
        .bind(&draft.grant.action)
        .bind(draft.grant.mode.as_str())
        .bind(&draft.grant.audience)
        .bind(
            i64::try_from(draft.grant.issuer_epoch)
                .map_err(|_| StoreError::InvalidInput("issuer epoch"))?,
        )
        .bind(to_i64(draft.grant.issued_at_ms, "grant issue time")?)
        .bind(to_i64(draft.grant.expires_at_ms, "grant expiry")?)
        .bind(body_json)
        .bind(signature)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

async fn insert_grant_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    draft: &GrantIssueDraft,
) -> Result<(), StoreError> {
    let envelope = SignedEnvelope::from_json(&draft.envelope_json)
        .map_err(|_| StoreError::InvalidInput("signed grant envelope"))?;
    let body_json = String::from_utf8(
        envelope
            .body_json()
            .map_err(|_| StoreError::InvalidInput("grant body"))?,
    )
    .map_err(|_| StoreError::InvalidInput("grant body"))?;
    let signature = serde_json::from_str::<serde_json::Value>(&draft.envelope_json)
        .ok()
        .and_then(|value| {
            value
                .get("sig")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .ok_or(StoreError::InvalidInput("grant signature"))?;
    let sql = format!("INSERT INTO grants (id, tenant_id, operation_id, node_id, workload_id,
        invocation_id, service_delivery_binding, account, resource_id, recipient_key_id,
        policy_version, approval_reference, request_use_id, unit, action, mode, audience,
        issuer_epoch, issued_at, expires_at, body_json, signature, status, consumed_at, revoked_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, 'issued', NULL, NULL, {POSTGRES_NOW_MS})");
    sqlx::query(&sql)
        .bind(&draft.grant.id)
        .bind(tenant_id)
        .bind(&draft.grant.operation_id)
        .bind(&draft.grant.node_id)
        .bind(&draft.grant.workload_id)
        .bind(&draft.grant.invocation_id)
        .bind(&draft.grant.account)
        .bind(&draft.grant.resource_id)
        .bind(&draft.grant.recipient_key_id)
        .bind(
            i64::try_from(draft.grant.policy_version)
                .map_err(|_| StoreError::InvalidInput("policy version"))?,
        )
        .bind(&draft.grant.approval_reference)
        .bind(&draft.grant.id)
        .bind(&draft.grant.unit)
        .bind(&draft.grant.action)
        .bind(draft.grant.mode.as_str())
        .bind(&draft.grant.audience)
        .bind(
            i64::try_from(draft.grant.issuer_epoch)
                .map_err(|_| StoreError::InvalidInput("issuer epoch"))?,
        )
        .bind(to_i64(draft.grant.issued_at_ms, "grant issue time")?)
        .bind(to_i64(draft.grant.expires_at_ms, "grant expiry")?)
        .bind(body_json)
        .bind(signature)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::Database)?;
    Ok(())
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput(field))
}

fn grant_from_sqlite(row: &SqliteRow) -> Result<GrantRecord, StoreError> {
    Ok(GrantRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        operation_id: row.try_get("operation_id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        workload_id: row.try_get("workload_id").map_err(StoreError::Database)?,
        invocation_id: row.try_get("invocation_id").map_err(StoreError::Database)?,
        unit: row.try_get("unit").map_err(StoreError::Database)?,
        account: row.try_get("account").map_err(StoreError::Database)?,
        resource_id: row.try_get("resource_id").map_err(StoreError::Database)?,
        recipient_key_id: row
            .try_get("recipient_key_id")
            .map_err(StoreError::Database)?,
        policy_version: row
            .try_get("policy_version")
            .map_err(StoreError::Database)?,
        approval_reference: row
            .try_get("approval_reference")
            .map_err(StoreError::Database)?,
        action: row.try_get("action").map_err(StoreError::Database)?,
        mode: row.try_get("mode").map_err(StoreError::Database)?,
        audience: row.try_get("audience").map_err(StoreError::Database)?,
        issuer_epoch: row.try_get("issuer_epoch").map_err(StoreError::Database)?,
        issued_at_ms: row.try_get("issued_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        consumed_at_ms: row.try_get("consumed_at").map_err(StoreError::Database)?,
        revoked_at_ms: row.try_get("revoked_at").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
    })
}

fn grant_from_postgres(row: &PgRow) -> Result<GrantRecord, StoreError> {
    Ok(GrantRecord {
        id: row.try_get("id").map_err(StoreError::Database)?,
        operation_id: row.try_get("operation_id").map_err(StoreError::Database)?,
        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
        workload_id: row.try_get("workload_id").map_err(StoreError::Database)?,
        invocation_id: row.try_get("invocation_id").map_err(StoreError::Database)?,
        unit: row.try_get("unit").map_err(StoreError::Database)?,
        account: row.try_get("account").map_err(StoreError::Database)?,
        resource_id: row.try_get("resource_id").map_err(StoreError::Database)?,
        recipient_key_id: row
            .try_get("recipient_key_id")
            .map_err(StoreError::Database)?,
        policy_version: row
            .try_get("policy_version")
            .map_err(StoreError::Database)?,
        approval_reference: row
            .try_get("approval_reference")
            .map_err(StoreError::Database)?,
        action: row.try_get("action").map_err(StoreError::Database)?,
        mode: row.try_get("mode").map_err(StoreError::Database)?,
        audience: row.try_get("audience").map_err(StoreError::Database)?,
        issuer_epoch: row.try_get("issuer_epoch").map_err(StoreError::Database)?,
        issued_at_ms: row.try_get("issued_at").map_err(StoreError::Database)?,
        expires_at_ms: row.try_get("expires_at").map_err(StoreError::Database)?,
        status: row.try_get("status").map_err(StoreError::Database)?,
        consumed_at_ms: row.try_get("consumed_at").map_err(StoreError::Database)?,
        revoked_at_ms: row.try_get("revoked_at").map_err(StoreError::Database)?,
        created_at_ms: row.try_get("created_at").map_err(StoreError::Database)?,
    })
}

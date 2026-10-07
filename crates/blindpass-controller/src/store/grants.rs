// SPDX-License-Identifier: AGPL-3.0-only

//! Durable grant issuance and metadata queries.

use super::operation_approvals::{
    closure_targets_postgres, closure_targets_sqlite, enqueue_closures_postgres,
    enqueue_closures_sqlite,
};
use super::{
    AuditDraft, Database, FleetSigner, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    audit::{insert_audit_postgres, insert_audit_sqlite},
    authorization::{
        OperationRecord, enqueue_node_document_postgres, enqueue_node_document_sqlite,
    },
};
use blindpass_core::canon::Value;
use blindpass_core::canon::{canonicalize_value, parse_json};
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
    pub broker_revocation_outcome: Option<String>,
    pub revoked_by: Option<String>,
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
    rotation_pending: bool,
    recipient_key_version: i64,
    approval_status: Option<String>,
}

const GRANT_COLUMNS: &str = "id, operation_id, node_id, workload_id, invocation_id, unit,
    account, resource_id, recipient_key_id, policy_version, approval_reference, action, mode,
    audience, issuer_epoch, issued_at, expires_at, status, consumed_at, revoked_at, created_at,
    broker_revocation_outcome, revoked_by";

impl Store {
    pub async fn grant_by_id(&self, id: &str) -> Result<Option<GrantRecord>, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            match &self.database {
                Database::Sqlite(pool) => {
                    let sql = format!(
                        "SELECT {GRANT_COLUMNS} FROM grants WHERE id = ? AND tenant_id = ?"
                    );
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
                    let sql = format!(
                        "SELECT {GRANT_COLUMNS} FROM grants WHERE id = $1 AND tenant_id = $2"
                    );
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
        })
        .await
    }

    pub async fn list_grants(
        &self,
        node_id: Option<&str>,
        status: Option<&str>,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<GrantRecord>, StoreError> {
        self.run_owned(async {
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
        })
        .await
    }

    /// Issue a bounded group of already-authorized operation grants. Every
    /// operation transition, grant row and node inbox entry commits together.
    pub async fn issue_operation_grants(
        &self,
        drafts: &[GrantIssueDraft],
    ) -> Result<GrantIssueOutcome, StoreError> {
        self.run_owned(async {
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
                let expected_body = canonicalize_value(&value)
                    .map_err(|_| StoreError::InvalidInput("grant body"))?;
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
                    issue_operation_grants_sqlite(
                        pool,
                        &self.tenant_id,
                        drafts,
                        self.fleet_signer.as_ref(),
                    )
                    .await
                }
                Database::Postgres(pool) => {
                    issue_operation_grants_postgres(
                        pool,
                        &self.tenant_id,
                        drafts,
                        self.fleet_signer.as_ref(),
                    )
                    .await
                }
            }
        })
        .await
    }

    /// Revoke an active grant and atomically persist its signed tombstone for
    /// node delivery. A consumed grant reports its registered consumer bound.
    ///
    /// `audit` is written in the same transaction when the grant is revoked
    /// or found consumed, with `outcome` set to the reported status; a
    /// replay of an earlier revocation changes nothing and writes no row.
    pub async fn revoke_grant(
        &self,
        grant_id: &str,
        reason: &str,
        envelope_json: &str,
        revoked_by: Option<&str>,
        audit: &AuditDraft,
    ) -> Result<GrantRevocationOutcome, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            if !matches!(reason, "operator" | "cancelled") {
                return Err(StoreError::InvalidInput("grant revocation reason"));
            }
            match &self.database {
                Database::Sqlite(pool) => {
                    revoke_grant_sqlite(
                        pool,
                        &self.tenant_id,
                        grant_id,
                        reason,
                        envelope_json,
                        revoked_by,
                        audit,
                    )
                    .await
                }
                Database::Postgres(pool) => {
                    revoke_grant_postgres(
                        pool,
                        &self.tenant_id,
                        grant_id,
                        reason,
                        envelope_json,
                        revoked_by,
                        audit,
                    )
                    .await
                }
            }
        })
        .await
    }

    /// Reconcile a broker-signed execution result without accepting arbitrary
    /// provider text or allowing a late result to undo a controller revocation.
    pub async fn reconcile_node_operation_result(
        &self,
        node_id: &str,
        body_json: &str,
    ) -> Result<(), StoreError> {
        self.run_owned(async {
            let body =
                parse_json(body_json).map_err(|_| StoreError::InvalidInput("node result"))?;
            let fields = body
                .as_object()
                .filter(|fields| fields.len() == 5)
                .ok_or(StoreError::InvalidInput("node result"))?;
            if fields.iter().any(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "grant_id" | "operation_id" | "status" | "result_code" | "observed_at_ms"
                )
            }) {
                return Err(StoreError::InvalidInput("node result fields"));
            }
            let grant_id = body
                .get("grant_id")
                .and_then(Value::as_str)
                .filter(|value| valid_node_event_id(value))
                .ok_or(StoreError::InvalidInput("node result grant"))?;
            let operation_id = body
                .get("operation_id")
                .and_then(Value::as_str)
                .filter(|value| valid_node_event_id(value))
                .ok_or(StoreError::InvalidInput("node result operation"))?;
            let status = body
                .get("status")
                .and_then(Value::as_str)
                .filter(|value| matches!(*value, "completed" | "uncertain"))
                .ok_or(StoreError::InvalidInput("node result status"))?;
            let result_code = body
                .get("result_code")
                .and_then(Value::as_str)
                .filter(|value| {
                    matches!(
                        *value,
                        "marker_created" | "browser_session_closed" | "result_uncertain"
                    )
                })
                .ok_or(StoreError::InvalidInput("node result code"))?;
            let observed_at = body
                .get("observed_at_ms")
                .and_then(Value::as_u64)
                .filter(|value| *value > 0)
                .ok_or(StoreError::InvalidInput("node result time"))?;
            let _ = i64::try_from(observed_at)
                .map_err(|_| StoreError::InvalidInput("node result time"))?;
            if (status == "completed") != (result_code != "result_uncertain") {
                return Err(StoreError::InvalidInput("node result binding"));
            }
            let result_json = format!("{{\"result_code\":\"{result_code}\"}}");
            self.checkpoint_clock().await?;
            let (now, lock) = match &self.database {
                Database::Sqlite(_) => (SQLITE_NOW_MS, ""),
                Database::Postgres(_) => (POSTGRES_NOW_MS, " FOR UPDATE OF g, o"),
            };
            let select_sql = format!(
                "SELECT g.status AS grant_status, g.action AS grant_action, g.mode AS grant_mode,
                    o.status AS operation_status, o.result_json
             FROM grants g JOIN operations o ON o.id = g.operation_id AND o.tenant_id = g.tenant_id
             WHERE g.id = ? AND g.node_id = ? AND g.operation_id = ? AND g.tenant_id = ?{lock}"
            );
            let consume_sql = format!(
                "UPDATE grants SET status = CASE WHEN status IN ('issued', 'delivered')
                 THEN 'consumed' ELSE status END,
               consumed_at = COALESCE(consumed_at, {now})
             WHERE id = ? AND tenant_id = ?"
            );
            let operation_sql = format!(
                "UPDATE operations SET status = ?, result_json = ?,
               completed_at = CASE WHEN ? THEN {now} ELSE completed_at END,
               version = version + 1
             WHERE id = ? AND tenant_id = ? AND status = ?"
            );
            macro_rules! reconcile {
                ($pool:expr, $convert:expr) => {{
                    let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                    if matches!(self.database, Database::Sqlite(_)) {
                        sqlx::query(
                            "UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1",
                        )
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                    }
                    let row = sqlx::query(&$convert(&select_sql))
                        .bind(grant_id)
                        .bind(node_id)
                        .bind(operation_id)
                        .bind(&self.tenant_id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                    let Some(row) = row else {
                        tx.rollback().await.map_err(StoreError::Database)?;
                        return Err(StoreError::InvalidInput("node result binding"));
                    };
                    let grant_status: String =
                        row.try_get("grant_status").map_err(StoreError::Database)?;
                    let operation_status: String = row
                        .try_get("operation_status")
                        .map_err(StoreError::Database)?;
                    let existing_result: Option<String> =
                        row.try_get("result_json").map_err(StoreError::Database)?;
                    let grant_action: String =
                        row.try_get("grant_action").map_err(StoreError::Database)?;
                    let grant_mode: String =
                        row.try_get("grant_mode").map_err(StoreError::Database)?;
                    if !result_matches_grant(result_code, &grant_action, &grant_mode) {
                        tx.rollback().await.map_err(StoreError::Database)?;
                        return Err(StoreError::InvalidInput("node result binding"));
                    }
                    if !matches!(
                        grant_status.as_str(),
                        "issued" | "delivered" | "consumed" | "revoked" | "expired"
                    ) {
                        tx.rollback().await.map_err(StoreError::Database)?;
                        return Err(StoreError::InvalidInput("node result grant state"));
                    }
                    let transition = result_transition(
                        status,
                        &operation_status,
                        existing_result.as_deref(),
                        &result_json,
                        result_code,
                    )?;
                    // Any broker result proves the grant was received and used,
                    // including a late result after the controller revoked it.
                    sqlx::query(&$convert(&consume_sql))
                        .bind(grant_id)
                        .bind(&self.tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(StoreError::Database)?;
                    if let Some((next_status, next_result, completed)) = transition {
                        sqlx::query(&$convert(&operation_sql))
                            .bind(next_status)
                            .bind(next_result)
                            .bind(completed)
                            .bind(operation_id)
                            .bind(&self.tenant_id)
                            .bind(&operation_status)
                            .execute(&mut *tx)
                            .await
                            .map_err(StoreError::Database)?;
                    }
                    tx.commit().await.map_err(StoreError::Database)?;
                }};
            }
            match &self.database {
                Database::Sqlite(pool) => reconcile!(pool, |sql: &str| sql.to_owned()),
                Database::Postgres(pool) => reconcile!(pool, super::pg),
            }
            Ok(())
        })
        .await
    }

    /// Audit a correctly signed node event that can never apply. The event
    /// is then acknowledged so it cannot stall the broker queue; the row
    /// keeps identifiers and the stable reason only, never the event body.
    pub async fn record_rejected_node_event(
        &self,
        node_id: &str,
        idempotency_key: &str,
        kind: &str,
        reason_code: &str,
    ) -> Result<(), StoreError> {
        self.run_owned(async {
            let id = format!("rej_{node_id}_{idempotency_key}");
            let metadata = serde_json::json!({
                "idempotency_key": idempotency_key,
                "kind": kind,
                "node_id": node_id,
                "reason_code": reason_code,
            })
            .to_string();
            match &self.database {
                Database::Sqlite(pool) => {
                    let sql = format!("INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES (?, ?, 'node', ?, 'node_event_rejected', 'node_event', ?, ?, {SQLITE_NOW_MS})
                    ON CONFLICT(id) DO NOTHING");
                    sqlx::query(&sql)
                        .bind(&id)
                        .bind(&self.tenant_id)
                        .bind(node_id)
                        .bind(idempotency_key)
                        .bind(&metadata)
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                }
                Database::Postgres(pool) => {
                    let sql = format!("INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES ($1, $2, 'node', $3, 'node_event_rejected', 'node_event', $4, $5, {POSTGRES_NOW_MS})
                    ON CONFLICT(id) DO NOTHING");
                    sqlx::query(&sql)
                        .bind(&id)
                        .bind(&self.tenant_id)
                        .bind(node_id)
                        .bind(idempotency_key)
                        .bind(&metadata)
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                }
            }
            Ok(())
        }).await
    }

    pub async fn record_node_audit_event(
        &self,
        node_id: &str,
        idempotency_key: &str,
        body_json: &str,
    ) -> Result<(), StoreError> {
        self.run_owned(async {
            let body =
                parse_json(body_json).map_err(|_| StoreError::InvalidInput("node audit event"))?;
            // Applying an audit event and recording its node event are separate
            // commits; an identical, already-applied event is acknowledged again
            // rather than failing the now-completed transition a second time.
            if let Some(applied) = self
                .node_audit_metadata(&format!("aud_{node_id}_{idempotency_key}"))
                .await?
            {
                if applied != body_json {
                    return Err(StoreError::InvalidInput("node audit event replay"));
                }
                // The audit row and the revocation finalization commit separately.
                // A retry after a failed finalization must still close the
                // revoked node's channel; finalization is idempotent.
                if body.get("action").and_then(Value::as_str) == Some("node_revocation_applied") {
                    self.finalize_node_revocation(node_id).await?;
                }
                return Ok(());
            }
            let fields = body
                .as_object()
                .filter(|fields| fields.len() <= 5)
                .ok_or(StoreError::InvalidInput("node audit event"))?;
            let action = body
                .get("action")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidInput("node audit event action"))?;
            let finalize_node_revocation = action == "node_revocation_applied";
            let (target_type, target_id) = match action {
                "operation_result" => {
                    if fields.len() != 5
                        || fields.iter().any(|(name, _)| {
                            !matches!(
                                name.as_str(),
                                "action" | "grant_id" | "operation_id" | "observed_at_ms" | "status"
                            )
                        })
                        || !body
                            .get("grant_id")
                            .and_then(Value::as_str)
                            .is_some_and(valid_node_event_id)
                        || !body
                            .get("operation_id")
                            .and_then(Value::as_str)
                            .is_some_and(valid_node_event_id)
                        || !body
                            .get("observed_at_ms")
                            .and_then(Value::as_u64)
                            .is_some_and(|value| value > 0)
                        || !body
                            .get("status")
                            .and_then(Value::as_str)
                            .is_some_and(|value| matches!(value, "completed" | "uncertain"))
                    {
                        return Err(StoreError::InvalidInput("node audit event fields"));
                    }
                    (
                        "operation",
                        body.get("operation_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                }
                "audit_overflow" => {
                    if fields.len() != 3
                        || fields.iter().any(|(name, _)| {
                            !matches!(name.as_str(), "action" | "node_id" | "observed_at_ms")
                        })
                        || body.get("node_id").and_then(Value::as_str) != Some(node_id)
                        || !body
                            .get("observed_at_ms")
                            .and_then(Value::as_u64)
                            .is_some_and(|value| value > 0)
                    {
                        return Err(StoreError::InvalidInput("node audit overflow event"));
                    }
                    ("node", node_id)
                }
                "grant_rejected" => {
                    if fields.len() != 5
                        || fields.iter().any(|(name, _)| {
                            !matches!(
                                name.as_str(),
                                "action" | "expires_at_ms" | "grant_id" | "node_id" | "reason_code"
                            )
                        })
                        || body.get("node_id").and_then(Value::as_str) != Some(node_id)
                        || !body
                            .get("grant_id")
                            .and_then(Value::as_str)
                            .is_some_and(|grant_id| {
                                grant_id.starts_with("gr_") && valid_node_event_id(grant_id)
                            })
                        || !body
                            .get("expires_at_ms")
                            .and_then(Value::as_u64)
                            .is_some_and(|value| value > 0)
                        || !matches!(
                            body.get("reason_code").and_then(Value::as_str),
                            Some("expired_before_receipt" | "binding_mismatch" | "stale_at_receipt")
                        )
                    {
                        return Err(StoreError::InvalidInput("node grant rejection audit"));
                    }
                    let grant_id = body
                        .get("grant_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let expires_at_ms = body
                        .get("expires_at_ms")
                        .and_then(Value::as_u64)
                        .and_then(|value| i64::try_from(value).ok())
                        .ok_or(StoreError::InvalidInput("node grant rejection expiry"))?;
                    let grant_expiry = match &self.database {
                        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
                            "SELECT expires_at FROM grants
                         WHERE id = ? AND node_id = ? AND tenant_id = ?",
                        )
                        .bind(grant_id)
                        .bind(node_id)
                        .bind(&self.tenant_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(StoreError::Database)?,
                        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(
                            "SELECT expires_at FROM grants
                         WHERE id = $1 AND node_id = $2 AND tenant_id = $3",
                        )
                        .bind(grant_id)
                        .bind(node_id)
                        .bind(&self.tenant_id)
                        .fetch_optional(pool)
                        .await
                        .map_err(StoreError::Database)?,
                    };
                    if grant_expiry != Some(expires_at_ms) {
                        return Err(StoreError::InvalidInput(
                            "node grant rejection does not match a current grant expiry",
                        ));
                    }
                    ("grant", grant_id)
                }
                "node_revocation_applied" => {
                    if fields.len() != 3
                        || fields.iter().any(|(name, _)| {
                            !matches!(name.as_str(), "action" | "node_id" | "observed_at_ms")
                        })
                        || body.get("node_id").and_then(Value::as_str) != Some(node_id)
                        || !body
                            .get("observed_at_ms")
                            .and_then(Value::as_u64)
                            .is_some_and(|value| value > 0)
                    {
                        return Err(StoreError::InvalidInput("node revocation acknowledgement"));
                    }
                    let pending = match &self.database {
                        Database::Sqlite(pool) => {
                            sqlx::query_scalar::<_, i64>(
                                "SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_revocation_queue q
                             ON q.node_id = n.id WHERE n.id = ? AND n.tenant_id = ?
                             AND n.status = 'revoked')",
                            )
                            .bind(node_id)
                            .bind(&self.tenant_id)
                            .fetch_one(pool)
                            .await
                            .map_err(StoreError::Database)?
                                == 1
                        }
                        Database::Postgres(pool) => sqlx::query_scalar::<_, bool>(
                            "SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_revocation_queue q
                             ON q.node_id = n.id WHERE n.id = $1 AND n.tenant_id = $2
                             AND n.status = 'revoked')",
                        )
                        .bind(node_id)
                        .bind(&self.tenant_id)
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?,
                    };
                    if !pending {
                        return Err(StoreError::InvalidInput("node revocation is not pending"));
                    }
                    ("node", node_id)
                }
                "node_key_rotation_applied" => {
                    if fields.len() != 5
                        || fields.iter().any(|(name, _)| {
                            !matches!(
                                name.as_str(),
                                "action" | "node_id" | "rotation_id" | "key_version" | "fingerprint"
                            )
                        })
                        || body.get("node_id").and_then(Value::as_str) != Some(node_id)
                        || !body
                            .get("rotation_id")
                            .and_then(Value::as_str)
                            .is_some_and(valid_node_event_id)
                        || !body
                            .get("key_version")
                            .and_then(Value::as_u64)
                            .is_some_and(|value| value > 1)
                        || !body
                            .get("fingerprint")
                            .and_then(Value::as_str)
                            .is_some_and(|value| {
                                value.len() == 64
                                    && value.bytes().all(|byte| {
                                        byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                    })
                            })
                    {
                        return Err(StoreError::InvalidInput(
                            "node key rotation acknowledgement",
                        ));
                    }
                    let rotation_id = body
                        .get("rotation_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let key_version = body
                        .get("key_version")
                        .and_then(Value::as_u64)
                        .and_then(|value| i64::try_from(value).ok())
                        .ok_or(StoreError::InvalidInput("node key rotation version"))?;
                    let fingerprint = body
                        .get("fingerprint")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !self
                        .complete_node_key_rotation(node_id, rotation_id, key_version, fingerprint)
                        .await?
                    {
                        return Err(StoreError::InvalidInput(
                            "node key rotation acknowledgement",
                        ));
                    }
                    ("node", node_id)
                }
                "grant_revocation_applied" => {
                    let grant_id = body.get("grant_id").and_then(Value::as_str);
                    let outcome = body.get("outcome").and_then(Value::as_str);
                    if fields.len() != 5
                        || fields.iter().any(|(name, _)| {
                            !matches!(
                                name.as_str(),
                                "action" | "node_id" | "grant_id" | "outcome" | "observed_at_ms"
                            )
                        })
                        || body.get("node_id").and_then(Value::as_str) != Some(node_id)
                        || !grant_id.is_some_and(valid_node_event_id)
                        || !outcome.is_some_and(|value| {
                            matches!(
                                value,
                                "revoked_before_consumption" | "already_consumed" | "not_received"
                            )
                        })
                        || !body
                            .get("observed_at_ms")
                            .and_then(Value::as_u64)
                            .is_some_and(|value| value > 0)
                    {
                        return Err(StoreError::InvalidInput("grant revocation acknowledgement"));
                    }
                    let grant_id = grant_id.unwrap_or_default();
                    if !self
                        .apply_grant_revocation_outcome(node_id, grant_id, outcome.unwrap_or_default())
                        .await?
                    {
                        return Err(StoreError::InvalidInput(
                            "grant revocation acknowledgement does not match a revoked grant",
                        ));
                    }
                    ("grant", grant_id)
                }
                _ => return Err(StoreError::InvalidInput("node audit event action")),
            };
            let id = format!("aud_{node_id}_{idempotency_key}");
            match &self.database {
                Database::Sqlite(pool) => {
                    let sql = format!("INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES (?, ?, 'node', ?, ?, ?, ?, ?, {SQLITE_NOW_MS})
                    ON CONFLICT(id) DO NOTHING");
                    sqlx::query(&sql)
                        .bind(&id)
                        .bind(&self.tenant_id)
                        .bind(node_id)
                        .bind(action)
                        .bind(target_type)
                        .bind(target_id)
                        .bind(body_json)
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                }
                Database::Postgres(pool) => {
                    let sql = format!("INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
                    VALUES ($1, $2, 'node', $3, $4, $5, $6, $7, {POSTGRES_NOW_MS})
                    ON CONFLICT(id) DO NOTHING");
                    sqlx::query(&sql)
                        .bind(&id)
                        .bind(&self.tenant_id)
                        .bind(node_id)
                        .bind(action)
                        .bind(target_type)
                        .bind(target_id)
                        .bind(body_json)
                        .execute(pool)
                        .await
                        .map_err(StoreError::Database)?;
                }
            }
            if finalize_node_revocation {
                self.finalize_node_revocation(node_id).await?;
            }
            Ok(())
        }).await
    }

    async fn finalize_node_revocation(&self, node_id: &str) -> Result<(), StoreError> {
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                let deleted = sqlx::query(
                    "DELETE FROM node_revocation_queue WHERE node_id = ? AND EXISTS (
                       SELECT 1 FROM nodes WHERE id = ? AND tenant_id = ? AND status = 'revoked'
                     )",
                )
                .bind(node_id)
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if deleted > 0 {
                    sqlx::query(&format!(
                        "UPDATE node_sessions SET revoked_at = {SQLITE_NOW_MS}
                         WHERE node_id = ? AND revoked_at IS NULL"
                    ))
                    .bind(node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(&format!(
                        "UPDATE node_inbox SET acked_at = {SQLITE_NOW_MS}
                         WHERE node_id = ? AND acked_at IS NULL AND delivered_at IS NOT NULL"
                    ))
                    .bind(node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                }
                tx.commit().await.map_err(StoreError::Database)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(StoreError::Database)?;
                let deleted = sqlx::query(
                    "DELETE FROM node_revocation_queue WHERE node_id = $1 AND EXISTS (
                       SELECT 1 FROM nodes WHERE id = $1 AND tenant_id = $2 AND status = 'revoked'
                     )",
                )
                .bind(node_id)
                .bind(&self.tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
                if deleted > 0 {
                    sqlx::query(&format!(
                        "UPDATE node_sessions SET revoked_at = {POSTGRES_NOW_MS}
                         WHERE node_id = $1 AND revoked_at IS NULL"
                    ))
                    .bind(node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                    sqlx::query(&format!(
                        "UPDATE node_inbox SET acked_at = {POSTGRES_NOW_MS}
                         WHERE node_id = $1 AND acked_at IS NULL AND delivered_at IS NOT NULL"
                    ))
                    .bind(node_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                }
                tx.commit().await.map_err(StoreError::Database)
            }
        }
    }
}

fn valid_node_event_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

async fn revoke_grant_sqlite(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    grant_id: &str,
    reason: &str,
    envelope_json: &str,
    revoked_by: Option<&str>,
    audit: &AuditDraft,
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
        "SELECT g.status, g.consumed_at, g.node_id, g.workload_id, g.operation_id, g.expires_at,
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
    let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(StoreError::Database)?;
    if status == "consumed" || (status == "revoked" && consumed_at.is_some()) {
        let audit = revocation_audit(audit, CONSUMED_OUTCOME);
        insert_audit_sqlite(&mut tx, tenant_id, &audit).await?;
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
        "UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ?
        WHERE id = ? AND tenant_id = ? AND status IN ('issued', 'delivered')",
    )
    .bind(now)
    .bind(revoked_by)
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
        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until, envelope_json)
        VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(grant_id)
    .bind(&node_id)
    .bind(reason)
    .bind(now)
    .bind(to_i64(revocation.retain_until_ms, "tombstone retention")?)
    .bind(envelope_json)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    enqueue_node_document_sqlite(&mut tx, &node_id, envelope_json).await?;
    let audit = revocation_audit(audit, revoked_outcome(offline));
    insert_audit_sqlite(&mut tx, tenant_id, &audit).await?;
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
    revoked_by: Option<&str>,
    audit: &AuditDraft,
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
        "SELECT g.status, g.consumed_at, g.node_id, g.workload_id, g.operation_id, g.expires_at,
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
    let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(StoreError::Database)?;
    if status == "consumed" || (status == "revoked" && consumed_at.is_some()) {
        let audit = revocation_audit(audit, CONSUMED_OUTCOME);
        insert_audit_postgres(&mut tx, tenant_id, &audit).await?;
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
        "UPDATE grants SET status = 'revoked', revoked_at = $1, revoked_by = $4
        WHERE id = $2 AND tenant_id = $3 AND status IN ('issued', 'delivered')",
    )
    .bind(now)
    .bind(grant_id)
    .bind(tenant_id)
    .bind(revoked_by)
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
        "INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until, envelope_json)
        VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(grant_id)
    .bind(&node_id)
    .bind(reason)
    .bind(now)
    .bind(to_i64(revocation.retain_until_ms, "tombstone retention")?)
    .bind(envelope_json)
    .execute(&mut *tx)
    .await
    .map_err(StoreError::Database)?;
    enqueue_node_document_postgres(&mut tx, &node_id, envelope_json).await?;
    let audit = revocation_audit(audit, revoked_outcome(offline));
    insert_audit_postgres(&mut tx, tenant_id, &audit).await?;
    tx.commit().await.map_err(StoreError::Database)?;
    Ok(GrantRevocationOutcome::Revoked {
        grant_id: grant_id.to_owned(),
        offline,
    })
}

/// Response and audit status of a revocation requested after consumption.
const CONSUMED_OUTCOME: &str = "grant_revoked_after_consumption";

/// Response and audit status of a completed revocation.
fn revoked_outcome(offline: bool) -> &'static str {
    if offline {
        "not_revocable_offline"
    } else {
        "grant_revoked"
    }
}

fn revocation_audit(audit: &AuditDraft, outcome: &str) -> AuditDraft {
    audit.clone().with_detail("outcome", outcome.into())
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
    signer: Option<&FleetSigner>,
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
        for context in &contexts {
            if context.operation.requested_by.starts_with("workload:") {
                let signer = signer.ok_or(StoreError::MissingState("browser denial issuer"))?;
                let targets = closure_targets_sqlite(
                    &mut tx,
                    tenant_id,
                    "o.id = ?",
                    &[&context.operation.id],
                )
                .await?;
                enqueue_closures_sqlite(&mut tx, Some(signer), &targets, "denied").await?;
                let audit = AuditDraft {
                    action: "fleet.operation_denied".to_owned(), actor_type: "workload".to_owned(),
                    actor_id: Some(context.operation.workload_id.clone()), target_type: "operation".to_owned(),
                    target_id: Some(context.operation.id.clone()),
                    metadata: serde_json::json!({"target_type":"operation", "outcome":"authorization_changed",
                        "node_id":context.operation.node_id, "workload_id":context.operation.workload_id,
                        "policy_version":context.operation.policy_version, "broker_event_key":context.operation.broker_event_key})
                        .as_object().expect("literal object").clone(),
                };
                insert_audit_sqlite(&mut tx, tenant_id, &audit).await?;
            }
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
    signer: Option<&FleetSigner>,
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
        for context in &contexts {
            if context.operation.requested_by.starts_with("workload:") {
                let signer = signer.ok_or(StoreError::MissingState("browser denial issuer"))?;
                let targets = closure_targets_postgres(
                    &mut tx,
                    tenant_id,
                    "o.id = ?",
                    &[&context.operation.id],
                )
                .await?;
                enqueue_closures_postgres(&mut tx, Some(signer), &targets, "denied").await?;
                let audit = AuditDraft {
                    action: "fleet.operation_denied".to_owned(), actor_type: "workload".to_owned(),
                    actor_id: Some(context.operation.workload_id.clone()), target_type: "operation".to_owned(),
                    target_id: Some(context.operation.id.clone()),
                    metadata: serde_json::json!({"target_type":"operation", "outcome":"authorization_changed",
                        "node_id":context.operation.node_id, "workload_id":context.operation.workload_id,
                        "policy_version":context.operation.policy_version, "broker_event_key":context.operation.broker_event_key})
                        .as_object().expect("literal object").clone(),
                };
                insert_audit_postgres(&mut tx, tenant_id, &audit).await?;
            }
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
        && (!(context.operation.requested_by.starts_with("workload:")
            && context.operation.decision == "allow")
            || expires_at <= context.operation.expires_at_ms)
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
        && !context.rotation_pending
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
     n.status AS node_status, n.key_version AS recipient_key_version, a.status AS approval_status,
     EXISTS (SELECT 1 FROM node_key_rotations r WHERE r.node_id = n.id) AS rotation_pending"
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
        rotation_pending: row
            .try_get("rotation_pending")
            .map_err(StoreError::Database)?,
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
        rotation_pending: row
            .try_get("rotation_pending")
            .map_err(StoreError::Database)?,
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
        broker_revocation_outcome: row
            .try_get("broker_revocation_outcome")
            .map_err(StoreError::Database)?,
        revoked_by: row.try_get("revoked_by").map_err(StoreError::Database)?,
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
        broker_revocation_outcome: row
            .try_get("broker_revocation_outcome")
            .map_err(StoreError::Database)?,
        revoked_by: row.try_get("revoked_by").map_err(StoreError::Database)?,
    })
}

/// The typed result recorded when a broker used a grant the controller had
/// already revoked.
pub(super) const REVOKED_AFTER_CONSUMPTION: &str = "grant_revoked_after_consumption";

/// Merge the post-consumption revocation result into an operation result,
/// keeping the original revocation reason and any broker result code.
pub(super) fn with_revocation_result(existing: Option<&str>, result_code: Option<&str>) -> String {
    let mut fields = existing
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    fields.insert(
        "revocation_result".to_owned(),
        serde_json::Value::String(REVOKED_AFTER_CONSUMPTION.to_owned()),
    );
    if let Some(code) = result_code {
        fields.insert(
            "result_code".to_owned(),
            serde_json::Value::String(code.to_owned()),
        );
    }
    serde_json::Value::Object(fields).to_string()
}

/// Decide how a broker result moves its operation: `uncertain` means the
/// broker started execution without confirming it; `completed` is final.
/// Returns the next status, result and whether it completes the operation,
/// or `None` when the result changes nothing (replays, later evidence).
fn result_matches_grant(code: &str, action: &str, mode: &str) -> bool {
    match code {
        "browser_session_closed" => action == "browser.session" && mode == "browser_session",
        "marker_created" => action == "noop.marker" && matches!(mode, "file" | "socket"),
        "result_uncertain" => true,
        _ => false,
    }
}

fn result_transition(
    status: &str,
    operation_status: &str,
    existing_result: Option<&str>,
    result_json: &str,
    result_code: &str,
) -> Result<Option<(&'static str, String, bool)>, StoreError> {
    Ok(match (status, operation_status) {
        ("completed", "granted" | "executing" | "uncertain") => {
            Some(("completed", result_json.to_owned(), true))
        }
        ("uncertain", "granted") => Some(("executing", result_json.to_owned(), false)),
        ("completed", "completed") | ("uncertain", "executing" | "completed" | "uncertain") => None,
        (_, "revoked") => {
            // Revocation remains authoritative, while confirmed execution or
            // cleanup evidence must not regress to a late provisional result.
            let confirmed = existing_result
                .and_then(|result| serde_json::from_str::<serde_json::Value>(result).ok())
                .is_some_and(|result| {
                    matches!(
                        result
                            .get("result_code")
                            .and_then(serde_json::Value::as_str),
                        Some("marker_created" | "browser_session_closed")
                    )
                });
            if status == "uncertain" && confirmed {
                return Ok(None);
            }
            let merged = with_revocation_result(existing_result, Some(result_code));
            (existing_result != Some(merged.as_str())).then_some(("revoked", merged, false))
        }
        (_, "cancelled" | "failed" | "expired") => None,
        _ => return Err(StoreError::InvalidInput("node result operation state")),
    })
}

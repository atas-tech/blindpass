// SPDX-License-Identifier: AGPL-3.0-only

//! Apply already signature-verified browser cancellation in the same transaction
//! as its evidence, approval membership, signed closure and grant tombstone.
use super::{
    Database, NodeEventInsert, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    authorization::{
        OPERATION_COLUMNS, enqueue_node_document_postgres, enqueue_node_document_sqlite,
        operation_from_postgres, operation_from_sqlite,
    },
    grants::with_revocation_result,
};
use blindpass_core::canon::parse_json;
use blindpass_core::fleet::{DocumentKind, OperationCancellation, OperationClosed, Revocation};
use serde_json::Value;
use sqlx::Row;

const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

macro_rules! apply_cancel {
    ($store:expr, $pool:expr, $convert:expr, $now:expr, $meta_lock:expr,
     $from_row:path, $enqueue:path, $request:expr, $key:expr, $body:expr, $hash:expr) => {{
        let request: &OperationCancellation = $request;
        let tenant = &$store.tenant_id;
        let signer = $store.fleet_signer.as_ref().ok_or(StoreError::MissingState("fleet cancellation issuer"))?;
        let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query($meta_lock).execute(&mut *tx).await.map_err(StoreError::Database)?;
        let prior: Option<String> = sqlx::query_scalar(&$convert("SELECT body_hash FROM node_events WHERE node_id = ? AND idempotency_key = ?"))
            .bind(&request.node_id).bind($key).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
        if let Some(prior) = prior {
            tx.rollback().await.map_err(StoreError::Database)?;
            return Ok(if prior == $hash { NodeEventInsert::Duplicate } else { NodeEventInsert::Conflict });
        }
        let original: Option<String> = sqlx::query_scalar(&$convert(
            "SELECT e.body_json FROM node_events e JOIN nodes n ON n.id = e.node_id
             WHERE n.tenant_id = ? AND e.node_id = ? AND e.idempotency_key = ? AND e.kind = 'operation_request'"))
            .bind(tenant).bind(&request.node_id).bind(&request.request_event_key)
            .fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
        let original: Value = serde_json::from_str(&original.ok_or(StoreError::InvalidInput("cancellation request evidence"))?)
            .map_err(|_| StoreError::InvalidInput("cancellation request evidence"))?;
        if original["node_id"] != request.node_id || original["workload_id"] != request.workload_id
            || original["invocation_id"] != request.invocation_id
            || original["action"] != "browser.session" || original["mode"] != "browser_session" {
            return Err(StoreError::InvalidInput("cancellation owner mismatch"));
        }
        let meta = sqlx::query(&format!("SELECT issuer_epoch, {} AS now_ms FROM controller_meta WHERE id = 1", $now))
            .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
        let now: i64 = meta.try_get("now_ms").map_err(StoreError::Database)?;
        let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
        let epoch = u64::try_from(epoch).map_err(|_| StoreError::InvalidInput("cancellation issuer epoch"))?;
        let now_unsigned = u64::try_from(now).map_err(|_| StoreError::InvalidInput("cancellation time"))?;
        let rows = sqlx::query(&$convert(&format!(
            "SELECT {OPERATION_COLUMNS} FROM operations WHERE tenant_id = ? AND node_id = ? AND broker_event_key = ?")))
            .bind(tenant).bind(&request.node_id).bind(&request.request_event_key)
            .fetch_all(&mut *tx).await.map_err(StoreError::Database)?;
        if rows.len() > 1 { return Err(StoreError::InvalidInput("ambiguous cancellation evidence")); }
        let operation = rows.first().map($from_row).transpose()?;
        let operation_id = operation.as_ref().map_or_else(|| format!("op_{}", $key), |operation| operation.id.clone());
        let mut outcome = "request_cancelled";
        if let Some(operation) = operation {
            if operation.workload_id != request.workload_id || operation.invocation_id != request.invocation_id
                || operation.action != "browser.session" || operation.mode != "browser_session" {
                return Err(StoreError::InvalidInput("cancellation operation mismatch"));
            }
            if operation.status == "awaiting_approval" {
                if let Some(approval_id) = &operation.approval_id {
                    let row = sqlx::query(&$convert("SELECT operation_ids_json, status FROM operation_approvals WHERE id = ? AND tenant_id = ?"))
                        .bind(approval_id).bind(tenant).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                    let status: String = row.try_get("status").map_err(StoreError::Database)?;
                    if status == "pending" {
                        let encoded: String = row.try_get("operation_ids_json").map_err(StoreError::Database)?;
                        let mut members: Vec<String> = serde_json::from_str(&encoded).map_err(|_| StoreError::InvalidInput("cancellation approval members"))?;
                        if !members.contains(&operation.id) { return Err(StoreError::InvalidInput("cancellation approval membership")); }
                        members.retain(|id| id != &operation.id);
                        let encoded = serde_json::to_string(&members).map_err(|_| StoreError::InvalidInput("cancellation approval members"))?;
                        sqlx::query(&$convert("UPDATE operation_approvals SET operation_ids_json = ?,
                            status = CASE WHEN ? THEN 'expired' ELSE status END,
                            decided_at = CASE WHEN ? THEN ? ELSE decided_at END,
                            version = version + 1 WHERE id = ? AND tenant_id = ? AND status = 'pending'"))
                            .bind(encoded).bind(members.is_empty()).bind(members.is_empty()).bind(now)
                            .bind(approval_id).bind(tenant).execute(&mut *tx).await.map_err(StoreError::Database)?;
                    }
                }
            }
            let mut consumed = false;
            if let Some(grant_id) = &operation.grant_id {
                let row = sqlx::query(&$convert("SELECT status, consumed_at, expires_at FROM grants WHERE id = ? AND tenant_id = ? AND node_id = ? AND operation_id = ?"))
                    .bind(grant_id).bind(tenant).bind(&request.node_id).bind(&operation.id)
                    .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                let status: String = row.try_get("status").map_err(StoreError::Database)?;
                let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(StoreError::Database)?;
                consumed = status == "consumed" || consumed_at.is_some();
                if status != "revoked" {
                    // Consumed browser authority can still have a copied website
                    // session. Revoke it too; prior consumer results are preserved.
                    let expires: i64 = row.try_get("expires_at").map_err(StoreError::Database)?;
                    let retain = now.max(expires).checked_add(RETENTION_MS).ok_or(StoreError::InvalidInput("cancellation retention"))?;
                    let revocation = Revocation { grant_id: grant_id.clone(), node_id: request.node_id.clone(),
                        reason: "cancelled".into(), revoked_at_ms: now_unsigned,
                        retain_until_ms: u64::try_from(retain).map_err(|_| StoreError::InvalidInput("cancellation retention"))?, issuer_epoch: epoch };
                    let envelope = signer.sign(DocumentKind::Revocation, revocation.to_value().map_err(|_| StoreError::InvalidInput("cancellation revocation"))?, epoch)?;
                    sqlx::query(&$convert("UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ? WHERE id = ? AND tenant_id = ?"))
                        .bind(now).bind(format!("workload:{}", request.workload_id)).bind(grant_id).bind(tenant)
                        .execute(&mut *tx).await.map_err(StoreError::Database)?;
                    sqlx::query(&$convert("INSERT INTO grant_tombstones (grant_id, node_id, reason, created_at, retain_until, envelope_json)
                        VALUES (?, ?, 'cancelled', ?, ?, ?) ON CONFLICT (grant_id) DO NOTHING"))
                        .bind(grant_id).bind(&request.node_id).bind(now).bind(retain).bind(&envelope)
                        .execute(&mut *tx).await.map_err(StoreError::Database)?;
                    $enqueue(&mut tx, &request.node_id, &envelope).await?;
                }
            }
            let next = match operation.status.as_str() {
                "requested" | "awaiting_approval" => Some("cancelled"),
                "granted" | "executing" | "uncertain" => Some("revoked"),
                _ => None,
            };
            if let Some(status) = next {
                let result = if status == "revoked" && consumed { with_revocation_result(operation.result_json.as_deref(), None) }
                    else { r#"{"reason":"workload_cancelled"}"#.into() };
                sqlx::query(&$convert("UPDATE operations SET status = ?, result_json = ?, completed_at = ?, version = version + 1 WHERE id = ? AND tenant_id = ?"))
                    .bind(status).bind(result).bind(now).bind(&operation.id).bind(tenant)
                    .execute(&mut *tx).await.map_err(StoreError::Database)?;
                outcome = status;
            } else {
                if consumed {
                    sqlx::query(&$convert("UPDATE operations SET result_json = ?, version = version + 1 WHERE id = ? AND tenant_id = ?"))
                        .bind(with_revocation_result(operation.result_json.as_deref(), None)).bind(&operation.id).bind(tenant)
                        .execute(&mut *tx).await.map_err(StoreError::Database)?;
                }
                outcome = "terminal_authority_withdrawn";
            }
        }
        let closed = OperationClosed { node_id: request.node_id.clone(), operation_id: operation_id.clone(),
            request_event_key: request.request_event_key.clone(), status: "cancelled".into(), closed_at_ms: now_unsigned, issuer_epoch: epoch };
        let envelope = signer.sign(DocumentKind::OperationClosed, closed.to_value().map_err(|_| StoreError::InvalidInput("cancellation closure"))?, epoch)?;
        $enqueue(&mut tx, &request.node_id, &envelope).await?;
        let metadata = serde_json::json!({"request_event_key":request.request_event_key,"invocation_id":request.invocation_id,"outcome":outcome}).to_string();
        sqlx::query(&$convert("INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, target_type, target_id, metadata_json, created_at)
            VALUES (?, ?, 'workload', ?, 'fleet.workload_cancelled', 'operation', ?, ?, ?)"))
            .bind(format!("aud_{}", $key)).bind(tenant).bind(&request.workload_id).bind(&operation_id).bind(metadata).bind(now)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        sqlx::query(&$convert("INSERT INTO node_events (id, node_id, idempotency_key, kind, body_json, body_hash, received_at)
            VALUES (?, ?, ?, 'operation_cancel', ?, ?, ?)"))
            .bind(format!("ne_{}", $key)).bind(&request.node_id).bind($key).bind($body).bind($hash).bind(now)
            .execute(&mut *tx).await.map_err(StoreError::Database)?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(NodeEventInsert::Inserted)
    }};
}

impl Store {
    /// Caller must authenticate the node and verify its broker signature first.
    pub async fn apply_browser_cancellation(
        &self,
        node_id: &str,
        key: &str,
        body_json: &str,
        body_hash: &str,
    ) -> Result<NodeEventInsert, StoreError> {
        self.run_owned(async {
            self.checkpoint_clock().await?;
            let body =
                parse_json(body_json).map_err(|_| StoreError::InvalidInput("cancellation body"))?;
            let request = OperationCancellation::from_value(&body)
                .map_err(|_| StoreError::InvalidInput("cancellation binding"))?;
            if request.node_id != node_id
                || request
                    .event_key()
                    .map_err(|_| StoreError::InvalidInput("cancellation key"))?
                    != key
            {
                return Err(StoreError::InvalidInput("cancellation node/key"));
            }
            match &self.database {
                Database::Sqlite(pool) => apply_cancel!(
                    self,
                    pool,
                    |sql: &str| sql.to_owned(),
                    SQLITE_NOW_MS,
                    "UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1",
                    operation_from_sqlite,
                    enqueue_node_document_sqlite,
                    &request,
                    key,
                    body_json,
                    body_hash
                ),
                Database::Postgres(pool) => apply_cancel!(
                    self,
                    pool,
                    super::pg,
                    POSTGRES_NOW_MS,
                    "SELECT issuer_epoch FROM controller_meta WHERE id = 1 FOR UPDATE",
                    operation_from_postgres,
                    enqueue_node_document_postgres,
                    &request,
                    key,
                    body_json,
                    body_hash
                ),
            }
        })
        .await
    }
}

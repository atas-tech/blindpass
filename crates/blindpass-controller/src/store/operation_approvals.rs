// SPDX-License-Identifier: AGPL-3.0-only

//! Operation approval groups: stable-scope grouping, named approvers,
//! decisions, cancellation, expiry and signed operation closures.

use super::{
    AuditDraft, Database, FleetSigner, POSTGRES_NOW_MS, SQLITE_NOW_MS, Store, StoreError,
    audit::{insert_audit_postgres, insert_audit_sqlite},
    authorization::{
        OPERATION_APPROVAL_COLUMNS, OPERATION_COLUMNS, OperationApprovalDraft,
        OperationDecisionOutcome, OperationRecord, enqueue_node_document_postgres,
        enqueue_node_document_sqlite, operation_approval_from_postgres,
        operation_approval_from_sqlite, operation_from_postgres, operation_from_sqlite,
    },
    fleet_lifecycle::{
        FleetExpirySummary, sign_pending_tombstones_postgres, sign_pending_tombstones_sqlite,
    },
};
use blindpass_core::fleet::{DocumentKind, OperationClosed};
use sqlx::{Postgres, Row, Sqlite, Transaction};

/// Members an approval group may hold before a new group starts.
const GROUP_LIMIT: usize = 10;
/// Rows moved to a terminal state by one expiry pass, per category.
const EXPIRY_BATCH: i64 = 200;

/// An operation that needs a signed closure because the broker recorded its
/// request and is waiting for an outcome.
pub(super) struct ClosureTarget {
    operation_id: String,
    node_id: String,
    event_key: String,
}

/// Inputs to an approval decision.
pub struct OperationDecision<'a> {
    pub id: &'a str,
    pub expected_version: i64,
    pub expected_operation_ids: &'a [String],
    pub decision: &'a str,
    pub decided_by: &'a str,
    pub decider_username: &'a str,
    pub decision_key_hash: &'a str,
    /// Written in the decision's transaction for every outcome that is
    /// decided or denied (including scope and self-approval denials), with
    /// `outcome` replaced by the result; replays, conflicts and missing
    /// approvals write no row.
    pub audit: &'a AuditDraft,
}

/// Result of cancelling an operation that awaits approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationCancelOutcome {
    Cancelled(Box<OperationRecord>),
    NotFound,
    Conflict,
}

const CLOSURE_TARGETS: &str = "SELECT o.id, o.node_id, o.broker_event_key FROM operations o
    JOIN nodes n ON n.id = o.node_id AND n.tenant_id = o.tenant_id
    WHERE o.tenant_id = ? AND o.broker_event_key IS NOT NULL AND n.status = 'active' AND ";

fn closure_envelope(
    signer: &FleetSigner,
    target: &ClosureTarget,
    status: &str,
    now_ms: i64,
    epoch: i64,
) -> Result<String, StoreError> {
    let epoch = u64::try_from(epoch).map_err(|_| StoreError::InvalidInput("issuer epoch"))?;
    let body = OperationClosed {
        node_id: target.node_id.clone(),
        operation_id: target.operation_id.clone(),
        request_event_key: target.event_key.clone(),
        status: status.to_owned(),
        closed_at_ms: u64::try_from(now_ms)
            .map_err(|_| StoreError::InvalidInput("operation closure time"))?,
        issuer_epoch: epoch,
    }
    .to_value()
    .map_err(|_| StoreError::InvalidInput("operation closure"))?;
    signer.sign(DocumentKind::OperationClosed, body, epoch)
}

macro_rules! closure_helpers {
    ($targets:ident, $enqueue_closures:ident, $db:ty, $convert:expr, $now:expr, $enqueue:path) => {
        /// Operations matching `condition` whose broker request awaits an
        /// outcome on an active node.
        pub(super) async fn $targets(
            tx: &mut Transaction<'_, $db>,
            tenant_id: &str,
            condition: &str,
            binds: &[&str],
        ) -> Result<Vec<ClosureTarget>, StoreError> {
            let sql = $convert(&format!(
                "{CLOSURE_TARGETS}{condition} ORDER BY o.created_at, o.id"
            ));
            let mut query = sqlx::query(&sql).bind(tenant_id);
            for bind in binds {
                query = query.bind(*bind);
            }
            let rows = query
                .fetch_all(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
            rows.iter()
                .map(|row| {
                    Ok(ClosureTarget {
                        operation_id: row.try_get("id").map_err(StoreError::Database)?,
                        node_id: row.try_get("node_id").map_err(StoreError::Database)?,
                        event_key: row
                            .try_get("broker_event_key")
                            .map_err(StoreError::Database)?,
                    })
                })
                .collect()
        }

        /// Queue a signed OperationClosed document for each target in the
        /// caller's transaction. Without a configured issuer nothing is sent.
        pub(super) async fn $enqueue_closures(
            tx: &mut Transaction<'_, $db>,
            signer: Option<&FleetSigner>,
            targets: &[ClosureTarget],
            status: &str,
        ) -> Result<(), StoreError> {
            let Some(signer) = signer else {
                return Ok(());
            };
            if targets.is_empty() {
                return Ok(());
            }
            let sql = format!(
                "SELECT issuer_epoch, {} AS now_ms FROM controller_meta WHERE id = 1",
                $now
            );
            let row = sqlx::query(&sql)
                .fetch_one(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
            let epoch: i64 = row.try_get("issuer_epoch").map_err(StoreError::Database)?;
            let now_ms: i64 = row.try_get("now_ms").map_err(StoreError::Database)?;
            for target in targets {
                let envelope = closure_envelope(signer, target, status, now_ms, epoch)?;
                $enqueue(tx, &target.node_id, &envelope).await?;
            }
            Ok(())
        }
    };
}

closure_helpers!(
    closure_targets_sqlite,
    enqueue_closures_sqlite,
    Sqlite,
    |sql: &str| sql.to_owned(),
    SQLITE_NOW_MS,
    enqueue_node_document_sqlite
);
closure_helpers!(
    closure_targets_postgres,
    enqueue_closures_postgres,
    Postgres,
    super::pg,
    POSTGRES_NOW_MS,
    enqueue_node_document_postgres
);

macro_rules! extend_approval {
    ($tx:expr, $convert:expr, $now:expr, $lock:expr, $from_row:path,
     $tenant_id:expr, $operation_id:expr, $draft:expr) => {{
        let tx = $tx;
        let draft: &OperationApprovalDraft = $draft;
        let sql = $convert(&format!(
            "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
             WHERE tenant_id = ? AND status = 'pending' AND rule_id = ? AND group_scope_hash = ?
               AND expires_at > {} ORDER BY created_at DESC, id DESC LIMIT 50{}",
            $now, $lock
        ));
        let candidates = sqlx::query(&sql)
            .bind($tenant_id)
            .bind(&draft.rule_id)
            .bind(&draft.group_scope_hash)
            .fetch_all(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
        let update = $convert(
            "UPDATE operation_approvals SET operation_ids_json = ?, version = version + 1
             WHERE id = ? AND tenant_id = ? AND status = 'pending' AND version = ?",
        );
        for row in candidates {
            let candidate = $from_row(&row)?;
            let mut operation_ids: Vec<String> =
                serde_json::from_str(&candidate.operation_ids_json)
                    .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
            if operation_ids.len() >= GROUP_LIMIT
                || operation_ids.iter().any(|id| id == $operation_id)
            {
                continue;
            }
            operation_ids.push($operation_id.to_owned());
            let encoded = serde_json::to_string(&operation_ids)
                .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
            let changed = sqlx::query(&update)
                .bind(encoded)
                .bind(&candidate.id)
                .bind($tenant_id)
                .bind(candidate.version)
                .execute(&mut **tx)
                .await
                .map_err(StoreError::Database)?;
            if changed.rows_affected() == 1 {
                return Ok(candidate.id);
            }
        }
        let operation_ids = serde_json::to_string(&vec![$operation_id])
            .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
        let insert = $convert(&format!(
            "INSERT INTO operation_approvals (id, tenant_id, operation_ids_json,
               requester_summary_json, verified_identity_json, rule_id, status, expires_at,
               idempotency_key, version, created_at, approver_ids_json, group_scope_hash)
             VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, 1, {}, ?, ?)",
            $now
        ));
        sqlx::query(&insert)
            .bind(&draft.id)
            .bind($tenant_id)
            .bind(operation_ids)
            .bind(&draft.requester_summary_json)
            .bind(&draft.verified_identity_json)
            .bind(&draft.rule_id)
            .bind(draft.expires_at_ms)
            .bind(&draft.idempotency_key)
            .bind(&draft.approver_ids_json)
            .bind(&draft.group_scope_hash)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::Database)?;
        Ok(draft.id.clone())
    }};
}

/// Join the newest pending group with the same stable scope that still has
/// room, or start a new one. The scope hash covers tenant, node, workload,
/// unit, account, action, mode, rule and policy version, so a group never
/// mixes authorities; each member keeps its own invocation evidence.
pub(super) async fn create_or_extend_approval_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    operation_id: &str,
    draft: &OperationApprovalDraft,
) -> Result<String, StoreError> {
    extend_approval!(
        tx,
        |sql: &str| sql.to_owned(),
        SQLITE_NOW_MS,
        "",
        operation_approval_from_sqlite,
        tenant_id,
        operation_id,
        draft
    )
}

pub(super) async fn create_or_extend_approval_postgres(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    operation_id: &str,
    draft: &OperationApprovalDraft,
) -> Result<String, StoreError> {
    extend_approval!(
        tx,
        super::pg,
        POSTGRES_NOW_MS,
        " FOR UPDATE",
        operation_approval_from_postgres,
        tenant_id,
        operation_id,
        draft
    )
}

macro_rules! decide {
    ($pool:expr, $convert:expr, $now:expr, $lock:expr, $meta_lock:expr, $from_row:path,
     $targets:ident, $closures:ident, $audit:path, $tenant_id:expr, $signer:expr,
     $input:expr) => {{
        let input: &OperationDecision<'_> = $input;
        let tenant_id: &str = $tenant_id;
        let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query($meta_lock)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let select = $convert(&format!(
            "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
             WHERE id = ? AND tenant_id = ?{}",
            $lock
        ));
        let Some(row) = sqlx::query(&select)
            .bind(input.id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?
        else {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationDecisionOutcome::NotFound);
        };
        let approval = $from_row(&row)?;
        let target_status = if input.decision == "approved" {
            "approved"
        } else {
            "rejected"
        };
        let stored_ids: Vec<String> = serde_json::from_str(&approval.operation_ids_json)
            .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
        if approval.status == target_status
            && approval.version == input.expected_version.saturating_add(1)
            && approval.decided_by.as_deref() == Some(input.decided_by)
            && approval.decision_key_hash.as_deref() == Some(input.decision_key_hash)
            && stored_ids == input.expected_operation_ids
        {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationDecisionOutcome::Replayed(approval));
        }
        if !matches!(input.decision, "approved" | "rejected")
            || approval.status != "pending"
            || approval.version != input.expected_version
            || stored_ids != input.expected_operation_ids
            || stored_ids.is_empty()
            || stored_ids.len() > GROUP_LIMIT
        {
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationDecisionOutcome::Conflict);
        }
        let approver_ids: Vec<String> = serde_json::from_str(&approval.approver_ids_json)
            .map_err(|_| StoreError::InvalidInput("approval approver ids"))?;
        if !approver_ids
            .iter()
            .any(|approver| approver == input.decided_by || approver == input.decider_username)
        {
            // The denial changes no state but is recorded durably: a failed
            // audit insert fails the request rather than dropping the row.
            let audit = input
                .audit
                .clone()
                .with_detail("outcome", "approval_scope_denied".into());
            $audit(&mut tx, tenant_id, &audit).await?;
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationDecisionOutcome::ScopeDenied);
        }
        let own: i64 = sqlx::query_scalar(&$convert(
            "SELECT COUNT(*) FROM operations
             WHERE approval_id = ? AND tenant_id = ? AND requested_by = ?",
        ))
        .bind(input.id)
        .bind(tenant_id)
        .bind(input.decided_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if own > 0 {
            let audit = input
                .audit
                .clone()
                .with_detail("outcome", "self_approval_denied".into());
            $audit(&mut tx, tenant_id, &audit).await?;
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationDecisionOutcome::SelfApproval);
        }
        let now: i64 = sqlx::query_scalar(&format!("SELECT {}", $now))
            .fetch_one(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let members = $targets(
            &mut tx,
            tenant_id,
            "o.approval_id = ? AND o.status = 'awaiting_approval'",
            &[input.id],
        )
        .await?;
        let close_members = $convert(&format!(
            "UPDATE operations SET status = 'denied', result_json = ?, completed_at = {},
               version = version + 1
             WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'",
            $now
        ));
        let mut stale = approval.expires_at_ms <= now;
        let expired = stale;
        if !stale {
            let policy_version: Option<i64> = sqlx::query_scalar(&$convert(
                "SELECT version FROM fleet_policies WHERE tenant_id = ?",
            ))
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            let current_policy = policy_version.unwrap_or(1);
            let member_sql = $convert(&format!(
                "SELECT o.policy_version, o.status, o.expires_at,
                        w.status AS workload_status, n.status AS node_status
                 FROM operations o JOIN workloads w ON w.id = o.workload_id
                 JOIN nodes n ON n.id = o.node_id
                 WHERE o.id = ? AND o.tenant_id = ? AND o.approval_id = ?{}",
                $lock
            ));
            for operation_id in &stored_ids {
                let row = sqlx::query(&member_sql)
                    .bind(operation_id)
                    .bind(tenant_id)
                    .bind(input.id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                let Some(row) = row else {
                    stale = true;
                    break;
                };
                let operation_policy: i64 = row
                    .try_get("policy_version")
                    .map_err(StoreError::Database)?;
                let operation_status: String =
                    row.try_get("status").map_err(StoreError::Database)?;
                let operation_expiry: i64 =
                    row.try_get("expires_at").map_err(StoreError::Database)?;
                let workload_status: String = row
                    .try_get("workload_status")
                    .map_err(StoreError::Database)?;
                let node_status: String =
                    row.try_get("node_status").map_err(StoreError::Database)?;
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
        }
        if stale {
            // Expired or no longer matching current authority: the group ends
            // without a decision and its brokers learn why.
            let (reason, closure) = if expired {
                (r#"{"reason":"approval_expired"}"#, "expired")
            } else {
                (r#"{"reason":"authorization_changed"}"#, "denied")
            };
            sqlx::query(&$convert(&format!(
                "UPDATE operation_approvals SET status = 'expired', decided_at = {},
                   version = version + 1
                 WHERE id = ? AND tenant_id = ? AND status = 'pending'",
                $now
            )))
            .bind(input.id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            sqlx::query(&close_members)
                .bind(reason)
                .bind(input.id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            $closures(&mut tx, $signer, &members, closure).await?;
            let audit = input
                .audit
                .clone()
                .with_detail("outcome", "ended_without_decision".into());
            $audit(&mut tx, tenant_id, &audit).await?;
            tx.commit().await.map_err(StoreError::Database)?;
            return Ok(OperationDecisionOutcome::StalePolicy);
        }
        sqlx::query(&$convert(&format!(
            "UPDATE operation_approvals SET status = ?, decided_by = ?, decided_at = {},
               decision_key_hash = ?, version = version + 1
             WHERE id = ? AND tenant_id = ? AND status = 'pending' AND version = ?",
            $now
        )))
        .bind(target_status)
        .bind(input.decided_by)
        .bind(input.decision_key_hash)
        .bind(input.id)
        .bind(tenant_id)
        .bind(input.expected_version)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if target_status == "approved" {
            sqlx::query(&$convert(&format!(
                "UPDATE operations SET status = 'requested',
                   expires_at = {} + requested_ttl_seconds * 1000, version = version + 1
                 WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'",
                $now
            )))
            .bind(input.id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        } else {
            sqlx::query(&close_members)
                .bind(r#"{"reason":"approval_rejected"}"#)
                .bind(input.id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?;
            $closures(&mut tx, $signer, &members, "rejected").await?;
        }
        let row = sqlx::query(&select)
            .bind(input.id)
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let updated = $from_row(&row)?;
        let audit = input
            .audit
            .clone()
            .with_detail("outcome", target_status.into());
        $audit(&mut tx, tenant_id, &audit).await?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(OperationDecisionOutcome::Applied(updated))
    }};
}

macro_rules! cancel_awaiting_impl {
    ($pool:expr, $convert:expr, $now:expr, $lock:expr, $meta_lock:expr, $from_row:path,
     $operation_from_row:path, $targets:ident, $closures:ident, $audit:path, $tenant_id:expr,
     $signer:expr, $operation_id:expr, $cancelled_by:expr, $audit_draft:expr) => {{
        let tenant_id: &str = $tenant_id;
        let operation_id: &str = $operation_id;
        let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query($meta_lock)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        let row = sqlx::query(&$convert(&format!(
            "SELECT status, approval_id FROM operations WHERE id = ? AND tenant_id = ?{}",
            $lock
        )))
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let Some(row) = row else {
            tx.rollback().await.map_err(StoreError::Database)?;
            return Ok(OperationCancelOutcome::NotFound);
        };
        let status: String = row.try_get("status").map_err(StoreError::Database)?;
        let approval_id: Option<String> =
            row.try_get("approval_id").map_err(StoreError::Database)?;
        if status != "awaiting_approval" {
            tx.rollback().await.map_err(StoreError::Database)?;
            return Ok(OperationCancelOutcome::Conflict);
        }
        let targets = $targets(&mut tx, tenant_id, "o.id = ?", &[operation_id]).await?;
        sqlx::query(&$convert(&format!(
            "UPDATE operations SET status = 'cancelled', result_json = ?, completed_at = {},
               version = version + 1
             WHERE id = ? AND tenant_id = ? AND status = 'awaiting_approval'",
            $now
        )))
        .bind(r#"{"reason":"operator_cancelled"}"#)
        .bind(operation_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        if let Some(approval_id) = approval_id {
            let select = $convert(&format!(
                "SELECT {OPERATION_APPROVAL_COLUMNS} FROM operation_approvals
                 WHERE id = ? AND tenant_id = ?{}",
                $lock
            ));
            if let Some(row) = sqlx::query(&select)
                .bind(&approval_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(StoreError::Database)?
            {
                let approval = $from_row(&row)?;
                let mut ids: Vec<String> = serde_json::from_str(&approval.operation_ids_json)
                    .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
                ids.retain(|id| id != operation_id);
                let encoded = serde_json::to_string(&ids)
                    .map_err(|_| StoreError::InvalidInput("approval operation ids"))?;
                if approval.status == "pending" {
                    // The member leaves its group, which changes the group
                    // version; an emptied group ends without a decision.
                    sqlx::query(&$convert(&format!(
                        "UPDATE operation_approvals SET operation_ids_json = ?,
                           status = CASE WHEN ? THEN 'expired' ELSE status END,
                           decided_by = CASE WHEN ? THEN ? ELSE decided_by END,
                           decided_at = CASE WHEN ? THEN {} ELSE decided_at END,
                           version = version + 1
                         WHERE id = ? AND tenant_id = ? AND status = 'pending'",
                        $now
                    )))
                    .bind(encoded)
                    .bind(ids.is_empty())
                    .bind(ids.is_empty())
                    .bind($cancelled_by)
                    .bind(ids.is_empty())
                    .bind(&approval_id)
                    .bind(tenant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(StoreError::Database)?;
                }
            }
        }
        $closures(&mut tx, $signer, &targets, "cancelled").await?;
        let row = sqlx::query(&$convert(&format!(
            "SELECT {OPERATION_COLUMNS} FROM operations WHERE id = ? AND tenant_id = ?"
        )))
        .bind(operation_id)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let operation = $operation_from_row(&row)?;
        let audit: &AuditDraft = $audit_draft;
        let audit = audit
            .clone()
            .with_detail("outcome", operation.status.clone().into());
        $audit(&mut tx, tenant_id, &audit).await?;
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(OperationCancelOutcome::Cancelled(Box::new(operation)))
    }};
}

macro_rules! expire {
    ($pool:expr, $convert:expr, $now:expr, $meta_lock:expr, $targets:ident, $closures:ident, $sign:ident,
     $tenant_id:expr, $signer:expr) => {{
        let tenant_id: &str = $tenant_id;
        let mut summary = FleetExpirySummary::default();
        let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query($meta_lock)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        // Approval groups past their deadline end and close their members.
        let approval_ids: Vec<String> = sqlx::query_scalar(&$convert(&format!(
            "SELECT id FROM operation_approvals
             WHERE tenant_id = ? AND status = 'pending' AND expires_at <= {}
             ORDER BY expires_at, id LIMIT ?",
            $now
        )))
        .bind(tenant_id)
        .bind(EXPIRY_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for approval_id in &approval_ids {
            let members = $targets(
                &mut tx,
                tenant_id,
                "o.approval_id = ? AND o.status = 'awaiting_approval'",
                &[approval_id.as_str()],
            )
            .await?;
            sqlx::query(&$convert(&format!(
                "UPDATE operation_approvals SET status = 'expired', decided_at = {},
                   version = version + 1
                 WHERE id = ? AND tenant_id = ? AND status = 'pending'",
                $now
            )))
            .bind(approval_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
            summary.expired_operations += sqlx::query(&$convert(&format!(
                "UPDATE operations SET status = 'denied', result_json = ?, completed_at = {},
                   version = version + 1
                 WHERE approval_id = ? AND tenant_id = ? AND status = 'awaiting_approval'",
                $now
            )))
            .bind(r#"{"reason":"approval_expired"}"#)
            .bind(approval_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            $closures(&mut tx, $signer, &members, "expired").await?;
        }
        summary.expired_approvals = approval_ids.len() as u64;
        // Operations that were never granted within their own deadline.
        let stale_condition = format!(
            "o.status IN ('requested', 'awaiting_approval') AND o.expires_at <= {}",
            $now
        );
        let targets = $targets(&mut tx, tenant_id, &stale_condition, &[]).await?;
        let operation_ids: Vec<String> = sqlx::query_scalar(&$convert(&format!(
            "SELECT id FROM operations
             WHERE tenant_id = ? AND status IN ('requested', 'awaiting_approval')
               AND expires_at <= {} ORDER BY expires_at, id LIMIT ?",
            $now
        )))
        .bind(tenant_id)
        .bind(EXPIRY_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        let deny = $convert(&format!(
            "UPDATE operations SET status = 'denied', result_json = ?, completed_at = {},
               version = version + 1
             WHERE id = ? AND tenant_id = ? AND status IN ('requested', 'awaiting_approval')",
            $now
        ));
        for operation_id in &operation_ids {
            summary.expired_operations += sqlx::query(&deny)
                .bind(r#"{"reason":"expired"}"#)
                .bind(operation_id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(StoreError::Database)?
                .rows_affected();
        }
        let targets = targets
            .into_iter()
            .filter(|target| operation_ids.contains(&target.operation_id))
            .collect::<Vec<_>>();
        $closures(&mut tx, $signer, &targets, "expired").await?;
        // Grants past their expiry. An operation whose grant was never
        // delivered failed; one that may have run is uncertain.
        let grants = sqlx::query(&$convert(&format!(
            "SELECT id, operation_id, status FROM grants
             WHERE tenant_id = ? AND status IN ('issued', 'delivered') AND expires_at <= {}
             ORDER BY expires_at, id LIMIT ?",
            $now
        )))
        .bind(tenant_id)
        .bind(EXPIRY_BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::Database)?;
        for grant in &grants {
            let grant_id: String = grant.try_get("id").map_err(StoreError::Database)?;
            let operation_id: String = grant
                .try_get("operation_id")
                .map_err(StoreError::Database)?;
            let grant_status: String = grant.try_get("status").map_err(StoreError::Database)?;
            summary.expired_grants += sqlx::query(&$convert(
                "UPDATE grants SET status = 'expired'
                 WHERE id = ? AND tenant_id = ? AND status IN ('issued', 'delivered')",
            ))
            .bind(&grant_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?
            .rows_affected();
            let granted_status = if grant_status == "issued" {
                "failed"
            } else {
                "uncertain"
            };
            sqlx::query(&$convert(&format!(
                "UPDATE operations SET
                   status = CASE WHEN status = 'granted' THEN ? ELSE 'uncertain' END,
                   result_json = CASE WHEN status = 'granted' THEN ? ELSE result_json END,
                   completed_at = {}, version = version + 1
                 WHERE id = ? AND tenant_id = ? AND status IN ('granted', 'executing')",
                $now
            )))
            .bind(granted_status)
            .bind(r#"{"reason":"grant_expired"}"#)
            .bind(&operation_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(StoreError::Database)?;
        }
        // The broker reports `uncertain` before consuming and `completed`
        // after the effect. Past the grant deadline it can no longer confirm
        // an execution, so an operation still executing is uncertain.
        summary.unconfirmed_operations = sqlx::query(&$convert(&format!(
            "UPDATE operations SET status = 'uncertain', result_json = ?,
               completed_at = {now}, version = version + 1
             WHERE tenant_id = ? AND status = 'executing' AND id IN (
               SELECT o.id FROM operations o JOIN grants g ON g.id = o.grant_id
               WHERE o.tenant_id = ? AND o.status = 'executing' AND g.expires_at <= {now}
               ORDER BY g.expires_at, o.id LIMIT ?)",
            now = $now
        )))
        .bind(r#"{"reason":"completion_unconfirmed"}"#)
        .bind(tenant_id)
        .bind(tenant_id)
        .bind(EXPIRY_BATCH)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::Database)?
        .rows_affected();
        if let Some(signer) = $signer {
            summary.signed_tombstones = $sign(&mut tx, signer, tenant_id).await?;
        }
        tx.commit().await.map_err(StoreError::Database)?;
        Ok(summary)
    }};
}

const SQLITE_META_LOCK: &str =
    "UPDATE controller_meta SET issuer_epoch = issuer_epoch WHERE id = 1";
const POSTGRES_META_LOCK: &str = "SELECT id FROM controller_meta WHERE id = 1 FOR UPDATE";

impl Store {
    /// Decide an operation approval group. Only an operator named by the
    /// rule may decide, and never one who requested any member.
    pub async fn decide_operation_approval(
        &self,
        input: &OperationDecision<'_>,
    ) -> Result<OperationDecisionOutcome, StoreError> {
        self.checkpoint_clock().await?;
        let signer = self.fleet_signer.as_ref();
        match &self.database {
            Database::Sqlite(pool) => decide!(
                pool,
                |sql: &str| sql.to_owned(),
                SQLITE_NOW_MS,
                "",
                SQLITE_META_LOCK,
                operation_approval_from_sqlite,
                closure_targets_sqlite,
                enqueue_closures_sqlite,
                insert_audit_sqlite,
                &self.tenant_id,
                signer,
                input
            ),
            Database::Postgres(pool) => decide!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                " FOR UPDATE",
                POSTGRES_META_LOCK,
                operation_approval_from_postgres,
                closure_targets_postgres,
                enqueue_closures_postgres,
                insert_audit_postgres,
                &self.tenant_id,
                signer,
                input
            ),
        }
    }

    /// Cancel (dismiss) an operation that still awaits approval, remove it
    /// from its group and tell the broker the request is closed. `audit` is
    /// written in the same transaction with `outcome` set to the new status.
    pub async fn cancel_awaiting_operation(
        &self,
        operation_id: &str,
        cancelled_by: &str,
        audit: &AuditDraft,
    ) -> Result<OperationCancelOutcome, StoreError> {
        self.checkpoint_clock().await?;
        let signer = self.fleet_signer.as_ref();
        match &self.database {
            Database::Sqlite(pool) => cancel_awaiting_impl!(
                pool,
                |sql: &str| sql.to_owned(),
                SQLITE_NOW_MS,
                "",
                SQLITE_META_LOCK,
                operation_approval_from_sqlite,
                operation_from_sqlite,
                closure_targets_sqlite,
                enqueue_closures_sqlite,
                insert_audit_sqlite,
                &self.tenant_id,
                signer,
                operation_id,
                cancelled_by,
                audit
            ),
            Database::Postgres(pool) => cancel_awaiting_impl!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                " FOR UPDATE",
                POSTGRES_META_LOCK,
                operation_approval_from_postgres,
                operation_from_postgres,
                closure_targets_postgres,
                enqueue_closures_postgres,
                insert_audit_postgres,
                &self.tenant_id,
                signer,
                operation_id,
                cancelled_by,
                audit
            ),
        }
    }

    /// Move expired approval groups, ungranted operations and grants to
    /// their terminal states, closing broker requests. Bounded per call; the
    /// list and count paths and the periodic maintenance task all run it.
    pub async fn expire_fleet_state(&self) -> Result<FleetExpirySummary, StoreError> {
        self.checkpoint_clock().await?;
        let signer = self.fleet_signer.as_ref();
        match &self.database {
            Database::Sqlite(pool) => expire!(
                pool,
                |sql: &str| sql.to_owned(),
                SQLITE_NOW_MS,
                SQLITE_META_LOCK,
                closure_targets_sqlite,
                enqueue_closures_sqlite,
                sign_pending_tombstones_sqlite,
                &self.tenant_id,
                signer
            ),
            Database::Postgres(pool) => expire!(
                pool,
                super::pg,
                POSTGRES_NOW_MS,
                POSTGRES_META_LOCK,
                closure_targets_postgres,
                enqueue_closures_postgres,
                sign_pending_tombstones_postgres,
                &self.tenant_id,
                signer
            ),
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Operator review, node waivers and the review-complete barrier for protected
//! recovery activation (P06-D30..D32). Everything here is metadata in the
//! independent authority; none of it activates a record. Activation is the
//! administrator-only `activate_recovery` function.
use super::{AuthorityError, ProcessOwnership, deadline, receipts::conflict, safe_integer};
use sqlx::Row;
use std::sync::Arc;

pub const CATEGORIES: [&str; 9] = [
    "operation",
    "agent",
    "operator",
    "legacy_policy",
    "fleet_policy",
    "workload",
    "source_binding",
    "node_key_rotation",
    "grant_intent",
];
pub const DECISIONS: [&str; 3] = ["accept", "reject", "revoke"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReviewKey {
    pub category: String,
    pub subject_id: String,
    pub related_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDecision {
    pub key: ReviewKey,
    pub decision: String,
    pub operator_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCoverage {
    pub node_id: String,
    pub revoked: bool,
    /// `covered`, `collecting`, `incomplete`, `rebase_required` or `None` (never reported).
    pub receipt: Option<String>,
    pub waived: bool,
}

fn operator_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'@' | b'-'))
}

fn note_text(value: &str) -> bool {
    value.len() <= 512 && !value.chars().any(char::is_control)
}

impl ReviewKey {
    pub(crate) fn validate(&self) -> Result<(), AuthorityError> {
        if !CATEGORIES.contains(&self.category.as_str())
            || self.subject_id.is_empty()
            || self.subject_id.len() > 256
            || self.related_id.len() > 256
        {
            return Err(AuthorityError::InvalidInput);
        }
        Ok(())
    }
}

impl ProcessOwnership {
    /// Records or replaces one decision until the review is completed. A `false`
    /// result (completed review, lost holder) is a definite refusal.
    pub async fn decide_recovery_item(
        self: &Arc<Self>,
        key: &ReviewKey,
        decision: &str,
        operator: &str,
        note: &str,
    ) -> Result<(), AuthorityError> {
        key.validate()?;
        if !DECISIONS.contains(&decision) || !operator_text(operator) || !note_text(note) {
            return Err(AuthorityError::InvalidInput);
        }
        let granted = self.receipt_work(true, async {
            sqlx::query_scalar::<_, bool>("SELECT blindpass_authority.decide_recovery_item($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
                .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id)
                .bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(self.backend_pid).bind(self.process_token.as_bytes())
                .bind(&key.category).bind(&key.subject_id).bind(&key.related_id).bind(decision).bind(operator).bind(note)
                .fetch_one(&self.pool).await.map_err(conflict)
        }).await?;
        granted.then_some(()).ok_or(AuthorityError::Conflict)
    }

    /// Named waiver for a node that cannot report. The authority also revokes the
    /// node's broker trust in the same transaction.
    pub async fn waive_recovery_node(
        self: &Arc<Self>,
        node_id: &str,
        operator: &str,
        note: &str,
    ) -> Result<(), AuthorityError> {
        if !blindpass_core::fleet::is_valid_opaque_id(node_id)
            || !operator_text(operator)
            || !note_text(note)
        {
            return Err(AuthorityError::InvalidInput);
        }
        let granted = self.receipt_work(true, async {
            sqlx::query_scalar::<_, bool>("SELECT blindpass_authority.waive_recovery_node($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind(&self.context.tenant_id).bind(&self.context.issuer_key_id).bind(&self.context.owner_id)
                .bind(self.record.epoch as i64).bind(self.record.revision as i64).bind(self.backend_pid).bind(self.process_token.as_bytes())
                .bind(node_id).bind(operator).bind(note)
                .fetch_one(&self.pool).await.map_err(conflict)
        }).await?;
        granted.then_some(()).ok_or(AuthorityError::Conflict)
    }

    /// Declares the review complete once `count` decisions exist. Decisions and
    /// waivers are refused afterwards.
    pub async fn complete_recovery_review(
        self: &Arc<Self>,
        count: u64,
    ) -> Result<(), AuthorityError> {
        if !safe_integer(count) {
            return Err(AuthorityError::InvalidInput);
        }
        let granted = self
            .receipt_work(true, async {
                sqlx::query_scalar::<_, bool>(
                    "SELECT blindpass_authority.complete_recovery_review($1,$2,$3,$4,$5,$6,$7,$8)",
                )
                .bind(&self.context.tenant_id)
                .bind(&self.context.issuer_key_id)
                .bind(&self.context.owner_id)
                .bind(self.record.epoch as i64)
                .bind(self.record.revision as i64)
                .bind(self.backend_pid)
                .bind(self.process_token.as_bytes())
                .bind(count as i64)
                .fetch_one(&self.pool)
                .await
                .map_err(conflict)
            })
            .await?;
        granted.then_some(()).ok_or(AuthorityError::Conflict)
    }

    /// Unmet authority-side gates by fixed name, without the process-guard check
    /// (this process holds the guard itself).
    pub async fn recovery_activation_gaps(self: &Arc<Self>) -> Result<Vec<String>, AuthorityError> {
        self.receipt_work(false, async {
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT blindpass_authority.recovery_activation_gaps($1,$2,$3,FALSE)",
            )
            .bind(&self.context.tenant_id)
            .bind(&self.context.issuer_key_id)
            .bind(&self.context.owner_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AuthorityError::Unavailable)
        })
        .await
    }

    pub async fn recovery_decisions(
        self: &Arc<Self>,
    ) -> Result<Vec<RecoveryDecision>, AuthorityError> {
        self.receipt_work(false, async {
            let rows = sqlx::query("SELECT category,subject_id,related_id,decision,operator_id FROM blindpass_authority.recovery_review_decisions WHERE tenant_id=$1 AND epoch=$2 ORDER BY category,subject_id,related_id")
                .bind(&self.context.tenant_id)
                .bind(self.record.epoch as i64)
                .fetch_all(&self.pool)
                .await
                .map_err(|_| AuthorityError::Unavailable)?;
            rows.into_iter()
                .map(|row| {
                    let text = |name: &str| {
                        row.try_get::<String, _>(name)
                            .map_err(|_| AuthorityError::Unavailable)
                    };
                    Ok(RecoveryDecision {
                        key: ReviewKey {
                            category: text("category")?,
                            subject_id: text("subject_id")?,
                            related_id: text("related_id")?,
                        },
                        decision: text("decision")?,
                        operator_id: text("operator_id")?,
                    })
                })
                .collect()
        })
        .await
    }

    /// Every broker the authority trusts for this tenant with its coverage at the
    /// current recovery epoch. The authority, not the controller snapshot, defines
    /// which nodes must report or be waived.
    pub async fn recovery_coverage(self: &Arc<Self>) -> Result<Vec<NodeCoverage>, AuthorityError> {
        self.receipt_work(false, async {
            let rows = sqlx::query(
                "SELECT t.node_id,(t.state='revoked') AS revoked,\
                 (SELECT c.state FROM blindpass_authority.recovery_challenges c WHERE c.tenant_id=t.tenant_id AND c.node_id=t.node_id AND c.epoch=$2 AND c.authority_revision=$3 ORDER BY (c.state='covered') DESC LIMIT 1) AS receipt,\
                 EXISTS(SELECT 1 FROM blindpass_authority.recovery_node_waivers w WHERE w.tenant_id=t.tenant_id AND w.node_id=t.node_id AND w.epoch=$2) AS waived \
                 FROM blindpass_authority.broker_trust t WHERE t.tenant_id=$1 ORDER BY t.node_id",
            )
            .bind(&self.context.tenant_id)
            .bind(self.record.epoch as i64)
            .bind(self.record.revision as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
            rows.into_iter()
                .map(|row| {
                    Ok(NodeCoverage {
                        node_id: row.try_get("node_id").map_err(|_| AuthorityError::Unavailable)?,
                        revoked: row.try_get("revoked").map_err(|_| AuthorityError::Unavailable)?,
                        receipt: row.try_get("receipt").map_err(|_| AuthorityError::Unavailable)?,
                        waived: row.try_get("waived").map_err(|_| AuthorityError::Unavailable)?,
                    })
                })
                .collect()
        })
        .await
    }

    /// True only when `activate_recovery` activated exactly this recovery epoch. The
    /// controller opens a recovered store for ordinary service against this proof alone;
    /// fencing a recovering record and re-activating it elsewhere leaves no such row.
    pub async fn recovery_activation_recorded(&self, epoch: u64) -> Result<bool, AuthorityError> {
        if !safe_integer(epoch) {
            return Err(AuthorityError::InvalidInput);
        }
        self.check().await?;
        deadline(async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM blindpass_authority.recovery_activations WHERE tenant_id=$1 AND epoch=$2)",
            )
            .bind(&self.context.tenant_id)
            .bind(epoch as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AuthorityError::Unavailable)
        })
        .await
    }
}

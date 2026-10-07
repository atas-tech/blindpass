// SPDX-License-Identifier: AGPL-3.0-only
//! Operator review of quarantined recovery items and its local effect (P06-D30..D32).
//! Decisions, waivers and the completion barrier live in the authority; this module
//! enumerates what must be decided and applies the one local consequence: accepted
//! operator accounts are re-enabled and waived nodes are revoked.
use super::{Database, RecoveryRow, SELECT, Store, StoreError, StoredRecovery, reports::authority};
use crate::recovery_authority::{AuthorityError, NodeCoverage, ProcessOwnership, ReviewKey};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

type ItemRow = (String, String, String, String);

/// A definite authority refusal is the operator's answer, not a lost holder: it must
/// not fence the controller the way an uncertain outcome does.
fn definite<T>(result: Result<T, AuthorityError>) -> Result<Result<T, StoreError>, StoreError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(AuthorityError::Conflict | AuthorityError::InvalidInput) => {
            Ok(Err(StoreError::InvalidInput("recovery review")))
        }
        Err(AuthorityError::Unavailable) => Err(StoreError::AuthorityFenced),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReviewItem {
    pub category: String,
    pub subject_id: String,
    pub related_id: String,
    pub snapshot_status: String,
    pub decision: Option<String>,
    pub operator_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryActivationStatus {
    pub recovery_id: String,
    pub target_epoch: u64,
    pub items: u64,
    pub undecided: u64,
    pub nodes: Vec<RecoveryNodeStatus>,
    /// Fixed gate names. `source_stop_missing` is the administrator's step and is
    /// expected until the controller is stopped and the attestation is recorded.
    pub gaps: Vec<String>,
    pub activation_permitted: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryNodeStatus {
    pub node_id: String,
    pub revoked: bool,
    pub receipt: Option<String>,
    pub waived: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReviewCompletion {
    pub items: u64,
    pub operators_enabled: u64,
    pub nodes_revoked: u64,
}

impl From<NodeCoverage> for RecoveryNodeStatus {
    fn from(value: NodeCoverage) -> Self {
        Self {
            node_id: value.node_id,
            revoked: value.revoked,
            receipt: value.receipt,
            waived: value.waived,
        }
    }
}

impl Store {
    async fn current_review_recovery(
        &self,
        owner: &Arc<ProcessOwnership>,
    ) -> Result<StoredRecovery, StoreError> {
        let sql = format!("{SELECT} WHERE tenant_id=? ORDER BY target_epoch DESC LIMIT 1");
        let row = match &self.database {
            Database::Sqlite(p) => sqlx::query_as::<_, RecoveryRow>(&sql)
                .bind(&self.tenant_id)
                .fetch_optional(p)
                .await
                .map_err(StoreError::Database)?,
            Database::Postgres(p) => sqlx::query_as::<_, RecoveryRow>(&crate::store::pg(&sql))
                .bind(&self.tenant_id)
                .fetch_optional(p)
                .await
                .map_err(StoreError::Database)?,
        };
        let current = row
            .map(StoredRecovery::parse)
            .transpose()?
            .ok_or(StoreError::MissingState("recovery metadata"))?;
        if !current.matches(owner) || current.status.phase != "invalidated" {
            return Err(StoreError::InvalidInput("recovery reservation"));
        }
        Ok(current)
    }

    async fn review_item_rows(&self, recovery_id: &str) -> Result<Vec<ItemRow>, StoreError> {
        // Matched intents are covered by their operation's decision; only intents the
        // controller could not reconcile need their own.
        let sql = "SELECT 'operation',operation_id,'',snapshot_status FROM controller_recovery_operations WHERE recovery_id=? \
            UNION ALL SELECT category,subject_id,related_id,snapshot_status FROM controller_recovery_reviews WHERE recovery_id=? \
            UNION ALL SELECT 'grant_intent',grant_id,node_id,mapping FROM controller_recovery_intents WHERE recovery_id=? AND mapping<>'matched' \
            ORDER BY 1,2,3";
        match &self.database {
            Database::Sqlite(p) => sqlx::query_as::<_, ItemRow>(sql)
                .bind(recovery_id)
                .bind(recovery_id)
                .bind(recovery_id)
                .fetch_all(p)
                .await
                .map_err(StoreError::Database),
            Database::Postgres(p) => sqlx::query_as::<_, ItemRow>(&crate::store::pg(sql))
                .bind(recovery_id)
                .bind(recovery_id)
                .bind(recovery_id)
                .fetch_all(p)
                .await
                .map_err(StoreError::Database),
        }
    }

    /// Everything the operator must decide, with the decision recorded so far.
    pub async fn recovery_review_items(
        &self,
        owner: &Arc<ProcessOwnership>,
    ) -> Result<Vec<RecoveryReviewItem>, StoreError> {
        self.recovery_boundary(owner, async {
            let current = self.current_review_recovery(owner).await?;
            let decisions: BTreeMap<ReviewKey, _> = authority(owner.recovery_decisions().await)?
                .into_iter()
                .map(|decision| (decision.key.clone(), decision))
                .collect();
            Ok(self
                .review_item_rows(&current.status.recovery_id)
                .await?
                .into_iter()
                .map(|(category, subject_id, related_id, snapshot_status)| {
                    let key = ReviewKey {
                        category,
                        subject_id,
                        related_id,
                    };
                    let decision = decisions.get(&key);
                    RecoveryReviewItem {
                        decision: decision.map(|d| d.decision.clone()),
                        operator_id: decision.map(|d| d.operator_id.clone()),
                        snapshot_status,
                        category: key.category,
                        subject_id: key.subject_id,
                        related_id: key.related_id,
                    }
                })
                .collect())
        })
        .await
    }

    /// Only an enumerated item can be decided; the authority keeps the decision.
    pub async fn decide_recovery_review(
        &self,
        owner: &Arc<ProcessOwnership>,
        key: &ReviewKey,
        decision: &str,
        operator: &str,
        note: &str,
    ) -> Result<(), StoreError> {
        let items = self.recovery_review_items(owner).await?;
        if !items.iter().any(|item| {
            item.category == key.category
                && item.subject_id == key.subject_id
                && item.related_id == key.related_id
        }) {
            return Err(StoreError::InvalidInput("recovery review item"));
        }
        self.recovery_boundary(owner, async {
            definite(
                owner
                    .decide_recovery_item(key, decision, operator, note)
                    .await,
            )
        })
        .await?
    }

    /// Named waiver for a node that cannot report. Its broker trust is revoked in the
    /// authority; the local revocation follows when the review is completed.
    pub async fn waive_recovery_node(
        &self,
        owner: &Arc<ProcessOwnership>,
        node_id: &str,
        operator: &str,
        note: &str,
    ) -> Result<(), StoreError> {
        self.recovery_boundary(owner, async {
            self.current_review_recovery(owner).await?;
            definite(owner.waive_recovery_node(node_id, operator, note).await)
        })
        .await?
    }

    /// Item counts, node coverage and the gates still open, without changing anything.
    pub async fn recovery_activation_status(
        &self,
        owner: &Arc<ProcessOwnership>,
    ) -> Result<RecoveryActivationStatus, StoreError> {
        let items = self.recovery_review_items(owner).await?;
        self.recovery_boundary(owner, async {
            let current = self.current_review_recovery(owner).await?;
            let undecided = items.iter().filter(|i| i.decision.is_none()).count() as u64;
            let mut gaps = authority(owner.recovery_activation_gaps().await)?;
            if undecided > 0 {
                gaps.push("review_undecided".into());
            }
            let nodes = authority(owner.recovery_coverage().await)?
                .into_iter()
                .map(RecoveryNodeStatus::from)
                .collect();
            Ok(RecoveryActivationStatus {
                recovery_id: current.status.recovery_id,
                target_epoch: current.status.target_epoch,
                items: items.len() as u64,
                undecided,
                nodes,
                activation_permitted: gaps.is_empty(),
                gaps,
            })
        })
        .await
    }

    /// Declares the review complete. Refused while an item is undecided or an active
    /// broker is neither covered nor waived (waivers close at completion). Applies the
    /// local consequences first so a recorded completion never outruns them.
    pub async fn complete_recovery_review(
        &self,
        owner: &Arc<ProcessOwnership>,
        operator: &str,
    ) -> Result<RecoveryReviewCompletion, StoreError> {
        let status = self.recovery_activation_status(owner).await?;
        if status.undecided > 0
            || status
                .gaps
                .iter()
                .any(|gap| !matches!(gap.as_str(), "source_stop_missing" | "review_incomplete"))
        {
            return Err(StoreError::InvalidInput("recovery review gates"));
        }
        let items = self.recovery_review_items(owner).await?;
        let waived: Vec<String> = status
            .nodes
            .iter()
            .filter(|node| node.waived)
            .map(|node| node.node_id.clone())
            .collect();
        let enabled: Vec<String> = items
            .iter()
            .filter(|i| i.category == "operator" && i.decision.as_deref() == Some("accept"))
            .map(|i| i.subject_id.clone())
            .collect();
        let mut result = RecoveryReviewCompletion {
            items: items.len() as u64,
            operators_enabled: 0,
            nodes_revoked: 0,
        };
        self.recovery_boundary(owner, async {
            let recovery_id = self.current_review_recovery(owner).await?.status.recovery_id;
            macro_rules! sync {($pool:expr,$convert:expr)=>{{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                if matches!(self.database, Database::Postgres(_)) {
                    sqlx::query(crate::store::PG_RECOVERY_ISOLATION).execute(&mut *tx).await.map_err(StoreError::Database)?;
                }
                sqlx::query("UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1").execute(&mut *tx).await.map_err(StoreError::Database)?;
                let now = super::database_wall_now_ms(&self.database).await?;
                // Only accounts the invalidation disabled: one an administrator had disabled
                // before the snapshot carries an earlier stamp and stays disabled.
                for id in &enabled {
                    result.operators_enabled += sqlx::query(&$convert("UPDATE operators SET disabled_at=NULL WHERE id=? AND disabled_at IS NOT NULL AND disabled_at>=(SELECT prepared_at FROM controller_recoveries WHERE recovery_id=?)"))
                        .bind(id).bind(&recovery_id).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                }
                for node in &waived {
                    result.nodes_revoked += sqlx::query(&$convert("UPDATE nodes SET status='revoked',revoked_at=?,revoked_by=?,version=version+1 WHERE id=? AND tenant_id=? AND status='active'"))
                        .bind(now).bind(operator).bind(node).bind(&self.tenant_id).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                }
                owner.check().await.map_err(|_| StoreError::AuthorityFenced)?;
                tx.commit().await.map_err(StoreError::Database)?;
            }};}
            match &self.database {
                Database::Sqlite(p) => sync!(p, |s: &str| s.to_owned()),
                Database::Postgres(p) => sync!(p, crate::store::pg),
            }
            definite(owner.complete_recovery_review(result.items).await)
        })
        .await??;
        Ok(result)
    }
}

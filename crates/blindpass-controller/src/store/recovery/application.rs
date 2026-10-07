// SPDX-License-Identifier: AGPL-3.0-only
//! Complete protected history becomes local quarantine metadata in one commit.
use super::{Database, RecoveryRow, SELECT, Store, StoreError, StoredRecovery, reports::authority};
use crate::recovery_authority::ProcessOwnership;
use std::sync::Arc;

/// Local reconciliation metadata; it never grants admission or provider success.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryApplicationSummary {
    pub matched: u64,
    pub unknown: u64,
    pub conflicting: u64,
    pub unmapped: u64,
}

type GrantMapping = (
    String,
    String,
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
);
type AppliedReport = (String, String, i64, i64, i64, i64, i64, i64, String);
type AppliedIntent = (Option<String>, Option<i64>, i64, String);

impl Store {
    /// Reverify consumed protected pages before one local commit. Unknown and
    /// conflicting bindings are retained for review without manufacturing any
    /// grant or operation. A retry rereads the receipt and exact existing rows.
    pub async fn apply_recovery_report(
        &self,
        owner: &Arc<ProcessOwnership>,
        node: &str,
    ) -> Result<RecoveryApplicationSummary, StoreError> {
        let scope = self.recovery_receipt_scope(owner).await?;
        let challenge = self.scoped_recovery_challenge(owner, &scope, node).await?;
        self.recovery_boundary(owner, async {
            let mut reader = authority(owner.read_covered_recovery_report(challenge.clone()).await)?;
            let manifest = challenge.manifest.as_ref().ok_or(StoreError::InvalidInput("recovery report"))?;
            macro_rules! apply {($pool:expr,$convert:expr)=>{{
                let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                if matches!(self.database, Database::Postgres(_)) {
                    sqlx::query(crate::store::PG_RECOVERY_ISOLATION).execute(&mut *tx).await.map_err(StoreError::Database)?;
                }
                let result = async {
                    sqlx::query("UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1")
                        .execute(&mut *tx).await.map_err(StoreError::Database)?;
                    let metadata=sqlx::query_as::<_,(i64,String,i64)>("SELECT CAST(schema_version AS BIGINT),tenant_id,issuer_epoch FROM controller_meta WHERE id=1")
                        .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                    if metadata.0!=crate::store::SCHEMA_VERSION || metadata.1!=self.tenant_id
                        || metadata.2!=challenge.identity.recovery_generation as i64 {
                        return Err(StoreError::InvalidInput("recovery controller metadata"));
                    }
                    let sql = format!("{SELECT} WHERE recovery_id=?");
                    let current = StoredRecovery::parse(sqlx::query_as::<_,RecoveryRow>(&$convert(&sql))
                        .bind(&scope.recovery_id).fetch_one(&mut *tx).await.map_err(StoreError::Database)?)?;
                    if !current.matches(owner) || current.status.phase!="invalidated"
                        || current.status.snapshot_epoch!=scope.snapshot_epoch {
                        return Err(StoreError::InvalidInput("recovery reservation"));
                    }
                    // Pending counts cannot escape this transaction. Node has no
                    // FK here so post-backup unknown brokers remain quarantined.
                    let inserted=sqlx::query(&$convert("INSERT INTO controller_recovery_reports (recovery_id,node_id,report_id,records_digest,trust_revision,node_key_version,matched,unknown_records,conflicting,unmapped,state) VALUES (?,?,?,?,?,?,0,0,0,0,'quarantined') ON CONFLICT(recovery_id,node_id) DO NOTHING"))
                        .bind(&scope.recovery_id).bind(node).bind(&manifest.report_id).bind(&manifest.records_digest)
                        .bind(challenge.trust_revision as i64).bind(challenge.identity.node_key_version as i64)
                        .execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                    let existing=sqlx::query_as::<_,AppliedReport>(&$convert("SELECT report_id,records_digest,trust_revision,node_key_version,matched,unknown_records,conflicting,unmapped,state FROM controller_recovery_reports WHERE recovery_id=? AND node_id=?"))
                        .bind(&scope.recovery_id).bind(node).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                    if existing.0!=manifest.report_id || existing.1!=manifest.records_digest
                        || existing.2!=challenge.trust_revision as i64 || existing.3!=challenge.identity.node_key_version as i64 || existing.8!="quarantined" {
                        return Err(StoreError::InvalidInput("recovery application marker"));
                    }
                    let mut summary=RecoveryApplicationSummary::default();
                    while let Some(page)=authority(reader.next_page().await)? {
                        for record in page.records {
                            let mapping = if record.operation_id.is_none() {"unmapped"} else {
                                let row=sqlx::query_as::<_,GrantMapping>(&$convert("SELECT g.tenant_id,g.node_id,g.operation_id,g.issuer_epoch,g.expires_at,g.status,o.tenant_id,o.node_id,o.workload_id,o.grant_id,o.status,g.workload_id FROM grants g JOIN operations o ON o.id=g.operation_id WHERE g.id=?"))
                                    .bind(&record.grant_id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                                if let Some(g)=row {
                                    let queued:i64=sqlx::query_scalar(&$convert("SELECT COUNT(*) FROM controller_recovery_operations r JOIN controller_recovery_nodes n ON n.recovery_id=r.recovery_id WHERE r.recovery_id=? AND r.operation_id=? AND r.state='uncertain' AND n.node_id=? AND n.state='quarantined'"))
                                        .bind(&scope.recovery_id).bind(&g.2).bind(node).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                                    if g.0==self.tenant_id && g.1==node && Some(&g.2)==record.operation_id.as_ref()
                                        && Some(g.3 as u64)==record.issuer_epoch && g.4==record.expires_at_ms as i64
                                        && matches!(g.5.as_str(),"revoked"|"consumed") && g.6==self.tenant_id && g.7==node
                                        && g.8==g.11 && g.9.as_ref()==Some(&record.grant_id) && g.10=="uncertain" && queued==1 {"matched"}
                                    else {"conflicting"}
                                } else {"unknown"}
                            };
                            match mapping {"matched"=>summary.matched+=1,"unknown"=>summary.unknown+=1,"conflicting"=>summary.conflicting+=1,_=>summary.unmapped+=1}
                            sqlx::query(&$convert("INSERT INTO controller_recovery_intents (recovery_id,node_id,grant_id,operation_id,issuer_epoch,expires_at_ms,mapping) VALUES (?,?,?,?,?,?,?) ON CONFLICT(recovery_id,node_id,grant_id) DO NOTHING"))
                                .bind(&scope.recovery_id).bind(node).bind(&record.grant_id).bind(&record.operation_id)
                                .bind(record.issuer_epoch.map(|epoch|epoch as i64)).bind(record.expires_at_ms as i64).bind(mapping)
                                .execute(&mut *tx).await.map_err(StoreError::Database)?;
                            let stored=sqlx::query_as::<_,AppliedIntent>(&$convert("SELECT operation_id,issuer_epoch,expires_at_ms,mapping FROM controller_recovery_intents WHERE recovery_id=? AND node_id=? AND grant_id=?"))
                                .bind(&scope.recovery_id).bind(node).bind(&record.grant_id).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                            if stored!=(record.operation_id,record.issuer_epoch.map(|epoch|epoch as i64),record.expires_at_ms as i64,mapping.to_owned()) {
                                return Err(StoreError::InvalidInput("recovery intent marker"));
                            }
                        }
                    }
                    let count:i64=sqlx::query_scalar(&$convert("SELECT COUNT(*) FROM controller_recovery_intents WHERE recovery_id=? AND node_id=?"))
                        .bind(&scope.recovery_id).bind(node).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                    if count!=manifest.total_records as i64 || self.recovery_receipt_scope(owner).await?!=scope {
                        return Err(StoreError::InvalidInput("recovery application context"));
                    }
                    if inserted==0 && (existing.4,existing.5,existing.6,existing.7)!=(summary.matched as i64,summary.unknown as i64,summary.conflicting as i64,summary.unmapped as i64) {
                        return Err(StoreError::InvalidInput("recovery application counts"));
                    }
                    sqlx::query(&$convert("UPDATE controller_recovery_reports SET matched=?,unknown_records=?,conflicting=?,unmapped=? WHERE recovery_id=? AND node_id=?"))
                        .bind(summary.matched as i64).bind(summary.unknown as i64).bind(summary.conflicting as i64).bind(summary.unmapped as i64)
                        .bind(&scope.recovery_id).bind(node).execute(&mut *tx).await.map_err(StoreError::Database)?;
                    owner.check().await.map_err(|_|StoreError::AuthorityFenced)?;
                    Ok(summary)
                }.await;
                match result {
                    Ok(summary)=>{tx.commit().await.map_err(StoreError::Database)?;Ok(summary)},
                    Err(error)=>{
                        // A semantic refusal after earlier page writes needs an
                        // observed rollback. Failure/cancellation stays uncertain.
                        tx.rollback().await.map_err(StoreError::Database)?;
                        Err(error)
                    }
                }
            }};}
            match &self.database {Database::Sqlite(p)=>apply!(p,|s:&str|s.to_owned()),Database::Postgres(p)=>apply!(p,crate::store::pg)}
        }).await
    }
}

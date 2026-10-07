// SPDX-License-Identifier: AGPL-3.0-only
//! Local durable fencing and atomic invalidation. No local clear API: the fence is released only against the authority's activation proof (ADR 0014).
use super::{Database, SCHEMA_VERSION, Store, StoreError, database_wall_now_ms};
use crate::recovery_authority::ProcessOwnership;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

const MAX: i64 = 9_007_199_254_740_991;
mod application;
mod reports;
mod review;
pub use application::RecoveryApplicationSummary;
pub use review::{
    RecoveryActivationStatus, RecoveryNodeStatus, RecoveryReviewCompletion, RecoveryReviewItem,
};
mod snapshot;
const DEADLINE: Duration = Duration::from_secs(30);
const SELECT: &str = "SELECT recovery_id,tenant_id,issuer_key_id,owner_id,snapshot_epoch,target_epoch,authority_revision,phase,summary_json FROM controller_recoveries";
type RecoveryRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    String,
    Option<String>,
);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInvalidationSummary {
    pub legacy_requests: u64,
    pub legacy_exchanges: u64,
    pub legacy_approvals: u64,
    pub enrollments: u64,
    pub fleet_approvals: u64,
    pub bootstrap_tokens: u64,
    pub node_sessions: u64,
    pub operator_sessions: u64,
    pub inbox_documents: u64,
    pub idempotency_rows: u64,
    pub provisioning_links: u64,
    pub provisioning_offers: u64,
    pub grants: u64,
    pub operations: u64,
    pub nodes: u64,
    pub reviews: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryStatus {
    pub recovery_id: String,
    pub snapshot_epoch: u64,
    pub target_epoch: u64,
    pub phase: String,
    pub summary: Option<RecoveryInvalidationSummary>,
}
struct StoredRecovery {
    status: RecoveryStatus,
    tenant: String,
    key: String,
    owner: String,
    revision: u64,
}
fn opaque(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
impl StoredRecovery {
    fn parse(row: RecoveryRow) -> Result<Self, StoreError> {
        if [&row.0, &row.1, &row.2, &row.3].iter().any(|s| !opaque(s))
            || !(1..=MAX).contains(&row.4)
            || !(row.4 + 1..=MAX).contains(&row.5)
            || !(1..=MAX).contains(&row.6)
            || !matches!(row.7.as_str(), "prepared" | "invalidated")
        {
            return Err(StoreError::MissingState("recovery metadata"));
        }
        let summary = row
            .8
            .map(|s| {
                serde_json::from_str::<RecoveryInvalidationSummary>(&s)
                    .map_err(|_| StoreError::MissingState("recovery summary"))
            })
            .transpose()?;
        if (row.7 == "invalidated") != summary.is_some() {
            return Err(StoreError::MissingState("recovery summary"));
        }
        Ok(Self {
            status: RecoveryStatus {
                recovery_id: row.0,
                snapshot_epoch: row.4 as u64,
                target_epoch: row.5 as u64,
                phase: row.7,
                summary,
            },
            tenant: row.1,
            key: row.2,
            owner: row.3,
            revision: row.6 as u64,
        })
    }
    fn matches(&self, owner: &ProcessOwnership) -> bool {
        let (context, record) = owner.recovery_context();
        self.tenant == context.tenant_id
            && self.key == context.issuer_key_id
            && self.owner == context.owner_id
            && self.status.target_epoch == record.epoch
            && self.revision == record.revision
    }
}

impl Store {
    /// Cached irreversible local latch shared by pre-existing clones. On open
    /// it is reconstructed from durable recovery records; no method clears it.
    pub fn recovery_required(&self) -> bool {
        self.recovery_required.load(Ordering::Acquire)
    }

    pub(super) async fn load_recovery_fence(
        &self,
        owner: Option<&Arc<ProcessOwnership>>,
    ) -> Result<(), StoreError> {
        let sql = "SELECT COUNT(*) FROM controller_recoveries WHERE tenant_id <> ?";
        let foreign: i64 = match &self.database {
            Database::Sqlite(p) => sqlx::query_scalar(sql)
                .bind(&self.tenant_id)
                .fetch_one(p)
                .await
                .map_err(StoreError::Database)?,
            Database::Postgres(p) => sqlx::query_scalar(&super::pg(sql))
                .bind(&self.tenant_id)
                .fetch_one(p)
                .await
                .map_err(StoreError::Database)?,
        };
        if foreign != 0 {
            return Err(StoreError::MissingState("recovery tenant"));
        }
        if let Some(status) = self.recovery_status().await?
            && !self.recovery_concluded(&status, owner).await?
        {
            self.recovery_required.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// A recovery is concluded only when the authority recorded its protected activation
    /// (`activate_recovery`) for this exact epoch and this process holds the resulting
    /// active record. Every other path, including a plain fence-then-activate of a
    /// `recovering` record, leaves the latch set.
    async fn recovery_concluded(
        &self,
        status: &RecoveryStatus,
        owner: Option<&Arc<ProcessOwnership>>,
    ) -> Result<bool, StoreError> {
        let Some(owner) = owner else {
            return Ok(false);
        };
        if status.phase != "invalidated" || !owner.is_active() {
            return Ok(false);
        }
        let (context, record) = owner.recovery_context();
        if context.tenant_id != self.tenant_id || record.epoch != status.target_epoch {
            return Ok(false);
        }
        owner
            .recovery_activation_recorded(record.epoch)
            .await
            .map_err(|_| StoreError::AuthorityFenced)
    }

    /// Metadata only, usable by local recovery administration while fenced.
    pub async fn recovery_status(&self) -> Result<Option<RecoveryStatus>, StoreError> {
        let sql = format!("{SELECT} WHERE tenant_id=? ORDER BY target_epoch DESC LIMIT 1");
        let row = match &self.database {
            Database::Sqlite(p) => sqlx::query_as::<_, RecoveryRow>(&sql)
                .bind(&self.tenant_id)
                .fetch_optional(p)
                .await
                .map_err(StoreError::Database)?,
            Database::Postgres(p) => sqlx::query_as::<_, RecoveryRow>(&super::pg(&sql))
                .bind(&self.tenant_id)
                .fetch_optional(p)
                .await
                .map_err(StoreError::Database)?,
        };
        row.map(StoredRecovery::parse)
            .transpose()
            .map(|row| row.map(|row| row.status))
    }

    async fn recovery_boundary<T>(
        &self,
        owner: &Arc<ProcessOwnership>,
        future: impl std::future::Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        let bound = self
            .ownership
            .lock()
            .map_err(|_| StoreError::AuthorityFenced)?
            .clone();
        let signer = self
            .fleet_signer
            .as_ref()
            .ok_or(StoreError::MissingState("issuer signer"))?;
        if !bound
            .as_ref()
            .is_some_and(|bound| Arc::ptr_eq(bound, owner))
            || !owner.is_recovering()
            || !owner.matches_controller(&self.tenant_id, &signer.key_id)
            || owner.check().await.is_err()
        {
            return Err(StoreError::AuthorityFenced);
        }
        let mut operation = owner
            .begin_recovery_operation()
            .map_err(|_| StoreError::AuthorityFenced)?
            .database_work();
        self.recovery_required.store(true, Ordering::Release);
        let result = tokio::select! {
            biased;
            _=owner.wait_fenced()=>Err(StoreError::AuthorityFenced),
            result=tokio::time::timeout(DEADLINE,async {self.database.validate_existing_schema_version().await?; future.await})=>match result {
                Ok(result) if !owner.is_fenced()=>result,
                _=>Err(StoreError::RecoveryRequired),
            }
        };
        super::acknowledge_database_work(&mut operation, &result);
        if result.is_err() {
            owner.fence();
        }
        result
    }

    /// Flush the isolated restored SQLite state before directory publication.
    /// A busy or uncertain checkpoint never establishes durable publication.
    pub(crate) async fn checkpoint_restore(
        &self,
        owner: &Arc<ProcessOwnership>,
    ) -> Result<(), StoreError> {
        self.recovery_boundary(owner, async {
            if !self.recovery_required() {
                return Err(StoreError::RecoveryRequired);
            }
            let Database::Sqlite(pool) = &self.database else {
                // PostgreSQL commits are durable at the server; nothing to flush.
                return Ok(());
            };
            let (busy, _, _): (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(pool)
                .await
                .map_err(StoreError::Database)?;
            if busy != 0 {
                return Err(StoreError::RecoveryRequired);
            }
            Ok(())
        })
        .await
    }

    /// Commit the fence before bulk mutation. This proves neither old-source
    /// stop nor trusted broker coverage and never enables ordinary operations.
    pub async fn prepare_recovery(
        &self,
        owner: &Arc<ProcessOwnership>,
        id: &str,
    ) -> Result<RecoveryStatus, StoreError> {
        if !opaque(id) {
            return Err(StoreError::InvalidInput("recovery identifier"));
        }
        self.recovery_boundary(owner,async {
            let (context,record)=owner.recovery_context();
            macro_rules! prepare {($pool:expr,$convert:expr)=>{{
                let mut tx=$pool.begin().await.map_err(StoreError::Database)?;
                if matches!(self.database, Database::Postgres(_)) {
                    sqlx::query(crate::store::PG_RECOVERY_ISOLATION).execute(&mut *tx).await.map_err(StoreError::Database)?;
                }
                sqlx::query("UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1").execute(&mut *tx).await.map_err(StoreError::Database)?;
                let (schema,tenant,epoch)=sqlx::query_as::<_,(i64,String,i64)>("SELECT CAST(schema_version AS BIGINT),tenant_id,issuer_epoch FROM controller_meta WHERE id=1")
                    .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                if schema!=SCHEMA_VERSION {return Err(StoreError::UnsupportedSchemaVersion);}
                if tenant!=context.tenant_id || !(1..=MAX).contains(&epoch) {return Err(StoreError::MissingState("recovery controller metadata"));}
                let select=format!("{SELECT} WHERE recovery_id=?");
                let existing=sqlx::query_as::<_,RecoveryRow>(&$convert(&select)).bind(id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                let status=if let Some(row)=existing {
                    let existing=StoredRecovery::parse(row)?;
                    let expected=if existing.status.phase=="prepared" {existing.status.snapshot_epoch} else {existing.status.target_epoch};
                    if !existing.matches(owner) || epoch as u64!=expected {return Err(StoreError::InvalidInput("recovery reservation"));}
                    existing.status
                } else {
                    let prior=sqlx::query_scalar::<_,Option<i64>>(&$convert("SELECT MAX(target_epoch) FROM controller_recoveries WHERE tenant_id=?"))
                        .bind(&tenant).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                    if record.epoch<=epoch as u64 || prior.is_some_and(|prior|record.epoch<=prior as u64) {return Err(StoreError::InvalidInput("recovery generation"));}
                    let now=database_wall_now_ms(&self.database).await?;
                    sqlx::query(&$convert("INSERT INTO controller_recoveries (recovery_id,tenant_id,issuer_key_id,owner_id,snapshot_epoch,target_epoch,authority_revision,phase,prepared_at) VALUES (?,?,?,?,?,?,?,'prepared',?)"))
                        .bind(id).bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id).bind(epoch).bind(record.epoch as i64).bind(record.revision as i64).bind(now)
                        .execute(&mut *tx).await.map_err(StoreError::Database)?;
                    RecoveryStatus {recovery_id:id.into(),snapshot_epoch:epoch as u64,target_epoch:record.epoch,phase:"prepared".into(),summary:None}
                };
                owner.check().await.map_err(|_|StoreError::AuthorityFenced)?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(status)
            }};}
            match &self.database {Database::Sqlite(p)=>prepare!(p,|s:&str|s.to_owned()),Database::Postgres(p)=>prepare!(p,super::pg)}
        }).await
    }

    /// Atomic invalidation after a separately durable prepared fence. Replays
    /// read the exact committed generation; no hidden retry follows an error.
    pub async fn invalidate_recovery(
        &self,
        owner: &Arc<ProcessOwnership>,
        id: &str,
    ) -> Result<RecoveryStatus, StoreError> {
        let prepared = self.prepare_recovery(owner, id).await?;
        if prepared.phase == "invalidated" {
            return Ok(prepared);
        }
        self.recovery_boundary(owner,async {
            let (context,record)=owner.recovery_context();
            macro_rules! invalidate {($pool:expr,$convert:expr)=>{{
                let mut tx=$pool.begin().await.map_err(StoreError::Database)?;
                if matches!(self.database, Database::Postgres(_)) {
                    sqlx::query(crate::store::PG_RECOVERY_ISOLATION).execute(&mut *tx).await.map_err(StoreError::Database)?;
                }
                sqlx::query("UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1").execute(&mut *tx).await.map_err(StoreError::Database)?;
                let (schema,tenant,epoch)=sqlx::query_as::<_,(i64,String,i64)>("SELECT CAST(schema_version AS BIGINT),tenant_id,issuer_epoch FROM controller_meta WHERE id=1")
                    .fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                if schema!=SCHEMA_VERSION {return Err(StoreError::UnsupportedSchemaVersion);}
                let select=format!("{SELECT} WHERE recovery_id=?");
                let current=StoredRecovery::parse(sqlx::query_as::<_,RecoveryRow>(&$convert(&select)).bind(id).fetch_one(&mut *tx).await.map_err(StoreError::Database)?)?;
                if tenant!=context.tenant_id || !current.matches(owner) {return Err(StoreError::InvalidInput("recovery reservation"));}
                if current.status.phase=="invalidated" {
                    if epoch as u64!=record.epoch {return Err(StoreError::MissingState("recovery generation"));}
                    owner.check().await.map_err(|_|StoreError::AuthorityFenced)?;
                    tx.commit().await.map_err(StoreError::Database)?;
                    return Ok(current.status);
                }
                if epoch<1 || epoch as u64!=current.status.snapshot_epoch || record.epoch<=epoch as u64 {return Err(StoreError::InvalidInput("recovery generation"));}
                for (table,column) in [("agents","key_version"),("workloads","version"),("operations","version")] {
                    let sql=format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=? AND ({column}<1 OR {column}>=9007199254740991)");
                    let unsafe_versions:i64=sqlx::query_scalar(&$convert(&sql)).bind(&tenant).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                    if unsafe_versions!=0 {return Err(StoreError::InvalidInput("recovery version"));}
                }
                let now=database_wall_now_ms(&self.database).await?;
                let mut summary=RecoveryInvalidationSummary::default();
                macro_rules! remove_tenant {($field:ident,$table:literal)=>{
                    summary.$field=sqlx::query(&$convert(concat!("DELETE FROM ",$table," WHERE tenant_id=?"))).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                };}
                remove_tenant!(legacy_requests,"secret_requests");
                remove_tenant!(legacy_exchanges,"exchanges");
                remove_tenant!(legacy_approvals,"approvals");
                remove_tenant!(enrollments,"enrollment_requests");
                remove_tenant!(fleet_approvals,"operation_approvals");
                remove_tenant!(idempotency_rows,"idempotency_keys");
                remove_tenant!(provisioning_links,"fleet_provisioning_links");
                remove_tenant!(provisioning_offers,"fleet_provisioning_offers");
                sqlx::query(&$convert("DELETE FROM node_challenges WHERE tenant_id=?")).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?;
                summary.bootstrap_tokens=sqlx::query("DELETE FROM bootstrap_tokens").execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                summary.operator_sessions=sqlx::query("DELETE FROM operator_sessions").execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                summary.node_sessions=sqlx::query(&$convert("DELETE FROM node_sessions WHERE node_id IN (SELECT id FROM nodes WHERE tenant_id=?)")).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                summary.inbox_documents=sqlx::query(&$convert("DELETE FROM node_inbox WHERE node_id IN (SELECT id FROM nodes WHERE tenant_id=?)")).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                summary.nodes=sqlx::query(&$convert("INSERT INTO controller_recovery_nodes (recovery_id,node_id,snapshot_status,snapshot_key_version,state) SELECT ?,id,status,key_version,'quarantined' FROM nodes WHERE tenant_id=?"))
                    .bind(id).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                summary.operations=sqlx::query(&$convert("INSERT INTO controller_recovery_operations (recovery_id,operation_id,snapshot_status,snapshot_result_json,snapshot_completed_at,state) SELECT ?,id,status,result_json,completed_at,'uncertain' FROM operations WHERE tenant_id=?"))
                    .bind(id).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                for sql in [
                    "INSERT INTO controller_recovery_reviews SELECT ?,'agent',id,'',key_version,status,'quarantined' FROM agents WHERE tenant_id=?",
                    "INSERT INTO controller_recovery_reviews SELECT ?,'workload',id,'',version,status,'quarantined' FROM workloads WHERE tenant_id=?",
                    "INSERT INTO controller_recovery_reviews SELECT ?,'legacy_policy',tenant_id,'',version,'present','quarantined' FROM policies WHERE tenant_id=?",
                    "INSERT INTO controller_recovery_reviews SELECT ?,'fleet_policy',tenant_id,'',version,'present','quarantined' FROM fleet_policies WHERE tenant_id=?",
                    "INSERT INTO controller_recovery_reviews SELECT ?,'source_binding',node_id,resource_id,version,'present','quarantined' FROM fleet_source_bindings WHERE tenant_id=?",
                    "INSERT INTO controller_recovery_reviews SELECT ?,'node_key_rotation',node_id,rotation_id,from_key_version,'present','quarantined' FROM node_key_rotations WHERE node_id IN (SELECT id FROM nodes WHERE tenant_id=?)",
                ] {
                    summary.reviews+=sqlx::query(&$convert(sql)).bind(id).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                }
                summary.reviews+=sqlx::query(&$convert("INSERT INTO controller_recovery_reviews SELECT ?,'operator',id,'',0,role,'quarantined' FROM operators"))
                    .bind(id).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                let invalid_tombstones:i64=sqlx::query_scalar(&$convert("SELECT COUNT(*) FROM grant_tombstones t JOIN grants g ON g.id=t.grant_id WHERE g.tenant_id=? AND (t.node_id<>g.node_id OR t.retain_until>9007199254740991)"))
                    .bind(&tenant).fetch_one(&mut *tx).await.map_err(StoreError::Database)?;
                if invalid_tombstones!=0 {return Err(StoreError::InvalidInput("recovery grant retention"));}
                summary.grants=sqlx::query(&$convert("INSERT INTO grant_tombstones (grant_id,node_id,reason,created_at,retain_until) SELECT id,node_id,'controller_recovery',?,9007199254740991 FROM grants WHERE tenant_id=? ON CONFLICT(grant_id) DO UPDATE SET retain_until=9007199254740991"))
                    .bind(now).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                sqlx::query(&$convert("UPDATE grants SET status=CASE WHEN status='consumed' THEN 'consumed' ELSE 'revoked' END,revoked_at=COALESCE(revoked_at,?) WHERE tenant_id=?"))
                    .bind(now).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?;
                sqlx::query(&$convert("UPDATE operations SET status='uncertain',result_json='{\"status\":\"uncertain\",\"reason\":\"controller_recovery\"}',completed_at=NULL,version=version+1 WHERE tenant_id=?"))
                    .bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?;
                sqlx::query(&$convert("UPDATE agents SET status='revoked',revoked_at=COALESCE(revoked_at,?),key_version=key_version+1 WHERE tenant_id=?"))
                    .bind(now).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?;
                sqlx::query(&$convert("UPDATE workloads SET status='revoked',revoked_at=COALESCE(revoked_at,?),version=version+1 WHERE tenant_id=?"))
                    .bind(now).bind(&tenant).execute(&mut *tx).await.map_err(StoreError::Database)?;
                sqlx::query(&$convert("UPDATE operators SET disabled_at=COALESCE(disabled_at,?)")).bind(now).execute(&mut *tx).await.map_err(StoreError::Database)?;
                let updated=sqlx::query(&$convert("UPDATE controller_meta SET issuer_epoch=? WHERE id=1 AND tenant_id=? AND issuer_epoch=? AND schema_version=?"))
                    .bind(record.epoch as i64).bind(&tenant).bind(epoch).bind(SCHEMA_VERSION as i32).execute(&mut *tx).await.map_err(StoreError::Database)?.rows_affected();
                if updated!=1 {return Err(StoreError::MissingState("recovery controller metadata"));}
                let json=serde_json::to_string(&summary).map_err(|_|StoreError::InvalidInput("recovery summary"))?;
                sqlx::query(&$convert("UPDATE controller_recoveries SET phase='invalidated',invalidated_at=?,summary_json=? WHERE recovery_id=? AND phase='prepared'"))
                    .bind(now).bind(json).bind(id).execute(&mut *tx).await.map_err(StoreError::Database)?;
                owner.check().await.map_err(|_|StoreError::AuthorityFenced)?;
                tx.commit().await.map_err(StoreError::Database)?;
                Ok(RecoveryStatus {recovery_id:id.into(),snapshot_epoch:epoch as u64,target_epoch:record.epoch,phase:"invalidated".into(),summary:Some(summary)})
            }};}
            match &self.database {Database::Sqlite(p)=>invalidate!(p,|s:&str|s.to_owned()),Database::Postgres(p)=>invalidate!(p,super::pg)}
        }).await
    }
}

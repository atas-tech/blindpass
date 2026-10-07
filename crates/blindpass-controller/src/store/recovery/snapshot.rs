// SPDX-License-Identifier: AGPL-3.0-only
//! Archive context is bound only while private authenticated restore staging
//! and the live recovering holder are both present. It never clears the fence.

use super::{Database, MAX, RecoveryRow, SELECT, Store, StoreError, StoredRecovery};
use crate::{
    backup::VerifiedBackup,
    recovery_authority::{ProcessOwnership, RecoveryReceiptScope},
};
use blindpass_core::{
    custody::sha256,
    signing::{base64_url_decode, base64_url_encode, ed25519::verify},
};
use std::sync::Arc;

fn scope_message(
    owner: &ProcessOwnership,
    scope: &RecoveryReceiptScope,
) -> Result<Vec<u8>, StoreError> {
    let (context, record) = owner.recovery_context();
    let body = serde_json::to_vec(&(
        1_u8,
        &context.tenant_id,
        &context.issuer_key_id,
        &context.owner_id,
        &scope.recovery_id,
        record.epoch,
        record.revision,
        scope.snapshot_epoch,
        scope.snapshot_time_ms,
        &scope.backup_digest,
    ))
    .map_err(|_| StoreError::MissingState("recovery snapshot signature"))?;
    let mut message = b"blindpass recovery snapshot v1\0".to_vec();
    message.extend(body);
    Ok(message)
}

impl Store {
    pub(crate) async fn bind_verified_recovery_snapshot(
        &self,
        owner: &Arc<ProcessOwnership>,
        id: &str,
        verified: &VerifiedBackup,
    ) -> Result<(), StoreError> {
        let snapshot = &verified.manifest.snapshot;
        let epoch = i64::try_from(snapshot.recovery_generation)
            .map_err(|_| StoreError::InvalidInput("backup generation"))?;
        if snapshot.tenant_id != self.tenant_id
            || !(1..=MAX).contains(&epoch)
            || !(1..=MAX).contains(&snapshot.clock_ms)
        {
            return Err(StoreError::InvalidInput("backup recovery context"));
        }
        let manifest = serde_json::to_vec(&verified.manifest)
            .map_err(|_| StoreError::InvalidInput("backup manifest"))?;
        let digest = base64_url_encode(
            &sha256(&manifest).map_err(|_| StoreError::MissingState("backup manifest digest"))?,
        );
        self.prepare_recovery(owner, id).await?;
        self.recovery_boundary(owner, async {
            let scope = RecoveryReceiptScope {
                recovery_id: id.into(), snapshot_epoch: snapshot.recovery_generation,
                snapshot_time_ms: snapshot.clock_ms as u64, backup_digest: digest.clone(),
            };
            let signer = self.fleet_signer.as_ref().ok_or(StoreError::MissingState("issuer signer"))?;
            let signature = base64_url_encode(&signer.keypair.sign(&scope_message(owner, &scope)?)
                .map_err(|_| StoreError::MissingState("recovery snapshot signature"))?);
            macro_rules! bind {
                ($pool:expr, $convert:expr) => {{
                    let mut tx = $pool.begin().await.map_err(StoreError::Database)?;
                if matches!(self.database, Database::Postgres(_)) {
                    sqlx::query(crate::store::PG_RECOVERY_ISOLATION).execute(&mut *tx).await.map_err(StoreError::Database)?;
                }
                    sqlx::query("UPDATE controller_meta SET issuer_epoch=issuer_epoch WHERE id=1")
                        .execute(&mut *tx).await.map_err(StoreError::Database)?;
                    let select = format!("{SELECT} WHERE recovery_id=?");
                    let recovery = StoredRecovery::parse(
                        sqlx::query_as::<_, RecoveryRow>(&$convert(&select)).bind(id)
                            .fetch_one(&mut *tx).await.map_err(StoreError::Database)?,
                    )?;
                    if !recovery.matches(owner) || recovery.status.snapshot_epoch != snapshot.recovery_generation {
                        return Err(StoreError::InvalidInput("backup recovery reservation"));
                    }
                    let existing = sqlx::query_as::<_, (i64, i64, String, String)>(&$convert(
                        "SELECT snapshot_epoch,snapshot_time_ms,backup_digest,signature FROM controller_recovery_snapshots WHERE recovery_id=?",
                    )).bind(id).fetch_optional(&mut *tx).await.map_err(StoreError::Database)?;
                    if let Some(existing) = existing {
                        if existing != (epoch, snapshot.clock_ms, digest.clone(), signature.clone()) {
                            return Err(StoreError::InvalidInput("backup recovery context"));
                        }
                    } else {
                        // A migrated historical invalidation has no authenticated
                        // timestamp. Never fill that gap from a later archive.
                        if recovery.status.phase != "prepared" {
                            return Err(StoreError::MissingState("authenticated recovery snapshot"));
                        }
                        sqlx::query(&$convert(
                            "INSERT INTO controller_recovery_snapshots (recovery_id,snapshot_epoch,snapshot_time_ms,backup_digest,signature) VALUES (?,?,?,?,?)",
                        )).bind(id).bind(epoch).bind(snapshot.clock_ms).bind(&digest).bind(&signature)
                            .execute(&mut *tx).await.map_err(StoreError::Database)?;
                    }
                    owner.check().await.map_err(|_| StoreError::AuthorityFenced)?;
                    tx.commit().await.map_err(StoreError::Database)?;
                    Ok(())
                }};
            }
            match &self.database {
                Database::Sqlite(pool) => bind!(pool, |sql: &str| sql.to_owned()),
                Database::Postgres(pool) => bind!(pool, crate::store::pg),
            }
        }).await
    }

    /// Verified local archive metadata only. This is not a coverage receipt or
    /// admission capability. Historical recoveries with no binding refuse.
    pub async fn recovery_receipt_scope(
        &self,
        owner: &Arc<ProcessOwnership>,
    ) -> Result<RecoveryReceiptScope, StoreError> {
        let bound = self
            .ownership
            .lock()
            .map_err(|_| StoreError::AuthorityFenced)?
            .clone();
        let signer = self
            .fleet_signer
            .as_ref()
            .ok_or(StoreError::MissingState("issuer signer"))?;
        if self.snapshot_only
            || !self.recovery_required()
            || !bound
                .as_ref()
                .is_some_and(|bound| Arc::ptr_eq(bound, owner))
            || !owner.is_recovering()
            || !owner.matches_controller(&self.tenant_id, &signer.key_id)
        {
            return Err(StoreError::AuthorityFenced);
        }
        owner
            .check()
            .await
            .map_err(|_| StoreError::AuthorityFenced)?;
        // Count the reader for guard lifetime, but cancelling this SELECT cannot
        // create an uncertain server-side database mutation.
        let _operation = owner
            .begin_recovery_operation()
            .map_err(|_| StoreError::AuthorityFenced)?;
        let result = tokio::select! { biased;
            _=owner.wait_fenced()=>Err(StoreError::AuthorityFenced),
            result=tokio::time::timeout(super::DEADLINE, async {
                self.database.validate_existing_schema_version().await?;
                let (context, record) = owner.recovery_context();
                let sql = "SELECT s.recovery_id,s.snapshot_epoch,s.snapshot_time_ms,s.backup_digest,s.signature FROM controller_recovery_snapshots s JOIN controller_recoveries r USING(recovery_id) WHERE r.tenant_id=? AND r.issuer_key_id=? AND r.owner_id=? AND r.target_epoch=? AND r.authority_revision=? AND r.phase='invalidated' AND s.snapshot_epoch=r.snapshot_epoch";
                macro_rules! read {($pool:expr,$convert:expr)=>{{
                    sqlx::query_as::<_, (String,i64,i64,String,String)>(&$convert(sql))
                        .bind(&context.tenant_id).bind(&context.issuer_key_id).bind(&context.owner_id)
                        .bind(record.epoch as i64).bind(record.revision as i64)
                        .fetch_optional($pool).await.map_err(StoreError::Database)?
                        .ok_or(StoreError::MissingState("authenticated recovery snapshot"))?
                }};}
                let row = match &self.database {
                    Database::Sqlite(pool)=>read!(pool,|sql:&str|sql.to_owned()),
                    Database::Postgres(pool)=>read!(pool,crate::store::pg),
                };
                let scope = RecoveryReceiptScope {
                    recovery_id: row.0,
                    snapshot_epoch: u64::try_from(row.1).map_err(|_|StoreError::MissingState("authenticated recovery snapshot"))?,
                    snapshot_time_ms: u64::try_from(row.2).map_err(|_|StoreError::MissingState("authenticated recovery snapshot"))?,
                    backup_digest: row.3,
                };
                scope.validate().map_err(|_|StoreError::MissingState("authenticated recovery snapshot"))?;
                let signature = base64_url_decode(&row.4,64).ok_or(StoreError::MissingState("recovery snapshot signature"))?;
                if !verify(signer.keypair.public_key(), &scope_message(owner, &scope)?, &signature)
                    .map_err(|_|StoreError::MissingState("recovery snapshot signature"))? {
                    return Err(StoreError::MissingState("recovery snapshot signature"));
                }
                Ok(scope)
            })=>result.unwrap_or(Err(StoreError::AuthorityFenced)),
        };
        if result.is_err() {
            owner.fence();
        }
        owner
            .check()
            .await
            .map_err(|_| StoreError::AuthorityFenced)?;
        result
    }
}

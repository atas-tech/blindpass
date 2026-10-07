// SPDX-License-Identifier: AGPL-3.0-only
//! Production startup and maintenance keep the external guard around the entire
//! local future. Neither path reserves generations or activates restored state.
use super::{Database, SCHEMA_VERSION, Store, StoreError, SystemClock};
use crate::recovery_authority::ProcessOwnership;
use crate::upgrade::{MigrationOutcome, PreUpgradeBackup};
use std::sync::Arc;
use std::time::Duration;

impl Store {
    /// Bind before startup clock writes. Nonactive holders open diagnostics only.
    pub async fn connect_existing_owned(
        url: &str,
        tolerance_ms: u64,
        owner: Arc<ProcessOwnership>,
        issuer_key_id: &str,
    ) -> Result<Self, StoreError> {
        // A handoff's retired source never opens its store; an imported
        // destination's first start must hold exactly the revision after it.
        if let Err(error) = crate::handoff::refuse_retired_source(url) {
            owner.fence();
            return Err(error);
        }
        let destination = if owner.is_active() {
            match crate::handoff::guard_destination_start(url, &owner) {
                Ok(destination) => destination,
                Err(error) => {
                    owner.fence();
                    return Err(error);
                }
            }
        } else {
            None
        };
        owner
            .check()
            .await
            .map_err(|_| StoreError::AuthorityFenced)?;
        let mut operation = if owner.is_active() {
            Some(
                owner
                    .begin_operation()
                    .map_err(|_| StoreError::AuthorityFenced)?
                    .database_work(),
            )
        } else {
            None
        };
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                biased;
                _ = owner.wait_fenced() => Err(StoreError::AuthorityFenced),
                result = Self::connect_existing_inner(url, tolerance_ms, Some((owner.clone(), issuer_key_id)), super::ExistingPurpose::Ordinary) => result,
            }
        }).await.unwrap_or(Err(StoreError::AuthorityFenced));
        if let Some(operation) = operation.as_mut() {
            super::acknowledge_database_work(operation, &result);
        }
        // The imported state is adopted only once the store really opened.
        let result = match (result, destination) {
            (Ok(store), Some(destination)) => match destination.consume() {
                Ok(()) => Ok(store),
                Err(error) => {
                    store.close().await;
                    Err(error)
                }
            },
            (result, _) => result,
        };
        if result.is_err() {
            owner.fence();
        }
        result
    }

    /// Open only authenticated isolated restore staging under a recovering
    /// holder. The encrypted source archive remains the pre-upgrade backup.
    /// No tenant/clock is initialized and no activation is performed.
    pub(crate) async fn connect_existing_for_restore(
        url: &str,
        owner: Arc<ProcessOwnership>,
        issuer_key_id: &str,
        snapshot: &crate::backup::SnapshotInfo,
    ) -> Result<Self, StoreError> {
        if !owner.is_recovering()
            || !owner.matches_controller(&snapshot.tenant_id, issuer_key_id)
            || owner.recovery_context().1.epoch <= snapshot.recovery_generation
        {
            return Err(StoreError::AuthorityFenced);
        }
        owner
            .check()
            .await
            .map_err(|_| StoreError::AuthorityFenced)?;
        let mut operation = owner
            .begin_recovery_operation()
            .map_err(|_| StoreError::AuthorityFenced)?
            .database_work();
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                biased;
                _ = owner.wait_fenced() => Err(StoreError::AuthorityFenced),
                result = async {
                    let database = Database::connect_existing(url).await?;
                    database.validate_existing_schema_version().await?;
                    match &database {
                        Database::Sqlite(pool) => {
                            let row: (i64, String, i64) = sqlx::query_as("SELECT schema_version,tenant_id,issuer_epoch FROM controller_meta WHERE id=1 AND typeof(schema_version)='integer' AND typeof(tenant_id)='text' AND typeof(issuer_epoch)='integer'")
                                .fetch_one(pool).await.map_err(StoreError::Database)?;
                            if row.0 != snapshot.schema_version || row.1 != snapshot.tenant_id || u64::try_from(row.2).ok() != Some(snapshot.recovery_generation)
                                || !crate::backup::supported_snapshot_schema(row.0) {
                                return Err(StoreError::MissingState("restore metadata"));
                            }
                            if row.0 < SCHEMA_VERSION {
                                database.migrate().await?;
                                if !database.state_columns_present(SCHEMA_VERSION).await? { return Err(StoreError::UnsupportedSchemaVersion); }
                                sqlx::query("UPDATE controller_meta SET schema_version=? WHERE id=1 AND schema_version=?")
                                    .bind(SCHEMA_VERSION).bind(row.0).execute(pool).await.map_err(StoreError::Database)?;
                            }
                        }
                        Database::Postgres(pool) => {
                            let row: (i64, String, i64) = sqlx::query_as("SELECT CAST(schema_version AS BIGINT),tenant_id,issuer_epoch FROM controller_meta WHERE id=1")
                                .fetch_one(pool).await.map_err(StoreError::Database)?;
                            if row.0 != snapshot.schema_version || row.1 != snapshot.tenant_id
                                || u64::try_from(row.2).ok() != Some(snapshot.recovery_generation)
                                || !crate::backup::supported_snapshot_schema(row.0) {
                                return Err(StoreError::MissingState("restore metadata"));
                            }
                            // A pre-upgrade backup restores forward in the empty target.
                            if row.0 < SCHEMA_VERSION {
                                database.migrate().await?;
                                if !database.state_columns_present(SCHEMA_VERSION).await? { return Err(StoreError::UnsupportedSchemaVersion); }
                                sqlx::query("UPDATE controller_meta SET schema_version=$1 WHERE id=1 AND schema_version=$2")
                                    .bind(i32::try_from(SCHEMA_VERSION).map_err(|_| StoreError::UnsupportedSchemaVersion)?)
                                    .bind(i32::try_from(row.0).map_err(|_| StoreError::UnsupportedSchemaVersion)?)
                                    .execute(pool).await.map_err(StoreError::Database)?;
                            }
                        }
                    }
                    close_database(&database).await;
                    let store = Self::connect_existing_inner(url, 5000, Some((owner.clone(), issuer_key_id)), super::ExistingPurpose::Recovery).await?;
                    owner.check().await.map_err(|_| StoreError::AuthorityFenced)?;
                    Ok(store)
                } => result,
            }
        }).await.unwrap_or(Err(StoreError::AuthorityFenced));
        super::acknowledge_database_work(&mut operation, &result);
        if result.is_err() {
            owner.fence();
        }
        result
    }

    /// Initial creation, current-schema verification and the locked upgrade of a
    /// supported older SQLite schema. An older schema is migrated only after an
    /// encrypted backup of it has been published and re-verified; a newer or
    /// unsupported schema, an active owner or any damage refuses unchanged.
    pub async fn migrate_owned(
        url: &str,
        tolerance_ms: u64,
        owner: Arc<ProcessOwnership>,
        issuer_key_id: &str,
        upgrade: Option<&PreUpgradeBackup>,
    ) -> Result<MigrationOutcome, StoreError> {
        crate::handoff::refuse_retired_source(url)?;
        let plan = maintenance(&owner, async {
            let (context, record) = owner.recovery_context();
            if context.issuer_key_id != issuer_key_id { return Err(StoreError::AuthorityFenced); }
            let database = if record.epoch == 1 && record.revision == 1 { Database::connect(url).await? } else { Database::connect_existing(url).await? };
            if database.table_exists("controller_meta").await? {
                // Do not repair missing rows/tables or upgrade behind a version
                // marker before a complete verified pre-upgrade backup exists.
                let (version, tenant) = recorded_metadata(&database, &owner, issuer_key_id).await?;
                database.validate_existing_schema_version().await?;
                close_database(&database).await;
                if version == SCHEMA_VERSION {
                    let store = Self::connect_existing_owned(url, tolerance_ms, owner.clone(), issuer_key_id).await?;
                    store.close().await;
                    return Ok(Plan::Done(MigrationOutcome { from_schema: version, to_schema: version, backup_taken: false }));
                }
                if !crate::backup::supported_snapshot_schema(version) {
                    return Err(StoreError::UnsupportedSchemaVersion);
                }
                return Ok(Plan::Upgrade { from: version, tenant });
            }
            let tables: i64 = match &database {
                Database::Sqlite(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetch_one(pool).await.map_err(StoreError::Database)?,
                Database::Postgres(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY(current_schemas(false))").fetch_one(pool).await.map_err(StoreError::Database)?,
            };
            // Every ledger transition advances the revision, so only a record
            // that never left its provisioned state may create a controller.
            // A fenced record that was once active is lost state instead.
            if tables != 0 || record.epoch != 1 || record.revision != 1 {
                return Err(StoreError::MissingState("controller metadata"));
            }
            close_database(&database).await;
            let store = Self::connect_with_clock_source_for_tenant(url, Arc::new(SystemClock), tolerance_ms, Some(&context.tenant_id)).await?;
            store.bind_ownership(owner.clone(), issuer_key_id)?;
            current_metadata(&store.database, &owner, issuer_key_id).await?;
            store.close().await;
            Ok(Plan::Done(MigrationOutcome { from_schema: SCHEMA_VERSION, to_schema: SCHEMA_VERSION, backup_taken: false }))
        }).await?;
        let (from, tenant) = match plan {
            Plan::Done(outcome) => return Ok(outcome),
            Plan::Upgrade { from, tenant } => (from, tenant),
        };
        let Some(backup) = upgrade else {
            return Err(StoreError::InvalidInput(
                "older schema requires a verified pre-upgrade backup",
            ));
        };
        // The backup has its own tool deadlines, outside the maintenance window.
        // The process keeps the fenced guard throughout and rechecks it below.
        owner
            .check()
            .await
            .map_err(|_| StoreError::AuthorityFenced)?;
        backup
            .take(from, &tenant)
            .await
            .map_err(StoreError::InvalidInput)?;
        maintenance(&owner, async {
            let database = Database::connect_existing(url).await?;
            let (version, _) = recorded_metadata(&database, &owner, issuer_key_id).await?;
            if version != from {
                return Err(StoreError::UnsupportedSchemaVersion);
            }
            database.validate_existing_schema_version().await?;
            database.migrate().await?;
            if !database.state_columns_present(SCHEMA_VERSION).await? {
                return Err(StoreError::UnsupportedSchemaVersion);
            }
            let changed = match &database {
                Database::Sqlite(pool) => sqlx::query(
                    "UPDATE controller_meta SET schema_version=? WHERE id=1 AND schema_version=?",
                )
                .bind(SCHEMA_VERSION)
                .bind(from)
                .execute(pool)
                .await
                .map_err(StoreError::Database)?
                .rows_affected(),
                Database::Postgres(pool) => sqlx::query(
                    "UPDATE controller_meta SET schema_version=$1 WHERE id=1 AND schema_version=$2",
                )
                .bind(
                    i32::try_from(SCHEMA_VERSION)
                        .map_err(|_| StoreError::UnsupportedSchemaVersion)?,
                )
                .bind(i32::try_from(from).map_err(|_| StoreError::UnsupportedSchemaVersion)?)
                .execute(pool)
                .await
                .map_err(StoreError::Database)?
                .rows_affected(),
            };
            if changed != 1 {
                return Err(StoreError::UnsupportedSchemaVersion);
            }
            current_metadata(&database, &owner, issuer_key_id).await?;
            database.validate_existing_schema_version().await?;
            close_database(&database).await;
            let store =
                Self::connect_existing_owned(url, tolerance_ms, owner.clone(), issuer_key_id)
                    .await?;
            store.close().await;
            Ok(())
        })
        .await?;
        backup.retain();
        Ok(MigrationOutcome {
            from_schema: from,
            to_schema: SCHEMA_VERSION,
            backup_taken: true,
        })
    }

    /// Clock repair cannot run under active/recovering ownership or clear a
    /// durable recovery intent. It does not reserve/activate a recovery epoch.
    pub async fn reconcile_clock_owned(
        url: &str,
        owner: Arc<ProcessOwnership>,
        issuer_key_id: &str,
    ) -> Result<super::ClockReconciliation, StoreError> {
        crate::handoff::refuse_retired_source(url)?;
        maintenance(&owner, async {
            let database = Database::connect_existing(url).await?;
            current_metadata(&database, &owner, issuer_key_id).await?;
            database.validate_existing_schema_version().await?;
            let recoveries: i64 = match &database {
                Database::Sqlite(pool) => {
                    sqlx::query_scalar("SELECT COUNT(*) FROM controller_recoveries")
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?
                }
                Database::Postgres(pool) => {
                    sqlx::query_scalar("SELECT COUNT(*) FROM controller_recoveries")
                        .fetch_one(pool)
                        .await
                        .map_err(StoreError::Database)?
                }
            };
            if recoveries != 0 {
                return Err(StoreError::RecoveryRequired);
            }
            close_database(&database).await;
            Self::reconcile_clock(url).await
        })
        .await
    }
}

enum Plan {
    Done(MigrationOutcome),
    Upgrade { from: i64, tenant: String },
}

async fn current_metadata(
    database: &Database,
    owner: &ProcessOwnership,
    issuer_key_id: &str,
) -> Result<(), StoreError> {
    let (version, _) = recorded_metadata(database, owner, issuer_key_id).await?;
    if version != SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchemaVersion);
    }
    Ok(())
}

/// Tenant, issuer and epoch must match the protected record whatever the
/// schema version; the version itself is the caller's decision.
async fn recorded_metadata(
    database: &Database,
    owner: &ProcessOwnership,
    issuer_key_id: &str,
) -> Result<(i64, String), StoreError> {
    let row: Option<(i64,String,i64)> = match database {
        Database::Sqlite(pool) => sqlx::query_as("SELECT schema_version,tenant_id,issuer_epoch FROM controller_meta WHERE id=1 AND typeof(schema_version)='integer' AND typeof(tenant_id)='text' AND typeof(issuer_epoch)='integer'").fetch_optional(pool).await.map_err(StoreError::Database)?,
        Database::Postgres(pool) => sqlx::query_as("SELECT CAST(schema_version AS BIGINT),tenant_id,issuer_epoch FROM controller_meta WHERE id=1").fetch_optional(pool).await.map_err(StoreError::Database)?,
    };
    let (version, tenant, epoch) = row.ok_or(StoreError::MissingState("controller metadata"))?;
    if !u64::try_from(epoch).is_ok_and(crate::legacy_authority::safe_epoch)
        || !owner.matches_controller(&tenant, issuer_key_id)
        || !owner.matches_epoch(epoch as u64)
    {
        return Err(StoreError::AuthorityFenced);
    }
    Ok((version, tenant))
}

async fn close_database(database: &Database) {
    match database {
        Database::Sqlite(pool) => pool.close().await,
        Database::Postgres(pool) => pool.close().await,
    }
}

async fn maintenance<T>(
    owner: &Arc<ProcessOwnership>,
    future: impl std::future::Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    owner
        .check()
        .await
        .map_err(|_| StoreError::AuthorityFenced)?;
    let mut operation = owner
        .begin_maintenance_operation()
        .map_err(|_| StoreError::AuthorityFenced)?
        .database_work();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            biased;
            _=owner.wait_fenced()=>Err(StoreError::AuthorityFenced),
            result=future=> {
                owner.check().await.map_err(|_|StoreError::AuthorityFenced)?;
                result
            },
        }
    })
    .await
    .unwrap_or(Err(StoreError::AuthorityFenced));
    super::acknowledge_database_work(&mut operation, &result);
    if result.is_err() {
        owner.fence();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn p06_pw06_snapshot_mode_cannot_be_reused_for_ordinary_work_or_signing() {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(std::env::temp_dir().join(format!(
            "blindpass-p06-snapshot-{}",
            super::super::new_uuid()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.0.join("controller.db").display()
        );
        let source = Store::connect(&url).await.unwrap();
        let snapshot = Store::connect_existing_for_snapshot(&url, 2000)
            .await
            .unwrap();
        assert!(matches!(
            snapshot.database_now_ms().await,
            Err(StoreError::AuthorityFenced)
        ));
        assert!(matches!(
            snapshot
                .create_secret_request("P06_DUMMY", "dummy", "dummy", "123456", 60)
                .await,
            Err(StoreError::AuthorityFenced)
        ));
        let signer = super::super::FleetSigner::new(Arc::new(
            blindpass_core::signing::ed25519::Ed25519KeyPair::from_seed(&[b'I'; 32]).unwrap(),
        ));
        let snapshot = snapshot.with_fleet_signer(signer);
        assert!(matches!(
            snapshot
                .sign_node_document(
                    blindpass_core::fleet::DocumentKind::TimeReply,
                    blindpass_core::canon::Value::Object(Default::default()),
                    1
                )
                .await,
            Err(StoreError::AuthorityFenced)
        ));
        assert!(snapshot.recovery_status().await.unwrap().is_none());
        snapshot.close().await;
        source.close().await;
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
use super::{Database, SCHEMA_TABLES, STATE_COLUMNS, Store, StoreError};
use crate::backup::SnapshotInfo;
use sqlx::{
    Postgres, Row, SqlitePool, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Holds the source transaction open until the matching dump has finished.
/// Dropping this guard queues SQLx rollback; explicit close awaits rollback.
pub struct PostgresSnapshot {
    transaction: Transaction<'static, Postgres>,
    id: String,
    schema: String,
    info: SnapshotInfo,
    started: Instant,
}

impl PostgresSnapshot {
    pub fn info(&self) -> &SnapshotInfo {
        &self.info
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn id(&self) -> Result<&str, crate::backup::BackupError> {
        if self.started.elapsed() >= Duration::from_secs(60) {
            return Err(crate::backup::BackupError("PostgreSQL snapshot expired"));
        }
        Ok(&self.id)
    }

    pub async fn close(self) -> Result<(), crate::backup::BackupError> {
        tokio::time::timeout(Duration::from_secs(5), self.transaction.rollback())
            .await
            .map_err(|_| crate::backup::BackupError("PostgreSQL snapshot close timed out"))?
            .map_err(|_| crate::backup::BackupError("PostgreSQL snapshot close failed"))
    }
}

/// Validates the one controller schema and reads its identity and row counts
/// inside the caller's transaction. Used for the live source snapshot and for
/// the restored isolated copy, so both are measured identically.
pub(crate) async fn collect_snapshot_info(
    transaction: &mut Transaction<'static, Postgres>,
) -> Result<(String, SnapshotInfo), StoreError> {
    let schemas: Vec<String> = sqlx::query_scalar("SELECT unnest(current_schemas(false))::text")
        .fetch_all(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    if schemas.len() != 1 || schemas[0].starts_with("pg_") || schemas[0] == "information_schema" {
        return Err(StoreError::InvalidInput(
            "backup requires one controller schema",
        ));
    }
    let schema = schemas[0].clone();
    let tables: Vec<String> = sqlx::query_scalar("SELECT c.relname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') ORDER BY c.relname")
            .bind(&schema).fetch_all(&mut **transaction).await.map_err(StoreError::Database)?;
    if !tables.iter().any(|table| table == "controller_meta") {
        return Err(StoreError::UnsupportedSchemaVersion);
    }
    // A supported older schema (the pre-upgrade backup) is shaped as that version:
    // only the tables and columns introduced up to it are required.
    let recorded: i32 = sqlx::query_scalar(&format!(
        "SELECT schema_version FROM {}.controller_meta WHERE id = 1",
        quoted(&schema)
    ))
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    let recorded = i64::from(recorded);
    if !crate::backup::supported_snapshot_schema(recorded) {
        return Err(StoreError::UnsupportedSchemaVersion);
    }
    if tables.len() > 256
        || SCHEMA_TABLES
            .iter()
            .filter(|(introduced, _)| *introduced <= recorded)
            .any(|(_, required)| {
                required
                    .iter()
                    .any(|name| !tables.iter().any(|table| table == name))
            })
    {
        return Err(StoreError::UnsupportedSchemaVersion);
    }
    // Access-share locks do not block ordinary writes. Hold every relation
    // against concurrent drop/alter through export and the eventual dump.
    for table in &tables {
        sqlx::query(&format!(
            "LOCK TABLE {}.{} IN ACCESS SHARE MODE",
            quoted(&schema),
            quoted(table)
        ))
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
    }
    for (_, table, required) in STATE_COLUMNS
        .iter()
        .filter(|(introduced, _, _)| *introduced <= recorded)
    {
        let columns: Vec<String> = sqlx::query_scalar("SELECT a.attname::text FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped")
                .bind(&schema).bind(table).fetch_all(&mut **transaction).await.map_err(StoreError::Database)?;
        if required
            .iter()
            .any(|name| !columns.iter().any(|column| column == name))
        {
            return Err(StoreError::UnsupportedSchemaVersion);
        }
    }
    let (version, tenant, epoch): (i32, String, i64) = sqlx::query_as(&format!(
        "SELECT schema_version, tenant_id, issuer_epoch FROM {}.controller_meta WHERE id = 1",
        quoted(&schema)
    ))
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    let clock_ms: i64 = sqlx::query_scalar(&format!(
        "SELECT last_observed_ms FROM {}.controller_clock WHERE id = 1",
        quoted(&schema)
    ))
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::Database)?;
    if i64::from(version) != recorded
        || tenant.is_empty()
        || tenant.len() > 128
        || epoch < 1
        || clock_ms < 1
    {
        return Err(StoreError::UnsupportedSchemaVersion);
    }
    let mut table_rows = BTreeMap::new();
    for table in tables {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {}.{}",
            quoted(&schema),
            quoted(&table)
        ))
        .fetch_one(&mut **transaction)
        .await
        .map_err(StoreError::Database)?;
        table_rows.insert(
            table,
            u64::try_from(count).map_err(|_| StoreError::InvalidInput("snapshot count"))?,
        );
    }
    Ok((
        schema,
        SnapshotInfo {
            schema_version: i64::from(version),
            tenant_id: tenant,
            recovery_generation: epoch as u64,
            clock_ms,
            table_rows,
        },
    ))
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

impl Store {
    pub(crate) async fn begin_postgres_snapshot(&self) -> Result<PostgresSnapshot, StoreError> {
        let Database::Postgres(pool) = &self.database else {
            return Err(StoreError::InvalidInput("PostgreSQL backup backend"));
        };
        let started = Instant::now();
        let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        for setting in [
            "SET LOCAL statement_timeout = '60s'",
            "SET LOCAL lock_timeout = '5s'",
            "SET LOCAL idle_in_transaction_session_timeout = '60s'",
        ] {
            sqlx::query(setting)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Database)?;
        }
        let (schema, info) = collect_snapshot_info(&mut transaction).await?;
        let id: String = sqlx::query_scalar("SELECT pg_catalog.pg_export_snapshot()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(StoreError::Database)?;
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err(StoreError::InvalidInput("snapshot identifier"));
        }
        Ok(PostgresSnapshot {
            transaction,
            id,
            schema,
            started,
            info,
        })
    }

    pub(crate) async fn capture_sqlite(&self, output: &Path) -> Result<SnapshotInfo, StoreError> {
        let Database::Sqlite(pool) = &self.database else {
            return Err(StoreError::InvalidInput("SQLite backup backend"));
        };
        let filename = output
            .to_str()
            .ok_or(StoreError::InvalidInput("backup output"))?;
        // SQLite accepts an existing empty output file. Its mode is already
        // 0600 inside private staging; never copy a live database or its WAL.
        sqlx::query("VACUUM INTO ?")
            .bind(filename)
            .execute(pool)
            .await
            .map_err(StoreError::Database)?;
        inspect_sqlite(output).await
    }
}

pub(crate) async fn inspect_sqlite(path: &Path) -> Result<SnapshotInfo, StoreError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .immutable(true)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(StoreError::Database)?;
    let result = inspect_pool(&pool).await;
    pool.close().await;
    result
}

async fn inspect_pool(pool: &SqlitePool) -> Result<SnapshotInfo, StoreError> {
    let integrity: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(pool)
        .await
        .map_err(StoreError::Database)?;
    if integrity != ["ok"]
        || !sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(pool)
            .await
            .map_err(StoreError::Database)?
            .is_empty()
    {
        return Err(StoreError::InvalidInput("backup snapshot integrity"));
    }
    Database::Sqlite(pool.clone())
        .validate_existing_schema_version()
        .await?;
    let meta = sqlx::query(
        "SELECT schema_version, tenant_id, issuer_epoch FROM controller_meta WHERE id = 1",
    )
    .fetch_one(pool)
    .await
    .map_err(StoreError::Database)?;
    let schema_version: i64 = meta
        .try_get("schema_version")
        .map_err(StoreError::Database)?;
    let tenant_id: String = meta.try_get("tenant_id").map_err(StoreError::Database)?;
    let epoch: i64 = meta.try_get("issuer_epoch").map_err(StoreError::Database)?;
    if !crate::backup::supported_snapshot_schema(schema_version)
        || tenant_id.is_empty()
        || epoch < 1
    {
        return Err(StoreError::UnsupportedSchemaVersion);
    }
    let clock_ms: i64 =
        sqlx::query_scalar("SELECT last_observed_ms FROM controller_clock WHERE id = 1")
            .fetch_one(pool)
            .await
            .map_err(StoreError::Database)?;
    let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .fetch_all(pool).await.map_err(StoreError::Database)?;
    let mut table_rows = BTreeMap::new();
    for name in tables {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM \"{}\"",
            name.replace('"', "\"\"")
        ))
        .fetch_one(pool)
        .await
        .map_err(StoreError::Database)?;
        table_rows.insert(
            name,
            u64::try_from(count).map_err(|_| StoreError::InvalidInput("snapshot count"))?,
        );
    }
    Ok(SnapshotInfo {
        schema_version,
        tenant_id,
        recovery_generation: epoch as u64,
        clock_ms,
        table_rows,
    })
}

/// Private verification cluster only: connect over its Unix socket.
fn socket_options(socket: &Path, user: &str, database: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .socket(socket)
        .username(user)
        .database(database)
}

pub(crate) async fn postgres_socket_ready(socket: &Path, user: &str, database: &str) -> bool {
    let Ok(Ok(pool)) = tokio::time::timeout(
        Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(socket_options(socket, user, database)),
    )
    .await
    else {
        return false;
    };
    pool.close().await;
    true
}

/// Create the unprivileged restore role and its empty database.
pub(crate) async fn prepare_restore_target(
    socket: &Path,
    admin: &str,
    role: &str,
    database: &str,
) -> Result<(), StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(socket_options(socket, admin, "postgres"))
        .await
        .map_err(StoreError::Database)?;
    let result = async {
        sqlx::query(&format!(
            "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE",
            quoted(role)
        ))
        .execute(&pool)
        .await?;
        sqlx::query(&format!(
            "CREATE DATABASE {} OWNER {}",
            quoted(database),
            quoted(role)
        ))
        .execute(&pool)
        .await?;
        Ok(())
    }
    .await
    .map_err(StoreError::Database);
    pool.close().await;
    result
}

/// Measure the restored copy exactly as the live snapshot was measured. The
/// dump carries exactly one controller schema; any other shape is refused.
pub(crate) async fn inspect_restored_postgres(
    socket: &Path,
    user: &str,
    database: &str,
) -> Result<SnapshotInfo, StoreError> {
    inspect_restored_with(socket_options(socket, user, database))
        .await
        .map(|(_, info)| info)
}

/// The same measurement of the restored schema in a real target database.
pub(crate) async fn inspect_restored_target(
    url: &str,
) -> Result<(String, SnapshotInfo), StoreError> {
    inspect_restored_with(target_options(url)?).await
}

async fn inspect_restored_with(
    options: PgConnectOptions,
) -> Result<(String, SnapshotInfo), StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .map_err(StoreError::Database)?;
    let schemas: Vec<String> = sqlx::query_scalar(
        "SELECT nspname::text FROM pg_catalog.pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema', 'public')",
    )
    .fetch_all(&pool)
    .await
    .map_err(StoreError::Database)?;
    pool.close().await;
    let [schema] = schemas.as_slice() else {
        return Err(StoreError::InvalidInput("restored schema"));
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .map_err(StoreError::Database)?;
    let result = async {
        let mut transaction = pool.begin().await.map_err(StoreError::Database)?;
        collect_snapshot_info(&mut transaction)
            .await
            .map(|(_, info)| (schema.clone(), info))
    }
    .await;
    pool.close().await;
    result
}

fn target_options(url: &str) -> Result<PgConnectOptions, StoreError> {
    url.parse::<PgConnectOptions>()
        .map_err(|_| StoreError::InvalidInput("restore target"))
}

/// Marker for a target whose only occupant is one empty schema (the Compose init hook's).
pub(crate) const RESTORE_TARGET_EMPTY_SCHEMA: &str = "restore target holds only an empty schema";

/// A PostgreSQL restore target must hold no user schema and no object in
/// `public`: restoring never merges into or replaces existing state.
pub(crate) async fn require_empty_restore_target(url: &str) -> Result<(), StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(target_options(url)?)
        .await
        .map_err(StoreError::Database)?;
    let result = async {
        let occupied: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM pg_catalog.pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema', 'public')) \
                  + (SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public') \
                  + (SELECT COUNT(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public')",
        )
        .fetch_one(&pool)
        .await
        .map_err(StoreError::Database)?;
        if occupied != 0 {
            // The shipped Compose init hook leaves one empty schema. Name that case so
            // the operator knows to drop it; anything else stays the generic refusal.
            let only_empty: bool = sqlx::query_scalar(
                "SELECT (SELECT COUNT(*) FROM pg_catalog.pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('information_schema', 'public')) = 1 \
                    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema') \
                    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema') \
                    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema')",
            )
            .fetch_one(&pool)
            .await
            .map_err(StoreError::Database)?;
            return Err(StoreError::InvalidInput(if only_empty {
                RESTORE_TARGET_EMPTY_SCHEMA
            } else {
                "restore target is not empty"
            }));
        }
        Ok(())
    }
    .await;
    pool.close().await;
    result
}

/// Remove a schema this process just restored and still owns the decision
/// about. Never used on a schema that existed before the restore.
pub(crate) async fn drop_restored_schema(url: &str, schema: &str) -> Result<(), StoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(target_options(url)?)
        .await
        .map_err(StoreError::Database)?;
    let result = sqlx::query(&format!("DROP SCHEMA {} CASCADE", quoted(schema)))
        .execute(&pool)
        .await
        .map(|_| ())
        .map_err(StoreError::Database);
    pool.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL via P02_TEST_POSTGRES_URL"]
    async fn p06_pgs04_postgres_snapshot_is_read_only_and_refuses_multiple_schemas() {
        let parent =
            std::env::var("P02_TEST_POSTGRES_URL").expect("isolated test database required");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&parent)
            .await
            .expect("test database connection");
        let schema = format!(
            "p06_readonly_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let separator = if parent.contains('?') { '&' } else { '?' };
        let url = format!("{parent}{separator}options=-c%20search_path%3D{schema}");
        let store = Store::connect(&url)
            .await
            .expect("isolated store initialization");
        let mut snapshot = store.begin_postgres_snapshot().await.unwrap();
        let readonly: String = sqlx::query_scalar("SHOW transaction_read_only")
            .fetch_one(&mut *snapshot.transaction)
            .await
            .unwrap();
        assert_eq!(readonly, "on");
        let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut *snapshot.transaction)
            .await
            .unwrap();
        assert_eq!(isolation, "repeatable read");
        for (setting, expected) in [
            ("statement_timeout", "1min"),
            ("lock_timeout", "5s"),
            ("idle_in_transaction_session_timeout", "1min"),
        ] {
            let value: String = sqlx::query_scalar(&format!("SHOW {setting}"))
                .fetch_one(&mut *snapshot.transaction)
                .await
                .unwrap();
            assert_eq!(value, expected);
        }
        snapshot.started -= Duration::from_secs(60);
        assert!(snapshot.id().is_err());
        let epoch = snapshot.info().recovery_generation;
        let error =
            sqlx::query("UPDATE controller_meta SET issuer_epoch = issuer_epoch + 1 WHERE id = 1")
                .execute(&mut *snapshot.transaction)
                .await
                .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("25006")
        );
        snapshot.close().await.unwrap();
        let unchanged: i64 = sqlx::query_scalar(&format!(
            "SELECT issuer_epoch FROM {schema}.controller_meta WHERE id = 1"
        ))
        .fetch_one(&admin)
        .await
        .unwrap();
        assert_eq!(unchanged as u64, epoch);
        let multiple = Store::connect_existing(&format!("{url}%2Cpublic"), 2000)
            .await
            .expect("existing multi-schema store");
        assert!(multiple.begin_postgres_snapshot().await.is_err());
        multiple.close().await;
        store.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}

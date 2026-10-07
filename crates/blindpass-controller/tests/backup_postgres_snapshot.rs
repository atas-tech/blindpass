// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::{backup::begin_postgres_snapshot, store::Store};
use sqlx::{PgPool, postgres::PgPoolOptions};

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    store: Store,
    schema: String,
}

impl Fixture {
    async fn new() -> Self {
        let parent =
            std::env::var("P02_TEST_POSTGRES_URL").expect("isolated test database required");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&parent)
            .await
            .expect("test database connection");
        let schema = format!(
            "p06_snapshot_{}_{}",
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
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("isolated pool connection");
        Self {
            admin,
            pool,
            store,
            schema,
        }
    }

    async fn close(self) {
        self.store.close().await;
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via P02_TEST_POSTGRES_URL"]
async fn p06_pgs01_import_matches_metadata_and_complete_pairs_during_writes() {
    let f = Fixture::new().await;
    sqlx::query("CREATE TABLE snapshot_pairs (id BIGINT PRIMARY KEY, value BIGINT NOT NULL)")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO snapshot_pairs VALUES (1, 7), (2, 7)")
        .execute(&f.pool)
        .await
        .unwrap();
    let snapshot = begin_postgres_snapshot(&f.store).await.unwrap();
    assert_eq!(snapshot.schema(), f.schema);
    assert_eq!(snapshot.info().table_rows["snapshot_pairs"], 2);
    let old = snapshot.info().clone();
    let mut write = f.pool.begin().await.unwrap();
    sqlx::query("INSERT INTO snapshot_pairs VALUES (3, 8), (4, 8)")
        .execute(&mut *write)
        .await
        .unwrap();
    sqlx::query("UPDATE controller_meta SET tenant_id = 'P06-DUMMY-NEW-TENANT', issuer_epoch = issuer_epoch + 1 WHERE id = 1").execute(&mut *write).await.unwrap();
    sqlx::query("UPDATE controller_clock SET last_observed_ms = last_observed_ms + 1 WHERE id = 1")
        .execute(&mut *write)
        .await
        .unwrap();
    write.commit().await.unwrap();
    let mut imported = f.pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *imported)
        .await
        .unwrap();
    sqlx::query(&format!(
        "SET TRANSACTION SNAPSHOT '{}'",
        snapshot.id().unwrap()
    ))
    .execute(&mut *imported)
    .await
    .unwrap();
    let meta: (String, i64, i64) = sqlx::query_as("SELECT m.tenant_id, m.issuer_epoch, c.last_observed_ms FROM controller_meta m CROSS JOIN controller_clock c WHERE m.id = 1 AND c.id = 1").fetch_one(&mut *imported).await.unwrap();
    assert_eq!(
        meta,
        (old.tenant_id, old.recovery_generation as i64, old.clock_ms)
    );
    let pairs: Vec<(i64, i64)> =
        sqlx::query_as("SELECT value, COUNT(*) FROM snapshot_pairs GROUP BY value")
            .fetch_all(&mut *imported)
            .await
            .unwrap();
    assert_eq!(pairs, [(7, 2)]);
    for (table, count) in &snapshot.info().table_rows {
        let actual: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM \"{}\"",
            table.replace('"', "\"\"")
        ))
        .fetch_one(&mut *imported)
        .await
        .unwrap();
        assert_eq!(actual as u64, *count, "snapshot count: {table}");
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM snapshot_pairs")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        4
    );
    imported.rollback().await.unwrap();
    snapshot.close().await.unwrap();
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via P02_TEST_POSTGRES_URL"]
async fn p06_pgs02_close_and_drop_revoke_exported_snapshot() {
    let f = Fixture::new().await;
    for explicit in [true, false] {
        let snapshot = begin_postgres_snapshot(&f.store).await.unwrap();
        let id = snapshot.id().unwrap().to_owned();
        if explicit {
            snapshot.close().await.unwrap();
        } else {
            drop(snapshot);
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut imported = f.pool.begin().await.unwrap();
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *imported)
                .await
                .unwrap();
            let denied = sqlx::query(&format!("SET TRANSACTION SNAPSHOT '{id}'"))
                .execute(&mut *imported)
                .await
                .is_err();
            imported.rollback().await.unwrap();
            if denied {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "exporter rollback exceeded deadline"
            );
            tokio::task::yield_now().await;
        }
    }
    f.close().await;
}

#[tokio::test]
async fn p06_pgs04_sqlite_cannot_export_a_postgres_snapshot() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let tenant = store.tenant_id().to_owned();
    assert!(begin_postgres_snapshot(&store).await.is_err());
    assert_eq!(store.tenant_id(), tenant);
    store.close().await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via P02_TEST_POSTGRES_URL"]
async fn p06_pgs03_missing_schema_and_damaged_metadata_are_not_repaired() {
    let f = Fixture::new().await;
    sqlx::query("UPDATE controller_meta SET issuer_epoch = 0 WHERE id = 1")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(begin_postgres_snapshot(&f.store).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT issuer_epoch FROM controller_meta WHERE id = 1")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    sqlx::query("UPDATE controller_meta SET issuer_epoch = 1 WHERE id = 1")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE fleet_provisioning_receipts RENAME COLUMN tenant_id TO missing_tenant_id",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(begin_postgres_snapshot(&f.store).await.is_err());
    sqlx::query(
        "ALTER TABLE fleet_provisioning_receipts RENAME COLUMN missing_tenant_id TO tenant_id",
    )
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::query("DROP TABLE fleet_provisioning_receipts")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(begin_postgres_snapshot(&f.store).await.is_err());
    assert!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT to_regclass('fleet_provisioning_receipts')::text"
        )
        .fetch_one(&f.pool)
        .await
        .unwrap()
        .is_none()
    );
    f.close().await;
}

// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_controller::{
    backup::{capture_sqlite, inspect_sqlite},
    store::Store,
};
use sqlx::Row;
use sqlx::sqlite::SqlitePoolOptions;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn p06_b01_live_wal_snapshot_preserves_complete_transactions_and_metadata() {
    let dir = std::env::temp_dir().join(format!(
        "blindpass-backup-snapshot-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.join("source.db").display());
    let store = Store::connect(&url).await.unwrap();
    let writer = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE snapshot_pairs (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)")
        .execute(&writer)
        .await
        .unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    let writing = tokio::spawn(async move {
        let mut count = 0i64;
        while !stop.load(Ordering::SeqCst) || count == 0 {
            let mut transaction = writer.begin().await.unwrap();
            for side in 0..2 {
                sqlx::query("INSERT INTO snapshot_pairs (id, value) VALUES (?, ?)")
                    .bind(count * 2 + side)
                    .bind(count)
                    .execute(&mut *transaction)
                    .await
                    .unwrap();
            }
            transaction.commit().await.unwrap();
            count += 1;
            tokio::task::yield_now().await;
        }
        writer.close().await;
        count
    });
    // Establish a committed WAL-only mutation before capturing under load.
    let observer = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    for _ in 0..1000 {
        if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM snapshot_pairs")
            .fetch_one(&observer)
            .await
            .unwrap()
            > 0
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    observer.close().await;
    let info = capture_sqlite(&store, &dir.join("snapshot.db"))
        .await
        .unwrap();
    done.store(true, Ordering::SeqCst);
    assert!(writing.await.unwrap() > 0);
    assert!(info.table_rows["snapshot_pairs"] > 0);
    assert_eq!(info.table_rows["snapshot_pairs"] % 2, 0);
    assert_eq!(
        info,
        inspect_sqlite(&dir.join("snapshot.db")).await.unwrap()
    );
    let snapshot = SqlitePoolOptions::new()
        .connect(&format!(
            "sqlite://{}?mode=ro",
            dir.join("snapshot.db").display()
        ))
        .await
        .unwrap();
    for row in sqlx::query("SELECT value, COUNT(*) AS n FROM snapshot_pairs GROUP BY value")
        .fetch_all(&snapshot)
        .await
        .unwrap()
    {
        assert_eq!(row.get::<i64, _>("n"), 2);
    }
    snapshot.close().await;
    assert_eq!(
        fs::metadata(dir.join("snapshot.db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        capture_sqlite(&store, &dir.join("snapshot.db"))
            .await
            .is_err()
    );
    store.close().await;
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn p06_b09_authentic_snapshot_still_requires_integrity_and_complete_schema() {
    let dir = std::env::temp_dir().join(format!(
        "blindpass-backup-damage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::connect(&format!(
        "sqlite://{}?mode=rwc",
        dir.join("source.db").display()
    ))
    .await
    .unwrap();
    capture_sqlite(&store, &dir.join("snapshot.db"))
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{}", dir.join("snapshot.db").display()))
        .await
        .unwrap();
    sqlx::query("DROP TABLE fleet_provisioning_receipts")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(inspect_sqlite(&dir.join("snapshot.db")).await.is_err());
    fs::write(dir.join("snapshot.db"), b"P06-DUMMY-DAMAGED-DATABASE").unwrap();
    assert!(inspect_sqlite(&dir.join("snapshot.db")).await.is_err());
    store.close().await;
    fs::remove_dir_all(&dir).unwrap();
}

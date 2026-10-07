// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_core::deployment::Directory;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn p06_b06_explicit_cleanup_requires_custody_and_preserves_published_files() {
    let root = std::env::temp_dir().join(format!(
        "blindpass-backup-cleanup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let work = root.join("work");
    let outside = root.join("outside");
    for path in [&work, &outside] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let stage = work.join(format!(".backup-{}", "a".repeat(32)));
    fs::create_dir(&stage).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stage.join("archive.tar"), b"P06-DUMMY-PRIVATE-RESIDUE").unwrap();
    fs::set_permissions(stage.join("archive.tar"), fs::Permissions::from_mode(0o600)).unwrap();
    for path in [
        work.join("controller-backup-dummy.bpbackup"),
        work.join("recovery.pem"),
        work.join(".backup-operator-notes"),
        outside.join("canary"),
    ] {
        fs::write(&path, b"P06-DUMMY-PRESERVE").unwrap();
    }
    let cleanup = || {
        Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .args(["backup", "cleanup", "--work-directory"])
            .arg(&work)
            .output()
            .unwrap()
    };
    let linked = work.join(format!(".backup-{}", "b".repeat(32)));
    symlink(&outside, &linked).unwrap();
    assert!(!cleanup().status.success(), "followed a linked stage");
    assert!(
        stage.join("archive.tar").exists(),
        "deleted before preflight completed"
    );
    fs::remove_file(&linked).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        !cleanup().status.success(),
        "accepted unsafe residue custody"
    );
    assert!(stage.exists());
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&outside, stage.join("outside-link")).unwrap();
    {
        let busy = Directory::open_private(&stage).unwrap();
        busy.lock(false).unwrap();
        assert!(
            !cleanup().status.success(),
            "ignored active nested verification"
        );
        assert!(stage.exists());
    }
    {
        let busy = Directory::open_private(&work).unwrap();
        busy.lock(false).unwrap();
        assert!(
            !cleanup().status.success(),
            "ignored an active verification lock"
        );
        assert!(stage.exists());
    }
    let output = cleanup();
    assert!(
        output.status.success(),
        "explicit private staging cleanup failed"
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["removed_staging_directories"], 1);
    assert!(!stage.exists());
    assert_eq!(fs::read_dir(&work).unwrap().count(), 3);
    assert_eq!(
        fs::read(outside.join("canary")).unwrap(),
        b"P06-DUMMY-PRESERVE"
    );
    let result: serde_json::Value = serde_json::from_slice(&cleanup().stdout).unwrap();
    assert_eq!(result["removed_staging_directories"], 0);
    fs::set_permissions(&work, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        !cleanup().status.success(),
        "accepted unsafe staging custody"
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn p06_b06_killed_capture_cannot_publish_and_explicit_cleanup_removes_private_residue() {
    let root = std::env::temp_dir().join(format!(
        "blindpass-backup-kill-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let keys = root.join("keys");
    blindpass_core::deployment::initialize_keys(&keys).unwrap();
    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let database = data.join("controller.db");
    let url = format!("sqlite://{}?mode=rwc", database.display());
    let store = blindpass_controller::store::Store::connect(&url)
        .await
        .unwrap();
    let writer = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE interruption_payload (id INTEGER PRIMARY KEY, dummy BLOB NOT NULL)")
        .execute(&writer)
        .await
        .unwrap();
    // Enough dummy data to observe actual private capture before publication,
    // without a test-only production delay or a secret exposure canary.
    sqlx::query("INSERT INTO interruption_payload VALUES (1, zeroblob(67108864))")
        .execute(&writer)
        .await
        .unwrap();
    writer.close().await;
    store.close().await;
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    let recovery = root.join("recovery.pem");
    blindpass_controller::backup::initialize_recovery_key(&recovery).unwrap();
    let output = data.join("backups");
    let mut child = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .env("BLINDPASS_KEYS_DIR", &keys)
        .env("BLINDPASS_DATA_DIR", &data)
        .env("BLINDPASS_PUBLIC_URL", "https://controller.p06.invalid")
        .env("BLINDPASS_UI_BASE_URL", "https://controller.p06.invalid")
        .args(["backup", "create", "--output"])
        .arg(&output)
        .arg("--recovery-key-file")
        .arg(&recovery)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut observed = false;
    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(entries) = fs::read_dir(&output) {
            observed = entries.filter_map(Result::ok).any(|entry| {
                fs::metadata(entry.path().join("database.sqlite"))
                    .is_ok_and(|metadata| metadata.len() > 1024 * 1024)
            });
        }
        if observed || child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // Kill/reap even on a failed observation, so the test never leaks a child.
    let _ = child.kill();
    let status = child.wait().unwrap();
    assert!(
        observed,
        "did not observe actual plaintext capture before interruption"
    );
    assert!(!status.success());
    let entries: Vec<_> = fs::read_dir(&output).unwrap().map(Result::unwrap).collect();
    assert!(
        !entries.is_empty(),
        "interruption left no residue to exercise cleanup"
    );
    for entry in entries {
        assert!(
            entry.file_name().to_str().unwrap().starts_with(".backup-"),
            "published a partial archive"
        );
        assert_eq!(
            entry.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        for member in fs::read_dir(entry.path()).unwrap().map(Result::unwrap) {
            assert_eq!(
                member.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert_eq!(
        blindpass_controller::backup::cleanup_staging(&output).unwrap(),
        1
    );
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    let source = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    let length: i64 =
        sqlx::query_scalar("SELECT length(dummy) FROM interruption_payload WHERE id = 1")
            .fetch_one(&source)
            .await
            .unwrap();
    assert_eq!(length, 67108864, "cleanup changed production state");
    source.close().await;
    fs::remove_dir_all(root).unwrap();
}

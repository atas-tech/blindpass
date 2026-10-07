// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0011 toolkit tests. They need the exact pinned PostgreSQL toolkit at its
//! fixed path and a non-root user, so they run in the controller test image
//! (`tests/deployment/pg-toolkit-test.sh`), never in ordinary `cargo test`.
//! The source database is a private socket-only cluster created per test.
mod pg_fixture;
use blindpass_controller::backup::{
    ArchiveManifest, Backend, encrypt_bundle, verify_backup, write_archive,
};
use pg_fixture::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires the pinned PostgreSQL toolkit image"]
fn p06_pgt01_postgres_backup_is_a_complete_verified_isolated_restore_without_credential_exposure() {
    let d = Deployment::new();
    // State to prove complete capture: a canary row in an ordinary table.
    let table_before = d.rows("SELECT COUNT(*) FROM p06_src.operators");
    let out = d.work.file("out");
    private_dir(&out);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = watch_for_canary(stop.clone());
    let created = d.create(&out);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        !watcher.join().unwrap(),
        "database password appeared in a process argument or environment"
    );
    assert!(
        created.status.success(),
        "postgres backup failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    for stream in [&created.stdout, &created.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("P06-DUMMY-PG-CANARY"));
    }
    let summary: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(summary["verified"], true);
    let archive = out.join(summary["backup"].as_str().unwrap());
    // Exactly one published file; no plaintext dump, passfile or cluster staging remains.
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    assert_eq!(
        fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = fs::read(&archive).unwrap();
    for needle in [
        PASSWORD.as_bytes(),
        b"PGDMP".as_slice(),
        b"p06_src".as_slice(),
        b"CREATE TABLE".as_slice(),
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked into the sealed archive"
        );
    }
    let key = d.recovery_key();
    let work = d.work.file("verify");
    private_dir(&work);
    let manifest = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(verify_backup(&archive, &key, &work))
        .unwrap();
    assert_eq!(manifest.backend, Backend::Postgres);
    let mut names: Vec<_> = manifest.members.iter().map(|m| m.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "agent-jwt-secret",
            "database.pgcustom",
            "issuer-key",
            "root-secret"
        ]
    );
    assert_eq!(
        manifest.snapshot.table_rows["operators"].to_string(),
        table_before
    );
    assert!(
        fs::read_dir(&work).unwrap().next().is_none(),
        "verification staging remained"
    );
    // The CLI verify path (as an operator would run it) agrees.
    let verified = d.command(
        &[
            "backup".as_ref(),
            "verify".as_ref(),
            "--archive".as_ref(),
            archive.as_os_str(),
            "--recovery-key-file".as_ref(),
            key.as_os_str(),
            "--work-directory".as_ref(),
            work.as_os_str(),
        ],
        false,
    );
    assert!(verified.status.success());
    let value: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(
        (value["verified"].as_bool(), value["backend"].as_str()),
        (Some(true), Some("postgres"))
    );
    // The source database was only read, and no verification server outlived the command.
    assert_eq!(
        d.rows("SELECT COUNT(*) FROM p06_src.operators"),
        table_before
    );
    assert_eq!(
        leftover_postgres_children(),
        0,
        "a verification cluster outlived the command"
    );
}

#[test]
#[ignore = "requires the pinned PostgreSQL toolkit image"]
fn p06_pgt02_capture_is_snapshot_consistent_during_concurrent_writes() {
    let d = Deployment::new();
    let out = d.work.file("out");
    private_dir(&out);
    // A writer commits operators continuously. Backup verification compares the
    // restored row counts with the exported snapshot's counts, so any dump that
    // was not taken at exactly that snapshot would be refused.
    let socket = d.source.socket.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let writer = std::thread::spawn(move || {
        let mut written = 0u32;
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            let sql = format!(
                "INSERT INTO p06_src.operators (id, username, display_name, password_hash, role, created_at) VALUES ('P06_W{written}','w{written}','W','x','viewer',1)"
            );
            let status = Command::new(format!("{BIN}/psql"))
                .env_clear()
                .env("PGPASSWORD", "bootpw")
                .args(["-X", "-q", "-h"])
                .arg(&socket)
                .args(["-U", "boot", "-d", "blindpass", "-c", &sql])
                .stdout(Stdio::null())
                .status()
                .unwrap();
            if status.success() {
                written += 1;
            }
        }
        written
    });
    std::thread::sleep(Duration::from_millis(300));
    let created = d.create(&out);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let written = writer.join().unwrap();
    assert!(written > 0, "the concurrent writer never ran");
    assert!(
        created.status.success(),
        "backup under concurrent writes failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
}

#[test]
#[ignore = "requires the pinned PostgreSQL toolkit image"]
fn p06_pgt03_damaged_or_inconsistent_dump_is_refused_and_leaves_no_residue() {
    let d = Deployment::new();
    let out = d.work.file("out");
    private_dir(&out);
    let created = d.create(&out);
    assert!(created.status.success());
    let summary: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let archive = out.join(summary["backup"].as_str().unwrap());
    let key = d.recovery_key();
    let work = d.work.file("tamper");
    private_dir(&work);
    // Decrypt, then rebuild authenticated archives around altered members.
    let plain = work.join("plain.tar");
    blindpass_controller::backup::decrypt_bundle(&archive, &plain, &key, &work).unwrap();
    let members = d.work.file("members");
    private_dir(&members);
    let manifest: ArchiveManifest =
        blindpass_controller::backup::extract_archive(&plain, &members).unwrap();
    let rebuild = |name: &str, snapshot: &blindpass_controller::backup::SnapshotInfo| {
        let tar = d.work.file(&format!("{name}.tar"));
        write_archive(&members, &tar, Backend::Postgres, snapshot).unwrap();
        let sealed = d.work.file(&format!("{name}.bpbackup"));
        encrypt_bundle(&tar, &sealed, &key, &work).unwrap();
        sealed
    };
    let verify = |path: &Path| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(verify_backup(path, &key, &work))
    };
    // 1. A flipped byte inside the dump body fails the restore (or its checksums).
    let dump = members.join("database.pgcustom");
    let original = fs::read(&dump).unwrap();
    let mut damaged = original.clone();
    let middle = damaged.len() / 2;
    damaged[middle..middle + 64]
        .iter_mut()
        .for_each(|b| *b ^= 0xff);
    fs::write(&dump, &damaged).unwrap();
    let sealed = rebuild("flipped", &manifest.snapshot);
    assert!(verify(&sealed).is_err(), "a damaged dump verified");
    // 2. A truncated dump.
    fs::write(&dump, &original[..original.len() / 2]).unwrap();
    let sealed = rebuild("truncated", &manifest.snapshot);
    assert!(verify(&sealed).is_err(), "a truncated dump verified");
    // 3. A valid dump whose authenticated manifest claims different state.
    fs::write(&dump, &original).unwrap();
    let mut forged = manifest.snapshot.clone();
    *forged.table_rows.get_mut("operators").unwrap() += 1;
    let sealed = rebuild("forged", &forged);
    assert!(
        verify(&sealed).is_err(),
        "inconsistent snapshot metadata verified"
    );
    // 4. The untouched dump with its true manifest still verifies.
    let sealed = rebuild("genuine", &manifest.snapshot);
    verify(&sealed).unwrap();
    assert!(
        fs::read_dir(&work)
            .unwrap()
            .filter_map(Result::ok)
            .all(|e| !e.file_name().to_string_lossy().starts_with(".backup-")),
        "failed verification left staging"
    );
    assert_eq!(leftover_postgres_children(), 0);
}

#[test]
#[ignore = "requires the pinned PostgreSQL toolkit image"]
fn p06_pgt04_unreachable_database_or_bad_credentials_fail_closed_without_residue() {
    let d = Deployment::new();
    let out = d.work.file("out");
    private_dir(&out);
    // Wrong password in the URL file.
    fs::write(
        d.work.file("database-url"),
        d.source.url().replace("%3A", "%3B"),
    )
    .unwrap();
    let created = d.create(&out);
    assert!(!created.status.success());
    assert_eq!(
        fs::read_dir(&out).unwrap().count(),
        0,
        "a failed backup left files behind"
    );
    assert!(!String::from_utf8_lossy(&created.stderr).contains("P06-DUMMY-PG-CANARY"));
    // Stopped source database.
    fs::write(d.work.file("database-url"), d.source.url()).unwrap();
    let mut d = d;
    let mut server = d.source.server.take().unwrap();
    server.kill().unwrap();
    server.wait().unwrap();
    let created = d.create(&out);
    assert!(!created.status.success());
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    assert_eq!(leftover_postgres_children(), 0);
}

#[test]
#[ignore = "requires the pinned PostgreSQL toolkit image"]
fn p06_pgt05_killing_the_backup_command_stops_every_toolkit_child_and_cleanup_removes_residue() {
    let d = Deployment::new();
    // A payload large enough that capture and the restore verification last for a while.
    assert!(
        d.source
            .admin_in(
                "blindpass",
                "CREATE TABLE p06_src.p06_payload (id integer primary key, payload text not null); \
                 INSERT INTO p06_src.p06_payload SELECT g, repeat(md5(g::text), 4096) FROM generate_series(1, 400) g; \
                 GRANT ALL ON p06_src.p06_payload TO ctl",
            )
            .status
            .success()
    );
    let key = d.recovery_key();
    for (phase, needle) in [("capture", "pg_dump"), ("verification", "pgdata")] {
        let out = d.work.file(&format!("out-{phase}"));
        private_dir(&out);
        let mut child = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
            .env_clear()
            .env("BLINDPASS_KEYS_DIR", &d.keys)
            .env("BLINDPASS_DATA_DIR", d.work.file("data"))
            .env("BLINDPASS_PUBLIC_URL", "https://controller.p06.invalid")
            .env("BLINDPASS_UI_BASE_URL", "https://controller.p06.invalid")
            .env("BLINDPASS_DATABASE_URL_FILE", d.work.file("database-url"))
            .env("BLINDPASS_AUTHORITY_URL_FILE", &d.authority)
            .env("BLINDPASS_CONTROLLER_TENANT_ID", "P06_DUMMY_PGT")
            .env("BLINDPASS_CONTROLLER_OWNER_ID", "P06_DUMMY_PGT_OWNER")
            .args(["backup", "create", "--output"])
            .arg(&out)
            .arg("--recovery-key-file")
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let mut children = Vec::new();
        while children.is_empty() {
            children = processes_matching(needle);
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "phase {phase} never started"
            );
            if child.try_wait().unwrap().is_some() {
                panic!("backup finished before phase {phase} could be interrupted");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        // Parent-death signalling must stop the tool children promptly.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !processes_matching(needle).is_empty() {
            assert!(
                Instant::now() < deadline,
                "{phase}: a toolkit child survived its killed parent"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            fs::read_dir(&out)
                .unwrap()
                .flatten()
                .all(|e| e.file_name().to_string_lossy().starts_with(".backup-")),
            "{phase}: a partial file was published"
        );
        assert!(
            fs::read_dir(&out)
                .unwrap()
                .flatten()
                .all(|e| !e.file_name().to_string_lossy().ends_with(".bpbackup"))
        );
        // Explicit cleanup removes the private residue and nothing else.
        let cleaned = d.command(
            &[
                "backup".as_ref(),
                "cleanup".as_ref(),
                "--work-directory".as_ref(),
                out.as_os_str(),
            ],
            false,
        );
        assert!(cleaned.status.success(), "{phase}: cleanup failed");
        assert_eq!(
            fs::read_dir(&out).unwrap().count(),
            0,
            "{phase}: residue survived cleanup"
        );
        // The source stays usable and a fresh backup still succeeds.
        let again = d.create(&out);
        assert!(
            again.status.success(),
            "{phase}: backup after interruption failed"
        );
        for entry in fs::read_dir(&out).unwrap().flatten() {
            fs::remove_file(entry.path()).unwrap();
        }
    }
    assert_eq!(leftover_postgres_children(), 0);
}

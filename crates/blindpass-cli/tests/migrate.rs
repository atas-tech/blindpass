// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Writing then executing a fixture while another test forks yields ETXTBSY (the forked
// child holds the write descriptor until it execs); every test that spawns the CLI
// therefore holds this lock and they run one at a time.
static EXEC: Mutex<()> = Mutex::new(());

struct SocketDirectory(PathBuf);

impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn migrate_dispatches_to_colocated_controller_binary() {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "blindpass-cli-migrate-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create CLI fixture directory");
    let cli = directory.join("blindpass");
    std::fs::copy(env!("CARGO_BIN_EXE_blindpass"), &cli).expect("copy CLI binary");
    let controller = directory.join("blindpass-controller");
    let marker = directory.join("invocation.txt");
    std::fs::write(
        &controller,
        "#!/bin/sh\nprintf '%s' \"$1\" > \"$BLINDPASS_TEST_MARKER\"\n",
    )
    .expect("write controller fixture");
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))
        .expect("make controller fixture executable");
    let output = Command::new(&cli)
        .arg("migrate")
        .env("BLINDPASS_TEST_MARKER", &marker)
        .output()
        .expect("run CLI migration");
    assert!(
        output.status.success(),
        "CLI migration failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "migrate");
    std::fs::remove_dir_all(&directory).expect("remove fixture directory");
}

#[test]
fn p06_up11_migrate_forwards_the_pre_upgrade_backup_arguments_unchanged() {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "blindpass-cli-upgrade-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create CLI fixture directory");
    let cli = directory.join("blindpass");
    std::fs::copy(env!("CARGO_BIN_EXE_blindpass"), &cli).expect("copy CLI binary");
    let controller = directory.join("blindpass-controller");
    let marker = directory.join("invocation.txt");
    std::fs::write(
        &controller,
        "#!/bin/sh\nprintf '%s|%s|%s|%s|%s' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" > \"$BLINDPASS_TEST_MARKER\"\n",
    )
    .expect("write controller fixture");
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))
        .expect("make controller fixture executable");
    let output = Command::new(&cli)
        .args([
            "migrate",
            "--pre-upgrade-backup-dir",
            "/var/lib/backups",
            "--recovery-key-file",
            "/run/credentials/key",
        ])
        .env("BLINDPASS_TEST_MARKER", &marker)
        .output()
        .expect("run CLI migration");
    assert!(
        output.status.success(),
        "CLI migration failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "migrate|--pre-upgrade-backup-dir|/var/lib/backups|--recovery-key-file|/run/credentials/key"
    );
    // Half of the pair never reaches the controller.
    std::fs::remove_file(&marker).unwrap();
    let output = Command::new(&cli)
        .args(["migrate", "--recovery-key-file", "/run/credentials/key"])
        .env("BLINDPASS_TEST_MARKER", &marker)
        .output()
        .expect("run CLI migration");
    assert!(!output.status.success());
    assert!(!marker.exists());
    std::fs::remove_dir_all(&directory).expect("remove fixture directory");
}

#[test]
fn admin_seed_dispatches_fixture_to_colocated_controller_binary() {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("blindpass-cli-seed-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create CLI fixture directory");
    let cli = directory.join("blindpass");
    std::fs::copy(env!("CARGO_BIN_EXE_blindpass"), &cli).expect("copy CLI binary");
    let controller = directory.join("blindpass-controller");
    let marker = directory.join("invocation.txt");
    let fixture = directory.join("fixture.json");
    std::fs::write(&fixture, br#"{"agents":["seed-agent"]}"#).unwrap();
    std::fs::write(
        &controller,
        "#!/bin/sh\nprintf '%s|%s|%s' \"$1\" \"$2\" \"$3\" > \"$BLINDPASS_TEST_MARKER\"\n",
    )
    .expect("write controller fixture");
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))
        .expect("make controller fixture executable");
    let output = Command::new(&cli)
        .args(["admin", "seed", "--fixture"])
        .arg(&fixture)
        .env("BLINDPASS_TEST_MARKER", &marker)
        .output()
        .expect("run CLI seed");
    assert!(
        output.status.success(),
        "CLI seed failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        format!("seed|--fixture|{}", fixture.display())
    );
    std::fs::remove_dir_all(&directory).expect("remove fixture directory");
}

#[test]
fn admin_reconcile_clock_dispatches_to_colocated_controller_binary() {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "blindpass-cli-clock-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create CLI fixture directory");
    let cli = directory.join("blindpass");
    std::fs::copy(env!("CARGO_BIN_EXE_blindpass"), &cli).expect("copy CLI binary");
    let controller = directory.join("blindpass-controller");
    let marker = directory.join("invocation.txt");
    std::fs::write(
        &controller,
        "#!/bin/sh\nprintf '%s' \"$1\" > \"$BLINDPASS_TEST_MARKER\"\n",
    )
    .expect("write controller fixture");
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))
        .expect("make controller fixture executable");
    let output = Command::new(&cli)
        .args(["admin", "reconcile-clock"])
        .env("BLINDPASS_TEST_MARKER", &marker)
        .output()
        .expect("run CLI clock reconciliation");
    assert!(
        output.status.success(),
        "CLI clock reconciliation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "reconcile-clock");
    std::fs::remove_dir_all(&directory).expect("remove fixture directory");
}

#[test]
fn local_password_reset_is_exposed_by_cli() {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
        .args(["admin", "reset-password", "--help"])
        .output()
        .expect("inspect CLI password reset help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 CLI help");
    assert!(help.contains("<OPERATOR>"));
    assert!(
        help.contains("username"),
        "help must say a username is accepted"
    );
    assert!(help.contains("--socket"));
}

#[test]
fn local_password_reset_sends_the_operator_id_to_the_private_socket() {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let directory = SocketDirectory(std::env::temp_dir().join(format!(
        "blindpass-cli-reset-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir_all(&directory.0).expect("create socket fixture directory");
    let socket = directory.0.join("admin.sock");
    let listener = UnixListener::bind(&socket).expect("bind fixture administration socket");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept reset request");
        let mut request = String::new();
        stream
            .read_to_string(&mut request)
            .expect("read reset request");
        stream
            .write_all(b"{\"temporary_password\":\"dummy-reset-only\"}\n")
            .expect("reply to reset request");
        request
    });
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
        .args(["admin", "reset-password", "operator-fixture", "--socket"])
        .arg(&socket)
        .output()
        .expect("run CLI reset command");
    assert!(
        output.status.success(),
        "CLI reset failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request: serde_json::Value =
        serde_json::from_str(&server.join().expect("join socket fixture")).expect("JSON request");
    assert_eq!(request["command"], "reset-password");
    assert_eq!(request["id"], "operator-fixture");
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON reset response");
    assert_eq!(response["temporary_password"], "dummy-reset-only");
}

/// Run `blindpass` against a fixture administration socket that answers once with
/// `reply`; returns the CLI output and the single request the CLI sent.
fn admin_against_fixture(
    tag: &str,
    arguments: &[&str],
    reply: &'static str,
) -> (std::process::Output, serde_json::Value) {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let directory = SocketDirectory(std::env::temp_dir().join(format!(
        "blindpass-cli-{tag}-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir_all(&directory.0).expect("create socket fixture directory");
    let socket = directory.0.join("admin.sock");
    let listener = UnixListener::bind(&socket).expect("bind fixture administration socket");
    // A CLI that never connects (for example an unknown subcommand) must fail the
    // test, not hang it: poll for a connection for ten seconds.
    listener
        .set_nonblocking(true)
        .expect("non-blocking fixture socket");
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        return "null".to_owned();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => panic!("accept request: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking stream");
        let mut request = String::new();
        stream.read_to_string(&mut request).expect("read request");
        stream.write_all(reply.as_bytes()).expect("reply");
        request
    });
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
        .arg("admin")
        .args(arguments)
        .arg("--socket")
        .arg(&socket)
        .output()
        .expect("run CLI against the fixture socket");
    let request =
        serde_json::from_str(&server.join().expect("join socket fixture")).expect("JSON request");
    (output, request)
}

#[test]
fn p07_cli_reset_by_username_sends_it_unchanged_and_a_miss_says_what_is_accepted() {
    let (output, request) = admin_against_fixture(
        "reset-user",
        &["reset-password", "Admin"],
        "{\"temporary_password\":\"dummy-reset-only\"}\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(request["command"], "reset-password");
    assert_eq!(request["id"], "Admin");

    let (output, _) = admin_against_fixture(
        "reset-miss",
        &["reset-password", "nobody"],
        "{\"error\":\"operator_not_found\"}\n",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("operator_not_found"), "{stderr}");
    assert!(
        stderr.contains("username"),
        "must say a username is accepted: {stderr}"
    );
    assert!(
        stderr.contains("operators list"),
        "must point at the listing: {stderr}"
    );
    assert!(
        !stderr.contains("nobody"),
        "never echo the reference back: {stderr}"
    );

    for (code, needle) in [
        ("operator_ambiguous", "letter case"),
        ("operator_disabled", "disabled"),
        ("invalid_operator_id", "64 characters"),
    ] {
        let reply: &'static str = Box::leak(format!("{{\"error\":\"{code}\"}}\n").into_boxed_str());
        let (output, _) = admin_against_fixture("reset-codes", &["reset-password", "x"], reply);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(code) && stderr.contains(needle),
            "{code}: {stderr}"
        );
    }
}

#[test]
fn p07_cli_operators_list_prints_ids_and_lock_state_and_can_print_json() {
    let reply = "{\"operators\":[{\"id\":\"11111111-2222-4333-8444-555555555555\",\"username\":\"opnative\",\"display_name\":\"Op\",\"role\":\"admin\",\"disabled\":false,\"must_change_password\":false,\"account_locked_seconds\":842,\"source_locks\":1}]}\n";
    let (output, request) = admin_against_fixture("operators-list", &["operators", "list"], reply);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(request["command"], "operators-list");
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "ID",
        "USERNAME",
        "ROLE",
        "11111111-2222-4333-8444-555555555555",
        "opnative",
        "admin",
    ] {
        assert!(text.contains(expected), "{expected} missing from: {text}");
    }
    assert!(
        text.contains("locked 842s"),
        "lock state must be visible: {text}"
    );

    let (output, _) =
        admin_against_fixture("operators-json", &["operators", "list", "--json"], reply);
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON listing");
    assert_eq!(parsed["operators"][0]["username"], "opnative");
}

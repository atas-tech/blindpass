// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct SocketDirectory(PathBuf);

impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn migrate_dispatches_to_colocated_controller_binary() {
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
fn admin_seed_dispatches_fixture_to_colocated_controller_binary() {
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
fn local_password_reset_is_exposed_by_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
        .args(["admin", "reset-password", "--help"])
        .output()
        .expect("inspect CLI password reset help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 CLI help");
    assert!(help.contains("<ID>"));
    assert!(help.contains("--socket"));
}

#[test]
fn local_password_reset_sends_the_operator_id_to_the_private_socket() {
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

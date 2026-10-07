// SPDX-License-Identifier: AGPL-3.0-only

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Writing then executing a fixture while another test forks yields ETXTBSY.
static EXEC: Mutex<()> = Mutex::new(());

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the CLI next to a controller stand-in that records its arguments.
fn forwarded(args: &[&str]) -> String {
    let _exec = EXEC.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after Unix epoch")
        .as_nanos();
    let fixture = Fixture(std::env::temp_dir().join(format!(
        "blindpass-cli-handoff-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir_all(&fixture.0).expect("create CLI fixture directory");
    let cli = fixture.0.join("blindpass");
    std::fs::copy(env!("CARGO_BIN_EXE_blindpass"), &cli).expect("copy CLI binary");
    let controller = fixture.0.join("blindpass-controller");
    let marker = fixture.0.join("invocation.txt");
    std::fs::write(
        &controller,
        "#!/bin/sh\nprintf '%s ' \"$@\" > \"$BLINDPASS_TEST_MARKER\"\n",
    )
    .expect("write controller fixture");
    std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))
        .expect("make controller fixture executable");
    let output = Command::new(&cli)
        .args(args)
        .env("BLINDPASS_TEST_MARKER", &marker)
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_to_string(marker)
        .expect("controller was not run")
        .trim()
        .to_owned()
}

#[test]
fn p06_ho_cli_export_import_and_abort_dispatch_to_the_colocated_controller() {
    assert_eq!(
        forwarded(&[
            "handoff",
            "export",
            "--output",
            "/out",
            "--recovery-key-file",
            "/key",
            "--handoff-id",
            "ho_cli"
        ]),
        "handoff export --output /out --recovery-key-file /key --handoff-id ho_cli"
    );
    assert_eq!(
        forwarded(&[
            "handoff",
            "import",
            "--archive",
            "/out/a.bpbackup",
            "--receipt",
            "/out/handoff-ho_cli.json",
            "--recovery-key-file",
            "/key",
            "--destination",
            "/dest",
            "--authority-url-file",
            "/authority-url",
            "--tenant-id",
            "tenant_cli",
            "--owner-id",
            "owner_cli"
        ]),
        "handoff import --archive /out/a.bpbackup --receipt /out/handoff-ho_cli.json --recovery-key-file /key --destination /dest --authority-url-file /authority-url --tenant-id tenant_cli --owner-id owner_cli"
    );
    assert_eq!(
        forwarded(&["handoff", "abort", "--handoff-id", "ho_cli"]),
        "handoff abort --handoff-id ho_cli"
    );
    assert_eq!(
        forwarded(&[
            "handoff",
            "abort",
            "--handoff-id",
            "ho_cli",
            "--output",
            "/out"
        ]),
        "handoff abort --handoff-id ho_cli --output /out"
    );
}

#[test]
fn p06_ho_cli_refuses_missing_required_options_without_running_the_controller() {
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
        .args(["handoff", "export", "--output", "/out"])
        .env("PATH", "/nonexistent")
        .output()
        .expect("run CLI");
    assert!(!output.status.success());
}

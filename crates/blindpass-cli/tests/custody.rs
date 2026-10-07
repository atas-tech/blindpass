// SPDX-License-Identifier: AGPL-3.0-only
//! P06-D29 (ADR 0013): the CLI forwards the split signing/recipient credential
//! options exactly and refuses incomplete or mixed credential models before the
//! controller is ever executed.
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Writing then executing a fixture while another test forks yields ETXTBSY.
static EXEC: Mutex<()> = Mutex::new(());

struct Harness {
    directory: PathBuf,
    cli: PathBuf,
    marker: PathBuf,
}
impl Harness {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "blindpass-cli-custody-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let cli = directory.join("blindpass");
        std::fs::copy(env!("CARGO_BIN_EXE_blindpass"), &cli).unwrap();
        let controller = directory.join("blindpass-controller");
        std::fs::write(
            &controller,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$BLINDPASS_TEST_MARKER\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = directory.join("invocation.txt");
        Self {
            directory,
            cli,
            marker,
        }
    }
    /// Arguments the controller received, or `None` when the CLI refused first.
    fn forwarded(&self, args: &[&str]) -> Option<Vec<String>> {
        let _ = std::fs::remove_file(&self.marker);
        let output = Command::new(&self.cli)
            .args(args)
            .env("BLINDPASS_TEST_MARKER", &self.marker)
            .output()
            .unwrap();
        match std::fs::read_to_string(&self.marker) {
            Ok(text) => {
                assert!(
                    output.status.success(),
                    "controller fixture exited non-zero"
                );
                Some(text.lines().map(str::to_owned).collect())
            }
            Err(_) => {
                assert!(!output.status.success(), "CLI succeeded without forwarding");
                None
            }
        }
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn expect(h: &Harness, args: &[&str], controller: &[&str]) {
    assert_eq!(
        h.forwarded(args).as_deref(),
        Some(
            &controller
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>()[..]
        ),
        "{args:?}"
    );
}

#[test]
fn p06_d29_c01_backup_commands_forward_both_credential_models() {
    let _exec = EXEC.lock().unwrap_or_else(|p| p.into_inner());
    let h = Harness::new();
    expect(
        &h,
        &[
            "backup",
            "key-init",
            "--role",
            "recipient",
            "--output",
            "/k/r.pem",
            "--certificate-output",
            "/k/r.crt",
        ],
        &[
            "backup",
            "key-init",
            "--output",
            "/k/r.pem",
            "--role",
            "recipient",
            "--certificate-output",
            "/k/r.crt",
        ],
    );
    expect(
        &h,
        &["backup", "key-init", "--output", "/k/legacy.pem"],
        &["backup", "key-init", "--output", "/k/legacy.pem"],
    );
    expect(
        &h,
        &[
            "backup",
            "create",
            "--output",
            "/b",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
        ],
        &[
            "backup",
            "create",
            "--output",
            "/b",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
        ],
    );
    expect(
        &h,
        &[
            "backup",
            "create",
            "--output",
            "/b",
            "--recovery-key-file",
            "/k/legacy.pem",
        ],
        &[
            "backup",
            "create",
            "--output",
            "/b",
            "--recovery-key-file",
            "/k/legacy.pem",
        ],
    );
    expect(
        &h,
        &[
            "backup",
            "verify",
            "--archive",
            "/b/a.bpbackup",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
            "--work-directory",
            "/w",
            "--expected-archive-sha256",
            &"a".repeat(64),
        ],
        &[
            "backup",
            "verify",
            "--archive",
            "/b/a.bpbackup",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
            "--work-directory",
            "/w",
            "--expected-archive-sha256",
            &"a".repeat(64),
        ],
    );
}

#[test]
fn p06_d29_c02_incomplete_or_mixed_credential_models_never_reach_the_controller() {
    let _exec = EXEC.lock().unwrap_or_else(|p| p.into_inner());
    let h = Harness::new();
    for args in [
        // create: none, half, mixed
        vec!["backup", "create", "--output", "/b"],
        vec![
            "backup",
            "create",
            "--output",
            "/b",
            "--signing-credential-file",
            "/k/s.pem",
        ],
        vec![
            "backup",
            "create",
            "--output",
            "/b",
            "--recipient-certificate-file",
            "/k/r.crt",
        ],
        vec![
            "backup",
            "create",
            "--output",
            "/b",
            "--recovery-key-file",
            "/k/l.pem",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
        ],
        // verify: half and mixed
        vec![
            "backup",
            "verify",
            "--archive",
            "/a",
            "--work-directory",
            "/w",
            "--recipient-key-file",
            "/k/r.pem",
        ],
        vec![
            "backup",
            "verify",
            "--archive",
            "/a",
            "--work-directory",
            "/w",
            "--recovery-key-file",
            "/k/l.pem",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
        ],
        // key-init role without a certificate output
        vec![
            "backup", "key-init", "--output", "/k/s.pem", "--role", "signing",
        ],
        // restore with no credential at all
        vec![
            "restore",
            "--archive",
            "/a",
            "--destination",
            "/d",
            "--authority-url-file",
            "/u",
            "--tenant-id",
            "t",
            "--owner-id",
            "o",
            "--recovery-id",
            "r",
        ],
        // migrate: a half pair
        vec![
            "migrate",
            "--pre-upgrade-backup-dir",
            "/b",
            "--signing-credential-file",
            "/k/s.pem",
        ],
    ] {
        assert!(
            h.forwarded(&args).is_none(),
            "{args:?} reached the controller"
        );
    }
}

#[test]
fn p06_d29_c03_restore_handoff_and_migrate_forward_split_options_and_staging() {
    let _exec = EXEC.lock().unwrap_or_else(|p| p.into_inner());
    let h = Harness::new();
    let digest = "b".repeat(64);
    expect(
        &h,
        &[
            "restore",
            "--archive",
            "/a",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
            "--expected-archive-sha256",
            &digest,
            "--staging-directory",
            "/dev/shm/stage",
            "--destination",
            "/d",
            "--authority-url-file",
            "/u",
            "--tenant-id",
            "t",
            "--owner-id",
            "o",
            "--recovery-id",
            "r",
        ],
        &[
            "restore",
            "--archive",
            "/a",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
            "--expected-archive-sha256",
            &digest,
            "--staging-directory",
            "/dev/shm/stage",
            "--destination",
            "/d",
            "--authority-url-file",
            "/u",
            "--tenant-id",
            "t",
            "--owner-id",
            "o",
            "--recovery-id",
            "r",
        ],
    );
    expect(
        &h,
        &[
            "handoff",
            "export",
            "--output",
            "/o",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
            "--handoff-id",
            "h1",
        ],
        &[
            "handoff",
            "export",
            "--output",
            "/o",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
            "--handoff-id",
            "h1",
        ],
    );
    expect(
        &h,
        &[
            "handoff",
            "import",
            "--archive",
            "/a",
            "--receipt",
            "/r",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
            "--staging-directory",
            "/dev/shm/stage",
            "--destination",
            "/d",
            "--authority-url-file",
            "/u",
            "--tenant-id",
            "t",
            "--owner-id",
            "o",
        ],
        &[
            "handoff",
            "import",
            "--archive",
            "/a",
            "--receipt",
            "/r",
            "--recipient-key-file",
            "/k/r.pem",
            "--signing-certificate-file",
            "/k/s.crt",
            "--staging-directory",
            "/dev/shm/stage",
            "--destination",
            "/d",
            "--authority-url-file",
            "/u",
            "--tenant-id",
            "t",
            "--owner-id",
            "o",
        ],
    );
    expect(
        &h,
        &[
            "migrate",
            "--pre-upgrade-backup-dir",
            "/b",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
        ],
        &[
            "migrate",
            "--pre-upgrade-backup-dir",
            "/b",
            "--signing-credential-file",
            "/k/s.pem",
            "--recipient-certificate-file",
            "/k/r.crt",
        ],
    );
}

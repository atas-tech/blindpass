// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("p06-keys-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn keys(&self) -> PathBuf {
        self.0.join("keys")
    }

    fn run(&self, action: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_blindpass"))
            .env_clear()
            .args(["keys", action, "--directory"])
            .arg(self.keys())
            .output()
            .unwrap()
    }

    fn init(&self) {
        let output = self.run("init");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const NAMES: [&str; 3] = ["root-secret", "agent-jwt-secret", "issuer-key"];

#[test]
fn p06_k01_init_creates_independent_private_raw_keys_and_never_prints_them() {
    let fixture = Fixture::new();
    let output = fixture.run("init");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::metadata(fixture.keys()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let keys: Vec<_> = NAMES
        .iter()
        .map(|name| {
            let path = fixture.keys().join(name);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let bytes = fs::read(path).unwrap();
            assert_eq!(bytes.len(), 32);
            assert!(!output.stdout.windows(32).any(|window| window == bytes));
            assert!(!output.stderr.windows(32).any(|window| window == bytes));
            bytes
        })
        .collect();
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[0], keys[2]);
    assert_ne!(keys[1], keys[2]);
    assert!(fixture.run("check").status.success());
}

#[test]
fn p06_k02_repeated_init_cannot_replace_existing_trust() {
    let fixture = Fixture::new();
    fixture.init();
    let before: Vec<_> = NAMES
        .iter()
        .map(|n| fs::read(fixture.keys().join(n)).unwrap())
        .collect();
    assert!(!fixture.run("init").status.success());
    for (name, bytes) in NAMES.iter().zip(before) {
        assert_eq!(fs::read(fixture.keys().join(name)).unwrap(), bytes);
    }
}

#[test]
fn p06_k03_partial_initialization_is_refused_without_filling_or_overwriting() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.keys()).unwrap();
    fs::set_permissions(fixture.keys(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.keys().join("root-secret");
    fs::write(&path, b"P06-DUMMY-CANARY-INCOMPLETE").unwrap();
    assert!(!fixture.run("init").status.success());
    assert!(!fixture.run("check").status.success());
    assert_eq!(fs::read(path).unwrap(), b"P06-DUMMY-CANARY-INCOMPLETE");
    assert!(!fixture.keys().join("agent-jwt-secret").exists());
}

#[test]
fn p06_k04_unsafe_directory_is_not_chmodded_or_populated() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.keys()).unwrap();
    fs::set_permissions(fixture.keys(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!fixture.run("init").status.success());
    assert_eq!(fs::read_dir(fixture.keys()).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(fixture.keys()).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn p06_k05_check_denies_missing_short_oversized_and_exposed_keys() {
    for failure in ["missing", "short", "oversized", "exposed"] {
        let fixture = Fixture::new();
        fixture.init();
        let path = fixture.keys().join("issuer-key");
        match failure {
            "missing" => fs::remove_file(&path).unwrap(),
            "short" => fs::write(&path, [0; 31]).unwrap(),
            "oversized" => fs::write(&path, [0; 33]).unwrap(),
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap(),
        }
        let output = fixture.run("check");
        assert!(!output.status.success(), "accepted {failure}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(fixture.0.to_str().unwrap()));
    }
}

#[test]
fn p06_k06_symlink_and_hardlinked_keys_or_directories_are_refused() {
    for failure in ["directory", "parent", "key", "hardlink"] {
        let fixture = Fixture::new();
        fixture.init();
        let path = fixture.keys().join("root-secret");
        match failure {
            "directory" => {
                fs::rename(fixture.keys(), fixture.0.join("real")).unwrap();
                symlink(fixture.0.join("real"), fixture.keys()).unwrap();
            }
            "parent" => {
                symlink(&fixture.0, fixture.0.join("alias")).unwrap();
                let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
                    .env_clear()
                    .args(["keys", "check", "--directory"])
                    .arg(fixture.0.join("alias/keys"))
                    .output()
                    .unwrap();
                assert!(!output.status.success());
                continue;
            }
            "key" => {
                fs::rename(&path, fixture.0.join("other")).unwrap();
                symlink(fixture.0.join("other"), &path).unwrap();
            }
            _ => fs::hard_link(&path, fixture.0.join("other")).unwrap(),
        }
        assert!(!fixture.run("check").status.success(), "accepted {failure}");
        assert!(!fixture.run("init").status.success());
    }
}

#[test]
fn p06_k07_init_can_use_an_empty_private_directory_and_environment_layout() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.keys()).unwrap();
    fs::set_permissions(fixture.keys(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass"))
        .env_clear()
        .env("BLINDPASS_KEYS_DIR", fixture.keys())
        .args(["keys", "init"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.run("check").status.success());
}

#[test]
fn p06_k08_fifo_is_rejected_without_blocking() {
    let fixture = Fixture::new();
    fixture.init();
    let path = fixture.keys().join("root-secret");
    fs::remove_file(&path).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg("-m600")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new("timeout")
        .arg("2")
        .arg(env!("CARGO_BIN_EXE_blindpass"))
        .args(["keys", "check", "--directory"])
        .arg(fixture.keys())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn p06_k06_issuer_id_prints_only_the_public_authority_identifier() {
    use blindpass_core::signing::{ed25519::Ed25519KeyPair, issuer_key_id};
    let fixture = Fixture::new();
    fixture.init();
    let seed = fs::read(fixture.keys().join("issuer-key")).unwrap();
    let expected = issuer_key_id(Ed25519KeyPair::from_seed(&seed).unwrap().public_key());
    let output = fixture.run("issuer-id");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(line, format!("{expected}\n"));
    // `ed25519-` plus the unpadded base64url of a 32-byte public key.
    let body = expected.strip_prefix("ed25519-").unwrap();
    assert_eq!(body.len(), 43);
    assert!(
        body.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    for name in NAMES {
        let bytes = fs::read(fixture.keys().join(name)).unwrap();
        assert!(!output.stdout.windows(32).any(|window| window == bytes));
        assert!(!output.stderr.windows(32).any(|window| window == bytes));
    }
    assert_eq!(fixture.run("issuer-id").stdout, output.stdout);
}

#[test]
fn p06_k06_issuer_id_refuses_missing_short_and_exposed_keys_without_output() {
    for failure in ["missing", "short", "exposed"] {
        let fixture = Fixture::new();
        fixture.init();
        let path = fixture.keys().join("issuer-key");
        match failure {
            "missing" => fs::remove_file(&path).unwrap(),
            "short" => fs::write(&path, [0; 31]).unwrap(),
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap(),
        }
        let output = fixture.run("issuer-id");
        assert!(!output.status.success(), "accepted {failure}");
        assert!(
            output.stdout.is_empty(),
            "printed an identifier for {failure}"
        );
    }
}

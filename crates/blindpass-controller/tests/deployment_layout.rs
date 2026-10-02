// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::config::Config;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("p06-layout-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        for name in ["keys", "data"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, contents) in [
            ("root-secret", [b'R'; 32]),
            ("agent-jwt-secret", [b'A'; 32]),
            ("issuer-key", [b'I'; 32]),
        ] {
            fs::write(root.join("keys").join(name), contents).unwrap();
            fs::set_permissions(
                root.join("keys").join(name),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        Self(root)
    }
    fn values(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "BLINDPASS_KEYS_DIR".into(),
                self.0.join("keys").display().to_string(),
            ),
            (
                "BLINDPASS_DATA_DIR".into(),
                self.0.join("data").display().to_string(),
            ),
            (
                "BLINDPASS_PUBLIC_URL".into(),
                "https://blindpass.example".into(),
            ),
            (
                "BLINDPASS_UI_BASE_URL".into(),
                "https://blindpass.example".into(),
            ),
        ])
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn p06_l01_explicit_layout_resolves_keys_and_sqlite_without_creating_state() {
    let fixture = Fixture::new();
    let config = Config::from_variables(fixture.values()).expect("layout config");
    assert_eq!(config.root_secret(), &[b'R'; 32]);
    assert_eq!(config.agent_jwt_secret(), &[b'A'; 32]);
    assert!(config.issuer_keypair().is_some());
    assert_eq!(
        config.database_url(),
        format!(
            "sqlite://{}?mode=rwc",
            fixture.0.join("data/controller.db").display()
        )
    );
    assert_eq!(fs::read_dir(fixture.0.join("data")).unwrap().count(), 0);
}

#[test]
fn p06_l02_explicit_credential_paths_override_layout_names() {
    let fixture = Fixture::new();
    let alternate = fixture.0.join("alternate");
    fs::write(&alternate, [b'X'; 32]).unwrap();
    fs::set_permissions(&alternate, fs::Permissions::from_mode(0o600)).unwrap();
    let database = fixture.0.join("database.url");
    fs::write(&database, "sqlite::memory:").unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    let mut values = fixture.values();
    values.insert(
        "BLINDPASS_ROOT_SECRET_FILE".into(),
        alternate.display().to_string(),
    );
    values.insert(
        "BLINDPASS_DATABASE_URL_FILE".into(),
        database.display().to_string(),
    );
    let config = Config::from_variables(values).expect("explicit overrides");
    assert_eq!(config.root_secret(), &[b'X'; 32]);
    assert_eq!(config.database_url(), "sqlite::memory:");
}

#[test]
fn p06_l03_missing_exposed_and_linked_directories_fail_without_repair() {
    for root in ["keys", "data"] {
        for failure in ["missing", "exposed", "symlink"] {
            let fixture = Fixture::new();
            let path = fixture.0.join(root);
            match failure {
                "missing" => fs::remove_dir_all(&path).unwrap(),
                "exposed" => fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap(),
                _ => {
                    fs::rename(&path, fixture.0.join("real")).unwrap();
                    symlink(fixture.0.join("real"), &path).unwrap();
                }
            }
            assert!(
                Config::from_variables(fixture.values()).is_err(),
                "accepted {root}/{failure}"
            );
            if failure == "missing" {
                assert!(!path.exists());
            }
        }
    }
}

#[test]
fn p06_l04_relative_layout_roots_are_rejected() {
    let fixture = Fixture::new();
    for key in ["BLINDPASS_KEYS_DIR", "BLINDPASS_DATA_DIR"] {
        let mut values = fixture.values();
        values.insert(key.into(), "relative".into());
        assert!(Config::from_variables(values).is_err());
    }
}

#[test]
fn p06_l05_no_database_is_guessed_without_an_explicit_data_root() {
    let fixture = Fixture::new();
    let mut values = fixture.values();
    values.remove("BLINDPASS_DATA_DIR");
    assert!(Config::from_variables(values).is_err());
}

#[test]
fn p06_l06_credential_links_and_unbounded_files_fail_with_sanitized_diagnostics() {
    for failure in ["symlink", "hardlink", "oversized"] {
        let fixture = Fixture::new();
        let path = fixture.0.join("keys/root-secret");
        match failure {
            "symlink" => {
                fs::rename(&path, fixture.0.join("other")).unwrap();
                symlink(fixture.0.join("other"), &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, fixture.0.join("other")).unwrap(),
            _ => fs::write(&path, [b'Z'; 8192]).unwrap(),
        }
        let error = Config::from_variables(fixture.values())
            .err()
            .expect("unsafe credential denied")
            .to_string();
        assert!(!error.contains(fixture.0.to_str().unwrap()));
        assert!(!error.contains("ZZZZZZ"));
    }
}

#[test]
fn p06_l07_version_works_without_any_runtime_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("blindpass-controller {}", env!("CARGO_PKG_VERSION"))
    );
}

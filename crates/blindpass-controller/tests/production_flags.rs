// SPDX-License-Identifier: AGPL-3.0-only

//! P07-I02 / N-03: test flags are refused on production profiles. Every
//! shipped native, image and Compose profile sets `BLINDPASS_PROXY_REQUIRED=1`
//! and none sets `NODE_ENV`, so these cases run with `NODE_ENV` unset. The
//! flag list is read from the source, so a new `BLINDPASS_TEST_*` knob cannot
//! ship without this test covering it.

mod support;

use blindpass_controller::config::{Config, ConfigError};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use support::TestDirectory;

/// A profile shaped like the shipped ones: HTTPS origins, an explicit proxy
/// peer and `BLINDPASS_PROXY_REQUIRED=1`. `NODE_ENV` is never set.
fn production_profile(directory: &TestDirectory) -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
        (
            "BLINDPASS_PUBLIC_URL".to_owned(),
            "https://blindpass.example".to_owned(),
        ),
        (
            "BLINDPASS_UI_BASE_URL".to_owned(),
            "https://input.example".to_owned(),
        ),
        ("BLINDPASS_PROXY_REQUIRED".to_owned(), "1".to_owned()),
        ("BLINDPASS_TRUST_PROXY".to_owned(), "172.29.6.3".to_owned()),
    ]);
    for (variable, name, bytes) in [
        ("BLINDPASS_ROOT_SECRET_FILE", "root", vec![b'R'; 32]),
        ("BLINDPASS_AGENT_JWT_SECRET_FILE", "agent", vec![b'A'; 32]),
        ("BLINDPASS_ISSUER_KEY_FILE", "issuer", vec![b'I'; 32]),
        (
            "BLINDPASS_DATABASE_URL_FILE",
            "database",
            b"sqlite::memory:".to_vec(),
        ),
    ] {
        let path = directory.file(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        values.insert(variable.to_owned(), path.display().to_string());
    }
    values
}

/// Every `BLINDPASS_TEST_*` name that appears in controller source.
fn flags_in_source() -> BTreeSet<String> {
    fn walk(path: &std::path::Path, found: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(path).expect("read source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                let mut rest = text.as_str();
                while let Some(start) = rest.find("\"BLINDPASS_TEST_") {
                    let tail = &rest[start + 1..];
                    let end = tail
                        .find(|c: char| !(c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()))
                        .unwrap_or(tail.len());
                    let name = &tail[..end];
                    // A literal prefix such as "BLINDPASS_TEST_" is not a flag.
                    if !name.ends_with('_') {
                        found.insert(name.to_owned());
                    }
                    rest = &tail[end..];
                }
            }
        }
    }
    let mut found = BTreeSet::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    found
}

#[test]
fn p07_pf01_every_test_flag_in_the_source_is_known_to_this_test() {
    // A new flag must be added here deliberately, with the test below proving
    // a production profile refuses it.
    let expected = BTreeSet::from(
        [
            "BLINDPASS_TEST_AGENT_RATE_WINDOW_MS",
            "BLINDPASS_TEST_AGENT_TOKEN_RATE_WINDOW_MS",
            "BLINDPASS_TEST_APPROVAL_TTL_SECONDS",
            "BLINDPASS_TEST_FAILPOINT",
            "BLINDPASS_TEST_MODE",
            "BLINDPASS_TEST_REFRESH_TOKEN_TTL_SECONDS",
            "BLINDPASS_TEST_REQUEST_TTL_SECONDS",
            "BLINDPASS_TEST_REVOKED_TTL_SECONDS",
            "BLINDPASS_TEST_SEED_TOKEN",
            "BLINDPASS_TEST_SUBMITTED_TTL_SECONDS",
        ]
        .map(str::to_owned),
    );
    assert_eq!(flags_in_source(), expected);
}

#[test]
fn p07_pf02_each_test_flag_is_refused_on_a_production_profile_with_node_env_unset() {
    let directory = TestDirectory::new();
    let profile = production_profile(&directory);
    assert!(!profile.contains_key("NODE_ENV"));
    assert!(
        Config::from_variables(profile.clone()).is_ok(),
        "the production-shaped profile itself must be valid"
    );
    for flag in flags_in_source() {
        // Without the master switch: refused for the override itself.
        if flag != "BLINDPASS_TEST_MODE" {
            let mut values = profile.clone();
            values.insert(flag.clone(), "1".to_owned());
            assert_eq!(
                Config::from_variables(values).err(),
                Some(ConfigError::Invalid(
                    "BLINDPASS_TEST_* requires BLINDPASS_TEST_MODE=1"
                )),
                "{flag} without BLINDPASS_TEST_MODE"
            );
        }
        // With the master switch: refused because the profile is production.
        let mut values = profile.clone();
        values.insert("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned());
        if flag != "BLINDPASS_TEST_MODE" {
            values.insert(flag.clone(), "1".to_owned());
        }
        assert_eq!(
            Config::from_variables(values).err(),
            Some(ConfigError::Invalid("BLINDPASS_TEST_MODE in production")),
            "{flag} with BLINDPASS_TEST_MODE=1 on a production profile"
        );
    }
}

#[test]
fn p07_pf03_node_env_production_still_refuses_test_mode() {
    let directory = TestDirectory::new();
    let mut values = production_profile(&directory);
    values.remove("BLINDPASS_PROXY_REQUIRED");
    values.remove("BLINDPASS_TRUST_PROXY");
    values.insert(
        "BLINDPASS_PUBLIC_URL".into(),
        "http://127.0.0.1:3200".into(),
    );
    values.insert(
        "BLINDPASS_UI_BASE_URL".into(),
        "http://127.0.0.1:3100".into(),
    );
    values.insert("BLINDPASS_TEST_MODE".into(), "1".into());
    assert!(Config::from_variables(values.clone()).is_ok());
    values.insert("NODE_ENV".into(), "production".into());
    assert_eq!(
        Config::from_variables(values).err(),
        Some(ConfigError::Invalid("BLINDPASS_TEST_MODE in production"))
    );
}

#[test]
fn p07_pf04_the_serving_binary_refuses_test_mode_on_a_production_profile() {
    let directory = TestDirectory::new();
    let profile = production_profile(&directory);
    let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
    command.arg("check-config").env_clear();
    for (name, value) in &profile {
        command.env(name, value);
    }
    // The production profile reaches the authority requirement test mode
    // would otherwise skip.
    let baseline = command.output().expect("run check-config");
    assert!(!baseline.status.success());
    assert!(
        String::from_utf8_lossy(&baseline.stderr).contains("BLINDPASS_AUTHORITY_URL_FILE"),
        "{}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    command.env("BLINDPASS_TEST_MODE", "1");
    command.env(
        "BLINDPASS_TEST_SEED_TOKEN",
        "p07-dummy-seed-token-with-32-bytes-or-more",
    );
    let refused = command.output().expect("run check-config with test mode");
    assert!(!refused.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(text.contains("BLINDPASS_TEST_MODE in production"), "{text}");
    assert!(!text.contains("p07-dummy-seed-token"), "{text}");
}

#[test]
fn p07_pf05_fixture_seeding_command_needs_test_mode() {
    let directory = TestDirectory::new();
    let mut profile = production_profile(&directory);
    profile.remove("BLINDPASS_PROXY_REQUIRED");
    profile.remove("BLINDPASS_TRUST_PROXY");
    let fixture = directory.file("fixture.json");
    std::fs::write(&fixture, "{}").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
    command
        .arg("seed")
        .arg("--fixture")
        .arg(&fixture)
        .env_clear();
    for (name, value) in &profile {
        command.env(name, value);
    }
    let output = command.output().expect("run seed");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires BLINDPASS_TEST_MODE=1"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn p07_pf06_check_config_says_so_when_test_mode_is_on() {
    let directory = TestDirectory::new();
    let mut profile = production_profile(&directory);
    profile.remove("BLINDPASS_PROXY_REQUIRED");
    profile.remove("BLINDPASS_TRUST_PROXY");
    let run = |test_mode: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        command.arg("check-config").env_clear();
        for (name, value) in &profile {
            command.env(name, value);
        }
        if test_mode {
            command.env("BLINDPASS_TEST_MODE", "1");
        } else {
            command.env("BLINDPASS_AUTHORITY_URL_FILE", directory.file("absent"));
        }
        command.output().expect("run check-config")
    };
    let test_fixture = run(true);
    assert!(
        test_fixture.status.success(),
        "{}",
        String::from_utf8_lossy(&test_fixture.stderr)
    );
    assert!(
        String::from_utf8_lossy(&test_fixture.stderr).contains("BLINDPASS_TEST_MODE=1 is set"),
        "{}",
        String::from_utf8_lossy(&test_fixture.stderr)
    );
    assert!(!String::from_utf8_lossy(&run(false).stderr).contains("BLINDPASS_TEST_MODE=1 is set"));
}

#[test]
fn p07_pf07_the_in_process_fixture_seam_is_called_only_from_tests() {
    fn callers(path: &std::path::Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(path).expect("read source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                callers(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source");
                for (number, line) in text.lines().enumerate() {
                    if line.contains("with_test_fixture_mode") {
                        found.push(format!("{}:{}", path.display(), number + 1));
                    }
                }
            }
        }
    }
    let mut found = Vec::new();
    callers(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    assert_eq!(
        found.len(),
        1,
        "only the definition may name the fixture seam: {found:?}"
    );
    assert!(found[0].contains("config.rs"), "{found:?}");
    // The seam does not widen the environment path: the same shape is refused.
    let directory = TestDirectory::new();
    let mut values = production_profile(&directory);
    values.insert("BLINDPASS_TEST_MODE".to_owned(), "1".to_owned());
    assert!(matches!(
        Config::from_variables(values),
        Err(ConfigError::Invalid("BLINDPASS_TEST_MODE in production"))
    ));
}

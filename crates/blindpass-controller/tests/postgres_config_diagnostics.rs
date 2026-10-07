// SPDX-License-Identifier: AGPL-3.0-only
mod support;

use blindpass_controller::config::Config;
use blindpass_core::deployment::initialize_keys;
use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::TestDirectory;

const PASSWORD: &str = "P06-DUMMY-PGQ-PASSWORD";
const OPTION: &str = "P06-DUMMY-PGQ-OPTION";
const NAME: &str = "P06_DUMMY_PGQ_NAME";

struct Fixture {
    directory: TestDirectory,
    values: BTreeMap<String, String>,
}

impl Fixture {
    fn new(url: &str) -> Self {
        let directory =
            TestDirectory(std::env::temp_dir().join(support::unique("blindpass-p06-pgq")));
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let keys = directory.file("keys");
        initialize_keys(&keys).unwrap();
        let data = directory.file("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let url_file = directory.file("database-url");
        fs::write(&url_file, url).unwrap();
        fs::set_permissions(&url_file, fs::Permissions::from_mode(0o600)).unwrap();
        let values = BTreeMap::from([
            ("BLINDPASS_KEYS_DIR".into(), keys.display().to_string()),
            ("BLINDPASS_DATA_DIR".into(), data.display().to_string()),
            (
                "BLINDPASS_DATABASE_URL_FILE".into(),
                url_file.display().to_string(),
            ),
            (
                "BLINDPASS_PUBLIC_URL".into(),
                "https://controller.pgq.invalid".into(),
            ),
            (
                "BLINDPASS_UI_BASE_URL".into(),
                "https://controller.pgq.invalid".into(),
            ),
            (
                "BLINDPASS_ADMIN_SOCKET_PATH".into(),
                directory.file("admin.sock").display().to_string(),
            ),
            ("BLINDPASS_LISTEN".into(), "127.0.0.1:0".into()),
        ]);
        Self { directory, values }
    }

    fn assert_no_state(&self, original: &str) {
        assert_eq!(
            fs::read(self.directory.file("database-url")).unwrap(),
            original.as_bytes(),
            "protected input changed"
        );
        assert_eq!(
            fs::read_dir(self.directory.file("data")).unwrap().count(),
            0,
            "controller state created"
        );
        assert!(!self.directory.file("admin.sock").exists());
    }
}

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn p06_pgq01_actual_startup_refuses_unknown_options_without_logging_credentials() {
    // Keep a private endpoint reserved; no real PostgreSQL or credential is used.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("postgres://pgq:{PASSWORD}@127.0.0.1:{port}/pgq?{NAME}={OPTION}");
    for format in ["json", "text"] {
        let f = Fixture::new(&url);
        let mut child = OwnedChild(Some(
            Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
                .env_clear()
                .envs(&f.values)
                .env("BLINDPASS_LOG_FORMAT", format)
                .arg("serve")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let started = Instant::now();
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none()
            && started.elapsed() < Duration::from_secs(3)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let timed_out = child.0.as_mut().unwrap().try_wait().unwrap().is_none();
        if timed_out {
            child.0.as_mut().unwrap().kill().unwrap();
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        let mut diagnostics = output.stdout;
        diagnostics.extend(output.stderr);
        let diagnostics = String::from_utf8_lossy(&diagnostics);
        let logged_canary = [PASSWORD, OPTION, NAME, url.as_str()]
            .iter()
            .any(|canary| diagnostics.contains(canary));
        // Record booleans only; raw diagnostic bytes stay in fixture memory.
        eprintln!(
            "P06-PGQ01 format={format} dummy_canary_logged={logged_canary} startup_timed_out={timed_out}"
        );
        assert!(
            !logged_canary,
            "unknown database option leaked a dummy canary"
        );
        assert!(!timed_out, "unsupported option reached database setup");
        assert!(!output.status.success());
        assert!(diagnostics.contains("BLINDPASS_DATABASE_URL"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "unsupported option reached the database network endpoint"
        );
        f.assert_no_state(&url);
    }
}

#[test]
fn p06_pgq02_supported_and_encoded_names_work_unknown_or_malformed_names_refuse() {
    let base = format!("postgres://pgq:{PASSWORD}@127.0.0.1:5432/pgq");
    for query in [
        "",
        "sslmode=require&application_name=pgq&options=-c%20search_path%3Dpublic",
        "%73slmode=require&options%5Bsearch_path%5D=public",
        "ssl-mode=verify-full&ssl-root-cert=%2Fdummy%2Fca.pem&ssl-cert=%2Fdummy%2Fcert.pem&ssl-key=%2Fdummy%2Fkey.pem",
        "host=127.0.0.1&hostaddr=127.0.0.1&port=5432&user=pgq&dbname=pgq&password=dummy&statement-cache-capacity=0",
        "sslrootcert=%2Fdummy%2Fca.pem&sslcert=%2Fdummy%2Fcert.pem&sslkey=%2Fdummy%2Fkey.pem&ssl-ca=%2Fdummy%2Fca.pem",
        "options[custom.setting]=dummy&&",
    ] {
        let url = format!("{base}?{query}");
        let f = Fixture::new(&url);
        assert!(
            Config::from_variables(f.values.clone()).is_ok(),
            "supported options rejected"
        );
        f.assert_no_state(&url);
    }
    for query in [
        "unknown=dummy",
        "%75nknown=dummy",
        "unknown+key=dummy",
        "host%GG=dummy",
        "options[search_path=dummy",
        "options[]=dummy",
        "options%5Bsearch_path%5D%00=dummy",
        "SSLMODE=require",
    ] {
        let url = format!("{base}?{query}");
        let f = Fixture::new(&url);
        match Config::from_variables(f.values.clone()) {
            Ok(_) => panic!("unsupported database option accepted"),
            Err(error) => {
                let message = error.to_string();
                assert!(message.contains("BLINDPASS_DATABASE_URL"));
                assert!(!message.contains(PASSWORD) && !message.contains(query));
            }
        }
        f.assert_no_state(&url);
    }
}

#[test]
fn p06_pgq03_production_file_and_test_mode_url_have_the_same_safe_refusal() {
    let url = format!("postgresql://pgq:{PASSWORD}@127.0.0.1:5432/pgq?{NAME}={OPTION}");
    let f = Fixture::new(&url);
    assert!(Config::from_variables(f.values.clone()).is_err());
    let mut test_values = f.values.clone();
    test_values.remove("BLINDPASS_DATABASE_URL_FILE");
    test_values.insert("BLINDPASS_TEST_MODE".into(), "1".into());
    test_values.insert("BLINDPASS_DATABASE_URL".into(), url.clone());
    assert!(Config::from_variables(test_values).is_err());
    f.assert_no_state(&url);

    let valid = Fixture::new("postgresql://pgq:dummy@127.0.0.1:5432/pgq?sslmode=disable");
    assert!(Config::from_variables(valid.values).is_ok());
    let sqlite = Fixture::new("sqlite://controller.db?mode=rwc");
    assert!(Config::from_variables(sqlite.values).is_ok());
}

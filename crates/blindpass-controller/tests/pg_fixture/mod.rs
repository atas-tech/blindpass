// SPDX-License-Identifier: AGPL-3.0-only
//! Shared fixture for the pinned-toolkit tests: private socket-only source cluster,
//! a controller deployment on it and process/credential observers.
#![allow(dead_code)]
use blindpass_controller::backup::initialize_recovery_key;
use blindpass_core::deployment::initialize_keys;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub const BIN: &str = "/usr/lib/postgresql/16/bin";
pub const PASSWORD: &str = "P06-DUMMY-PG-CANARY:with\\colon";

pub struct Private(pub PathBuf);
impl Private {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "blindpass-pgt-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Private {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Source "controller database": scram-authenticated, Unix-socket only.
pub struct Source {
    _root: Private,
    pub server: Option<Child>,
    pub socket: PathBuf,
    pub schema: String,
}
impl Source {
    pub fn start() -> Self {
        Self::start_with_schema("p06_src")
    }
    pub fn start_with_schema(schema: &str) -> Self {
        let root = Private::new("src");
        let socket = root.file("s");
        fs::create_dir(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
        let pwfile = root.file("pw");
        fs::write(&pwfile, "bootpw").unwrap();
        let init = Command::new(format!("{BIN}/initdb"))
            .args([
                "--username=boot",
                "--auth-local=scram-sha-256",
                "--auth-host=reject",
                "--encoding=UTF8",
                "--locale=C",
                "--no-sync",
            ])
            .arg(format!("--pwfile={}", pwfile.display()))
            .arg("--pgdata")
            .arg(root.file("data"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            init.success(),
            "initdb failed (is this the pinned toolkit image?)"
        );
        let server = Command::new(format!("{BIN}/postgres"))
            .arg("-D")
            .arg(root.file("data"))
            .args([
                "-c",
                "listen_addresses=",
                "-c",
                "fsync=off",
                "-c",
                "ssl=off",
                "-c",
                "max_connections=30",
            ])
            .arg("-c")
            .arg(format!("unix_socket_directories={}", socket.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let source = Self {
            _root: root,
            server: Some(server),
            socket,
            schema: schema.to_owned(),
        };
        let started = Instant::now();
        while !source.admin("SELECT 1").status.success() {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "source cluster did not start"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            source
                .admin(&format!(
                    "CREATE ROLE ctl LOGIN NOSUPERUSER PASSWORD '{PASSWORD}'"
                ))
                .status
                .success()
        );
        assert!(
            source
                .admin("CREATE DATABASE blindpass OWNER ctl")
                .status
                .success()
        );
        source
    }
    pub fn admin(&self, sql: &str) -> Output {
        self.admin_in("postgres", sql)
    }
    pub fn admin_in(&self, database: &str, sql: &str) -> Output {
        Command::new(format!("{BIN}/psql"))
            .env_clear()
            .env("PGPASSWORD", "bootpw")
            .args(["-X", "-q", "-h"])
            .arg(&self.socket)
            .args([
                "-U",
                "boot",
                "-d",
                database,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                sql,
            ])
            .output()
            .unwrap()
    }
    pub fn url(&self) -> String {
        // The password is percent-encoded (":" and "\") as a real URL file would.
        let encoded = PASSWORD.replace(':', "%3A").replace('\\', "%5C");
        format!(
            "postgresql://ctl:{encoded}@localhost/blindpass?host={}&options=-c%20search_path%3D{}",
            self.socket.display(),
            self.schema
        )
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        if let Some(mut server) = self.server.take() {
            let _ = server.kill();
            let _ = server.wait();
        }
    }
}

pub struct Deployment {
    pub work: Private,
    pub source: Source,
    pub keys: PathBuf,
    pub authority: PathBuf,
}
impl Deployment {
    pub fn new() -> Self {
        Self::with_schema("p06_src")
    }
    pub fn with_schema(schema: &str) -> Self {
        let source = Source::start_with_schema(schema);
        let work = Private::new("work");
        let keys = work.file("keys");
        initialize_keys(&keys).unwrap();
        fs::create_dir(work.file("data")).unwrap();
        fs::set_permissions(work.file("data"), fs::Permissions::from_mode(0o700)).unwrap();
        // The command must stay offline: this reserved endpoint proves it.
        let authority = work.file("authority-url");
        fs::write(
            &authority,
            "postgres://backup:P06-DUMMY-AUTH@127.0.0.1:1/backup",
        )
        .unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).unwrap();
        let url_file = work.file("database-url");
        fs::write(&url_file, source.url()).unwrap();
        fs::set_permissions(&url_file, fs::Permissions::from_mode(0o600)).unwrap();
        // Controller schema and test-mode initialization of the source store.
        let schema = source.admin_in(
            "blindpass",
            &format!("CREATE SCHEMA {schema} AUTHORIZATION ctl"),
        );
        assert!(schema.status.success());
        let deployment = Self {
            work,
            source,
            keys,
            authority,
        };
        let init = deployment.command(&["migrate".as_ref()], true);
        if !init.status.success() {
            let direct = tokio::runtime::Runtime::new().unwrap().block_on(
                blindpass_controller::store::Store::connect(&deployment.source.url()),
            );
            panic!(
                "source initialization failed: {} / direct: {:?}",
                String::from_utf8_lossy(&init.stderr),
                direct.err()
            );
        }
        deployment
    }
    pub fn command(&self, args: &[&std::ffi::OsStr], test_mode: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"));
        command
            .env_clear()
            .env("BLINDPASS_KEYS_DIR", &self.keys)
            .env("BLINDPASS_DATA_DIR", self.work.file("data"))
            .env("BLINDPASS_PUBLIC_URL", "https://controller.p06.invalid")
            .env("BLINDPASS_UI_BASE_URL", "https://controller.p06.invalid")
            .env(
                "BLINDPASS_DATABASE_URL_FILE",
                self.work.file("database-url"),
            )
            .env("BLINDPASS_AUTHORITY_URL_FILE", &self.authority)
            .env("BLINDPASS_CONTROLLER_TENANT_ID", "P06_DUMMY_PGT")
            .env("BLINDPASS_CONTROLLER_OWNER_ID", "P06_DUMMY_PGT_OWNER");
        if test_mode {
            command
                .env("BLINDPASS_TEST_MODE", "1")
                .env_remove("BLINDPASS_AUTHORITY_URL_FILE")
                .env_remove("BLINDPASS_CONTROLLER_TENANT_ID")
                .env_remove("BLINDPASS_CONTROLLER_OWNER_ID");
        }
        command.args(args).output().unwrap()
    }
    pub fn recovery_key(&self) -> PathBuf {
        let key = self.work.file("recovery.pem");
        if !key.exists() {
            initialize_recovery_key(&key).unwrap();
        }
        key
    }
    pub fn create(&self, output: &Path) -> Output {
        let key = self.recovery_key();
        self.command(
            &[
                "backup".as_ref(),
                "create".as_ref(),
                "--output".as_ref(),
                output.as_os_str(),
                "--recovery-key-file".as_ref(),
                key.as_os_str(),
            ],
            false,
        )
    }
    pub fn rows(&self, sql: &str) -> String {
        let output = Command::new(format!("{BIN}/psql"))
            .env_clear()
            .env("PGPASSWORD", "bootpw")
            .args(["-X", "-q", "-A", "-t", "-h"])
            .arg(&self.source.socket)
            .args(["-U", "boot", "-d", "blindpass", "-c", sql])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}

pub fn private_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Poll every process's argv and environment for the password canary while the
/// caller runs a backup. Only same-UID processes are readable, which is exactly
/// the exposure an unprivileged co-tenant would have.
pub fn watch_for_canary(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<bool> {
    watch_for_bytes(stop, b"P06-DUMMY-PG-CANARY".to_vec())
}

/// The same observer for any credential bytes.
pub fn watch_for_bytes(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    needle: Vec<u8>,
) -> std::thread::JoinHandle<bool> {
    // The test process and its ancestors legitimately hold the fixture's own
    // environment; only other processes (the command under test and its tools)
    // can expose a credential to a co-tenant.
    let own = own_and_ancestors();
    std::thread::spawn(move || {
        let mut seen = false;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                        .is_some_and(|pid| own.contains(&pid))
                    {
                        continue;
                    }
                    let comm = fs::read_to_string(entry.path().join("comm"))
                        .unwrap_or_default()
                        .trim()
                        .to_owned();
                    // Argument vectors are checked everywhere. Environments are
                    // checked for the product and its tools only: the fixture's own
                    // servers and a forked child before exec carry the harness
                    // environment, which is not the exposure under test.
                    let product = ["blindpass", "pg_restore", "pg_dump", "initdb", "openssl"]
                        .iter()
                        .any(|prefix| comm.starts_with(prefix));
                    for name in ["cmdline", "environ"] {
                        if name == "environ" && !product {
                            continue;
                        }
                        if let Ok(bytes) = fs::read(entry.path().join(name))
                            && bytes.windows(needle.len()).any(|window| window == needle)
                        {
                            // Name only: the process, never its contents.
                            eprintln!("credential observed in {name} of process {comm}");
                            seen = true;
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        seen
    })
}

pub fn leftover_postgres_children() -> usize {
    let me = std::process::id().to_string();
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|entry| {
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                return false;
            };
            let after = stat.rsplit_once(')').map_or("", |(_, rest)| rest);
            let mut fields = after.split_whitespace();
            let _state = fields.next();
            let parent = fields.next().unwrap_or("");
            // Children of this test process are the source server only; verification
            // clusters are grandchildren of the command, which has exited by now.
            parent != me
                && fs::read_to_string(entry.path().join("cmdline"))
                    .is_ok_and(|c| c.contains("postgres") && c.contains("pgdata"))
        })
        .count()
}

pub fn processes_matching(needle: &str) -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let command = fs::read(entry.path().join("cmdline")).ok()?;
            String::from_utf8_lossy(&command)
                .replace('\0', " ")
                .contains(needle)
                .then_some(pid)
        })
        .collect()
}

fn own_and_ancestors() -> Vec<u32> {
    let mut pids = Vec::new();
    let mut pid = std::process::id();
    while pid >= 1 && !pids.contains(&pid) {
        pids.push(pid);
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            break;
        };
        pid = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|parent| parent.parse().ok())
            .unwrap_or(0);
    }
    pids
}

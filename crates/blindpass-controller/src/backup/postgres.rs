// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL custom-format capture and isolated full-restore verification
//! (ADR 0011). The exact reviewed PGDG toolkit is invoked only by absolute path,
//! with libpq settings in a private environment and a private passfile; no
//! credential ever appears in an argument, a diagnostic or the controller log.
use super::*;

/// Reviewed toolkit location; there is no override.
pub(crate) const TOOLKIT_DIR: &str = "/usr/lib/postgresql/16/bin";
/// Exact reviewed server and client version.
pub(crate) const TOOLKIT_VERSION: &str = "16.15";

/// Parsed controller database URL. The password is kept only for the private
/// passfile and is redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PgConnection {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    database: String,
    ssl_mode: Option<String>,
    ssl_root_cert: Option<String>,
    ssl_cert: Option<String>,
    ssl_key: Option<String>,
}
impl fmt::Debug for PgConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PgConnection(<redacted>)")
    }
}

const REFUSED: BackupError = BackupError("PostgreSQL connection settings are unsupported");

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let digits = bytes.get(index + 1..index + 3)?;
                let high = (digits[0] as char).to_digit(16)?;
                let low = (digits[1] as char).to_digit(16)?;
                decoded.push((high * 16 + low) as u8);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    let text = String::from_utf8(decoded).ok()?;
    (!text.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r')).then_some(text)
}

fn absolute(value: String) -> Result<String> {
    if Path::new(&value).is_absolute() {
        Ok(value)
    } else {
        Err(REFUSED)
    }
}

impl PgConnection {
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("postgresql://")
            .or_else(|| url.strip_prefix("postgres://"))
            .ok_or(REFUSED)?;
        let rest = rest.split('#').next().unwrap_or(rest);
        let (location, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, database) = location.split_once('/').ok_or(REFUSED)?;
        let (userinfo, hostport) = authority
            .rsplit_once('@')
            .map_or(("", authority), |(u, h)| (u, h));
        let (user, password) = match userinfo.split_once(':') {
            Some((user, password)) => (
                percent_decode(user),
                Some(percent_decode(password).ok_or(REFUSED)?),
            ),
            None => (percent_decode(userinfo), None),
        };
        let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
            let (host, tail) = bracketed.split_once(']').ok_or(REFUSED)?;
            (host.to_owned(), tail.strip_prefix(':'))
        } else {
            match hostport.rsplit_once(':') {
                Some((host, port)) => (host.to_owned(), Some(port)),
                None => (hostport.to_owned(), None),
            }
        };
        let mut connection = Self {
            host: percent_decode(&host).ok_or(REFUSED)?,
            port: match port {
                None | Some("") => 5432,
                Some(port) => port.parse().ok().filter(|port| *port != 0).ok_or(REFUSED)?,
            },
            user: user.ok_or(REFUSED)?,
            password,
            database: percent_decode(database).ok_or(REFUSED)?,
            ssl_mode: None,
            ssl_root_cert: None,
            ssl_cert: None,
            ssl_key: None,
        };
        for item in query.split('&').filter(|item| !item.is_empty()) {
            let (name, value) = item.split_once('=').unwrap_or((item, ""));
            let name = percent_decode(name).ok_or(REFUSED)?;
            let value = percent_decode(value).ok_or(REFUSED)?;
            match name.as_str() {
                "sslmode" | "ssl-mode" => {
                    if !matches!(
                        value.as_str(),
                        "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
                    ) {
                        return Err(REFUSED);
                    }
                    connection.ssl_mode = Some(value);
                }
                "sslrootcert" | "ssl-root-cert" | "ssl-ca" => {
                    connection.ssl_root_cert = Some(absolute(value)?)
                }
                "sslcert" | "ssl-cert" => connection.ssl_cert = Some(absolute(value)?),
                "sslkey" | "ssl-key" => connection.ssl_key = Some(absolute(value)?),
                "host" => connection.host = value,
                "port" => {
                    connection.port = value
                        .parse()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or(REFUSED)?
                }
                "dbname" => connection.database = value,
                "user" => connection.user = value,
                "password" => connection.password = Some(value),
                // The schema is taken from the exported snapshot, not the URL.
                "application_name" | "options" | "statement-cache-capacity" => {}
                other if other.starts_with("options[") => {}
                _ => return Err(REFUSED),
            }
        }
        // A socket directory must be absolute; a network host never contains a slash.
        if connection.host.is_empty()
            || connection.user.is_empty()
            || connection.database.is_empty()
            || connection.database.len() > 63
            || connection.host.starts_with('-')
            || (connection.host.contains('/') && !Path::new(&connection.host).is_absolute())
        {
            return Err(REFUSED);
        }
        Ok(connection)
    }

    /// libpq environment, never containing the password.
    pub(crate) fn environment(&self, passfile: &Path) -> Vec<(&'static str, std::ffi::OsString)> {
        let mut environment: Vec<(&'static str, std::ffi::OsString)> = vec![
            ("PGHOST", self.host.clone().into()),
            ("PGPORT", self.port.to_string().into()),
            ("PGUSER", self.user.clone().into()),
            ("PGDATABASE", self.database.clone().into()),
            ("PGCONNECT_TIMEOUT", "10".into()),
            ("PGAPPNAME", "blindpass-backup".into()),
            ("PGPASSFILE", passfile.as_os_str().to_owned()),
        ];
        for (name, value) in [
            ("PGSSLMODE", &self.ssl_mode),
            ("PGSSLROOTCERT", &self.ssl_root_cert),
            ("PGSSLCERT", &self.ssl_cert),
            ("PGSSLKEY", &self.ssl_key),
        ] {
            if let Some(value) = value {
                environment.push((name, value.clone().into()));
            }
        }
        environment
    }

    /// One passfile line matching any host/port/database/user for this single use.
    pub(crate) fn passfile_line(&self) -> Option<String> {
        self.password.as_ref().map(|password| {
            let escaped: String = password
                .chars()
                .flat_map(|c| {
                    if c == ':' || c == '\\' {
                        vec!['\\', c]
                    } else {
                        vec![c]
                    }
                })
                .collect();
            format!("*:*:*:*:{escaped}")
        })
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !value.as_bytes()[0].is_ascii_digit()
}

/// `pg_dump` arguments for one exported snapshot of one validated schema.
pub(crate) fn dump_arguments(schema: &str, snapshot: &str) -> Result<Vec<String>> {
    if !identifier(schema)
        || schema.starts_with("pg_")
        || matches!(schema, "information_schema" | "public")
        || snapshot.is_empty()
        || snapshot.len() > 128
        || !snapshot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err(BackupError("PostgreSQL dump settings are unsupported"));
    }
    Ok(vec![
        "--format=custom".into(),
        "--no-owner".into(),
        "--no-privileges".into(),
        "--no-sync".into(),
        format!("--schema={schema}"),
        format!("--snapshot={snapshot}"),
    ])
}

const DUMP_DEADLINE: Duration = Duration::from_secs(60);
const RESTORE_DEADLINE: Duration = Duration::from_secs(300);
const START_DEADLINE: Duration = Duration::from_secs(30);

fn tool_path(name: &str) -> PathBuf {
    Path::new(TOOLKIT_DIR).join(name)
}

/// Both server and client must be exactly the reviewed release before any
/// database credential is handed to a tool.
pub(crate) fn require_toolkit(stage: &Stage) -> Result<()> {
    for name in ["pg_dump", "pg_restore", "initdb", "postgres"] {
        let output = stage.member(&format!("{name}-version"));
        let mut command = Command::new(tool_path(name));
        command.arg("--version");
        tool(command, None, private_create(&output)?)
            .map_err(|_| BackupError("PostgreSQL toolkit is unavailable"))?;
        let bytes = read_private_file(&output, 512)
            .map_err(|_| BackupError("PostgreSQL toolkit is unavailable"))?;
        let text = std::str::from_utf8(bytes.as_bytes())
            .map_err(|_| BackupError("PostgreSQL toolkit is unavailable"))?;
        let version = text.split_whitespace().nth(2);
        if version != Some(TOOLKIT_VERSION) {
            return Err(BackupError(
                "PostgreSQL toolkit version is not the reviewed release",
            ));
        }
    }
    Ok(())
}

/// Custom-format dump of exactly the exported snapshot. The connection is
/// supplied through a private passfile and environment, never arguments.
pub(crate) fn dump(
    connection: &PgConnection,
    schema: &str,
    snapshot: &str,
    stage: &Stage,
    output: &Path,
) -> Result<()> {
    let arguments = dump_arguments(schema, snapshot)?;
    let passfile = stage.member("pgpass");
    match connection.passfile_line() {
        Some(line) => private_write(&passfile, format!("{line}\n").as_bytes())?,
        None => private_write(&passfile, b"# no password\n")?,
    }
    let environment = connection.environment(&passfile);
    let borrowed: Vec<(&str, &std::ffi::OsStr)> = environment
        .iter()
        .map(|(name, value)| (*name, value.as_os_str()))
        .collect();
    let mut command = Command::new(tool_path("pg_dump"));
    command.args(&arguments);
    let result = tool_with_env(
        command,
        &borrowed,
        None,
        private_create(output)?,
        DUMP_DEADLINE,
    );
    let _ = fs::remove_file(&passfile);
    if result.is_err() {
        let _ = fs::remove_file(output);
        return Err(BackupError("PostgreSQL dump failed"));
    }
    Ok(())
}

/// A private, socket-only cluster that exists only to prove a dump restores.
/// It is never a controller store; it is killed and removed with its stage.
struct Cluster {
    server: ToolChild,
    socket: PathBuf,
}
impl Cluster {
    async fn start(stage: &Stage) -> Result<Self> {
        let data = stage.member("pgdata");
        let mut init = Command::new(tool_path("initdb"));
        init.args([
            "--username=boot",
            "--auth=trust",
            "--encoding=UTF8",
            "--locale=C",
            "--no-sync",
        ])
        .arg("--pgdata")
        .arg(&data);
        tool_with_deadline(
            init,
            None,
            private_create(&stage.member("initdb.out"))?,
            RESTORE_DEADLINE,
        )
        .map_err(|_| BackupError("PostgreSQL verification cluster could not be created"))?;
        // A Unix socket path is limited to 107 bytes and stage paths can be longer.
        // The server chdirs to its data directory, so `/proc/<pid>/cwd/s` is a short,
        // private path to this directory for the server and for every client.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(data.join("s"))
            .map_err(|_| BackupError("PostgreSQL verification staging unavailable"))?;
        let mut server = Command::new(tool_path("postgres"));
        server
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("-D")
            .arg(&data)
            .args([
                "-c",
                "listen_addresses=",
                "-c",
                "fsync=off",
                "-c",
                "synchronous_commit=off",
                "-c",
                "full_page_writes=off",
                "-c",
                "autovacuum=off",
                "-c",
                "max_connections=8",
                "-c",
                "shared_buffers=64MB",
                "-c",
                "ssl=off",
                "-c",
                "log_destination=stderr",
                "-c",
                "unix_socket_permissions=0700",
            ])
            .args(["-c", "unix_socket_directories=/proc/self/cwd/s"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        restrict_child(&mut server, None);
        let child = ToolChild(
            server
                .spawn()
                .map_err(|_| BackupError("PostgreSQL verification server unavailable"))?,
        );
        let socket = PathBuf::from(format!("/proc/{}/cwd/s", child.0.id()));
        let mut cluster = Self {
            server: child,
            socket,
        };
        let started = Instant::now();
        loop {
            if cluster
                .server
                .0
                .try_wait()
                .map_err(|_| BackupError("PostgreSQL verification server failed"))?
                .is_some()
            {
                return Err(BackupError("PostgreSQL verification server exited"));
            }
            if crate::store::backup::postgres_socket_ready(&cluster.socket, "boot", "postgres")
                .await
            {
                return Ok(cluster);
            }
            if started.elapsed() >= START_DEADLINE {
                return Err(BackupError("PostgreSQL verification server timed out"));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    /// SIGTERM first so the cluster closes cleanly; the guard kills any remainder.
    fn stop(mut self) {
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        // SAFETY: signalling our own live child by pid.
        unsafe { kill(self.server.0.id() as i32, 15) };
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            if matches!(self.server.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Complete isolated restore of the custom dump as an unprivileged role, then
/// the same identity/row-count measurement the live snapshot used. A dump that
/// does not restore, or restores to different state, is refused.
pub(crate) async fn verify_dump(dump: &Path, expected: &SnapshotInfo, stage: &Stage) -> Result<()> {
    require_toolkit(stage)?;
    private_input(dump, MAX_BUNDLE_BYTES)?;
    let cluster = Cluster::start(stage).await?;
    let outcome = async {
        crate::store::backup::prepare_restore_target(
            &cluster.socket,
            "boot",
            "restore_role",
            "restore",
        )
        .await
        .map_err(|_| BackupError("PostgreSQL verification database could not be prepared"))?;
        let mut restore = Command::new(tool_path("pg_restore"));
        restore
            .args([
                "--no-owner",
                "--no-privileges",
                "--exit-on-error",
                "--single-transaction",
            ])
            .arg("--dbname=restore")
            .arg(dump);
        let environment: [(&str, &std::ffi::OsStr); 2] = [
            ("PGHOST", cluster.socket.as_os_str()),
            ("PGUSER", std::ffi::OsStr::new("restore_role")),
        ];
        tool_with_env(
            restore,
            &environment,
            None,
            private_create(&stage.member("pg_restore.out"))?,
            RESTORE_DEADLINE,
        )
        .map_err(|_| BackupError("PostgreSQL dump did not restore"))?;
        let actual = crate::store::backup::inspect_restored_postgres(
            &cluster.socket,
            "restore_role",
            "restore",
        )
        .await
        .map_err(|_| BackupError("PostgreSQL restored state failed validation"))?;
        if &actual != expected {
            return Err(BackupError("backup snapshot metadata mismatch"));
        }
        Ok(())
    }
    .await;
    cluster.stop();
    outcome
}

/// Name of the single schema a verified dump creates, read from its table of
/// contents so a restore can be undone without guessing.
fn dump_schema(dump: &Path, stage: &Stage) -> Result<String> {
    let listing = stage.member("restore.list");
    let mut command = Command::new(tool_path("pg_restore"));
    command.arg("--list").arg(dump);
    tool(command, None, private_create(&listing)?)
        .map_err(|_| BackupError("PostgreSQL dump could not be listed"))?;
    let bytes = read_private_file(&listing, 4 * 1024 * 1024)
        .map_err(|_| BackupError("PostgreSQL dump could not be listed"))?;
    let text = std::str::from_utf8(bytes.as_bytes())
        .map_err(|_| BackupError("PostgreSQL dump could not be listed"))?;
    let mut schemas = Vec::new();
    for line in text.lines().filter(|line| !line.starts_with(';')) {
        let mut fields = line
            .split_whitespace()
            .skip_while(|field| *field != "SCHEMA");
        if fields.next() == Some("SCHEMA") && fields.next() == Some("-") {
            schemas.push(fields.next().unwrap_or("").to_owned());
        }
    }
    let _ = fs::remove_file(&listing);
    match schemas.as_slice() {
        [schema]
            if identifier(schema)
                && !schema.starts_with("pg_")
                && !matches!(schema.as_str(), "information_schema" | "public") =>
        {
            Ok(schema.clone())
        }
        _ => Err(BackupError("PostgreSQL dump schema is unsupported")),
    }
}

/// Fixed operator-facing reason for the init hook's empty schema (never carries a name or value).
pub(crate) const EMPTY_SCHEMA_REFUSAL: BackupError = BackupError(
    "PostgreSQL restore target holds an empty schema: drop it first (docs/deploy/recovery-stage.md)",
);

/// Restore the verified dump into an empty target database in one transaction
/// and re-measure it against the authenticated manifest. The target is never
/// merged into or replaced; any failure after the restore commits removes the
/// schema this call created (and only that schema). Returns the schema name.
pub(crate) async fn restore_into_target(
    connection: &PgConnection,
    url: &str,
    dump: &Path,
    expected: &SnapshotInfo,
    stage: &Stage,
) -> Result<String> {
    require_toolkit(stage)?;
    private_input(dump, MAX_BUNDLE_BYTES)?;
    let schema = dump_schema(dump, stage)?;
    crate::store::backup::require_empty_restore_target(url)
        .await
        .map_err(|error| match error {
            crate::store::StoreError::InvalidInput(
                crate::store::backup::RESTORE_TARGET_EMPTY_SCHEMA,
            ) => EMPTY_SCHEMA_REFUSAL,
            _ => BackupError("PostgreSQL restore target is not empty"),
        })?;
    let passfile = stage.member("pgpass");
    match connection.passfile_line() {
        Some(line) => private_write(&passfile, format!("{line}\n").as_bytes())?,
        None => private_write(&passfile, b"# no password\n")?,
    }
    let environment = connection.environment(&passfile);
    let borrowed: Vec<(&str, &std::ffi::OsStr)> = environment
        .iter()
        .map(|(name, value)| (*name, value.as_os_str()))
        .collect();
    let mut restore = Command::new(tool_path("pg_restore"));
    restore
        .args([
            "--no-owner",
            "--no-privileges",
            "--exit-on-error",
            "--single-transaction",
        ])
        .arg(format!("--dbname={}", connection.database))
        .arg(dump);
    let restored = tool_with_env(
        restore,
        &borrowed,
        None,
        private_create(&stage.member("pg_restore.out"))?,
        RESTORE_DEADLINE,
    );
    let _ = fs::remove_file(&passfile);
    restored.map_err(|_| BackupError("PostgreSQL dump did not restore"))?;
    let measured = crate::store::backup::inspect_restored_target(url).await;
    match measured {
        Ok((found, actual)) if found == schema && &actual == expected => Ok(schema),
        _ => {
            let _ = crate::store::backup::drop_restored_schema(url, &schema).await;
            Err(BackupError("PostgreSQL restored state failed validation"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p06_pg01_url_parts_are_decoded_and_the_password_never_reaches_environment_or_arguments() {
        let connection = PgConnection::parse(
            "postgresql://ctl%40user:p%3Ass%5Cw%2Frd@db.example:6543/blindpass?sslmode=verify-full&sslrootcert=/etc/ca.pem&application_name=x",
        )
        .unwrap();
        assert_eq!(connection.user, "ctl@user");
        assert_eq!(connection.password.as_deref(), Some("p:ss\\w/rd"));
        assert_eq!(
            (connection.host.as_str(), connection.port),
            ("db.example", 6543)
        );
        assert_eq!(connection.database, "blindpass");
        let environment = connection.environment(Path::new("/stage/pgpass"));
        let rendered = format!("{environment:?}");
        assert!(!rendered.contains("p:ss") && !rendered.contains("w/rd"));
        let get = |name: &str| {
            environment
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string_lossy().into_owned())
        };
        assert_eq!(get("PGHOST").as_deref(), Some("db.example"));
        assert_eq!(get("PGPORT").as_deref(), Some("6543"));
        assert_eq!(get("PGUSER").as_deref(), Some("ctl@user"));
        assert_eq!(get("PGDATABASE").as_deref(), Some("blindpass"));
        assert_eq!(get("PGSSLMODE").as_deref(), Some("verify-full"));
        assert_eq!(get("PGSSLROOTCERT").as_deref(), Some("/etc/ca.pem"));
        assert_eq!(get("PGPASSFILE").as_deref(), Some("/stage/pgpass"));
        assert!(get("PGPASSWORD").is_none());
        // Colons and backslashes are escaped as libpq requires.
        assert_eq!(
            connection.passfile_line().as_deref(),
            Some("*:*:*:*:p\\:ss\\\\w/rd")
        );
        assert!(format!("{connection:?}").find("p:ss").is_none());
    }

    #[test]
    fn p06_pg02_unix_socket_sqlx_aliases_and_defaults_are_accepted() {
        let connection = PgConnection::parse(
            "postgres:///blindpass?host=/run/postgresql&user=ctl&ssl-mode=disable&options=-c%20search_path%3Dcontroller",
        )
        .unwrap();
        assert_eq!(connection.host, "/run/postgresql");
        assert_eq!(connection.port, 5432);
        assert_eq!(connection.user, "ctl");
        assert!(connection.password.is_none() && connection.passfile_line().is_none());
        let other = PgConnection::parse(
            "postgresql://u@[::1]:5433/d?ssl-root-cert=/ca&sslcert=/c&ssl-key=/k",
        )
        .unwrap();
        assert_eq!(other.host, "::1");
        assert_eq!(other.ssl_root_cert.as_deref(), Some("/ca"));
        assert_eq!(other.ssl_key.as_deref(), Some("/k"));
    }

    #[test]
    fn p06_pg03_unsafe_or_ambiguous_urls_are_refused_without_echo() {
        for url in [
            "mysql://u:p@h/d",
            "postgresql://u:p@h",
            "postgresql://u:p@h/",
            "postgresql://u:p@h/d?sslmode=bogus",
            "postgresql://u:p@h/d?sslrootcert=relative.pem",
            "postgresql://u:p@h/d?unknown=1",
            "postgresql://u:p@h:99999/d",
            "postgresql://u:p@h/d?host=rel/ative",
            "postgresql://u:p@h/d%0Aevil",
            "postgresql://u:p@h/d?user=a%00b",
            "",
        ] {
            let error = PgConnection::parse(url).unwrap_err().to_string();
            assert!(
                !error.contains(":p@") && !error.contains(url) || url.is_empty(),
                "{error}"
            );
        }
    }

    #[test]
    fn p06_pg04_dump_arguments_carry_only_the_snapshot_and_a_validated_schema() {
        let arguments = dump_arguments("p06_controller", "00000003-00000002-1").unwrap();
        for expected in [
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--schema=p06_controller",
            "--snapshot=00000003-00000002-1",
        ] {
            assert!(
                arguments.iter().any(|argument| argument == expected),
                "{expected}"
            );
        }
        assert!(
            arguments
                .iter()
                .all(|argument| !argument.contains("postgres") && !argument.contains("password"))
        );
        for schema in [
            "",
            "a b",
            "a;b",
            "a\"b",
            "-x",
            &"s".repeat(64),
            "pg_catalog",
            "information_schema",
            "public",
        ] {
            assert!(
                dump_arguments(schema, "00000003-00000002-1").is_err(),
                "{schema}"
            );
        }
        for snapshot in ["", "x y", "a;b", "--help", &"0".repeat(129)] {
            assert!(
                dump_arguments("p06_controller", snapshot).is_err(),
                "{snapshot}"
            );
        }
    }
}

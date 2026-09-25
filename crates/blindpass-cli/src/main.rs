// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::fleet::node_key_fingerprint;
use blindpass_core::secret::wipe;
use blindpass_core::signing::base64_url_decode;
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ADMIN_SOCKET: &str = "/run/blindpass-controller/admin.sock";

#[derive(Debug, Parser)]
#[command(name = "blindpass", about = "Local Blindpass administration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Admin(AdminCommand),
    /// Apply controller database migrations and exit.
    Migrate,
}

#[derive(Debug, Args)]
struct AdminCommand {
    #[command(flatten)]
    http: HttpOptions,
    #[command(subcommand)]
    command: AdminAction,
}

#[derive(Debug, Args, Default)]
struct HttpOptions {
    /// Controller origin for authenticated fleet administration.
    #[arg(long, global = true)]
    controller_url: Option<String>,
    /// Exact controller-approved browser origin; defaults to --controller-url.
    #[arg(long, global = true)]
    origin: Option<String>,
    /// Operator username for authenticated fleet administration.
    #[arg(long, global = true)]
    username: Option<String>,
    /// Read the operator password from stdin (never from a command-line value).
    #[arg(long, global = true)]
    password_stdin: bool,
}

#[derive(Debug, Subcommand)]
enum AdminAction {
    /// Create the first administrator and print its one-time temporary password.
    Bootstrap {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value = "Blindpass administrator")]
        display_name: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Mint a one-use, 15-minute token for HTTP setup.
    BootstrapToken {
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Seed agents from a JSON fixture in controller test mode.
    Seed {
        #[arg(long)]
        fixture: PathBuf,
    },
    /// Recover from a detected database clock regression. Removes expiring
    /// state created under the regressed clock and revokes operator sessions.
    ReconcileClock,
    /// Reset an operator password through the local administration socket.
    ResetPassword {
        id: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Manage one-use node enrollment requests through the controller API.
    Enrollment {
        #[command(subcommand)]
        command: EnrollmentAction,
    },
    /// Rotate or revoke a registered node through the controller API.
    Node {
        #[command(subcommand)]
        command: NodeAction,
    },
}

#[derive(Debug, Subcommand)]
enum EnrollmentAction {
    /// Create an enrollment token and write it once to a new mode-0600 file.
    Create {
        name: String,
        #[arg(long)]
        token_file: PathBuf,
    },
    /// List enrollment requests.
    List,
    /// Approve a submitted node after comparing its displayed fingerprint.
    Approve {
        id: String,
        #[arg(long)]
        expected_fingerprint: String,
    },
    /// Reject a submitted node after comparing its displayed fingerprint.
    Reject {
        id: String,
        #[arg(long)]
        expected_fingerprint: String,
    },
}

#[derive(Debug, Subcommand)]
enum NodeAction {
    /// Revoke a node; --confirm must repeat the node ID.
    Revoke {
        id: String,
        #[arg(long)]
        confirm: String,
    },
    /// Stage broker-prepared public keys from `blindpass-node rotate-prepare`.
    Rotate {
        id: String,
        #[arg(long)]
        metadata_file: PathBuf,
        #[arg(long)]
        expected_fingerprint: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("blindpass: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let admin = match cli.command {
        Command::Migrate => return run_migrate(),
        Command::Admin(admin) => admin,
    };
    let AdminCommand { http, command } = admin;
    if matches!(
        command,
        AdminAction::Enrollment { .. } | AdminAction::Node { .. }
    ) {
        return run_fleet_admin(&http, command);
    }
    let (socket, request) = match command {
        AdminAction::Bootstrap {
            username,
            display_name,
            socket,
        } => (
            socket,
            json!({"command":"bootstrap","username":username,"display_name":display_name}),
        ),
        AdminAction::BootstrapToken { socket } => (socket, json!({"command":"bootstrap-token"})),
        AdminAction::Seed { fixture } => return run_seed(&fixture),
        AdminAction::ReconcileClock => {
            return run_controller(&[std::ffi::OsStr::new("reconcile-clock")]);
        }
        AdminAction::ResetPassword { id, socket } => {
            (socket, json!({"command":"reset-password","id":id}))
        }
        AdminAction::Enrollment { .. } | AdminAction::Node { .. } => unreachable!(),
    };
    let response = call_admin_socket(&socket, &request)?;
    if response.get("error").is_some() {
        let error = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("admin_request_failed");
        return Err(error.to_owned());
    }
    let output = serde_json::to_string_pretty(&response)
        .map_err(|_| "could not format administration response".to_owned())?;
    println!("{output}");
    Ok(())
}

fn run_migrate() -> Result<(), String> {
    run_controller(&[std::ffi::OsStr::new("migrate")])
}

fn run_seed(fixture: &std::path::Path) -> Result<(), String> {
    run_controller(&[
        std::ffi::OsStr::new("seed"),
        std::ffi::OsStr::new("--fixture"),
        fixture.as_os_str(),
    ])
}

fn run_fleet_admin(options: &HttpOptions, command: AdminAction) -> Result<(), String> {
    let controller_url = required_option(options.controller_url.as_deref(), "--controller-url")?;
    let controller_url = validate_origin(controller_url)?;
    let origin = options
        .origin
        .as_deref()
        .map(validate_origin)
        .transpose()?
        .unwrap_or_else(|| controller_url.clone());
    let username = required_option(options.username.as_deref(), "--username")?;
    if !options.password_stdin {
        return Err("fleet commands require --password-stdin".to_owned());
    }
    let password = read_password_stdin()?;
    let session_result = AdminHttpSession::login(&controller_url, &origin, username, &password);
    let mut password_bytes = password.into_bytes();
    wipe(&mut password_bytes);
    let mut session = session_result?;
    if session.must_change_password {
        let _ = session.logout();
        return Err(
            "change the temporary password in the controller UI before using fleet commands"
                .to_owned(),
        );
    }

    let result = match command {
        AdminAction::Enrollment { command } => run_enrollment_action(&mut session, command),
        AdminAction::Node { command } => run_node_action(&mut session, command),
        _ => unreachable!(),
    };
    let logout = session.logout();
    match (result, logout) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(_)) => {
            Err("command completed, but the controller session could not be logged out".to_owned())
        }
    }
}

fn run_enrollment_action(
    session: &mut AdminHttpSession,
    command: EnrollmentAction,
) -> Result<(), String> {
    match command {
        EnrollmentAction::Create { name, token_file } => {
            let mut token_file = ReservedTokenFile::create(token_file)?;
            let mut response = session.post("/api/v3/enrollments", &json!({"name":name}))?;
            let token = response
                .get("token")
                .and_then(Value::as_str)
                .ok_or("controller did not return an enrollment token")?;
            token_file.write(token.as_bytes())?;
            let summary = json!({
                "id": response.get("id"),
                "node_id": response.get("node_id"),
                "expires_at": response.get("expires_at"),
                "token_file": token_file.path.display().to_string()
            });
            if let Some(object) = response.as_object_mut() {
                object.remove("token");
            }
            print_json(&summary)
        }
        EnrollmentAction::List => {
            let mut items = Vec::new();
            let mut cursor: Option<String> = None;
            for _ in 0..1_000 {
                let path = match cursor.as_deref() {
                    Some(cursor) if valid_cursor(cursor) => {
                        format!("/api/v3/enrollments?limit=100&cursor={cursor}")
                    }
                    Some(_) => {
                        return Err("controller returned an invalid enrollment cursor".to_owned());
                    }
                    None => "/api/v3/enrollments?limit=100".to_owned(),
                };
                let page = session.get(&path)?;
                let page_items = page
                    .get("items")
                    .and_then(Value::as_array)
                    .ok_or("controller returned an invalid enrollment page")?;
                items.extend(page_items.iter().cloned());
                cursor = page
                    .get("next_cursor")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if cursor.is_none() {
                    return print_json(&json!({"items":items,"next_cursor":null}));
                }
            }
            Err("enrollment listing exceeded the page limit".to_owned())
        }
        EnrollmentAction::Approve {
            id,
            expected_fingerprint,
        } => decide_enrollment(session, &id, &expected_fingerprint, true),
        EnrollmentAction::Reject {
            id,
            expected_fingerprint,
        } => decide_enrollment(session, &id, &expected_fingerprint, false),
    }
}

fn decide_enrollment(
    session: &mut AdminHttpSession,
    id: &str,
    expected_fingerprint: &str,
    approve: bool,
) -> Result<(), String> {
    if !valid_fingerprint(expected_fingerprint) {
        return Err(
            "--expected-fingerprint must be 64 lowercase hexadecimal characters".to_owned(),
        );
    }
    let path = format!("/api/v3/enrollments/{}", encode_path_segment(id));
    let enrollment = session.get(&path)?;
    if enrollment.get("status").and_then(Value::as_str) != Some("submitted") {
        return Err("enrollment is not in submitted state".to_owned());
    }
    if enrollment.get("fingerprint").and_then(Value::as_str) != Some(expected_fingerprint) {
        return Err("submitted fingerprint does not match --expected-fingerprint".to_owned());
    }
    let version = enrollment
        .get("version")
        .and_then(Value::as_i64)
        .filter(|version| *version > 0)
        .ok_or("controller returned an invalid enrollment version")?;
    let action = if approve { "approve" } else { "reject" };
    let result = session.post(
        &format!("{path}/{action}"),
        &json!({
            "expected_fingerprint": expected_fingerprint,
            "expected_version": version
        }),
    )?;
    print_json(&result)
}

fn run_node_action(session: &mut AdminHttpSession, command: NodeAction) -> Result<(), String> {
    match command {
        NodeAction::Revoke { id, confirm } => {
            if id != confirm {
                return Err("--confirm must exactly repeat the node ID".to_owned());
            }
            let result = session.delete(&format!("/api/v3/nodes/{}", encode_path_segment(&id)))?;
            print_json(&result)
        }
        NodeAction::Rotate {
            id,
            metadata_file,
            expected_fingerprint,
        } => rotate_node_key(session, &id, &metadata_file, &expected_fingerprint),
    }
}

fn rotate_node_key(
    session: &mut AdminHttpSession,
    id: &str,
    metadata_file: &Path,
    expected_fingerprint: &str,
) -> Result<(), String> {
    let metadata = fs::read(metadata_file)
        .map_err(|_| "cannot read broker rotation metadata file".to_owned())?;
    if metadata.len() > 16 * 1024 {
        return Err("broker rotation metadata exceeds its size limit".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&metadata)
        .map_err(|_| "broker rotation metadata is invalid JSON".to_owned())?;
    let signing_public = metadata
        .get("signing_pub")
        .and_then(Value::as_str)
        .ok_or("broker rotation metadata is missing signing_pub")?;
    let recipient_public = metadata
        .get("recipient_pub")
        .and_then(Value::as_str)
        .ok_or("broker rotation metadata is missing recipient_pub")?;
    let fingerprint = metadata
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or("broker rotation metadata is missing fingerprint")?;
    let candidate_version = metadata
        .get("key_version")
        .and_then(Value::as_i64)
        .filter(|version| *version > 1)
        .ok_or("broker rotation metadata has an invalid key_version")?;
    let signing_key = base64_url_decode(signing_public, 32)
        .ok_or("broker rotation metadata has an invalid signing key")?;
    let recipient_key = base64_url_decode(recipient_public, 32)
        .ok_or("broker rotation metadata has an invalid recipient key")?;
    let computed_fingerprint = node_key_fingerprint(&signing_key, &recipient_key)
        .map_err(|_| "broker rotation metadata has invalid node public keys".to_owned())?;
    if !valid_fingerprint(fingerprint)
        || computed_fingerprint != fingerprint
        || fingerprint != expected_fingerprint
    {
        return Err("broker key fingerprint does not match --expected-fingerprint".to_owned());
    }

    let node_path = format!("/api/v3/nodes/{}", encode_path_segment(id));
    let node = session.get(&node_path)?;
    if node.get("status").and_then(Value::as_str) == Some("revoked")
        || node.get("rotation_pending").and_then(Value::as_bool) == Some(true)
    {
        return Err("node is revoked or already has a pending key rotation".to_owned());
    }
    let current_version = node
        .get("key_version")
        .and_then(Value::as_i64)
        .filter(|version| *version > 0)
        .ok_or("controller returned an invalid node key version")?;
    if candidate_version != current_version + 1 {
        return Err("candidate key version is not the next node key version".to_owned());
    }
    let result = session.post(
        &format!("{node_path}/rotate-key"),
        &json!({
            "expected_key_version": current_version,
            "expected_fingerprint": fingerprint,
            "signing_pub": signing_public,
            "recipient_pub": recipient_public
        }),
    )?;
    print_json(&result)
}

struct PrivateCookieJar {
    path: PathBuf,
}

impl PrivateCookieJar {
    fn create() -> Result<Self, String> {
        let directory = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| {
                path.is_absolute()
                    && std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0
                    })
            })
            .unwrap_or_else(std::env::temp_dir);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?
            .as_nanos();
        for attempt in 0..16_u8 {
            let path = directory.join(format!(
                ".blindpass-cli-session-{}-{time}-{attempt}",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("cannot create a private controller session file".to_owned()),
            }
        }
        Err("cannot allocate a private controller session file".to_owned())
    }
}

impl Drop for PrivateCookieJar {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct AdminHttpSession {
    controller_url: String,
    origin: String,
    csrf_token: String,
    must_change_password: bool,
    cookie_jar: PrivateCookieJar,
    logged_out: bool,
}

impl AdminHttpSession {
    fn login(
        controller_url: &str,
        origin: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, String> {
        let cookie_jar = PrivateCookieJar::create()?;
        let pre_session = format!("blindpass-cli-{}", std::process::id());
        #[derive(serde::Serialize)]
        struct LoginInput<'a> {
            username: &'a str,
            password: &'a str,
        }
        let mut body = serde_json::to_vec(&LoginInput { username, password })
            .map_err(|_| "could not encode operator login".to_owned())?;
        let url = format!("{controller_url}/api/v3/admin/session/login");
        let response = curl_request(
            "POST",
            &url,
            origin,
            &cookie_jar.path,
            None,
            Some(&pre_session),
            Some(&body),
        );
        wipe(&mut body);
        let (status, response) = response?;
        let response = parse_response(status, response)?;
        if status != 200 {
            return Err(response_error(status, &response));
        }
        let csrf_token = response
            .get("csrf_token")
            .and_then(Value::as_str)
            .filter(|token| token.len() == 43 && token.bytes().all(is_base64url_byte))
            .ok_or("controller returned an invalid session CSRF token")?
            .to_owned();
        let must_change_password = response
            .get("must_change_password")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        Ok(Self {
            controller_url: controller_url.to_owned(),
            origin: origin.to_owned(),
            csrf_token,
            must_change_password,
            cookie_jar,
            logged_out: false,
        })
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        self.request("GET", path, None)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let body = serde_json::to_vec(body)
            .map_err(|_| "could not encode controller request".to_owned())?;
        self.request("POST", path, Some(&body))
    }

    fn delete(&self, path: &str) -> Result<Value, String> {
        self.request("DELETE", path, None)
    }

    fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Value, String> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err("controller request path is invalid".to_owned());
        }
        let url = format!("{}{path}", self.controller_url);
        let (status, response) = curl_request(
            method,
            &url,
            &self.origin,
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            None,
            body,
        )?;
        let response = parse_response(status, response)?;
        if !(200..300).contains(&status) {
            return Err(response_error(status, &response));
        }
        Ok(response)
    }

    fn logout(&mut self) -> Result<(), String> {
        if self.logged_out {
            return Ok(());
        }
        let result = self.request("POST", "/api/v3/admin/session/logout", None);
        if result.is_ok() {
            self.logged_out = true;
        }
        result.map(|_| ())
    }
}

fn curl_request(
    method: &str,
    url: &str,
    origin: &str,
    cookie_jar: &Path,
    csrf_token: Option<&str>,
    pre_session_csrf: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let mut command = ProcessCommand::new("curl");
    command
        .arg("--disable")
        .arg("--silent")
        .arg("--show-error")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("30")
        .arg("--proto")
        .arg("=https,http")
        .arg("--request")
        .arg(method)
        .arg("--url")
        .arg(url)
        .arg("--header")
        .arg(format!("Origin: {origin}"))
        .arg("--header")
        .arg("Accept: application/json")
        .arg("--cookie-jar")
        .arg(cookie_jar)
        .arg("--write-out")
        .arg("\n__BLINDPASS_HTTP_STATUS__%{http_code}");
    if csrf_token.is_some() {
        command.arg("--cookie").arg(cookie_jar);
    }
    if let Some(token) = csrf_token {
        command
            .arg("--header")
            .arg(format!("X-CSRF-Token: {token}"));
    }
    if let Some(token) = pre_session_csrf {
        command
            .arg("--header")
            .arg(format!("Cookie: bp_csrf={token}"))
            .arg("--header")
            .arg(format!("X-CSRF-Token: {token}"));
    }
    if body.is_some() {
        command
            .arg("--header")
            .arg("Content-Type: application/json")
            .arg("--data-binary")
            .arg("@-")
            .stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "cannot start curl for the controller request".to_owned())?;
    if let Some(body) = body {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("cannot send controller request body")?;
        stdin
            .write_all(body)
            .map_err(|_| "cannot send controller request body".to_owned())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "cannot read controller response".to_owned())?;
    if !output.status.success() {
        return Err("curl could not complete the controller request".to_owned());
    }
    let marker = b"\n__BLINDPASS_HTTP_STATUS__";
    let marker_at = output
        .stdout
        .windows(marker.len())
        .rposition(|window| window == marker)
        .ok_or("curl returned a response without an HTTP status")?;
    let status_bytes = &output.stdout[marker_at + marker.len()..];
    let status = std::str::from_utf8(status_bytes)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("curl returned an invalid HTTP status")?;
    Ok((status, output.stdout[..marker_at].to_vec()))
}

fn parse_response(status: u16, body: Vec<u8>) -> Result<Value, String> {
    if body.is_empty() && status == 204 {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&body).map_err(|_| "controller returned invalid JSON".to_owned())
}

fn response_error(status: u16, body: &Value) -> String {
    let code = body
        .get("error")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty() && code.bytes().all(is_error_code_byte))
        .unwrap_or("http_error");
    format!("controller returned HTTP {status} ({code})")
}

fn read_password_stdin() -> Result<String, String> {
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(|_| "cannot read operator password from stdin".to_owned())?;
    if password.len() > 1_025 {
        return Err("operator password exceeds its input limit".to_owned());
    }
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err("operator password from stdin is empty".to_owned());
    }
    Ok(password)
}

fn validate_origin(value: &str) -> Result<String, String> {
    let origin = value.trim_end_matches('/');
    if origin.is_empty()
        || origin
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || origin.contains(['?', '#', '@'])
    {
        return Err("controller URL and origin must be plain HTTP(S) origins".to_owned());
    }
    let (scheme, authority) = origin
        .split_once("://")
        .ok_or("controller URL and origin must be plain HTTP(S) origins")?;
    if !matches!(scheme, "https" | "http") || authority.is_empty() || authority.contains('/') {
        return Err("controller URL and origin must be plain HTTP(S) origins".to_owned());
    }
    if scheme == "http" && !is_loopback_authority(authority) {
        return Err("unencrypted HTTP is allowed only for a loopback controller".to_owned());
    }
    Ok(origin.to_owned())
}

fn is_loopback_authority(authority: &str) -> bool {
    authority == "localhost"
        || authority.starts_with("localhost:")
        || authority == "127.0.0.1"
        || authority.starts_with("127.0.0.1:")
        || authority == "[::1]"
        || authority.starts_with("[::1]:")
}

fn required_option<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, String> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("fleet commands require {name}"))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_cursor(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_base64url_byte)
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_error_code_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

struct ReservedTokenFile {
    path: PathBuf,
    file: Option<File>,
    completed: bool,
}

impl ReservedTokenFile {
    fn create(path: PathBuf) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| "token file already exists or cannot be created".to_owned())?;
        Ok(Self {
            path,
            file: Some(file),
            completed: false,
        })
    }

    fn write(&mut self, content: &[u8]) -> Result<(), String> {
        let file = self
            .file
            .as_mut()
            .ok_or("cannot write enrollment token file")?;
        if file
            .write_all(content)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            return Err("cannot write enrollment token file".to_owned());
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for ReservedTokenFile {
    fn drop(&mut self) {
        if !self.completed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|_| "could not format controller response".to_owned())?;
    println!("{output}");
    Ok(())
}

fn run_controller(args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let controller = std::env::current_exe()
        .map_err(|_| "cannot locate installed CLI binary".to_owned())?
        .with_file_name("blindpass-controller");
    let status = ProcessCommand::new(controller)
        .args(args)
        .status()
        .map_err(|_| "cannot run colocated controller binary".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        Err("controller command failed".to_owned())
    }
}

fn call_admin_socket(socket_path: &PathBuf, request: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|_| "cannot connect to local administration socket".to_owned())?;
    let encoded = serde_json::to_vec(request)
        .map_err(|_| "could not encode administration request".to_owned())?;
    stream
        .write_all(&encoded)
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|_| "could not write to local administration socket".to_owned())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| "could not finish local administration request".to_owned())?;
    let mut response = Vec::new();
    stream
        .take(8 * 1024)
        .read_to_end(&mut response)
        .map_err(|_| "could not read local administration response".to_owned())?;
    serde_json::from_slice(&response)
        .map_err(|_| "local administration returned an invalid response".to_owned())
}

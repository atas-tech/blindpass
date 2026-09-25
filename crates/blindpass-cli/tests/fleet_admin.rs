// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::fleet::node_key_fingerprint;
use blindpass_core::signing::base64_url_encode;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SESSION_CSRF: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-cli-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create CLI test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect CLI test directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct RequestExpectation {
    method: &'static str,
    path: String,
    body: Option<Value>,
    pre_session_csrf: bool,
    session: bool,
    response: Value,
    status: u16,
}

fn login_step() -> RequestExpectation {
    RequestExpectation {
        method: "POST",
        path: "/api/v3/admin/session/login".to_owned(),
        body: Some(json!({"username":"fleet-admin","password":"dummy-password"})),
        pre_session_csrf: true,
        session: false,
        response: json!({"csrf_token":SESSION_CSRF,"must_change_password":false}),
        status: 200,
    }
}

fn logout_step() -> RequestExpectation {
    RequestExpectation {
        method: "POST",
        path: "/api/v3/admin/session/logout".to_owned(),
        body: None,
        pre_session_csrf: false,
        session: true,
        response: Value::Null,
        status: 204,
    }
}

fn serve_script(steps: Vec<RequestExpectation>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock controller");
    listener
        .set_nonblocking(true)
        .expect("use bounded mock accept");
    let address = listener.local_addr().expect("mock controller address");
    let task = std::thread::spawn(move || {
        for expectation in steps {
            let mut accepted = None;
            for _ in 0..500 {
                match listener.accept() {
                    Ok(connection) => {
                        accepted = Some(connection.0);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept mock request: {error}"),
                }
            }
            let mut stream = accepted.expect("CLI connected to mock controller");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("set request timeout");
            let request = read_request(&mut stream);
            assert_eq!(request.method, expectation.method);
            assert_eq!(request.path, expectation.path);
            assert!(
                header(&request.headers, "origin")
                    .expect("Origin header")
                    .starts_with("http://127.0.0.1:")
            );
            if expectation.pre_session_csrf {
                let cookie = header(&request.headers, "cookie").expect("pre-session cookie");
                let csrf = header(&request.headers, "x-csrf-token").expect("pre-session CSRF");
                let cookie_token = cookie.strip_prefix("bp_csrf=").expect("CSRF cookie name");
                assert!(cookie_token.starts_with("blindpass-cli-"));
                assert_eq!(csrf, cookie_token);
            }
            if expectation.session {
                let cookie = header(&request.headers, "cookie").expect("session cookie");
                assert!(cookie.contains("bp_session=fixture-session"));
                assert!(cookie.contains(&format!("bp_csrf={SESSION_CSRF}")));
                assert_eq!(header(&request.headers, "x-csrf-token"), Some(SESSION_CSRF));
            }
            if let Some(expected) = expectation.body {
                let actual: Value =
                    serde_json::from_slice(&request.body).expect("JSON request body");
                assert_eq!(actual, expected);
            } else {
                assert!(request.body.is_empty());
            }
            write_response(&mut stream, expectation.status, &expectation.response);
        }
    });
    (format!("http://{address}"), task)
}

struct HttpRequest {
    method: String,
    path: String,
    headers: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> HttpRequest {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let (header_end, content_length) = loop {
        let count = stream.read(&mut chunk).expect("read mock request");
        assert!(count > 0, "CLI closed before sending an HTTP request");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_text = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
            let content_length = header_text
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(str::trim)
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                break (header_end, content_length);
            }
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let request_line = headers.lines().next().expect("HTTP request line");
    let mut fields = request_line.split_whitespace();
    let method = fields.next().expect("HTTP method").to_owned();
    let path = fields.next().expect("HTTP path").to_owned();
    HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end + 4..header_end + 4 + content_length].to_vec(),
    }
}

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn write_response(stream: &mut TcpStream, status: u16, body: &Value) {
    let body = if status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(body).expect("serialize mock response")
    };
    let reason = if status == 204 { "No Content" } else { "OK" };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if status == 200 && body.windows(12).any(|window| window == b"\"csrf_token\"") {
        response.push_str(
            "Set-Cookie: bp_session=fixture-session; Path=/; HttpOnly; SameSite=Strict\r\n",
        );
        response.push_str("Set-Cookie: bp_csrf=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; Path=/; SameSite=Strict\r\n");
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write mock headers");
    stream.write_all(&body).expect("write mock body");
    stream.flush().expect("flush mock response");
}

fn run_cli(directory: &TestDirectory, origin: &str, args: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_blindpass"));
    command
        .arg("admin")
        .args([
            "--controller-url",
            origin,
            "--origin",
            origin,
            "--username",
            "fleet-admin",
            "--password-stdin",
        ])
        .args(args)
        .env("XDG_RUNTIME_DIR", &directory.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("start fleet CLI");
    child
        .stdin
        .take()
        .expect("CLI stdin")
        .write_all(b"dummy-password\n")
        .expect("write dummy operator password");
    child.wait_with_output().expect("wait for fleet CLI")
}

#[test]
fn enrollment_approval_checks_displayed_fingerprint_and_uses_csrf_session() {
    let directory = TestDirectory::new("approve");
    let fingerprint = "a".repeat(64);
    let node = json!({"id":"nd_fixture","status":"active"});
    let steps = vec![
        login_step(),
        RequestExpectation {
            method: "GET",
            path: "/api/v3/enrollments/en_fixture".to_owned(),
            body: None,
            pre_session_csrf: false,
            session: true,
            response: json!({"id":"en_fixture","status":"submitted","fingerprint":fingerprint,"version":4}),
            status: 200,
        },
        RequestExpectation {
            method: "POST",
            path: "/api/v3/enrollments/en_fixture/approve".to_owned(),
            body: Some(json!({"expected_fingerprint":fingerprint,"expected_version":4})),
            pre_session_csrf: false,
            session: true,
            response: node,
            status: 200,
        },
        logout_step(),
    ];
    let (origin, server) = serve_script(steps);
    let output = run_cli(
        &directory,
        &origin,
        &[
            "enrollment".to_owned(),
            "approve".to_owned(),
            "en_fixture".to_owned(),
            "--expected-fingerprint".to_owned(),
            fingerprint,
        ],
    );
    assert!(
        output.status.success(),
        "approval CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("nd_fixture"));
    assert_eq!(
        fs::read_dir(&directory.0).unwrap().count(),
        0,
        "session cookie jar is removed after logout"
    );
    server.join().expect("mock approval server");
}

#[test]
fn enrollment_create_writes_token_once_without_printing_it() {
    let directory = TestDirectory::new("create");
    let token_file = directory.file("node.enrollment");
    let token = "en_fixture_SECRET_CANARY";
    let steps = vec![
        login_step(),
        RequestExpectation {
            method: "POST",
            path: "/api/v3/enrollments".to_owned(),
            body: Some(json!({"name":"edge-node"})),
            pre_session_csrf: false,
            session: true,
            response: json!({"id":"en_fixture","node_id":"nd_fixture","token":token,"expires_at":1900000000000_i64}),
            status: 201,
        },
        logout_step(),
    ];
    let (origin, server) = serve_script(steps);
    let output = run_cli(
        &directory,
        &origin,
        &[
            "enrollment".to_owned(),
            "create".to_owned(),
            "edge-node".to_owned(),
            "--token-file".to_owned(),
            token_file.display().to_string(),
        ],
    );
    assert!(
        output.status.success(),
        "enrollment create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&token_file).unwrap(), token.as_bytes());
    assert_eq!(
        fs::metadata(&token_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("en_fixture"));
    assert!(!stdout.contains(token));
    server.join().expect("mock enrollment server");
}

#[test]
fn enrollment_list_follows_server_cursors() {
    let directory = TestDirectory::new("list");
    let steps = vec![
        login_step(),
        RequestExpectation {
            method: "GET",
            path: "/api/v3/enrollments?limit=100".to_owned(),
            body: None,
            pre_session_csrf: false,
            session: true,
            response: json!({"items":[{"id":"en_one"}],"next_cursor":"cursor_1"}),
            status: 200,
        },
        RequestExpectation {
            method: "GET",
            path: "/api/v3/enrollments?limit=100&cursor=cursor_1".to_owned(),
            body: None,
            pre_session_csrf: false,
            session: true,
            response: json!({"items":[{"id":"en_two"}],"next_cursor":null}),
            status: 200,
        },
        logout_step(),
    ];
    let (origin, server) = serve_script(steps);
    let output = run_cli(
        &directory,
        &origin,
        &["enrollment".to_owned(), "list".to_owned()],
    );
    assert!(
        output.status.success(),
        "enrollment list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("en_one"));
    assert!(stdout.contains("en_two"));
    server.join().expect("mock enrollment list server");
}

#[test]
fn enrollment_rejection_uses_the_verified_fingerprint_and_version() {
    let directory = TestDirectory::new("reject");
    let fingerprint = "b".repeat(64);
    let steps = vec![
        login_step(),
        RequestExpectation {
            method: "GET",
            path: "/api/v3/enrollments/en_fixture".to_owned(),
            body: None,
            pre_session_csrf: false,
            session: true,
            response: json!({"status":"submitted","fingerprint":fingerprint,"version":7}),
            status: 200,
        },
        RequestExpectation {
            method: "POST",
            path: "/api/v3/enrollments/en_fixture/reject".to_owned(),
            body: Some(json!({"expected_fingerprint":fingerprint,"expected_version":7})),
            pre_session_csrf: false,
            session: true,
            response: json!({"id":"en_fixture","status":"rejected"}),
            status: 200,
        },
        logout_step(),
    ];
    let (origin, server) = serve_script(steps);
    let output = run_cli(
        &directory,
        &origin,
        &[
            "enrollment".to_owned(),
            "reject".to_owned(),
            "en_fixture".to_owned(),
            "--expected-fingerprint".to_owned(),
            fingerprint,
        ],
    );
    assert!(
        output.status.success(),
        "enrollment reject failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("rejected"));
    server.join().expect("mock enrollment rejection server");
}

#[test]
fn node_rotation_validates_operator_fingerprint_and_next_key_version() {
    let directory = TestDirectory::new("rotate");
    let signing_key = [3_u8; 32];
    let recipient_key = [8_u8; 32];
    let fingerprint = node_key_fingerprint(&signing_key, &recipient_key).unwrap();
    let metadata_file = directory.file("rotation.json");
    fs::write(
        &metadata_file,
        serde_json::to_vec(&json!({
            "key_version":2,
            "signing_pub":base64_url_encode(&signing_key),
            "recipient_pub":base64_url_encode(&recipient_key),
            "fingerprint":fingerprint
        }))
        .unwrap(),
    )
    .unwrap();
    let steps = vec![
        login_step(),
        RequestExpectation {
            method: "GET",
            path: "/api/v3/nodes/nd_fixture".to_owned(),
            body: None,
            pre_session_csrf: false,
            session: true,
            response: json!({"id":"nd_fixture","status":"active","rotation_pending":false,"key_version":1}),
            status: 200,
        },
        RequestExpectation {
            method: "POST",
            path: "/api/v3/nodes/nd_fixture/rotate-key".to_owned(),
            body: Some(json!({
                "expected_key_version":1,
                "expected_fingerprint":fingerprint,
                "signing_pub":base64_url_encode(&signing_key),
                "recipient_pub":base64_url_encode(&recipient_key)
            })),
            pre_session_csrf: false,
            session: true,
            response: json!({"id":"nd_fixture","key_version":1,"pending_key_version":2,"rotation_pending":true}),
            status: 202,
        },
        logout_step(),
    ];
    let (origin, server) = serve_script(steps);
    let output = run_cli(
        &directory,
        &origin,
        &[
            "node".to_owned(),
            "rotate".to_owned(),
            "nd_fixture".to_owned(),
            "--metadata-file".to_owned(),
            metadata_file.display().to_string(),
            "--expected-fingerprint".to_owned(),
            fingerprint,
        ],
    );
    assert!(
        output.status.success(),
        "node rotation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("rotation_pending"));
    server.join().expect("mock rotation server");
}

#[test]
fn node_revoke_requires_exact_confirmation_before_delete() {
    let directory = TestDirectory::new("revoke");
    let (origin, server) = serve_script(vec![login_step(), logout_step()]);
    let output = run_cli(
        &directory,
        &origin,
        &[
            "node".to_owned(),
            "revoke".to_owned(),
            "nd_fixture".to_owned(),
            "--confirm".to_owned(),
            "different-node".to_owned(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("repeat the node ID"));
    server.join().expect("mock revoke server");
}

#[test]
fn node_revoke_posts_only_after_exact_confirmation() {
    let directory = TestDirectory::new("revoke-confirmed");
    let steps = vec![
        login_step(),
        RequestExpectation {
            method: "DELETE",
            path: "/api/v3/nodes/nd_fixture".to_owned(),
            body: None,
            pre_session_csrf: false,
            session: true,
            response: json!({"id":"nd_fixture","status":"revoked","revocation_pending":true}),
            status: 200,
        },
        logout_step(),
    ];
    let (origin, server) = serve_script(steps);
    let output = run_cli(
        &directory,
        &origin,
        &[
            "node".to_owned(),
            "revoke".to_owned(),
            "nd_fixture".to_owned(),
            "--confirm".to_owned(),
            "nd_fixture".to_owned(),
        ],
    );
    assert!(
        output.status.success(),
        "node revoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("revocation_pending"));
    server.join().expect("mock confirmed revoke server");
}

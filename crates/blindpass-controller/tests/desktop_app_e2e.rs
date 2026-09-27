// SPDX-License-Identifier: AGPL-3.0-only

//! P04-E02 (app portion): the Quickshell approval app in
//! `desktop/approval-app` against this controller. Each phase runs the real
//! app offscreen with its curl transport and session-store helper, then the
//! test checks the controller's database and the files the app left.
//!
//! Needs `quickshell`, `curl` and `openssl` on PATH and an offscreen Qt
//! platform, so it is ignored by default:
//!
//! ```sh
//! cargo test -p blindpass-controller --test desktop_app_e2e -- --ignored --nocapture
//! ```

mod support;

use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use support::{Harness, OperationSpec, TestDirectory};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const APPROVER: &str = "desk-approver";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Run {
    status: i32,
    output: String,
}

/// Run one scenario phase of desktop/approval-app/e2e.qml.
async fn run_app(
    runtime: &Path,
    config: &Path,
    controller: &str,
    password: &str,
    approval: &str,
    phase: &str,
) -> Run {
    let shell = repo_root().join("desktop/approval-app/e2e.qml");
    let mut command = Command::new("timeout");
    command
        .arg("90")
        .arg("quickshell")
        .arg("-p")
        .arg(shell)
        .env("QT_QPA_PLATFORM", "offscreen")
        .env("QT_FORCE_STDERR_LOGGING", "1")
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_CONFIG_HOME", config)
        .env("BLINDPASS_E2E_PHASE", phase)
        .env("BLINDPASS_E2E_CONTROLLER", controller)
        .env("BLINDPASS_E2E_USER", APPROVER)
        .env("BLINDPASS_E2E_PASSWORD", password)
        .env("BLINDPASS_E2E_APPROVAL", approval)
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("BLINDPASS_CONTROLLER_URL");
    let output = tokio::task::spawn_blocking(move || command.output().expect("run quickshell"))
        .await
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("--- approval app phase {phase} ---\n{}", e2e_lines(&text));
    Run {
        status: output.status.code().unwrap_or(-1),
        output: text,
    }
}

fn e2e_lines(output: &str) -> String {
    output
        .lines()
        .filter(|line| line.contains("E2E ") || line.contains("rror"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_passed(run: &Run, phase: &str) {
    assert!(
        run.output.contains("E2E DONE failures=0") && run.status == 0,
        "phase {phase} failed (exit {}):\n{}",
        run.status,
        run.output
    );
    assert!(!run.output.contains("E2E FAIL"), "{}", run.output);
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// No credential appears in the app's output or in any file it left under
/// the runtime and config directories (Quickshell also keeps its logs there).
fn assert_not_leaked(run: &Run, secrets: &[&str], roots: &[&Path], allowed_file: Option<&Path>) {
    for secret in secrets {
        assert!(
            !run.output.contains(secret),
            "a credential appeared in the app output"
        );
        for root in roots {
            for file in files(root) {
                if Some(file.as_path()) == allowed_file {
                    continue;
                }
                let bytes = std::fs::read(&file).unwrap_or_default();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(secret),
                    "a credential appeared in {}",
                    file.display()
                );
            }
        }
    }
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files(&path));
        } else {
            found.push(path);
        }
    }
    found
}

fn approval_rule(approvers: &[&str]) -> Value {
    json!([{
        "id":"approve-noop-file","action":"noop.marker","mode":"file",
        "decision":"pending_approval","approval_required":true,"max_ttl_seconds":120,
        "approver_ids":approvers
    }])
}

fn tool_available(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the Quickshell approval app offscreen; needs quickshell, curl and openssl"]
async fn approval_app_signs_in_decides_restarts_and_signs_out() {
    for tool in ["quickshell", "curl", "timeout"] {
        assert!(tool_available(tool), "{tool} is required");
    }
    let harness = Harness::start().await;
    let node = harness.online_node("desktop-e2e-node", 81).await;
    let requester = harness.create_operator("desk-requester", "operator").await;
    let approver = harness.create_operator(APPROVER, "operator").await;
    let password = format!("{APPROVER}-test-password-long");
    let policy = harness.set_policy(approval_rule(&[APPROVER])).await;
    assert_eq!(policy.status, 200, "{}", policy.body);
    let workload = harness
        .create_workload(
            &node.id,
            "desktop-e2e",
            "desktop-e2e.service",
            "desktop",
            "file",
        )
        .await;
    assert_eq!(workload.status, 201, "{}", workload.body);
    let created = harness
        .request_operation(
            &requester,
            &node,
            &workload.body,
            &OperationSpec::new("desktop-e2e-approval-1"),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let approval = created.body["approval_id"].as_str().unwrap().to_owned();

    let scratch = TestDirectory::new();
    let runtime = scratch.file("run");
    let config = scratch.file("config");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let controller = format!("http://{}", harness.address);

    // First run: sign in, list, open and approve.
    let first = run_app(
        &runtime,
        &config,
        &controller,
        &password,
        &approval,
        "first",
    )
    .await;
    assert_passed(&first, "first");
    let decided = harness
        .strings(
            "SELECT status FROM operation_approvals WHERE id = ?",
            vec![support::Bind::Text(approval.clone())],
        )
        .await;
    assert_eq!(decided, vec![Some("approved".to_owned())]);
    let decided_by = harness
        .strings(
            "SELECT decided_by FROM operation_approvals WHERE id = ?",
            vec![support::Bind::Text(approval.clone())],
        )
        .await;
    assert_eq!(decided_by, vec![Some(approver.id.clone())]);
    let session_file = runtime.join("blindpass/session");
    assert_eq!(mode(&runtime.join("blindpass")), 0o700);
    assert_eq!(mode(&session_file), 0o600);
    let record: Value = serde_json::from_slice(&std::fs::read(&session_file).unwrap()).unwrap();
    let first_refresh = record["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(record["controller"], controller.as_str());
    let live = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM operator_sessions WHERE kind = 'desktop' AND revoked_at IS NULL",
            vec![],
        )
        .await;
    assert_eq!(live, 1, "one live desktop session after the first run");
    let config_file: Value =
        serde_json::from_slice(&std::fs::read(config.join("blindpass/approval-app.json")).unwrap())
            .unwrap();
    assert_eq!(
        config_file,
        json!({"controller_url": controller, "locale": "en"}),
        "settings hold no credential"
    );
    assert_not_leaked(
        &first,
        &[&password, &first_refresh],
        &[&runtime, &config],
        Some(&session_file),
    );

    // Restart: the stored refresh token is used once and rotated, then the
    // operator signs out and the controller revokes the session.
    let restart = run_app(
        &runtime,
        &config,
        &controller,
        &password,
        &approval,
        "restart",
    )
    .await;
    assert_passed(&restart, "restart");
    assert!(!session_file.exists(), "sign-out deletes the session file");
    let live = harness
        .scalar_i64(
            "SELECT COUNT(*) FROM operator_sessions WHERE kind = 'desktop' AND revoked_at IS NULL",
            vec![],
        )
        .await;
    assert_eq!(
        live, 0,
        "sign-out revoked the desktop session on the controller"
    );
    let replay = harness
        .request(
            "POST",
            "/api/v3/admin/session/refresh",
            &[("content-type", "application/json")],
            Some(&json!({"kind":"desktop","refresh_token":first_refresh})),
        )
        .await;
    assert_eq!(
        replay.status, 401,
        "the first run's refresh token was rotated away"
    );
    assert_not_leaked(
        &restart,
        &[&password, &first_refresh],
        &[&runtime, &config],
        None,
    );

    // A stored token the controller no longer honours: 401, then deleted.
    std::fs::create_dir_all(runtime.join("blindpass")).unwrap();
    std::fs::write(
        &session_file,
        json!({"v":1,"controller":controller,"refresh_token":first_refresh,"username":APPROVER,"last_active_at":0}).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&session_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let revoked = run_app(
        &runtime,
        &config,
        &controller,
        &password,
        &approval,
        "revoked",
    )
    .await;
    assert_passed(&revoked, "revoked");
    assert!(!session_file.exists());
}

/// Accept connections, answer each with `response`, and count them.
async fn scripted_server(response: String) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 8192];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("http://{address}"), hits)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the Quickshell approval app offscreen; needs quickshell, curl and openssl"]
async fn approval_app_follows_no_redirect_and_refuses_an_unverified_certificate() {
    for tool in ["quickshell", "curl", "openssl", "timeout"] {
        assert!(tool_available(tool), "{tool} is required");
    }
    let scratch = TestDirectory::new();
    let runtime = scratch.file("run");
    let config = scratch.file("config");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let password = "desktop-e2e-canary-password-3f9c";

    // A controller address that redirects the login elsewhere: the app must
    // not send the password (or anything) to the redirect target.
    let (elsewhere, elsewhere_hits) =
        scripted_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_owned()).await;
    let (redirecting, redirect_hits) = scripted_server(format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere}/api/v3/admin/session/login\r\nContent-Length: 0\r\n\r\n"
    ))
    .await;
    let redirect = run_app(&runtime, &config, &redirecting, password, "", "redirect").await;
    assert_passed(&redirect, "redirect");
    assert_eq!(redirect_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        elsewhere_hits.load(Ordering::SeqCst),
        0,
        "the redirect was not followed"
    );
    assert_not_leaked(&redirect, &[password], &[&runtime, &config], None);

    // An https controller with a self-signed certificate for this address.
    let key = scratch.file("key.pem");
    let cert = scratch.file("cert.pem");
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut server = Command::new("openssl")
        .args(["s_server", "-quiet", "-www", "-accept"])
        .arg(port.to_string())
        .arg("-cert")
        .arg(&cert)
        .arg("-key")
        .arg(&key)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let tls = run_app(
        &runtime,
        &config,
        &format!("https://127.0.0.1:{port}"),
        password,
        "",
        "tls",
    )
    .await;
    let _ = server.kill();
    let _ = server.wait();
    assert_passed(&tls, "tls");
    assert_not_leaked(&tls, &[password], &[&runtime, &config], None);
}

/// P04-I04 (app portion): the only same-user IPC surface is window control.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the Quickshell approval app offscreen; needs quickshell"]
async fn approval_app_ipc_exposes_window_control_only() {
    assert!(tool_available("quickshell"), "quickshell is required");
    // Quickshell's IPC socket lives under XDG_RUNTIME_DIR; keep the path
    // short enough for a Unix socket.
    let short = tempfile_dir();
    let runtime = short.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let shell = repo_root().join("desktop/approval-app/shell.qml");
    let environment = |command: &mut Command| {
        command
            .env("QT_QPA_PLATFORM", "offscreen")
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CONFIG_HOME", short.join("config"))
            .env("BLINDPASS_CONTROLLER_URL", "http://127.0.0.1:9")
            .env_remove("WAYLAND_DISPLAY");
    };
    let mut app = Command::new("quickshell");
    app.arg("-p")
        .arg(&shell)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    environment(&mut app);
    let mut child = app.spawn().unwrap();
    let mut listing = String::new();
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut show = Command::new("quickshell");
        show.args(["ipc", "-p"]).arg(&shell).arg("show");
        environment(&mut show);
        let output = show.output().unwrap();
        listing = String::from_utf8_lossy(&output.stdout).into_owned();
        if listing.contains("target blindpass-approvals") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&short);
    let mut functions: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("function "))
        .collect();
    functions.sort_unstable();
    assert_eq!(
        functions,
        vec!["function hide(): void", "function show(): void"],
        "{listing}"
    );
    let targets = listing
        .lines()
        .filter(|line| line.starts_with("target "))
        .count();
    assert_eq!(targets, 1, "{listing}");
}

fn tempfile_dir() -> PathBuf {
    let output = Command::new("mktemp")
        .args(["-d", "/tmp/bpq.XXXXXX"])
        .output()
        .unwrap();
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

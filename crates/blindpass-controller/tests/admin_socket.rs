// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::admin_socket::{bind_admin_socket, serve_admin_socket};
use blindpass_controller::store::Store;
use serde_json::Value;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

struct SocketDir(PathBuf);

impl SocketDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-admin-socket-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create socket test directory");
        Self(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("admin.sock")
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn admin_socket_is_private_and_bootstraps_only_once() {
    let directory = SocketDir::new();
    let path = directory.socket();
    let socket = bind_admin_socket(&path).expect("bind local admin socket");
    let permissions = std::fs::metadata(&path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(permissions, 0o600);

    let db = format!(
        "sqlite://{}?mode=rwc",
        directory.0.join("controller.db").display()
    );
    let store = Store::connect(&db)
        .await
        .expect("create bootstrap fixture store");
    let server = tokio::spawn(serve_admin_socket(socket, store.clone()));
    let mut client = UnixStream::connect(&path)
        .await
        .expect("connect local admin socket");
    client
        .write_all(b"{\"command\":\"bootstrap\"}\n")
        .await
        .expect("write command");
    client.shutdown().await.expect("finish command");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response: Value = serde_json::from_slice(&response).expect("bootstrap response is JSON");
    assert_eq!(
        response.get("username").and_then(Value::as_str),
        Some("admin")
    );
    assert!(
        response
            .get("temporary_password")
            .and_then(Value::as_str)
            .is_some()
    );
    assert!(store.has_active_admin().await.expect("bootstrap persisted"));

    let operator_id = store
        .list_local_operators()
        .await
        .expect("list bootstrap operator")[0]
        .id
        .clone();
    let mut reset = UnixStream::connect(&path)
        .await
        .expect("connect password reset request");
    reset
        .write_all(
            format!("{{\"command\":\"reset-password\",\"id\":\"{operator_id}\"}}\n").as_bytes(),
        )
        .await
        .expect("write password reset command");
    reset
        .shutdown()
        .await
        .expect("finish password reset command");
    let mut reset_response = Vec::new();
    reset
        .read_to_end(&mut reset_response)
        .await
        .expect("read password reset response");
    let reset_response: Value =
        serde_json::from_slice(&reset_response).expect("password reset response is JSON");
    assert!(reset_response["temporary_password"].as_str().is_some());

    let mut second = UnixStream::connect(&path)
        .await
        .expect("connect second request");
    second
        .write_all(b"{\"command\":\"bootstrap\"}\n")
        .await
        .expect("write second command");
    second.shutdown().await.expect("finish second command");
    let mut second_response = Vec::new();
    second
        .read_to_end(&mut second_response)
        .await
        .expect("read second response");
    assert!(
        String::from_utf8(second_response)
            .expect("response is utf-8")
            .contains("already_configured")
    );

    assert!(
        matches!(bind_admin_socket(&path), Err(error) if error.kind() == io::ErrorKind::AddrInUse)
    );
    server.abort();
    let _ = server.await;
    assert!(
        !path.exists(),
        "dropping the socket server removes its socket path"
    );
    drop(store);
}

#[tokio::test]
async fn admin_socket_rejects_relative_paths() {
    assert!(bind_admin_socket(std::path::Path::new("admin.sock")).is_err());
}

#[tokio::test]
async fn p06_qf05_stopping_admin_listener_cancels_its_accepted_partial_client() {
    use std::time::Duration;
    let directory = SocketDir::new();
    let path = directory.0.join("admin.sock");
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.0.join("controller.db").display()
    );
    let store = Store::connect(&url).await.unwrap();
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    let bound = bind_admin_socket(&path).unwrap();
    let observer = store.clone();
    let server = tokio::spawn(serve_admin_socket(bound, store));
    let mut stream = UnixStream::connect(&path).await.unwrap();
    stream
        .write_all(b"{\"command\":\"bootstrap-token\"")
        .await
        .unwrap();
    // Observe the exact accepted server FD/path, excluding other parallel
    // tests and an unaccepted connection closed by listener drop.
    tokio::time::timeout(Duration::from_secs(2), async {
        while accepted_admin_clients(&path) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("local client was not accepted");
    server.abort();
    let _ = server.await;
    assert!(!path.exists());
    let _ = stream.write_all(b"}\n").await;
    let mut byte = [0];
    let reply = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await;
    assert!(
        matches!(reply, Ok(Ok(0)) | Ok(Err(_))),
        "accepted child delivered bytes after its admin listener stopped"
    );
    let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bootstrap_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tokens, 0, "stopped admin child created a token");
    pool.close().await;
    observer.close().await;
}

fn accepted_admin_clients(path: &std::path::Path) -> usize {
    let fds: std::collections::HashSet<String> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            std::fs::read_link(entry.ok()?.path())
                .ok()?
                .to_str()
                .map(str::to_owned)
        })
        .collect();
    std::fs::read_to_string("/proc/self/net/unix")
        .unwrap()
        .lines()
        .skip(1)
        .filter(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() > 7
                && fields[5] == "03"
                && fields[7] == path.to_str().unwrap()
                && fds.contains(&format!("socket:[{}]", fields[6]))
        })
        .count()
}

#[tokio::test]
async fn p06_qf05_partial_admin_client_has_the_actual_ten_second_deadline() {
    use std::time::{Duration, Instant};
    let directory = SocketDir::new();
    let path = directory.0.join("admin.sock");
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let bound = bind_admin_socket(&path).unwrap();
    let server = tokio::spawn(serve_admin_socket(bound, store.clone()));
    let mut client = UnixStream::connect(&path).await.unwrap();
    client.write_all(b"{").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while accepted_admin_clients(&path) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let started = Instant::now();
    let mut byte = [0];
    let reply = tokio::time::timeout(Duration::from_secs(12), client.read(&mut byte)).await;
    assert!(
        matches!(reply, Ok(Ok(0)) | Ok(Err(_))),
        "partial admin client exceeded its ten-second deadline"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(9),
        "admin connection closed before its expected lifetime"
    );
    assert_eq!(accepted_admin_clients(&path), 0);
    server.abort();
    let _ = server.await;
    store.close().await;
}

#[tokio::test]
async fn p06_qf05_admin_listener_limits_accepted_children_to_sixty_four() {
    use std::time::Duration;
    let directory = SocketDir::new();
    let path = directory.0.join("admin.sock");
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let bound = bind_admin_socket(&path).unwrap();
    let server = tokio::spawn(serve_admin_socket(bound, store.clone()));
    let mut clients = Vec::new();
    for _ in 0..65 {
        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(b"{").await.unwrap();
        clients.push(client);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let n = accepted_admin_clients(&path);
            assert!(
                n <= 64,
                "admin listener exceeded its sixty-four-child bound"
            );
            if n == 64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepted_admin_clients(&path),
        64,
        "queued sixty-fifth client escaped the admission limit"
    );
    server.abort();
    let _ = server.await;
    for mut client in clients {
        let mut byte = [0];
        let reply = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await;
        assert!(
            matches!(reply, Ok(Ok(0)) | Ok(Err(_))),
            "stopped admin child did not close"
        );
    }
    assert_eq!(accepted_admin_clients(&path), 0);
    store.close().await;
}

#[tokio::test]
async fn recovery_commands_are_refused_unless_the_controller_is_recovering() {
    let directory = SocketDir::new();
    let path = directory.socket();
    let socket = bind_admin_socket(&path).expect("bind local admin socket");
    let db = format!(
        "sqlite://{}?mode=rwc",
        directory.0.join("controller.db").display()
    );
    let store = Store::connect(&db).await.expect("create fixture store");
    let server = tokio::spawn(serve_admin_socket(socket, store.clone()));
    for command in [
        "recovery-status",
        "recovery-review-list",
        "recovery-review-complete",
        "recovery-waive-node",
        "recovery-review-decide",
    ] {
        let mut client = UnixStream::connect(&path).await.expect("connect");
        client
            .write_all(format!("{{\"command\":\"{command}\",\"operator\":\"op\"}}\n").as_bytes())
            .await
            .expect("write command");
        client.shutdown().await.expect("finish command");
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("read");
        let response: Value = serde_json::from_slice(&response).expect("JSON response");
        assert_eq!(
            response.get("error").and_then(Value::as_str),
            Some("recovery_not_active"),
            "{command}"
        );
    }
    server.abort();
}

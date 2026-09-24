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

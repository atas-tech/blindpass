// SPDX-License-Identifier: AGPL-3.0-only

//! Local-only administrative socket used by the CLI for first-run actions.

use crate::routes::auth::hash_api_key;
use crate::store::Store;
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use serde_json::Value;
use serde_json::json;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const MAX_ADMIN_REQUEST_BYTES: usize = 8 * 1024;

pub struct BoundAdminSocket {
    listener: UnixListener,
    path: PathBuf,
}

impl Drop for BoundAdminSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn bind_admin_socket(path: &Path) -> io::Result<BoundAdminSocket> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "admin socket path must be absolute",
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    remove_stale_socket(path)?;
    let listener = UnixListener::bind(path)?;
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(BoundAdminSocket {
        listener,
        path: path.to_owned(),
    })
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "admin socket path is occupied by a non-socket file",
        ));
    }
    match StdUnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "admin socket already has a live listener",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            std::fs::remove_file(path)
        }
        Err(error) => Err(error),
    }
}

pub async fn serve_admin_socket(bound: BoundAdminSocket, store: Store) -> io::Result<()> {
    loop {
        let (stream, _) = bound.listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, store).await;
        });
    }
}

async fn handle_connection(mut stream: UnixStream, store: Store) -> io::Result<()> {
    let mut request = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    let mut complete = false;
    while request.len() <= MAX_ADMIN_REQUEST_BYTES {
        let count = stream.read(&mut byte).await?;
        if count == 0 {
            break;
        }
        if byte[0] == b'\n' {
            complete = true;
            break;
        }
        request.push(byte[0]);
    }

    let response = if request.len() > MAX_ADMIN_REQUEST_BYTES {
        json!({ "error": "request_too_large" })
    } else if !complete || serde_json::from_slice::<serde_json::Value>(&request).is_err() {
        json!({ "error": "invalid_request" })
    } else {
        let body = serde_json::from_slice::<Value>(&request).unwrap_or(Value::Null);
        handle_admin_request(&store, &body).await
    };
    let mut encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    stream.shutdown().await
}

async fn handle_admin_request(store: &Store, body: &Value) -> Value {
    match body.get("command").and_then(Value::as_str) {
        Some("bootstrap") => {
            let username = body
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("admin")
                .trim();
            let display_name = body
                .get("display_name")
                .and_then(Value::as_str)
                .unwrap_or("Blindpass administrator")
                .trim();
            if !valid_account_name(username) || display_name.is_empty() || display_name.len() > 128
            {
                return json!({"error":"invalid_account"});
            }
            let operator_id = random_uuid();
            let password = random_token();
            let password_hash = match hash_api_key(&password) {
                Ok(hash) => hash,
                Err(_) => return json!({"error":"bootstrap_failed"}),
            };
            match store
                .bootstrap_local_operator(&operator_id, username, display_name, &password_hash)
                .await
            {
                Ok(true) => json!({
                    "username":username,
                    "temporary_password":password,
                    "must_change_password":true
                }),
                Ok(false) => json!({"error":"already_configured"}),
                Err(_) => json!({"error":"bootstrap_failed"}),
            }
        }
        Some("bootstrap-token") => {
            let token = random_token();
            let Some(token_hash) = hash_token(&token) else {
                return json!({"error":"bootstrap_token_failed"});
            };
            match store.issue_bootstrap_token(&token_hash, 900).await {
                Ok(true) => json!({"bootstrap_token":token,"expires_in_seconds":900}),
                Ok(false) => json!({"error":"already_configured"}),
                Err(_) => json!({"error":"bootstrap_token_failed"}),
            }
        }
        _ => json!({"error":"unsupported_command"}),
    }
}

fn valid_account_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(&byte))
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(token: &str) -> Option<String> {
    blindpass_core::custody::sha256(token.as_bytes())
        .ok()
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::{bind_admin_socket, serve_admin_socket};
    use crate::store::Store;
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn cli_socket_bootstrap_is_private_and_one_time() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "blindpass-admin-socket-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let socket_path = root.join("admin.sock");
        let database_path = root.join("controller.db");
        let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
        let store = Store::connect(&database_url).await.unwrap();
        let bound = bind_admin_socket(&socket_path).unwrap();
        assert_eq!(
            std::fs::metadata(&socket_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let task = tokio::spawn(serve_admin_socket(bound, store.clone()));

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        stream
            .write_all(
                br#"{"command":"bootstrap","username":"admin"}
"#,
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            response.get("username").and_then(Value::as_str),
            Some("admin")
        );
        assert!(
            response
                .get("temporary_password")
                .and_then(Value::as_str)
                .is_some_and(|value| value.len() >= 40)
        );
        assert!(
            response
                .get("must_change_password")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        );
        assert!(store.has_active_admin().await.unwrap());

        let mut second = UnixStream::connect(&socket_path).await.unwrap();
        second
            .write_all(
                br#"{"command":"bootstrap"}
"#,
            )
            .await
            .unwrap();
        second.shutdown().await.unwrap();
        let mut second_response = Vec::new();
        second.read_to_end(&mut second_response).await.unwrap();
        assert!(
            String::from_utf8(second_response)
                .unwrap()
                .contains("already_configured")
        );

        task.abort();
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}

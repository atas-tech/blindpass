// SPDX-License-Identifier: AGPL-3.0-only

//! Local-only administrative socket used by the CLI for first-run actions.

use crate::owned_transport::{OwnedIo, TransportShutdown};
use crate::recovery_authority::ReviewKey;
use crate::routes::auth::hash_api_key;
use crate::store::{LocalOperator, Store, StoreError};
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use serde_json::Value;
use serde_json::json;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;

const MAX_ADMIN_REQUEST_BYTES: usize = 8 * 1024;
/// Items per `recovery-review-list` response; the CLI reads further pages by offset.
const RECOVERY_LIST_PAGE: usize = 100;

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

const MAX_ADMIN_CONNECTIONS: usize = 64;
const ADMIN_CONNECTION_LIFETIME: Duration = Duration::from_secs(10);

struct StopAdminTransports(Arc<TransportShutdown>);
impl Drop for StopAdminTransports {
    fn drop(&mut self) {
        self.0.stop();
    }
}

pub async fn serve_admin_socket(bound: BoundAdminSocket, store: Store) -> io::Result<()> {
    let shutdown = Arc::new(TransportShutdown::default());
    let _stop = StopAdminTransports(shutdown.clone());
    let mut children = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = children.join_next(), if !children.is_empty() => {},
            incoming = bound.listener.accept(), if children.len() < MAX_ADMIN_CONNECTIONS => {
                let (stream, _) = match incoming {
                    Ok(accepted) => accepted,
                    // Descriptor/memory pressure (for example from an HTTP flood
                    // in the same process) is transient and must not stop the
                    // controller; any other accept failure still does.
                    Err(error) if transient_accept_error(&error) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let store = store.clone();
                let owner = store.ownership_holder().map_err(|_| io::Error::other("controller ownership unavailable"))?;
                let stream = match OwnedIo::new(stream, owner, ADMIN_CONNECTION_LIFETIME, shutdown.clone()) {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                children.spawn(async move {
                    let _ = handle_connection(stream, store).await;
                });
            }
        }
    }
}

fn transient_accept_error(error: &io::Error) -> bool {
    // EINTR, ENFILE, EMFILE, ENOMEM, ENOBUFS, ECONNABORTED, EPROTO
    matches!(
        error.raw_os_error(),
        Some(4 | 23 | 24 | 12 | 105 | 103 | 71)
    ) || matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    )
}

async fn handle_connection(mut stream: OwnedIo<UnixStream>, store: Store) -> io::Result<()> {
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
        Some("reset-password") => {
            // The reference is an operator id or the username the console shows
            // (P07 slice 7): an operator locked out of the only account knows
            // nothing else. `id` is the original field name and stays accepted.
            let Some(reference) = body
                .get("id")
                .or_else(|| body.get("operator"))
                .and_then(Value::as_str)
                .map(str::trim)
            else {
                return json!({"error":"invalid_operator_id"});
            };
            if !valid_account_name(reference) {
                return json!({"error":"invalid_operator_id"});
            }
            let operators = match store.list_local_operators().await {
                Ok(operators) => operators,
                Err(_) => return json!({"error":"reset_password_failed"}),
            };
            let target = match resolve_operator(&operators, reference) {
                Resolved::One(operator) => operator,
                Resolved::None => return json!({"error":"operator_not_found"}),
                Resolved::Ambiguous => return json!({"error":"operator_ambiguous"}),
            };
            if target.disabled_at_ms.is_some() {
                return json!({"error":"operator_disabled"});
            }
            let password = random_token();
            let hash = match hash_api_key(&password) {
                Ok(hash) => hash,
                Err(_) => return json!({"error":"reset_password_failed"}),
            };
            match store.reset_local_operator_password(&target.id, &hash).await {
                Ok(true) => json!({"temporary_password":password,"must_change_password":true}),
                Ok(false) => json!({"error":"operator_not_found"}),
                Err(_) => json!({"error":"reset_password_failed"}),
            }
        }
        Some("operators-list") => {
            let operators = match store.list_local_operators().await {
                Ok(operators) => operators,
                Err(_) => return json!({"error":"operators_list_failed"}),
            };
            let mut rows = Vec::with_capacity(operators.len());
            for operator in &operators {
                let lock = match store.operator_lock_state(&operator.username).await {
                    Ok(lock) => lock,
                    Err(_) => return json!({"error":"operators_list_failed"}),
                };
                // Identity and state only: never a hash, session or token.
                rows.push(json!({
                    "id": operator.id,
                    "username": operator.username,
                    "display_name": operator.display_name,
                    "role": operator.role,
                    "disabled": operator.disabled_at_ms.is_some(),
                    "must_change_password": operator.must_change_password,
                    "account_locked_seconds": lock.account_locked_seconds,
                    "source_locks": lock.source_locks,
                }));
            }
            json!({"operators":rows})
        }
        Some(command) if command.starts_with("recovery-") => {
            recovery_command(store, command, body).await
        }
        _ => json!({"error":"unsupported_command"}),
    }
}

/// Operator review for a restored controller (P06-D30..D32). Metadata only: nothing
/// here reads or returns secret values, and nothing activates the record.
async fn recovery_command(store: &Store, command: &str, body: &Value) -> Value {
    let text = |name: &str| body.get(name).and_then(Value::as_str);
    let Ok(Some(owner)) = store.ownership_holder() else {
        return json!({"error":"recovery_not_active"});
    };
    if !store.recovery_required() || !owner.is_recovering() {
        return json!({"error":"recovery_not_active"});
    }
    let failed = |error: StoreError| match error {
        StoreError::AuthorityFenced => json!({"error":"authority_fenced"}),
        StoreError::InvalidInput(_) => json!({"error":"refused"}),
        error => {
            tracing::warn!(command, error = %error, "recovery review command failed");
            json!({"error":"recovery_failed"})
        }
    };
    match command {
        "recovery-status" => match store.recovery_activation_status(&owner).await {
            Ok(status) => json!(status),
            Err(error) => failed(error),
        },
        "recovery-review-list" => match store.recovery_review_items(&owner).await {
            Ok(items) => {
                let offset = body
                    .get("offset")
                    .and_then(Value::as_u64)
                    .and_then(|offset| usize::try_from(offset).ok())
                    .unwrap_or(0);
                let page: Vec<_> = items.iter().skip(offset).take(RECOVERY_LIST_PAGE).collect();
                json!({"total":items.len(),"offset":offset,"items":page})
            }
            Err(error) => failed(error),
        },
        "recovery-review-decide" => {
            let (Some(category), Some(subject), Some(decision), Some(operator)) = (
                text("category"),
                text("subject_id"),
                text("decision"),
                text("operator"),
            ) else {
                return json!({"error":"invalid_request"});
            };
            let key = ReviewKey {
                category: category.into(),
                subject_id: subject.into(),
                related_id: text("related_id").unwrap_or_default().into(),
            };
            match store
                .decide_recovery_review(
                    &owner,
                    &key,
                    decision,
                    operator,
                    text("note").unwrap_or_default(),
                )
                .await
            {
                Ok(()) => json!({"decided":true}),
                Err(error) => failed(error),
            }
        }
        "recovery-waive-node" => {
            let (Some(node), Some(operator)) = (text("node_id"), text("operator")) else {
                return json!({"error":"invalid_request"});
            };
            match store
                .waive_recovery_node(&owner, node, operator, text("note").unwrap_or_default())
                .await
            {
                Ok(()) => json!({"waived":true}),
                Err(error) => failed(error),
            }
        }
        "recovery-review-complete" => {
            let Some(operator) = text("operator") else {
                return json!({"error":"invalid_request"});
            };
            match store.complete_recovery_review(&owner, operator).await {
                Ok(done) => json!({"completed":true,"summary":done}),
                Err(error) => failed(error),
            }
        }
        _ => json!({"error":"unsupported_command"}),
    }
}

enum Resolved<'a> {
    One(&'a LocalOperator),
    None,
    Ambiguous,
}

/// Operator id first, then the exact username, then a case-insensitive username
/// that matches exactly one operator. Usernames are unique case-sensitively, so
/// two operators may differ only by case; refuse to guess between them.
fn resolve_operator<'a>(operators: &'a [LocalOperator], reference: &str) -> Resolved<'a> {
    if let Some(operator) = operators.iter().find(|operator| operator.id == reference) {
        return Resolved::One(operator);
    }
    if let Some(operator) = operators
        .iter()
        .find(|operator| operator.username == reference)
    {
        return Resolved::One(operator);
    }
    let mut matches = operators
        .iter()
        .filter(|operator| operator.username.eq_ignore_ascii_case(reference));
    match (matches.next(), matches.next()) {
        (Some(operator), None) => Resolved::One(operator),
        (Some(_), Some(_)) => Resolved::Ambiguous,
        (None, _) => Resolved::None,
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
    use super::{bind_admin_socket, handle_admin_request, serve_admin_socket};
    use crate::store::Store;
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn local_password_reset_rotates_password_and_requires_change() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let bootstrap =
            handle_admin_request(&store, &serde_json::json!({"command":"bootstrap"})).await;
        assert!(bootstrap["temporary_password"].as_str().is_some());
        let operator = store.list_local_operators().await.unwrap().remove(0);
        let response = handle_admin_request(
            &store,
            &serde_json::json!({"command":"reset-password","id":operator.id}),
        )
        .await;
        assert!(response["temporary_password"].as_str().is_some());
        let updated = store.list_local_operators().await.unwrap().remove(0);
        assert!(updated.must_change_password);
        assert_ne!(updated.password_hash, operator.password_hash);
        store.close().await;
    }

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

#[cfg(test)]
mod accept_tests {
    use super::transient_accept_error;
    use std::io;

    #[test]
    fn descriptor_pressure_is_transient_but_a_closed_listener_is_not() {
        assert!(transient_accept_error(&io::Error::from_raw_os_error(24)));
        assert!(transient_accept_error(&io::Error::from_raw_os_error(23)));
        assert!(transient_accept_error(&io::Error::from(
            io::ErrorKind::ConnectionAborted
        )));
        assert!(!transient_accept_error(&io::Error::from_raw_os_error(9)));
        assert!(!transient_accept_error(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Root-only administrator revocation transport. Source/browser authority and
//! actual helper/browser cgroup termination remain coordinator requirements.
use crate::private_helper::{connect_until, read_exact_until, wipe_value, write_all_until};
use crate::session_journal::RevokeHandle;
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::secret::SecretBytes;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
const SOCKET: &str = "/run/blindpass-private/revocation.sock";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationError {
    Unavailable,
    Uncertain,
}
pub struct RevocationClient {
    stream: UnixStream,
    resource: crate::BrowserResource,
    operation: String,
    ready_until: u64,
    active: bool,
}
impl std::fmt::Debug for RevocationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevocationClient([administrator])")
    }
}
impl RevocationClient {
    pub fn prepare(
        resource: &crate::BrowserResource,
        operation: &str,
        credential: &SecretBytes,
        deadline: u64,
    ) -> Result<Self, RevocationError> {
        let now = now()?;
        if crate::effective_uid() != 0 || deadline <= now || deadline - now > 120_000 {
            return Err(RevocationError::Unavailable);
        }
        validate_start(resource, operation, credential)?;
        let path = Path::new(SOCKET);
        let before = protected_socket(path)?;
        let stream = connect_until(path, deadline.min(now + 5000))
            .map_err(|_| RevocationError::Unavailable)?;
        crate::os_identity::require_root_peer(&stream).map_err(|_| RevocationError::Unavailable)?;
        if protected_socket(path)? != before {
            return Err(RevocationError::Unavailable);
        }
        Self::prepare_on(stream, resource, operation, credential, deadline)
    }
    /// Successful online preflight is necessary before source delivery. It
    /// expires independently, binds the full recipe/operation and holds its
    /// original private connection. Current signed authority is a separate gate.
    #[must_use]
    pub fn ready_for(&self, resource: &crate::BrowserResource, operation: &str) -> bool {
        self.active
            && self.operation == operation
            && matches!((self.resource.recipe_fingerprint(), resource.recipe_fingerprint()), (Ok(a), Ok(b)) if a == b)
            && now().is_ok_and(|now| now < self.ready_until)
            && channel_alive(&self.stream)
    }
    fn prepare_on(
        stream: UnixStream,
        resource: &crate::BrowserResource,
        operation: &str,
        credential: &SecretBytes,
        deadline: u64,
    ) -> Result<Self, RevocationError> {
        validate_start(resource, operation, credential)?;
        let started = now()?;
        if deadline <= started || deadline - started > 120_000 {
            return Err(RevocationError::Unavailable);
        }
        let mut client = Self {
            stream,
            resource: resource.clone(),
            operation: operation.into(),
            ready_until: 0,
            active: true,
        };
        let profile = resource
            .revocation_profile()
            .ok_or(RevocationError::Unavailable)?;
        client.request(
            object(vec![
                ("type", text("preflight")),
                ("version", Value::Unsigned(1)),
                ("operationId", text(operation)),
                ("configuration", resource.configuration()),
                ("profile", profile.to_value()),
                (
                    "credential",
                    text(
                        std::str::from_utf8(credential.as_bytes())
                            .map_err(|_| RevocationError::Unavailable)?,
                    ),
                ),
                (
                    "deadlineBoottimeMs",
                    Value::Unsigned(deadline.min(started + 5000)),
                ),
            ]),
            "revocation-ready",
            deadline.min(started + 5000),
        )?;
        client.ready_until = deadline.min(now()? + 30_000);
        Ok(client)
    }
    /// Caller must close proxy authority and stop the exact private helper
    /// before logout; this acknowledgement proves only the application request.
    pub fn revoke_session(&mut self, handle: &RevokeHandle) -> Result<(), RevocationError> {
        let profile = self
            .resource
            .revocation_profile()
            .ok_or(RevocationError::Unavailable)?;
        if !profile.accepts_handle(self.resource.account(), handle) {
            return Err(RevocationError::Unavailable);
        }
        let handle = match handle {
            RevokeHandle::Fixture {
                account,
                session_reference,
            } => {
                if session_reference.len() != 32
                    || !session_reference
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(RevocationError::Unavailable);
                }
                object(vec![
                    ("kind", text("fixture")),
                    ("account", text(account)),
                    ("sessionReference", text(session_reference)),
                ])
            }
            RevokeHandle::GrafanaManaged {
                account,
                user_id,
                org_id,
            } => {
                if self
                    .resource
                    .configuration()
                    .get("orgId")
                    .and_then(Value::as_u64)
                    != Some(u64::from(*org_id))
                {
                    return Err(RevocationError::Unavailable);
                }
                object(vec![
                    ("kind", text("grafana-managed")),
                    ("account", text(account)),
                    ("userId", Value::Unsigned(u64::from(*user_id))),
                    ("orgId", Value::Unsigned(u64::from(*org_id))),
                ])
            }
        };
        self.request(
            object(vec![("type", text("revoke-session")), ("handle", handle)]),
            "revoked",
            now()? + 5000,
        )
    }
    /// Recovery without a session handle uses only the prepared fixed account.
    pub fn revoke_account(&mut self) -> Result<(), RevocationError> {
        self.request(
            object(vec![("type", text("revoke-account"))]),
            "revoked",
            now()? + 5000,
        )
    }
    pub fn close(&mut self) -> Result<(), RevocationError> {
        let result = self.request(
            object(vec![("type", text("close"))]),
            "revocation-closed",
            now()? + 5000,
        );
        self.abort();
        result
    }
    fn abort(&mut self) {
        self.active = false;
        self.ready_until = 0;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
    fn request(
        &mut self,
        mut value: Value,
        expected: &str,
        deadline: u64,
    ) -> Result<(), RevocationError> {
        if !self.active {
            wipe_value(&mut value);
            return Err(RevocationError::Unavailable);
        }
        let body = canonicalize_value(&value).map(SecretBytes::new);
        wipe_value(&mut value);
        let result = (|| {
            let body = body.map_err(|_| ())?;
            if body.len() > 16_384 {
                return Err(());
            }
            write_all_until(
                &mut self.stream,
                &(body.len() as u32).to_be_bytes(),
                deadline,
            )?;
            write_all_until(&mut self.stream, body.as_bytes(), deadline)?;
            let mut size = [0; 4];
            read_exact_until(&mut self.stream, &mut size, deadline)?;
            let size = u32::from_be_bytes(size) as usize;
            if !(2..=1024).contains(&size) {
                return Err(());
            }
            let mut bytes = vec![0; size];
            let read = read_exact_until(&mut self.stream, &mut bytes, deadline);
            let protected = SecretBytes::new(bytes);
            read?;
            let value = parse_json(std::str::from_utf8(protected.as_bytes()).map_err(|_| ())?)
                .map_err(|_| ())?;
            if value.as_object().is_none_or(|fields| fields.len() != 1)
                || value.get("type").and_then(Value::as_str) != Some(expected)
            {
                return Err(());
            }
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result.map_err(|_| RevocationError::Uncertain)
    }
}
fn validate_start(
    resource: &crate::BrowserResource,
    operation: &str,
    credential: &SecretBytes,
) -> Result<(), RevocationError> {
    if !(16..=128).contains(&operation.len())
        || !operation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(RevocationError::Unavailable);
    }
    resource
        .revocation_profile()
        .ok_or(RevocationError::Unavailable)?
        .validate_credential(credential)
        .map_err(|_| RevocationError::Unavailable)
}
fn protected_socket(path: &Path) -> Result<(u64, u64), RevocationError> {
    let run = fs::symlink_metadata("/run").map_err(|_| RevocationError::Unavailable)?;
    let parent = fs::symlink_metadata(path.parent().ok_or(RevocationError::Unavailable)?)
        .map_err(|_| RevocationError::Unavailable)?;
    let socket = fs::symlink_metadata(path).map_err(|_| RevocationError::Unavailable)?;
    if !run.is_dir()
        || run.uid() != 0
        || run.mode() & 0o022 != 0
        || !parent.is_dir()
        || parent.uid() != 0
        || parent.gid() != 0
        || parent.mode() & 0o7777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != 0
        || socket.gid() != 0
        || socket.mode() & 0o7777 != 0o600
        || socket.nlink() != 1
    {
        return Err(RevocationError::Unavailable);
    }
    Ok((socket.dev(), socket.ino()))
}
fn now() -> Result<u64, RevocationError> {
    crate::grants::boottime_ms().map_err(|_| RevocationError::Unavailable)
}
fn channel_alive(stream: &UnixStream) -> bool {
    unsafe extern "C" {
        fn recv(fd: i32, buffer: *mut u8, length: usize, flags: i32) -> isize;
    }
    let mut byte = 0;
    // SAFETY: one-byte valid output, retained descriptor; MSG_PEEK|MSG_DONTWAIT
    // reads no bytes and changes no socket options on the shared connection.
    (unsafe { recv(stream.as_raw_fd(), &mut byte, 1, 0x2 | 0x40) }) == -1
        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
}
fn text(value: &str) -> Value {
    Value::String(value.into())
}
fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn resource() -> crate::BrowserResource {
        crate::BrowserResource::from_value(&parse_json(r#"{"resource_id":"report-primary","workload_ids":["workload-a"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","revocation":{"kind":"fixture-admin","credential_unit":"blindpass-session-revoker@.service","credential_name":"fixture-admin"},"configuration":{"kind":"fixture","origin":"https://127.0.0.1:4443","account":"primary","sessionMaxMs":300000}}"#).unwrap()).unwrap()
    }
    fn deadline() -> u64 {
        crate::grants::boottime_ms().unwrap() + 2000
    }
    fn receive(stream: &mut UnixStream) -> Value {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut bytes).unwrap();
        parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap()
    }
    fn reply(stream: &mut UnixStream, body: &[u8]) {
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(body).unwrap();
    }
    #[test]
    fn revocation_client_preflight_binds_exact_recipe_operation_and_private_admin_copy() {
        let (stream, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let request = receive(&mut server);
            assert_eq!(
                request.get("type").and_then(Value::as_str),
                Some("preflight")
            );
            assert_eq!(
                request.get("operationId").and_then(Value::as_str),
                Some("operation_aaaaaaaa")
            );
            assert_eq!(
                request.get("credential").and_then(Value::as_str),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            );
            assert!(request.get("cookies").is_none());
            assert!(request.get("password").is_none());
            reply(&mut server, br#"{"type":"revocation-ready"}"#);
            let mut byte = [0];
            let _ = server.read(&mut byte);
        });
        let result = RevocationClient::prepare_on(
            stream,
            &resource(),
            "operation_aaaaaaaa",
            &SecretBytes::from_slice("a".repeat(64).as_bytes()),
            deadline(),
        );
        assert!(result.is_ok());
        let client = result.unwrap();
        assert!(client.ready_for(&resource(), "operation_aaaaaaaa"));
        assert!(!client.ready_for(&resource(), "operation_bbbbbbbb"));
        assert!(!format!("{client:?}").contains("aaaaaaaa"));
        drop(client);
        worker.join().unwrap();
    }
    #[test]
    fn revocation_client_rejects_duplicate_extra_oversized_and_lost_replies() {
        for response in [
            Some(br#"{"type":"revocation-ready","type":"revocation-ready"}"#.as_slice()),
            Some(br#"{"type":"revocation-ready","cookie":"P05-COOKIE-CANARY"}"#.as_slice()),
            Some(br#"{"type":"revocation-unavailable"}"#.as_slice()),
            Some(b"[]".as_slice()),
            None,
        ] {
            let (stream, mut server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                receive(&mut server);
                if let Some(body) = response {
                    reply(&mut server, body);
                }
            });
            assert!(matches!(
                RevocationClient::prepare_on(
                    stream,
                    &resource(),
                    "operation_aaaaaaaa",
                    &SecretBytes::from_slice("a".repeat(64).as_bytes()),
                    deadline()
                ),
                Err(RevocationError::Uncertain)
            ));
            worker.join().unwrap();
        }
        let (stream, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            receive(&mut server);
            server.write_all(&1025_u32.to_be_bytes()).unwrap();
        });
        assert!(matches!(
            RevocationClient::prepare_on(
                stream,
                &resource(),
                "operation_aaaaaaaa",
                &SecretBytes::from_slice("a".repeat(64).as_bytes()),
                deadline()
            ),
            Err(RevocationError::Uncertain)
        ));
        worker.join().unwrap();
    }
    #[test]
    fn revocation_client_invalid_admin_input_sends_no_bytes() {
        for credential in ["", "short", "ADMIN-CANARY", &"A".repeat(64)] {
            let (stream, mut server) = UnixStream::pair().unwrap();
            assert!(matches!(
                RevocationClient::prepare_on(
                    stream,
                    &resource(),
                    "operation_aaaaaaaa",
                    &SecretBytes::from_slice(credential.as_bytes()),
                    deadline()
                ),
                Err(RevocationError::Unavailable)
            ));
            let mut byte = [0];
            assert_eq!(server.read(&mut byte).unwrap(), 0);
        }
    }
    #[test]
    fn revocation_client_preserves_cleanup_after_source_preflight_expiry_and_checks_handles() {
        let (stream, mut server) = UnixStream::pair().unwrap();
        let (ready, observed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            receive(&mut server);
            reply(&mut server, br#"{"type":"revocation-ready"}"#);
            let next = receive(&mut server);
            assert_eq!(
                next.get("type").and_then(Value::as_str),
                Some("revoke-account")
            );
            reply(&mut server, br#"{"type":"revoked"}"#);
            ready.send(()).unwrap();
            let next = receive(&mut server);
            assert_eq!(next.get("type").and_then(Value::as_str), Some("close"));
            reply(&mut server, br#"{"type":"revocation-closed"}"#);
        });
        let resource = resource();
        let mut client = RevocationClient::prepare_on(
            stream,
            &resource,
            "operation_aaaaaaaa",
            &SecretBytes::from_slice("a".repeat(64).as_bytes()),
            deadline(),
        )
        .unwrap();
        let mut changed = resource.to_value();
        if let Value::Object(fields) = &mut changed.get_mut_for_test("revocation") {
            fields
                .iter_mut()
                .find(|(name, _)| name == "credential_name")
                .unwrap()
                .1 = Value::String("other-admin".into());
        }
        assert!(!client.ready_for(
            &crate::BrowserResource::from_value(&changed).unwrap(),
            "operation_aaaaaaaa"
        ));
        assert_eq!(
            client.revoke_session(&RevokeHandle::Fixture {
                account: "isolation".into(),
                session_reference: "a".repeat(32)
            }),
            Err(RevocationError::Unavailable)
        );
        client.ready_until = 0;
        assert!(!client.ready_for(&resource, "operation_aaaaaaaa"));
        client.revoke_account().unwrap();
        observed.recv().unwrap();
        client.close().unwrap();
        assert!(!client.ready_for(&resource, "operation_aaaaaaaa"));
        worker.join().unwrap();
    }
    #[test]
    fn revocation_client_lost_ready_connection_cannot_authorize_source() {
        let (stream, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            receive(&mut server);
            reply(&mut server, br#"{"type":"revocation-ready"}"#);
        });
        let client = RevocationClient::prepare_on(
            stream,
            &resource(),
            "operation_aaaaaaaa",
            &SecretBytes::from_slice("a".repeat(64).as_bytes()),
            deadline(),
        )
        .unwrap();
        worker.join().unwrap();
        assert!(!client.ready_for(&resource(), "operation_aaaaaaaa"));
    }
    trait FieldMut {
        fn get_mut_for_test(&mut self, key: &str) -> &mut Value;
    }
    impl FieldMut for Value {
        fn get_mut_for_test(&mut self, key: &str) -> &mut Value {
            let Value::Object(fields) = self else {
                panic!("object")
            };
            &mut fields.iter_mut().find(|(name, _)| name == key).unwrap().1
        }
    }
}

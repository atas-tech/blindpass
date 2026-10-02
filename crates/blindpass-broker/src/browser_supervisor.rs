// SPDX-License-Identifier: AGPL-3.0-only
//! Fixed private Root supervisor client. This transport grants no workload
//! authority; kernel/profile/journal/current-authority gates belong to dispatch.
use crate::private_helper::{connect_until, read_exact_until, wipe_value, write_all_until};
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::secret::SecretBytes;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

const SOCKET: &str = "/run/blindpass-private/supervisor.sock";
const MAX_INPUT: usize = 65_536;
const MAX_REPLY: usize = 1_024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorError {
    Unavailable,
    Uncertain,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connected,
    Prepared,
    Proved,
    Imported,
    Ready,
    Closed,
}
pub struct PreparedRuntimeHint {
    pub(crate) pid: u32,
    pub(crate) invocation: String,
    pub(crate) devtools_path: String,
}
impl PreparedRuntimeHint {
    /// Protected discovery metadata only. Never authorize a process, cgroup or
    /// cookie import from these worker-supplied fields.
    #[must_use]
    pub fn discovery_hint(&self) -> (u32, &str, &str) {
        (self.pid, &self.invocation, &self.devtools_path)
    }
}
impl std::fmt::Debug for PreparedRuntimeHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRuntimeHint([private, not authority])")
    }
}
pub struct SupervisorClient {
    stream: UnixStream,
    deadline: u64,
    phase: Phase,
    operation: Option<String>,
    session_deadline: Option<u64>,
    recipe_fingerprint: Option<String>,
}
impl std::fmt::Debug for SupervisorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SupervisorClient([private])")
    }
}
impl SupervisorClient {
    /// Fixed Root activation path. Root listener credentials establish trusted
    /// transport only, not the non-root namespace browser's kernel identity.
    pub fn connect(deadline: u64) -> Result<Self, SupervisorError> {
        let result = (|| {
            let now = crate::grants::boottime_ms().map_err(|_| ())?;
            if crate::effective_uid() != 0 || deadline <= now || deadline - now > 120_000 {
                return Err(());
            }
            let path = Path::new(SOCKET);
            let before = protected_socket(path)?;
            let stream = connect_until(path, deadline.min(now + 5_000))?;
            crate::os_identity::require_root_peer(&stream).map_err(|_| ())?;
            if protected_socket(path)? != before {
                return Err(());
            }
            Ok(Self {
                stream,
                deadline,
                phase: Phase::Connected,
                operation: None,
                session_deadline: None,
                recipe_fingerprint: None,
            })
        })();
        result.map_err(|()| SupervisorError::Unavailable)
    }
    pub fn prepare(
        &mut self,
        resource: &crate::BrowserResource,
        operation: &str,
    ) -> Result<PreparedRuntimeHint, SupervisorError> {
        if self.phase != Phase::Connected || !opaque(operation) {
            return Err(SupervisorError::Unavailable);
        }
        let reply = self.send_value(
            object(vec![
                ("type", text("start")),
                ("version", Value::Unsigned(1)),
                ("operationId", text(operation)),
                ("configuration", resource.configuration()),
                ("deadlineBoottimeMs", Value::Unsigned(self.deadline)),
            ]),
            "prepared",
        )?;
        self.phase = Phase::Prepared;
        self.operation = Some(operation.into());
        self.recipe_fingerprint = Some(
            resource
                .recipe_fingerprint()
                .map_err(|_| SupervisorError::Uncertain)?,
        );
        Ok(PreparedRuntimeHint {
            pid: u32::try_from(
                reply
                    .get("pid")
                    .and_then(Value::as_u64)
                    .ok_or(SupervisorError::Uncertain)?,
            )
            .map_err(|_| SupervisorError::Uncertain)?,
            invocation: reply
                .get("invocation")
                .and_then(Value::as_str)
                .ok_or(SupervisorError::Uncertain)?
                .into(),
            devtools_path: reply
                .get("devtoolsPath")
                .and_then(Value::as_str)
                .ok_or(SupervisorError::Uncertain)?
                .into(),
        })
    }
    /// Only a broker-created reverse ticket belongs here; the acknowledgement
    /// still requires ticket.wait() and independent profile/journal checks.
    pub fn prove(&mut self, challenge: &SecretBytes) -> Result<(), SupervisorError> {
        if self.phase != Phase::Prepared {
            return Err(SupervisorError::Unavailable);
        }
        let challenge =
            std::str::from_utf8(challenge.as_bytes()).map_err(|_| SupervisorError::Unavailable)?;
        if !hex(challenge, 64) {
            return Err(SupervisorError::Unavailable);
        }
        self.send_value(
            object(vec![
                ("type", text("prove")),
                ("version", Value::Unsigned(1)),
                ("challenge", text(challenge)),
            ]),
            "identity-proved",
        )?;
        self.phase = Phase::Proved;
        Ok(())
    }
    pub fn import(
        &mut self,
        session: &crate::ApprovedSession,
        deadline: u64,
    ) -> Result<(), SupervisorError> {
        let now = crate::grants::boottime_ms().map_err(|_| SupervisorError::Unavailable)?;
        if self.phase != Phase::Proved
            || deadline <= now
            || deadline - now > 1_800_000
            || self.recipe_fingerprint.as_deref() != Some(session.recipe_fingerprint.as_str())
        {
            return Err(SupervisorError::Unavailable);
        }
        let protected = session
            .cookie_import()
            .map_err(|_| SupervisorError::Uncertain)?;
        let cookies = parse_json(
            std::str::from_utf8(protected.as_bytes()).map_err(|_| SupervisorError::Uncertain)?,
        )
        .map_err(|_| SupervisorError::Uncertain)?;
        self.send_value(
            object(vec![
                ("type", text("import")),
                (
                    "originalDeadlineMs",
                    Value::Unsigned(session.original_deadline_ms()),
                ),
                ("sessionDeadlineBoottimeMs", Value::Unsigned(deadline)),
                ("cookies", cookies),
            ]),
            "imported",
        )?;
        self.session_deadline = Some(deadline);
        self.phase = Phase::Imported;
        Ok(())
    }
    pub fn publish(&mut self) -> Result<String, SupervisorError> {
        if self.phase != Phase::Imported {
            return Err(SupervisorError::Unavailable);
        }
        let expected = format!(
            "ctx_{}",
            operation_hash(
                self.operation
                    .as_deref()
                    .ok_or(SupervisorError::Uncertain)?
            )?
        );
        let reply = self.send_value(object(vec![("type", text("publish"))]), "published")?;
        if reply.get("contextHandle").and_then(Value::as_str) != Some(expected.as_str()) {
            self.abort();
            return Err(SupervisorError::Uncertain);
        }
        self.phase = Phase::Ready;
        self.deadline = self.session_deadline.ok_or(SupervisorError::Uncertain)?;
        Ok(expected)
    }
    /// Ready has no unsolicited successful messages. EOF or any private failure
    /// reply removes readiness; Root must still reconcile website and cgroups.
    pub fn check_ready(&mut self) -> Result<(), SupervisorError> {
        if self.phase != Phase::Ready
            || crate::grants::boottime_ms().map_err(|_| SupervisorError::Uncertain)?
                >= self.deadline
        {
            return Err(SupervisorError::Uncertain);
        }
        self.stream
            .set_nonblocking(true)
            .map_err(|_| SupervisorError::Uncertain)?;
        let read = self.stream.read(&mut [0]);
        self.stream
            .set_nonblocking(false)
            .map_err(|_| SupervisorError::Uncertain)?;
        if read.is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock) {
            Ok(())
        } else {
            self.abort();
            Err(SupervisorError::Uncertain)
        }
    }
    /// A private worker acknowledgement is never website/cgroup cleanup proof.
    pub fn stop(&mut self) -> Result<(), SupervisorError> {
        if self.phase == Phase::Closed {
            return Err(SupervisorError::Uncertain);
        }
        self.deadline = crate::grants::boottime_ms()
            .map_err(|_| SupervisorError::Uncertain)?
            .checked_add(5_000)
            .ok_or(SupervisorError::Uncertain)?;
        let result = self
            .send_value(object(vec![("type", text("stop"))]), "stopped")
            .map(|_| ());
        self.abort();
        result
    }
    fn send_value(&mut self, mut value: Value, expected: &str) -> Result<Value, SupervisorError> {
        let body = canonicalize_value(&value).map(SecretBytes::new);
        wipe_value(&mut value);
        self.request(
            body.map_err(|_| SupervisorError::Uncertain)?.as_bytes(),
            expected,
        )
    }
    fn request(&mut self, body: &[u8], expected: &str) -> Result<Value, SupervisorError> {
        if self.phase == Phase::Closed || body.is_empty() || body.len() > MAX_INPUT {
            return Err(SupervisorError::Unavailable);
        }
        let result = (|| {
            write_all_until(
                &mut self.stream,
                &(body.len() as u32).to_be_bytes(),
                self.deadline,
            )?;
            write_all_until(&mut self.stream, body, self.deadline)?;
            let mut length = [0; 4];
            read_exact_until(&mut self.stream, &mut length, self.deadline)?;
            let length = u32::from_be_bytes(length) as usize;
            if !(2..=MAX_REPLY).contains(&length) {
                return Err(());
            }
            let mut body = vec![0; length];
            let read = read_exact_until(&mut self.stream, &mut body, self.deadline);
            let protected = SecretBytes::new(body);
            read?;
            let mut value = parse_json(std::str::from_utf8(protected.as_bytes()).map_err(|_| ())?)
                .map_err(|_| ())?;
            if !valid_reply(&value, expected) {
                wipe_value(&mut value);
                return Err(());
            }
            Ok(value)
        })();
        result.map_err(|()| {
            self.abort();
            SupervisorError::Uncertain
        })
    }
    fn abort(&mut self) {
        self.phase = Phase::Closed;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
impl Drop for SupervisorClient {
    fn drop(&mut self) {
        self.abort();
    }
}
fn protected_socket(path: &Path) -> Result<(u64, u64), ()> {
    let parent = fs::symlink_metadata(path.parent().ok_or(())?).map_err(|_| ())?;
    let socket = fs::symlink_metadata(path).map_err(|_| ())?;
    if !parent.is_dir()
        || parent.uid() != 0
        || parent.gid() != 0
        || parent.mode() & 0o7777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != 0
        || socket.gid() != 0
        || socket.mode() & 0o7777 != 0o600
        || socket.nlink() != 1
    {
        return Err(());
    }
    Ok((socket.dev(), socket.ino()))
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
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn opaque(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
fn operation_hash(operation: &str) -> Result<String, SupervisorError> {
    if !opaque(operation) {
        return Err(SupervisorError::Unavailable);
    }
    let digest = blindpass_core::custody::sha256(operation.as_bytes())
        .map_err(|_| SupervisorError::Unavailable)?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
pub fn backend_path(operation: &str) -> Result<std::path::PathBuf, SupervisorError> {
    Ok(format!(
        "/run/blindpass-backends/{}/cdp.sock",
        operation_hash(operation)?
    )
    .into())
}
fn valid_reply(value: &Value, expected: &str) -> bool {
    let keys: &[&str] = match expected {
        "prepared" => &["type", "version", "pid", "invocation", "devtoolsPath"],
        "published" => &["type", "contextHandle"],
        "identity-proved" | "imported" | "stopped" => &["type"],
        _ => return false,
    };
    if !value.as_object().is_some_and(|fields| {
        fields.len() == keys.len() && fields.iter().all(|(key, _)| keys.contains(&key.as_str()))
    }) || value.get("type").and_then(Value::as_str) != Some(expected)
    {
        return false;
    }
    if expected == "prepared" {
        let Some(invocation) = value.get("invocation").and_then(Value::as_str) else {
            return false;
        };
        let Some(path) = value.get("devtoolsPath").and_then(Value::as_str) else {
            return false;
        };
        value.get("version").and_then(Value::as_u64) == Some(1)
            && value
                .get("pid")
                .and_then(Value::as_u64)
                .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok())
            && hex(invocation, 32)
            && path.strip_prefix("/devtools/browser/").is_some_and(|tail| {
                tail.len() == 36
                    && tail.bytes().all(|byte| {
                        byte == b'-' || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    })
            })
    } else if expected == "published" {
        value
            .get("contextHandle")
            .and_then(Value::as_str)
            .and_then(|handle| handle.strip_prefix("ctx_"))
            .is_some_and(|tail| hex(tail, 64))
    } else {
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;
    fn client(stream: UnixStream) -> SupervisorClient {
        SupervisorClient {
            stream,
            deadline: crate::grants::boottime_ms().unwrap() + 5_000,
            phase: Phase::Connected,
            operation: None,
            session_deadline: None,
            recipe_fingerprint: None,
        }
    }
    #[test]
    fn supervisor_reply_metadata_is_strict_and_never_a_process_authority() {
        let good=parse_json(r#"{"type":"prepared","version":1,"pid":77,"invocation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","devtoolsPath":"/devtools/browser/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#).unwrap();
        assert!(valid_reply(&good, "prepared"));
        for (key, value) in [
            ("pid", Value::Unsigned(0)),
            ("pid", Value::Unsigned(u64::MAX)),
            ("invocation", text("claimed")),
            ("devtoolsPath", text("/current?P05-PRIVATE-CANARY")),
            ("uid", Value::Unsigned(0)),
        ] {
            let mut input = good.clone();
            let Value::Object(fields) = &mut input else {
                unreachable!()
            };
            fields.retain(|(name, _)| name != key);
            fields.push((key.into(), value));
            assert!(!valid_reply(&input, "prepared"));
        }
    }
    #[test]
    fn supervisor_path_and_phase_failures_cannot_select_a_target_or_publish() {
        let (stream, _server) = UnixStream::pair().unwrap();
        let mut client = client(stream);
        assert_eq!(client.publish(), Err(SupervisorError::Unavailable));
        assert_eq!(
            client.prove(&SecretBytes::from_slice(&[b'a'; 64])),
            Err(SupervisorError::Unavailable)
        );
        for input in [
            "",
            "../cookie",
            "/tmp/model.sock",
            "https://model.invalid",
            &"x".repeat(129),
        ] {
            assert_eq!(backend_path(input), Err(SupervisorError::Unavailable));
        }
        let path = backend_path("p05_outside_supervisor_probe").unwrap();
        assert!(path.starts_with("/run/blindpass-backends"));
        assert!(path.as_os_str().len() < 108);
        assert!(!format!("{client:?}").contains("supervisor.sock"));
    }
    #[test]
    fn supervisor_ready_channel_loss_removes_transport_readiness_without_cleanup_claim() {
        let (stream, server) = UnixStream::pair().unwrap();
        let mut client = client(stream);
        client.phase = Phase::Ready;
        assert_eq!(client.check_ready(), Ok(()));
        drop(server);
        assert_eq!(client.check_ready(), Err(SupervisorError::Uncertain));
        assert!(client.phase == Phase::Closed);
        assert_eq!(client.stop(), Err(SupervisorError::Uncertain));
    }
    #[test]
    fn supervisor_import_cannot_mix_a_session_validated_for_another_source_recipe() {
        let value=parse_json(r#"{"resource_id":"report-primary","workload_ids":["p05-agent"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","configuration":{"kind":"fixture","origin":"https://127.0.0.1:4443","account":"primary","sessionMaxMs":300000}}"#).unwrap();
        let original = crate::BrowserResource::from_value(&value).unwrap();
        let mut changed = value.clone();
        let Value::Object(fields) = &mut changed else {
            unreachable!()
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "credential_name")
            .unwrap()
            .1 = text("other-password");
        let other = crate::BrowserResource::from_value(&changed).unwrap();
        let session=other.validate_session(SecretBytes::from_slice(br#"{"status":"authenticated","originalDeadlineMs":101000,"revokeHandle":{"kind":"fixture","account":"primary","sessionReference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"cookies":[{"name":"__Host-bp-fixture","value":"P05-PRIVATE-COOKIE-CANARY","domain":"127.0.0.1","path":"/","secure":true,"httpOnly":true,"sameSite":"Strict","expires":101}]}"#),1000).unwrap();
        let (stream, mut server) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let mut client = client(stream);
        client.phase = Phase::Proved;
        // The client is prepared for the original full recipe. Same origin and
        // account are insufficient when its Root source mapping differs.
        client.recipe_fingerprint = Some(original.recipe_fingerprint().unwrap());
        client.deadline = crate::grants::boottime_ms().unwrap() + 25;
        assert_eq!(
            client.import(&session, crate::grants::boottime_ms().unwrap() + 50_000),
            Err(SupervisorError::Unavailable)
        );
        let read = server.read(&mut [0]);
        assert!(read.is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock));
    }
    fn run(body: &[u8], response: Vec<u8>, pause: Duration) -> Result<Value, SupervisorError> {
        let (client, mut server) = UnixStream::pair().unwrap();
        let deadline = crate::grants::boottime_ms().unwrap() + 100;
        let reply = std::thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut length = [0; 4];
            if server.read_exact(&mut length).is_err() {
                return;
            }
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            server.read_exact(&mut request).unwrap();
            assert_eq!(request, br#"{"type":"stop"}"#);
            std::thread::sleep(pause);
            let _ = server.write_all(&response);
        });
        let result = SupervisorClient {
            stream: client,
            deadline,
            phase: Phase::Connected,
            operation: None,
            session_deadline: None,
            recipe_fingerprint: None,
        }
        .request(body, "stopped");
        reply.join().unwrap();
        result
    }
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut result = (body.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(body);
        result
    }
    #[test]
    fn supervisor_private_frame_roundtrip_has_no_eof_requirement() {
        assert!(
            run(
                br#"{"type":"stop"}"#,
                frame(br#"{"type":"stopped"}"#),
                Duration::ZERO
            )
            .is_ok()
        );
    }
    #[test]
    fn supervisor_rejects_duplicates_nested_private_errors_wrong_reply_and_oversize() {
        for body in [
            br#"{"type":"stopped","type":"prepared"}"#.as_slice(),
            br#"{"type":"stopped","cause":"P05-PRIVATE-CANARY"}"#,
            br#"{"type":"published"}"#,
            &[0xff],
            br#"{"type":"uncertain"}"#,
        ] {
            let result = run(br#"{"type":"stop"}"#, frame(body), Duration::ZERO);
            assert_eq!(result, Err(SupervisorError::Uncertain));
            assert!(!format!("{result:?}").contains("CANARY"));
        }
        assert_eq!(
            run(
                br#"{"type":"stop"}"#,
                1025u32.to_be_bytes().to_vec(),
                Duration::ZERO
            ),
            Err(SupervisorError::Uncertain)
        );
    }
    #[test]
    fn supervisor_stalled_partial_frame_obeys_original_boottime_budget() {
        assert_eq!(
            run(br#"{"type":"stop"}"#, vec![0], Duration::from_millis(150)),
            Err(SupervisorError::Uncertain)
        );
    }
}

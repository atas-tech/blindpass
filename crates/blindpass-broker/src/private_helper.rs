// SPDX-License-Identifier: AGPL-3.0-only

//! Protected, bounded broker-to-helper transport. This is not workload authority
//! or a model-facing API; session bytes are delivered only to a trusted importer.

use blindpass_core::canon::{Value, parse_json};
use blindpass_core::secret::SecretBytes;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SOCKET_PATH: &str = "/run/blindpass-private/login.sock";
const MAX_BODY: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperStatus {
    Unavailable,
    Uncertain,
    AuthenticationFailed,
    LoginFailed,
    TimedOut,
    UnsupportedAuthentication,
    InvalidConfiguration,
    BindingMismatch,
    UnsafeConfiguration,
    InvalidRequest,
}
impl HelperStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Uncertain => "uncertain",
            Self::AuthenticationFailed => "authentication_failed",
            Self::LoginFailed => "login_failed",
            Self::TimedOut => "timed_out",
            Self::UnsupportedAuthentication => "unsupported_authentication",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::BindingMismatch => "binding_mismatch",
            Self::UnsafeConfiguration => "unsafe_configuration",
            Self::InvalidRequest => "invalid_request",
        }
    }
}
#[derive(Debug)]
pub enum HelperReply {
    Status(HelperStatus),
    /// Raw protected envelope; the trusted importer MUST validate cookie scope,
    /// original deadline and revoke binding before any workload import.
    Session(SecretBytes),
}

/// Connect and prove the actual activated helper BEFORE any source bytes are
/// sent. The coordinator supplies only trusted dedicated-user configuration.
/// A systemd listener's Root credentials never prove the helper's identity.
pub fn begin_private_login(
    book: &std::sync::Arc<crate::runtime_identity::RuntimeIdentityBook>,
    helper_uid: u32,
    excluded_uids: &[u32],
    deadline: u64,
) -> Result<VerifiedPrivateHelper, HelperStatus> {
    let maximum = deadline_after(Duration::from_secs(60)).map_err(|_| HelperStatus::Unavailable)?;
    let deadline = deadline.min(maximum);
    let proof_deadline = deadline
        .min(deadline_after(Duration::from_secs(5)).map_err(|_| HelperStatus::Unavailable)?);
    let binding =
        crate::runtime_identity::RuntimeBinding::private_helper(helper_uid, excluded_uids)
            .map_err(|_| HelperStatus::Unavailable)?;
    let ticket = book
        .register(binding, proof_deadline)
        .map_err(|_| HelperStatus::Unavailable)?;
    let path = Path::new(SOCKET_PATH);
    let connect = || -> Result<UnixStream, ()> {
        let directory = fs::symlink_metadata(path.parent().ok_or(())?).map_err(|_| ())?;
        let socket = fs::symlink_metadata(path).map_err(|_| ())?;
        if !directory.is_dir()
            || directory.uid() != 0
            || directory.mode() & 0o7777 != 0o700
            || !socket.file_type().is_socket()
            || socket.uid() != 0
            || socket.mode() & 0o7777 != 0o600
            || socket.nlink() != 1
        {
            return Err(());
        }
        let stream = connect_until(path, proof_deadline)?;
        crate::os_identity::require_root_peer(&stream).map_err(|_| ())?;
        Ok(stream)
    };
    let mut stream = connect().map_err(|_| HelperStatus::Unavailable)?;
    let challenge = std::str::from_utf8(ticket.challenge().as_bytes())
        .map_err(|_| HelperStatus::Unavailable)?;
    let control =
        SecretBytes::new(format!("{{\"version\":2,\"challenge\":\"{challenge}\"}}").into_bytes());
    write_all_until(
        &mut stream,
        &(control.len() as u32).to_be_bytes(),
        proof_deadline,
    )
    .and_then(|()| write_all_until(&mut stream, control.as_bytes(), proof_deadline))
    .map_err(|_| HelperStatus::Unavailable)?;
    drop(control);
    let runtime = ticket.wait().map_err(|_| HelperStatus::Unavailable)?;
    Ok(VerifiedPrivateHelper {
        stream,
        runtime,
        deadline,
    })
}
/// A held kernel proof plus the same private connection which received its
/// challenge. Fields are private: callers cannot forge proof from JSON metadata.
pub struct VerifiedPrivateHelper {
    stream: UnixStream,
    runtime: crate::runtime_identity::VerifiedRuntime,
    deadline: u64,
}
impl std::fmt::Debug for VerifiedPrivateHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedPrivateHelper([kernel-bound])")
    }
}
impl VerifiedPrivateHelper {
    #[must_use]
    pub fn identity(&self) -> &blindpass_core::identity::PeerIdentity {
        self.runtime.identity()
    }
    /// The journal write is mandatory and precedes every source write. This
    /// consumes the connection; failed persistence/liveness cannot be retried
    /// with a new helper under the same operation.
    #[must_use]
    pub fn request(
        self,
        job: &SecretBytes,
        journal: &mut crate::session_journal::SessionJournal,
        operation: &str,
        trusted_time_ms: u64,
        deadline: u64,
    ) -> HelperReply {
        self.request_guarded(job, journal, operation, trusted_time_ms, deadline, || true)
    }
    /// Recheck live administrator/current workload authority after durable
    /// helper identity and immediately before source writes. Root embedding
    /// callers of `request` still own their own authorization gates.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Keep the durable identity and immediate source authorization gates explicit.
    pub fn request_guarded<F: FnOnce() -> bool>(
        self,
        job: &SecretBytes,
        journal: &mut crate::session_journal::SessionJournal,
        operation: &str,
        trusted_time_ms: u64,
        deadline: u64,
        authorize: F,
    ) -> HelperReply {
        let recorded = match self.record(journal, operation, trusted_time_ms, deadline) {
            Ok(recorded) => recorded,
            Err(status) => return HelperReply::Status(status),
        };
        if !authorize() {
            return HelperReply::Status(HelperStatus::Unavailable);
        }
        recorded.request_guarded(job, || true, || true)
    }
    /// Fsync the exact proved helper identity, then detach its one-use channel.
    /// The returned transport borrows no journal and retains its lifetime lock.
    pub fn record(
        mut self,
        journal: &mut crate::session_journal::SessionJournal,
        operation: &str,
        trusted_time_ms: u64,
        deadline: u64,
    ) -> Result<JournaledPrivateHelper, HelperStatus> {
        self.deadline = self.deadline.min(deadline);
        self.runtime
            .ensure_alive()
            .map_err(|_| HelperStatus::Unavailable)?;
        remaining(self.deadline).map_err(|_| HelperStatus::Unavailable)?;
        let peer = self.runtime.identity();
        let unit = peer.unit.as_deref().ok_or(HelperStatus::Unavailable)?;
        let invocation = peer
            .invocation_id
            .as_deref()
            .ok_or(HelperStatus::Unavailable)?;
        journal
            .record_helper(operation, unit, invocation, trusted_time_ms)
            .map_err(|_| HelperStatus::Unavailable)?;
        let permit = journal
            .helper_source_permit(operation, unit, invocation)
            .map_err(|_| HelperStatus::Unavailable)?;
        self.runtime
            .ensure_alive()
            .map_err(|_| HelperStatus::Unavailable)?;
        remaining(self.deadline).map_err(|_| HelperStatus::Unavailable)?;
        Ok(JournaledPrivateHelper {
            helper: self,
            permit,
        })
    }
}
/// Sealed source channel: actual held kernel proof plus fsynced exact helper
/// identity. Moving this to a worker thread retains no mutable journal borrow.
pub struct JournaledPrivateHelper {
    helper: VerifiedPrivateHelper,
    permit: crate::session_journal::HelperSourcePermit,
}
impl std::fmt::Debug for JournaledPrivateHelper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JournaledPrivateHelper([protected, single-use])")
    }
}
impl JournaledPrivateHelper {
    #[must_use]
    pub fn identity(&self) -> &blindpass_core::identity::PeerIdentity {
        self.helper.identity()
    }
    /// Source authorization remains fresh throughout writes. The independent
    /// runtime authority is checked throughout response polls, without renewing
    /// a short administrator preflight window after source was already sent.
    #[must_use]
    pub fn request_guarded<S: Fn() -> bool, R: Fn() -> bool>(
        mut self,
        job: &SecretBytes,
        source_authority: S,
        runtime_authority: R,
    ) -> HelperReply {
        let valid = || self.permit.allows_source() && self.helper.runtime.ensure_alive().is_ok();
        if !valid() || !source_authority() {
            return HelperReply::Status(HelperStatus::Unavailable);
        }
        exchange_guarded(
            &mut self.helper.stream,
            job,
            self.helper.deadline,
            || valid() && source_authority(),
            || {
                self.permit.allows_source()
                    && self.helper.runtime.book_is_alive()
                    && runtime_authority()
            },
        )
    }
}

#[repr(C)]
struct UnixAddress {
    family: u16,
    path: [u8; 108],
}
unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn connect(fd: i32, address: *const UnixAddress, length: u32) -> i32;
    #[cfg(test)]
    fn listen(fd: i32, backlog: i32) -> i32;
}
fn deadline_after(budget: Duration) -> Result<u64, ()> {
    crate::grants::boottime_ms()
        .map_err(|_| ())?
        .checked_add(u64::try_from(budget.as_millis()).map_err(|_| ())?)
        .ok_or(())
}
fn remaining_at(deadline: u64, now: u64) -> Result<Duration, ()> {
    deadline
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .map(Duration::from_millis)
        .ok_or(())
}
fn remaining(deadline: u64) -> Result<Duration, ()> {
    remaining_at(deadline, crate::grants::boottime_ms().map_err(|_| ())?)
}
fn io_window(deadline: u64) -> Result<Duration, ()> {
    // Socket timeouts exclude suspend. Recheck CLOCK_BOOTTIME at least every
    // 250ms of runnable time and after each successful read, including EOF.
    Ok(remaining(deadline)?.min(Duration::from_millis(250)))
}
fn retryable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}
pub(crate) fn connect_until(path: &Path, deadline: u64) -> Result<UnixStream, ()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(());
    }
    let mut address = UnixAddress {
        family: 1,
        path: [0; 108],
    };
    address.path[..bytes.len()].copy_from_slice(bytes);
    // Linux AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC. The owned stream closes the fd
    // on every error. SO_SNDTIMEO is set BEFORE connect, bounding backlog waits.
    let fd = unsafe { socket(1, 1 | 0x80000, 0) };
    if fd < 0 {
        return Err(());
    }
    // SAFETY: socket returned a new owned descriptor, adopted exactly once.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream
        .set_write_timeout(Some(io_window(deadline)?))
        .map_err(|_| ())?;
    // SAFETY: repr(C) sockaddr_un stays live with a NUL-terminated bounded path.
    if unsafe {
        connect(
            stream.as_raw_fd(),
            &raw const address,
            (2 + bytes.len() + 1) as u32,
        )
    } != 0
    {
        return Err(());
    }
    remaining(deadline)?;
    Ok(stream)
}
#[cfg(test)]
fn exchange(stream: &mut UnixStream, job: &SecretBytes, deadline: u64) -> HelperReply {
    exchange_guarded(stream, job, deadline, || true, || true)
}
fn exchange_guarded<S: Fn() -> bool, R: Fn() -> bool>(
    stream: &mut UnixStream,
    job: &SecretBytes,
    deadline: u64,
    source_authority: S,
    runtime_authority: R,
) -> HelperReply {
    let mut transact = || -> Result<SecretBytes, ()> {
        if job.is_empty() || job.len() > MAX_BODY {
            return Err(());
        }
        write_all_guarded(
            stream,
            &(job.len() as u32).to_be_bytes(),
            deadline,
            &source_authority,
        )?;
        write_all_guarded(stream, job.as_bytes(), deadline, &source_authority)?;
        stream.shutdown(std::net::Shutdown::Write).map_err(|_| ())?;
        let mut size = [0; 4];
        read_exact_guarded(stream, &mut size, deadline, &runtime_authority)?;
        let length = u32::from_be_bytes(size) as usize;
        if !(2..=MAX_BODY).contains(&length) {
            return Err(());
        }
        let mut body = vec![0; length];
        if let Err(()) = read_exact_guarded(stream, &mut body, deadline, &runtime_authority) {
            blindpass_core::secret::wipe(&mut body);
            return Err(());
        }
        let secret = SecretBytes::new(body);
        if read_guarded(stream, &mut [0], deadline, &runtime_authority)? != 0 {
            return Err(());
        }
        Ok(secret)
    };
    match transact() {
        Ok(secret) => classify(secret),
        Err(()) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            HelperReply::Status(HelperStatus::Uncertain)
        }
    }
}
pub(crate) fn write_all_until(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: u64,
) -> Result<(), ()> {
    write_all_guarded(stream, bytes, deadline, &|| true)
}
fn write_all_guarded<F: Fn() -> bool>(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: u64,
    authorize: &F,
) -> Result<(), ()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if !authorize() {
            return Err(());
        }
        stream
            .set_write_timeout(Some(io_window(deadline)?))
            .map_err(|_| ())?;
        let count = match stream.write(&bytes[offset..]) {
            Ok(count) => count,
            Err(error) if retryable(&error) => continue,
            Err(_) => return Err(()),
        };
        remaining(deadline)?;
        if count == 0 || !authorize() {
            return Err(());
        }
        offset += count;
    }
    Ok(())
}
fn read_guarded<F: Fn() -> bool>(
    stream: &mut UnixStream,
    body: &mut [u8],
    deadline: u64,
    authorize: &F,
) -> Result<usize, ()> {
    loop {
        if !authorize() {
            return Err(());
        }
        stream
            .set_read_timeout(Some(io_window(deadline)?))
            .map_err(|_| ())?;
        match stream.read(body) {
            Ok(count) => {
                remaining(deadline)?;
                if !authorize() {
                    return Err(());
                }
                return Ok(count);
            }
            Err(error) if retryable(&error) => continue,
            Err(_) => return Err(()),
        }
    }
}
pub(crate) fn read_exact_until(
    stream: &mut UnixStream,
    body: &mut [u8],
    deadline: u64,
) -> Result<(), ()> {
    read_exact_guarded(stream, body, deadline, &|| true)
}
fn read_exact_guarded<F: Fn() -> bool>(
    stream: &mut UnixStream,
    body: &mut [u8],
    deadline: u64,
    authorize: &F,
) -> Result<(), ()> {
    let mut offset = 0;
    while offset < body.len() {
        let count = read_guarded(stream, &mut body[offset..], deadline, authorize)?;
        if count == 0 {
            return Err(());
        }
        offset += count;
    }
    Ok(())
}

fn classify(secret: SecretBytes) -> HelperReply {
    let parsed = std::str::from_utf8(secret.as_bytes())
        .ok()
        .and_then(|text| parse_json(text).ok());
    let Some(value) = parsed else {
        return HelperReply::Status(HelperStatus::Uncertain);
    };
    let status = value.get("status").and_then(Value::as_str);
    let reply = if status == Some("authenticated")
        && exact_keys(
            &value,
            &["status", "cookies", "originalDeadlineMs", "revokeHandle"],
        )
        && value
            .get("cookies")
            .and_then(Value::as_array)
            .is_some_and(|cookies| cookies.len() <= 2)
        && value
            .get("originalDeadlineMs")
            .and_then(Value::as_u64)
            .is_some()
        && value
            .get("revokeHandle")
            .and_then(Value::as_object)
            .is_some()
    {
        HelperReply::Session(secret)
    } else if exact_keys(&value, &["status"]) {
        HelperReply::Status(match status {
            Some("authentication_failed") => HelperStatus::AuthenticationFailed,
            Some("login_failed") => HelperStatus::LoginFailed,
            Some("timed_out") => HelperStatus::TimedOut,
            Some("unsupported_authentication") => HelperStatus::UnsupportedAuthentication,
            Some("invalid_configuration") => HelperStatus::InvalidConfiguration,
            Some("binding_mismatch") => HelperStatus::BindingMismatch,
            Some("unsafe_configuration") => HelperStatus::UnsafeConfiguration,
            Some("invalid_request") => HelperStatus::InvalidRequest,
            _ => HelperStatus::Uncertain,
        })
    } else {
        HelperReply::Status(HelperStatus::Uncertain)
    };
    // Parsing necessarily allocates strings. Clear their local copies without
    // claiming that all allocator/OS copies can be erased.
    let mut value = value;
    wipe_value(&mut value);
    reply
}
fn exact_keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == names.len() && fields.iter().all(|(key, _)| names.contains(&key.as_str()))
    })
}
pub(crate) fn wipe_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            let mut bytes = std::mem::take(text).into_bytes();
            blindpass_core::secret::wipe(&mut bytes);
        }
        Value::Array(values) => {
            for value in values {
                wipe_value(value);
            }
        }
        Value::Object(fields) => {
            for (_, value) in fields {
                wipe_value(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindpass_core::secret::SecretBytes;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn reply(body: &[u8]) -> Vec<u8> {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        frame
    }
    fn run(response: Vec<u8>) -> HelperReply {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut job = Vec::new();
            server.read_to_end(&mut job).unwrap();
            assert_eq!(&job[4..], b"{\"dummy\":true}");
            server.write_all(&response).unwrap();
        });
        let result = exchange(
            &mut client,
            &SecretBytes::from_slice(b"{\"dummy\":true}"),
            deadline_after(Duration::from_secs(1)).unwrap(),
        );
        thread.join().unwrap();
        result
    }
    #[test]
    fn helper_only_publishes_fixed_statuses_or_protected_session_buffers() {
        let result = run(reply(br#"{"status":"authentication_failed"}"#));
        assert!(matches!(
            result,
            HelperReply::Status(HelperStatus::AuthenticationFailed)
        ));
        let body = br#"{"status":"authenticated","cookies":[],"originalDeadlineMs":123,"revokeHandle":{}}"#;
        let result = run(reply(body));
        let HelperReply::Session(buffer) = result else {
            panic!("protected session missing")
        };
        assert_eq!(buffer.as_bytes(), body);
        assert!(!format!("{buffer:?}").contains("cookies"));
    }
    #[test]
    fn helper_response_fences_malformed_partial_oversized_and_private_exceptions() {
        let mut oversized = vec![0; 4];
        oversized.copy_from_slice(&16_385_u32.to_be_bytes());
        let mut trailing = reply(br#"{"status":"uncertain"}"#);
        trailing.push(1);
        for bytes in [
            vec![],
            vec![0, 0],
            oversized,
            trailing,
            reply(br#"{"status":"P05-PRIVATE-ERROR-CANARY"}"#),
            reply(br#"{"status":"uncertain","cause":"P05-COOKIE-CANARY"}"#),
            reply(br#"{"status":"uncertain","status":"authenticated"}"#),
            reply(&[0xff]),
            reply(br#"{"status":"authenticated"}"#),
        ] {
            let result = run(bytes);
            assert!(matches!(
                result,
                HelperReply::Status(HelperStatus::Uncertain)
            ));
            assert!(!format!("{result:?}").contains("CANARY"));
        }
    }
    #[test]
    fn helper_whole_response_deadline_bounds_a_stalled_frame() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut job = Vec::new();
            server.read_to_end(&mut job).unwrap();
            server.write_all(&[0]).unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        let start = Instant::now();
        let result = exchange(
            &mut client,
            &SecretBytes::from_slice(b"{}"),
            deadline_after(Duration::from_millis(50)).unwrap(),
        );
        assert!(matches!(
            result,
            HelperReply::Status(HelperStatus::Uncertain)
        ));
        assert!(start.elapsed() < Duration::from_millis(125));
        thread.join().unwrap();
    }
    #[test]
    fn detached_exchange_withdraws_stalled_authority_and_closes_private_channel() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let live = Arc::new(AtomicBool::new(true));
        let authority = Arc::clone(&live);
        let (sent, received) = mpsc::channel();
        let (stopped, stop) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut body = Vec::new();
            server.read_to_end(&mut body).unwrap();
            assert_eq!(&body[4..], b"{}");
            sent.send(()).unwrap();
            stop.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(
                server
                    .write_all(&reply(br#"{"status":"authentication_failed"}"#))
                    .is_err()
            );
        });
        let exchange = std::thread::spawn(move || {
            exchange_guarded(
                &mut client,
                &SecretBytes::from_slice(b"{}"),
                deadline_after(Duration::from_secs(5)).unwrap(),
                || true,
                || authority.load(Ordering::Acquire),
            )
        });
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        live.store(false, Ordering::Release);
        assert!(matches!(
            exchange.join().unwrap(),
            HelperReply::Status(HelperStatus::Uncertain)
        ));
        assert!(start.elapsed() < Duration::from_millis(500));
        stopped.send(()).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn detached_exchange_does_not_renew_or_extend_the_source_preflight_window() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let source = Arc::new(AtomicBool::new(true));
        let source_window = Arc::clone(&source);
        let worker = std::thread::spawn(move || {
            let mut body = Vec::new();
            server.read_to_end(&mut body).unwrap();
            assert_eq!(&body[4..], b"{}");
            source_window.store(false, Ordering::Release);
            server
                .write_all(&reply(br#"{"status":"authentication_failed"}"#))
                .unwrap();
        });
        let response = exchange_guarded(
            &mut client,
            &SecretBytes::from_slice(b"{}"),
            deadline_after(Duration::from_secs(2)).unwrap(),
            || source.load(Ordering::Acquire),
            || true,
        );
        assert!(matches!(
            response,
            HelperReply::Status(HelperStatus::AuthenticationFailed)
        ));
        worker.join().unwrap();
    }
    #[test]
    fn helper_connect_deadline_bounds_an_actual_full_unix_backlog() {
        use std::os::unix::net::UnixListener;
        let directory =
            std::env::temp_dir().join(format!("blindpass-helper-connect-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("private.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // SAFETY: the live listener owns this fd; Linux permits updating backlog.
        assert_eq!(unsafe { listen(listener.as_raw_fd(), 0) }, 0);
        let queued = connect_until(&path, deadline_after(Duration::from_secs(1)).unwrap()).unwrap();
        let start = Instant::now();
        assert!(connect_until(&path, deadline_after(Duration::from_millis(50)).unwrap()).is_err());
        assert!(start.elapsed() < Duration::from_millis(125));
        drop(queued);
        drop(listener);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn boottime_deadline_is_not_extended_by_suspend_or_clock_rollback() {
        assert_eq!(remaining_at(60_001, 1), Ok(Duration::from_secs(60)));
        assert!(remaining_at(60_001, 60_001).is_err());
        assert!(remaining_at(60_001, 120_001).is_err());
    }
    #[test]
    fn bounded_polling_does_not_mistake_a_slow_helper_for_failure() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut job = Vec::new();
            server.read_to_end(&mut job).unwrap();
            std::thread::sleep(Duration::from_millis(350));
            server
                .write_all(&reply(br#"{"status":"authentication_failed"}"#))
                .unwrap();
        });
        let result = exchange(
            &mut client,
            &SecretBytes::from_slice(b"{}"),
            deadline_after(Duration::from_secs(1)).unwrap(),
        );
        assert!(matches!(
            result,
            HelperReply::Status(HelperStatus::AuthenticationFailed)
        ));
        thread.join().unwrap();
    }
}

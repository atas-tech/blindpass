// SPDX-License-Identifier: AGPL-3.0-only

//! Root-owned static Unix CDP proxy. UID permissions are an outer boundary;
//! every connection requires the kernel peer's exact unit and invocation.
//! The coordinator supplies only verified, durably staged browser contexts.

use blindpass_core::identity::PeerIdentity;
use blindpass_core::secret::{SecretBytes, wipe};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADER: usize = 4096;
const POLL_MS: i32 = 50;
const MAX_CONNECTIONS: usize = 16;
const MAX_SESSION_MS: u64 = 30 * 60 * 1000;
const DENIED: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    InvalidConfiguration,
    Denied,
    Busy,
    Unavailable,
    Revoked,
}
impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "browser_proxy_invalid",
            Self::Denied => "browser_proxy_denied",
            Self::Busy => "browser_proxy_busy",
            Self::Unavailable => "browser_proxy_unavailable",
            Self::Revoked => "browser_proxy_revoked",
        })
    }
}
impl std::error::Error for ProxyError {}

#[derive(Debug, Clone)]
pub struct BrowserPeerBinding {
    workload_id: String,
    unit: String,
    uid: u32,
    invocation: String,
}
impl BrowserPeerBinding {
    /// Trusted coordinator input derived from the consumed grant, never HTTP
    /// routing labels. The website account is a distinct credential identity.
    pub fn new(
        workload_id: &str,
        unit: &str,
        uid: u32,
        invocation: &str,
    ) -> Result<Self, ProxyError> {
        if !identifier(workload_id)
            || uid == 0
            || unit.len() > 256
            || !unit.ends_with(".service")
            || unit
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'/' | b'\\'))
            || invocation.len() != 32
            || !invocation
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ProxyError::InvalidConfiguration);
        }
        Ok(Self {
            workload_id: workload_id.to_owned(),
            unit: unit.to_owned(),
            uid,
            invocation: invocation.to_owned(),
        })
    }
    fn matches(&self, peer: &PeerIdentity) -> bool {
        peer.uid != 0
            && peer.uid == self.uid
            && peer.pidfd_supported
            && peer.unit.as_deref() == Some(self.unit.as_str())
            && peer.invocation_id.as_deref() == Some(self.invocation.as_str())
            && peer.account.as_deref() == Some(format!("uid:{}", self.uid).as_str())
    }
}

type Authority = Arc<dyn Fn() -> bool + Send + Sync>;
type OpenBackend = Arc<dyn Fn(Instant) -> Result<UnixStream, ProxyError> + Send + Sync>;
pub struct ReadyBrowserContext {
    binding: BrowserPeerBinding,
    deadline_boottime_ms: u64,
    devtools_path: SecretBytes,
    authority: Authority,
    open_backend: OpenBackend,
}
impl std::fmt::Debug for ReadyBrowserContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadyBrowserContext")
            .field("binding", &self.binding)
            .field("endpoint", &"[protected]")
            .finish_non_exhaustive()
    }
}
impl ReadyBrowserContext {
    /// Publish only after grant/source checks, durable journal activation with
    /// verified manager identity, and successful fresh cookie import. Authority
    /// must recheck current policy/revocations, journal fence and runtime state.
    /// The private backend callback must obey its supplied connect deadline.
    pub fn new(
        binding: BrowserPeerBinding,
        deadline_boottime_ms: u64,
        devtools_path: &str,
        authority: Authority,
        open_backend: OpenBackend,
    ) -> Result<Self, ProxyError> {
        if !devtools_path_valid(devtools_path) || deadline_boottime_ms == 0 {
            return Err(ProxyError::InvalidConfiguration);
        }
        Ok(Self {
            binding,
            deadline_boottime_ms,
            devtools_path: SecretBytes::from_slice(devtools_path.as_bytes()),
            authority,
            open_backend,
        })
    }
}

#[derive(Default)]
pub struct BrowserProxySlot {
    state: Mutex<(u64, Option<Arc<ReadyBrowserContext>>)>,
}
impl BrowserProxySlot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn activate(&self, context: ReadyBrowserContext) -> Result<u64, ProxyError> {
        self.activate_at(context, now()?)
    }
    fn activate_at(&self, context: ReadyBrowserContext, now_ms: u64) -> Result<u64, ProxyError> {
        if context.deadline_boottime_ms <= now_ms
            || context.deadline_boottime_ms - now_ms > MAX_SESSION_MS
            || !(context.authority)()
        {
            return Err(ProxyError::Denied);
        }
        let mut state = self.state.lock().map_err(|_| ProxyError::Unavailable)?;
        if state.1.is_some() {
            return Err(ProxyError::Busy);
        }
        state.0 = state.0.checked_add(1).ok_or(ProxyError::Unavailable)?;
        state.1 = Some(Arc::new(context));
        Ok(state.0)
    }
    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.1 = None;
        }
    }
    fn snapshot(&self) -> Result<(u64, Arc<ReadyBrowserContext>), ProxyError> {
        let state = self.state.lock().map_err(|_| ProxyError::Unavailable)?;
        Ok((
            state.0,
            Arc::clone(state.1.as_ref().ok_or(ProxyError::Denied)?),
        ))
    }
    fn is_current(&self, generation: u64, now_ms: u64) -> bool {
        let Ok((current, context)) = self.snapshot() else {
            return false;
        };
        current == generation && now_ms < context.deadline_boottime_ms && (context.authority)()
    }
}

pub struct BrowserProxy {
    listener: UnixListener,
    path: PathBuf,
    inode: u64,
    workload_id: String,
    slot: Arc<BrowserProxySlot>,
}
impl BrowserProxy {
    /// Fixed administrator-derived runtime path, no arbitrary endpoint or
    /// profile supplied by the workload. Root owns all parent directories.
    pub fn bind(
        workload_id: &str,
        group: u32,
        slot: Arc<BrowserProxySlot>,
    ) -> Result<Self, ProxyError> {
        if !identifier(workload_id) {
            return Err(ProxyError::InvalidConfiguration);
        }
        let path = PathBuf::from(format!("/run/blindpass/browser/{workload_id}/cdp.sock"));
        for parent in [
            Path::new("/run/blindpass"),
            Path::new("/run/blindpass/browser"),
            path.parent().expect("fixed parent"),
        ] {
            match fs::symlink_metadata(parent) {
                Ok(metadata)
                    if metadata.is_dir()
                        && metadata.uid() == 0
                        && metadata.mode() & 0o777 == 0o751 => {}
                Ok(_) => return Err(ProxyError::InvalidConfiguration),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::DirBuilder::new()
                        .mode(0o751)
                        .create(parent)
                        .map_err(|_| ProxyError::Unavailable)?;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o751))
                        .map_err(|_| ProxyError::Unavailable)?;
                    if fs::symlink_metadata(parent)
                        .map_err(|_| ProxyError::Unavailable)?
                        .uid()
                        != 0
                    {
                        return Err(ProxyError::InvalidConfiguration);
                    }
                }
                Err(_) => return Err(ProxyError::Unavailable),
            }
        }
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != 0o660
            {
                return Err(ProxyError::InvalidConfiguration);
            }
            // Never replace a live listener. Startup recovery of the exclusive
            // broker owner may remove only a refused, root-owned stale socket.
            match UnixStream::connect(&path) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&path).map_err(|_| ProxyError::Unavailable)?
                }
                _ => return Err(ProxyError::Busy),
            }
        }
        let listener = UnixListener::bind(&path).map_err(|_| ProxyError::Unavailable)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))
            .map_err(|_| ProxyError::Unavailable)?;
        chown(&path, Some(0), Some(group)).map_err(|_| ProxyError::Unavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProxyError::Unavailable)?;
        let inode = fs::symlink_metadata(&path)
            .map_err(|_| ProxyError::Unavailable)?
            .ino();
        Ok(Self {
            listener,
            path,
            inode,
            workload_id: workload_id.to_owned(),
            slot,
        })
    }
    /// The outcome callback receives fixed codes only, never request/CDP bytes.
    /// Clearing the slot stops existing channels as well as new attachments.
    pub fn serve(
        self,
        stop: Arc<AtomicBool>,
        outcome: Arc<dyn Fn(Result<(), ProxyError>) + Send + Sync>,
    ) -> Result<(), ProxyError> {
        let active = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::Acquire) {
            let (mut stream, _) = match self.listener.accept() {
                Ok(connection) => connection,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(_) => return Err(ProxyError::Unavailable),
            };
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::AcqRel);
                deny(&mut stream);
                outcome(Err(ProxyError::Busy));
                continue;
            }
            let active = Arc::clone(&active);
            let slot = Arc::clone(&self.slot);
            let workload = self.workload_id.clone();
            let outcome = Arc::clone(&outcome);
            std::thread::spawn(move || {
                struct Permit(Arc<AtomicUsize>);
                impl Drop for Permit {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _permit = Permit(active);
                let result = handle_connection(&mut stream, &slot, &workload);
                if result == Err(ProxyError::Denied) {
                    deny(&mut stream);
                }
                let _ = stream.shutdown(Shutdown::Both);
                outcome(result);
            });
        }
        self.slot.clear();
        Ok(())
    }
}
impl Drop for BrowserProxy {
    fn drop(&mut self) {
        self.slot.clear();
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && metadata.uid() == 0 && metadata.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn handle_connection(
    client: &mut UnixStream,
    slot: &BrowserProxySlot,
    workload: &str,
) -> Result<(), ProxyError> {
    let header_deadline = now()?.checked_add(2000).ok_or(ProxyError::Unavailable)?;
    let peer = crate::os_identity::resolve_live_peer(
        client,
        Instant::now() + Duration::from_secs(2),
        Duration::ZERO,
    )
    .map_err(|_| ProxyError::Denied)?;
    let (generation, context) = slot.snapshot()?;
    if context.binding.workload_id != workload
        || !context.binding.matches(peer.identity())
        || !slot.is_current(generation, now()?)
    {
        return Err(ProxyError::Denied);
    }
    let check =
        || peer.ensure_alive().is_ok() && now().is_ok_and(|time| slot.is_current(generation, time));
    let header = read_upgrade(client, header_deadline, &check)?;
    let path = std::str::from_utf8(context.devtools_path.as_bytes())
        .map_err(|_| ProxyError::InvalidConfiguration)?;
    let opening = rewrite_upgrade(header.as_bytes(), path)?;
    if !check() {
        return Err(ProxyError::Revoked);
    }
    let mut backend = (context.open_backend)(Instant::now() + Duration::from_secs(2))?;
    if !check() {
        let _ = backend.shutdown(Shutdown::Both);
        return Err(ProxyError::Revoked);
    }
    backend
        .set_write_timeout(Some(Duration::from_millis(POLL_MS as u64)))
        .map_err(|_| ProxyError::Unavailable)?;
    write_checked(&mut backend, opening.as_bytes(), header_deadline, &check)?;
    relay(client, &mut backend, &check)
}

fn now() -> Result<u64, ProxyError> {
    crate::grants::boottime_ms().map_err(|_| ProxyError::Unavailable)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
fn devtools_path_valid(path: &str) -> bool {
    let Some(uuid) = path.strip_prefix("/devtools/browser/") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}
fn deny(stream: &mut UnixStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(POLL_MS as u64)));
    let _ = stream.write_all(DENIED);
}
fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn read_upgrade(
    client: &mut UnixStream,
    deadline: u64,
    check: &impl Fn() -> bool,
) -> Result<SecretBytes, ProxyError> {
    client
        .set_read_timeout(Some(Duration::from_millis(POLL_MS as u64)))
        .map_err(|_| ProxyError::Unavailable)?;
    let mut header = Vec::with_capacity(MAX_HEADER);
    let result = (|| {
        // Stop exactly at the header terminator so no initial WebSocket bytes
        // are lost or treated as routing/authorization data.
        while header.len() < MAX_HEADER {
            if !check() || now()? >= deadline {
                return Err(ProxyError::Revoked);
            }
            let mut byte = [0];
            match client.read(&mut byte) {
                Ok(0) => return Err(ProxyError::Denied),
                Ok(_) => {
                    header.push(byte[0]);
                    if header.ends_with(b"\r\n\r\n") {
                        return Ok(SecretBytes::from_slice(&header));
                    }
                }
                Err(error) if retry(&error) => continue,
                Err(_) => return Err(ProxyError::Unavailable),
            }
        }
        Err(ProxyError::Denied)
    })();
    wipe(&mut header);
    result
}

fn rewrite_upgrade(bytes: &[u8], devtools_path: &str) -> Result<SecretBytes, ProxyError> {
    if !devtools_path_valid(devtools_path) {
        return Err(ProxyError::InvalidConfiguration);
    }
    if bytes.len() > MAX_HEADER || !bytes.ends_with(b"\r\n\r\n") {
        return Err(ProxyError::Denied);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ProxyError::Denied)?;
    if text.bytes().any(|byte| !byte.is_ascii() || byte == 0) {
        return Err(ProxyError::Denied);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    if lines.next() != Some("GET /current HTTP/1.1") {
        return Err(ProxyError::Denied);
    }
    let mut seen = HashSet::new();
    let mut key = None;
    let mut version = false;
    let mut upgrade = false;
    let mut connection = false;
    let mut host = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ProxyError::Denied)?;
        if name.is_empty()
            || name
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(ProxyError::Denied);
        }
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return Err(ProxyError::Denied);
        }
        let value = value.trim();
        match name.as_str() {
            "sec-websocket-key" => {
                let bytes = value.as_bytes();
                if bytes.len() != 24
                    || bytes[22..] != *b"=="
                    || !b"AQgw".contains(&bytes[21])
                    || !bytes[..22]
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
                {
                    return Err(ProxyError::Denied);
                }
                key = Some(value);
            }
            "sec-websocket-version" => version = value == "13",
            "upgrade" => upgrade = value.eq_ignore_ascii_case("websocket"),
            "connection" => {
                connection = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            }
            "host" => host = !value.is_empty() && value.len() <= 256,
            "authorization" | "proxy-authorization" | "cookie" | "transfer-encoding" => {
                return Err(ProxyError::Denied);
            }
            "content-length" if value != "0" => return Err(ProxyError::Denied),
            _ => {}
        }
    }
    if !version || !upgrade || !connection || !host {
        return Err(ProxyError::Denied);
    }
    let key = key.ok_or(ProxyError::Denied)?;
    Ok(SecretBytes::new(format!("GET {devtools_path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n").into_bytes()))
}

fn write_checked(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: u64,
    check: &impl Fn() -> bool,
) -> Result<(), ProxyError> {
    let mut offset = 0;
    while offset < bytes.len() {
        if !check() || now()? >= deadline {
            return Err(ProxyError::Revoked);
        }
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(ProxyError::Unavailable),
            Ok(count) => offset += count,
            Err(error) if retry(&error) => continue,
            Err(_) => return Err(ProxyError::Unavailable),
        }
    }
    Ok(())
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}
unsafe extern "C" {
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
}
struct Buffer {
    bytes: [u8; 16_384],
    start: usize,
    end: usize,
}
impl Buffer {
    fn new() -> Self {
        Self {
            bytes: [0; 16_384],
            start: 0,
            end: 0,
        }
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

fn relay(
    client: &mut UnixStream,
    backend: &mut UnixStream,
    check: &impl Fn() -> bool,
) -> Result<(), ProxyError> {
    client
        .set_nonblocking(true)
        .map_err(|_| ProxyError::Unavailable)?;
    backend
        .set_nonblocking(true)
        .map_err(|_| ProxyError::Unavailable)?;
    let mut to_backend = Buffer::new();
    let mut to_client = Buffer::new();
    let mut client_eof = false;
    let mut backend_eof = false;
    let mut client_write_closed = false;
    let mut backend_write_closed = false;
    let result = (|| {
        const IN: i16 = 1;
        const OUT: i16 = 4;
        loop {
            if !check() {
                return Err(ProxyError::Revoked);
            }
            if client_eof && to_backend.end == 0 && !backend_write_closed {
                let _ = backend.shutdown(Shutdown::Write);
                backend_write_closed = true;
            }
            if backend_eof && to_client.end == 0 && !client_write_closed {
                let _ = client.shutdown(Shutdown::Write);
                client_write_closed = true;
            }
            if client_eof && backend_eof && to_backend.end == 0 && to_client.end == 0 {
                return Ok(());
            }
            let client_events = (if !client_eof && to_backend.end == 0 {
                IN
            } else {
                0
            }) | (if to_client.end > 0 { OUT } else { 0 });
            let backend_events = (if !backend_eof && to_client.end == 0 {
                IN
            } else {
                0
            }) | (if to_backend.end > 0 { OUT } else { 0 });
            let mut descriptors = [
                PollFd {
                    fd: if client_events == 0 {
                        -1
                    } else {
                        client.as_raw_fd()
                    },
                    events: client_events,
                    revents: 0,
                },
                PollFd {
                    fd: if backend_events == 0 {
                        -1
                    } else {
                        backend.as_raw_fd()
                    },
                    events: backend_events,
                    revents: 0,
                },
            ];
            // SAFETY: the array owns two initialized ABI descriptors for poll.
            let polled = unsafe { poll(descriptors.as_mut_ptr(), descriptors.len(), POLL_MS) };
            if polled < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ProxyError::Unavailable);
            }
            if !check() {
                return Err(ProxyError::Revoked);
            }
            if to_backend.end > 0 && descriptors[1].revents & OUT != 0 {
                flush(backend, &mut to_backend)?;
            }
            if to_client.end > 0 && descriptors[0].revents & OUT != 0 {
                flush(client, &mut to_client)?;
            }
            if !client_eof && to_backend.end == 0 && descriptors[0].revents & (IN | 16) != 0 {
                client_eof = !fill(client, &mut to_backend)?;
            }
            if !backend_eof && to_client.end == 0 && descriptors[1].revents & (IN | 16) != 0 {
                backend_eof = !fill(backend, &mut to_client)?;
            }
            // HUP can accompany pending readable bytes; drain those before
            // closing. Errors/invalid descriptors fail with a fixed outcome.
            if descriptors.iter().any(|fd| fd.revents & (8 | 32) != 0) {
                return Err(ProxyError::Unavailable);
            }
        }
    })();
    let _ = client.shutdown(Shutdown::Both);
    let _ = backend.shutdown(Shutdown::Both);
    result
}
fn fill(stream: &mut UnixStream, buffer: &mut Buffer) -> Result<bool, ProxyError> {
    match stream.read(&mut buffer.bytes) {
        Ok(0) => Ok(false),
        Ok(count) => {
            buffer.start = 0;
            buffer.end = count;
            Ok(true)
        }
        Err(error) if retry(&error) => Ok(true),
        Err(_) => Err(ProxyError::Unavailable),
    }
}
fn flush(stream: &mut UnixStream, buffer: &mut Buffer) -> Result<(), ProxyError> {
    match stream.write(&buffer.bytes[buffer.start..buffer.end]) {
        Ok(0) => Err(ProxyError::Unavailable),
        Ok(count) => {
            wipe(&mut buffer.bytes[buffer.start..buffer.start + count]);
            buffer.start += count;
            if buffer.start == buffer.end {
                buffer.start = 0;
                buffer.end = 0;
            }
            Ok(())
        }
        Err(error) if retry(&error) => Ok(()),
        Err(_) => Err(ProxyError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/devtools/browser/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const OPENING: &[u8] = b"GET /current HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

    fn binding() -> BrowserPeerBinding {
        BrowserPeerBinding::new("work-a", "agent.service", 1001, &"a".repeat(32)).unwrap()
    }

    #[test]
    fn browser_proxy_matches_os_unit_uid_and_exact_invocation_without_caller_labels() {
        let expected = binding();
        let peer = PeerIdentity::fixture(1001, 1001, "agent.service", &"a".repeat(32), "uid:1001");
        assert!(expected.matches(&peer));
        for replacement in [
            PeerIdentity::fixture(1001, 1001, "other.service", &"a".repeat(32), "uid:1001"),
            PeerIdentity::fixture(1001, 1001, "agent.service", &"b".repeat(32), "uid:1001"),
            PeerIdentity::fixture(1002, 1001, "agent.service", &"a".repeat(32), "uid:1002"),
            PeerIdentity::fixture(0, 1001, "agent.service", &"a".repeat(32), "uid:0"),
        ] {
            assert!(!expected.matches(&replacement));
        }
        let mut unsupported = peer.clone();
        unsupported.pidfd_supported = false;
        assert!(!expected.matches(&unsupported));
        let mut forged = peer;
        forged.account = Some("uid:1002".to_owned());
        assert!(!expected.matches(&forged));
    }

    #[test]
    fn browser_proxy_upgrade_rewrites_only_the_trusted_path_and_preserves_no_authority_headers() {
        let mut opening = OPENING[..OPENING.len() - 2].to_vec();
        opening.extend_from_slice(
            b"X-Workload-Unit: forged.service\r\nX-Workload-Invocation: forged\r\n\r\n",
        );
        let rewritten = rewrite_upgrade(&opening, PATH).unwrap();
        let text = std::str::from_utf8(rewritten.as_bytes()).unwrap();
        assert!(text.starts_with(&format!("GET {PATH} HTTP/1.1\r\n")));
        assert!(text.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(!text.contains("forged"));
        assert!(!text.contains("/current"));
        assert!(!format!("{rewritten:?}").contains(PATH));
    }

    #[test]
    fn browser_proxy_upgrade_rejects_paths_headers_bad_keys_and_ambiguous_framing() {
        let original = std::str::from_utf8(OPENING).unwrap();
        for text in [
            original.replace("/current", "http://agent-substituted.invalid/current"),
            original.replace("/current", "/current?context=forged"),
            original.replace("GET ", "POST "),
            original.replace("Version: 13", "Version: 12"),
            original.replace("dGhlIHNhbXBsZSBub25jZQ==", "PRIVATE-CANARY"),
            original.replace(
                "\r\n\r\n",
                "\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            ),
            original.replace("\r\n\r\n", "\r\nCookie: PRIVATE-CANARY\r\n\r\n"),
            original.replace(
                "\r\n\r\n",
                "\r\nAuthorization: Bearer PRIVATE-CANARY\r\n\r\n",
            ),
            original.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
            original.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\n"),
            original.replace("Connection: Upgrade", "Connection: keep-alive"),
            original.replace("Upgrade: websocket", "Upgrade: other"),
            original.replace("Host: localhost", " Host: localhost"),
        ] {
            assert_eq!(
                rewrite_upgrade(text.as_bytes(), PATH).unwrap_err(),
                ProxyError::Denied
            );
        }
        assert_eq!(
            rewrite_upgrade(OPENING, "/devtools/browser/agent\r\nheader").unwrap_err(),
            ProxyError::InvalidConfiguration
        );
        assert_eq!(
            rewrite_upgrade(&vec![b'x'; 4097], PATH).unwrap_err(),
            ProxyError::Denied
        );
    }

    #[test]
    fn browser_proxy_slot_generation_and_deadline_prevent_reuse_after_cancel_or_replacement() {
        let slot = BrowserProxySlot::new();
        let ready = || {
            ReadyBrowserContext::new(
                binding(),
                1100,
                PATH,
                Arc::new(|| true),
                Arc::new(|_| Err(ProxyError::Unavailable)),
            )
            .unwrap()
        };
        assert!(!slot.is_current(1, 1000));
        let first = slot.activate_at(ready(), 1000).unwrap();
        assert!(slot.is_current(first, 1099));
        assert!(!slot.is_current(first, 1100));
        assert_eq!(slot.activate_at(ready(), 1000), Err(ProxyError::Busy));
        slot.clear();
        assert!(!slot.is_current(first, 1000));
        let second = slot.activate_at(ready(), 1000).unwrap();
        assert_ne!(first, second);
        assert!(!slot.is_current(first, 1000));
        assert!(slot.is_current(second, 1000));
        slot.clear();
    }

    #[test]
    fn browser_proxy_configuration_and_debug_do_not_accept_or_reveal_endpoints() {
        assert!(
            BrowserPeerBinding::new("../escape", "agent.service", 1001, &"a".repeat(32)).is_err()
        );
        assert!(BrowserPeerBinding::new("work-a", "agent.service", 0, &"a".repeat(32)).is_err());
        assert!(BrowserPeerBinding::new("work-a", "agent.service", 1001, "stale").is_err());
        let context = ReadyBrowserContext::new(
            binding(),
            1100,
            PATH,
            Arc::new(|| true),
            Arc::new(|_| Err(ProxyError::Unavailable)),
        )
        .unwrap();
        assert!(!format!("{context:?}").contains(PATH));
        let slot = BrowserProxySlot::new();
        assert_eq!(slot.activate_at(context, 1100), Err(ProxyError::Denied));
    }

    #[test]
    fn browser_proxy_relay_preserves_both_directions_and_closes_on_revocation() {
        let (mut client, mut client_proxy) = UnixStream::pair().unwrap();
        let (mut backend_proxy, mut backend) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        backend
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let authorized = Arc::new(AtomicBool::new(true));
        let check = Arc::clone(&authorized);
        let task = std::thread::spawn(move || {
            relay(&mut client_proxy, &mut backend_proxy, &|| {
                check.load(Ordering::Acquire)
            })
        });
        let first = vec![b'a'; 100_000];
        let second = vec![b'b'; 100_000];
        client.write_all(&first).unwrap();
        backend.write_all(&second).unwrap();
        let mut received = vec![0; first.len()];
        backend.read_exact(&mut received).unwrap();
        assert_eq!(received, first);
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, second);
        authorized.store(false, Ordering::Release);
        assert_eq!(task.join().unwrap(), Err(ProxyError::Revoked));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert_eq!(backend.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn browser_proxy_half_close_flushes_last_bytes_without_reopening_authority() {
        let (mut client, mut client_proxy) = UnixStream::pair().unwrap();
        let (mut backend_proxy, mut backend) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let task =
            std::thread::spawn(move || relay(&mut client_proxy, &mut backend_proxy, &|| true));
        client.shutdown(Shutdown::Write).unwrap();
        backend.write_all(b"last-websocket-bytes").unwrap();
        backend.shutdown(Shutdown::Write).unwrap();
        let mut bytes = [0; 20];
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"last-websocket-bytes");
        assert_eq!(task.join().unwrap(), Ok(()));
    }
}

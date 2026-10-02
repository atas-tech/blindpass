// SPDX-License-Identifier: AGPL-3.0-only

//! Challenge-bound reverse connection from the actual namespace worker. An
//! activation socket identifies systemd's listener; this connection captures the
//! worker's own kernel pidfd. Namespace/configuration and durable journal checks
//! remain the coordinator's responsibility before importing any cookie.

use crate::os_identity::{LivePeer, resolve_live_peer};
use blindpass_core::canon::{Value, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::identity::PeerIdentity;
use blindpass_core::secret::SecretBytes;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FAILURE: &str = "runtime_identity_unavailable";
const DENIED: &str = "runtime_identity_denied";
const MAX_PENDING: usize = 16;
const MAX_PROOF: usize = 256;
const MAX_TICKET_MS: u64 = 15_000;
const SOCKET: &str = "/run/blindpass-runtime/identity.sock";

#[derive(Clone, Debug)]
pub struct RuntimeBinding {
    unit: String,
    invocation: String,
    uid: u32,
    helper_activation: bool,
    browser_activation: bool,
    excluded_uids: Vec<u32>,
}
impl RuntimeBinding {
    pub fn new(
        unit: &str,
        invocation: &str,
        uid: u32,
        excluded_uids: &[u32],
    ) -> Result<Self, &'static str> {
        if uid == 0
            || excluded_uids.contains(&uid)
            || !unit.starts_with("blindpass-browser@")
            || !unit.ends_with(".service")
            || unit.len() > 200
            || unit.len() <= "blindpass-browser@.service".len()
            || !unit.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':' | b'\\')
            })
            || unit.contains("..")
            || invocation.len() != 32
            || !invocation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DENIED);
        }
        Ok(Self {
            unit: unit.into(),
            invocation: invocation.into(),
            uid,
            helper_activation: false,
            browser_activation: false,
            excluded_uids: Vec::new(),
        })
    }
    /// Socket activation chooses the instance name. Only the installed helper
    /// template and dedicated UID are eligible; the exact kernel/manager
    /// identity returned by the proof must be journaled before source delivery.
    pub fn private_helper(uid: u32, excluded_uids: &[u32]) -> Result<Self, &'static str> {
        if uid == 0 || excluded_uids.contains(&uid) {
            return Err(DENIED);
        }
        Ok(Self {
            unit: String::new(),
            invocation: String::new(),
            uid,
            helper_activation: true,
            browser_activation: false,
            excluded_uids: Vec::new(),
        })
    }
    /// Learn the actual activation identity from the held reverse kernel proof,
    /// without trusting a worker PID/UID/unit hint. Profile proof is separate.
    pub fn browser_activation(excluded_uids: &[u32]) -> Result<Self, &'static str> {
        if excluded_uids.len() > 32 {
            return Err(DENIED);
        }
        Ok(Self {
            unit: String::new(),
            invocation: String::new(),
            uid: 0,
            helper_activation: false,
            browser_activation: true,
            excluded_uids: excluded_uids.to_vec(),
        })
    }
    fn matches(&self, peer: &PeerIdentity) -> bool {
        peer.uid != 0
            && peer.pidfd_supported
            && peer.account.as_deref() == Some(&format!("uid:{}", peer.uid))
            && if self.browser_activation {
                !self.excluded_uids.contains(&peer.uid)
                    && peer.unit.as_deref().is_some_and(valid_browser_unit)
                    && peer.invocation_id.as_deref().is_some_and(valid_invocation)
            } else if self.helper_activation {
                peer.uid == self.uid
                    && peer.unit.as_deref().is_some_and(valid_helper_unit)
                    && peer.invocation_id.as_deref().is_some_and(valid_invocation)
            } else {
                peer.uid == self.uid
                    && peer.unit.as_deref() == Some(&self.unit)
                    && peer.invocation_id.as_deref() == Some(&self.invocation)
            }
    }
}
pub(crate) fn valid_browser_unit(unit: &str) -> bool {
    unit.starts_with("blindpass-browser@")
        && unit.ends_with(".service")
        && unit.len() > "blindpass-browser@.service".len()
        && unit.len() <= 200
        && !unit.contains("..")
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':')
        })
}
pub(crate) fn valid_helper_unit(unit: &str) -> bool {
    unit.starts_with("blindpass-login-helper@")
        && unit.ends_with(".service")
        && unit.len() > "blindpass-login-helper@.service".len()
        && unit.len() <= 200
        && !unit.contains("..")
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':' | b'\\')
        })
}
fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
struct Pending {
    binding: RuntimeBinding,
    deadline_ms: u64,
    sender: SyncSender<VerifiedRuntime>,
}
pub struct RuntimeIdentityBook {
    pending: Mutex<BTreeMap<[u8; 32], Pending>>,
    alive: Arc<AtomicBool>,
    private_helper: bool,
}
impl std::fmt::Debug for RuntimeIdentityBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuntimeIdentityBook([protected])")
    }
}
impl Default for RuntimeIdentityBook {
    fn default() -> Self {
        Self::new()
    }
}
impl RuntimeIdentityBook {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(BTreeMap::new()),
            alive: Arc::new(AtomicBool::new(true)),
            private_helper: false,
        }
    }
    #[must_use]
    pub fn new_private_helper() -> Self {
        Self {
            private_helper: true,
            ..Self::new()
        }
    }
    pub fn register(
        self: &Arc<Self>,
        binding: RuntimeBinding,
        deadline_ms: u64,
    ) -> Result<RuntimeTicket, &'static str> {
        self.register_at(binding, deadline_ms, now()?)
    }
    pub fn register_for(
        self: &Arc<Self>,
        binding: RuntimeBinding,
        window: Duration,
    ) -> Result<RuntimeTicket, &'static str> {
        let now_ms = now()?;
        let milliseconds = u64::try_from(window.as_millis()).map_err(|_| DENIED)?;
        self.register_at(
            binding,
            now_ms.checked_add(milliseconds).ok_or(DENIED)?,
            now_ms,
        )
    }
    fn register_at(
        self: &Arc<Self>,
        binding: RuntimeBinding,
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<RuntimeTicket, &'static str> {
        if binding.helper_activation != self.private_helper
            || !self.alive.load(Ordering::Acquire)
            || deadline_ms <= now_ms
            || deadline_ms - now_ms > MAX_TICKET_MS
        {
            return Err(DENIED);
        }
        let mut random = [0; 32];
        if File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .is_err()
        {
            blindpass_core::secret::wipe(&mut random);
            return Err(FAILURE);
        }
        let challenge = SecretBytes::new(
            random
                .iter()
                .flat_map(|byte| {
                    [
                        b"0123456789abcdef"[(byte >> 4) as usize],
                        b"0123456789abcdef"[(byte & 15) as usize],
                    ]
                })
                .collect(),
        );
        blindpass_core::secret::wipe(&mut random);
        let key = sha256(challenge.as_bytes()).map_err(|_| FAILURE)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut pending = self.pending.lock().map_err(|_| FAILURE)?;
        if !self.alive.load(Ordering::Acquire) {
            return Err(DENIED);
        }
        pending.retain(|_, item| item.deadline_ms > now_ms);
        if pending.len() >= MAX_PENDING || pending.contains_key(&key) {
            return Err(FAILURE);
        }
        pending.insert(
            key,
            Pending {
                binding,
                deadline_ms,
                sender,
            },
        );
        Ok(RuntimeTicket {
            book: Arc::clone(self),
            key,
            challenge,
            deadline_ms,
            receiver,
        })
    }
    fn complete(&self, key: [u8; 32], peer: LivePeer) -> Result<(), &'static str> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(DENIED);
        }
        peer.ensure_alive().map_err(|_| DENIED)?;
        let now_ms = now()?;
        let mut pending = self.pending.lock().map_err(|_| FAILURE)?;
        pending.retain(|_, item| item.deadline_ms > now_ms);
        let item = pending.get(&key).ok_or(DENIED)?;
        // A wrong unit/invocation cannot burn the legitimate worker's ticket.
        if !item.binding.matches(peer.identity()) {
            return Err(DENIED);
        }
        let item = pending.remove(&key).expect("validated pending ticket");
        item.sender
            .try_send(VerifiedRuntime {
                peer,
                book_alive: Arc::clone(&self.alive),
            })
            .map_err(|_| DENIED)
    }
    fn shutdown(&self) {
        self.alive.store(false, Ordering::Release);
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }
}
pub struct RuntimeTicket {
    book: Arc<RuntimeIdentityBook>,
    key: [u8; 32],
    challenge: SecretBytes,
    deadline_ms: u64,
    receiver: Receiver<VerifiedRuntime>,
}
impl std::fmt::Debug for RuntimeTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuntimeTicket([protected])")
    }
}
impl RuntimeTicket {
    /// Protected control-channel data only; never model/audit/argv output.
    #[must_use]
    pub fn challenge(&self) -> &SecretBytes {
        &self.challenge
    }
    pub fn wait(self) -> Result<VerifiedRuntime, &'static str> {
        loop {
            if now()? >= self.deadline_ms || !self.book.alive.load(Ordering::Acquire) {
                return Err(DENIED);
            }
            match self.receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(runtime) => {
                    if now()? >= self.deadline_ms {
                        return Err(DENIED);
                    }
                    runtime.ensure_alive()?;
                    return Ok(runtime);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(DENIED),
            }
        }
    }
}
impl Drop for RuntimeTicket {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.book.pending.lock() {
            pending.remove(&self.key);
        }
    }
}
pub struct VerifiedRuntime {
    peer: LivePeer,
    book_alive: Arc<AtomicBool>,
}
impl VerifiedRuntime {
    pub(crate) fn book_is_alive(&self) -> bool {
        self.book_alive.load(Ordering::Acquire)
    }
    #[must_use]
    pub fn identity(&self) -> &PeerIdentity {
        self.peer.identity()
    }
    pub fn ensure_current(&self, deadline: Instant) -> Result<(), &'static str> {
        if !self.book_is_alive() {
            return Err(DENIED);
        }
        self.peer.ensure_current(deadline).map_err(|_| DENIED)
    }
    pub fn ensure_alive(&self) -> Result<(), &'static str> {
        if !self.book_alive.load(Ordering::Acquire) {
            return Err(DENIED);
        }
        self.peer.ensure_alive().map_err(|_| DENIED)
    }
}
impl std::fmt::Debug for VerifiedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedRuntime([kernel-bound])")
    }
}

pub struct RuntimeIdentityListener {
    listener: UnixListener,
    path: PathBuf,
    inode: (u64, u64),
    book: Arc<RuntimeIdentityBook>,
}
impl RuntimeIdentityListener {
    pub fn bind(group: u32, book: Arc<RuntimeIdentityBook>) -> Result<Self, &'static str> {
        if book.private_helper {
            return Err(DENIED);
        }
        Self::bind_at(group, book, "/run/blindpass-runtime", SOCKET)
    }
    pub fn bind_private_helper(
        group: u32,
        book: Arc<RuntimeIdentityBook>,
    ) -> Result<Self, &'static str> {
        if !book.private_helper {
            return Err(DENIED);
        }
        Self::bind_at(
            group,
            book,
            "/run/blindpass-helper-identity",
            "/run/blindpass-helper-identity/identity.sock",
        )
    }
    fn bind_at(
        group: u32,
        book: Arc<RuntimeIdentityBook>,
        parent: &str,
        socket: &str,
    ) -> Result<Self, &'static str> {
        if crate::effective_uid() != 0 || group == 0 {
            return Err(DENIED);
        }
        let ancestor = fs::symlink_metadata("/run").map_err(|_| FAILURE)?;
        if !ancestor.is_dir() || ancestor.uid() != 0 || ancestor.mode() & 0o022 != 0 {
            return Err(DENIED);
        }
        let parent = PathBuf::from(parent);
        if fs::create_dir(&parent).is_ok() {
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).map_err(|_| FAILURE)?;
            chown(&parent, None, Some(group)).map_err(|_| FAILURE)?;
        }
        let metadata = fs::symlink_metadata(&parent).map_err(|_| FAILURE)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != group
            || metadata.mode() & 0o7777 != 0o750
        {
            return Err(DENIED);
        }
        let path = PathBuf::from(socket);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || metadata.gid() != group
                || metadata.mode() & 0o7777 != 0o660
                || metadata.nlink() != 1
            {
                return Err(DENIED);
            }
            match UnixStream::connect(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&path).map_err(|_| FAILURE)?;
                }
                _ => return Err(DENIED),
            }
        }
        let listener = UnixListener::bind(&path).map_err(|_| FAILURE)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|_| FAILURE)?;
        chown(&path, None, Some(group)).map_err(|_| FAILURE)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).map_err(|_| FAILURE)?;
        listener.set_nonblocking(true).map_err(|_| FAILURE)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| FAILURE)?;
        Ok(Self {
            listener,
            path,
            inode: (metadata.dev(), metadata.ino()),
            book,
        })
    }
    pub fn serve(&self, stop: Arc<AtomicBool>) -> Result<(), &'static str> {
        struct Shutdown<'a>(&'a RuntimeIdentityBook);
        impl Drop for Shutdown<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _shutdown = Shutdown(&self.book);
        let active = Arc::new(AtomicUsize::new(0));
        while !stop.load(Ordering::Acquire) {
            let mut stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(FAILURE),
            };
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING {
                active.fetch_sub(1, Ordering::AcqRel);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let book = Arc::clone(&self.book);
            let count = Arc::clone(&active);
            std::thread::spawn(move || {
                struct Slot(Arc<AtomicUsize>);
                impl Drop for Slot {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _slot = Slot(count);
                let result = (|| {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let peer =
                        resolve_live_peer(&stream, deadline, Duration::ZERO).map_err(|_| DENIED)?;
                    let key = read_proof(&mut stream, deadline)?;
                    book.complete(key, peer)
                })();
                let _ = stream.set_write_timeout(Some(Duration::from_millis(50)));
                let _ = stream.write_all(if result.is_ok() {
                    b"OK runtime_identity\n"
                } else {
                    b"ERR runtime_identity_denied\n"
                });
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
        self.book.shutdown();
        Ok(())
    }
}
impl Drop for RuntimeIdentityListener {
    fn drop(&mut self) {
        self.book.shutdown();
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn now() -> Result<u64, &'static str> {
    crate::grants::boottime_ms().map_err(|_| FAILURE)
}
fn parse_proof(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    if bytes.len() > MAX_PROOF {
        return Err(DENIED);
    }
    let mut value =
        parse_json(std::str::from_utf8(bytes).map_err(|_| DENIED)?).map_err(|_| DENIED)?;
    let result = (|| {
        if value.as_object().is_none_or(|fields| fields.len() != 2)
            || value.get("version").and_then(Value::as_u64) != Some(1)
        {
            return Err(DENIED);
        }
        let challenge = value
            .get("challenge")
            .and_then(Value::as_str)
            .ok_or(DENIED)?;
        if challenge.len() != 64
            || !challenge
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DENIED);
        }
        sha256(challenge.as_bytes()).map_err(|_| FAILURE)
    })();
    crate::private_helper::wipe_value(&mut value);
    result
}
fn read_proof(stream: &mut UnixStream, deadline: Instant) -> Result<[u8; 32], &'static str> {
    stream
        .set_read_timeout(Some(Duration::from_millis(25)))
        .map_err(|_| FAILURE)?;
    fn exact(
        stream: &mut UnixStream,
        mut target: &mut [u8],
        deadline: Instant,
    ) -> Result<(), &'static str> {
        while !target.is_empty() {
            if Instant::now() >= deadline {
                return Err(DENIED);
            }
            match stream.read(target) {
                Ok(0) => return Err(DENIED),
                Ok(count) => target = &mut target[count..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err(DENIED),
            }
        }
        Ok(())
    }
    let mut header = [0; 4];
    exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if !(2..=MAX_PROOF).contains(&length) {
        return Err(DENIED);
    }
    let mut bytes = vec![0; length];
    if let Err(error) = exact(stream, &mut bytes, deadline) {
        blindpass_core::secret::wipe(&mut bytes);
        return Err(error);
    }
    let body = SecretBytes::new(bytes);
    let mut trailing = [0];
    loop {
        if Instant::now() >= deadline {
            return Err(DENIED);
        }
        match stream.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(DENIED),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err(DENIED),
        }
    }
    parse_proof(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindpass_core::identity::PeerIdentity;
    fn binding() -> RuntimeBinding {
        RuntimeBinding::new(
            "blindpass-browser@0-123-root.service",
            &"a".repeat(32),
            61001,
            &[0, 900, 1001],
        )
        .unwrap()
    }
    #[test]
    fn browser_activation_learns_only_the_installed_non_workload_kernel_class() {
        let binding = RuntimeBinding::browser_activation(&[0, 900, 1001]).unwrap();
        let peer = PeerIdentity::fixture(
            61001,
            61001,
            "blindpass-browser@0-123-root.service",
            &"a".repeat(32),
            "uid:61001",
        );
        assert!(binding.matches(&peer));
        for uid in [0, 900, 1001] {
            let mut wrong = peer.clone();
            wrong.uid = uid;
            wrong.account = Some(format!("uid:{uid}"));
            assert!(!binding.matches(&wrong));
        }
        for unit in [
            "agent.service",
            "blindpass-login-helper@0-123-root.service",
            "blindpass-browser@.service",
            "blindpass-browser@../other.service",
        ] {
            let mut wrong = peer.clone();
            wrong.unit = Some(unit.into());
            assert!(!binding.matches(&wrong));
        }
        let mut wrong = peer.clone();
        wrong.invocation_id = Some("claimed".into());
        assert!(!binding.matches(&wrong));
        let mut wrong = peer;
        wrong.pidfd_supported = false;
        assert!(!binding.matches(&wrong));
    }
    #[test]
    fn helper_proof_requires_dedicated_uid_installed_template_and_manager_invocation() {
        let binding = RuntimeBinding::private_helper(900, &[0, 1001, 61001]).unwrap();
        let peer = PeerIdentity::fixture(
            900,
            900,
            "blindpass-login-helper@0-123-root.service",
            &"a".repeat(32),
            "uid:900",
        );
        assert!(binding.matches(&peer));
        for unit in [
            "agent.service",
            "blindpass-browser@0-123-root.service",
            "blindpass-login-helper@.service",
            "blindpass-login-helper@../other.service",
        ] {
            let mut wrong = peer.clone();
            wrong.unit = Some(unit.into());
            assert!(!binding.matches(&wrong));
        }
        for invocation in ["", "claimed", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
            let mut wrong = peer.clone();
            wrong.invocation_id = Some(invocation.into());
            assert!(!binding.matches(&wrong));
        }
        let mut wrong = peer.clone();
        wrong.pidfd_supported = false;
        assert!(!binding.matches(&wrong));
        let mut wrong = peer.clone();
        wrong.uid = 1001;
        assert!(!binding.matches(&wrong));
        let mut wrong = peer;
        wrong.account = Some("uid:1001".into());
        assert!(!binding.matches(&wrong));
        for uid in [0, 1001, 61001] {
            assert!(RuntimeBinding::private_helper(uid, &[1001, 61001]).is_err());
        }
    }
    #[test]
    fn helper_and_browser_challenges_cannot_cross_identity_books() {
        let browser = Arc::new(RuntimeIdentityBook::new());
        let helper = Arc::new(RuntimeIdentityBook::new_private_helper());
        assert!(
            browser
                .register_for(
                    RuntimeBinding::private_helper(900, &[0, 1001]).unwrap(),
                    Duration::from_secs(1)
                )
                .is_err()
        );
        assert!(
            helper
                .register_for(binding(), Duration::from_secs(1))
                .is_err()
        );
        let ticket = helper
            .register_for(
                RuntimeBinding::private_helper(900, &[0, 1001]).unwrap(),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(helper.pending.lock().unwrap().len(), 1);
        drop(ticket);
        assert!(helper.pending.lock().unwrap().is_empty());
    }
    #[test]
    fn runtime_identity_requires_the_exact_non_workload_unit_invocation_and_uid() {
        let binding = binding();
        let peer = PeerIdentity::fixture(
            61001,
            61001,
            "blindpass-browser@0-123-root.service",
            &"a".repeat(32),
            "uid:61001",
        );
        assert!(binding.matches(&peer));
        let mut wrong = peer.clone();
        wrong.uid = 1001;
        assert!(!binding.matches(&wrong));
        let mut wrong = peer.clone();
        wrong.unit = Some("agent.service".into());
        assert!(!binding.matches(&wrong));
        let mut wrong = peer.clone();
        wrong.invocation_id = Some("b".repeat(32));
        assert!(!binding.matches(&wrong));
        let mut wrong = peer.clone();
        wrong.pidfd_supported = false;
        assert!(!binding.matches(&wrong));
        let mut wrong = peer;
        wrong.account = Some("uid:1001".into());
        assert!(!binding.matches(&wrong));
        for uid in [0, 900, 1001] {
            assert!(
                RuntimeBinding::new(
                    "blindpass-browser@0-123-root.service",
                    &"a".repeat(32),
                    uid,
                    &[900, 1001]
                )
                .is_err()
            );
        }
        assert!(RuntimeBinding::new("agent.service", &"a".repeat(32), 61001, &[]).is_err());
        assert!(
            RuntimeBinding::new(
                "blindpass-browser@../escape.service",
                &"a".repeat(32),
                61001,
                &[]
            )
            .is_err()
        );
    }
    #[test]
    fn runtime_identity_tickets_are_bounded_private_and_cancelled_when_dropped() {
        let book = Arc::new(RuntimeIdentityBook::new());
        let mut tickets = Vec::new();
        for _ in 0..16 {
            tickets.push(book.register(binding(), now().unwrap() + 15_000).unwrap());
        }
        assert!(book.register(binding(), now().unwrap() + 15_000).is_err());
        let challenge = std::str::from_utf8(tickets[0].challenge().as_bytes()).unwrap();
        assert_eq!(challenge.len(), 64);
        assert!(!format!("{:?} {:?}", book, tickets[0]).contains(challenge));
        tickets.pop();
        assert!(book.register(binding(), now().unwrap() + 15_000).is_ok());
        drop(tickets);
        assert_eq!(book.pending.lock().unwrap().len(), 0);
        assert!(book.register_at(binding(), 1000, 1000).is_err());
        assert!(book.register_at(binding(), 16_001, 1000).is_err());
        book.shutdown();
        assert!(
            book.register_for(binding(), Duration::from_secs(1))
                .is_err()
        );
    }
    #[test]
    fn runtime_identity_parser_accepts_only_one_bounded_versioned_challenge() {
        let good = format!(r#"{{"version":1,"challenge":"{}"}}"#, "a".repeat(64));
        assert!(parse_proof(good.as_bytes()).is_ok());
        for bad in [
            good.replace("\"version\":1", "\"version\":2"),
            good.replace("\"version\":1", "\"version\":1,\"version\":1"),
            good.replace(&"a".repeat(64), &"a".repeat(63)),
            good.replace(&"a".repeat(64), &"A".repeat(64)),
            good.replace(
                "\"version\":1",
                "\"version\":1,\"password\":\"PRIVATE-CANARY\"",
            ),
        ] {
            assert!(parse_proof(bad.as_bytes()).is_err());
        }
        assert!(parse_proof(&[0xff]).is_err());
        assert!(parse_proof(&vec![b' '; 257]).is_err());
    }
    #[test]
    fn runtime_identity_wire_rejects_partial_trailing_and_stalled_input() {
        use std::io::Write;
        for bad in [
            vec![0, 0, 1, 1],
            vec![0, 0, 0, 2, b'{'],
            vec![0, 0, 0, 2, b'{', b'}', 0],
            vec![0, 0, 0, 0],
        ] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            client.write_all(&bad).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(read_proof(&mut server, Instant::now() + Duration::from_secs(1)).is_err());
        }
        let (mut server, _client) = UnixStream::pair().unwrap();
        let started = Instant::now();
        assert!(read_proof(&mut server, started + Duration::from_millis(80)).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}

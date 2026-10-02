// SPDX-License-Identifier: AGPL-3.0-only
//! Fixed Root metadata/termination transport. Contains no source or session bytes.
use crate::private_helper::connect_until;
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::identity::PeerIdentity;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
const PATH: &str = "/run/blindpass-private/manager.sock";
const FAILURE: &str = "runtime_management_unavailable";
pub(crate) struct RuntimeManagerClient {
    stream: UnixStream,
}
impl RuntimeManagerClient {
    pub(crate) fn connect() -> Result<Self, &'static str> {
        if crate::effective_uid() != 0 {
            return Err(FAILURE);
        }
        let before = protected()?;
        let stream =
            connect_until(std::path::Path::new(PATH), deadline(5000)?).map_err(|_| FAILURE)?;
        crate::os_identity::require_root_peer(&stream).map_err(|_| FAILURE)?;
        if protected()? != before {
            return Err(FAILURE);
        }
        stream.set_nonblocking(true).map_err(|_| FAILURE)?;
        Ok(Self { stream })
    }
    pub(crate) fn inspect(
        &mut self,
        peer: &PeerIdentity,
        browser: bool,
    ) -> Result<(), &'static str> {
        let reply = self.request("inspect", selection(peer, browser)?)?;
        if !exact(
            &reply,
            &[
                "type",
                "unit",
                "invocation",
                "uid",
                "networkIsolated",
                "profilePrivate",
            ],
        ) || reply.get("type").and_then(Value::as_str) != Some("runtime-verified")
            || reply.get("unit").and_then(Value::as_str) != peer.unit.as_deref()
            || reply.get("invocation").and_then(Value::as_str) != peer.invocation_id.as_deref()
            || reply.get("uid").and_then(Value::as_u64) != Some(u64::from(peer.uid))
            || reply.get("networkIsolated") != Some(&Value::Bool(browser))
            || reply.get("profilePrivate") != Some(&Value::Bool(browser))
        {
            return Err(FAILURE);
        }
        Ok(())
    }
    pub(crate) fn terminate(
        &mut self,
        peer: &PeerIdentity,
        browser: bool,
    ) -> Result<(), &'static str> {
        let reply = self.request("terminate", selection(peer, browser)?)?;
        if !exact(&reply, &["type", "terminated", "profileRemoved"])
            || reply.get("type").and_then(Value::as_str) != Some("runtime-terminated")
            || reply.get("terminated") != Some(&Value::Bool(true))
            || reply.get("profileRemoved") != Some(&Value::Bool(true))
        {
            return Err(FAILURE);
        }
        Ok(())
    }
    pub(crate) fn recover(&mut self) -> Result<(), &'static str> {
        let reply = self.exchange(Value::Object(vec![
            ("type".into(), Value::String("recover".into())),
            ("version".into(), Value::Unsigned(1)),
        ]))?;
        if !exact(&reply, &["type", "runtimesStopped", "backendsRemoved"])
            || reply.get("type").and_then(Value::as_str) != Some("runtime-recovered")
            || reply.get("runtimesStopped") != Some(&Value::Bool(true))
            || reply.get("backendsRemoved") != Some(&Value::Bool(true))
        {
            return Err(FAILURE);
        }
        Ok(())
    }
    fn request(&mut self, kind: &str, selection: Value) -> Result<Value, &'static str> {
        let value = Value::Object(vec![
            ("type".into(), Value::String(kind.into())),
            ("version".into(), Value::Unsigned(1)),
            ("selection".into(), selection),
        ]);
        self.exchange(value)
    }
    fn exchange(&mut self, value: Value) -> Result<Value, &'static str> {
        let body = canonicalize_value(&value).map_err(|_| FAILURE)?;
        let until = deadline(8000)?;
        let runnable_until = Instant::now() + Duration::from_secs(8);
        self.stream.set_nonblocking(true).map_err(|_| FAILURE)?;
        let result = (|| {
            transfer(
                &mut self.stream,
                &mut (body.len() as u32).to_be_bytes(),
                true,
                until,
                runnable_until,
            )?;
            transfer(
                &mut self.stream,
                &mut body.clone(),
                true,
                until,
                runnable_until,
            )?;
            let mut header = [0; 4];
            transfer(&mut self.stream, &mut header, false, until, runnable_until)?;
            let length = u32::from_be_bytes(header) as usize;
            if !(2..=1024).contains(&length) {
                return Err(());
            }
            let mut reply = vec![0; length];
            transfer(&mut self.stream, &mut reply, false, until, runnable_until)?;
            parse_json(std::str::from_utf8(&reply).map_err(|_| ())?).map_err(|_| ())
        })();
        result.map_err(|()| {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            FAILURE
        })
    }
}
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    returned: i16,
}
unsafe extern "C" {
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: i32) -> i32;
}
fn transfer(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    write: bool,
    until: u64,
    runnable_until: Instant,
) -> Result<(), ()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = until
            .checked_sub(crate::grants::boottime_ms().map_err(|_| ())?)
            .filter(|remaining| *remaining > 0)
            .ok_or(())?;
        let runnable = runnable_until
            .saturating_duration_since(Instant::now())
            .as_millis();
        if runnable == 0 {
            return Err(());
        }
        let mut fd = PollFd {
            fd: stream.as_raw_fd(),
            events: if write { 4 } else { 1 },
            returned: 0,
        };
        let timeout = remaining
            .min(250)
            .min(u64::try_from(runnable).map_err(|_| ())?) as i32;
        // SAFETY: one repr(C) pollfd remains owned/live; the fd belongs to stream.
        let ready = unsafe { poll(&raw mut fd, 1, timeout) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(());
        }
        if ready == 0 {
            continue;
        }
        let count = if write {
            stream.write(&bytes[offset..])
        } else {
            stream.read(&mut bytes[offset..])
        };
        match count {
            Ok(0) => return Err(()),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return Err(()),
        }
        if crate::grants::boottime_ms().map_err(|_| ())? >= until
            || Instant::now() >= runnable_until
        {
            return Err(());
        }
    }
    Ok(())
}
fn selection(peer: &PeerIdentity, browser: bool) -> Result<Value, &'static str> {
    let unit = peer.unit.as_deref().ok_or(FAILURE)?;
    let invocation = peer.invocation_id.as_deref().ok_or(FAILURE)?;
    if peer.uid == 0
        || !peer.pidfd_supported
        || peer.account.as_deref() != Some(format!("uid:{}", peer.uid).as_str())
        || !(if browser {
            crate::runtime_identity::valid_browser_unit(unit)
        } else {
            crate::runtime_identity::valid_helper_unit(unit)
        })
        || invocation.len() != 32
        || !invocation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FAILURE);
    }
    Ok(Value::Object(vec![
        (
            "kind".into(),
            Value::String(if browser { "browser" } else { "helper" }.into()),
        ),
        ("unit".into(), Value::String(unit.into())),
        ("invocation".into(), Value::String(invocation.into())),
        ("uid".into(), Value::Unsigned(u64::from(peer.uid))),
    ]))
}
fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == keys.len() && fields.iter().all(|(k, _)| keys.contains(&k.as_str()))
    })
}
fn deadline(window: u64) -> Result<u64, &'static str> {
    crate::grants::boottime_ms()
        .ok()
        .and_then(|now| now.checked_add(window))
        .ok_or(FAILURE)
}
fn protected() -> Result<(u64, u64), &'static str> {
    let parent = fs::symlink_metadata("/run/blindpass-private").map_err(|_| FAILURE)?;
    let socket = fs::symlink_metadata(PATH).map_err(|_| FAILURE)?;
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
        return Err(FAILURE);
    }
    Ok((socket.dev(), socket.ino()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_recovery_bounds_a_stalled_reply_and_closes_private_transport() {
        use std::io::{Read, Write};
        let (client, mut server) = UnixStream::pair().unwrap();
        let (stop, stopped) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            let mut header = [0; 4];
            server.read_exact(&mut header).unwrap();
            let mut body = vec![0; u32::from_be_bytes(header) as usize];
            server.read_exact(&mut body).unwrap();
            let body = parse_json(std::str::from_utf8(&body).unwrap()).unwrap();
            assert!(exact(&body, &["type", "version"]));
            server.write_all(&[0, 0]).unwrap(); // incomplete private header
            stopped
                .recv_timeout(std::time::Duration::from_secs(12))
                .unwrap();
            server
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            assert_eq!(server.read(&mut header).unwrap(), 0);
        });
        let mut client = RuntimeManagerClient { stream: client };
        let start = std::time::Instant::now();
        assert!(client.recover().is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        stop.send(()).unwrap();
        task.join().unwrap();
    }
    #[test]
    fn manager_selection_never_contains_a_pid_path_source_or_caller_extension() {
        let peer = PeerIdentity::fixture(
            61001,
            61001,
            "blindpass-browser@0-123-root.service",
            &"a".repeat(32),
            "uid:61001",
        );
        let value = selection(&peer, true).unwrap();
        assert!(exact(&value, &["kind", "unit", "invocation", "uid"]));
        assert!(selection(&peer, false).is_err());
        let mut wrong = peer.clone();
        wrong.unit = Some("ssh.service".into());
        assert!(selection(&wrong, true).is_err());
        let mut wrong = peer.clone();
        wrong.uid = 0;
        assert!(selection(&wrong, true).is_err());
        let mut wrong = peer;
        wrong.pidfd_supported = false;
        assert!(selection(&wrong, true).is_err());
    }
    #[test]
    fn native_manager_reply_checks_exact_kernel_binding_and_cleanup() {
        use std::io::{Read, Write};
        let (client, mut server) = UnixStream::pair().unwrap();
        let task = std::thread::spawn(move || {
            let mut header = [0; 4];
            server.read_exact(&mut header).unwrap();
            let mut body = vec![0; u32::from_be_bytes(header) as usize];
            server.read_exact(&mut body).unwrap();
            let request = parse_json(std::str::from_utf8(&body).unwrap()).unwrap();
            assert_eq!(request.get("type").and_then(Value::as_str), Some("inspect"));
            let reply=br#"{"type":"runtime-verified","unit":"blindpass-browser@0-123-root.service","invocation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","uid":61001,"networkIsolated":true,"profilePrivate":true}"#;
            server
                .write_all(&(reply.len() as u32).to_be_bytes())
                .unwrap();
            server.write_all(reply).unwrap();
        });
        let mut client = RuntimeManagerClient { stream: client };
        let peer = PeerIdentity::fixture(
            61001,
            61001,
            "blindpass-browser@0-123-root.service",
            &"a".repeat(32),
            "uid:61001",
        );
        assert!(client.inspect(&peer, true).is_ok());
        task.join().unwrap();
    }
}

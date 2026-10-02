// SPDX-License-Identifier: AGPL-3.0-only

//! Disposable VM probe, not a workload API. Input is private stdin; only fd 3
//! receives the protected framed reply. No source bytes or errors go to logs.

use blindpass_broker::private_helper::{HelperReply, HelperStatus, begin_private_login};
use blindpass_broker::runtime_identity::{RuntimeIdentityBook, RuntimeIdentityListener};
use blindpass_broker::session_journal::{SessionBinding, SessionJournal};
use blindpass_core::clock::{ClockSource, SystemClock};
use blindpass_core::secret::SecretBytes;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}
fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}
fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    // F_GETFD before adopting avoids constructing an owner for an absent fd.
    if unsafe { fcntl(3, 1) } < 0 {
        return Err(());
    }
    // Capture optional inherited fd 4 before any internal opens can reuse its
    // number; late adoption could steal a listener or journal descriptor.
    let mut observation = if unsafe { fcntl(4, 1) } >= 0 {
        // SAFETY: the VM harness transfers an optional owned socket fd 4.
        let file = unsafe { File::from_raw_fd(4) };
        if !file.metadata().map_err(|_| ())?.file_type().is_socket() {
            return Err(());
        }
        let stream = UnixStream::from(OwnedFd::from(file));
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| ())?;
        Some(stream)
    } else {
        None
    };
    // SAFETY: the harness passes exclusive ownership of this inherited fd.
    let output = unsafe { File::from_raw_fd(3) };
    if !output.metadata().map_err(|_| ())?.file_type().is_socket() {
        return Err(());
    }
    let mut output = UnixStream::from(OwnedFd::from(output));
    output
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())?;
    let mut input = Vec::new();
    let read = std::io::stdin().take(16_385).read_to_end(&mut input);
    let input = SecretBytes::new(input);
    let reply = if read.is_err() || input.is_empty() || input.len() > 16_384 {
        HelperReply::Status(HelperStatus::InvalidRequest)
    } else {
        verified_request(&input, &mut observation)
            .unwrap_or(HelperReply::Status(HelperStatus::Unavailable))
    };
    let body = match reply {
        HelperReply::Session(bytes) => bytes,
        HelperReply::Status(status) => {
            SecretBytes::new(format!("{{\"status\":\"{}\"}}", status.as_str()).into_bytes())
        }
    };
    output
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    output.write_all(body.as_bytes()).map_err(|_| ())?;
    Ok(())
}

fn verified_request(
    input: &SecretBytes,
    observation: &mut Option<UnixStream>,
) -> Result<HelperReply, ()> {
    // Disposable guest uses the administrator-installed local sysusers entry.
    // These values never come from the private job or caller JSON.
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|_| ())?;
    let fields: Vec<_> = passwd
        .lines()
        .find(|line| line.starts_with("blindpass-login:"))
        .ok_or(())?
        .split(':')
        .collect();
    let uid: u32 = fields.get(2).ok_or(())?.parse().map_err(|_| ())?;
    let group: u32 = fields.get(3).ok_or(())?.parse().map_err(|_| ())?;
    let book = Arc::new(RuntimeIdentityBook::new_private_helper());
    let listener =
        RuntimeIdentityListener::bind_private_helper(group, Arc::clone(&book)).map_err(|_| ())?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let handle = std::thread::spawn(move || listener.serve(stop_thread));
    let result = (|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())?;
        let operation = format!("helper-probe-{}-{}", std::process::id(), now.as_nanos());
        let time = u64::try_from(now.as_millis()).map_err(|_| ())?;
        let mut journal = SessionJournal::open().map_err(|_| ())?;
        journal
            .reserve(
                SessionBinding {
                    node_id: "helper-probe-node".into(),
                    workload_id: operation.clone(),
                    operation_id: operation.clone(),
                    idempotency_key: operation.clone(),
                    request_event_key: None,
                    workload_unit: format!("{operation}.service"),
                    workload_invocation: "a".repeat(32),
                    resource: "helper-probe-resource".into(),
                    recipe_fingerprint: "a".repeat(64),
                    account: operation.clone(),
                },
                time,
            )
            .map_err(|_| ())?;
        let deadline = u64::try_from(SystemClock.sample().map_err(|_| ())?.boottime_ms)
            .map_err(|_| ())?
            .checked_add(60_000)
            .ok_or(())?;
        let helper = begin_private_login(&book, uid, &[0], deadline).map_err(|_| ())?;
        // Optional private test observation; no challenge/identity/source data
        // or diagnostics are emitted. Production callers do not use this probe.
        if let Some(observation) = observation {
            observation.write_all(b"proof_verified\n").map_err(|_| ())?;
        }
        // Test-only Root gate: exercise source denial after successful kernel
        // proof and durable identity. It is not a workload-controlled option.
        let recorded = helper
            .record(&mut journal, &operation, time, deadline)
            .map_err(|_| ())?;
        if std::env::var_os("P05_PROBE_JOURNAL_WITHDRAW").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            journal.begin_revoke(&operation, time).map_err(|_| ())?;
        }
        Ok(recorded.request_guarded(
            input,
            || {
                std::env::var_os("P05_PROBE_SOURCE_DENY").as_deref()
                    != Some(std::ffi::OsStr::new("1"))
            },
            || true,
        ))
    })();
    stop.store(true, Ordering::Release);
    handle.join().map_err(|_| ())?.map_err(|_| ())?;
    result
}

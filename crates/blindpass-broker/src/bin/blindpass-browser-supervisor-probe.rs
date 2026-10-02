// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable Root VM driver of the production supervisor transport, running
//! under the broker's Unix-only/JIT-disabled sandbox. Private activated fd0;
//! no normal output, signed workload authority or reconciliation claim.
use blindpass_broker::BrowserResource;
use blindpass_broker::browser_supervisor::SupervisorClient;
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::clock::{ClockSource, SystemClock};
use blindpass_core::secret::{SecretBytes, wipe};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;
unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn mmap(
        address: *mut std::ffi::c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut std::ffi::c_void;
    fn mprotect(address: *mut std::ffi::c_void, length: usize, protection: i32) -> i32;
    fn munmap(address: *mut std::ffi::c_void, length: usize) -> i32;
}
fn verify_native_sandbox() -> Result<(), ()> {
    // Actual test-only APIs: no connect or executable code is attempted.
    let network = unsafe { socket(2, 1 | 0x80000, 0) };
    if network >= 0 {
        unsafe {
            close(network);
        }
        return Err(());
    }
    // SAFETY: own one anonymous 4KiB page until matching munmap, containing no
    // data/instructions and never dereferenced. Only an RX permission is tried.
    let page = unsafe { mmap(std::ptr::null_mut(), 4096, 3, 0x22, -1, 0) };
    if page as usize == usize::MAX {
        return Err(());
    }
    let denied = unsafe { mprotect(page, 4096, 5) } != 0;
    let released = unsafe { munmap(page, 4096) } == 0;
    if denied && released { Ok(()) } else { Err(()) }
}
fn main() {
    if run().is_err() {
        std::process::exit(70);
    }
}
fn clock() -> Result<(u64, u64), ()> {
    let time = SystemClock.sample().map_err(|_| ())?;
    Ok((
        u64::try_from(time.boottime_ms).map_err(|_| ())?,
        u64::try_from(time.host_wall_ms).map_err(|_| ())?,
    ))
}
fn window(deadline: u64) -> Result<Duration, ()> {
    let remaining = deadline
        .checked_sub(clock()?.0)
        .filter(|value| *value > 0)
        .ok_or(())?;
    Ok(Duration::from_millis(remaining.min(250)))
}
fn read(stream: &mut UnixStream, body: &mut [u8], deadline: u64) -> Result<(), ()> {
    let mut offset = 0;
    while offset < body.len() {
        stream
            .set_read_timeout(Some(window(deadline)?))
            .map_err(|_| ())?;
        match stream.read(&mut body[offset..]) {
            Ok(0) => return Err(()),
            Ok(count) => {
                window(deadline)?;
                offset += count;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(()),
        }
    }
    Ok(())
}
fn receive(stream: &mut UnixStream, deadline: u64) -> Result<Value, ()> {
    let mut length = [0; 4];
    read(stream, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if !(2..=65_536).contains(&length) {
        return Err(());
    }
    let mut body = vec![0; length];
    let result = read(stream, &mut body, deadline);
    let protected = SecretBytes::new(body);
    result?;
    parse_json(std::str::from_utf8(protected.as_bytes()).map_err(|_| ())?).map_err(|_| ())
}
fn send(stream: &mut UnixStream, value: Value) -> Result<(), ()> {
    let bytes = SecretBytes::new(canonicalize_value(&value).map_err(|_| ())?);
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ())?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    stream.write_all(bytes.as_bytes()).map_err(|_| ())
}
fn string(value: &str) -> Value {
    Value::String(value.into())
}
fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ()> {
    value.get(key).and_then(Value::as_str).ok_or(())
}
fn number(value: &Value, key: &str) -> Result<u64, ()> {
    value.get(key).and_then(Value::as_u64).ok_or(())
}
fn exact(value: &Value, keys: &[&str]) -> Result<(), ()> {
    if value.as_object().is_some_and(|entries| {
        entries.len() == keys.len() && entries.iter().all(|(key, _)| keys.contains(&key.as_str()))
    }) {
        Ok(())
    } else {
        Err(())
    }
}
fn clear(value: &mut Value) {
    match value {
        Value::String(text) => wipe(&mut std::mem::take(text).into_bytes()),
        Value::Array(values) => values.iter_mut().for_each(clear),
        Value::Object(values) => values.iter_mut().for_each(|(_, value)| clear(value)),
        _ => {}
    }
}
fn run() -> Result<(), ()> {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--socket"] {
        return Err(());
    }
    verify_native_sandbox()?;
    // SAFETY: the disposable installed unit exclusively transfers activated fd0.
    let file = unsafe { File::from_raw_fd(0) };
    if !file.metadata().map_err(|_| ())?.file_type().is_socket() {
        return Err(());
    }
    let mut parent = UnixStream::from(OwnedFd::from(file));
    blindpass_broker::os_identity::require_root_peer(&parent).map_err(|_| ())?;
    let mut deadline = clock()?.0 + 120_000;
    let mut client = None;
    let mut resource = None;
    let mut revoker = None;
    let mut done = false;
    while !done {
        let mut input = receive(&mut parent, deadline)?;
        let handled = (|| {
            let kind = text(&input, "type")?;
            match kind {
                "revocation-preflight" => {
                    exact(
                        &input,
                        &[
                            "type",
                            "configuration",
                            "profile",
                            "credential",
                            "operationId",
                            "deadlineBoottimeMs",
                        ],
                    )?;
                    if revoker.is_some() || client.is_some() {
                        return Err(());
                    }
                    deadline = number(&input, "deadlineBoottimeMs")?;
                    let recipe = BrowserResource::from_value(&object(vec![
                        ("resource_id", string("p05-component")),
                        ("workload_ids", Value::Array(vec![string("p05-agent")])),
                        ("credential_unit", string("blindpass-login-helper@.service")),
                        ("credential_name", string("primary-password")),
                        (
                            "configuration",
                            input.get("configuration").ok_or(())?.clone(),
                        ),
                        ("revocation", input.get("profile").ok_or(())?.clone()),
                    ]))
                    .map_err(|_| ())?;
                    let runtime = blindpass_broker::session_revoker::RevocationClient::prepare(
                        &recipe,
                        text(&input, "operationId")?,
                        &SecretBytes::from_slice(text(&input, "credential")?.as_bytes()),
                        deadline,
                    )
                    .map_err(|_| ())?;
                    if !runtime.ready_for(&recipe, text(&input, "operationId")?) {
                        return Err(());
                    }
                    revoker = Some(runtime);
                    Ok(object(vec![("type", string("revocation-ready"))]))
                }
                "revocation-session" => {
                    exact(&input, &["type", "handle"])?;
                    let handle = input.get("handle").ok_or(())?;
                    let handle = match text(handle, "kind")? {
                        "fixture" => {
                            exact(handle, &["kind", "account", "sessionReference"])?;
                            blindpass_broker::session_journal::RevokeHandle::Fixture {
                                account: text(handle, "account")?.into(),
                                session_reference: text(handle, "sessionReference")?.into(),
                            }
                        }
                        "grafana-managed" => {
                            exact(handle, &["kind", "account", "userId", "orgId"])?;
                            blindpass_broker::session_journal::RevokeHandle::GrafanaManaged {
                                account: text(handle, "account")?.into(),
                                user_id: u32::try_from(number(handle, "userId")?)
                                    .map_err(|_| ())?,
                                org_id: u32::try_from(number(handle, "orgId")?).map_err(|_| ())?,
                            }
                        }
                        _ => return Err(()),
                    };
                    revoker
                        .as_mut()
                        .ok_or(())?
                        .revoke_session(&handle)
                        .map_err(|_| ())?;
                    Ok(object(vec![("type", string("revoked"))]))
                }
                "revocation-account" => {
                    exact(&input, &["type"])?;
                    revoker
                        .as_mut()
                        .ok_or(())?
                        .revoke_account()
                        .map_err(|_| ())?;
                    Ok(object(vec![("type", string("revoked"))]))
                }
                "revocation-close" => {
                    exact(&input, &["type"])?;
                    revoker.as_mut().ok_or(())?.close().map_err(|_| ())?;
                    done = true;
                    Ok(object(vec![("type", string("revocation-closed"))]))
                }
                "start" => {
                    exact(
                        &input,
                        &[
                            "type",
                            "version",
                            "operationId",
                            "configuration",
                            "deadlineBoottimeMs",
                        ],
                    )?;
                    if client.is_some() || number(&input, "version")? != 1 {
                        return Err(());
                    }
                    deadline = number(&input, "deadlineBoottimeMs")?;
                    let recipe = BrowserResource::from_value(&object(vec![
                        ("resource_id", string("p05-component")),
                        ("workload_ids", Value::Array(vec![string("p05-agent")])),
                        ("credential_unit", string("blindpass-login-helper@.service")),
                        ("credential_name", string("primary-password")),
                        (
                            "configuration",
                            input.get("configuration").ok_or(())?.clone(),
                        ),
                    ]))
                    .map_err(|_| ())?;
                    let mut runtime = SupervisorClient::connect(deadline).map_err(|_| ())?;
                    let prepared = runtime
                        .prepare(&recipe, text(&input, "operationId")?)
                        .map_err(|_| ())?;
                    let (pid, invocation, path) = prepared.discovery_hint();
                    let reply = object(vec![
                        ("type", string("prepared")),
                        ("version", Value::Unsigned(1)),
                        ("pid", Value::Unsigned(u64::from(pid))),
                        ("invocation", string(invocation)),
                        ("devtoolsPath", string(path)),
                    ]);
                    resource = Some(recipe);
                    client = Some(runtime);
                    Ok(reply)
                }
                "prove" => {
                    exact(&input, &["type", "version", "challenge"])?;
                    if number(&input, "version")? != 1 {
                        return Err(());
                    }
                    client
                        .as_mut()
                        .ok_or(())?
                        .prove(&SecretBytes::from_slice(
                            text(&input, "challenge")?.as_bytes(),
                        ))
                        .map_err(|_| ())?;
                    Ok(object(vec![("type", string("identity-proved"))]))
                }
                "import" => {
                    exact(
                        &input,
                        &[
                            "type",
                            "originalDeadlineMs",
                            "sessionDeadlineBoottimeMs",
                            "cookies",
                            "revokeHandle",
                        ],
                    )?;
                    let mut envelope = object(vec![
                        ("status", string("authenticated")),
                        (
                            "originalDeadlineMs",
                            Value::Unsigned(number(&input, "originalDeadlineMs")?),
                        ),
                        ("cookies", input.get("cookies").ok_or(())?.clone()),
                        ("revokeHandle", input.get("revokeHandle").ok_or(())?.clone()),
                    ]);
                    let protected = canonicalize_value(&envelope).map(SecretBytes::new);
                    clear(&mut envelope);
                    let session = resource
                        .as_ref()
                        .ok_or(())?
                        .validate_session(protected.map_err(|_| ())?, clock()?.1)
                        .map_err(|_| ())?;
                    let session_deadline = number(&input, "sessionDeadlineBoottimeMs")?;
                    client
                        .as_mut()
                        .ok_or(())?
                        .import(&session, session_deadline)
                        .map_err(|_| ())?;
                    deadline = session_deadline;
                    Ok(object(vec![("type", string("imported"))]))
                }
                "publish" => {
                    exact(&input, &["type"])?;
                    let handle = client.as_mut().ok_or(())?.publish().map_err(|_| ())?;
                    Ok(object(vec![
                        ("type", string("published")),
                        ("contextHandle", string(&handle)),
                    ]))
                }
                "stop" => {
                    exact(&input, &["type"])?;
                    client.as_mut().ok_or(())?.stop().map_err(|_| ())?;
                    done = true;
                    Ok(object(vec![("type", string("stopped"))]))
                }
                _ => Err(()),
            }
        })();
        clear(&mut input);
        match handled {
            Ok(reply) => send(&mut parent, reply)?,
            Err(()) => {
                let _ = send(&mut parent, object(vec![("type", string("uncertain"))]));
                return Err(());
            }
        }
    }
    Ok(())
}

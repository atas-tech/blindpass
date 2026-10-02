// SPDX-License-Identifier: AGPL-3.0-only
// Disposable root VM probe of the production proxy component. Its stdin lease
// is synthetic test metadata; this is not a signed-grant workload entrypoint.
use blindpass_broker::browser_proxy::{
    BrowserPeerBinding, BrowserProxy, BrowserProxySlot, ProxyError, ReadyBrowserContext,
};
use blindpass_core::canon::{Value, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::secret::SecretBytes;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn main() {
    if run().is_err() {
        std::process::exit(70);
    }
}

fn line(input: &mut impl Read, limit: usize) -> Result<SecretBytes, ()> {
    let mut bytes = Vec::new();
    while bytes.len() < limit {
        let mut byte = [0];
        match input.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(SecretBytes::new(bytes)),
            Ok(0) => return Err(()),
            Ok(_) if byte[0] == b'\n' => return Ok(SecretBytes::new(bytes)),
            Ok(_) => bytes.push(byte[0]),
            Err(_) => return Err(()),
        }
    }
    Err(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ()> {
    value.get(key).and_then(Value::as_str).ok_or(())
}
fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let mut input = std::io::stdin().lock();
    let protected = line(&mut input, 16_384)?;
    let value =
        parse_json(std::str::from_utf8(protected.as_bytes()).map_err(|_| ())?).map_err(|_| ())?;
    let fields = value.as_object().ok_or(())?;
    let keys = [
        "version",
        "uid",
        "group",
        "unit",
        "invocation",
        "devtoolsPath",
        "deadlineBoottimeMs",
    ];
    if fields.len() != keys.len()
        || keys.iter().any(|key| value.get(key).is_none())
        || value.get("version").and_then(Value::as_u64) != Some(1)
    {
        return Err(());
    }
    let uid = u32::try_from(value.get("uid").and_then(Value::as_u64).ok_or(())?).map_err(|_| ())?;
    let group =
        u32::try_from(value.get("group").and_then(Value::as_u64).ok_or(())?).map_err(|_| ())?;
    let deadline = value
        .get("deadlineBoottimeMs")
        .and_then(Value::as_u64)
        .ok_or(())?;
    let binding = BrowserPeerBinding::new(
        "p05-agent",
        text(&value, "unit")?,
        uid,
        text(&value, "invocation")?,
    )
    .map_err(|_| ())?;
    let authorized = Arc::new(AtomicBool::new(true));
    let current = Arc::clone(&authorized);
    let context = ReadyBrowserContext::new(
        binding,
        deadline,
        text(&value, "devtoolsPath")?,
        Arc::new(move || current.load(Ordering::Acquire)),
        Arc::new(|until| {
            if std::time::Instant::now() >= until {
                return Err(ProxyError::Unavailable);
            }
            // This disposable probe selects exactly one test operation's
            // production supervisor backend; stdin cannot select a path.
            let digest =
                sha256(b"p05_outside_supervisor_probe").map_err(|_| ProxyError::Unavailable)?;
            let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            let directory = format!("/run/blindpass-backends/{hash}");
            for parent in ["/run/blindpass-backends", directory.as_str()] {
                let metadata =
                    std::fs::symlink_metadata(parent).map_err(|_| ProxyError::Unavailable)?;
                if !metadata.is_dir()
                    || metadata.uid() != 0
                    || metadata.gid() != 0
                    || metadata.mode() & 0o7777 != 0o700
                {
                    return Err(ProxyError::Unavailable);
                }
            }
            let path = format!("{directory}/cdp.sock");
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ProxyError::Unavailable)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(ProxyError::Unavailable);
            }
            let stream = UnixStream::connect(path).map_err(|_| ProxyError::Unavailable)?;
            blindpass_broker::os_identity::require_root_peer(&stream)
                .map_err(|_| ProxyError::Unavailable)?;
            stream
                .set_write_timeout(Some(Duration::from_millis(50)))
                .map_err(|_| ProxyError::Unavailable)?;
            Ok(stream)
        }),
    )
    .map_err(|_| ())?;
    drop(value);
    drop(protected);
    let slot = Arc::new(BrowserProxySlot::new());
    slot.activate(context).map_err(|_| ())?;
    let proxy = BrowserProxy::bind("p05-agent", group, Arc::clone(&slot)).map_err(|_| ())?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let task = std::thread::spawn(move || {
        proxy.serve(
            server_stop,
            Arc::new(|result| {
                let status = match result {
                    Ok(()) => "closed",
                    Err(ProxyError::Denied) => "denied",
                    Err(ProxyError::Revoked) => "revoked",
                    Err(_) => "unavailable",
                };
                println!("{{\"type\":\"outcome\",\"status\":\"{status}\"}}");
            }),
        )
    });
    println!("{{\"type\":\"ready\"}}");
    std::io::stdout().flush().map_err(|_| ())?;
    loop {
        let command = line(&mut input, 128)?;
        match command.as_bytes() {
            b"clear" => {
                authorized.store(false, Ordering::Release);
                slot.clear();
                println!("{{\"type\":\"cleared\"}}");
            }
            b"stop" | b"" => break,
            _ => {
                authorized.store(false, Ordering::Release);
                slot.clear();
                break;
            }
        }
    }
    stop.store(true, Ordering::Release);
    slot.clear();
    task.join().map_err(|_| ())?.map_err(|_| ())
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable root VM driver of the actual reverse pidfd proof component.
//! Expected identity arrives on private stdin; only fd 3 receives the challenge.
//! This does not replace production signed-grant and journal orchestration.
use blindpass_broker::runtime_identity::{
    RuntimeBinding, RuntimeIdentityBook, RuntimeIdentityListener,
};
use blindpass_core::canon::{Value, parse_json};
use blindpass_core::secret::SecretBytes;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}
fn main() {
    if run().is_err() {
        std::process::exit(70);
    }
}
fn line(input: &mut impl Read, limit: usize) -> Result<SecretBytes, ()> {
    let mut bytes = Vec::new();
    let result = (|| {
        while bytes.len() < limit {
            let mut byte = [0];
            match input.read(&mut byte) {
                Ok(0) if bytes.is_empty() => return Ok(()),
                Ok(0) => return Err(()),
                Ok(_) if byte[0] == b'\n' => return Ok(()),
                Ok(_) => bytes.push(byte[0]),
                Err(_) => return Err(()),
            }
        }
        Err(())
    })();
    let bytes = SecretBytes::new(bytes);
    result?;
    Ok(bytes)
}
fn number(value: &Value, key: &str) -> Result<u32, ()> {
    u32::try_from(value.get(key).and_then(Value::as_u64).ok_or(())?).map_err(|_| ())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ()> {
    value.get(key).and_then(Value::as_str).ok_or(())
}
fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 || unsafe { fcntl(3, 1) } < 0 {
        return Err(());
    }
    // SAFETY: the VM harness transfers exclusive ownership of inherited fd 3.
    let output = unsafe { File::from_raw_fd(3) };
    if !output.metadata().map_err(|_| ())?.file_type().is_socket() {
        return Err(());
    }
    let mut output = UnixStream::from(OwnedFd::from(output));
    output
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ())?;
    let mut input = std::io::stdin().lock();
    let protected = line(&mut input, 4096)?;
    let value =
        parse_json(std::str::from_utf8(protected.as_bytes()).map_err(|_| ())?).map_err(|_| ())?;
    let helper = value.get("version").and_then(Value::as_u64) == Some(2);
    let keys: &[&str] = if helper {
        &["version", "uid", "group", "workloadUid", "browserUid"]
    } else {
        &[
            "version",
            "unit",
            "invocation",
            "uid",
            "group",
            "helperUid",
            "workloadUid",
        ]
    };
    if value
        .as_object()
        .is_none_or(|fields| fields.len() != keys.len())
        || keys.iter().any(|key| value.get(key).is_none())
        || !matches!(value.get("version").and_then(Value::as_u64), Some(1 | 2))
    {
        return Err(());
    }
    let binding = if helper {
        RuntimeBinding::private_helper(
            number(&value, "uid")?,
            &[
                0,
                number(&value, "workloadUid")?,
                number(&value, "browserUid")?,
            ],
        )
    } else {
        RuntimeBinding::new(
            text(&value, "unit")?,
            text(&value, "invocation")?,
            number(&value, "uid")?,
            &[
                0,
                number(&value, "helperUid")?,
                number(&value, "workloadUid")?,
            ],
        )
    }
    .map_err(|_| ())?;
    let book = Arc::new(if helper {
        RuntimeIdentityBook::new_private_helper()
    } else {
        RuntimeIdentityBook::new()
    });
    let listener = if helper {
        RuntimeIdentityListener::bind_private_helper(number(&value, "group")?, Arc::clone(&book))
    } else {
        RuntimeIdentityListener::bind(number(&value, "group")?, Arc::clone(&book))
    }
    .map_err(|_| ())?;
    drop(value);
    drop(protected);
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop);
    let task = std::thread::spawn(move || listener.serve(server_stop));
    let result = (|| {
        let ticket = book
            .register_for(binding, Duration::from_secs(15))
            .map_err(|_| ())?;
        output
            .write_all(ticket.challenge().as_bytes())
            .map_err(|_| ())?;
        output.shutdown(std::net::Shutdown::Write).map_err(|_| ())?;
        drop(output);
        println!("{{\"type\":\"identity-ready\"}}");
        std::io::stdout().flush().map_err(|_| ())?;
        let runtime = ticket.wait().map_err(|_| ())?;
        println!("{{\"type\":\"identity-verified\"}}");
        std::io::stdout().flush().map_err(|_| ())?;
        loop {
            let command = line(&mut input, 128)?;
            match command.as_bytes() {
                b"check" => {
                    let status = if runtime.ensure_alive().is_ok() {
                        "alive"
                    } else {
                        "exited"
                    };
                    println!("{{\"type\":\"identity-status\",\"status\":\"{status}\"}}");
                    std::io::stdout().flush().map_err(|_| ())?;
                }
                b"stop" | b"" => break,
                _ => return Err(()),
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    task.join().map_err(|_| ())?.map_err(|_| ())?;
    result
}

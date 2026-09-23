// SPDX-License-Identifier: AGPL-3.0-only

//! Disposable transport probe used by the real-systemd P01 harness.
//! It connects without sending a frame so the broker's bounded read deadline
//! is exercised against a real peer and socket.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-transport-probe: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut socket = PathBuf::from("/run/blindpass/loader.sock");
    let mut hold = Duration::from_secs(3);
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--socket" => socket = PathBuf::from(next(&args, &mut index)?),
            "--hold-ms" => {
                hold = Duration::from_millis(
                    next(&args, &mut index)?
                        .parse()
                        .map_err(|_| "--hold-ms must be an integer".to_owned())?,
                )
            }
            "--help" | "-h" => {
                println!("blindpass-transport-probe --socket PATH [--hold-ms N]");
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }

    let started = Instant::now();
    let stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let mut reader = stream.try_clone().map_err(|error| error.to_string())?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut response = [0; 512];
        let result = reader
            .read(&mut response)
            .map(|length| response[..length].to_vec())
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });
    let response = match receiver.recv_timeout(hold) {
        Ok(result) => result?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            let _ = reader_thread.join();
            return Err("broker read deadline was not observed before the hold bound".to_owned());
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            let _ = reader_thread.join();
            return Err("reader thread disconnected".to_owned());
        }
    };
    let _ = stream.shutdown(std::net::Shutdown::Both);
    reader_thread
        .join()
        .map_err(|_| "reader thread panicked".to_owned())?;
    if !response.starts_with(b"ERR ") {
        return Err(format!(
            "broker did not reject stalled frame: {:?}",
            String::from_utf8_lossy(&response)
        ));
    }
    println!(
        "STALL_DENIED elapsed_ms={} response_code={}",
        started.elapsed().as_millis(),
        String::from_utf8_lossy(&response).trim()
    );
    Ok(())
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}

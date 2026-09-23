// SPDX-License-Identifier: AGPL-3.0-only

//! Small non-root workload probe used by the disposable systemd VM harness.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-workload-client: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut socket = PathBuf::from("/run/blindpass/workload.sock");
    let mut node = None;
    let mut workload = None;
    let mut unit = None;
    let mut invocation = std::env::var("INVOCATION_ID").ok();
    let mut operation = "health".to_owned();
    let mut hold_seconds = 0u64;
    let mut startup_delay = Duration::ZERO;
    let mut pre_request_delay = Duration::ZERO;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--socket" => socket = PathBuf::from(next(&args, &mut index)?),
            "--node" => node = Some(next(&args, &mut index)?),
            "--workload" => workload = Some(next(&args, &mut index)?),
            "--unit" => unit = Some(next(&args, &mut index)?),
            "--invocation" => invocation = Some(next(&args, &mut index)?),
            "--operation" => operation = next(&args, &mut index)?,
            "--hold-seconds" => {
                hold_seconds = next(&args, &mut index)?
                    .parse()
                    .map_err(|_| "--hold-seconds must be an integer".to_owned())?;
            }
            "--startup-delay-ms" => {
                startup_delay = Duration::from_millis(
                    next(&args, &mut index)?
                        .parse()
                        .map_err(|_| "--startup-delay-ms must be an integer".to_owned())?,
                );
            }
            "--pre-request-delay-ms" => {
                pre_request_delay = Duration::from_millis(
                    next(&args, &mut index)?
                        .parse()
                        .map_err(|_| "--pre-request-delay-ms must be an integer".to_owned())?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "blindpass-workload-client --node NODE --workload ID --unit UNIT \\
                     [--invocation ID] [--operation NAME] [--hold-seconds N] \\
                     [--startup-delay-ms N] [--pre-request-delay-ms N]"
                );
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }

    let node = node.ok_or("--node is required")?;
    let workload = workload.ok_or("--workload is required")?;
    let unit = unit.ok_or("--unit is required")?;
    let invocation = invocation.ok_or("--invocation or INVOCATION_ID is required")?;
    let frame = format!("WORK {node} {workload} {unit} {invocation} {operation}\n");

    if !startup_delay.is_zero() {
        std::thread::sleep(startup_delay);
    }

    let mut last_error: Option<String> = None;
    let mut delayed_before_request = pre_request_delay.is_zero();
    // The VM harness starts this unit first so that it can read the systemd
    // invocation ID before registering the workload with the broker.
    for _attempt in 0..600 {
        match UnixStream::connect(&socket) {
            Ok(mut stream) => {
                if !delayed_before_request {
                    std::thread::sleep(pre_request_delay);
                    delayed_before_request = true;
                }
                let response = (|| -> Result<Vec<u8>, String> {
                    stream
                        .write_all(frame.as_bytes())
                        .map_err(|error| error.to_string())?;
                    stream
                        .shutdown(std::net::Shutdown::Write)
                        .map_err(|error| error.to_string())?;
                    let mut response = Vec::new();
                    stream
                        .read_to_end(&mut response)
                        .map_err(|error| error.to_string())?;
                    Ok(response)
                })();
                match response {
                    Ok(response) if response.starts_with(b"OK ") => {
                        println!("WORKLOAD_READY");
                        if hold_seconds > 0 {
                            std::thread::sleep(Duration::from_secs(hold_seconds));
                        }
                        return Ok(());
                    }
                    Ok(response) => {
                        last_error = Some(String::from_utf8_lossy(&response).trim().to_owned());
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "workload socket unavailable: {}",
        last_error.unwrap_or_else(|| "unknown error".to_owned())
    ))
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}

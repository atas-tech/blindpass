// SPDX-License-Identifier: AGPL-3.0-only

//! Small non-root workload probe used by the disposable systemd VM harness.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const ROOT_OWNED_GRANT_FILE_MODE: u32 = 0o640;
const O_NOFOLLOW: i32 = 0x20000;

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
    let mut grant_file = None;
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
            "--grant-file" => grant_file = Some(PathBuf::from(next(&args, &mut index)?)),
            "--help" | "-h" => {
                println!(
                    "blindpass-workload-client --node NODE --workload ID --unit UNIT \\
                     [--invocation ID] [--operation NAME] [--hold-seconds N] \\
                     [--startup-delay-ms N] [--pre-request-delay-ms N] [--grant-file PATH]"
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
    if let Some(path) = grant_file.as_ref()
        && (!path.is_absolute() || !operation.starts_with("request:"))
    {
        return Err("--grant-file requires an absolute path and a request operation".to_owned());
    }
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
                        println!("{}", operation_output(&operation, &response)?);
                        if let Some(grant_file) = grant_file.as_ref() {
                            let grant_id = wait_for_grant(grant_file)?;
                            let consume = format!("consume:{grant_id}");
                            let consume_frame =
                                format!("WORK {node} {workload} {unit} {invocation} {consume}\n");
                            let response = send_work_frame(&socket, &consume_frame)?;
                            println!("{}", operation_output(&consume, &response)?);
                        }
                        if hold_seconds > 0 {
                            std::thread::sleep(Duration::from_secs(hold_seconds));
                        }
                        return Ok(());
                    }
                    Ok(response) => {
                        if let Some(reason) = permanent_workload_error(&response) {
                            return Err(reason.to_owned());
                        }
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

fn operation_output(operation: &str, response: &[u8]) -> Result<String, String> {
    let response =
        std::str::from_utf8(response).map_err(|_| "broker response was malformed".to_owned())?;
    let response = response.strip_suffix('\n').unwrap_or(response);
    if operation.starts_with("request:") {
        let event_key = response
            .strip_prefix("OK operation_request ")
            .filter(|key| valid_opaque_id(key))
            .ok_or_else(|| "broker did not accept the operation request".to_owned())?;
        return Ok(format!("OPERATION_REQUEST {event_key}"));
    }
    if let Some(grant_id) = operation.strip_prefix("consume:") {
        if response == format!("OK operation_completed {grant_id}") {
            return Ok(format!("OPERATION_COMPLETED {grant_id}"));
        }
        if response.starts_with("OK operation_uncertain ") {
            return Err("operation result is uncertain".to_owned());
        }
        return Err("broker did not complete the operation".to_owned());
    }
    if response.starts_with("OK ") {
        return Ok("WORKLOAD_READY".to_owned());
    }
    Err("broker rejected the workload request".to_owned())
}

fn permanent_workload_error(response: &[u8]) -> Option<&'static str> {
    match response.strip_suffix(b"\n").unwrap_or(response) {
        b"ERR operation_request_is_denied_by_local_policy" => {
            Some("operation request was denied by local policy")
        }
        b"ERR node_revoked" => Some("node identity is revoked"),
        _ => None,
    }
}

fn wait_for_grant(path: &std::path::Path) -> Result<String, String> {
    for _attempt in 0..6_000 {
        match read_grant_id(path) {
            Ok(grant_id) => return Ok(grant_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return Err("grant file is unsafe or unreadable".to_owned()),
        }
    }
    Err("timed out waiting for an approved grant".to_owned())
}

fn read_grant_id(path: &std::path::Path) -> Result<String, std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "grant path has no parent")
    })?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != 0
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "grant directory ownership or mode is unsafe",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != ROOT_OWNED_GRANT_FILE_MODE
        || metadata.len() > 130
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "grant file ownership or mode is unsafe",
        ));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)?;
    let source = std::str::from_utf8(&contents)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid grant id"))?;
    let grant_id = source.strip_suffix('\n').unwrap_or(source);
    if grant_id.contains('\n') || !valid_opaque_id(grant_id) || !grant_id.starts_with("gr_") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid grant id",
        ));
    }
    Ok(grant_id.to_owned())
}

fn send_work_frame(socket: &std::path::Path, frame: &str) -> Result<Vec<u8>, String> {
    let mut last_error = None;
    for _attempt in 0..600 {
        match UnixStream::connect(socket) {
            Ok(mut stream) => {
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
                    Ok(response) if response.starts_with(b"OK ") => return Ok(response),
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

fn valid_opaque_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{operation_output, permanent_workload_error};

    #[test]
    fn permanent_policy_and_revocation_errors_do_not_need_retrying() {
        assert_eq!(
            permanent_workload_error(b"ERR operation_request_is_denied_by_local_policy\n"),
            Some("operation request was denied by local policy")
        );
        assert_eq!(
            permanent_workload_error(b"ERR node_revoked\n"),
            Some("node identity is revoked")
        );
        assert_eq!(
            permanent_workload_error(b"ERR workload_registration_is_unavailable\n"),
            None
        );
        assert_eq!(
            permanent_workload_error(b"ERR trusted_time_unavailable\n"),
            None
        );
    }

    #[test]
    fn operation_request_reports_only_the_broker_event_key() {
        assert_eq!(
            operation_output(
                "request:eyJhY3Rpb24iOiJub29wLm1hcmtlciJ9",
                b"OK operation_request event_key_0123456789\n"
            )
            .unwrap(),
            "OPERATION_REQUEST event_key_0123456789"
        );
        assert!(operation_output("request:x", b"OK operation_request bad!\n").is_err());
    }

    #[test]
    fn consume_reports_only_a_completed_marker_and_rejects_uncertainty() {
        let grant_id = "gr_0123456789abcdef0123456789abcdef";
        assert_eq!(
            operation_output(
                &format!("consume:{grant_id}"),
                format!("OK operation_completed {grant_id}\n").as_bytes()
            )
            .unwrap(),
            format!("OPERATION_COMPLETED {grant_id}")
        );
        assert!(
            operation_output(
                &format!("consume:{grant_id}"),
                b"OK operation_uncertain gr_0123456789abcdef0123456789abcdef\n"
            )
            .is_err()
        );
    }
}

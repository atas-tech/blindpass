// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_CONTROL_SOCKET: &str = "/run/blindpass/control.sock";
const MAX_STATUS_RESPONSE: usize = 256;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-node: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    let Some(command) = arguments.first().map(String::as_str) else {
        print_help();
        return Err("a command is required".to_owned());
    };
    let socket = parse_socket(&arguments[1..])?;
    match command {
        "status" => status(&socket),
        "run" => Err(
            "node channel configuration is not available until enrollment and issuer pinning are complete"
                .to_owned(),
        ),
        "enroll" => Err("enrollment is not available until the controller enrollment API is configured".to_owned()),
        "--help" | "-h" | "help" => {
            print_help();
            Ok(())
        }
        unknown => Err(format!("unknown command {unknown}")),
    }
}

fn parse_socket(arguments: &[String]) -> Result<PathBuf, String> {
    let mut socket = PathBuf::from(DEFAULT_CONTROL_SOCKET);
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--socket" => {
                index += 1;
                let value = arguments.get(index).ok_or("--socket requires a path")?;
                socket = PathBuf::from(value);
                if !socket.is_absolute() {
                    return Err("--socket path must be absolute".to_owned());
                }
            }
            unknown => return Err(format!("unknown option {unknown}")),
        }
        index += 1;
    }
    Ok(socket)
}

fn status(socket: &Path) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "could not connect to the local broker control socket".to_owned())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "could not configure the control socket timeout".to_owned())?;
    stream
        .write_all(b"STATUS\n")
        .map_err(|_| "could not query the local broker".to_owned())?;
    let mut response = Vec::new();
    stream
        .take((MAX_STATUS_RESPONSE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| "could not read the local broker status".to_owned())?;
    if response.len() > MAX_STATUS_RESPONSE || !response.ends_with(b"\n") {
        return Err("invalid response from the local broker".to_owned());
    }
    let response = std::str::from_utf8(&response)
        .map_err(|_| "invalid response from the local broker".to_owned())?;
    if response != "OK blindpass-control/1\n" {
        return Err("the local broker did not accept the status request".to_owned());
    }
    println!("broker_control=ready protocol=blindpass-control/1");
    Ok(())
}

fn print_help() {
    println!(
        "blindpass-node <run|enroll|status> [--socket PATH]\n\n\
         status queries the local broker control socket."
    );
}

#[cfg(test)]
mod tests {
    use super::{parse_socket, run};
    use std::path::PathBuf;

    #[test]
    fn node_cli_accepts_only_absolute_socket_paths() {
        assert_eq!(
            parse_socket(&["--socket".to_owned(), "/tmp/control.sock".to_owned()]).unwrap(),
            PathBuf::from("/tmp/control.sock")
        );
        assert!(parse_socket(&["--socket".to_owned(), "relative.sock".to_owned()]).is_err());
        assert!(parse_socket(&["--unexpected".to_owned()]).is_err());
    }

    #[test]
    fn network_commands_fail_closed_before_enrollment_is_configured() {
        assert!(run(vec!["run".to_owned()]).is_err());
        assert!(run(vec!["enroll".to_owned()]).is_err());
    }
}

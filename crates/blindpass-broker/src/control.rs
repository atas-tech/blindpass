// SPDX-License-Identifier: AGPL-3.0-only

//! Local relay socket. This listener accepts no network connections.

use crate::BrokerError;
use crate::os_identity::require_control_peer;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_CONTROL_LINE_BYTES: usize = 128;
const MAX_CONTROL_DOCUMENT_BYTES: usize = 64 * 1024;

pub(crate) fn handle_connection(
    stream: &mut UnixStream,
    expected_group: Option<u32>,
    deadline: Instant,
) -> Result<(), BrokerError> {
    require_control_peer(stream, expected_group)?;
    let command = read_line(stream, deadline)?;
    match command.as_slice() {
        b"STATUS\n" => stream.write_all(b"OK blindpass-control/1\n")?,
        b"PULL_EVENTS\n" => stream.write_all(b"EVENTS 0\n")?,
        _ if command.starts_with(b"RELAY ") => {
            let length = parse_relay_length(&command)?;
            let mut document = vec![0; length];
            read_exact_until(stream, &mut document, deadline)?;
            stream.write_all(b"ERR issuer_not_configured\n")?;
        }
        _ => stream.write_all(b"ERR invalid_control_command\n")?,
    }
    Ok(())
}

fn parse_relay_length(command: &[u8]) -> Result<usize, BrokerError> {
    if command.len() < 8 || command.last() != Some(&b'\n') {
        return Err(BrokerError::Configuration("invalid_control_command"));
    }
    let value = std::str::from_utf8(&command[6..command.len() - 1])
        .map_err(|_| BrokerError::Configuration("invalid_control_command"))?;
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BrokerError::Configuration("invalid_control_command"));
    }
    let length = value
        .parse::<usize>()
        .map_err(|_| BrokerError::Configuration("invalid_control_command"))?;
    if !(1..=MAX_CONTROL_DOCUMENT_BYTES).contains(&length) {
        return Err(BrokerError::Configuration("invalid_control_document_size"));
    }
    Ok(length)
}

fn read_line(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, BrokerError> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0; 1];
        read_exact_until(stream, &mut byte, deadline)?;
        line.push(byte[0]);
        if line.len() > MAX_CONTROL_LINE_BYTES {
            return Err(BrokerError::Configuration("control_line_too_large"));
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn read_exact_until(
    stream: &mut UnixStream,
    value: &mut [u8],
    deadline: Instant,
) -> Result<(), BrokerError> {
    let mut offset = 0;
    while offset < value.len() {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                BrokerError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control request deadline exceeded",
                ))
            })?;
        stream.set_read_timeout(Some(timeout.min(Duration::from_secs(2))))?;
        let read = stream.read(&mut value[offset..])?;
        if read == 0 {
            return Err(BrokerError::Configuration("invalid_control_frame"));
        }
        offset += read;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_CONTROL_DOCUMENT_BYTES, handle_connection, parse_relay_length};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    #[test]
    fn relay_frames_are_bounded_and_require_canonical_lengths() {
        assert!(matches!(parse_relay_length(b"RELAY 2\n"), Ok(2)));
        assert!(parse_relay_length(b"RELAY 0\n").is_err());
        assert!(parse_relay_length(b"RELAY 02\n").is_err());
        assert!(parse_relay_length(b"RELAY 65537\n").is_err());
        assert_eq!(MAX_CONTROL_DOCUMENT_BYTES, 64 * 1024);
    }

    #[test]
    fn control_socket_status_and_relay_never_accept_unsigned_authority() {
        let (mut broker, mut client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        client.write_all(b"STATUS\n").unwrap();
        handle_connection(&mut broker, Some(current_gid()), deadline).unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"OK blindpass-control/1\n");

        let (mut broker, mut client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        client.write_all(b"RELAY 2\n{}").unwrap();
        handle_connection(&mut broker, Some(current_gid()), deadline).unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"ERR issuer_not_configured\n");
    }

    fn current_gid() -> u32 {
        unsafe extern "C" {
            fn getgid() -> u32;
        }
        // SAFETY: getgid has no arguments and always returns the caller's gid.
        unsafe { getgid() }
    }
}

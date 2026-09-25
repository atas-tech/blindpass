// SPDX-License-Identifier: AGPL-3.0-only

//! Local relay socket. This listener accepts no network connections.

use crate::BrokerError;
use crate::keys::{NodeIdentity, PinnedIssuer};
use crate::os_identity::require_control_peer;
use crate::os_identity::require_root_peer;
use blindpass_core::secret::wipe;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_CONTROL_LINE_BYTES: usize = 512;
const MAX_CONTROL_DOCUMENT_BYTES: usize = 64 * 1024;

pub(crate) fn handle_connection(
    stream: &mut UnixStream,
    expected_group: Option<u32>,
    identity: std::sync::Arc<NodeIdentity>,
    deadline: Instant,
) -> Result<(), BrokerError> {
    require_control_peer(stream, expected_group)?;
    let mut command = read_line(stream, deadline)?;
    let result = handle_command(stream, &command, &identity, deadline);
    wipe(&mut command);
    result
}

fn handle_command(
    stream: &mut UnixStream,
    command: &[u8],
    identity: &NodeIdentity,
    deadline: Instant,
) -> Result<(), BrokerError> {
    match command {
        b"STATUS\n" => stream.write_all(b"OK blindpass-control/1\n")?,
        b"PULL_EVENTS\n" => stream.write_all(b"EVENTS 0\n")?,
        b"IDENTITY\n" => {
            let public = identity.public_identity()?;
            writeln!(
                stream,
                "OK identity/1 signing_pub={} recipient_pub={} fingerprint={}",
                public.signing_public, public.recipient_public, public.fingerprint
            )?;
        }
        b"PIN_STATUS\n" => match identity.pinned_issuer()? {
            Some(pin) => writeln!(
                stream,
                "PIN {} {} {} {} {}",
                pin.tenant_id, pin.node_id, pin.epoch, pin.key_id, pin.public_key
            )?,
            None => stream.write_all(b"PIN none\n")?,
        },
        _ if command.starts_with(b"SIGN_ENROLLMENT ") => {
            require_root_peer(stream)?;
            let token = std::str::from_utf8(&command[16..command.len() - 1])
                .map_err(|_| BrokerError::Configuration("invalid_enrollment_proof_request"))?;
            let signature = identity.enrollment_proof(token)?;
            writeln!(stream, "PROOF {signature}")?;
        }
        _ if command.starts_with(b"SIGN_NODE_CHALLENGE ") => {
            let fields = parse_node_challenge(&command)?;
            let signature = identity.node_challenge_signature(
                &fields.tenant_id,
                &fields.node_id,
                &fields.protocol_version,
                &fields.nonce,
                &fields.capabilities_hash,
                fields.key_version,
                fields.issuer_epoch,
                fields.controller_time_ms,
                fields.expires_at_ms,
            )?;
            writeln!(stream, "CHALLENGE {signature}")?;
        }
        _ if command.starts_with(b"PIN_ISSUER ") => {
            require_root_peer(stream)?;
            let pin = parse_pin(&command)?;
            identity.pin_issuer(pin)?;
            stream.write_all(b"OK issuer_pinned\n")?;
        }
        _ if command.starts_with(b"RELAY ") => {
            let length = parse_relay_length(&command)?;
            let mut document = vec![0_u8; length];
            let read_result = read_exact_until(stream, &mut document, deadline);
            read_result?;
            let verification = identity.verify_controller_document(&document);
            wipe(&mut document);
            match verification {
                Ok(kind) => writeln!(stream, "OK document_verified {kind}")?,
                Err(_) => stream.write_all(b"ERR invalid_controller_document\n")?,
            }
        }
        _ => stream.write_all(b"ERR invalid_control_command\n")?,
    }
    Ok(())
}

fn parse_pin(command: &[u8]) -> Result<PinnedIssuer, BrokerError> {
    let line = std::str::from_utf8(command)
        .map_err(|_| BrokerError::Configuration("invalid_issuer_pin_request"))?;
    let mut fields = line
        .strip_prefix("PIN_ISSUER ")
        .and_then(|line| line.strip_suffix('\n'))
        .ok_or(BrokerError::Configuration("invalid_issuer_pin_request"))?
        .split(' ');
    let tenant_id = fields.next().unwrap_or_default();
    let node_id = fields.next().unwrap_or_default();
    let epoch_text = fields
        .next()
        .ok_or(BrokerError::Configuration("invalid_issuer_pin_request"))?;
    let epoch = epoch_text
        .parse::<u64>()
        .ok()
        .filter(|epoch| *epoch > 0 && epoch.to_string() == epoch_text)
        .ok_or(BrokerError::Configuration("invalid_issuer_pin_request"))?;
    let key_id = fields.next().unwrap_or_default();
    let public_key = fields.next().unwrap_or_default();
    let pin = PinnedIssuer {
        tenant_id: tenant_id.to_owned(),
        node_id: node_id.to_owned(),
        epoch,
        key_id: key_id.to_owned(),
        public_key: public_key.to_owned(),
    };
    if fields.next().is_some() {
        return Err(BrokerError::Configuration("invalid_issuer_pin_request"));
    }
    if !valid_control_identifier(tenant_id)
        || !valid_control_identifier(node_id)
        || !valid_control_identifier(key_id)
        || public_key.len() != 43
        || !public_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(BrokerError::Configuration("invalid_issuer_pin_request"));
    }
    Ok(pin)
}

struct NodeChallengeFields {
    tenant_id: String,
    node_id: String,
    protocol_version: String,
    nonce: String,
    capabilities_hash: String,
    key_version: u64,
    issuer_epoch: u64,
    controller_time_ms: i64,
    expires_at_ms: i64,
}

fn parse_node_challenge(command: &[u8]) -> Result<NodeChallengeFields, BrokerError> {
    let line = std::str::from_utf8(command)
        .map_err(|_| BrokerError::Configuration("invalid_node_challenge_request"))?;
    let mut fields = line
        .strip_prefix("SIGN_NODE_CHALLENGE ")
        .and_then(|line| line.strip_suffix('\n'))
        .ok_or(BrokerError::Configuration("invalid_node_challenge_request"))?
        .split(' ');
    let tenant_id = fields.next().unwrap_or_default();
    let node_id = fields.next().unwrap_or_default();
    let protocol_version = fields.next().unwrap_or_default();
    let nonce = fields.next().unwrap_or_default();
    let capabilities_hash = fields.next().unwrap_or_default();
    let key_version_text = fields.next().unwrap_or_default();
    let issuer_epoch_text = fields.next().unwrap_or_default();
    let controller_time_text = fields.next().unwrap_or_default();
    let expires_at_text = fields.next().unwrap_or_default();
    let parse_unsigned = |value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0 && number.to_string() == value)
    };
    let parse_signed = |value: &str| {
        value
            .parse::<i64>()
            .ok()
            .filter(|number| *number > 0 && number.to_string() == value)
    };
    if fields.next().is_some() {
        return Err(BrokerError::Configuration("invalid_node_challenge_request"));
    }
    let request = NodeChallengeFields {
        tenant_id: tenant_id.to_owned(),
        node_id: node_id.to_owned(),
        protocol_version: protocol_version.to_owned(),
        nonce: nonce.to_owned(),
        capabilities_hash: capabilities_hash.to_owned(),
        key_version: parse_unsigned(key_version_text)
            .ok_or(BrokerError::Configuration("invalid_node_challenge_request"))?,
        issuer_epoch: parse_unsigned(issuer_epoch_text)
            .ok_or(BrokerError::Configuration("invalid_node_challenge_request"))?,
        controller_time_ms: parse_signed(controller_time_text)
            .ok_or(BrokerError::Configuration("invalid_node_challenge_request"))?,
        expires_at_ms: parse_signed(expires_at_text)
            .ok_or(BrokerError::Configuration("invalid_node_challenge_request"))?,
    };
    if !valid_control_identifier(&request.tenant_id)
        || !valid_control_identifier(&request.node_id)
        || blindpass_core::fleet::node_session_challenge_message(
            &request.tenant_id,
            &request.node_id,
            &request.protocol_version,
            &request.nonce,
            &request.capabilities_hash,
            request.key_version,
            request.issuer_epoch,
            request.controller_time_ms,
            request.expires_at_ms,
        )
        .is_err()
    {
        return Err(BrokerError::Configuration("invalid_node_challenge_request"));
    }
    Ok(request)
}

fn valid_control_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
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
    use super::{MAX_CONTROL_DOCUMENT_BYTES, handle_connection, parse_pin, parse_relay_length};
    use crate::keys::NodeIdentity;
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
        let directory = temporary_directory();
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        handle_connection(&mut broker, Some(current_gid()), identity.clone(), deadline).unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"OK blindpass-control/1\n");

        let (mut broker, mut client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        client.write_all(b"RELAY 2\n{}").unwrap();
        handle_connection(&mut broker, Some(current_gid()), identity, deadline).unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"ERR invalid_controller_document\n");
    }

    fn current_gid() -> u32 {
        unsafe extern "C" {
            fn getgid() -> u32;
        }
        // SAFETY: getgid has no arguments and always returns the caller's gid.
        unsafe { getgid() }
    }

    fn temporary_directory() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "blindpass-control-keys-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        directory
    }

    #[test]
    fn issuer_pin_command_requires_canonical_fields() {
        let line = format!(
            "PIN_ISSUER tenant_a nd_node 3 ed25519-{} {}\n",
            blindpass_core::signing::base64_url_encode(&[9; 32]),
            blindpass_core::signing::base64_url_encode(&[9; 32])
        );
        assert!(parse_pin(line.as_bytes()).is_ok());
        assert!(
            parse_pin(
                b"PIN_ISSUER tenant_a nd_node 03 ed25519-A AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            )
            .is_err()
        );
    }
}

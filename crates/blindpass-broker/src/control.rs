// SPDX-License-Identifier: AGPL-3.0-only

//! Local relay socket. This listener accepts no network connections.

use crate::BrokerError;
use crate::BrokerState;
use crate::keys::{NodeIdentity, PinnedIssuer};
use crate::os_identity::require_control_peer;
use crate::os_identity::require_root_peer;
use blindpass_core::canon::{Value, canonicalize_value};
use blindpass_core::fleet::{
    ApplicationAck, DocumentKind, Grant, NodeKeyRotation, NodeRevocation, PolicySnapshot,
    Registration, Revocation, SignedEnvelope, TimeReply,
};
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
    state: std::sync::Arc<std::sync::Mutex<BrokerState>>,
    deadline: Instant,
) -> Result<(), BrokerError> {
    require_control_peer(stream, expected_group)?;
    let mut command = read_line(stream, deadline)?;
    let result = handle_command(stream, &command, &identity, &state, deadline);
    wipe(&mut command);
    result
}

fn handle_command(
    stream: &mut UnixStream,
    command: &[u8],
    identity: &NodeIdentity,
    state: &std::sync::Arc<std::sync::Mutex<BrokerState>>,
    deadline: Instant,
) -> Result<(), BrokerError> {
    match command {
        b"STATUS\n" => stream.write_all(b"OK blindpass-control/1\n")?,
        b"PULL_EVENTS\n" => {
            let mut state = state
                .lock()
                .map_err(|_| BrokerError::Configuration("broker fleet state is unavailable"))?;
            let pin = identity.pinned_issuer()?.ok_or(BrokerError::Configuration(
                "controller issuer is not pinned",
            ))?;
            state.queue_overflow_event_if_possible(&pin.node_id)?;
            state.queue_node_revocation_ack_if_possible(&pin.node_id)?;
            if let Some((rotation_id, key_version, fingerprint)) =
                identity.applied_rotation_ack()?
            {
                state.queue_node_key_rotation_ack(
                    &pin.node_id,
                    &rotation_id,
                    key_version,
                    &fingerprint,
                )?;
            }
            let mut events = state.pending_node_events(100);
            let encoded = loop {
                let mut values = Vec::with_capacity(events.len());
                for event in &events {
                    let signature = identity.sign_node_event(
                        &pin.node_id,
                        &event.idempotency_key,
                        &event.kind,
                        &event.body,
                    )?;
                    values.push(Value::Object(vec![
                        ("body".to_owned(), event.body.clone()),
                        ("broker_signature".to_owned(), Value::String(signature)),
                        (
                            "idempotency_key".to_owned(),
                            Value::String(event.idempotency_key.clone()),
                        ),
                        ("kind".to_owned(), Value::String(event.kind.clone())),
                    ]));
                }
                let encoded = canonicalize_value(&Value::Array(values))
                    .map_err(|_| BrokerError::Configuration("broker event batch is invalid"))?;
                if encoded.len() <= MAX_CONTROL_DOCUMENT_BYTES {
                    break encoded;
                }
                if events.pop().is_none() {
                    return Err(BrokerError::Configuration(
                        "broker event exceeds its size bound",
                    ));
                }
            };
            writeln!(stream, "EVENTS {}", encoded.len())?;
            stream.write_all(&encoded)?;
            stream.write_all(b"\n")?;
        }
        b"TIME_CHALLENGE\n" => {
            let challenge = state
                .lock()
                .map_err(|_| BrokerError::Configuration("broker fleet state is unavailable"))?
                .grant_verifier
                .begin_time_challenge()
                .map_err(BrokerError::Configuration)?;
            writeln!(stream, "TIME {challenge}")?;
        }
        b"IDENTITY\n" => {
            let public = identity.public_identity()?;
            writeln!(
                stream,
                "OK identity/1 key_version={} signing_pub={} recipient_pub={} fingerprint={}",
                identity.key_version()?,
                public.signing_public,
                public.recipient_public,
                public.fingerprint
            )?;
        }
        b"PREPARE_ROTATION\n" => {
            require_root_peer(stream)?;
            let (key_version, public) = identity.prepare_rotation()?;
            writeln!(
                stream,
                "ROTATION key_version={key_version} signing_pub={} recipient_pub={} fingerprint={}",
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
            let fields = parse_node_challenge(command)?;
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
            let pin = parse_pin(command)?;
            identity.pin_issuer(pin)?;
            stream.write_all(b"OK issuer_pinned\n")?;
        }
        _ if command.starts_with(b"RELAY ") => {
            let length = parse_relay_length(command)?;
            let mut document = vec![0_u8; length];
            let read_result = read_exact_until(stream, &mut document, deadline);
            read_result?;
            let application = apply_controller_document(state, identity, &document, true);
            wipe(&mut document);
            match application {
                Ok("grant_discarded_expired") => {
                    stream.write_all(b"OK document_discarded grant_expired\n")?
                }
                Ok(kind) => writeln!(stream, "OK document_applied {kind}")?,
                Err(BrokerError::Configuration(reason)) => {
                    eprintln!("controller document rejected: {reason}");
                    stream.write_all(b"ERR invalid_controller_document\n")?;
                }
                Err(_) => stream.write_all(b"ERR invalid_controller_document\n")?,
            }
        }
        _ => stream.write_all(b"ERR invalid_control_command\n")?,
    }
    Ok(())
}

pub(crate) fn restore_controller_documents(
    state: &mut BrokerState,
    identity: &NodeIdentity,
) -> Result<(), BrokerError> {
    for document in identity.persisted_controller_documents()? {
        apply_controller_document_to_state(state, identity, &document, false)?;
    }
    Ok(())
}

fn apply_controller_document(
    state: &std::sync::Arc<std::sync::Mutex<BrokerState>>,
    identity: &NodeIdentity,
    document: &[u8],
    persist: bool,
) -> Result<&'static str, BrokerError> {
    let mut state = state
        .lock()
        .map_err(|_| BrokerError::Configuration("broker fleet state is unavailable"))?;
    apply_controller_document_to_state(&mut state, identity, document, persist)
}

fn apply_controller_document_to_state(
    state: &mut BrokerState,
    identity: &NodeIdentity,
    document: &[u8],
    persist: bool,
) -> Result<&'static str, BrokerError> {
    let kind = identity.verify_controller_document(document)?;
    if kind == "stale_epoch" {
        let source = std::str::from_utf8(document)
            .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
        let envelope = SignedEnvelope::from_json(source)
            .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
        if envelope.kind() == DocumentKind::NodeRevocation {
            let revocation = NodeRevocation::from_value(envelope.body()).map_err(|_| {
                BrokerError::Configuration("controller node revocation is malformed")
            })?;
            let pin = identity.pinned_issuer()?.ok_or(BrokerError::Configuration(
                "controller issuer is not pinned",
            ))?;
            if revocation.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller node revocation is bound to another node",
                ));
            }
            if persist {
                identity.persist_controller_document(document)?;
            }
            state.apply_node_revocation(&revocation.node_id, revocation.revoked_at_ms)?;
            return Ok("node_revocation");
        }
        return Ok("stale_epoch");
    }
    let source = std::str::from_utf8(document)
        .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
    let envelope = SignedEnvelope::from_json(source)
        .map_err(|_| BrokerError::Configuration("controller document is malformed"))?;
    let pin = identity.pinned_issuer()?.ok_or(BrokerError::Configuration(
        "controller issuer is not pinned",
    ))?;
    match envelope.kind() {
        DocumentKind::Registration => {
            let registration = Registration::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller registration is malformed"))?;
            if registration.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller registration is bound to another node",
                ));
            }
            let changed = state.validate_fleet_registration(&registration)?;
            if changed {
                if persist {
                    identity.persist_controller_document(document)?;
                }
                state.apply_fleet_registration(registration)?;
            }
        }
        DocumentKind::PolicySnapshot => {
            let policy = PolicySnapshot::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller fleet policy is malformed"))?;
            let changed = state.validate_fleet_policy(&policy)?;
            if changed {
                if persist {
                    identity.persist_controller_document(document)?;
                }
                state.apply_fleet_policy(policy)?;
            }
        }
        DocumentKind::TimeReply => {
            let reply = TimeReply::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller time reply is malformed"))?;
            if reply.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller time reply is bound to another node",
                ));
            }
            state
                .grant_verifier
                .accept_time_reply(
                    &reply,
                    &pin.node_id,
                    envelope.epoch(),
                    crate::grants::boottime_ms().map_err(BrokerError::Configuration)?,
                )
                .map_err(BrokerError::Configuration)?;
        }
        DocumentKind::ApplicationAck => {
            let ack = ApplicationAck::from_value(envelope.body()).map_err(|_| {
                BrokerError::Configuration("controller acknowledgement is malformed")
            })?;
            if ack.node_id != pin.node_id || ack.issuer_epoch != envelope.epoch() {
                return Err(BrokerError::Configuration(
                    "controller acknowledgement is bound to another node or epoch",
                ));
            }
            state.acknowledge_node_events(&ack.node_id, &ack.event_keys)?;
            identity.acknowledge_rotation_event(&ack.event_keys)?;
        }
        DocumentKind::Grant => {
            let grant = Grant::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller grant is malformed"))?;
            if grant.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller grant is bound to another node",
                ));
            }
            let registration = state.fleet_registrations.get(&grant.workload_id).ok_or(
                BrokerError::Configuration("controller grant has no current workload registration"),
            )?;
            let policy = state
                .fleet_policy
                .as_ref()
                .ok_or(BrokerError::Configuration("fleet policy is unavailable"))?;
            let expected_recipient_key_id = format!("{}-{}", pin.node_id, identity.key_version()?);
            let grant_id = grant.id.clone();
            let grant_expires_at_ms = grant.expires_at_ms;
            let now_boottime_ms =
                crate::grants::boottime_ms().map_err(BrokerError::Configuration)?;
            match state.grant_verifier.accept_grant(
                grant,
                document,
                &pin.node_id,
                &expected_recipient_key_id,
                policy,
                registration,
                now_boottime_ms,
            ) {
                Ok(_) => {}
                Err("grant expired before broker receipt") => {
                    if persist {
                        state.queue_expired_grant_audit(
                            &pin.node_id,
                            &grant_id,
                            grant_expires_at_ms,
                        )?;
                    }
                    return Ok("grant_discarded_expired");
                }
                Err(reason) => return Err(BrokerError::Configuration(reason)),
            }
        }
        DocumentKind::Revocation => {
            let revocation = Revocation::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller revocation is malformed"))?;
            if revocation.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller revocation is bound to another node",
                ));
            }
            state
                .grant_verifier
                .revoke(&revocation)
                .map_err(BrokerError::Configuration)?;
        }
        DocumentKind::NodeRevocation => {
            let revocation = NodeRevocation::from_value(envelope.body()).map_err(|_| {
                BrokerError::Configuration("controller node revocation is malformed")
            })?;
            if revocation.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller node revocation is bound to another node",
                ));
            }
            if persist {
                identity.persist_controller_document(document)?;
            }
            state.apply_node_revocation(&revocation.node_id, revocation.revoked_at_ms)?;
        }
        DocumentKind::NodeKeyRotation => {
            let rotation = NodeKeyRotation::from_value(envelope.body()).map_err(|_| {
                BrokerError::Configuration("controller node key rotation is malformed")
            })?;
            if rotation.node_id != pin.node_id || rotation.issuer_epoch != envelope.epoch() {
                return Err(BrokerError::Configuration(
                    "controller node key rotation is bound to another node or epoch",
                ));
            }
            identity.apply_key_rotation(&rotation)?;
        }
        _ => {
            return Err(BrokerError::Configuration(
                "controller document kind is not supported by this broker",
            ));
        }
    }
    match kind.as_str() {
        "registration" => Ok("registration"),
        "policy_snapshot" => Ok("policy_snapshot"),
        "grant" => Ok("grant"),
        "revocation" => Ok("revocation"),
        "node_revocation" => Ok("node_revocation"),
        "node_key_rotation" => Ok("node_key_rotation"),
        "time_reply" => Ok("time_reply"),
        "application_ack" => Ok("application_ack"),
        _ => Err(BrokerError::Configuration(
            "controller document kind is unsupported",
        )),
    }
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
    use super::{
        MAX_CONTROL_DOCUMENT_BYTES, handle_connection, parse_pin, parse_relay_length,
        restore_controller_documents,
    };
    use crate::BrokerState;
    use crate::keys::NodeIdentity;
    use blindpass_core::canon::{Value, canonicalize_value, parse_json};
    use blindpass_core::delivery::DeliveryPolicy;
    use blindpass_core::fleet::{
        ApplicationAck, ConsumptionMode, DocumentKind, Grant, NodeRevocation, PolicySnapshot,
        Registration, Revocation, SignedEnvelope, TimeReply, node_event_message,
    };
    use blindpass_core::identity::{PeerIdentity, WorkloadRequest};
    use blindpass_core::signing::base64_url_encode;
    use blindpass_core::signing::ed25519::{Ed25519KeyPair, verify};
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
        let state = std::sync::Arc::new(std::sync::Mutex::new(BrokerState::new(
            DeliveryPolicy::default(),
        )));
        handle_connection(
            &mut broker,
            Some(current_gid()),
            identity.clone(),
            state.clone(),
            deadline,
        )
        .unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"OK blindpass-control/1\n");

        let (mut broker, mut client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        client.write_all(b"RELAY 2\n{}").unwrap();
        handle_connection(&mut broker, Some(current_gid()), identity, state, deadline).unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"ERR invalid_controller_document\n");
    }

    #[test]
    fn signed_node_revocation_disables_workloads_and_survives_acknowledged_restart() {
        let directory = temporary_directory();
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        let issuer = Ed25519KeyPair::from_seed(&[19; 32]).unwrap();
        let issuer_public = base64_url_encode(issuer.public_key());
        let issuer_key_id = format!("ed25519-{issuer_public}");
        identity
            .pin_issuer(crate::keys::PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: "nd_node-a".to_owned(),
                epoch: 1,
                key_id: issuer_key_id.clone(),
                public_key: issuer_public,
            })
            .unwrap();
        let mut broker_state = BrokerState::new(DeliveryPolicy::default());
        broker_state.configure_grant_storage(&identity).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(broker_state));

        let observed_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let revocation = NodeRevocation {
            node_id: "nd_node-a".to_owned(),
            revoked_at_ms: observed_at_ms,
            issuer_epoch: 1,
        };
        let document = SignedEnvelope::sign(
            DocumentKind::NodeRevocation,
            revocation.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &document),
            b"OK document_applied node_revocation\n"
        );
        assert!(state.lock().unwrap().node_revoked);
        let rejected = state.lock().unwrap().process_workload(
            &PeerIdentity::fixture(1000, current_gid(), "worker.service", "inv-a", "worker"),
            &WorkloadRequest {
                node_id: "nd_node-a".to_owned(),
                workload_id: "wl_worker-a".to_owned(),
                claimed_unit: "worker.service".to_owned(),
                claimed_invocation_id: "inv-a".to_owned(),
                operation: "health".to_owned(),
            },
        );
        assert!(rejected.is_err());

        let events = control_exchange(&identity, &state, b"PULL_EVENTS\n");
        let header_end = events.iter().position(|byte| *byte == b'\n').unwrap();
        let payload = std::str::from_utf8(&events[header_end + 1..events.len() - 1]).unwrap();
        let event = parse_json(payload).unwrap();
        let event = &event.as_array().unwrap()[0];
        assert_eq!(
            event
                .get("body")
                .and_then(|body| body.get("action"))
                .and_then(Value::as_str),
            Some("node_revocation_applied")
        );
        let event_key = event
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let ack = ApplicationAck {
            node_id: "nd_node-a".to_owned(),
            issuer_epoch: 1,
            acknowledged_at_ms: observed_at_ms,
            event_keys: vec![event_key],
        };
        let ack_document = SignedEnvelope::sign(
            DocumentKind::ApplicationAck,
            ack.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &ack_document),
            b"OK document_applied application_ack\n"
        );
        assert_eq!(
            control_exchange(&identity, &state, b"PULL_EVENTS\n"),
            b"EVENTS 2\n[]\n"
        );
        drop(state);

        let mut restored = BrokerState::new(DeliveryPolicy::default());
        restored.configure_grant_storage(&identity).unwrap();
        restore_controller_documents(&mut restored, &identity).unwrap();
        assert!(restored.node_revoked);
        assert!(restored.node_revocation_acknowledged);
        assert!(restored.pending_node_events.is_empty());

        let restored = std::sync::Arc::new(std::sync::Mutex::new(restored));
        assert_eq!(
            relay_signed_document(&identity, &restored, &document),
            b"OK document_applied node_revocation\n"
        );
        let restored = restored.lock().unwrap();
        assert!(restored.node_revoked);
        assert!(restored.node_revocation_acknowledged);
        assert!(restored.pending_node_events.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn delayed_policy_replay_cannot_restore_an_older_version_before_or_after_restart() {
        let directory = temporary_directory();
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        let issuer = Ed25519KeyPair::from_seed(&[23; 32]).unwrap();
        let issuer_public = base64_url_encode(issuer.public_key());
        let issuer_key_id = format!("ed25519-{issuer_public}");
        identity
            .pin_issuer(crate::keys::PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: "nd_node-a".to_owned(),
                epoch: 1,
                key_id: issuer_key_id.clone(),
                public_key: issuer_public,
            })
            .unwrap();

        let stale_policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        let current_policy = PolicySnapshot {
            policy_version: 5,
            local_ceiling_seconds: 30,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        let sign_policy = |policy: &PolicySnapshot| {
            SignedEnvelope::sign(
                DocumentKind::PolicySnapshot,
                policy.to_value().unwrap(),
                &issuer_key_id,
                1,
                &issuer,
            )
            .unwrap()
            .to_json()
            .unwrap()
        };
        let stale_document = sign_policy(&stale_policy);
        let current_document = sign_policy(&current_policy);
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state.configure_grant_storage(&identity).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(state));

        assert_eq!(
            relay_signed_document(&identity, &state, &current_document),
            b"OK document_applied policy_snapshot\n"
        );
        assert_eq!(
            relay_signed_document(&identity, &state, &stale_document),
            b"OK document_applied policy_snapshot\n"
        );
        assert_eq!(
            state
                .lock()
                .unwrap()
                .fleet_policy
                .as_ref()
                .unwrap()
                .policy_version,
            5
        );
        drop(state);

        let mut restored = BrokerState::new(DeliveryPolicy::default());
        restored.configure_grant_storage(&identity).unwrap();
        restore_controller_documents(&mut restored, &identity).unwrap();
        assert_eq!(restored.fleet_policy.as_ref().unwrap().policy_version, 5);
        let restored = std::sync::Arc::new(std::sync::Mutex::new(restored));
        assert_eq!(
            relay_signed_document(&identity, &restored, &stale_document),
            b"OK document_applied policy_snapshot\n"
        );
        assert_eq!(
            restored
                .lock()
                .unwrap()
                .fleet_policy
                .as_ref()
                .unwrap()
                .policy_version,
            5
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn replayed_grant_revocation_survives_broker_restart_and_denies_old_grant() {
        let directory = temporary_directory();
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        let issuer = Ed25519KeyPair::from_seed(&[29; 32]).unwrap();
        let issuer_public = base64_url_encode(issuer.public_key());
        let issuer_key_id = format!("ed25519-{issuer_public}");
        identity
            .pin_issuer(crate::keys::PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: "nd_node-a".to_owned(),
                epoch: 1,
                key_id: issuer_key_id.clone(),
                public_key: issuer_public,
            })
            .unwrap();

        let mut initial = BrokerState::new(DeliveryPolicy::default());
        initial.operation_directory = directory.join("ops");
        std::fs::create_dir_all(&initial.operation_directory).unwrap();
        initial.configure_grant_storage(&identity).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(initial));
        let registration = Registration {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            invocation_id: None,
            status: "active".to_owned(),
            consumption_mode: ConsumptionMode::File,
            registration_version: 1,
            policy_version: 4,
            local_ceiling_seconds: 60,
        };
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        for (kind, body) in [
            (DocumentKind::Registration, registration.to_value().unwrap()),
            (DocumentKind::PolicySnapshot, policy.to_value().unwrap()),
        ] {
            let document = SignedEnvelope::sign(kind, body, &issuer_key_id, 1, &issuer)
                .unwrap()
                .to_json()
                .unwrap();
            assert!(
                relay_signed_document(&identity, &state, &document)
                    .starts_with(b"OK document_applied ")
            );
        }

        let challenge_response = control_exchange(&identity, &state, b"TIME_CHALLENGE\n");
        let challenge = std::str::from_utf8(&challenge_response)
            .unwrap()
            .strip_prefix("TIME ")
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let time_document = SignedEnvelope::sign(
            DocumentKind::TimeReply,
            TimeReply {
                node_id: "nd_node-a".to_owned(),
                challenge,
                controller_time_ms: now_ms,
                issuer_epoch: 1,
            }
            .to_value()
            .unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &time_document),
            b"OK document_applied time_reply\n"
        );

        let grant = Grant {
            id: "gr_2123456789abcdef0123456789abcdef".to_owned(),
            operation_id: "op_2123456789abcdef0123456789abcdef".to_owned(),
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            invocation_id: "invocation-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            resource_id: "marker-revoked".to_owned(),
            recipient_key_id: "nd_node-a-1".to_owned(),
            policy_version: 4,
            approval_reference: None,
            action: "noop.marker".to_owned(),
            mode: ConsumptionMode::File,
            audience: "blindpass-node".to_owned(),
            issuer_epoch: 1,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + 120_000,
            local_ceiling_seconds: 60,
        };
        let grant_document = SignedEnvelope::sign(
            DocumentKind::Grant,
            grant.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &grant_document),
            b"OK document_applied grant\n"
        );
        let revocation = Revocation {
            grant_id: grant.id.clone(),
            node_id: "nd_node-a".to_owned(),
            reason: "operator".to_owned(),
            revoked_at_ms: now_ms,
            retain_until_ms: now_ms + 7 * 24 * 60 * 60 * 1_000,
            issuer_epoch: 1,
        };
        let revocation_document = SignedEnvelope::sign(
            DocumentKind::Revocation,
            revocation.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &revocation_document),
            b"OK document_applied revocation\n"
        );
        assert_eq!(
            relay_signed_document(&identity, &state, &grant_document),
            b"ERR invalid_controller_document\n"
        );
        drop(state);

        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted.operation_directory = directory.join("ops");
        restarted.configure_grant_storage(&identity).unwrap();
        restore_controller_documents(&mut restarted, &identity).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(restarted));
        assert_eq!(
            relay_signed_document(&identity, &state, &revocation_document),
            b"OK document_applied revocation\n"
        );

        let challenge_response = control_exchange(&identity, &state, b"TIME_CHALLENGE\n");
        let challenge = std::str::from_utf8(&challenge_response)
            .unwrap()
            .strip_prefix("TIME ")
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned();
        let fresh_time = SignedEnvelope::sign(
            DocumentKind::TimeReply,
            TimeReply {
                node_id: "nd_node-a".to_owned(),
                challenge,
                controller_time_ms: now_ms + 1,
                issuer_epoch: 1,
            }
            .to_value()
            .unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &fresh_time),
            b"OK document_applied time_reply\n"
        );
        assert_eq!(
            relay_signed_document(&identity, &state, &grant_document),
            b"ERR invalid_controller_document\n"
        );
        let peer = PeerIdentity::fixture(
            1000,
            current_gid(),
            "worker.service",
            "invocation-a",
            "worker",
        );
        let request = WorkloadRequest {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            claimed_unit: "worker.service".to_owned(),
            claimed_invocation_id: "invocation-a".to_owned(),
            operation: format!("consume:{}", grant.id),
        };
        assert!(
            state
                .lock()
                .unwrap()
                .process_workload(&peer, &request)
                .is_err()
        );
        assert!(
            !directory
                .join("ops")
                .join(format!("{}.marker", grant.id))
                .exists()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn signed_time_and_grant_relay_authorize_exactly_one_live_invocation() {
        let directory = temporary_directory();
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        let issuer = Ed25519KeyPair::from_seed(&[9; 32]).unwrap();
        let issuer_public = base64_url_encode(issuer.public_key());
        let issuer_key_id = format!("ed25519-{issuer_public}");
        identity
            .pin_issuer(crate::keys::PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: "nd_node-a".to_owned(),
                epoch: 1,
                key_id: issuer_key_id.clone(),
                public_key: issuer_public,
            })
            .unwrap();
        let mut broker_state = BrokerState::new(DeliveryPolicy::default());
        let operation_directory = directory.join("ops");
        broker_state.operation_directory = operation_directory.clone();
        broker_state.configure_grant_storage(&identity).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(broker_state));

        let registration = Registration {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            invocation_id: None,
            status: "active".to_owned(),
            consumption_mode: ConsumptionMode::File,
            registration_version: 1,
            policy_version: 4,
            local_ceiling_seconds: 60,
        };
        let policy = PolicySnapshot {
            policy_version: 4,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["noop.marker".to_owned()],
            allowed_modes: vec![ConsumptionMode::File],
        };
        for (kind, body) in [
            (DocumentKind::Registration, registration.to_value().unwrap()),
            (DocumentKind::PolicySnapshot, policy.to_value().unwrap()),
        ] {
            let envelope = SignedEnvelope::sign(kind, body, &issuer_key_id, 1, &issuer)
                .unwrap()
                .to_json()
                .unwrap();
            assert!(
                relay_signed_document(&identity, &state, &envelope)
                    .starts_with(b"OK document_applied ")
            );
        }

        let challenge_response = control_exchange(&identity, &state, b"TIME_CHALLENGE\n");
        let challenge = std::str::from_utf8(&challenge_response)
            .unwrap()
            .strip_prefix("TIME ")
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let time_reply = TimeReply {
            node_id: "nd_node-a".to_owned(),
            challenge,
            controller_time_ms: now_ms,
            issuer_epoch: 1,
        };
        let time_envelope = SignedEnvelope::sign(
            DocumentKind::TimeReply,
            time_reply.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &time_envelope),
            b"OK document_applied time_reply\n"
        );

        let peer = PeerIdentity::fixture(
            1000,
            current_gid(),
            "worker.service",
            "invocation-a",
            "worker",
        );
        let request_body = Value::Object(vec![
            ("action".to_owned(), Value::String("noop.marker".to_owned())),
            ("mode".to_owned(), Value::String("file".to_owned())),
            (
                "purpose".to_owned(),
                Value::String("nightly marker".to_owned()),
            ),
            (
                "resource_id".to_owned(),
                Value::String("marker-request".to_owned()),
            ),
            ("ttl_seconds".to_owned(), Value::Unsigned(30)),
        ]);
        let request_bytes = canonicalize_value(&request_body).unwrap();
        let operation_request = WorkloadRequest {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            claimed_unit: "worker.service".to_owned(),
            claimed_invocation_id: "invocation-a".to_owned(),
            operation: format!("request:{}", base64_url_encode(&request_bytes)),
        };
        let requested = state
            .lock()
            .unwrap()
            .process_workload(&peer, &operation_request)
            .unwrap();
        let event_key = std::str::from_utf8(&requested)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned();
        let pulled = control_exchange(&identity, &state, b"PULL_EVENTS\n");
        let header_end = pulled.iter().position(|byte| *byte == b'\n').unwrap();
        let payload = std::str::from_utf8(&pulled[header_end + 1..pulled.len() - 1]).unwrap();
        let event_batch = parse_json(payload).unwrap();
        let event = &event_batch.as_array().unwrap()[0];
        assert_eq!(
            event.get("kind").and_then(Value::as_str),
            Some("operation_request")
        );
        assert_eq!(
            event.get("idempotency_key").and_then(Value::as_str),
            Some(event_key.as_str())
        );
        let body = event.get("body").unwrap();
        let message =
            node_event_message("nd_node-a", &event_key, "operation_request", body).unwrap();
        let public_identity = identity.public_identity().unwrap();
        let public_key =
            blindpass_core::signing::base64_url_decode(&public_identity.signing_public, 32)
                .unwrap();
        let signature = blindpass_core::signing::base64_url_decode(
            event
                .get("broker_signature")
                .and_then(Value::as_str)
                .unwrap(),
            64,
        )
        .unwrap();
        assert!(verify(&public_key, &message, &signature).unwrap());
        let ack = ApplicationAck {
            node_id: "nd_node-a".to_owned(),
            issuer_epoch: 1,
            acknowledged_at_ms: now_ms,
            event_keys: vec![event_key],
        };
        let ack_envelope = SignedEnvelope::sign(
            DocumentKind::ApplicationAck,
            ack.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &ack_envelope),
            b"OK document_applied application_ack\n"
        );
        assert_eq!(
            control_exchange(&identity, &state, b"PULL_EVENTS\n"),
            b"EVENTS 2\n[]\n"
        );

        let grant = Grant {
            id: "gr_0123456789abcdef0123456789abcdef".to_owned(),
            operation_id: "op_0123456789abcdef0123456789abcdef".to_owned(),
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            invocation_id: "invocation-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            resource_id: "marker-a".to_owned(),
            recipient_key_id: "nd_node-a-1".to_owned(),
            policy_version: 4,
            approval_reference: None,
            action: "noop.marker".to_owned(),
            mode: ConsumptionMode::File,
            audience: "blindpass-node".to_owned(),
            issuer_epoch: 1,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + 60_000,
            local_ceiling_seconds: 60,
        };
        let grant_envelope = SignedEnvelope::sign(
            DocumentKind::Grant,
            grant.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &grant_envelope),
            b"OK document_applied grant\n"
        );

        let request = WorkloadRequest {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            claimed_unit: "worker.service".to_owned(),
            claimed_invocation_id: "invocation-a".to_owned(),
            operation: format!("consume:{}", grant.id),
        };
        let first_state = std::sync::Arc::clone(&state);
        let first_peer = peer.clone();
        let first_request = request.clone();
        let second_state = std::sync::Arc::clone(&state);
        let second_peer = peer.clone();
        let second_request = request.clone();
        let first_consume = std::thread::spawn(move || {
            first_state
                .lock()
                .unwrap()
                .process_workload(&first_peer, &first_request)
        });
        let second_consume = std::thread::spawn(move || {
            second_state
                .lock()
                .unwrap()
                .process_workload(&second_peer, &second_request)
        });
        let first_result = first_consume.join().unwrap();
        let second_result = second_consume.join().unwrap();
        let consumed = match (first_result, second_result) {
            (Ok(consumed), Err(_)) | (Err(_), Ok(consumed)) => consumed,
            (Ok(_), Ok(_)) => panic!("concurrent consumers both consumed one grant"),
            (Err(first), Err(second)) => {
                panic!("both concurrent grant consumers failed: {first}; {second}")
            }
        };
        assert_eq!(
            consumed,
            format!("OK operation_completed {}\n", grant.id).as_bytes()
        );
        let marker = operation_directory.join(format!("{}.marker", grant.id));
        assert_eq!(std::fs::metadata(marker).unwrap().len(), 0);
        assert!(
            state
                .lock()
                .unwrap()
                .process_workload(&peer, &request)
                .is_err()
        );

        let mut uncertain_grant = grant.clone();
        uncertain_grant.id = "gr_1123456789abcdef0123456789abcdef".to_owned();
        uncertain_grant.operation_id = "op_1123456789abcdef0123456789abcdef".to_owned();
        uncertain_grant.resource_id = "marker-b".to_owned();
        let uncertain_envelope = SignedEnvelope::sign(
            DocumentKind::Grant,
            uncertain_grant.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &uncertain_envelope),
            b"OK document_applied grant\n"
        );
        std::fs::write(
            operation_directory.join(format!("{}.marker", uncertain_grant.id)),
            [],
        )
        .unwrap();
        let uncertain_request = WorkloadRequest {
            operation: format!("consume:{}", uncertain_grant.id),
            ..request.clone()
        };
        let uncertain_result = state
            .lock()
            .unwrap()
            .process_workload(&peer, &uncertain_request)
            .unwrap();
        assert_eq!(
            uncertain_result,
            format!("OK operation_uncertain {}\n", uncertain_grant.id).as_bytes()
        );
        assert!(
            state
                .lock()
                .unwrap()
                .process_workload(&peer, &uncertain_request)
                .is_err()
        );

        let mut expired_grant = grant.clone();
        expired_grant.id = "gr_2123456789abcdef0123456789abcdef".to_owned();
        expired_grant.operation_id = "op_2123456789abcdef0123456789abcdef".to_owned();
        expired_grant.issued_at_ms = now_ms - 2_000;
        expired_grant.expires_at_ms = now_ms - 1_000;
        let expired_envelope = SignedEnvelope::sign(
            DocumentKind::Grant,
            expired_grant.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &state, &expired_envelope),
            b"OK document_discarded grant_expired\n"
        );
        assert_eq!(
            relay_signed_document(&identity, &state, &expired_envelope),
            b"OK document_discarded grant_expired\n"
        );

        drop(state);
        let mut recovered_state = BrokerState::new(DeliveryPolicy::default());
        recovered_state.configure_grant_storage(&identity).unwrap();
        let recovered_state = std::sync::Arc::new(std::sync::Mutex::new(recovered_state));
        let recovered_events = control_exchange(&identity, &recovered_state, b"PULL_EVENTS\n");
        let header_end = recovered_events
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap();
        let payload =
            std::str::from_utf8(&recovered_events[header_end + 1..recovered_events.len() - 1])
                .unwrap();
        let recovered_events = parse_json(payload).unwrap();
        let recovered_events = recovered_events.as_array().unwrap();
        assert_eq!(recovered_events.len(), 5);
        let expired_grant_audit = recovered_events
            .iter()
            .find(|event| {
                event
                    .get("body")
                    .and_then(|body| body.get("action"))
                    .and_then(Value::as_str)
                    == Some("grant_rejected")
            })
            .expect("expired grant rejection must be durably audited");
        assert_eq!(
            expired_grant_audit
                .get("body")
                .and_then(|body| body.get("grant_id"))
                .and_then(Value::as_str),
            Some(expired_grant.id.as_str())
        );
        assert_eq!(
            expired_grant_audit
                .get("body")
                .and_then(|body| body.get("expires_at_ms"))
                .and_then(Value::as_u64),
            Some(expired_grant.expires_at_ms)
        );
        assert_eq!(
            expired_grant_audit
                .get("body")
                .and_then(|body| body.get("reason_code"))
                .and_then(Value::as_str),
            Some("expired_before_receipt")
        );
        let result_statuses = recovered_events
            .iter()
            .filter(|event| event.get("kind").and_then(Value::as_str) == Some("operation_result"))
            .filter_map(|event| {
                event
                    .get("body")
                    .and_then(|body| body.get("status"))
                    .and_then(Value::as_str)
            })
            .collect::<Vec<_>>();
        assert_eq!(result_statuses, ["completed", "uncertain"]);
        let recovered_keys = recovered_events
            .iter()
            .map(|event| {
                event
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        let recovered_ack = ApplicationAck {
            node_id: "nd_node-a".to_owned(),
            issuer_epoch: 1,
            acknowledged_at_ms: now_ms,
            event_keys: recovered_keys,
        };
        let recovered_ack_envelope = SignedEnvelope::sign(
            DocumentKind::ApplicationAck,
            recovered_ack.to_value().unwrap(),
            &issuer_key_id,
            1,
            &issuer,
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            relay_signed_document(&identity, &recovered_state, &recovered_ack_envelope),
            b"OK document_applied application_ack\n"
        );
        assert_eq!(
            control_exchange(&identity, &recovered_state, b"PULL_EVENTS\n"),
            b"EVENTS 2\n[]\n"
        );
        drop(recovered_state);
        drop(identity);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn relay_signed_document(
        identity: &std::sync::Arc<NodeIdentity>,
        state: &std::sync::Arc<std::sync::Mutex<BrokerState>>,
        document: &[u8],
    ) -> Vec<u8> {
        let mut request = format!("RELAY {}\n", document.len()).into_bytes();
        request.extend_from_slice(document);
        control_exchange(identity, state, &request)
    }

    fn control_exchange(
        identity: &std::sync::Arc<NodeIdentity>,
        state: &std::sync::Arc<std::sync::Mutex<BrokerState>>,
        request: &[u8],
    ) -> Vec<u8> {
        let (mut broker, mut client) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        handle_connection(
            &mut broker,
            Some(current_gid()),
            identity.clone(),
            state.clone(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        response
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

// SPDX-License-Identifier: AGPL-3.0-only

//! Local relay socket. This listener accepts no network connections.

use crate::BrokerError;
use crate::BrokerState;
use crate::keys::{NodeIdentity, PinnedIssuer};
use crate::os_identity::require_control_peer;
use crate::os_identity::require_root_peer;
use blindpass_core::canon::{Value, canonicalize_value};
use blindpass_core::fleet::{
    ApplicationAck, DocumentKind, Grant, NodeKeyRotation, NodeRevocation, OperationClosed,
    PolicySnapshot, Registration, Revocation, SignedEnvelope, TimeReply,
};
use blindpass_core::secret::wipe;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_CONTROL_LINE_BYTES: usize = 512;
/// RELAY and every non-delivery document; only `provisioning_delivery` (via
/// PROVISION_SOURCE) may be larger.
const MAX_CONTROL_DOCUMENT_BYTES: usize = blindpass_core::fleet::MAX_NODE_DOCUMENT_BYTES;

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
        b"RECOVERY_CHALLENGE\n" => {
            let value = state
                .lock()
                .map_err(|_| BrokerError::Configuration("recovery_report_denied"))?
                .grant_verifier
                .begin_recovery_challenge(identity)?;
            let encoded = canonicalize_value(&value)
                .map_err(|_| BrokerError::Configuration("recovery_report_denied"))?;
            writeln!(stream, "RECOVERY_CHALLENGE {}", encoded.len())?;
            stream.write_all(&encoded)?;
        }
        _ if command.starts_with(b"RECOVERY_REPORT ") => {
            let framed = command
                .strip_prefix(b"RECOVERY_REPORT ")
                .ok_or(BrokerError::Configuration("recovery_report_denied"))?;
            let mut relay = b"RELAY ".to_vec();
            relay.extend_from_slice(framed);
            let length = parse_relay_length(&relay)?;
            if length > 4_096 {
                return Err(BrokerError::Configuration("recovery_report_denied"));
            }
            let mut bytes = vec![0_u8; length];
            read_exact_until(stream, &mut bytes, deadline)?;
            let request = std::str::from_utf8(&bytes).ok().and_then(|text| {
                blindpass_core::recovery::pages::SignedReportRequest::from_json(text).ok()
            });
            wipe(&mut bytes);
            let result = request
                .ok_or(BrokerError::Configuration("recovery_report_denied"))
                .and_then(|request| {
                    state
                        .lock()
                        .map_err(|_| BrokerError::Configuration("recovery_report_denied"))?
                        .grant_verifier
                        .recovery_page(&request, identity)
                });
            match result {
                Ok(value) => {
                    let encoded = canonicalize_value(&value)
                        .map_err(|_| BrokerError::Configuration("recovery_report_denied"))?;
                    writeln!(stream, "RECOVERY_REPORT {}", encoded.len())?;
                    stream.write_all(&encoded)?;
                }
                Err(_) => stream.write_all(b"ERR recovery_report_denied\n")?,
            }
        }
        b"PULL_EVENTS\n" => {
            let mut state = state
                .lock()
                .map_err(|_| BrokerError::Configuration("broker fleet state is unavailable"))?;
            state.retry_pending_persistence(identity);
            if state
                .pending_state_fenced
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(BrokerError::Configuration("broker_persistence_fenced"));
            }
            let pin = identity.pinned_issuer()?.ok_or(BrokerError::Configuration(
                "controller issuer is not pinned",
            ))?;
            state.queue_overflow_event_if_possible(&pin.node_id)?;
            state.queue_node_revocation_ack_if_possible(&pin.node_id)?;
            state.queue_deferred_revocation_outcomes()?;
            state.queue_pending_cancellations(&pin.node_id)?;
            // Expire stale fulfillment state and retry results the queue could not
            // take; a failure here is retried on the next pull and never blocks it.
            state.maintain_fulfillments();
            let _ = state.flush_fulfillment_reports();
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
        _ if command.starts_with(b"BROWSER_OFFER ") => {
            let grant_id = std::str::from_utf8(&command[14..command.len() - 1])
                .ok()
                .filter(|id| crate::valid_event_identifier(id));
            let offer = grant_id.and_then(|id| {
                state
                    .lock()
                    .ok()?
                    .browser_recipient_offer(identity, id)
                    .ok()
            });
            match offer.and_then(|offer| offer.to_json().ok()) {
                Some(bytes) => {
                    writeln!(stream, "OFFER {}", bytes.len())?;
                    stream.write_all(&bytes)?;
                    stream.write_all(b"\n")?;
                }
                None => stream.write_all(b"ERR browser_provisioning_denied\n")?,
            }
        }
        _ if command.starts_with(b"BROWSER_OFFER_EVENT ") => {
            // The broker signs the outer node event only for an offer it minted
            // itself; the unprivileged relay never supplies a body to sign.
            let grant_id = std::str::from_utf8(&command[20..command.len() - 1])
                .ok()
                .filter(|id| crate::valid_event_identifier(id));
            let event = grant_id.and_then(|id| {
                state
                    .lock()
                    .ok()?
                    .browser_recipient_offer_event(identity, id)
                    .ok()
            });
            match event {
                Some(bytes) => {
                    writeln!(stream, "OFFER_EVENT {}", bytes.len())?;
                    stream.write_all(&bytes)?;
                    stream.write_all(b"\n")?;
                }
                None => stream.write_all(b"ERR browser_provisioning_denied\n")?,
            }
        }
        _ if command.starts_with(b"FULFILL_EVENT ") => {
            // As BROWSER_OFFER_EVENT: the broker signs the outer node event only
            // for an offer or submission it minted itself, never for relay bytes.
            let fulfillment_id = std::str::from_utf8(&command[14..command.len() - 1])
                .ok()
                .filter(|id| crate::valid_event_identifier(id));
            let event = fulfillment_id
                .and_then(|id| state.lock().ok()?.fulfillment_event(identity, id).ok());
            match event {
                Some(bytes) => {
                    writeln!(stream, "FULFILL_EVENT {}", bytes.len())?;
                    stream.write_all(&bytes)?;
                    stream.write_all(b"\n")?;
                }
                None => stream.write_all(b"ERR fulfillment_denied\n")?,
            }
        }
        _ if command.starts_with(b"PROVISION_SOURCE ") => {
            let length = parse_provision_length(command);
            let Some(length) = length else {
                stream.write_all(b"ERR browser_provisioning_denied\n")?;
                return Ok(());
            };
            let mut document = vec![0_u8; length];
            read_exact_until(stream, &mut document, deadline)?;
            let applied = state
                .lock()
                .ok()
                .and_then(|mut state| state.accept_browser_provisioning(identity, &document).ok());
            wipe(&mut document);
            match applied {
                Some(true) => stream.write_all(b"OK browser_source_provisioned\n")?,
                Some(false) => stream.write_all(b"OK browser_source_already_provisioned\n")?,
                None => stream.write_all(b"ERR browser_provisioning_denied\n")?,
            }
        }
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
            let epoch = pin.epoch;
            let mut state = state
                .lock()
                .map_err(|_| BrokerError::Configuration("broker fleet state is unavailable"))?;
            identity.pin_issuer(pin)?;
            state.grant_verifier.observe_issuer_epoch(epoch);
            state.observe_fulfillment_epoch(epoch);
            stream.write_all(b"OK issuer_pinned\n")?;
        }
        _ if command.starts_with(b"RELAY ") => {
            let length = parse_relay_length(command)?;
            let mut document = vec![0_u8; length];
            let read_result = read_exact_until(stream, &mut document, deadline);
            read_result?;
            if is_provisioning_delivery(&document) {
                // Source delivery has exactly one entry point; refuse it here
                // before signature verification can touch the issuer pin.
                wipe(&mut document);
                stream.write_all(b"ERR invalid_controller_document\n")?;
                return Ok(());
            }
            let application = apply_controller_document(state, identity, &document, true);
            wipe(&mut document);
            match application {
                Ok("grant_discarded_expired") => {
                    stream.write_all(b"OK document_discarded grant_expired\n")?
                }
                Ok("grant_discarded_settled") => {
                    stream.write_all(b"OK document_discarded grant_settled\n")?
                }
                Ok("grant_discarded_rejected") => {
                    stream.write_all(b"OK document_discarded grant_rejected\n")?
                }
                Ok("fulfillment_discarded_rejected") => {
                    stream.write_all(b"OK document_discarded fulfillment_rejected\n")?
                }
                Ok(kind) => writeln!(stream, "OK document_applied {kind}")?,
                Err(BrokerError::Configuration(
                    code @ ("controller_document_not_durable" | "broker_persistence_fenced"),
                )) => {
                    eprintln!("controller document not applied durably: {code}");
                    writeln!(stream, "ERR {code}")?;
                }
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

pub(crate) fn apply_controller_document_to_state(
    state: &mut BrokerState,
    identity: &NodeIdentity,
    document: &[u8],
    persist: bool,
) -> Result<&'static str, BrokerError> {
    let kind = identity.verify_controller_document(document)?;
    // Verification may have advanced the pinned epoch; grants of an older
    // epoch lose their authority before anything else is applied.
    if let Some(pin) = identity.pinned_issuer()? {
        state.grant_verifier.observe_issuer_epoch(pin.epoch);
        state.observe_fulfillment_epoch(pin.epoch);
    }
    if persist {
        state.retry_pending_persistence(identity);
    }
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
            state.apply_node_revocation(&revocation.node_id, revocation.revoked_at_ms)?;
            if persist {
                state.persist_or_fence(
                    identity,
                    format!("node_revocation:{}", revocation.node_id),
                    document,
                )?;
            }
            return Ok("node_revocation");
        }
        if envelope.kind() == DocumentKind::Revocation {
            // A correctly signed revocation only removes authority, so it is
            // honoured from any epoch; an older epoch never restores a grant.
            let revocation = Revocation::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller revocation is malformed"))?;
            let pin = identity.pinned_issuer()?.ok_or(BrokerError::Configuration(
                "controller issuer is not pinned",
            ))?;
            if revocation.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller revocation is bound to another node",
                ));
            }
            state.apply_grant_revocation(&pin.node_id, &revocation)?;
            return Ok("revocation");
        }
        if envelope.kind() == DocumentKind::FulfillmentRevocation {
            // Honoured from any epoch for the same reason: it only removes authority.
            let pin = identity.pinned_issuer()?.ok_or(BrokerError::Configuration(
                "controller issuer is not pinned",
            ))?;
            return state.apply_fulfillment_document(identity, &pin, &envelope);
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
                let key = format!("registration:{}", registration.workload_id);
                state.apply_fleet_registration(registration)?;
                if persist {
                    state.persist_or_fence(identity, key, document)?;
                }
            }
        }
        DocumentKind::PolicySnapshot => {
            let policy = PolicySnapshot::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller fleet policy is malformed"))?;
            let changed = state.validate_fleet_policy(&policy)?;
            if changed {
                state.apply_fleet_policy(policy)?;
                if persist {
                    state.persist_or_fence(identity, "policy".to_owned(), document)?;
                }
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
            if envelope.body().get("registration_version").is_none() {
                // The signed pre-migration shape is valid but carries no
                // binding to a registration version. Discard it permanently
                // so it cannot authorize a changed registration or block
                // later documents in the relay inbox.
                let node_id = envelope
                    .body()
                    .get("node_id")
                    .and_then(Value::as_str)
                    .ok_or(BrokerError::Configuration("controller grant is malformed"))?;
                if node_id != pin.node_id {
                    return Err(BrokerError::Configuration(
                        "controller grant is bound to another node",
                    ));
                }
                if persist {
                    let grant_id = envelope
                        .body()
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or(BrokerError::Configuration("controller grant is malformed"))?;
                    let expires_at_ms = envelope
                        .body()
                        .get("expires_at_ms")
                        .and_then(Value::as_u64)
                        .ok_or(BrokerError::Configuration("controller grant is malformed"))?;
                    state.queue_grant_rejection_audit(
                        &pin.node_id,
                        grant_id,
                        expires_at_ms,
                        "missing_registration_version",
                    )?;
                }
                return Ok("grant_discarded_rejected");
            }
            let grant = Grant::from_value(envelope.body())
                .map_err(|_| BrokerError::Configuration("controller grant is malformed"))?;
            if grant.node_id != pin.node_id {
                return Err(BrokerError::Configuration(
                    "controller grant is bound to another node",
                ));
            }
            if state.persistence_fenced() {
                return Err(BrokerError::Configuration("broker_persistence_fenced"));
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
                Err(crate::grants::GRANT_ALREADY_SETTLED) => return Ok("grant_discarded_settled"),
                Err(reason) => {
                    // A verified grant that can never be accepted is audited and
                    // discarded; only transient failures stay retryable, so one
                    // grant cannot block every document queued behind it.
                    let (reason_code, outcome) = match reason {
                        "grant expired before broker receipt" => {
                            ("expired_before_receipt", "grant_discarded_expired")
                        }
                        "grant issuer epoch is not the pinned issuer epoch"
                        | "grant does not match current broker policy and workload registration" => {
                            ("binding_mismatch", "grant_discarded_rejected")
                        }
                        "grant is stale or exceeds the broker lifetime maximum" => {
                            ("stale_at_receipt", "grant_discarded_rejected")
                        }
                        "broker grant capacity reached" => {
                            ("capacity_exceeded", "grant_discarded_rejected")
                        }
                        _ => return Err(BrokerError::Configuration(reason)),
                    };
                    if persist {
                        state.queue_grant_rejection_audit(
                            &pin.node_id,
                            &grant_id,
                            grant_expires_at_ms,
                            reason_code,
                        )?;
                    }
                    return Ok(outcome);
                }
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
            state.apply_grant_revocation(&pin.node_id, &revocation)?;
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
            state.apply_node_revocation(&revocation.node_id, revocation.revoked_at_ms)?;
            if persist {
                state.persist_or_fence(
                    identity,
                    format!("node_revocation:{}", revocation.node_id),
                    document,
                )?;
            }
        }
        DocumentKind::OperationClosed => {
            let closed = OperationClosed::from_value(envelope.body()).map_err(|_| {
                BrokerError::Configuration("controller operation closure is malformed")
            })?;
            if closed.node_id != pin.node_id || closed.issuer_epoch != envelope.epoch() {
                return Err(BrokerError::Configuration(
                    "controller operation closure is bound to another node or epoch",
                ));
            }
            if state
                .operation_requests
                .get(&closed.request_event_key)
                .is_some()
            {
                // A known owner was durable before its request was published.
                // Unknown closures confer no authority and need no local slot.
                state.record_operation_closure(&closed.request_event_key, &closed.status);
                state.persist_pending_node_events()?;
            }
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
            state.grant_verifier.retire_other_recipient_keys(&format!(
                "{}-{}",
                pin.node_id,
                identity.key_version()?
            ));
            state.retire_unfinished_fulfillments();
        }
        DocumentKind::FulfillmentAuthorization
        | DocumentKind::FulfillmentDelivery
        | DocumentKind::FulfillmentRevocation => {
            return state.apply_fulfillment_document(identity, &pin, &envelope);
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
        "operation_closed" => Ok("operation_closed"),
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

/// `PROVISION_SOURCE <len>\n` carries one canonical `provisioning_delivery`
/// document: no leading zero, digits only, at most the dedicated delivery cap.
fn parse_provision_length(command: &[u8]) -> Option<usize> {
    let line = command.strip_prefix(b"PROVISION_SOURCE ")?;
    let text = std::str::from_utf8(line.strip_suffix(b"\n")?).ok()?;
    if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<usize>().ok().filter(|length| {
        (2..=blindpass_core::fleet::MAX_PROVISIONING_DELIVERY_DOCUMENT_BYTES).contains(length)
    })
}

fn is_provisioning_delivery(document: &[u8]) -> bool {
    std::str::from_utf8(document)
        .ok()
        .and_then(|source| SignedEnvelope::from_json(source).ok())
        .is_some_and(|envelope| envelope.kind() == DocumentKind::ProvisioningDelivery)
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
    mod fulfillment;
    mod recovery_reports;
    use super::{
        MAX_CONTROL_DOCUMENT_BYTES, handle_connection, parse_pin, parse_provision_length,
        parse_relay_length, restore_controller_documents,
    };
    use crate::BrokerState;
    use crate::keys::NodeIdentity;
    use blindpass_core::canon::{Value, canonicalize_value, parse_json};
    use blindpass_core::delivery::DeliveryPolicy;
    use blindpass_core::fleet::{
        ApplicationAck, ConsumptionMode, DocumentKind, Grant, NodeKeyRotation, NodeRevocation,
        OperationClosed, PolicySnapshot, Registration, Revocation, SignedEnvelope, TimeReply,
        node_event_message,
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
    fn relay_cap_is_the_shared_node_document_cap_for_every_kind() {
        assert_eq!(
            MAX_CONTROL_DOCUMENT_BYTES,
            blindpass_core::fleet::MAX_NODE_DOCUMENT_BYTES
        );
        assert!(matches!(parse_relay_length(b"RELAY 65536\n"), Ok(65_536)));
        assert!(parse_relay_length(b"RELAY 65537\n").is_err());
        assert!(parse_relay_length(b"RELAY 131072\n").is_err());
    }

    #[test]
    fn provision_source_length_gate_accepts_exactly_the_delivery_cap() {
        assert_eq!(
            blindpass_core::fleet::MAX_PROVISIONING_DELIVERY_DOCUMENT_BYTES,
            131_072
        );
        assert_eq!(
            parse_provision_length(b"PROVISION_SOURCE 131072\n"),
            Some(131_072)
        );
        assert_eq!(parse_provision_length(b"PROVISION_SOURCE 2\n"), Some(2));
        assert_eq!(
            parse_provision_length(b"PROVISION_SOURCE 65537\n"),
            Some(65_537)
        );
        for rejected in [
            &b"PROVISION_SOURCE 131073\n"[..],
            b"PROVISION_SOURCE 0131072\n",
            b"PROVISION_SOURCE 0\n",
            b"PROVISION_SOURCE 1\n",
            b"PROVISION_SOURCE \n",
            b"PROVISION_SOURCE +5\n",
            b"PROVISION_SOURCE 5 \n",
            b"PROVISION_SOURCE 1e3\n",
            b"PROVISION_SOURCE 99999999999999999999\n",
            b"PROVISION_SOURCE 131072",
        ] {
            assert_eq!(parse_provision_length(rejected), None, "{rejected:?}");
        }
    }

    fn short_deadline_exchange(
        command: &[u8],
        payload: &[u8],
        close_after_payload: bool,
    ) -> Result<Vec<u8>, crate::BrokerError> {
        let directory = temporary_directory();
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        let state = std::sync::Arc::new(std::sync::Mutex::new(BrokerState::new(
            DeliveryPolicy::default(),
        )));
        let (mut broker, mut client) = UnixStream::pair().unwrap();
        let mut request = command.to_vec();
        let payload = payload.to_vec();
        // Write from a thread: a large frame must not depend on socket buffer size.
        let writer = std::thread::spawn(move || {
            request.extend_from_slice(&payload);
            let _ = client.write_all(&request);
            if close_after_payload {
                let _ = client.shutdown(std::net::Shutdown::Write);
            }
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            response
        });
        let result = handle_connection(
            &mut broker,
            Some(current_gid()),
            identity,
            state,
            Instant::now() + Duration::from_millis(1_500),
        );
        drop(broker);
        let response = writer.join().unwrap();
        let _ = std::fs::remove_dir_all(directory);
        result.map(|()| response)
    }

    #[test]
    fn provision_source_reads_exactly_the_delivery_cap_and_refuses_one_byte_more_before_reading() {
        let at_cap = vec![b'x'; 131_072];
        assert_eq!(
            short_deadline_exchange(b"PROVISION_SOURCE 131072\n", &at_cap, true).unwrap(),
            b"ERR browser_provisioning_denied\n"
        );
        // One byte short of the declared length is a partial frame, not a document.
        assert!(
            short_deadline_exchange(b"PROVISION_SOURCE 131072\n", &at_cap[..131_071], true)
                .is_err()
        );
        // Over the cap is refused from the header alone: no payload is ever sent
        // and the handler answers before its read deadline.
        let started = Instant::now();
        assert_eq!(
            short_deadline_exchange(b"PROVISION_SOURCE 131073\n", &[], false).unwrap(),
            b"ERR browser_provisioning_denied\n"
        );
        assert!(started.elapsed() < Duration::from_millis(1_000));
    }

    #[test]
    fn relay_reads_exactly_the_node_document_cap_and_refuses_one_byte_more() {
        let at_cap = vec![b'x'; 65_536];
        assert_eq!(
            short_deadline_exchange(b"RELAY 65536\n", &at_cap, true).unwrap(),
            b"ERR invalid_controller_document\n"
        );
        assert!(short_deadline_exchange(b"RELAY 65536\n", &at_cap[..65_535], true).is_err());
        // A header over the cap is an error before any payload read.
        let started = Instant::now();
        assert!(short_deadline_exchange(b"RELAY 65537\n", &[], false).is_err());
        assert!(started.elapsed() < Duration::from_millis(1_000));
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
                challenge_received_at_ms: now_ms,
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
            registration_version: 1,
            policy_version: 4,
            approval_reference: None,
            request_event_key: None,
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
            b"OK document_discarded grant_settled\n"
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
                challenge_received_at_ms: now_ms + 1,
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
            b"OK document_discarded grant_settled\n",
            "the durable tombstone settles the redelivered grant after restart"
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
            challenge_received_at_ms: now_ms,
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
            registration_version: 1,
            policy_version: 4,
            approval_reference: None,
            request_event_key: None,
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

    /// A pinned broker with a registration, a policy and fresh signed time,
    /// driven only through the control socket like the relay does.
    pub(crate) struct Fleet {
        pub directory: std::path::PathBuf,
        pub identity: std::sync::Arc<NodeIdentity>,
        pub state: std::sync::Arc<std::sync::Mutex<BrokerState>>,
        issuer: Ed25519KeyPair,
        issuer_key_id: String,
        pub now_ms: u64,
    }

    impl Fleet {
        pub fn new(seed: u8) -> Self {
            let directory = temporary_directory();
            let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
            let issuer = Ed25519KeyPair::from_seed(&[seed; 32]).unwrap();
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
            let mut state = BrokerState::new(DeliveryPolicy::default());
            state.operation_directory = directory.join("ops");
            state.configure_grant_storage(&identity).unwrap();
            let fleet = Self {
                directory,
                identity,
                state: std::sync::Arc::new(std::sync::Mutex::new(state)),
                issuer,
                issuer_key_id,
                now_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            };
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
                assert!(fleet.relay(&fleet.sign(kind, body, 1)).starts_with(b"OK "));
            }
            fleet.refresh_time(1);
            fleet
        }

        pub fn sign(&self, kind: DocumentKind, body: Value, epoch: u64) -> Vec<u8> {
            SignedEnvelope::sign(kind, body, &self.issuer_key_id, epoch, &self.issuer)
                .unwrap()
                .to_json()
                .unwrap()
        }

        pub fn relay(&self, document: &[u8]) -> Vec<u8> {
            relay_signed_document(&self.identity, &self.state, document)
        }

        pub fn refresh_time(&self, epoch: u64) {
            let response = control_exchange(&self.identity, &self.state, b"TIME_CHALLENGE\n");
            let challenge = std::str::from_utf8(&response)
                .unwrap()
                .strip_prefix("TIME ")
                .unwrap()
                .strip_suffix('\n')
                .unwrap()
                .to_owned();
            let reply = TimeReply {
                node_id: "nd_node-a".to_owned(),
                challenge,
                challenge_received_at_ms: self.now_ms,
                controller_time_ms: self.now_ms,
                issuer_epoch: epoch,
            };
            assert_eq!(
                self.relay(&self.sign(DocumentKind::TimeReply, reply.to_value().unwrap(), epoch)),
                b"OK document_applied time_reply\n"
            );
        }

        pub fn grant(&self, index: u8, epoch: u64) -> Grant {
            Grant {
                id: format!("gr_{index:02}23456789abcdef0123456789abcdef"),
                operation_id: format!("op_{index:02}23456789abcdef0123456789abcdef"),
                node_id: "nd_node-a".to_owned(),
                workload_id: "wl_worker-a".to_owned(),
                invocation_id: "invocation-a".to_owned(),
                unit: "worker.service".to_owned(),
                account: "worker".to_owned(),
                resource_id: format!("marker-{index}"),
                recipient_key_id: "nd_node-a-1".to_owned(),
                registration_version: 1,
                policy_version: 4,
                approval_reference: None,
                request_event_key: None,
                action: "noop.marker".to_owned(),
                mode: ConsumptionMode::File,
                audience: "blindpass-node".to_owned(),
                issuer_epoch: epoch,
                issued_at_ms: self.now_ms,
                expires_at_ms: self.now_ms + 60_000,
                local_ceiling_seconds: 60,
            }
        }

        pub fn deliver(&self, grant: &Grant) -> Vec<u8> {
            self.relay(&self.sign(
                DocumentKind::Grant,
                grant.to_value().unwrap(),
                grant.issuer_epoch,
            ))
        }

        pub fn revocation(&self, grant_id: &str, epoch: u64) -> Vec<u8> {
            let revocation = Revocation {
                grant_id: grant_id.to_owned(),
                node_id: "nd_node-a".to_owned(),
                reason: "operator".to_owned(),
                revoked_at_ms: self.now_ms,
                retain_until_ms: self.now_ms + 7 * 24 * 60 * 60 * 1_000,
                issuer_epoch: epoch,
            };
            self.sign(
                DocumentKind::Revocation,
                revocation.to_value().unwrap(),
                epoch,
            )
        }

        pub fn peer() -> PeerIdentity {
            PeerIdentity::fixture(
                1000,
                current_gid(),
                "worker.service",
                "invocation-a",
                "worker",
            )
        }

        pub fn request(operation: String) -> WorkloadRequest {
            WorkloadRequest {
                node_id: "nd_node-a".to_owned(),
                workload_id: "wl_worker-a".to_owned(),
                claimed_unit: "worker.service".to_owned(),
                claimed_invocation_id: "invocation-a".to_owned(),
                operation,
            }
        }

        pub fn consume(&self, grant_id: &str) -> Result<Vec<u8>, crate::BrokerError> {
            self.state
                .lock()
                .unwrap()
                .process_workload(&Self::peer(), &Self::request(format!("consume:{grant_id}")))
        }

        pub fn marker_exists(&self, grant_id: &str) -> bool {
            self.directory
                .join("ops")
                .join(format!("{grant_id}.marker"))
                .exists()
        }

        pub fn pulled_events(&self) -> Vec<Value> {
            let events = control_exchange(&self.identity, &self.state, b"PULL_EVENTS\n");
            let header_end = events.iter().position(|byte| *byte == b'\n').unwrap();
            let payload = std::str::from_utf8(&events[header_end + 1..events.len() - 1]).unwrap();
            parse_json(payload).unwrap().as_array().unwrap().to_vec()
        }
    }

    impl Drop for Fleet {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn denial(result: Result<Vec<u8>, crate::BrokerError>) -> &'static str {
        match result {
            Err(crate::BrokerError::Configuration(code)) => code,
            other => panic!("expected a coded denial, got {other:?}"),
        }
    }

    #[test]
    fn issuer_epoch_bump_purges_old_grants_and_lower_epoch_revocations_still_apply() {
        let fleet = Fleet::new(31);
        let old_grant = fleet.grant(1, 1);
        assert_eq!(fleet.deliver(&old_grant), b"OK document_applied grant\n");
        let pending_grant = fleet.grant(2, 1);

        // A newer-epoch document advances the pin and retires every grant of
        // the older epoch before it can be consumed.
        fleet.refresh_time(2);
        assert_eq!(fleet.identity.pinned_issuer().unwrap().unwrap().epoch, 2);
        assert_eq!(denial(fleet.consume(&old_grant.id)), "grant_epoch_stale");
        assert!(!fleet.marker_exists(&old_grant.id));
        assert_eq!(
            fleet.deliver(&pending_grant),
            b"OK document_applied stale_epoch\n"
        );
        assert_eq!(denial(fleet.consume(&pending_grant.id)), "grant_unknown");

        // A correctly signed revocation from the older epoch is still a
        // tombstone and denies the grant id from now on.
        let current = fleet.grant(3, 2);
        assert_eq!(fleet.deliver(&current), b"OK document_applied grant\n");
        assert_eq!(
            fleet.relay(&fleet.revocation(&current.id, 1)),
            b"OK document_applied revocation\n"
        );
        assert_eq!(denial(fleet.consume(&current.id)), "grant_revoked");
        assert!(!fleet.marker_exists(&current.id));
        assert_eq!(
            fleet.deliver(&current),
            b"OK document_discarded grant_settled\n",
            "the tombstone also blocks redelivery"
        );
        assert_eq!(denial(fleet.consume(&current.id)), "grant_revoked");
    }

    fn grant_rejection_reasons(fleet: &Fleet) -> Vec<(String, String)> {
        fleet
            .pulled_events()
            .iter()
            .filter_map(|event| {
                let body = event.get("body")?;
                (body.get("action").and_then(Value::as_str) == Some("grant_rejected")).then(|| {
                    (
                        body.get("grant_id")
                            .and_then(Value::as_str)
                            .unwrap()
                            .to_owned(),
                        body.get("reason_code")
                            .and_then(Value::as_str)
                            .unwrap()
                            .to_owned(),
                    )
                })
            })
            .collect()
    }

    #[test]
    fn redelivered_or_permanently_invalid_grants_are_discarded_not_retried() {
        let fleet = Fleet::new(41);

        // An identical retransmission of a live grant stays idempotent.
        let live = fleet.grant(1, 1);
        assert_eq!(fleet.deliver(&live), b"OK document_applied grant\n");
        assert_eq!(fleet.deliver(&live), b"OK document_applied grant\n");

        // A consumed grant redelivered after a session break is settled.
        assert!(fleet.consume(&live.id).is_ok());
        assert_eq!(
            fleet.deliver(&live),
            b"OK document_discarded grant_settled\n"
        );
        assert_eq!(denial(fleet.consume(&live.id)), "grant_consumed");

        // A grant accepted under the old node key is retired by the signed
        // rotation, and its redelivery no longer blocks the channel.
        let before_rotation = fleet.grant(2, 1);
        assert_eq!(
            fleet.deliver(&before_rotation),
            b"OK document_applied grant\n"
        );
        let (to_key_version, candidate) = fleet.identity.prepare_rotation().unwrap();
        let rotation = NodeKeyRotation {
            node_id: "nd_node-a".to_owned(),
            rotation_id: "rot_test_rotation_000000000041".to_owned(),
            from_key_version: 1,
            to_key_version,
            signing_public: candidate.signing_public,
            recipient_public: candidate.recipient_public,
            fingerprint: candidate.fingerprint,
            issuer_epoch: 1,
        };
        assert_eq!(
            fleet.relay(&fleet.sign(
                DocumentKind::NodeKeyRotation,
                rotation.to_value().unwrap(),
                1
            )),
            b"OK document_applied node_key_rotation\n"
        );
        assert_eq!(
            denial(fleet.consume(&before_rotation.id)),
            "grant_key_rotated"
        );
        assert!(!fleet.marker_exists(&before_rotation.id));
        assert_eq!(
            fleet.deliver(&before_rotation),
            b"OK document_discarded grant_settled\n"
        );

        // A grant that was never accepted and can never match the current
        // key, policy or registration is discarded with a durable audit event.
        let old_key = fleet.grant(3, 1);
        assert_eq!(
            fleet.deliver(&old_key),
            b"OK document_discarded grant_rejected\n"
        );
        assert_eq!(denial(fleet.consume(&old_key.id)), "grant_unknown");
        let mut stale = fleet.grant(4, 1);
        stale.recipient_key_id = "nd_node-a-2".to_owned();
        stale.issued_at_ms = fleet.now_ms - 61_000;
        assert_eq!(
            fleet.deliver(&stale),
            b"OK document_discarded grant_rejected\n"
        );
        assert_eq!(
            fleet.deliver(&stale),
            b"OK document_discarded grant_rejected\n"
        );
        let mut legacy = fleet.grant(6, 1);
        legacy.recipient_key_id = "nd_node-a-2".to_owned();
        let mut legacy_body = legacy.to_value().unwrap();
        if let Value::Object(fields) = &mut legacy_body {
            fields.retain(|(name, _)| name != "registration_version");
        }
        assert_eq!(
            fleet.relay(&fleet.sign(DocumentKind::Grant, legacy_body, 1)),
            b"OK document_discarded grant_rejected\n"
        );
        assert_eq!(denial(fleet.consume(&legacy.id)), "grant_unknown");
        assert_eq!(
            grant_rejection_reasons(&fleet),
            vec![
                (old_key.id.clone(), "binding_mismatch".to_owned()),
                (stale.id.clone(), "stale_at_receipt".to_owned()),
                (legacy.id.clone(), "missing_registration_version".to_owned()),
            ],
            "each rejection is audited exactly once"
        );

        // A grant that is not the same signed content keeps failing loudly.
        let mut reused = fleet.grant(5, 1);
        reused.recipient_key_id = "nd_node-a-2".to_owned();
        assert_eq!(fleet.deliver(&reused), b"OK document_applied grant\n");
        reused.resource_id = "marker-other".to_owned();
        assert_eq!(fleet.deliver(&reused), b"ERR invalid_controller_document\n");
    }

    fn request_operation() -> String {
        let body = Value::Object(vec![
            ("action".to_owned(), Value::String("noop.marker".to_owned())),
            ("mode".to_owned(), Value::String("file".to_owned())),
            ("purpose".to_owned(), Value::String("test".to_owned())),
            (
                "resource_id".to_owned(),
                Value::String("marker-request".to_owned()),
            ),
            ("ttl_seconds".to_owned(), Value::Unsigned(30)),
        ]);
        format!(
            "request:{}",
            base64_url_encode(&canonicalize_value(&body).unwrap())
        )
    }

    fn operation_request(fleet: &Fleet) -> Result<Vec<u8>, crate::BrokerError> {
        fleet
            .state
            .lock()
            .unwrap()
            .process_workload(&Fleet::peer(), &Fleet::request(request_operation()))
    }

    /// Replace a durable state file with a non-empty directory so that the
    /// next atomic write or append to it fails.
    fn block_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        std::fs::create_dir(path).unwrap();
        std::fs::write(path.join("blocker"), b"").unwrap();
    }

    fn unblock_path(path: &std::path::Path) {
        std::fs::remove_dir_all(path).unwrap();
    }

    fn assert_fenced(fleet: &Fleet) {
        assert_eq!(
            fleet.deliver(&fleet.grant(90, 1)),
            b"ERR broker_persistence_fenced\n"
        );
        assert_eq!(
            denial(operation_request(fleet)),
            "broker_persistence_fenced"
        );
    }

    #[test]
    fn grant_revocation_applies_in_memory_when_its_tombstone_cannot_be_persisted() {
        let fleet = Fleet::new(37);
        let grant = fleet.grant(1, 1);
        assert_eq!(fleet.deliver(&grant), b"OK document_applied grant\n");
        let journal = fleet.identity.revoked_grant_journal_path();
        block_path(&journal);
        let revocation = fleet.revocation(&grant.id, 1);
        assert_eq!(
            fleet.relay(&revocation),
            b"ERR controller_document_not_durable\n"
        );
        assert!(
            !fleet
                .state
                .lock()
                .unwrap()
                .grant_verifier
                .is_accepted(&grant.id)
        );
        assert_eq!(
            denial(fleet.consume(&grant.id)),
            "broker_persistence_fenced"
        );
        assert!(!fleet.marker_exists(&grant.id));
        assert_fenced(&fleet);

        // The relay retries; once the write succeeds the fence lifts.
        unblock_path(&journal);
        assert_eq!(
            fleet.relay(&revocation),
            b"OK document_applied revocation\n"
        );
        assert!(
            std::fs::read_to_string(&journal)
                .unwrap()
                .contains(&grant.id)
        );
        let next = fleet.grant(2, 1);
        assert_eq!(fleet.deliver(&next), b"OK document_applied grant\n");
        assert_eq!(denial(fleet.consume(&grant.id)), "grant_revoked");
    }

    #[test]
    fn registration_revocation_applies_in_memory_when_it_cannot_be_persisted() {
        let fleet = Fleet::new(41);
        let grant = fleet.grant(1, 1);
        assert_eq!(fleet.deliver(&grant), b"OK document_applied grant\n");
        let path = fleet.directory.join("fleet-registration-wl_worker-a.json");
        block_path(&path);
        let revoked = Registration {
            node_id: "nd_node-a".to_owned(),
            workload_id: "wl_worker-a".to_owned(),
            unit: "worker.service".to_owned(),
            account: "worker".to_owned(),
            invocation_id: None,
            status: "revoked".to_owned(),
            consumption_mode: ConsumptionMode::File,
            registration_version: 2,
            policy_version: 4,
            local_ceiling_seconds: 60,
        };
        let document = fleet.sign(DocumentKind::Registration, revoked.to_value().unwrap(), 1);
        assert_eq!(
            fleet.relay(&document),
            b"ERR controller_document_not_durable\n"
        );
        assert!(fleet.consume(&grant.id).is_err());
        assert!(!fleet.marker_exists(&grant.id));
        let health = fleet
            .state
            .lock()
            .unwrap()
            .process_workload(&Fleet::peer(), &Fleet::request("health".to_owned()));
        assert!(
            health.is_err(),
            "the revoked registration must not authorize"
        );
        assert_eq!(
            fleet.deliver(&fleet.grant(90, 1)),
            b"ERR broker_persistence_fenced\n"
        );

        unblock_path(&path);
        assert_eq!(
            fleet.relay(&document),
            b"OK document_applied registration\n"
        );
        assert_eq!(std::fs::read(&path).unwrap(), document);
        drop(fleet.state.lock().unwrap());
        let mut restored = BrokerState::new(DeliveryPolicy::default());
        restored.configure_grant_storage(&fleet.identity).unwrap();
        restore_controller_documents(&mut restored, &fleet.identity).unwrap();
        assert_eq!(
            restored.fleet_registrations["wl_worker-a"].status,
            "revoked"
        );
    }

    #[test]
    fn policy_narrowing_and_node_revocation_apply_when_they_cannot_be_persisted() {
        let fleet = Fleet::new(43);
        let grant = fleet.grant(1, 1);
        assert_eq!(fleet.deliver(&grant), b"OK document_applied grant\n");
        let policy_path = fleet.directory.join("fleet-policy.json");
        block_path(&policy_path);
        let narrowed = PolicySnapshot {
            policy_version: 5,
            local_ceiling_seconds: 30,
            allowed_actions: Vec::new(),
            allowed_modes: Vec::new(),
        };
        let policy_document = fleet.sign(
            DocumentKind::PolicySnapshot,
            narrowed.to_value().unwrap(),
            1,
        );
        assert_eq!(
            fleet.relay(&policy_document),
            b"ERR controller_document_not_durable\n"
        );
        assert_eq!(
            fleet
                .state
                .lock()
                .unwrap()
                .fleet_policy
                .as_ref()
                .unwrap()
                .policy_version,
            5
        );
        assert!(fleet.consume(&grant.id).is_err());
        assert_fenced(&fleet);
        unblock_path(&policy_path);
        assert_eq!(
            fleet.relay(&policy_document),
            b"OK document_applied policy_snapshot\n"
        );
        assert_eq!(std::fs::read(&policy_path).unwrap(), policy_document);

        let node_path = fleet.directory.join("node-revocation-nd_node-a.json");
        block_path(&node_path);
        let node_revocation = NodeRevocation {
            node_id: "nd_node-a".to_owned(),
            revoked_at_ms: fleet.now_ms,
            issuer_epoch: 1,
        };
        let node_document = fleet.sign(
            DocumentKind::NodeRevocation,
            node_revocation.to_value().unwrap(),
            1,
        );
        assert_eq!(
            fleet.relay(&node_document),
            b"ERR controller_document_not_durable\n"
        );
        assert!(fleet.state.lock().unwrap().node_revoked);
        unblock_path(&node_path);
        assert_eq!(
            fleet.relay(&node_document),
            b"OK document_applied node_revocation\n"
        );
        assert_eq!(std::fs::read(&node_path).unwrap(), node_document);
    }

    fn revocation_outcomes(events: &[Value]) -> Vec<(String, Value)> {
        events
            .iter()
            .filter(|event| {
                event
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| key.starts_with("grant_revocation_applied_"))
            })
            .map(|event| {
                assert_eq!(event.get("kind").and_then(Value::as_str), Some("audit"));
                (
                    event
                        .get("idempotency_key")
                        .and_then(Value::as_str)
                        .unwrap()
                        .to_owned(),
                    event.get("body").unwrap().clone(),
                )
            })
            .collect()
    }

    fn acknowledge_all(fleet: &Fleet) {
        let keys = fleet
            .pulled_events()
            .iter()
            .map(|event| {
                event
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        if keys.is_empty() {
            return;
        }
        let ack = ApplicationAck {
            node_id: "nd_node-a".to_owned(),
            issuer_epoch: 1,
            acknowledged_at_ms: fleet.now_ms,
            event_keys: keys,
        };
        assert_eq!(
            fleet.relay(&fleet.sign(DocumentKind::ApplicationAck, ack.to_value().unwrap(), 1)),
            b"OK document_applied application_ack\n"
        );
    }

    #[test]
    fn applied_grant_revocations_emit_one_signed_outcome_each() {
        let fleet = Fleet::new(47);
        let unconsumed = fleet.grant(1, 1);
        let consumed = fleet.grant(2, 1);
        for grant in [&unconsumed, &consumed] {
            assert_eq!(fleet.deliver(grant), b"OK document_applied grant\n");
        }
        assert!(fleet.consume(&consumed.id).is_ok());
        acknowledge_all(&fleet);
        let never_delivered = fleet.grant(3, 1);
        for grant in [&unconsumed, &consumed, &never_delivered] {
            assert_eq!(
                fleet.relay(&fleet.revocation(&grant.id, 1)),
                b"OK document_applied revocation\n"
            );
        }
        let events = fleet.pulled_events();
        let outcomes = revocation_outcomes(&events);
        assert_eq!(outcomes.len(), 3);
        for ((key, body), (grant, outcome)) in outcomes.iter().zip([
            (&unconsumed, "revoked_before_consumption"),
            (&consumed, "already_consumed"),
            (&never_delivered, "not_received"),
        ]) {
            assert_eq!(key, &format!("grant_revocation_applied_{}", grant.id));
            let fields = body.as_object().unwrap();
            assert_eq!(fields.len(), 5);
            assert_eq!(
                body.get("action").and_then(Value::as_str),
                Some("grant_revocation_applied")
            );
            assert_eq!(
                body.get("node_id").and_then(Value::as_str),
                Some("nd_node-a")
            );
            assert_eq!(
                body.get("grant_id").and_then(Value::as_str),
                Some(grant.id.as_str())
            );
            assert_eq!(body.get("outcome").and_then(Value::as_str), Some(outcome));
            assert!(body.get("observed_at_ms").and_then(Value::as_u64).unwrap() >= fleet.now_ms);
        }
        // The events carry a broker signature over the fixed node-event message.
        let public = fleet.identity.public_identity().unwrap();
        let public_key =
            blindpass_core::signing::base64_url_decode(&public.signing_public, 32).unwrap();
        for event in &events {
            let message = node_event_message(
                "nd_node-a",
                event
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .unwrap(),
                "audit",
                event.get("body").unwrap(),
            )
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
        }

        // Replays do not duplicate a pending or acknowledged outcome, before
        // or after a restart.
        assert_eq!(
            fleet.relay(&fleet.revocation(&unconsumed.id, 1)),
            b"OK document_applied revocation\n"
        );
        assert_eq!(revocation_outcomes(&fleet.pulled_events()).len(), 3);
        acknowledge_all(&fleet);
        assert_eq!(
            fleet.relay(&fleet.revocation(&unconsumed.id, 1)),
            b"OK document_applied revocation\n"
        );
        assert!(fleet.pulled_events().is_empty());
        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted.configure_grant_storage(&fleet.identity).unwrap();
        *fleet.state.lock().unwrap() = restarted;
        assert_eq!(
            fleet.relay(&fleet.revocation(&consumed.id, 1)),
            b"OK document_applied revocation\n"
        );
        assert!(fleet.pulled_events().is_empty());
    }

    #[test]
    fn grant_revocation_applies_under_audit_backpressure_and_reports_later() {
        let fleet = Fleet::new(53);
        let grant = fleet.grant(1, 1);
        assert_eq!(fleet.deliver(&grant), b"OK document_applied grant\n");
        {
            let mut state = fleet.state.lock().unwrap();
            state.pending_node_events = (0..crate::MAX_BROKER_AUDIT_EVENTS)
                .map(|index| crate::PendingNodeEvent {
                    idempotency_key: format!("broker-event-capacity-{index:08}"),
                    kind: "audit".to_owned(),
                    body: Value::Object(vec![(
                        "action".to_owned(),
                        Value::String("existing_event".to_owned()),
                    )]),
                })
                .collect();
        }
        assert_eq!(
            fleet.relay(&fleet.revocation(&grant.id, 1)),
            b"OK document_applied revocation\n"
        );
        assert!(
            fleet.state.lock().unwrap().audit_overflow_pending,
            "a deferred outcome is recorded durably as an audit overflow"
        );
        assert_eq!(denial(fleet.consume(&grant.id)), "audit_backpressure");
        assert!(
            !fleet
                .state
                .lock()
                .unwrap()
                .grant_verifier
                .is_accepted(&grant.id)
        );
        assert!(!fleet.marker_exists(&grant.id));
        assert_eq!(
            fleet.state.lock().unwrap().pending_node_events.len(),
            crate::MAX_BROKER_AUDIT_EVENTS
        );

        // The relay already acknowledged the revocation. Restart without
        // redelivering it; startup must recover the deferred outcome itself.
        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted.configure_grant_storage(&fleet.identity).unwrap();
        restore_controller_documents(&mut restarted, &fleet.identity).unwrap();
        *fleet.state.lock().unwrap() = restarted;

        // Space returns after an acknowledgement; the outcome is emitted
        // exactly once and the grant stays revoked. Four acknowledgements
        // leave room for the overflow audit, the outcome and a consumption.
        let ack = ApplicationAck {
            node_id: "nd_node-a".to_owned(),
            issuer_epoch: 1,
            acknowledged_at_ms: fleet.now_ms,
            event_keys: vec![
                "broker-event-capacity-00000000".to_owned(),
                "broker-event-capacity-00000001".to_owned(),
                "broker-event-capacity-00000002".to_owned(),
                "broker-event-capacity-00000003".to_owned(),
            ],
        };
        assert_eq!(
            fleet.relay(&fleet.sign(DocumentKind::ApplicationAck, ack.to_value().unwrap(), 1)),
            b"OK document_applied application_ack\n"
        );
        let state = fleet.state.lock().unwrap();
        let outcomes = state
            .pending_node_events
            .iter()
            .filter(|event| {
                event.idempotency_key == format!("grant_revocation_applied_{}", grant.id)
            })
            .collect::<Vec<_>>();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0].body.get("outcome").and_then(Value::as_str),
            Some("revoked_before_consumption")
        );
        drop(state);
        fleet.refresh_time(1);
        assert_eq!(denial(fleet.consume(&grant.id)), "grant_revoked");
    }

    fn status(
        fleet: &Fleet,
        peer: &PeerIdentity,
        event_key: &str,
    ) -> Result<Vec<u8>, crate::BrokerError> {
        let mut request = Fleet::request(format!("status:{event_key}"));
        request.claimed_invocation_id = peer.invocation_id.clone().unwrap();
        fleet.state.lock().unwrap().process_workload(peer, &request)
    }

    fn closure(fleet: &Fleet, node_id: &str, event_key: &str, status: &str, epoch: u64) -> Vec<u8> {
        let closed = OperationClosed {
            node_id: node_id.to_owned(),
            operation_id: "op_0123456789abcdef0123456789abcdef".to_owned(),
            request_event_key: event_key.to_owned(),
            status: status.to_owned(),
            closed_at_ms: fleet.now_ms,
            issuer_epoch: epoch,
        };
        fleet.sign(
            DocumentKind::OperationClosed,
            closed.to_value().unwrap(),
            epoch,
        )
    }

    #[test]
    fn recipient_offer_cannot_be_relayed_as_controller_authority() {
        use blindpass_core::provisioning::{
            BrowserProvisioningBinding, sign_browser_recipient_offer,
        };
        let fleet = Fleet::new(114);
        let binding = BrowserProvisioningBinding::from_json(include_str!(
            "../../../packages/browser-ui/tests/fixtures/fleet-provisioning-v1.json"
        ))
        .unwrap();
        let signer = Ed25519KeyPair::generate().unwrap();
        let offer = sign_browser_recipient_offer(&binding, &signer)
            .unwrap()
            .to_json()
            .unwrap();
        // Even a controller-signed document with this kind has no grant role.
        let controller_signed =
            fleet.sign(DocumentKind::RecipientOffer, binding.to_value().unwrap(), 1);
        for document in [&offer, &controller_signed] {
            assert_eq!(fleet.relay(document), b"ERR invalid_controller_document\n");
            assert_eq!(fleet.identity.pinned_issuer().unwrap().unwrap().epoch, 1);
            let state = fleet.state.lock().unwrap();
            assert!(state.pending_node_events.is_empty());
            assert!(state.operation_requests.values.is_empty());
            assert!(state.original_workload_leases.is_empty());
            assert_eq!(state.fleet_policy.as_ref().unwrap().policy_version, 4);
        }
        std::fs::remove_dir_all(&fleet.directory).unwrap();
    }

    #[test]
    fn signed_browser_grant_crosses_control_transport_and_correlates_with_its_request() {
        use std::os::unix::fs::PermissionsExt;
        let fleet = Fleet::new(113);
        let mut registration = fleet
            .state
            .lock()
            .unwrap()
            .fleet_registrations
            .get("wl_worker-a")
            .unwrap()
            .clone();
        registration.registration_version = 2;
        registration.policy_version = 5;
        registration.consumption_mode = ConsumptionMode::BrowserSession;
        let policy = PolicySnapshot {
            policy_version: 5,
            local_ceiling_seconds: 60,
            allowed_actions: vec!["browser.session".into()],
            allowed_modes: vec![ConsumptionMode::BrowserSession],
        };
        for (kind, body) in [
            (DocumentKind::Registration, registration.to_value().unwrap()),
            (DocumentKind::PolicySnapshot, policy.to_value().unwrap()),
        ] {
            assert!(fleet.relay(&fleet.sign(kind, body, 1)).starts_with(b"OK "));
        }
        let resource = crate::BrowserResource::from_value(&parse_json(r#"{"resource_id":"report-primary","workload_ids":["wl_worker-a"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","revocation":{"kind":"fixture-admin","credential_unit":"blindpass-session-revoker@.service","credential_name":"fixture-admin"},"configuration":{"kind":"fixture","origin":"https://127.0.0.1:4443","account":"primary","sessionMaxMs":300000}}"#).unwrap()).unwrap();
        let bytes = canonicalize_value(&Value::Object(vec![
            ("version".into(), Value::Unsigned(1)),
            ("resources".into(), Value::Array(vec![resource.to_value()])),
        ]))
        .unwrap();
        {
            let mut state = fleet.state.lock().unwrap();
            let (unit, name) = resource.credential_destination();
            state.loader_policy.map_unit(unit, name).unwrap();
            let (admin_unit, admin_name) = resource
                .revocation_profile()
                .unwrap()
                .credential_destination();
            state
                .loader_policy
                .map_unit(admin_unit, admin_name)
                .unwrap();
            state
                .credentials
                .insert(
                    &crate::destination_key(admin_unit, admin_name),
                    "a".repeat(64).as_bytes(),
                )
                .unwrap();
            state
                .credentials
                .insert(
                    &crate::destination_key(unit, name),
                    b"P05-SIGNED-SOURCE-CANARY",
                )
                .unwrap();
            state.credential_expiries.insert(
                crate::destination_key(unit, name),
                crate::CredentialExpiry::after(Duration::from_secs(300)).unwrap(),
            );
            state
                .configure_browser_catalog(
                    crate::browser_catalog::BrowserCatalog::from_bytes(&bytes).unwrap(),
                )
                .unwrap();
        }
        let invocation = "a".repeat(32);
        let peer =
            PeerIdentity::fixture(1000, current_gid(), "worker.service", &invocation, "worker");
        let mut request = Fleet::request(format!("request:{}", base64_url_encode(br#"{"action":"browser.session","mode":"browser_session","purpose":"read report","resource_id":"report-primary","ttl_seconds":60}"#)));
        request.claimed_invocation_id = invocation.clone();
        let requested = fleet
            .state
            .lock()
            .unwrap()
            .process_workload(&peer, &request)
            .unwrap();
        let key = std::str::from_utf8(&requested)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .trim()
            .to_owned();
        {
            let mut state = fleet.state.lock().unwrap();
            let authorization =
                crate::authorize_workload(&peer, &request, &state.workloads).unwrap();
            let (lease, _) = crate::original_workload::OriginalWorkloadLease::fixture(
                &key,
                authorization,
                peer.clone(),
            );
            state.original_workload_leases.insert(key.clone(), lease);
        }
        let mut grant = fleet.grant(1, 1);
        grant.action = "browser.session".into();
        grant.mode = ConsumptionMode::BrowserSession;
        grant.invocation_id = invocation;
        grant.resource_id = "report-primary".into();
        grant.registration_version = 2;
        grant.policy_version = 5;
        grant.request_event_key = Some(key.clone());
        let signed = fleet.sign(DocumentKind::Grant, grant.to_value().unwrap(), 1);
        let tampered = String::from_utf8(signed.clone())
            .unwrap()
            .replace("report-primary", "report-isolation");
        assert!(fleet.relay(tampered.as_bytes()).starts_with(b"ERR "));
        assert!(fleet.relay(&signed).starts_with(b"OK "));
        request.operation = format!("status:{key}");
        assert_eq!(
            fleet
                .state
                .lock()
                .unwrap()
                .process_workload(&peer, &request)
                .unwrap(),
            format!(
                "OK operation_status granted {} {}\n",
                grant.id, grant.operation_id
            )
            .as_bytes()
        );
        let path = fleet.directory.join("sessions");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal =
            crate::session_journal::SessionJournal::open_at(&path, crate::effective_uid()).unwrap();
        request.operation = format!("consume:{}", grant.id);
        let preparation = fleet
            .state
            .lock()
            .unwrap()
            .prepare_browser_login(&peer, &request, &resource, &mut journal)
            .unwrap();
        assert!(matches!(preparation, crate::BrowserPreparation::Login(_)));
        assert_eq!(journal.pending().len(), 1);
        assert!(matches!(
            fleet
                .state
                .lock()
                .unwrap()
                .prepare_browser_login(&peer, &request, &resource, &mut journal)
                .unwrap(),
            crate::BrowserPreparation::Existing(_)
        ));
        let events = canonicalize_value(&Value::Array(fleet.pulled_events())).unwrap();
        for private in [
            b"P05-SIGNED-SOURCE-CANARY".as_slice(),
            b"127.0.0.1",
            b"primary-password",
        ] {
            assert!(!events.windows(private.len()).any(|bytes| bytes == private));
        }
    }

    #[test]
    fn requesting_workload_learns_a_signed_operation_closure() {
        let fleet = Fleet::new(59);
        let requested = operation_request(&fleet).unwrap();
        let event_key = std::str::from_utf8(&requested)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned();
        let peer = Fleet::peer();
        assert_eq!(
            status(&fleet, &peer, &event_key).unwrap(),
            b"OK operation_status pending\n"
        );

        // Only the requesting workload invocation may ask.
        let other_invocation = PeerIdentity::fixture(
            1000,
            current_gid(),
            "worker.service",
            "invocation-b",
            "worker",
        );
        assert_eq!(
            denial(status(&fleet, &other_invocation, &event_key)),
            "operation_status_denied"
        );

        // A closure bound to another node is rejected and changes nothing.
        assert_eq!(
            fleet.relay(&closure(&fleet, "nd_node-b", &event_key, "rejected", 1)),
            b"ERR invalid_controller_document\n"
        );
        assert_eq!(
            status(&fleet, &peer, &event_key).unwrap(),
            b"OK operation_status pending\n"
        );

        assert_eq!(
            fleet.relay(&closure(&fleet, "nd_node-a", &event_key, "rejected", 1)),
            b"OK document_applied operation_closed\n"
        );
        assert_eq!(
            status(&fleet, &peer, &event_key).unwrap(),
            b"OK operation_status closed rejected\n"
        );
        assert_eq!(
            denial(status(&fleet, &other_invocation, &event_key)),
            "operation_status_denied"
        );

        // Keys the broker did not issue, or no longer remembers, are unknown.
        assert_eq!(
            status(&fleet, &peer, "event_not_issued_by_this_broker").unwrap(),
            b"OK operation_status unknown\n"
        );
        // Acknowledgement removes transport evidence, not its ownership.
        fleet
            .state
            .lock()
            .unwrap()
            .acknowledge_node_events("nd_node-a", std::slice::from_ref(&event_key))
            .unwrap();
        assert!(fleet.state.lock().unwrap().pending_node_events.is_empty());
        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted.configure_grant_storage(&fleet.identity).unwrap();
        restore_controller_documents(&mut restarted, &fleet.identity).unwrap();
        *fleet.state.lock().unwrap() = restarted;
        assert_eq!(
            status(&fleet, &peer, &event_key).unwrap(),
            b"OK operation_status closed rejected\n"
        );
        assert_eq!(
            denial(status(&fleet, &other_invocation, &event_key)),
            "operation_status_denied"
        );
    }

    #[test]
    fn operation_owner_survives_ack_and_restart_while_pending() {
        let fleet = Fleet::new(119);
        let reply = operation_request(&fleet).unwrap();
        let key = std::str::from_utf8(&reply)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .trim()
            .to_owned();
        fleet
            .state
            .lock()
            .unwrap()
            .acknowledge_node_events("nd_node-a", std::slice::from_ref(&key))
            .unwrap();
        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted.configure_grant_storage(&fleet.identity).unwrap();
        restore_controller_documents(&mut restarted, &fleet.identity).unwrap();
        *fleet.state.lock().unwrap() = restarted;
        assert_eq!(
            status(&fleet, &Fleet::peer(), &key).unwrap(),
            b"OK operation_status pending\n"
        );
        let other = PeerIdentity::fixture(
            1000,
            current_gid(),
            "worker.service",
            "invocation-b",
            "worker",
        );
        assert_eq!(
            denial(status(&fleet, &other, &key)),
            "operation_status_denied"
        );
        assert!(fleet.state.lock().unwrap().pending_node_events.is_empty());
    }

    #[test]
    fn operation_closure_write_failure_fences_until_durable_retry() {
        let fleet = Fleet::new(120);
        let reply = operation_request(&fleet).unwrap();
        let key = std::str::from_utf8(&reply)
            .unwrap()
            .strip_prefix("OK operation_request ")
            .unwrap()
            .trim()
            .to_owned();
        let path = fleet.identity.pending_node_events_path();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let document = closure(&fleet, "nd_node-a", &key, "cancelled", 1);
        assert!(fleet.relay(&document).starts_with(b"ERR "));
        assert!(fleet.state.lock().unwrap().persistence_fenced());
        assert_eq!(
            status(&fleet, &Fleet::peer(), &key).unwrap(),
            b"OK operation_status closed cancelled\n"
        );
        assert!(operation_request(&fleet).is_err());
        std::fs::remove_dir(&path).unwrap();
        assert!(fleet.relay(&document).starts_with(b"OK "));
        assert!(!fleet.state.lock().unwrap().persistence_fenced());
        let mut restarted = BrokerState::new(DeliveryPolicy::default());
        restarted.configure_grant_storage(&fleet.identity).unwrap();
        restore_controller_documents(&mut restarted, &fleet.identity).unwrap();
        *fleet.state.lock().unwrap() = restarted;
        assert_eq!(
            status(&fleet, &Fleet::peer(), &key).unwrap(),
            b"OK operation_status closed cancelled\n"
        );
    }

    #[test]
    fn full_operation_owner_storage_denies_admission_without_eviction() {
        let fleet = Fleet::new(121);
        {
            let mut state = fleet.state.lock().unwrap();
            for index in 0..crate::MAX_OPERATION_RECORDS {
                state.remember_operation_request(
                    &format!("capacity_owner_{index:08}"),
                    "wl_worker-a",
                    "invocation-a",
                );
            }
        }
        assert_eq!(
            denial(operation_request(&fleet)),
            "operation_record_capacity"
        );
        let state = fleet.state.lock().unwrap();
        assert!(
            state
                .operation_requests
                .contains_key("capacity_owner_00000000")
        );
        assert_eq!(state.operation_requests.len(), crate::MAX_OPERATION_RECORDS);
        assert!(state.pending_node_events.is_empty());
    }

    #[test]
    fn operation_request_and_closure_records_are_bounded() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        for index in 0..crate::MAX_OPERATION_RECORDS + 3 {
            let key = format!("event_bounded_{index:08}");
            state.remember_operation_request(&key, "wl_worker-a", "invocation-a");
            state.record_operation_closure(&key, "expired");
        }
        assert_eq!(state.operation_requests.len(), crate::MAX_OPERATION_RECORDS);
        assert_eq!(state.operation_closures.len(), crate::MAX_OPERATION_RECORDS);
        assert!(
            !state
                .operation_requests
                .contains_key("event_bounded_00000000")
        );
        assert!(
            !state
                .operation_closures
                .contains_key("event_bounded_00000002")
        );
        assert!(state.operation_closures.contains_key(&format!(
            "event_bounded_{:08}",
            crate::MAX_OPERATION_RECORDS + 2
        )));
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

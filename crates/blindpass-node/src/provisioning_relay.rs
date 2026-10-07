// SPDX-License-Identifier: AGPL-3.0-only

//! Automatic Source provisioning and fulfillment relay steps. The node handles only signed
//! public documents and HPKE ciphertext: it never holds a recipient private
//! key, a Source plaintext or a signing key, and it never alters bytes the
//! broker signed. Every log line is a fixed `&'static str`, so no document,
//! ciphertext, key or identifier can reach a log by construction.

use crate::ChannelError;
use crate::outbox::{NodeEvent, Outbox};
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::fleet::{DocumentKind, MAX_PROVISIONING_DELIVERY_DOCUMENT_BYTES};
use blindpass_core::secret::wipe;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Grant ids remembered per process; clearing is safe because the broker's
/// exact-retry and the outbox's same-key/same-bytes insert are idempotent.
const MAX_REMEMBERED_GRANTS: usize = 4_096;
const MAX_OFFER_EVENT_BYTES: usize = 64 * 1024;

pub(crate) const LOG_OFFER_DENIED: &str =
    "node relay: the broker declined to publish a recipient offer for a browser grant";
pub(crate) const LOG_OFFER_MALFORMED: &str =
    "node relay: the broker returned a malformed recipient offer event";
pub(crate) const LOG_OFFER_CONFLICT: &str =
    "node relay: a different recipient offer event is already queued for that grant";
pub(crate) const LOG_DELIVERY_DENIED: &str =
    "node relay: the broker declined a signed provisioning delivery; acknowledging it";
pub(crate) const LOG_DELIVERY_UNUSABLE: &str =
    "node relay: a provisioning delivery could not be forwarded safely; acknowledging it";
pub(crate) const LOG_BROKER_UNAVAILABLE: &str =
    "node relay could not reach the local broker control socket";
pub(crate) const LOG_FULFILLMENT_DENIED: &str =
    "node relay: the broker declined to publish an event for a fulfillment authorization";
pub(crate) const LOG_FULFILLMENT_MALFORMED: &str =
    "node relay: the broker returned a malformed fulfillment event";
pub(crate) const LOG_FULFILLMENT_CONFLICT: &str =
    "node relay: a different fulfillment event is already queued for that fulfillment";

/// Result of one inbox document step that may be acknowledged to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepOutcome {
    /// Relayed through RELAY with no extra publication.
    Relayed,
    /// A browser grant was relayed and its broker-signed offer event queued.
    OfferQueued,
    /// A browser grant was relayed; its offer was already requested by this process.
    OfferAlreadyRequested,
    /// A browser grant was relayed; the broker declined or returned an unusable offer.
    OfferSkipped,
    DeliveryProvisioned,
    DeliveryAlreadyProvisioned,
    /// Un-appliable delivery acknowledged so it cannot wedge the inbox.
    DeliveryDropped,
    /// A fulfillment authorization was relayed and the broker's signed offer or
    /// submission event queued.
    FulfillmentEventQueued,
    /// A fulfillment authorization was relayed; its event was already requested
    /// by this process.
    FulfillmentEventAlreadyRequested,
    /// A fulfillment authorization was relayed; the broker declined or returned
    /// an unusable event, which is acknowledged rather than retried.
    FulfillmentEventSkipped,
}

/// A broker answer distinguishing an explicit refusal from an unreachable broker.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BrokerReply {
    Reply(Vec<u8>),
    Refused,
    Unavailable,
}

/// One bounded broker control exchange. Unlike `broker_request`, an explicit
/// `ERR ...` answer (a decision) is distinct from an unreachable or confused
/// broker (a transient fault).
pub(crate) fn broker_exchange(socket: &Path, request: &[u8]) -> BrokerReply {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return BrokerReply::Unavailable;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(3))))
        .and_then(|()| stream.write_all(request))
        .is_err()
    {
        return BrokerReply::Unavailable;
    }
    let mut response = Vec::new();
    if (&mut stream)
        .take((crate::MAX_CONTROL_RESPONSE + 1) as u64)
        .read_to_end(&mut response)
        .is_err()
        || response.len() > crate::MAX_CONTROL_RESPONSE
        || !response.ends_with(b"\n")
    {
        wipe(&mut response);
        return BrokerReply::Unavailable;
    }
    if response.starts_with(b"ERR ") {
        return BrokerReply::Refused;
    }
    BrokerReply::Reply(response)
}

fn remember(published: &mut HashSet<String>, grant_id: &str) {
    if published.len() >= MAX_REMEMBERED_GRANTS {
        published.clear();
    }
    published.insert(grant_id.to_owned());
}

/// The grant id of a browser-session grant document; every other document
/// (including file/socket grants) yields none.
fn browser_grant_id(envelope: &Value) -> Option<&str> {
    if envelope.get("kind")?.as_str()? != DocumentKind::Grant.as_str() {
        return None;
    }
    let body = envelope.get("body")?;
    if body.get("mode")?.as_str()? != "browser_session" {
        return None;
    }
    let id = body.get("id")?.as_str()?;
    crate::valid_identifier(id).then_some(id)
}

/// The deterministic event key the broker uses for a grant's offer event.
fn offer_event_key(grant_id: &str) -> Option<String> {
    let digest = sha256(grant_id.as_bytes()).ok()?;
    Some(format!(
        "ro_{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

/// Strictly parse `OFFER_EVENT <len>\n<canonical json>\n` for exactly one
/// `recipient_offer` event of `grant_id`. The returned event is the broker's
/// value unchanged, so its canonical bytes equal the broker's payload.
fn parse_offer_event(response: &[u8], grant_id: &str) -> Option<NodeEvent> {
    let newline = response.iter().position(|byte| *byte == b'\n')?;
    let digits = std::str::from_utf8(&response[..newline])
        .ok()?
        .strip_prefix("OFFER_EVENT ")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: usize = digits.parse().ok()?;
    let payload = response[newline + 1..].strip_suffix(b"\n")?;
    if length == 0 || length != payload.len() || length > MAX_OFFER_EVENT_BYTES {
        return None;
    }
    let value = parse_json(std::str::from_utf8(payload).ok()?).ok()?;
    if canonicalize_value(&value).ok()? != payload {
        return None;
    }
    let event = NodeEvent::from_value(&value).ok()?;
    if event.kind != "recipient_offer" || event.idempotency_key != offer_event_key(grant_id)? {
        return None;
    }
    let offered = event.body.get("body")?.get("grant")?.get("id")?.as_str()?;
    (offered == grant_id).then_some(event)
}

fn request_offer(
    socket: &Path,
    outbox: &mut Outbox,
    published: &mut HashSet<String>,
    log: &mut dyn FnMut(&'static str),
    grant_id: &str,
) -> Result<StepOutcome, ChannelError> {
    if published.contains(grant_id) {
        return Ok(StepOutcome::OfferAlreadyRequested);
    }
    let request = format!("BROWSER_OFFER_EVENT {grant_id}\n").into_bytes();
    match broker_exchange(socket, &request) {
        BrokerReply::Unavailable => {
            log(LOG_BROKER_UNAVAILABLE);
            Err(ChannelError::Retryable)
        }
        BrokerReply::Refused => {
            remember(published, grant_id);
            log(LOG_OFFER_DENIED);
            Ok(StepOutcome::OfferSkipped)
        }
        BrokerReply::Reply(mut reply) => {
            let event = parse_offer_event(&reply, grant_id);
            wipe(&mut reply);
            let Some(event) = event else {
                remember(published, grant_id);
                log(LOG_OFFER_MALFORMED);
                return Ok(StepOutcome::OfferSkipped);
            };
            match outbox.insert_batch(vec![event]) {
                Ok(()) => {
                    remember(published, grant_id);
                    Ok(StepOutcome::OfferQueued)
                }
                Err(crate::outbox::KEY_REUSED) => {
                    remember(published, grant_id);
                    log(LOG_OFFER_CONFLICT);
                    Ok(StepOutcome::OfferSkipped)
                }
                Err(_) => Err(ChannelError::Retryable),
            }
        }
    }
}

/// The fulfillment id and the event the broker publishes for it, for an
/// authorization document only: the recipient side yields the one-use offer, the
/// issuer side the sealed submission. Anything else yields none.
fn fulfillment_authorization(envelope: &Value) -> Option<(&str, &'static str, &'static str)> {
    if envelope.get("kind")?.as_str()? != DocumentKind::FulfillmentAuthorization.as_str() {
        return None;
    }
    let body = envelope.get("body")?;
    let id = body.get("terms")?.get("fulfillment_id")?.as_str()?;
    if !crate::valid_identifier(id) {
        return None;
    }
    match body.get("side")?.as_str()? {
        "recipient" => Some((id, "fulfillment_offer", "fo_")),
        "issuer" => Some((id, "fulfillment_submit", "fs_")),
        _ => None,
    }
}

/// Strictly parse `FULFILL_EVENT <len>\n<canonical json>\n` for exactly one event
/// of `kind` for `fulfillment_id`. The returned event is the broker's value
/// unchanged, so its canonical bytes equal the broker's payload.
fn parse_fulfillment_event(
    response: &[u8],
    fulfillment_id: &str,
    kind: &str,
    prefix: &str,
) -> Option<NodeEvent> {
    let newline = response.iter().position(|byte| *byte == b'\n')?;
    let digits = std::str::from_utf8(&response[..newline])
        .ok()?
        .strip_prefix("FULFILL_EVENT ")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: usize = digits.parse().ok()?;
    let payload = response[newline + 1..].strip_suffix(b"\n")?;
    if length == 0 || length != payload.len() || length > MAX_OFFER_EVENT_BYTES {
        return None;
    }
    let value = parse_json(std::str::from_utf8(payload).ok()?).ok()?;
    if canonicalize_value(&value).ok()? != payload {
        return None;
    }
    let event = NodeEvent::from_value(&value).ok()?;
    let digest = sha256(fulfillment_id.as_bytes()).ok()?;
    let key = format!(
        "{prefix}{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    if event.kind != kind || event.idempotency_key != key {
        return None;
    }
    // The event body is the broker-signed envelope; it must be of the same kind
    // and name the same fulfillment.
    let signed = &event.body;
    (signed.get("kind")?.as_str()? == kind
        && signed.get("body")?.get("fulfillment_id")?.as_str()? == fulfillment_id)
        .then_some(event)
}

fn request_fulfillment_event(
    socket: &Path,
    outbox: &mut Outbox,
    published: &mut HashSet<String>,
    log: &mut dyn FnMut(&'static str),
    (fulfillment_id, kind, prefix): (&str, &'static str, &'static str),
) -> Result<StepOutcome, ChannelError> {
    let remembered = format!("{kind}:{fulfillment_id}");
    if published.contains(&remembered) {
        return Ok(StepOutcome::FulfillmentEventAlreadyRequested);
    }
    let request = format!("FULFILL_EVENT {fulfillment_id}\n").into_bytes();
    match broker_exchange(socket, &request) {
        BrokerReply::Unavailable => {
            log(LOG_BROKER_UNAVAILABLE);
            Err(ChannelError::Retryable)
        }
        BrokerReply::Refused => {
            remember(published, &remembered);
            log(LOG_FULFILLMENT_DENIED);
            Ok(StepOutcome::FulfillmentEventSkipped)
        }
        BrokerReply::Reply(mut reply) => {
            let event = parse_fulfillment_event(&reply, fulfillment_id, kind, prefix);
            wipe(&mut reply);
            let Some(event) = event else {
                remember(published, &remembered);
                log(LOG_FULFILLMENT_MALFORMED);
                return Ok(StepOutcome::FulfillmentEventSkipped);
            };
            match outbox.insert_batch(vec![event]) {
                Ok(()) => {
                    remember(published, &remembered);
                    Ok(StepOutcome::FulfillmentEventQueued)
                }
                Err(crate::outbox::KEY_REUSED) => {
                    remember(published, &remembered);
                    log(LOG_FULFILLMENT_CONFLICT);
                    Ok(StepOutcome::FulfillmentEventSkipped)
                }
                Err(_) => Err(ChannelError::Retryable),
            }
        }
    }
}

/// A controller-signed delivery enters the broker only through
/// PROVISION_SOURCE. A document the broker cannot apply is acknowledged, not
/// retried, so it cannot block revocations queued behind it.
fn relay_delivery(
    socket: &Path,
    log: &mut dyn FnMut(&'static str),
    envelope: &Value,
) -> Result<StepOutcome, ChannelError> {
    let Ok(mut document) = canonicalize_value(envelope) else {
        log(LOG_DELIVERY_UNUSABLE);
        return Ok(StepOutcome::DeliveryDropped);
    };
    if document.len() < 2 || document.len() > MAX_PROVISIONING_DELIVERY_DOCUMENT_BYTES {
        wipe(&mut document);
        log(LOG_DELIVERY_UNUSABLE);
        return Ok(StepOutcome::DeliveryDropped);
    }
    let mut request = format!("PROVISION_SOURCE {}\n", document.len()).into_bytes();
    request.extend_from_slice(&document);
    wipe(&mut document);
    let reply = broker_exchange(socket, &request);
    wipe(&mut request);
    match reply {
        BrokerReply::Reply(reply) if reply == b"OK browser_source_provisioned\n" => {
            Ok(StepOutcome::DeliveryProvisioned)
        }
        BrokerReply::Reply(reply) if reply == b"OK browser_source_already_provisioned\n" => {
            Ok(StepOutcome::DeliveryAlreadyProvisioned)
        }
        BrokerReply::Reply(_) | BrokerReply::Refused => {
            log(LOG_DELIVERY_DENIED);
            Ok(StepOutcome::DeliveryDropped)
        }
        BrokerReply::Unavailable => {
            log(LOG_BROKER_UNAVAILABLE);
            Err(ChannelError::Retryable)
        }
    }
}

/// Apply one controller inbox document. Only `Ok` may be acknowledged; an
/// `Err` leaves the document unacknowledged so it is replayed.
pub(crate) fn process_inbox_document(
    socket: &Path,
    outbox: &mut Outbox,
    published: &mut HashSet<String>,
    log: &mut dyn FnMut(&'static str),
    envelope: &Value,
) -> Result<StepOutcome, ChannelError> {
    let kind = envelope
        .get("kind")
        .and_then(Value::as_str)
        .and_then(DocumentKind::parse);
    if kind == Some(DocumentKind::ProvisioningDelivery) {
        return relay_delivery(socket, log, envelope);
    }
    let response =
        crate::relay_document_response(socket, envelope).map_err(|_| ChannelError::Retryable)?;
    // Only an authorization the broker applied has an offer or submission to
    // publish; a discarded one has nothing left to do.
    if let Some(target) = fulfillment_authorization(envelope)
        && response == b"OK document_applied fulfillment_authorization\n"
    {
        return request_fulfillment_event(socket, outbox, published, log, target);
    }
    match browser_grant_id(envelope) {
        // Only a live accepted grant can receive an offer; a discarded or
        // settled one has nothing left to provision.
        Some(grant_id) if response == b"OK document_applied grant\n" => {
            request_offer(socket, outbox, published, log, grant_id)
        }
        _ => Ok(StepOutcome::Relayed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindpass_core::signing::base64_url_encode;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const CANARY: &str = "P05-NODE-SOURCE-CANARY";
    const GRANT_ID: &str = "gr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    type Handler = Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send>;

    /// A real Unix-socket broker stand-in that records every command and payload.
    struct FakeBroker {
        directory: PathBuf,
        socket: PathBuf,
        requests: Requests,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bp-relay-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    impl FakeBroker {
        fn start(directory: &Path, handler: Handler) -> Self {
            let socket = directory.join("control.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let requests: Requests = Arc::default();
            let stop = Arc::new(AtomicBool::new(false));
            let (log, flag) = (requests.clone(), stop.clone());
            let thread = std::thread::spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut line = Vec::new();
                    let mut byte = [0_u8; 1];
                    while stream.read_exact(&mut byte).is_ok() {
                        line.push(byte[0]);
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let command = String::from_utf8_lossy(&line).trim_end().to_owned();
                    let mut payload = Vec::new();
                    let length = ["RELAY ", "PROVISION_SOURCE "]
                        .iter()
                        .find_map(|prefix| command.strip_prefix(prefix))
                        .and_then(|value| value.parse::<usize>().ok());
                    if let Some(length) = length {
                        payload = vec![0_u8; length];
                        if stream.read_exact(&mut payload).is_err() {
                            continue;
                        }
                    }
                    let response = handler(&command, &payload);
                    log.lock().unwrap().push((command, payload));
                    let _ = stream.write_all(&response);
                }
            });
            Self {
                directory: directory.to_owned(),
                socket,
                requests,
                stop,
                thread: Some(thread),
            }
        }
        fn commands(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|(command, _)| command.split(' ').next().unwrap_or_default().to_owned())
                .collect()
        }
        fn payloads(&self) -> Vec<Vec<u8>> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|(_, payload)| payload.clone())
                .collect()
        }
        /// Close the listener but leave the socket file: connections are refused.
        fn shut_down(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    impl Drop for FakeBroker {
        fn drop(&mut self) {
            self.shut_down();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn grant_envelope(id: &str, mode: &str) -> Value {
        parse_json(&format!(
            r#"{{"v":1,"kind":"grant","kid":"ed25519-test","epoch":1,"body":{{"id":"{id}","mode":"{mode}"}},"sig":"{}"}}"#,
            base64_url_encode(&[3; 64])
        ))
        .unwrap()
    }

    fn other_envelope(kind: &str) -> Value {
        parse_json(&format!(
            r#"{{"v":1,"kind":"{kind}","kid":"ed25519-test","epoch":1,"body":{{"id":"x"}},"sig":"{}"}}"#,
            base64_url_encode(&[3; 64])
        ))
        .unwrap()
    }

    fn key_for(grant_id: &str) -> String {
        let digest = sha256(grant_id.as_bytes()).unwrap();
        format!(
            "ro_{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    /// The exact bytes a real broker returns: `OFFER_EVENT <len>\n<json>\n`.
    fn offer_event_reply(grant_id: &str, variant: &str) -> (Vec<u8>, Vec<u8>) {
        let event = parse_json(&format!(
            r#"{{"body":{{"v":1,"kind":"recipient_offer","kid":"nd_test-1","epoch":1,"body":{{"grant":{{"id":"{grant_id}"}},"offer_id":"pv_{variant}"}},"sig":"{}"}},"broker_signature":"{}","idempotency_key":"{}","kind":"recipient_offer"}}"#,
            base64_url_encode(&[5; 64]),
            base64_url_encode(&[6; 64]),
            key_for(grant_id)
        ))
        .unwrap();
        let json = canonicalize_value(&event).unwrap();
        let mut reply = format!("OFFER_EVENT {}\n", json.len()).into_bytes();
        reply.extend_from_slice(&json);
        reply.push(b'\n');
        (reply, json)
    }

    fn offering_broker(directory: &Path) -> FakeBroker {
        FakeBroker::start(
            directory,
            Box::new(|command, _| {
                if let Some(id) = command.strip_prefix("BROWSER_OFFER_EVENT ") {
                    offer_event_reply(id, "fixed").0
                } else if command.starts_with("RELAY ") {
                    b"OK document_applied grant\n".to_vec()
                } else if command.starts_with("PROVISION_SOURCE ") {
                    b"OK browser_source_provisioned\n".to_vec()
                } else {
                    b"ERR invalid_control_command\n".to_vec()
                }
            }),
        )
    }

    struct Rig {
        directory: PathBuf,
        outbox: Outbox,
        published: HashSet<String>,
        logs: Vec<&'static str>,
    }

    impl Rig {
        fn new() -> Self {
            let directory = directory();
            let outbox = Outbox::open(&directory.join("state")).unwrap();
            Self {
                directory,
                outbox,
                published: HashSet::new(),
                logs: Vec::new(),
            }
        }
        fn step(&mut self, socket: &Path, envelope: &Value) -> Result<StepOutcome, ChannelError> {
            let logs = &mut self.logs;
            process_inbox_document(
                socket,
                &mut self.outbox,
                &mut self.published,
                &mut |line| logs.push(line),
                envelope,
            )
        }
        fn restart(&mut self) {
            self.outbox = Outbox::open(&self.directory.join("state")).unwrap();
            self.published.clear();
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn offer_is_requested_once_per_grant_and_is_idempotent_across_restarts() {
        let mut rig = Rig::new();
        let broker = offering_broker(&rig.directory.clone());
        let grant = grant_envelope(GRANT_ID, "browser_session");
        assert_eq!(
            rig.step(&broker.socket, &grant),
            Ok(StepOutcome::OfferQueued)
        );
        assert_eq!(
            rig.step(&broker.socket, &grant),
            Ok(StepOutcome::OfferAlreadyRequested)
        );
        let asks = |broker: &FakeBroker| {
            broker
                .commands()
                .iter()
                .filter(|command| *command == "BROWSER_OFFER_EVENT")
                .count()
        };
        assert_eq!(asks(&broker), 1, "one offer request per grant per process");
        assert_eq!(rig.outbox.first_batch(10).len(), 1);
        // A restart forgets the in-memory set; the broker's exact retry and the
        // outbox's same-key/same-bytes insert keep exactly one event.
        rig.restart();
        assert_eq!(rig.outbox.first_batch(10).len(), 1);
        assert_eq!(
            rig.step(&broker.socket, &grant),
            Ok(StepOutcome::OfferQueued)
        );
        assert_eq!(asks(&broker), 2);
        assert_eq!(rig.outbox.first_batch(10).len(), 1);
        // A second grant is a second, independent offer.
        let second = "gr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(
            rig.step(&broker.socket, &grant_envelope(second, "browser_session")),
            Ok(StepOutcome::OfferQueued)
        );
        assert_eq!(rig.outbox.first_batch(10).len(), 2);
        assert!(rig.logs.is_empty());
    }

    #[test]
    fn queued_offer_event_is_exactly_the_bytes_the_broker_returned() {
        let mut rig = Rig::new();
        let broker = offering_broker(&rig.directory.clone());
        rig.step(&broker.socket, &grant_envelope(GRANT_ID, "browser_session"))
            .unwrap();
        let (_, expected) = offer_event_reply(GRANT_ID, "fixed");
        let queued = rig.outbox.first_batch(10);
        assert_eq!(queued.len(), 1);
        assert_eq!(
            canonicalize_value(&queued[0].to_value()).unwrap(),
            expected,
            "the node must publish the broker's event byte for byte"
        );
        assert_eq!(queued[0].kind, "recipient_offer");
        assert_eq!(queued[0].idempotency_key, key_for(GRANT_ID));
        // The grant itself went through RELAY first, byte for byte canonical.
        assert_eq!(broker.commands()[0], "RELAY");
        assert_eq!(
            broker.payloads()[0],
            canonicalize_value(&grant_envelope(GRANT_ID, "browser_session")).unwrap()
        );
    }

    #[test]
    fn other_grants_and_kinds_trigger_no_offer_request() {
        let mut rig = Rig::new();
        let broker = offering_broker(&rig.directory.clone());
        for envelope in [
            grant_envelope(GRANT_ID, "file"),
            grant_envelope(GRANT_ID, "socket"),
            other_envelope("registration"),
            other_envelope("policy_snapshot"),
            other_envelope("application_ack"),
            other_envelope("operation_closed"),
            other_envelope("revocation"),
        ] {
            assert_eq!(
                rig.step(&broker.socket, &envelope),
                Ok(StepOutcome::Relayed)
            );
        }
        assert!(
            broker.commands().iter().all(|command| command == "RELAY"),
            "{:?}",
            broker.commands()
        );
        assert!(rig.outbox.first_batch(10).is_empty());
        // A browser grant the broker discarded is not offered either.
        let settled = FakeBroker::start(
            &directory(),
            Box::new(|_, _| b"OK document_discarded grant_settled\n".to_vec()),
        );
        assert_eq!(
            rig.step(
                &settled.socket,
                &grant_envelope(GRANT_ID, "browser_session")
            ),
            Ok(StepOutcome::Relayed)
        );
        assert_eq!(settled.commands(), ["RELAY"]);
        assert!(rig.outbox.first_batch(10).is_empty());
    }

    fn delivery_envelope(padding: usize) -> Value {
        parse_json(&format!(
            r#"{{"v":1,"kind":"provisioning_delivery","kid":"ed25519-test","epoch":1,"body":{{"pad":"{}"}},"sig":"{}"}}"#,
            "A".repeat(padding),
            base64_url_encode(&[3; 64])
        ))
        .unwrap()
    }

    /// Padding that makes the canonical document exactly `target` bytes.
    fn padding_for(target: usize, build: fn(usize) -> Value) -> usize {
        target - canonicalize_value(&build(0)).unwrap().len()
    }

    #[test]
    fn delivery_relay_uses_provision_source_never_relay() {
        let mut rig = Rig::new();
        let broker = offering_broker(&rig.directory.clone());
        let delivery = delivery_envelope(1_000);
        assert_eq!(
            rig.step(&broker.socket, &delivery),
            Ok(StepOutcome::DeliveryProvisioned)
        );
        assert_eq!(broker.commands(), ["PROVISION_SOURCE"]);
        assert_eq!(broker.payloads()[0], canonicalize_value(&delivery).unwrap());
        let already = FakeBroker::start(
            &directory(),
            Box::new(|_, _| b"OK browser_source_already_provisioned\n".to_vec()),
        );
        assert_eq!(
            rig.step(&already.socket, &delivery),
            Ok(StepOutcome::DeliveryAlreadyProvisioned)
        );
        assert!(rig.outbox.first_batch(10).is_empty());
        assert!(rig.logs.is_empty());
    }

    #[test]
    fn delivery_cap_is_128_kib_and_one_byte_more_is_refused_without_the_broker() {
        let mut rig = Rig::new();
        let broker = offering_broker(&rig.directory.clone());
        let at_cap = delivery_envelope(padding_for(131_072, delivery_envelope));
        assert_eq!(canonicalize_value(&at_cap).unwrap().len(), 131_072);
        assert_eq!(
            rig.step(&broker.socket, &at_cap),
            Ok(StepOutcome::DeliveryProvisioned)
        );
        assert_eq!(broker.payloads()[0].len(), 131_072);
        let over = delivery_envelope(padding_for(131_073, delivery_envelope));
        assert_eq!(canonicalize_value(&over).unwrap().len(), 131_073);
        assert_eq!(
            rig.step(&broker.socket, &over),
            Ok(StepOutcome::DeliveryDropped)
        );
        assert_eq!(
            broker.commands(),
            ["PROVISION_SOURCE"],
            "oversize never sent"
        );
        assert_eq!(rig.logs, [LOG_DELIVERY_UNUSABLE]);
    }

    fn generic_envelope(padding: usize) -> Value {
        parse_json(&format!(
            r#"{{"v":1,"kind":"registration","kid":"ed25519-test","epoch":1,"body":{{"pad":"{}"}},"sig":"{}"}}"#,
            "A".repeat(padding),
            base64_url_encode(&[3; 64])
        ))
        .unwrap()
    }

    #[test]
    fn every_other_kind_keeps_the_64_kib_cap() {
        let mut rig = Rig::new();
        let broker = offering_broker(&rig.directory.clone());
        let at_cap = generic_envelope(padding_for(65_536, generic_envelope));
        assert_eq!(canonicalize_value(&at_cap).unwrap().len(), 65_536);
        assert_eq!(rig.step(&broker.socket, &at_cap), Ok(StepOutcome::Relayed));
        assert_eq!(broker.payloads()[0].len(), 65_536);
        let over = generic_envelope(padding_for(65_537, generic_envelope));
        assert_eq!(canonicalize_value(&over).unwrap().len(), 65_537);
        assert_eq!(
            rig.step(&broker.socket, &over),
            Err(ChannelError::Retryable)
        );
        assert_eq!(broker.commands(), ["RELAY"], "oversize never sent");
        // A delivery-kind document can never be pushed through RELAY.
        assert!(crate::relay_document(&broker.socket, &delivery_envelope(10)).is_err());
        assert_eq!(broker.commands(), ["RELAY"]);
    }

    #[test]
    fn broker_denial_of_a_delivery_is_acknowledged_so_the_inbox_cannot_wedge() {
        let mut rig = Rig::new();
        let denying = FakeBroker::start(
            &rig.directory.clone(),
            Box::new(|_, _| b"ERR browser_provisioning_denied\n".to_vec()),
        );
        assert_eq!(
            rig.step(&denying.socket, &delivery_envelope(500)),
            Ok(StepOutcome::DeliveryDropped)
        );
        assert_eq!(rig.logs, [LOG_DELIVERY_DENIED]);
        // An unexpected non-ERR reply is also dropped rather than retried forever.
        let odd = FakeBroker::start(
            &directory(),
            Box::new(|_, _| b"OK something_else\n".to_vec()),
        );
        assert_eq!(
            rig.step(&odd.socket, &delivery_envelope(500)),
            Ok(StepOutcome::DeliveryDropped)
        );
    }

    #[test]
    fn offer_denial_marks_the_grant_attempted_and_never_wedges() {
        let mut rig = Rig::new();
        let broker = FakeBroker::start(
            &rig.directory.clone(),
            Box::new(|command, _| {
                if command.starts_with("BROWSER_OFFER_EVENT ") {
                    b"ERR browser_provisioning_denied\n".to_vec()
                } else {
                    b"OK document_applied grant\n".to_vec()
                }
            }),
        );
        let grant = grant_envelope(GRANT_ID, "browser_session");
        assert_eq!(
            rig.step(&broker.socket, &grant),
            Ok(StepOutcome::OfferSkipped)
        );
        assert_eq!(rig.logs, [LOG_OFFER_DENIED]);
        assert_eq!(
            rig.step(&broker.socket, &grant),
            Ok(StepOutcome::OfferAlreadyRequested)
        );
        assert!(rig.outbox.first_batch(10).is_empty());
    }

    #[test]
    fn transient_broker_unavailability_is_retried_not_dropped() {
        let mut rig = Rig::new();
        let grant = grant_envelope(GRANT_ID, "browser_session");
        let delivery = delivery_envelope(300);
        // Socket file missing entirely.
        let missing = rig.directory.join("missing.sock");
        assert_eq!(rig.step(&missing, &grant), Err(ChannelError::Retryable));
        assert_eq!(rig.step(&missing, &delivery), Err(ChannelError::Retryable));
        // Listener closed: the stale socket file refuses connections.
        let mut broker = offering_broker(&rig.directory.clone());
        broker.shut_down();
        assert_eq!(
            rig.step(&broker.socket.clone(), &grant),
            Err(ChannelError::Retryable)
        );
        assert_eq!(
            rig.step(&broker.socket.clone(), &delivery),
            Err(ChannelError::Retryable)
        );
        assert!(rig.published.is_empty(), "nothing is marked as handled");
        assert!(rig.outbox.first_batch(10).is_empty());
        // The grant relays but the offer request cannot reach the broker: the
        // whole step stays retryable and the grant is not marked published.
        let flaky_dir = directory();
        let calls = Arc::new(AtomicU64::new(0));
        let counter = calls.clone();
        let flaky = FakeBroker::start(
            &flaky_dir,
            Box::new(move |command, _| {
                if command.starts_with("BROWSER_OFFER_EVENT ") {
                    // Close without a reply on the first attempt.
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        Vec::new()
                    } else {
                        offer_event_reply(GRANT_ID, "fixed").0
                    }
                } else {
                    b"OK document_applied grant\n".to_vec()
                }
            }),
        );
        assert_eq!(
            rig.step(&flaky.socket, &grant),
            Err(ChannelError::Retryable)
        );
        assert!(!rig.published.contains(GRANT_ID));
        assert_eq!(
            rig.step(&flaky.socket, &grant),
            Ok(StepOutcome::OfferQueued)
        );
        assert_eq!(rig.outbox.first_batch(10).len(), 1);
    }

    #[test]
    fn malformed_or_conflicting_offer_events_never_enter_the_outbox() {
        let (good, json) = offer_event_reply(GRANT_ID, "fixed");
        let mut cases: Vec<Vec<u8>> = Vec::new();
        // Declared length does not match the payload (trailing bytes).
        cases.push(good.iter().cloned().chain(*b"extra\n").collect());
        let text = String::from_utf8(good.clone()).unwrap();
        cases.push(text.replace("OFFER_EVENT ", "OFFER_EVENT 0").into_bytes());
        // Event for a different grant (key and body.grant.id both must match).
        cases.push(offer_event_reply("gr_cccccccccccccccccccccccccccccccc", "x").0);
        // Not canonical JSON (extra whitespace).
        let spaced = String::from_utf8(json.clone())
            .unwrap()
            .replace(":{", ": {");
        cases.push(format!("OFFER_EVENT {}\n{spaced}\n", spaced.len()).into_bytes());
        // Wrong command echo and garbage.
        cases.push(b"OFFER 2\n{}\n".to_vec());
        cases.push(b"OK nothing\n".to_vec());
        for reply in cases {
            let mut rig = Rig::new();
            let broker = FakeBroker::start(
                &rig.directory.clone(),
                Box::new(move |command, _| {
                    if command.starts_with("BROWSER_OFFER_EVENT ") {
                        reply.clone()
                    } else {
                        b"OK document_applied grant\n".to_vec()
                    }
                }),
            );
            assert_eq!(
                rig.step(&broker.socket, &grant_envelope(GRANT_ID, "browser_session")),
                Ok(StepOutcome::OfferSkipped)
            );
            assert_eq!(rig.logs, [LOG_OFFER_MALFORMED]);
            assert!(rig.outbox.first_batch(10).is_empty());
        }
        // A different event under the same key is never replaced (key reuse).
        let mut rig = Rig::new();
        let first = offering_broker(&rig.directory.clone());
        rig.step(&first.socket, &grant_envelope(GRANT_ID, "browser_session"))
            .unwrap();
        let second = FakeBroker::start(
            &directory(),
            Box::new(|command, _| {
                if command.starts_with("BROWSER_OFFER_EVENT ") {
                    offer_event_reply(GRANT_ID, "successor").0
                } else {
                    b"OK document_applied grant\n".to_vec()
                }
            }),
        );
        rig.restart();
        assert_eq!(
            rig.step(&second.socket, &grant_envelope(GRANT_ID, "browser_session")),
            Ok(StepOutcome::OfferSkipped)
        );
        assert_eq!(rig.logs, [LOG_OFFER_CONFLICT]);
        let queued = rig.outbox.first_batch(10);
        assert_eq!(queued.len(), 1);
        assert_eq!(
            canonicalize_value(&queued[0].to_value()).unwrap(),
            offer_event_reply(GRANT_ID, "fixed").1,
            "the original event is untouched"
        );
    }

    #[test]
    fn log_lines_are_fixed_text_and_never_carry_source_ciphertext_or_keys() {
        let mut rig = Rig::new();
        let denying = FakeBroker::start(
            &rig.directory.clone(),
            Box::new(|_, _| b"ERR browser_provisioning_denied\n".to_vec()),
        );
        let secret_bearing = parse_json(&format!(
            r#"{{"v":1,"kind":"provisioning_delivery","kid":"ed25519-test","epoch":1,"body":{{"enc":"{CANARY}","ciphertext":"{CANARY}","recipient_public":"{CANARY}"}},"sig":"{}"}}"#,
            base64_url_encode(&[3; 64])
        ))
        .unwrap();
        rig.step(&denying.socket, &secret_bearing).unwrap();
        // The canary does reach the broker (it is the receiver)...
        assert!(
            denying.payloads()[0]
                .windows(CANARY.len())
                .any(|window| window == CANARY.as_bytes())
        );
        rig.step(&rig.directory.join("missing.sock"), &secret_bearing)
            .unwrap_err();
        let all = [
            LOG_OFFER_DENIED,
            LOG_OFFER_MALFORMED,
            LOG_OFFER_CONFLICT,
            LOG_DELIVERY_DENIED,
            LOG_DELIVERY_UNUSABLE,
            LOG_BROKER_UNAVAILABLE,
        ];
        assert!(!rig.logs.is_empty());
        for line in rig.logs.iter().chain(all.iter()) {
            assert!(all.contains(line), "only fixed lines may be emitted");
            for forbidden in [CANARY, "enc", "ciphertext", "recipient_public", GRANT_ID] {
                assert!(
                    !line.split_whitespace().any(|word| word == forbidden),
                    "{line}"
                );
            }
            assert!(!line.contains(CANARY));
        }
    }

    // ---- P10 cross-workload fulfillment ----

    const FULFILLMENT_ID: &str = "ful_0123456789abcdefABCDEF";
    /// Events the real broker's FULFILL_EVENT minted for `FULFILLMENT_ID` (dummy
    /// credential, throwaway keys) and the issuer-side authorization they answer.
    const REAL: &str = include_str!("../testdata/p10-real-broker-events.txt");

    fn real(label: &str) -> String {
        REAL.lines()
            .find_map(|line| line.strip_prefix(&format!("{label} ")))
            .unwrap()
            .to_owned()
    }

    fn fulfillment_key(prefix: &str, id: &str) -> String {
        let digest = sha256(id.as_bytes()).unwrap();
        format!(
            "{prefix}{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    fn framed(json: &[u8]) -> Vec<u8> {
        let mut reply = format!("FULFILL_EVENT {}\n", json.len()).into_bytes();
        reply.extend_from_slice(json);
        reply.push(b'\n');
        reply
    }

    fn authorization_envelope(id: &str, side: &str) -> Value {
        parse_json(&format!(
            r#"{{"v":1,"kind":"fulfillment_authorization","kid":"ed25519-test","epoch":1,"body":{{"side":"{side}","terms":{{"fulfillment_id":"{id}"}}}},"sig":"{}"}}"#,
            base64_url_encode(&[3; 64])
        ))
        .unwrap()
    }

    /// A synthetic broker event with the real shape, for the cases a real broker
    /// never produces.
    fn event_json(id: &str, kind: &str, key: &str, variant: &str) -> Vec<u8> {
        let event = parse_json(&format!(
            r#"{{"body":{{"v":1,"kind":"{kind}","kid":"nd_test-1","epoch":1,"body":{{"fulfillment_id":"{id}","offer_id":"fo_{variant}"}},"sig":"{}"}},"broker_signature":"{}","idempotency_key":"{key}","kind":"{kind}"}}"#,
            base64_url_encode(&[5; 64]),
            base64_url_encode(&[6; 64]),
        ))
        .unwrap();
        canonicalize_value(&event).unwrap()
    }

    fn offer_json(variant: &str) -> Vec<u8> {
        event_json(
            FULFILLMENT_ID,
            "fulfillment_offer",
            &fulfillment_key("fo_", FULFILLMENT_ID),
            variant,
        )
    }

    /// A broker that applies every document and answers FULFILL_EVENT with `reply`.
    fn fulfilling_broker(reply: Vec<u8>) -> FakeBroker {
        FakeBroker::start(
            &directory(),
            Box::new(move |command, _| {
                if command.starts_with("FULFILL_EVENT ") {
                    reply.clone()
                } else if command.starts_with("RELAY ") {
                    b"OK document_applied fulfillment_authorization\n".to_vec()
                } else {
                    b"ERR invalid_control_command\n".to_vec()
                }
            }),
        )
    }

    #[test]
    fn p10_n01_real_broker_events_are_queued_byte_for_byte_for_both_sides() {
        let mut rig = Rig::new();
        let (offer, submit) = (real("OFFER").into_bytes(), real("SUBMIT").into_bytes());
        let recipient_side = fulfilling_broker(framed(&offer));
        assert_eq!(
            rig.step(
                &recipient_side.socket,
                &authorization_envelope(FULFILLMENT_ID, "recipient")
            ),
            Ok(StepOutcome::FulfillmentEventQueued)
        );
        let issuer_side = fulfilling_broker(framed(&submit));
        let authorization = parse_json(&real("AUTH")).unwrap();
        assert_eq!(
            rig.step(&issuer_side.socket, &authorization),
            Ok(StepOutcome::FulfillmentEventQueued)
        );
        assert_eq!(
            rig.step(&issuer_side.socket, &authorization),
            Ok(StepOutcome::FulfillmentEventAlreadyRequested)
        );
        let queued = rig.outbox.first_batch(10);
        assert_eq!(queued.len(), 2);
        for (event, expected, kind, prefix) in [
            (&queued[0], &offer, "fulfillment_offer", "fo_"),
            (&queued[1], &submit, "fulfillment_submit", "fs_"),
        ] {
            assert_eq!(
                &canonicalize_value(&event.to_value()).unwrap(),
                expected,
                "the node must publish the broker's event byte for byte"
            );
            assert_eq!(event.kind, kind);
            assert_eq!(
                event.idempotency_key,
                fulfillment_key(prefix, FULFILLMENT_ID)
            );
        }
        // The document went through RELAY first, canonical, and only then the event
        // request, which carries nothing but the fulfillment id.
        let requests = issuer_side.requests.lock().unwrap();
        assert!(requests[0].0.starts_with("RELAY "));
        assert_eq!(requests[0].1, canonicalize_value(&authorization).unwrap());
        assert_eq!(requests[1].0, format!("FULFILL_EVENT {FULFILLMENT_ID}"));
        // The repeat is relayed again (the broker applies it idempotently) but the
        // event is not requested a second time.
        assert_eq!(requests.len(), 3);
        assert!(requests[2].0.starts_with("RELAY "));
        assert!(rig.logs.is_empty());
    }

    #[test]
    fn p10_n02_only_an_applied_authorization_asks_for_an_event() {
        let mut rig = Rig::new();
        // A document the broker discarded as unappliable is acknowledged without
        // asking for anything to publish.
        let discarding = FakeBroker::start(
            &directory(),
            Box::new(|_, _| b"OK document_discarded fulfillment_rejected\n".to_vec()),
        );
        assert_eq!(
            rig.step(
                &discarding.socket,
                &authorization_envelope(FULFILLMENT_ID, "recipient")
            ),
            Ok(StepOutcome::Relayed)
        );
        assert_eq!(discarding.commands(), ["RELAY"]);
        // Deliveries, revocations and other documents never trigger one.
        let broker = fulfilling_broker(framed(&offer_json("fixed")));
        for kind in [
            "fulfillment_delivery",
            "fulfillment_revocation",
            "fulfillment_offer",
            "fulfillment_submit",
            "registration",
        ] {
            assert_eq!(
                rig.step(&broker.socket, &other_envelope(kind)),
                Ok(StepOutcome::Relayed),
                "{kind}"
            );
        }
        // An authorization that names no usable fulfillment or side asks nothing.
        for envelope in [
            authorization_envelope(FULFILLMENT_ID, "somebody"),
            authorization_envelope("bad id", "recipient"),
            authorization_envelope("bad/id", "issuer"),
            other_envelope("fulfillment_authorization"),
        ] {
            assert_eq!(
                rig.step(&broker.socket, &envelope),
                Ok(StepOutcome::Relayed)
            );
        }
        assert!(
            broker.commands().iter().all(|command| command == "RELAY"),
            "{:?}",
            broker.commands()
        );
        assert!(rig.outbox.first_batch(10).is_empty());
        assert!(rig.logs.is_empty());
    }

    #[test]
    fn p10_n03_anything_but_the_exact_brokers_event_is_skipped_never_queued() {
        let id = FULFILLMENT_ID;
        let offer_key = fulfillment_key("fo_", id);
        let good = offer_json("fixed");
        let spaced = String::from_utf8(good.clone())
            .unwrap()
            .replacen("{\"body\"", "{ \"body\"", 1)
            .into_bytes();
        let mut cases: Vec<(&str, Vec<u8>, &'static str)> = vec![
            (
                "refused",
                b"ERR fulfillment_denied\n".to_vec(),
                LOG_FULFILLMENT_DENIED,
            ),
            (
                "the other side's kind",
                framed(&event_json(
                    id,
                    "fulfillment_submit",
                    &fulfillment_key("fs_", id),
                    "x",
                )),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "a kind that is not a fulfillment event",
                framed(&event_json(id, "audit", &offer_key, "x")),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "the wrong event key",
                framed(&event_json(
                    id,
                    "fulfillment_offer",
                    &fulfillment_key("fo_", "ful_ffffffffffffffffffffff"),
                    "x",
                )),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "another fulfillment's body",
                framed(&event_json(
                    "ful_ffffffffffffffffffffff",
                    "fulfillment_offer",
                    &offer_key,
                    "x",
                )),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "non-canonical bytes",
                framed(&spaced),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "a length that does not match",
                [
                    format!("FULFILL_EVENT {}\n", good.len() + 1).into_bytes(),
                    good.clone(),
                    b"\n".to_vec(),
                ]
                .concat(),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "a padded length",
                [
                    format!("FULFILL_EVENT 0{}\n", good.len()).into_bytes(),
                    good.clone(),
                    b"\n".to_vec(),
                ]
                .concat(),
                LOG_FULFILLMENT_MALFORMED,
            ),
            (
                "the browser frame",
                [
                    format!("OFFER_EVENT {}\n", good.len()).into_bytes(),
                    good.clone(),
                    b"\n".to_vec(),
                ]
                .concat(),
                LOG_FULFILLMENT_MALFORMED,
            ),
        ];
        cases.push((
            "an empty event",
            b"FULFILL_EVENT 0\n\n".to_vec(),
            LOG_FULFILLMENT_MALFORMED,
        ));
        for (name, reply, log) in cases {
            let mut rig = Rig::new();
            let broker = fulfilling_broker(reply);
            let envelope = authorization_envelope(id, "recipient");
            assert_eq!(
                rig.step(&broker.socket, &envelope),
                Ok(StepOutcome::FulfillmentEventSkipped),
                "{name}"
            );
            assert_eq!(rig.logs, [log], "{name}");
            assert!(rig.outbox.first_batch(10).is_empty(), "{name}");
            // The decision is remembered, so the broker is not asked again.
            assert_eq!(
                rig.step(&broker.socket, &envelope),
                Ok(StepOutcome::FulfillmentEventAlreadyRequested),
                "{name}"
            );
            assert_eq!(
                broker
                    .commands()
                    .iter()
                    .filter(|command| *command == "FULFILL_EVENT")
                    .count(),
                1,
                "{name}"
            );
        }
    }

    #[test]
    fn p10_n04_an_unreachable_or_confused_broker_is_retried_not_skipped() {
        let mut rig = Rig::new();
        let envelope = authorization_envelope(FULFILLMENT_ID, "recipient");
        // No trailing newline: the answer is not a complete broker reply.
        let truncated = fulfilling_broker(b"FULFILL_EVENT 5\nabcde".to_vec());
        assert_eq!(
            rig.step(&truncated.socket, &envelope),
            Err(ChannelError::Retryable)
        );
        assert_eq!(rig.logs, [LOG_BROKER_UNAVAILABLE]);
        // It was not remembered: the next attempt asks again and succeeds.
        let working = fulfilling_broker(framed(&offer_json("fixed")));
        assert_eq!(
            rig.step(&working.socket, &envelope),
            Ok(StepOutcome::FulfillmentEventQueued)
        );
        assert_eq!(rig.outbox.first_batch(10).len(), 1);
        // A broker that cannot even apply the document leaves it unacknowledged.
        let mut gone = fulfilling_broker(Vec::new());
        gone.shut_down();
        assert_eq!(
            rig.step(
                &gone.socket,
                &authorization_envelope(FULFILLMENT_ID, "issuer")
            ),
            Err(ChannelError::Retryable)
        );
    }

    #[test]
    fn p10_n05_a_different_event_for_a_queued_key_is_a_conflict_not_a_replacement() {
        let mut rig = Rig::new();
        let envelope = authorization_envelope(FULFILLMENT_ID, "recipient");
        let first = fulfilling_broker(framed(&offer_json("first")));
        assert_eq!(
            rig.step(&first.socket, &envelope),
            Ok(StepOutcome::FulfillmentEventQueued)
        );
        // A restart forgets the in-memory set but keeps the durable outbox.
        rig.published.clear();
        let second = fulfilling_broker(framed(&offer_json("second")));
        assert_eq!(
            rig.step(&second.socket, &envelope),
            Ok(StepOutcome::FulfillmentEventSkipped)
        );
        assert_eq!(rig.logs, [LOG_FULFILLMENT_CONFLICT]);
        let queued = rig.outbox.first_batch(10);
        assert_eq!(queued.len(), 1);
        assert_eq!(
            canonicalize_value(&queued[0].to_value()).unwrap(),
            offer_json("first"),
            "first bytes win"
        );
        // The exact same event again is idempotent.
        rig.published.clear();
        assert_eq!(
            rig.step(&first.socket, &envelope),
            Ok(StepOutcome::FulfillmentEventQueued)
        );
        assert_eq!(rig.outbox.first_batch(10).len(), 1);
    }

    #[test]
    fn p10_n07_fulfillment_log_lines_are_fixed_text_and_never_carry_ids_or_bodies() {
        let mut rig = Rig::new();
        let all = [
            LOG_FULFILLMENT_DENIED,
            LOG_FULFILLMENT_MALFORMED,
            LOG_FULFILLMENT_CONFLICT,
            LOG_BROKER_UNAVAILABLE,
        ];
        let denied_id = "ful_P10DENIEDCANARY000000";
        let malformed_id = "ful_P10MALFORMEDCANARY00";
        let denying = fulfilling_broker(b"ERR fulfillment_denied\n".to_vec());
        rig.step(
            &denying.socket,
            &authorization_envelope(denied_id, "recipient"),
        )
        .unwrap();
        let garbled = fulfilling_broker(framed(CANARY.as_bytes()));
        rig.step(
            &garbled.socket,
            &authorization_envelope(malformed_id, "issuer"),
        )
        .unwrap();
        let truncated = fulfilling_broker(b"FULFILL_EVENT 5\nabcde".to_vec());
        rig.step(
            &truncated.socket,
            &authorization_envelope(FULFILLMENT_ID, "recipient"),
        )
        .unwrap_err();
        assert_eq!(
            rig.logs,
            [
                LOG_FULFILLMENT_DENIED,
                LOG_FULFILLMENT_MALFORMED,
                LOG_BROKER_UNAVAILABLE
            ]
        );
        for line in rig.logs.iter().chain(all.iter()) {
            assert!(all.contains(line), "only fixed lines may be emitted");
            for forbidden in [CANARY, denied_id, malformed_id, FULFILLMENT_ID, "ful_"] {
                assert!(!line.contains(forbidden), "{line}");
            }
        }
    }
}

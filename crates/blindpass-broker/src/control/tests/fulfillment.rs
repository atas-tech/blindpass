// SPDX-License-Identifier: AGPL-3.0-only

//! P10 fulfillment over the control socket, driven exactly as the unprivileged
//! node relay drives it: RELAY for controller documents, FULFILL_EVENT for the
//! broker-signed offer and submission, PULL_EVENTS for results.

use super::*;
use crate::keys::PinnedIssuer;
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fulfillment::{
    FulfillmentAuthorization, FulfillmentDelivery, FulfillmentParty, FulfillmentResult,
    FulfillmentRevocation, FulfillmentSide, FulfillmentTerms, ResultState, RevocationReason,
};
use blindpass_core::signing::base64_url_decode;

const SECRET: &[u8] = b"DUMMY-P10-CONTROL-CREDENTIAL-012";
const ID: &str = "ful_0123456789abcdefABCDEF";

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct Controller {
    key: Ed25519KeyPair,
    key_id: String,
    public: String,
    now_ms: u64,
}

impl Controller {
    fn new(seed: u8) -> Self {
        let key = Ed25519KeyPair::from_seed(&[seed; 32]).unwrap();
        let public = base64_url_encode(key.public_key());
        Self {
            key_id: format!("ed25519-{public}"),
            key,
            public,
            now_ms: wall_ms(),
        }
    }

    fn sign(&self, kind: DocumentKind, body: Value, epoch: u64) -> Vec<u8> {
        SignedEnvelope::sign(kind, body, &self.key_id, epoch, &self.key)
            .unwrap()
            .to_json()
            .unwrap()
    }

    fn terms(&self, issuer: &Peer, recipient: &Peer, id: &str) -> FulfillmentTerms {
        FulfillmentTerms {
            fulfillment_id: id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            issuer: issuer.party(),
            recipient: recipient.party(),
            policy_version: 4,
            rule_id: "rule-cross-1".to_owned(),
            approval_reference: Some("oa_0123456789abcdef".to_owned()),
            prior_fulfillment_id: None,
            max_plaintext_bytes: 8192,
            issued_at_ms: self.now_ms,
            expires_at_ms: self.now_ms + 600_000,
            issuer_epoch: 1,
        }
    }

    fn authorization(
        &self,
        side: FulfillmentSide,
        terms: &FulfillmentTerms,
        offer: Option<&SignedEnvelope>,
    ) -> Vec<u8> {
        let body = FulfillmentAuthorization {
            side,
            terms: terms.clone(),
            offer: offer.cloned(),
        }
        .to_value()
        .unwrap();
        self.sign(
            DocumentKind::FulfillmentAuthorization,
            body,
            terms.issuer_epoch,
        )
    }

    fn delivery(
        &self,
        terms: &FulfillmentTerms,
        offer: &SignedEnvelope,
        submit: &SignedEnvelope,
    ) -> Vec<u8> {
        let body = FulfillmentDelivery {
            terms: terms.clone(),
            offer: offer.clone(),
            submit: submit.clone(),
        }
        .to_value()
        .unwrap();
        self.sign(DocumentKind::FulfillmentDelivery, body, terms.issuer_epoch)
    }

    /// `epoch` is the epoch the document is signed under; it may be older than
    /// the node's pin, and is independent of the terms it names.
    fn revocation(&self, terms: &FulfillmentTerms, node_id: &str, epoch: u64) -> Vec<u8> {
        let body = FulfillmentRevocation {
            fulfillment_id: terms.fulfillment_id.clone(),
            terms_digest: terms.digest_hex().unwrap(),
            node_id: node_id.to_owned(),
            reason: RevocationReason::Operator,
            revoked_at_ms: self.now_ms,
            retain_until_ms: self.now_ms + 7 * 86_400_000,
            issuer_epoch: epoch,
        }
        .to_value()
        .unwrap();
        self.sign(DocumentKind::FulfillmentRevocation, body, epoch)
    }

    fn acknowledgement(&self, node_id: &str, event_keys: Vec<String>) -> Vec<u8> {
        let ack = ApplicationAck {
            node_id: node_id.to_owned(),
            issuer_epoch: 1,
            acknowledged_at_ms: self.now_ms,
            event_keys,
        };
        self.sign(DocumentKind::ApplicationAck, ack.to_value().unwrap(), 1)
    }
}

struct Peer {
    directory: std::path::PathBuf,
    identity: std::sync::Arc<NodeIdentity>,
    state: std::sync::Arc<std::sync::Mutex<BrokerState>>,
    node_id: String,
    workload_id: String,
    unit: String,
    credential: String,
}

impl Peer {
    fn new(controller: &Controller, name: &str, source: bool, destination: bool) -> Self {
        let directory = temporary_directory();
        let node_id = format!("nd_{name}");
        let identity = std::sync::Arc::new(NodeIdentity::load_or_create(&directory).unwrap());
        identity
            .pin_issuer(PinnedIssuer {
                tenant_id: "tenant-a".to_owned(),
                node_id: node_id.clone(),
                epoch: 1,
                key_id: controller.key_id.clone(),
                public_key: controller.public.clone(),
            })
            .unwrap();
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state.operation_directory = directory.join("ops");
        state.configure_grant_storage(&identity).unwrap();
        let unit = format!("{name}-app.service");
        let credential = "api-token".to_owned();
        state.loader_policy.map_unit(&unit, &credential).unwrap();
        let sources: Vec<String> = source.then(|| unit.clone()).into_iter().collect();
        let destinations: Vec<String> = destination.then(|| unit.clone()).into_iter().collect();
        state
            .configure_fulfillment(&sources, &destinations, Duration::from_secs(180))
            .unwrap();
        let peer = Self {
            directory,
            identity,
            state: std::sync::Arc::new(std::sync::Mutex::new(state)),
            workload_id: format!("wl_{name}"),
            node_id,
            unit,
            credential,
        };
        let registration = Registration {
            node_id: peer.node_id.clone(),
            workload_id: peer.workload_id.clone(),
            unit: peer.unit.clone(),
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
        assert_eq!(
            peer.relay(&controller.sign(
                DocumentKind::Registration,
                registration.to_value().unwrap(),
                1
            )),
            b"OK document_applied registration\n"
        );
        assert_eq!(
            peer.relay(&controller.sign(
                DocumentKind::PolicySnapshot,
                policy.to_value().unwrap(),
                1
            )),
            b"OK document_applied policy_snapshot\n"
        );
        peer.refresh_time(controller, 1);
        peer
    }

    fn relay(&self, document: &[u8]) -> Vec<u8> {
        relay_signed_document(&self.identity, &self.state, document)
    }

    fn command(&self, line: &str) -> Vec<u8> {
        control_exchange(&self.identity, &self.state, line.as_bytes())
    }

    fn refresh_time(&self, controller: &Controller, epoch: u64) {
        let response = self.command("TIME_CHALLENGE\n");
        let challenge = std::str::from_utf8(&response)
            .unwrap()
            .strip_prefix("TIME ")
            .unwrap()
            .strip_suffix('\n')
            .unwrap()
            .to_owned();
        let reply = TimeReply {
            node_id: self.node_id.clone(),
            challenge,
            challenge_received_at_ms: controller.now_ms,
            controller_time_ms: controller.now_ms,
            issuer_epoch: epoch,
        };
        assert_eq!(
            self.relay(&controller.sign(DocumentKind::TimeReply, reply.to_value().unwrap(), epoch)),
            b"OK document_applied time_reply\n"
        );
    }

    fn provision(&self, secret: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let public = state.provision_key(&self.unit, &self.credential).unwrap();
        let aad = crate::provision_aad(&self.unit, &self.credential);
        let sealed = RecipientKeyPair::seal(&public, secret, aad.as_bytes()).unwrap();
        state
            .provision_sealed(
                &self.unit,
                &self.credential,
                &sealed.enc,
                &sealed.ciphertext,
            )
            .unwrap();
    }

    /// What the unit would get from the loader; a read is a consumption.
    fn read(&self) -> Option<Vec<u8>> {
        self.state
            .lock()
            .unwrap()
            .process_systemd_credential(&self.unit, &self.credential)
            .ok()
            .map(|secret| secret.as_bytes().to_vec())
    }

    fn party(&self) -> FulfillmentParty {
        let public = self.identity.public_identity().unwrap();
        FulfillmentParty {
            node_id: self.node_id.clone(),
            workload_id: self.workload_id.clone(),
            unit: self.unit.clone(),
            credential: self.credential.clone(),
            registration_version: 1,
            key_version: self.identity.key_version().unwrap(),
            signing_public: public.signing_public,
            recipient_public: public.recipient_public,
            fingerprint: public.fingerprint,
        }
    }

    /// Check a broker-signed node event against this node's own key.
    fn verified_event(&self, event: &Value) -> (String, String, Value) {
        let kind = event.get("kind").and_then(Value::as_str).unwrap();
        let key = event
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap();
        let body = event.get("body").unwrap();
        let signature = event
            .get("broker_signature")
            .and_then(Value::as_str)
            .unwrap();
        let message = node_event_message(&self.node_id, key, kind, body).unwrap();
        let public = self.identity.public_identity().unwrap();
        assert!(
            verify(
                &base64_url_decode(&public.signing_public, 32).unwrap(),
                &message,
                &base64_url_decode(signature, 64).unwrap(),
            )
            .unwrap(),
            "{kind} is signed by this node's key"
        );
        (kind.to_owned(), key.to_owned(), body.clone())
    }

    /// `FULFILL_EVENT <id>`: the framed, canonical, broker-signed event bytes.
    fn fulfillment_event(&self, id: &str) -> (String, String, SignedEnvelope, Vec<u8>) {
        let response = self.command(&format!("FULFILL_EVENT {id}\n"));
        let end = response.iter().position(|byte| *byte == b'\n').unwrap();
        let header = std::str::from_utf8(&response[..end]).unwrap();
        let length: usize = header
            .strip_prefix("FULFILL_EVENT ")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            response.len(),
            end + 1 + length + 1,
            "one frame, one newline"
        );
        assert_eq!(response.last(), Some(&b'\n'));
        let bytes = response[end + 1..end + 1 + length].to_vec();
        let event = parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(
            canonicalize_value(&event).unwrap(),
            bytes,
            "canonical bytes"
        );
        let (kind, key, body) = self.verified_event(&event);
        let envelope = SignedEnvelope::from_json(
            std::str::from_utf8(&canonicalize_value(&body).unwrap()).unwrap(),
        )
        .unwrap();
        (kind, key, envelope, bytes)
    }

    fn pull(&self) -> Vec<Value> {
        let response = self.command("PULL_EVENTS\n");
        let end = response.iter().position(|byte| *byte == b'\n').unwrap();
        let payload = std::str::from_utf8(&response[end + 1..response.len() - 1]).unwrap();
        parse_json(payload).unwrap().as_array().unwrap().to_vec()
    }

    /// Every `fulfillment_result` this node would publish, signature-checked.
    fn results(&self) -> Vec<(String, FulfillmentResult)> {
        self.pull()
            .iter()
            .filter(|event| event.get("kind").and_then(Value::as_str) == Some("fulfillment_result"))
            .map(|event| {
                let (_, key, body) = self.verified_event(event);
                (key, FulfillmentResult::from_value(&body).unwrap())
            })
            .collect()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn p10_c01_the_relay_drives_a_whole_fulfillment_over_the_control_socket() {
    let controller = Controller::new(61);
    let issuer = Peer::new(&controller, "issuer", true, false);
    let recipient = Peer::new(&controller, "recipient", false, true);
    issuer.provision(SECRET);
    let terms = controller.terms(&issuer, &recipient, ID);

    assert_eq!(
        recipient.relay(&controller.authorization(FulfillmentSide::Recipient, &terms, None)),
        b"OK document_applied fulfillment_authorization\n"
    );
    let (kind, key, offer, offer_bytes) = recipient.fulfillment_event(ID);
    assert_eq!(kind, "fulfillment_offer");
    assert!(key.starts_with("fo_") && key.len() == 67);
    assert_eq!(
        recipient.fulfillment_event(ID).3,
        offer_bytes,
        "a lost reply is retried with identical bytes"
    );

    assert_eq!(
        issuer.relay(&controller.authorization(FulfillmentSide::Issuer, &terms, Some(&offer))),
        b"OK document_applied fulfillment_authorization\n"
    );
    let (kind, key, submit, _) = issuer.fulfillment_event(ID);
    assert_eq!(kind, "fulfillment_submit");
    assert!(key.starts_with("fs_") && key.len() == 67);
    assert!(
        issuer.results().is_empty(),
        "an issuer reports nothing on success"
    );

    assert_eq!(
        recipient.relay(&controller.delivery(&terms, &offer, &submit)),
        b"OK document_applied fulfillment_delivery\n"
    );
    let results = recipient.results();
    assert_eq!(results.len(), 1);
    let (stored_key, stored) = &results[0];
    assert_eq!(stored.state, ResultState::Stored);
    assert_eq!(stored.side, FulfillmentSide::Recipient);
    assert_eq!(stored.fulfillment_id, ID);
    assert_eq!(stored.terms_digest, terms.digest_hex().unwrap());
    assert!(stored_key.starts_with("fr_") && stored_key.len() == 67);

    // The controller acknowledges the stored result; only it leaves the queue.
    assert_eq!(
        recipient.relay(&controller.acknowledgement(&recipient.node_id, vec![stored_key.clone()])),
        b"OK document_applied application_ack\n"
    );
    assert!(recipient.results().is_empty());
    assert_eq!(recipient.read().as_deref(), Some(SECRET));
    let results = recipient.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1.state, ResultState::Consumed);
    // No plaintext ever appears in a pulled event.
    let pulled = recipient.command("PULL_EVENTS\n");
    assert!(!pulled.windows(SECRET.len()).any(|window| window == SECRET));
}

#[test]
fn p10_c02_an_unappliable_document_is_discarded_and_reported_not_retried() {
    let controller = Controller::new(62);
    let issuer = Peer::new(&controller, "issuer", true, false);
    // The recipient broker never opted in.
    let recipient = Peer::new(&controller, "recipient", false, false);
    let terms = controller.terms(&issuer, &recipient, ID);
    assert_eq!(
        recipient.relay(&controller.authorization(FulfillmentSide::Recipient, &terms, None)),
        b"OK document_discarded fulfillment_rejected\n"
    );
    let results = recipient.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1.state, ResultState::Failed);
    assert_eq!(results[0].1.code.as_deref(), Some("not_enabled"));
    // No offer was minted, so the relay has nothing to publish.
    assert_eq!(
        recipient.command(&format!("FULFILL_EVENT {ID}\n")),
        b"ERR fulfillment_denied\n"
    );
    // A document for another node is acknowledged too, without any event.
    let other = Peer::new(&controller, "stranger", true, true);
    assert_eq!(
        other.relay(&controller.authorization(FulfillmentSide::Recipient, &terms, None)),
        b"OK document_discarded fulfillment_rejected\n"
    );
    assert!(other.results().is_empty());
}

#[test]
fn p10_c03_fulfillment_event_refuses_everything_it_did_not_mint() {
    let controller = Controller::new(63);
    let issuer = Peer::new(&controller, "issuer", true, false);
    let recipient = Peer::new(&controller, "recipient", false, true);
    for line in [
        "FULFILL_EVENT \n",
        "FULFILL_EVENT bad/id\n",
        "FULFILL_EVENT ful_unknownunknownunknown\n",
        "FULFILL_EVENT ful_0123456789abcdefABCDEF extra\n",
    ] {
        assert_eq!(
            recipient.command(line),
            b"ERR fulfillment_denied\n",
            "{line:?}"
        );
    }
    // After a revocation the offer can no longer be fetched.
    let terms = controller.terms(&issuer, &recipient, ID);
    recipient.relay(&controller.authorization(FulfillmentSide::Recipient, &terms, None));
    assert_eq!(recipient.fulfillment_event(ID).0, "fulfillment_offer");
    assert_eq!(
        recipient.relay(&controller.revocation(&terms, &recipient.node_id, 1)),
        b"OK document_applied fulfillment_revocation\n"
    );
    assert_eq!(
        recipient.command(&format!("FULFILL_EVENT {ID}\n")),
        b"ERR fulfillment_denied\n"
    );
    // A revocation addressed to another node is acknowledged and changes nothing.
    assert_eq!(
        recipient.relay(&controller.revocation(&terms, &issuer.node_id, 1)),
        b"OK document_discarded fulfillment_rejected\n"
    );
}

#[test]
fn p10_c04_an_older_epoch_revocation_still_removes_authority_but_nothing_else_does() {
    let controller = Controller::new(64);
    let issuer = Peer::new(&controller, "issuer", true, false);
    let recipient = Peer::new(&controller, "recipient", false, true);
    // The controller recovers: the pin moves to epoch 2.
    recipient.refresh_time(&controller, 2);
    let mut terms = controller.terms(&issuer, &recipient, ID);
    terms.issuer_epoch = 2;
    // A delayed epoch-1 authorization confers nothing.
    let mut old_terms = terms.clone();
    old_terms.issuer_epoch = 1;
    assert_eq!(
        recipient.relay(&controller.authorization(FulfillmentSide::Recipient, &old_terms, None)),
        b"OK document_applied stale_epoch\n"
    );
    assert!(recipient.results().is_empty());
    // A delayed epoch-1 revocation is honoured as a tombstone for the terms it names.
    assert_eq!(
        recipient.relay(&controller.revocation(&terms, &recipient.node_id, 1)),
        b"OK document_applied fulfillment_revocation\n"
    );
    assert_eq!(
        recipient.relay(&controller.authorization(FulfillmentSide::Recipient, &terms, None)),
        b"OK document_discarded fulfillment_rejected\n"
    );
    assert_eq!(
        recipient.command(&format!("FULFILL_EVENT {ID}\n")),
        b"ERR fulfillment_denied\n"
    );
    assert!(
        recipient.results().is_empty(),
        "a revoked document is silent"
    );
}

#[test]
fn p10_c05_pull_events_retries_results_the_queue_could_not_take() {
    let controller = Controller::new(65);
    let issuer = Peer::new(&controller, "issuer", true, false);
    let recipient = Peer::new(&controller, "recipient", false, true);
    issuer.provision(SECRET);
    let terms = controller.terms(&issuer, &recipient, ID);
    recipient.relay(&controller.authorization(FulfillmentSide::Recipient, &terms, None));
    let (_, _, offer, _) = recipient.fulfillment_event(ID);
    issuer.relay(&controller.authorization(FulfillmentSide::Issuer, &terms, Some(&offer)));
    let (_, _, submit, _) = issuer.fulfillment_event(ID);

    // The node queue is full when the credential arrives: it is stored anyway.
    {
        let mut state = recipient.state.lock().unwrap();
        for index in 0..crate::MAX_BROKER_AUDIT_EVENTS - 1 {
            state
                .pending_node_events
                .push_back(crate::PendingNodeEvent {
                    idempotency_key: format!("event_fill_{index:08}"),
                    kind: "audit".to_owned(),
                    body: Value::Object(vec![(
                        "action".to_owned(),
                        Value::String("fill".to_owned()),
                    )]),
                });
        }
    }
    assert_eq!(
        recipient.relay(&controller.delivery(&terms, &offer, &submit)),
        b"OK document_applied fulfillment_delivery\n"
    );
    recipient.state.lock().unwrap().pending_node_events.clear();
    // The next pull queues the held result instead of losing it.
    let results = recipient.results();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1.state, ResultState::Stored);
    assert_eq!(recipient.read().as_deref(), Some(SECRET));
}

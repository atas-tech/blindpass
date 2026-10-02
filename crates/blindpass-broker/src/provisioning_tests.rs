// SPDX-License-Identifier: AGPL-3.0-only
use crate::keys::{NodeIdentity, PinnedIssuer};
use crate::{BrokerState, destination_key};
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::provisioning::{BrowserProvisioningBinding, BrowserProvisioningDelivery};
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use blindpass_core::signing::{base64_url_decode, base64_url_encode};

fn current_gid() -> u32 {
    unsafe extern "C" {
        fn getgid() -> u32;
    }
    // SAFETY: getgid has no arguments and always returns the caller's gid.
    unsafe { getgid() }
}

struct Fixture {
    directory: std::path::PathBuf,
    state: BrokerState,
    identity: std::sync::Arc<NodeIdentity>,
    issuer: Ed25519KeyPair,
    grant_id: String,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let (directory, state, grant, _, _) = crate::tests::browser_grant_fixture(label);
        let identity =
            std::sync::Arc::new(NodeIdentity::load_or_create(&directory.join("keys")).unwrap());
        let issuer = Ed25519KeyPair::generate().unwrap();
        let public = base64_url_encode(issuer.public_key());
        identity
            .pin_issuer(PinnedIssuer {
                tenant_id: "tenant-a".into(),
                node_id: "node-a".into(),
                epoch: 1,
                key_id: format!("ed25519-{public}"),
                public_key: public,
            })
            .unwrap();
        Self {
            directory,
            state,
            identity,
            issuer,
            grant_id: grant.id,
        }
    }
    fn offer(&mut self) -> SignedEnvelope {
        self.state
            .browser_recipient_offer(&self.identity, &self.grant_id)
            .unwrap()
    }
    fn delivery(&self, offer: &SignedEnvelope, source: &[u8]) -> BrowserProvisioningDelivery {
        let binding = BrowserProvisioningBinding::from_value(offer.body()).unwrap();
        let public = base64_url_decode(&binding.recipient_public, 32).unwrap();
        let sealed = RecipientKeyPair::seal(&public, source, &binding.aad().unwrap()).unwrap();
        BrowserProvisioningDelivery {
            binding,
            enc: base64_url_encode(&sealed.enc),
            ciphertext: base64_url_encode(&sealed.ciphertext),
        }
    }
    fn sign(&self, delivery: &BrowserProvisioningDelivery) -> Vec<u8> {
        let pin = self.identity.pinned_issuer().unwrap().unwrap();
        SignedEnvelope::sign(
            DocumentKind::ProvisioningDelivery,
            delivery.to_value().unwrap(),
            &pin.key_id,
            pin.epoch,
            &self.issuer,
        )
        .unwrap()
        .to_json()
        .unwrap()
    }
    /// One bounded control-socket exchange against this fixture's real state.
    fn exchange(&mut self, request: &[u8]) -> Vec<u8> {
        use std::io::{Read, Write};
        let state = std::sync::Arc::new(std::sync::Mutex::new(std::mem::replace(
            &mut self.state,
            BrokerState::new(blindpass_core::delivery::DeliveryPolicy::default()),
        )));
        let (mut broker, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        crate::control::handle_connection(
            &mut broker,
            Some(current_gid()),
            self.identity.clone(),
            state.clone(),
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .unwrap();
        drop(broker);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        self.state = std::sync::Arc::try_unwrap(state)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap();
        response
    }
    fn source(&self, binding: &BrowserProvisioningBinding) -> &[u8] {
        self.state
            .credentials
            .get(&destination_key(&binding.source_unit, &binding.credential))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn pv06_b01_actual_enrolled_offer_retry_and_controller_authorized_source() {
    let mut f = Fixture::new("pv06-enrolled");
    let offer = f.offer();
    let binding = BrowserProvisioningBinding::from_value(offer.body()).unwrap();
    let public = f.identity.public_identity().unwrap();
    assert!(
        offer
            .verify(
                &base64_url_decode(&public.signing_public, 32).unwrap(),
                "node-a-1",
                1
            )
            .unwrap()
    );
    assert_eq!(binding.grant.id, f.grant_id);
    assert_eq!(binding.source_unit, "blindpass-login-helper@.service");
    assert_eq!(binding.credential, "primary-password");
    assert_eq!(offer.to_json().unwrap(), f.offer().to_json().unwrap());
    assert!(binding.expires_at_ms - binding.issued_at_ms <= 180_000);
    assert!(binding.expires_at_ms <= binding.grant.expires_at_ms);
    let delivery = f.delivery(&offer, b"  DUMMY-PV06-SOURCE\n");
    let doc = f.sign(&delivery);
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .unwrap()
    );
    assert_eq!(f.source(&binding), b"  DUMMY-PV06-SOURCE\n");
    assert!(
        !f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .unwrap()
    );
    assert!(
        f.state
            .browser_recipient_offer(&f.identity, &f.grant_id)
            .is_err()
    );
}

#[test]
fn pv06_b03_foreign_sender_and_changed_binding_do_not_consume_private_key() {
    let mut f = Fixture::new("pv06-foreign");
    let offer = f.offer();
    let delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
    let pin = f.identity.pinned_issuer().unwrap().unwrap();
    let foreign = Ed25519KeyPair::generate().unwrap();
    let doc = SignedEnvelope::sign(
        DocumentKind::ProvisioningDelivery,
        delivery.to_value().unwrap(),
        &pin.key_id,
        1,
        &foreign,
    )
    .unwrap()
    .to_json()
    .unwrap();
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .is_err()
    );
    let mut changed = delivery.clone();
    changed.binding.credential = "other-credential".into();
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &f.sign(&changed))
            .is_err()
    );
    let doc = f.sign(&delivery);
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .unwrap()
    );
}

#[test]
fn pv06_b03_authenticated_corruption_spends_key_without_storing_source() {
    let mut f = Fixture::new("pv06-corrupt");
    let offer = f.offer();
    let mut delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
    let original = f.sign(&delivery);
    let mut bytes =
        base64_url_decode(&delivery.ciphertext, delivery.ciphertext.len() * 3 / 4).unwrap();
    bytes[0] ^= 1;
    delivery.ciphertext = base64_url_encode(&bytes);
    let corrupt = f.sign(&delivery);
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &corrupt)
            .is_err()
    );
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &original)
            .is_err()
    );
    assert_ne!(f.source(&delivery.binding), b"DUMMY-PV06-SOURCE");
    assert!(
        f.state
            .browser_recipient_offer(&f.identity, &f.grant_id)
            .is_err()
    );
}

#[test]
fn pv06_b04_cancel_policy_mapping_node_and_deadline_fences() {
    for variant in ["cancel", "policy", "mapping", "node", "deadline"] {
        let mut f = Fixture::new(&format!("pv06-{variant}"));
        let offer = f.offer();
        let delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
        let doc = f.sign(&delivery);
        match variant {
            "cancel" => {
                f.state
                    .operation_requests
                    .values
                    .get_mut(delivery.binding.grant.request_event_key.as_ref().unwrap())
                    .unwrap()
                    .cancel_requested = true;
            }
            "policy" => f.state.fleet_policy.as_mut().unwrap().policy_version += 1,
            "mapping" => f.state.browser_catalog = None,
            "node" => f.state.node_revoked = true,
            "deadline" => f.state.browser_offers.expire_all_for_test(),
            _ => unreachable!(),
        }
        assert!(
            f.state
                .accept_browser_provisioning(&f.identity, &doc)
                .is_err(),
            "{variant}"
        );
        assert_ne!(f.source(&delivery.binding), b"DUMMY-PV06-SOURCE");
    }
}

#[test]
fn pv06_b04_restart_does_not_reconstruct_offer_custody() {
    let mut f = Fixture::new("pv06-restart");
    let offer = f.offer();
    let delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
    let doc = f.sign(&delivery);
    f.state.browser_offers = Default::default();
    f.state.original_workload_leases.clear();
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .is_err()
    );
    assert_ne!(f.source(&delivery.binding), b"DUMMY-PV06-SOURCE");
    assert!(
        f.state
            .browser_recipient_offer(&f.identity, &f.grant_id)
            .is_err()
    );
}

#[test]
fn pv06_b05_invalid_plaintext_consumes_key_and_never_replaces_source() {
    for source in [&b""[..], &b"\xff"[..]] {
        let mut f = Fixture::new("pv06-invalid-source");
        let offer = f.offer();
        let delivery = f.delivery(&offer, source);
        let doc = f.sign(&delivery);
        assert!(
            f.state
                .accept_browser_provisioning(&f.identity, &doc)
                .is_err()
        );
        assert_eq!(f.source(&delivery.binding), b"P05-SOURCE-CANARY");
        assert!(
            f.state
                .accept_browser_provisioning(&f.identity, &doc)
                .is_err()
        );
    }
}

#[test]
fn pv06_b04_current_controller_epoch_and_actual_node_rotation_deny_old_delivery() {
    for variant in ["controller", "node-key"] {
        let mut f = Fixture::new(&format!("pv06-{variant}"));
        let offer = f.offer();
        let delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
        let doc = f.sign(&delivery);
        if variant == "controller" {
            let mut pin = f.identity.pinned_issuer().unwrap().unwrap();
            pin.epoch += 1;
            f.identity.pin_issuer(pin).unwrap();
        } else {
            let (_, public) = f.identity.prepare_rotation().unwrap();
            f.identity
                .apply_key_rotation(&blindpass_core::fleet::NodeKeyRotation {
                    node_id: "node-a".into(),
                    rotation_id: "rot_pv06_rotation_000000000001".into(),
                    from_key_version: 1,
                    to_key_version: 2,
                    signing_public: public.signing_public,
                    recipient_public: public.recipient_public,
                    fingerprint: public.fingerprint,
                    issuer_epoch: 1,
                })
                .unwrap();
        }
        assert!(
            f.state
                .accept_browser_provisioning(&f.identity, &doc)
                .is_err()
        );
        assert_eq!(f.source(&delivery.binding), b"P05-SOURCE-CANARY");
        assert!(
            f.state
                .browser_recipient_offer(&f.identity, &f.grant_id)
                .is_err()
        );
    }
}

fn exchange(f: &mut Fixture, request: &[u8]) -> Result<Vec<u8>, crate::BrokerError> {
    use std::io::{Read, Write};
    let state = std::mem::replace(&mut f.state, BrokerState::new(Default::default()));
    let state = std::sync::Arc::new(std::sync::Mutex::new(state));
    let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
    client.write_all(request).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    unsafe extern "C" {
        fn getgid() -> u32;
    }
    // SAFETY: getgid takes no arguments and returns this fixture's group.
    let result = crate::control::handle_connection(
        &mut server,
        Some(unsafe { getgid() }),
        f.identity.clone(),
        state.clone(),
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    );
    drop(server);
    f.state = std::sync::Arc::try_unwrap(state)
        .unwrap()
        .into_inner()
        .unwrap();
    result?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    Ok(response)
}

#[test]
fn pv06_b05_actual_control_frames_large_source_fixed_results_and_partial_denial() {
    let mut f = Fixture::new("pv06-transport");
    let command = format!("BROWSER_OFFER {}\n", f.grant_id);
    let response = exchange(&mut f, command.as_bytes()).unwrap();
    let newline = response.iter().position(|byte| *byte == b'\n').unwrap();
    let length: usize = std::str::from_utf8(&response[..newline])
        .unwrap()
        .strip_prefix("OFFER ")
        .unwrap()
        .parse()
        .unwrap();
    let offer = SignedEnvelope::from_json(
        std::str::from_utf8(&response[newline + 1..newline + 1 + length]).unwrap(),
    )
    .unwrap();
    assert_eq!(response.len(), newline + 1 + length + 1);
    let source = vec![b'x'; 65_536];
    let delivery = f.delivery(&offer, &source);
    let doc = f.sign(&delivery);
    assert!(doc.len() > 65_536); // Dedicated frame covers the complete 64KiB plaintext limit.
    let mut request = format!("PROVISION_SOURCE {}\n", doc.len()).into_bytes();
    request.extend_from_slice(&doc);
    assert_eq!(
        exchange(&mut f, &request).unwrap(),
        b"OK browser_source_provisioned\n"
    );
    assert_eq!(f.source(&delivery.binding).len(), 65_536);
    assert_eq!(
        exchange(&mut f, &request).unwrap(),
        b"OK browser_source_already_provisioned\n"
    );
    for request in [
        b"PROVISION_SOURCE 013\n".as_slice(),
        b"PROVISION_SOURCE 131073\n",
        b"BROWSER_OFFER ../foreign\n",
    ] {
        assert_eq!(
            exchange(&mut f, request).unwrap(),
            b"ERR browser_provisioning_denied\n"
        );
    }
    assert!(exchange(&mut f, b"PROVISION_SOURCE 20\npartial").is_err());
}

#[test]
fn pv06_b04_periodic_withdrawal_prevents_retry_from_renewing_cancelled_offer() {
    let mut f = Fixture::new("pv06-withdraw");
    let offer = f.offer();
    let delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
    let doc = f.sign(&delivery);
    let event = delivery.binding.grant.request_event_key.as_ref().unwrap();
    f.state
        .operation_requests
        .values
        .get_mut(event)
        .unwrap()
        .cancel_requested = true;
    f.state.purge_expired_credentials();
    // Withdrawing then restoring metadata cannot reconstruct the destroyed key.
    f.state
        .operation_requests
        .values
        .get_mut(event)
        .unwrap()
        .cancel_requested = false;
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .is_err()
    );
    assert!(
        f.state
            .browser_recipient_offer(&f.identity, &f.grant_id)
            .is_err()
    );
    assert_eq!(f.source(&delivery.binding), b"P05-SOURCE-CANARY");
}

#[test]
fn pv06_b01_configured_browser_offer_lifetime_caps_offer_without_extending_retry() {
    // Adapted from the custody-key-lifetime form: the offer lifetime now has its
    // own setting, and the configured value is still honoured and never renewed.
    let mut f = Fixture::new("pv06-configured-ttl");
    f.state.browser_offer_lifetime = std::time::Duration::from_millis(1_500);
    let offer = f.offer();
    let binding = BrowserProvisioningBinding::from_value(offer.body()).unwrap();
    assert_eq!(binding.expires_at_ms - binding.issued_at_ms, 1_500);
    assert_eq!(f.offer().to_json().unwrap(), offer.to_json().unwrap());
    let mut zero = Fixture::new("pv06-zero-ttl");
    zero.state.browser_offer_lifetime = std::time::Duration::ZERO;
    assert!(
        zero.state
            .browser_recipient_offer(&zero.identity, &zero.grant_id)
            .is_err()
    );
}

#[test]
fn pv06_b01_default_browser_offer_lifetime_is_180s_and_never_the_30s_custody_lifetime() {
    assert_eq!(
        crate::DEFAULT_BROWSER_OFFER_LIFETIME,
        std::time::Duration::from_secs(180)
    );
    assert_eq!(
        crate::DEFAULT_CUSTODY_KEY_LIFETIME,
        std::time::Duration::from_secs(30)
    );
    // The fixture grant lives 60 s, so the default offer is capped by the grant
    // (not by 30 s) and can never outlive it.
    let mut f = Fixture::new("pv06-default-ttl");
    let offer = f.offer();
    let binding = BrowserProvisioningBinding::from_value(offer.body()).unwrap();
    let lifetime = binding.expires_at_ms - binding.issued_at_ms;
    assert!(
        lifetime > 30_000 && lifetime <= 60_000,
        "default offer must exceed the old 30 s cap and stay within the grant: {lifetime}"
    );
    assert!(binding.expires_at_ms <= binding.grant.expires_at_ms);
    assert_eq!(f.offer().to_json().unwrap(), offer.to_json().unwrap());
}

#[test]
fn pv06_b01_offer_lifetime_beyond_the_grant_is_still_capped_by_grant_expiry() {
    let mut f = Fixture::new("pv06-grant-cap");
    f.state.browser_offer_lifetime = std::time::Duration::from_secs(3_600);
    let offer = f.offer();
    let binding = BrowserProvisioningBinding::from_value(offer.body()).unwrap();
    assert!(binding.expires_at_ms <= binding.grant.expires_at_ms);
    assert!(binding.expires_at_ms - binding.issued_at_ms <= 180_000);
    // A shorter configured value between the old and new defaults is honoured exactly.
    let mut shorter = Fixture::new("pv06-45s");
    shorter.state.browser_offer_lifetime = std::time::Duration::from_secs(45);
    let binding = BrowserProvisioningBinding::from_value(shorter.offer().body()).unwrap();
    assert_eq!(binding.expires_at_ms - binding.issued_at_ms, 45_000);
}

const DENIED: &[u8] = b"ERR browser_provisioning_denied\n";

fn offer_event_request(grant_id: &str) -> Vec<u8> {
    format!("BROWSER_OFFER_EVENT {grant_id}\n").into_bytes()
}

/// Parse `OFFER_EVENT <len>\n<json>\n` strictly and return the JSON bytes.
fn parse_offer_event(response: &[u8]) -> Vec<u8> {
    let newline = response.iter().position(|b| *b == b'\n').unwrap();
    let header = std::str::from_utf8(&response[..newline]).unwrap();
    let length: usize = header
        .strip_prefix("OFFER_EVENT ")
        .unwrap()
        .parse()
        .unwrap();
    assert!(!header.contains("  ") && length > 0);
    let payload = response[newline + 1..].strip_suffix(b"\n").unwrap();
    assert_eq!(payload.len(), length, "declared length must match payload");
    payload.to_vec()
}

#[test]
fn pv06_b06_offer_event_is_a_broker_signed_node_event_of_the_original_offer() {
    use blindpass_core::canon::{Value, canonicalize_value, parse_json};
    let mut f = Fixture::new("pv06-offer-event");
    let event_bytes = parse_offer_event(&f.exchange(&offer_event_request(&f.grant_id.clone())));
    let event = parse_json(std::str::from_utf8(&event_bytes).unwrap()).unwrap();
    assert_eq!(
        canonicalize_value(&event).unwrap(),
        event_bytes,
        "canonical"
    );
    let fields = event.as_object().unwrap();
    let mut names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["body", "broker_signature", "idempotency_key", "kind"]
    );
    assert_eq!(
        event.get("kind").and_then(Value::as_str),
        Some("recipient_offer")
    );
    let digest = blindpass_core::custody::sha256(f.grant_id.as_bytes()).unwrap();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let key = event
        .get("idempotency_key")
        .and_then(Value::as_str)
        .unwrap();
    assert_eq!(key, format!("ro_{hex}"));
    assert_eq!(key.len(), 67);
    // The body is exactly the immutable offer the broker minted (BROWSER_OFFER).
    let offer = f.offer();
    let body = event.get("body").unwrap();
    assert_eq!(
        canonicalize_value(body).unwrap(),
        offer.to_json().unwrap(),
        "event body must be the original signed offer"
    );
    let inner =
        SignedEnvelope::from_json(std::str::from_utf8(&canonicalize_value(body).unwrap()).unwrap())
            .unwrap();
    assert_eq!(inner.kind(), DocumentKind::RecipientOffer);
    // The outer signature covers the body exactly as the controller will
    // re-canonicalise it, and verifies under the enrolled broker signing key.
    let signature = base64_url_decode(
        event
            .get("broker_signature")
            .and_then(Value::as_str)
            .unwrap(),
        64,
    )
    .unwrap();
    let message =
        blindpass_core::fleet::node_event_message("node-a", key, "recipient_offer", body).unwrap();
    let public =
        base64_url_decode(&f.identity.public_identity().unwrap().signing_public, 32).unwrap();
    assert!(blindpass_core::signing::ed25519::verify(&public, &message, &signature).unwrap());
    // A reparse of the on-wire body gives the same signed message bytes.
    let reparsed =
        parse_json(&String::from_utf8(canonicalize_value(body).unwrap()).unwrap()).unwrap();
    assert_eq!(
        blindpass_core::fleet::node_event_message("node-a", key, "recipient_offer", &reparsed)
            .unwrap(),
        message
    );
    // Exact retry is byte-identical and BROWSER_OFFER is unchanged.
    let again = parse_offer_event(&f.exchange(&offer_event_request(&f.grant_id.clone())));
    assert_eq!(again, event_bytes);
    let plain = f.exchange(format!("BROWSER_OFFER {}\n", f.grant_id).as_bytes());
    assert!(plain.starts_with(b"OFFER "));
    assert!(!plain.starts_with(b"OFFER_EVENT"));
}

#[test]
fn pv06_b06_offer_event_denies_unsafe_unknown_or_spent_grants_without_leaking() {
    let mut f = Fixture::new("pv06-offer-event-deny");
    for grant in [
        String::new(),
        "../escape".to_owned(),
        "gr with space".to_owned(),
        "g".repeat(129),
        "gr_unknown_aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "gr_0123456789abcdef0123456789abcdef".to_owned(),
    ] {
        assert_eq!(
            f.exchange(&offer_event_request(&grant)),
            DENIED,
            "{grant:?}"
        );
    }
    // Once the original private key is spent the same grant is denied and no
    // ciphertext/plaintext appears in any later control response.
    let offer = f.offer();
    let canary = b"P05-OFFER-EVENT-SOURCE-CANARY";
    let delivery = f.delivery(&offer, canary);
    let doc = f.sign(&delivery);
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .unwrap()
    );
    let response = f.exchange(&offer_event_request(&f.grant_id.clone()));
    assert_eq!(response, DENIED);
    assert!(!response.windows(canary.len()).any(|w| w == canary));
}

#[test]
fn pv06_b06_relay_refuses_provisioning_delivery_and_never_advances_the_pin_for_it() {
    let mut f = Fixture::new("pv06-relay-refuse");
    let offer = f.offer();
    let delivery = f.delivery(&offer, b"DUMMY-PV06-SOURCE");
    let doc = f.sign(&delivery);
    let mut request = format!("RELAY {}\n", doc.len()).into_bytes();
    request.extend_from_slice(&doc);
    assert_eq!(f.exchange(&request), b"ERR invalid_controller_document\n");
    // The refused relay did not spend the one-use key: the real path still admits it.
    assert!(
        f.state
            .accept_browser_provisioning(&f.identity, &doc)
            .unwrap()
    );
    // A delivery signed with a later epoch is refused before the pin is advanced.
    let pin = f.identity.pinned_issuer().unwrap().unwrap();
    let mut later = delivery.clone();
    later.binding.grant.issuer_epoch = pin.epoch + 1;
    let signed = SignedEnvelope::sign(
        DocumentKind::ProvisioningDelivery,
        later.to_value().unwrap(),
        &pin.key_id,
        pin.epoch + 1,
        &f.issuer,
    )
    .unwrap()
    .to_json()
    .unwrap();
    let mut request = format!("RELAY {}\n", signed.len()).into_bytes();
    request.extend_from_slice(&signed);
    assert_eq!(f.exchange(&request), b"ERR invalid_controller_document\n");
    assert_eq!(
        f.identity.pinned_issuer().unwrap().unwrap().epoch,
        pin.epoch
    );
}

#[test]
fn pv06_b06_provision_source_denies_other_document_kinds() {
    let mut f = Fixture::new("pv06-wrong-kind");
    let pin = f.identity.pinned_issuer().unwrap().unwrap();
    let ack = blindpass_core::fleet::ApplicationAck {
        node_id: "node-a".into(),
        issuer_epoch: pin.epoch,
        acknowledged_at_ms: 1_800_000_000_000,
        event_keys: vec!["event_aaaaaaaaaaaaaaaa".into()],
    };
    let doc = SignedEnvelope::sign(
        DocumentKind::ApplicationAck,
        ack.to_value().unwrap(),
        &pin.key_id,
        pin.epoch,
        &f.issuer,
    )
    .unwrap()
    .to_json()
    .unwrap();
    let mut request = format!("PROVISION_SOURCE {}\n", doc.len()).into_bytes();
    request.extend_from_slice(&doc);
    assert_eq!(f.exchange(&request), DENIED);
}

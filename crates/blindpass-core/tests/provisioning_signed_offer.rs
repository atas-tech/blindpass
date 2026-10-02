// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_core::canon::{Value, parse_json};
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::provisioning::{
    BrowserProvisioningBinding, sign_browser_recipient_offer, verify_browser_recipient_offer,
};
use blindpass_core::signing::ed25519::Ed25519KeyPair;
const FIXTURE: &str =
    include_str!("../../../packages/browser-ui/tests/fixtures/fleet-provisioning-v1.json");

#[test]
fn pv05_s01_native_offer_round_trip_and_fixed_destination() {
    let binding = BrowserProvisioningBinding::from_json(FIXTURE).unwrap();
    let issuer = Ed25519KeyPair::generate().unwrap();
    let signed = sign_browser_recipient_offer(&binding, &issuer).unwrap();
    assert_eq!(signed.kind(), DocumentKind::RecipientOffer);
    assert_eq!(signed.key_id(), "nd_node-a-1");
    assert_eq!(signed.epoch(), 1);
    let parsed =
        SignedEnvelope::from_json(&String::from_utf8(signed.to_json().unwrap()).unwrap()).unwrap();
    let verified = verify_browser_recipient_offer(
        &parsed,
        issuer.public_key(),
        &binding.grant,
        1,
        binding.issued_at_ms,
        &binding.source_unit,
        &binding.credential,
    )
    .unwrap();
    assert_eq!(verified, binding);
}

#[test]
fn pv05_s02_foreign_key_scope_time_kind_and_epoch_reject() {
    let binding = BrowserProvisioningBinding::from_json(FIXTURE).unwrap();
    let issuer = Ed25519KeyPair::generate().unwrap();
    let foreign = Ed25519KeyPair::generate().unwrap();
    let signed = sign_browser_recipient_offer(&binding, &issuer).unwrap();
    assert!(
        verify_browser_recipient_offer(
            &signed,
            foreign.public_key(),
            &binding.grant,
            1,
            binding.issued_at_ms,
            &binding.source_unit,
            &binding.credential
        )
        .is_err()
    );
    for (version, now, unit, credential) in [
        (
            2,
            binding.issued_at_ms,
            binding.source_unit.as_str(),
            binding.credential.as_str(),
        ),
        (
            1,
            binding.expires_at_ms,
            binding.source_unit.as_str(),
            binding.credential.as_str(),
        ),
        (
            1,
            binding.issued_at_ms - 1,
            binding.source_unit.as_str(),
            binding.credential.as_str(),
        ),
        (
            1,
            binding.issued_at_ms,
            "other.service",
            binding.credential.as_str(),
        ),
        (
            1,
            binding.issued_at_ms,
            binding.source_unit.as_str(),
            "other-credential",
        ),
    ] {
        assert!(
            verify_browser_recipient_offer(
                &signed,
                issuer.public_key(),
                &binding.grant,
                version,
                now,
                unit,
                credential
            )
            .is_err()
        );
    }
    let mut current = binding.grant.clone();
    current.operation_id = "op_foreign".to_owned();
    assert!(
        verify_browser_recipient_offer(
            &signed,
            issuer.public_key(),
            &current,
            1,
            binding.issued_at_ms,
            &binding.source_unit,
            &binding.credential
        )
        .is_err()
    );
    assert!(
        SignedEnvelope::sign(
            DocumentKind::RecipientOffer,
            binding.to_value().unwrap(),
            "nd_node-a-1",
            2,
            &issuer
        )
        .is_err()
    );
    let audit = SignedEnvelope::sign(
        DocumentKind::AuditEvent,
        binding.to_value().unwrap(),
        "nd_node-a-1",
        1,
        &issuer,
    )
    .unwrap();
    assert!(
        verify_browser_recipient_offer(
            &audit,
            issuer.public_key(),
            &binding.grant,
            1,
            binding.issued_at_ms,
            &binding.source_unit,
            &binding.credential
        )
        .is_err()
    );
}

#[test]
fn pv05_s02_body_and_signature_mutation_fail() {
    let binding = BrowserProvisioningBinding::from_json(FIXTURE).unwrap();
    let issuer = Ed25519KeyPair::generate().unwrap();
    let signed = sign_browser_recipient_offer(&binding, &issuer).unwrap();
    let json = String::from_utf8(signed.to_json().unwrap()).unwrap();
    let altered =
        SignedEnvelope::from_json(&json.replace("source-credential", "other-credential")).unwrap();
    assert!(
        verify_browser_recipient_offer(
            &altered,
            issuer.public_key(),
            &binding.grant,
            1,
            binding.issued_at_ms,
            &binding.source_unit,
            &binding.credential
        )
        .is_err()
    );
    let mut value = parse_json(&json).unwrap();
    if let Value::Object(ref mut fields) = value {
        fields.iter_mut().find(|(key, _)| key == "kid").unwrap().1 =
            Value::String("nd_foreign-1".to_owned());
    }
    let bytes = blindpass_core::canon::canonicalize_value(&value).unwrap();
    let altered = SignedEnvelope::from_json(&String::from_utf8(bytes).unwrap()).unwrap();
    assert!(
        verify_browser_recipient_offer(
            &altered,
            issuer.public_key(),
            &binding.grant,
            1,
            binding.issued_at_ms,
            &binding.source_unit,
            &binding.credential
        )
        .is_err()
    );
}

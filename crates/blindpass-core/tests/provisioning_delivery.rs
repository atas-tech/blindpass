// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_core::canon::Value;
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::fleet::{DocumentKind, SignedEnvelope};
use blindpass_core::provisioning::{BrowserProvisioningBinding, BrowserProvisioningDelivery};
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
fn delivery() -> BrowserProvisioningDelivery {
    let mut binding = BrowserProvisioningBinding::from_json(include_str!(
        "../../../packages/browser-ui/tests/fixtures/fleet-provisioning-v1.json"
    ))
    .unwrap();
    let key = RecipientKeyPair::generate().unwrap();
    binding.recipient_public = base64_url_encode(key.public_key());
    let sealed = RecipientKeyPair::seal(
        key.public_key(),
        b"DUMMY-PV06-DELIVERY",
        &binding.aad().unwrap(),
    )
    .unwrap();
    BrowserProvisioningDelivery {
        binding,
        enc: base64_url_encode(&sealed.enc),
        ciphertext: base64_url_encode(&sealed.ciphertext),
    }
}
#[test]
fn pv06_delivery_round_trip_and_original_issuer_epoch() {
    let delivery = delivery();
    let issuer = Ed25519KeyPair::generate().unwrap();
    let envelope = SignedEnvelope::sign(
        DocumentKind::ProvisioningDelivery,
        delivery.to_value().unwrap(),
        "issuer-a",
        1,
        &issuer,
    )
    .unwrap();
    let json = envelope.to_json().unwrap();
    let parsed = SignedEnvelope::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
    assert!(parsed.verify(issuer.public_key(), "issuer-a", 1).unwrap());
    assert_eq!(
        BrowserProvisioningDelivery::from_value(parsed.body()).unwrap(),
        delivery
    );
    assert!(
        SignedEnvelope::sign(
            DocumentKind::ProvisioningDelivery,
            delivery.to_value().unwrap(),
            "issuer-a",
            2,
            &issuer
        )
        .is_err()
    );
}
#[test]
fn pv06_delivery_canonical_lengths_unknown_and_duplicate_fields_reject() {
    let original = delivery();
    for variant in [
        "short-enc",
        "zero-enc",
        "empty-ciphertext",
        "oversized",
        "padded",
    ] {
        let mut changed = original.clone();
        match variant {
            "short-enc" => changed.enc = base64_url_encode(&[1; 31]),
            "zero-enc" => changed.enc = base64_url_encode(&[0; 32]),
            "empty-ciphertext" => changed.ciphertext.clear(),
            "oversized" => changed.ciphertext = base64_url_encode(&vec![1; 65_553]),
            "padded" => changed.ciphertext.push('='),
            _ => unreachable!(),
        }
        assert!(changed.to_value().is_err(), "{variant}");
    }
    for variant in ["unknown", "duplicate"] {
        let mut value = original.to_value().unwrap();
        if let Value::Object(ref mut fields) = value {
            if variant == "unknown" {
                fields.push(("rawSource".into(), Value::String("DUMMY".into())));
            } else {
                fields[2] = fields[1].clone();
            }
        }
        assert!(
            BrowserProvisioningDelivery::from_value(&value).is_err(),
            "{variant}"
        );
    }
}
#[test]
fn pv06_s08_maximum_source_delivery_needs_the_dedicated_document_cap() {
    let mut full = delivery();
    let key = RecipientKeyPair::generate().unwrap();
    full.binding.recipient_public = base64_url_encode(key.public_key());
    let source = vec![b'z'; 65_536];
    let sealed =
        RecipientKeyPair::seal(key.public_key(), &source, &full.binding.aad().unwrap()).unwrap();
    full.enc = base64_url_encode(&sealed.enc);
    full.ciphertext = base64_url_encode(&sealed.ciphertext);
    let issuer = Ed25519KeyPair::generate().unwrap();
    let envelope = SignedEnvelope::sign(
        DocumentKind::ProvisioningDelivery,
        full.to_value().unwrap(),
        "issuer-a",
        1,
        &issuer,
    )
    .unwrap();
    let size = envelope.to_json().unwrap().len();
    let cap = DocumentKind::ProvisioningDelivery.max_document_bytes();
    assert!(size > DocumentKind::Grant.max_document_bytes(), "{size}");
    assert!(size <= cap, "{size}");
    assert_eq!(cap, 131_072);
}
#[test]
fn pv06_s04_sealed_fields_validate_without_a_binding() {
    let original = delivery();
    let (enc, ciphertext) =
        BrowserProvisioningDelivery::decode_sealed(&original.enc, &original.ciphertext).unwrap();
    assert_eq!(enc.len(), 32);
    assert_eq!((enc, ciphertext), original.sealed_bytes().unwrap());
    for (enc, ciphertext) in [
        ("short", original.ciphertext.as_str()),
        (original.enc.as_str(), "invalid"),
        (original.enc.as_str(), ""),
        (original.enc.as_str(), "A=="),
        (original.enc.as_str(), &"A".repeat(100_000)),
        ("P05-OPERATOR-SOURCE-CANARY", original.ciphertext.as_str()),
    ] {
        assert!(BrowserProvisioningDelivery::decode_sealed(enc, ciphertext).is_err());
    }
}

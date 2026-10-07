// SPDX-License-Identifier: AGPL-3.0-only
//! P10 cross-workload fulfillment: terms, one-use offer, issuer-signed
//! submission, authorization/delivery/revocation documents and result events.
//! Dummy credentials only.

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::{EphemeralCustody, RecipientKeyPair};
use blindpass_core::fleet::{
    DocumentKind, SignedEnvelope, node_event_message, node_key_fingerprint,
};
use blindpass_core::fulfillment::{
    FulfillmentAuthorization, FulfillmentDelivery, FulfillmentOffer, FulfillmentParty,
    FulfillmentResult, FulfillmentRevocation, FulfillmentSide, FulfillmentTerms, ResultState,
    RevocationReason, fulfillment_aad, fulfillment_info, seal_submit, sign_offer, verify_offer,
    verify_submit,
};
use blindpass_core::signing::base64_url_encode;
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use std::time::Duration;

const NOW: u64 = 1_800_000_000_000;
const SECRET: &[u8] = b"DUMMY-P10-CREDENTIAL-0123456789";

struct Fixture {
    controller: Ed25519KeyPair,
    issuer_signing: Ed25519KeyPair,
    recipient_signing: Ed25519KeyPair,
    terms: FulfillmentTerms,
    one_use: RecipientKeyPair,
}

fn party(
    node: &str,
    workload: &str,
    unit: &str,
    credential: &str,
    signing: &Ed25519KeyPair,
    recipient: &RecipientKeyPair,
) -> FulfillmentParty {
    FulfillmentParty {
        node_id: node.into(),
        workload_id: workload.into(),
        unit: unit.into(),
        credential: credential.into(),
        registration_version: 3,
        key_version: 2,
        signing_public: base64_url_encode(signing.public_key()),
        recipient_public: base64_url_encode(recipient.public_key()),
        fingerprint: node_key_fingerprint(signing.public_key(), recipient.public_key()).unwrap(),
    }
}

fn fixture() -> Fixture {
    let controller = Ed25519KeyPair::generate().unwrap();
    let issuer_signing = Ed25519KeyPair::generate().unwrap();
    let recipient_signing = Ed25519KeyPair::generate().unwrap();
    let issuer_recipient = RecipientKeyPair::generate().unwrap();
    let recipient_recipient = RecipientKeyPair::generate().unwrap();
    let terms = FulfillmentTerms {
        fulfillment_id: "ful_0123456789abcdefABCDEF".into(),
        tenant_id: "tenant-a".into(),
        issuer: party(
            "node-issuer",
            "wl_issuer_0001",
            "issuer-app.service",
            "api-token",
            &issuer_signing,
            &issuer_recipient,
        ),
        recipient: party(
            "node-recipient",
            "wl_recipient_0001",
            "recipient-app.service",
            "api-token",
            &recipient_signing,
            &recipient_recipient,
        ),
        policy_version: 7,
        rule_id: "rule-cross-1".into(),
        approval_reference: Some("oa_0123456789abcdef".into()),
        prior_fulfillment_id: None,
        max_plaintext_bytes: 8192,
        issued_at_ms: NOW,
        expires_at_ms: NOW + 600_000,
        issuer_epoch: 4,
    };
    Fixture {
        controller,
        issuer_signing,
        recipient_signing,
        terms,
        one_use: RecipientKeyPair::generate().unwrap(),
    }
}

fn offer_for(f: &Fixture) -> FulfillmentOffer {
    FulfillmentOffer {
        fulfillment_id: f.terms.fulfillment_id.clone(),
        terms_digest: f.terms.digest_hex().unwrap(),
        offer_id: "fo_0123456789abcdefABCDEF".into(),
        node_id: f.terms.recipient.node_id.clone(),
        node_key_version: f.terms.recipient.key_version,
        recipient_public: base64_url_encode(f.one_use.public_key()),
        issued_at_ms: NOW + 1_000,
        expires_at_ms: NOW + 1_000 + 180_000,
    }
}

fn set(value: &Value, path: &[&str], replacement: Value) -> Value {
    fn walk(value: &Value, path: &[&str], replacement: &Value) -> Value {
        let Value::Object(fields) = value else {
            panic!("not an object");
        };
        let mut out = Vec::new();
        for (key, inner) in fields {
            if key == path[0] {
                if path.len() == 1 {
                    out.push((key.clone(), replacement.clone()));
                } else {
                    out.push((key.clone(), walk(inner, &path[1..], replacement)));
                }
            } else {
                out.push((key.clone(), inner.clone()));
            }
        }
        Value::Object(out)
    }
    walk(value, path, &replacement)
}

fn without(value: &Value, key: &str) -> Value {
    let Value::Object(fields) = value else {
        panic!("not an object");
    };
    Value::Object(fields.iter().filter(|(k, _)| k != key).cloned().collect())
}

fn with_extra(value: &Value, key: &str, extra: Value) -> Value {
    let Value::Object(fields) = value else {
        panic!("not an object");
    };
    let mut fields = fields.clone();
    fields.push((key.into(), extra));
    Value::Object(fields)
}

fn s(text: &str) -> Value {
    Value::String(text.into())
}

// ---------------------------------------------------------------- terms

#[test]
fn p10_c01_terms_round_trip_with_a_stable_digest() {
    let f = fixture();
    let value = f.terms.to_value().unwrap();
    assert_eq!(FulfillmentTerms::from_value(&value).unwrap(), f.terms);
    let digest = f.terms.digest_hex().unwrap();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(digest, f.terms.digest_hex().unwrap());
    // Any single changed field changes the digest.
    let mut other = f.terms.clone();
    other.policy_version += 1;
    assert_ne!(digest, other.digest_hex().unwrap());
    let mut other = f.terms.clone();
    other.recipient.workload_id = "wl_recipient_0002".into();
    assert_ne!(digest, other.digest_hex().unwrap());
}

#[test]
fn p10_c01_terms_digest_vector_is_frozen() {
    // Fixed keys make the canonical bytes, and therefore the digest, reproducible.
    let issuer_signing = Ed25519KeyPair::from_seed(&[1_u8; 32]).unwrap();
    let recipient_signing = Ed25519KeyPair::from_seed(&[2_u8; 32]).unwrap();
    let issuer_recipient = RecipientKeyPair::from_private_key(&[3_u8; 32]).unwrap();
    let recipient_recipient = RecipientKeyPair::from_private_key(&[4_u8; 32]).unwrap();
    let mut f = fixture();
    f.terms.issuer = party(
        "node-issuer",
        "wl_issuer_0001",
        "issuer-app.service",
        "api-token",
        &issuer_signing,
        &issuer_recipient,
    );
    f.terms.recipient = party(
        "node-recipient",
        "wl_recipient_0001",
        "recipient-app.service",
        "api-token",
        &recipient_signing,
        &recipient_recipient,
    );
    assert_eq!(
        f.terms.digest_hex().unwrap(),
        "5d7268aaf170d33c9388a6a85cb131b4498bcd1cbbf821ea27dc22b30e97b582"
    );
}

#[test]
fn p10_c02_terms_reject_every_malformed_or_unsafe_shape() {
    let f = fixture();
    let good = f.terms.to_value().unwrap();
    // Unknown and missing fields, including a purpose that must never be signed in.
    assert!(FulfillmentTerms::from_value(&with_extra(&good, "purpose", s("login"))).is_err());
    assert!(FulfillmentTerms::from_value(&without(&good, "rule_id")).is_err());
    assert!(
        FulfillmentTerms::from_value(&set(&good, &["issuer", "extra"], s("x"))).is_err()
            || FulfillmentTerms::from_value(&with_extra(&good, "mode_hint", s("x"))).is_err()
    );
    for mutate in [
        |t: &mut FulfillmentTerms| t.recipient.node_id = t.issuer.node_id.clone(),
        |t: &mut FulfillmentTerms| t.recipient.workload_id = t.issuer.workload_id.clone(),
        |t: &mut FulfillmentTerms| t.expires_at_ms = t.issued_at_ms,
        |t: &mut FulfillmentTerms| t.expires_at_ms = t.issued_at_ms + 600_001,
        |t: &mut FulfillmentTerms| t.max_plaintext_bytes = 0,
        |t: &mut FulfillmentTerms| t.max_plaintext_bytes = 8193,
        |t: &mut FulfillmentTerms| t.policy_version = 0,
        |t: &mut FulfillmentTerms| t.issuer_epoch = 0,
        |t: &mut FulfillmentTerms| t.issuer.key_version = 0,
        |t: &mut FulfillmentTerms| t.issuer.registration_version = 0,
        |t: &mut FulfillmentTerms| t.issuer.unit = "not-a-unit".into(),
        |t: &mut FulfillmentTerms| t.recipient.credential = ".hidden".into(),
        |t: &mut FulfillmentTerms| t.recipient.credential = "a/b".into(),
        |t: &mut FulfillmentTerms| t.issuer.fingerprint = "0".repeat(64),
        |t: &mut FulfillmentTerms| t.issuer.fingerprint = t.issuer.fingerprint.to_uppercase(),
        |t: &mut FulfillmentTerms| t.recipient.signing_public = base64_url_encode(&[0_u8; 32]),
        |t: &mut FulfillmentTerms| t.recipient.recipient_public = "short".into(),
        |t: &mut FulfillmentTerms| t.fulfillment_id = "short".into(),
        |t: &mut FulfillmentTerms| t.tenant_id = "bad tenant".into(),
        |t: &mut FulfillmentTerms| t.approval_reference = Some("bad ref".into()),
        |t: &mut FulfillmentTerms| t.prior_fulfillment_id = Some("x".into()),
    ] {
        let mut t = f.terms.clone();
        mutate(&mut t);
        assert!(t.to_value().is_err(), "must reject {t:?}");
    }
    // The boundaries themselves are accepted.
    let mut t = f.terms.clone();
    t.max_plaintext_bytes = 1;
    t.expires_at_ms = t.issued_at_ms + 1;
    assert!(t.to_value().is_ok());
}

// ---------------------------------------------------------------- offer

#[test]
fn p10_c03_offer_is_signed_by_the_recipient_node_and_bound_to_the_terms() {
    let f = fixture();
    let offer = offer_for(&f);
    let envelope = sign_offer(&offer, &f.recipient_signing).unwrap();
    assert_eq!(envelope.kind(), DocumentKind::FulfillmentOffer);
    assert_eq!(envelope.epoch(), f.terms.recipient.key_version);
    assert_eq!(envelope.key_id(), "node-recipient-2");
    let verified = verify_offer(&envelope, &f.terms, NOW + 2_000).unwrap();
    assert_eq!(verified, offer);
    // JSON round trip keeps the signature valid.
    let json = envelope.to_json().unwrap();
    let parsed = SignedEnvelope::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
    assert_eq!(verify_offer(&parsed, &f.terms, NOW + 2_000).unwrap(), offer);
}

#[test]
fn p10_c03_offer_substitution_is_refused() {
    let f = fixture();
    let offer = offer_for(&f);
    let signed = |o: &FulfillmentOffer, key: &Ed25519KeyPair| sign_offer(o, key).unwrap();
    // Signed by the issuer node or by the controller instead of the recipient node.
    assert!(verify_offer(&signed(&offer, &f.issuer_signing), &f.terms, NOW + 2_000).is_err());
    assert!(verify_offer(&signed(&offer, &f.controller), &f.terms, NOW + 2_000).is_err());
    // Another node, key version, fulfillment, digest.
    let mut other = offer.clone();
    other.node_id = "node-issuer".into();
    assert!(verify_offer(&signed(&other, &f.recipient_signing), &f.terms, NOW + 2_000).is_err());
    let mut other = offer.clone();
    other.node_key_version += 1;
    assert!(verify_offer(&signed(&other, &f.recipient_signing), &f.terms, NOW + 2_000).is_err());
    let mut other = offer.clone();
    other.fulfillment_id = "ful_other_0123456789abcdef".into();
    assert!(verify_offer(&signed(&other, &f.recipient_signing), &f.terms, NOW + 2_000).is_err());
    let mut other = offer.clone();
    other.terms_digest = "0".repeat(64);
    assert!(verify_offer(&signed(&other, &f.recipient_signing), &f.terms, NOW + 2_000).is_err());
    // A terms document with different content (rotated recipient key) never verifies it.
    let mut rotated = f.terms.clone();
    rotated.recipient.key_version += 1;
    assert!(verify_offer(&signed(&offer, &f.recipient_signing), &rotated, NOW + 2_000).is_err());
}

#[test]
fn p10_c03_offer_lifetime_and_window_are_bounded() {
    let f = fixture();
    let ok = offer_for(&f);
    let envelope = sign_offer(&ok, &f.recipient_signing).unwrap();
    assert!(
        verify_offer(&envelope, &f.terms, ok.issued_at_ms - 1).is_err(),
        "not yet valid"
    );
    assert!(
        verify_offer(&envelope, &f.terms, ok.expires_at_ms).is_err(),
        "expired"
    );
    assert!(verify_offer(&envelope, &f.terms, ok.expires_at_ms - 1).is_ok());
    let mut long = ok.clone();
    long.expires_at_ms = long.issued_at_ms + 180_001;
    assert!(sign_offer(&long, &f.recipient_signing).is_err());
    let mut outside = ok.clone();
    outside.issued_at_ms = f.terms.issued_at_ms - 1;
    outside.expires_at_ms = outside.issued_at_ms + 180_000;
    assert!(sign_offer(&outside, &f.recipient_signing).is_ok());
    assert!(
        verify_offer(
            &sign_offer(&outside, &f.recipient_signing).unwrap(),
            &f.terms,
            f.terms.issued_at_ms
        )
        .is_err(),
        "an offer that starts before the terms is refused"
    );
    let mut past_terms = ok.clone();
    past_terms.issued_at_ms = f.terms.expires_at_ms - 10;
    past_terms.expires_at_ms = f.terms.expires_at_ms + 10;
    assert!(
        verify_offer(
            &sign_offer(&past_terms, &f.recipient_signing).unwrap(),
            &f.terms,
            f.terms.expires_at_ms - 5
        )
        .is_err(),
        "an offer that outlives the terms is refused"
    );
    let mut zero = ok.clone();
    zero.recipient_public = base64_url_encode(&[0_u8; 32]);
    assert!(sign_offer(&zero, &f.recipient_signing).is_err());
}

// ------------------------------------------------- seal, open, signature

fn sealed(f: &Fixture, plaintext: &[u8]) -> (FulfillmentOffer, SignedEnvelope, SignedEnvelope) {
    let offer = offer_for(f);
    let offer_envelope = sign_offer(&offer, &f.recipient_signing).unwrap();
    let verified = verify_offer(&offer_envelope, &f.terms, NOW + 2_000).unwrap();
    let submit = seal_submit(
        &f.terms,
        &verified,
        plaintext,
        &f.issuer_signing,
        NOW + 3_000,
    )
    .unwrap();
    (offer, offer_envelope, submit)
}

#[test]
fn p10_c04_round_trip_through_one_use_custody() {
    let f = fixture();
    let offer_id = "fo_0123456789abcdefABCDEF";
    let mut custody = EphemeralCustody::new(Duration::from_secs(60));
    let public = custody.provision(offer_id).unwrap();
    let mut offer = offer_for(&f);
    offer.recipient_public = base64_url_encode(&public);
    let offer_envelope = sign_offer(&offer, &f.recipient_signing).unwrap();
    let verified = verify_offer(&offer_envelope, &f.terms, NOW + 2_000).unwrap();
    let submit_envelope =
        seal_submit(&f.terms, &verified, SECRET, &f.issuer_signing, NOW + 3_000).unwrap();
    assert_eq!(submit_envelope.kind(), DocumentKind::FulfillmentSubmit);
    assert_eq!(submit_envelope.key_id(), "node-issuer-2");
    let submit = verify_submit(&submit_envelope, &f.terms, &verified).unwrap();
    let (enc, ciphertext) = submit.sealed_bytes().unwrap();
    let plaintext = custody
        .open_once_with_info(
            &verified.offer_id,
            &enc,
            &ciphertext,
            &fulfillment_info(&f.terms).unwrap(),
            &fulfillment_aad(&verified).unwrap(),
        )
        .unwrap();
    assert_eq!(plaintext.as_bytes(), SECRET);
    // One use: the key is spent whether or not the first open succeeded.
    assert!(
        custody
            .open_once_with_info(
                &verified.offer_id,
                &enc,
                &ciphertext,
                &fulfillment_info(&f.terms).unwrap(),
                &fulfillment_aad(&verified).unwrap(),
            )
            .is_err()
    );
    // No plaintext appears in the signed submission.
    let json = submit_envelope.to_json().unwrap();
    assert!(!json.windows(SECRET.len()).any(|w| w == SECRET));
}

#[test]
fn p10_c05_decryption_is_bound_to_terms_offer_key_and_context() {
    let f = fixture();
    let mut offer = offer_for(&f);
    offer.recipient_public = base64_url_encode(f.one_use.public_key());
    let offer_envelope = sign_offer(&offer, &f.recipient_signing).unwrap();
    let verified = verify_offer(&offer_envelope, &f.terms, NOW + 2_000).unwrap();
    let submit_envelope =
        seal_submit(&f.terms, &verified, SECRET, &f.issuer_signing, NOW + 3_000).unwrap();
    let submit = verify_submit(&submit_envelope, &f.terms, &verified).unwrap();
    let (enc, ct) = submit.sealed_bytes().unwrap();
    let info = fulfillment_info(&f.terms).unwrap();
    let aad = fulfillment_aad(&verified).unwrap();
    // The right key, info and AAD open it.
    assert_eq!(
        f.one_use
            .open_with_info(&enc, &ct, &info, &aad)
            .unwrap()
            .as_bytes(),
        SECRET
    );
    // A copy opened under any other context fails: ciphertext relocation is not re-encryption.
    let mut other_terms = f.terms.clone();
    other_terms.policy_version += 1;
    assert!(
        f.one_use
            .open_with_info(&enc, &ct, &fulfillment_info(&other_terms).unwrap(), &aad)
            .is_err()
    );
    let mut other_offer = verified.clone();
    other_offer.offer_id = "fo_ffffffffffffffffffffff".into();
    assert!(
        f.one_use
            .open_with_info(&enc, &ct, &info, &fulfillment_aad(&other_offer).unwrap())
            .is_err()
    );
    assert!(
        f.one_use.open_with_info(&enc, &ct, &[], &aad).is_err(),
        "empty info"
    );
    assert!(
        f.one_use.open_with_info(&enc, &ct, &info, &[]).is_err(),
        "empty aad"
    );
    let wrong = RecipientKeyPair::generate().unwrap();
    assert!(
        wrong.open_with_info(&enc, &ct, &info, &aad).is_err(),
        "another key"
    );
    // Plain exchange-style opening (no info, legacy AAD) never succeeds.
    assert!(f.one_use.open(&enc, &ct, &aad).is_err());
    let mut flipped = ct.clone();
    flipped[0] ^= 1;
    assert!(
        f.one_use
            .open_with_info(&enc, &flipped, &info, &aad)
            .is_err()
    );
}

#[test]
fn p10_c06_submission_authenticity_is_the_issuer_node_signature() {
    let f = fixture();
    let (offer, offer_envelope, submit) = sealed(&f, SECRET);
    let verified = verify_offer(&offer_envelope, &f.terms, NOW + 2_000).unwrap();
    assert_eq!(verified, offer);
    assert!(verify_submit(&submit, &f.terms, &verified).is_ok());
    // HPKE base mode lets anyone seal to the one-use key; only the issuer signature authenticates.
    let forged_by_controller = {
        let body = submit.body().clone();
        SignedEnvelope::sign(
            DocumentKind::FulfillmentSubmit,
            body,
            "node-issuer-2",
            f.terms.issuer.key_version,
            &f.controller,
        )
        .unwrap()
    };
    assert!(verify_submit(&forged_by_controller, &f.terms, &verified).is_err());
    // A submission signed by the recipient node, or by the issuer at another key version.
    let forged_by_recipient = SignedEnvelope::sign(
        DocumentKind::FulfillmentSubmit,
        submit.body().clone(),
        "node-issuer-2",
        2,
        &f.recipient_signing,
    )
    .unwrap();
    assert!(verify_submit(&forged_by_recipient, &f.terms, &verified).is_err());
    let wrong_version = SignedEnvelope::sign(
        DocumentKind::FulfillmentSubmit,
        set(submit.body(), &["node_key_version"], Value::Unsigned(3)),
        "node-issuer-3",
        3,
        &f.issuer_signing,
    )
    .unwrap();
    assert!(verify_submit(&wrong_version, &f.terms, &verified).is_err());
    // Altered ciphertext, enc, digest or offer id are rejected even when re-signed by the issuer.
    for (field, value) in [
        ("ciphertext_digest", s(&"0".repeat(64))),
        ("offer_id", s("fo_ffffffffffffffffffffff")),
        ("terms_digest", s(&"1".repeat(64))),
        ("fulfillment_id", s("ful_other_0123456789abcdef")),
        ("node_id", s("node-recipient")),
    ] {
        let body = set(submit.body(), &[field], value);
        let resigned = SignedEnvelope::sign(
            DocumentKind::FulfillmentSubmit,
            body,
            "node-issuer-2",
            2,
            &f.issuer_signing,
        );
        if let Ok(resigned) = resigned {
            assert!(
                verify_submit(&resigned, &f.terms, &verified).is_err(),
                "field {field}"
            );
        }
    }
    let ct = submit
        .body()
        .get("ciphertext")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let mut bytes = ct.into_bytes();
    bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
    let tampered = set(
        submit.body(),
        &["ciphertext"],
        Value::String(String::from_utf8(bytes).unwrap()),
    );
    let resigned = SignedEnvelope::sign(
        DocumentKind::FulfillmentSubmit,
        tampered,
        "node-issuer-2",
        2,
        &f.issuer_signing,
    );
    if let Ok(resigned) = resigned {
        assert!(
            verify_submit(&resigned, &f.terms, &verified).is_err(),
            "digest binds bytes"
        );
    }
}

#[test]
fn p10_c07_sealing_refuses_unsafe_inputs() {
    let f = fixture();
    let offer = offer_for(&f);
    let offer_envelope = sign_offer(&offer, &f.recipient_signing).unwrap();
    let verified = verify_offer(&offer_envelope, &f.terms, NOW + 2_000).unwrap();
    let seal = |plaintext: &[u8], key: &Ed25519KeyPair, now: u64| {
        seal_submit(&f.terms, &verified, plaintext, key, now)
    };
    assert!(seal(b"", &f.issuer_signing, NOW + 3_000).is_err(), "empty");
    assert!(
        seal(&vec![b'a'; 8193], &f.issuer_signing, NOW + 3_000).is_err(),
        "over 8 KiB"
    );
    assert!(
        seal(&vec![b'a'; 8192], &f.issuer_signing, NOW + 3_000).is_ok(),
        "exactly 8 KiB"
    );
    assert!(
        seal(SECRET, &f.recipient_signing, NOW + 3_000).is_err(),
        "not the issuer key"
    );
    assert!(
        seal(SECRET, &f.issuer_signing, verified.expires_at_ms).is_err(),
        "expired offer"
    );
    assert!(
        seal(SECRET, &f.issuer_signing, verified.issued_at_ms - 1).is_err(),
        "early"
    );
    let mut small = f.terms.clone();
    small.max_plaintext_bytes = 8;
    let (digest_changed_offer, ..) = (offer.clone(), ());
    // An offer minted for other terms cannot be used with these terms.
    assert!(
        seal_submit(
            &small,
            &digest_changed_offer,
            SECRET,
            &f.issuer_signing,
            NOW + 3_000
        )
        .is_err()
    );
    let mut small_offer = offer.clone();
    small_offer.terms_digest = small.digest_hex().unwrap();
    assert!(
        seal_submit(&small, &small_offer, SECRET, &f.issuer_signing, NOW + 3_000).is_err(),
        "30 bytes exceed an 8 byte ceiling"
    );
}

// ----------------------------------------------------------- documents

#[test]
fn p10_c08_authorization_sides_carry_exactly_what_they_should() {
    let f = fixture();
    let offer_envelope = sign_offer(&offer_for(&f), &f.recipient_signing).unwrap();
    let recipient = FulfillmentAuthorization {
        side: FulfillmentSide::Recipient,
        terms: f.terms.clone(),
        offer: None,
    };
    let issuer = FulfillmentAuthorization {
        side: FulfillmentSide::Issuer,
        terms: f.terms.clone(),
        offer: Some(offer_envelope.clone()),
    };
    for (doc, kid) in [(&recipient, "ed25519-c"), (&issuer, "ed25519-c")] {
        let envelope = SignedEnvelope::sign(
            DocumentKind::FulfillmentAuthorization,
            doc.to_value().unwrap(),
            kid,
            f.terms.issuer_epoch,
            &f.controller,
        )
        .unwrap();
        let json = envelope.to_json().unwrap();
        let parsed = SignedEnvelope::from_json(std::str::from_utf8(&json).unwrap()).unwrap();
        assert!(
            parsed
                .verify(f.controller.public_key(), kid, f.terms.issuer_epoch)
                .unwrap()
        );
        assert_eq!(
            &FulfillmentAuthorization::from_value(parsed.body()).unwrap(),
            doc
        );
    }
    // The recipient never receives an offer; the issuer cannot act without one.
    let bad_recipient = FulfillmentAuthorization {
        offer: Some(offer_envelope.clone()),
        ..recipient.clone()
    };
    let bad_issuer = FulfillmentAuthorization {
        offer: None,
        ..issuer.clone()
    };
    assert!(bad_recipient.to_value().is_err());
    assert!(bad_issuer.to_value().is_err());
    // The envelope epoch must equal the terms' issuer epoch.
    assert!(
        SignedEnvelope::sign(
            DocumentKind::FulfillmentAuthorization,
            recipient.to_value().unwrap(),
            "ed25519-c",
            f.terms.issuer_epoch + 1,
            &f.controller,
        )
        .is_err()
    );
    // Unknown side, extra and missing fields.
    let good = recipient.to_value().unwrap();
    assert!(FulfillmentAuthorization::from_value(&set(&good, &["side"], s("both"))).is_err());
    assert!(FulfillmentAuthorization::from_value(&with_extra(&good, "purpose", s("x"))).is_err());
    assert!(FulfillmentAuthorization::from_value(&without(&good, "terms")).is_err());
    // An offer that is not a fulfillment_offer envelope is refused.
    let other = SignedEnvelope::sign(
        DocumentKind::Registration,
        parse_json(
            r#"{"node_id":"node-a","workload_id":"wl-a","unit":"a.service","account":"a","status":"active","consumption_mode":"file","registration_version":1,"policy_version":1,"local_ceiling_seconds":60}"#,
        )
        .unwrap(),
        "ed25519-c",
        f.terms.issuer_epoch,
        &f.controller,
    );
    if let Ok(other) = other {
        let wrong = FulfillmentAuthorization {
            side: FulfillmentSide::Issuer,
            terms: f.terms.clone(),
            offer: Some(other),
        };
        assert!(wrong.to_value().is_err());
    }
}

#[test]
fn p10_c09_delivery_binds_terms_offer_and_submission() {
    let f = fixture();
    let (_, offer_envelope, submit) = sealed(&f, SECRET);
    let delivery = FulfillmentDelivery {
        terms: f.terms.clone(),
        offer: offer_envelope.clone(),
        submit: submit.clone(),
    };
    let envelope = SignedEnvelope::sign(
        DocumentKind::FulfillmentDelivery,
        delivery.to_value().unwrap(),
        "ed25519-c",
        f.terms.issuer_epoch,
        &f.controller,
    )
    .unwrap();
    assert!(
        envelope.to_json().unwrap().len() < blindpass_core::fleet::MAX_NODE_DOCUMENT_BYTES,
        "an 8 KiB credential fits the ordinary node document cap"
    );
    let parsed = FulfillmentDelivery::from_value(envelope.body()).unwrap();
    assert_eq!(parsed, delivery);
    let (verified_offer, verified_submit) = parsed.verify(NOW + 4_000).unwrap();
    assert_eq!(verified_offer.offer_id, verified_submit.offer_id);
    // Submission from another fulfillment's offer.
    let mut other_terms = f.terms.clone();
    other_terms.fulfillment_id = "ful_other_0123456789abcdef".into();
    let mismatch = FulfillmentDelivery {
        terms: other_terms,
        ..delivery.clone()
    };
    assert!(mismatch.to_value().is_err() || mismatch.verify(NOW + 4_000).is_err());
    // Offer expired by the time of delivery.
    assert!(delivery.verify(NOW + 1_000 + 180_000).is_err());
    assert!(
        SignedEnvelope::sign(
            DocumentKind::FulfillmentDelivery,
            delivery.to_value().unwrap(),
            "ed25519-c",
            f.terms.issuer_epoch + 1,
            &f.controller,
        )
        .is_err()
    );
}

#[test]
fn p10_c10_revocation_and_result_documents() {
    let f = fixture();
    let revocation = FulfillmentRevocation {
        fulfillment_id: f.terms.fulfillment_id.clone(),
        terms_digest: f.terms.digest_hex().unwrap(),
        node_id: "node-recipient".into(),
        reason: RevocationReason::Operator,
        revoked_at_ms: NOW + 5_000,
        retain_until_ms: NOW + 5_000 + 7 * 86_400_000,
        issuer_epoch: f.terms.issuer_epoch,
    };
    let envelope = SignedEnvelope::sign(
        DocumentKind::FulfillmentRevocation,
        revocation.to_value().unwrap(),
        "ed25519-c",
        f.terms.issuer_epoch,
        &f.controller,
    )
    .unwrap();
    assert_eq!(
        FulfillmentRevocation::from_value(envelope.body()).unwrap(),
        revocation
    );
    assert!(
        SignedEnvelope::sign(
            DocumentKind::FulfillmentRevocation,
            revocation.to_value().unwrap(),
            "ed25519-c",
            f.terms.issuer_epoch + 1,
            &f.controller,
        )
        .is_err()
    );
    for reason in [
        "operator",
        "expired",
        "policy",
        "recovery",
        "feature_disabled",
        "failed",
    ] {
        let value = set(&revocation.to_value().unwrap(), &["reason"], s(reason));
        assert!(
            FulfillmentRevocation::from_value(&value).is_ok(),
            "{reason}"
        );
    }
    assert!(
        FulfillmentRevocation::from_value(&set(
            &revocation.to_value().unwrap(),
            &["reason"],
            s("because")
        ))
        .is_err()
    );
    let mut backwards = revocation.clone();
    backwards.retain_until_ms = backwards.revoked_at_ms - 1;
    assert!(backwards.to_value().is_err());

    let result = FulfillmentResult {
        fulfillment_id: f.terms.fulfillment_id.clone(),
        terms_digest: f.terms.digest_hex().unwrap(),
        side: FulfillmentSide::Recipient,
        state: ResultState::Stored,
        code: None,
        observed_at_ms: NOW + 6_000,
    };
    assert_eq!(
        FulfillmentResult::from_value(&result.to_value().unwrap()).unwrap(),
        result
    );
    // States are side-specific; the issuer cannot claim the recipient stored or consumed it.
    for (side, state, ok) in [
        (FulfillmentSide::Issuer, ResultState::Stored, false),
        (FulfillmentSide::Issuer, ResultState::Consumed, false),
        (FulfillmentSide::Issuer, ResultState::Failed, true),
        (FulfillmentSide::Recipient, ResultState::Consumed, true),
        (FulfillmentSide::Recipient, ResultState::Failed, true),
    ] {
        let mut candidate = result.clone();
        candidate.side = side;
        candidate.state = state;
        candidate.code = (state == ResultState::Failed).then(|| "source_missing".to_owned());
        assert_eq!(candidate.to_value().is_ok(), ok, "{side:?} {state:?}");
    }
    let mut failed = result.clone();
    failed.state = ResultState::Failed;
    failed.code = None;
    assert!(failed.to_value().is_err(), "a failure names its code");
    failed.code = Some("Has Spaces".into());
    assert!(failed.to_value().is_err());
    let mut stored_with_code = result.clone();
    stored_with_code.code = Some("x".into());
    assert!(stored_with_code.to_value().is_err());
}

#[test]
fn p10_c11_node_events_may_carry_the_three_fulfillment_kinds_only() {
    let body = Value::Object(vec![("a".into(), s("b"))]);
    for kind in [
        "fulfillment_offer",
        "fulfillment_submit",
        "fulfillment_result",
    ] {
        assert!(
            node_event_message("node-a", "evt_0123456789abcdef", kind, &body).is_ok(),
            "{kind}"
        );
    }
    for kind in [
        "fulfillment_delivery",
        "fulfillment_authorization",
        "fulfillment",
        "exchange",
    ] {
        assert!(
            node_event_message("node-a", "evt_0123456789abcdef", kind, &body).is_err(),
            "{kind}"
        );
    }
}

#[test]
fn p10_c12_document_kinds_are_named_and_sized() {
    for (kind, name) in [
        (
            DocumentKind::FulfillmentAuthorization,
            "fulfillment_authorization",
        ),
        (DocumentKind::FulfillmentDelivery, "fulfillment_delivery"),
        (
            DocumentKind::FulfillmentRevocation,
            "fulfillment_revocation",
        ),
        (DocumentKind::FulfillmentOffer, "fulfillment_offer"),
        (DocumentKind::FulfillmentSubmit, "fulfillment_submit"),
    ] {
        assert_eq!(kind.as_str(), name);
        assert_eq!(DocumentKind::parse(name), Some(kind));
        assert_eq!(
            kind.max_document_bytes(),
            blindpass_core::fleet::MAX_NODE_DOCUMENT_BYTES
        );
    }
}

#[test]
fn p10_c13_canonical_encoding_is_deterministic() {
    let f = fixture();
    let a = canonicalize_value(&f.terms.to_value().unwrap()).unwrap();
    let b = canonicalize_value(
        &FulfillmentTerms::from_value(&f.terms.to_value().unwrap())
            .unwrap()
            .to_value()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(a, b);
    assert!(!a.windows(7).any(|w| w == b"purpose"));
}

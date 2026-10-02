// SPDX-License-Identifier: AGPL-3.0-only
use blindpass_core::canon::canonicalize_json;
use blindpass_core::custody::{RecipientKeyPair, SealedMessage};
use blindpass_core::provisioning::BrowserProvisioningBinding;
use blindpass_core::signing::base64_url_encode;

const FIXTURE: &str =
    include_str!("../../../packages/browser-ui/tests/fixtures/fleet-provisioning-v1.json");
const DOMAIN: &[u8] = b"blindpass:fleet-browser-source:v1\0";
fn binding() -> BrowserProvisioningBinding {
    BrowserProvisioningBinding::from_json(FIXTURE).unwrap()
}

#[test]
fn pv01_canonical_original_grant_and_domain() {
    let offer = binding();
    assert_eq!(
        offer.to_json().unwrap(),
        canonicalize_json(FIXTURE).unwrap()
    );
    let mut expected = DOMAIN.to_vec();
    expected.extend_from_slice(&offer.to_json().unwrap());
    assert_eq!(offer.aad().unwrap(), expected);
    let reordered = String::from_utf8(offer.to_json().unwrap()).unwrap();
    assert_eq!(
        BrowserProvisioningBinding::from_json(&reordered).unwrap(),
        offer
    );
}

#[test]
fn pv02_schema_and_ambiguous_metadata_fail_closed() {
    for value in [
        String::new(),
        "{}".to_owned(),
        FIXTURE.replace("\"version\": 1,", "\"version\": 1, \"version\": 1,"),
        FIXTURE.replace(
            "\"version\": 1,",
            "\"version\": 1, \"password\": \"DUMMY\",",
        ),
        FIXTURE.replace("\"version\": 1", "\"version\": 2"),
        FIXTURE.replace("browser_source", "native_password"),
        FIXTURE.replace("\"node_key_version\": 1", "\"node_key_version\": 2"),
        FIXTURE.replace("source-credential", "../credential"),
        FIXTURE.replace("blindpass-login@source.service", "../source.service"),
        FIXTURE.replace("browser_session", "native_file"),
        FIXTURE.replace(
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ] {
        assert!(BrowserProvisioningBinding::from_json(&value).is_err());
    }
    assert!(BrowserProvisioningBinding::from_json(&" ".repeat(16_385)).is_err());
}

#[test]
fn pv03_original_grant_offer_deadline_and_key_version() {
    let offer = binding();
    let now = offer.issued_at_ms;
    assert!(offer.validate_against(&offer.grant, 1, now).is_ok());
    assert!(offer.validate_against(&offer.grant, 2, now).is_err());
    assert!(offer.validate_against(&offer.grant, 1, now - 1).is_err());
    assert!(
        offer
            .validate_against(&offer.grant, 1, offer.expires_at_ms)
            .is_err()
    );
    let mut changed = offer.grant.clone();
    changed.operation_id = "op_other".to_owned();
    assert!(offer.validate_against(&changed, 1, now).is_err());
    let mut extended = offer.clone();
    extended.expires_at_ms = offer.grant.expires_at_ms + 1;
    assert!(extended.aad().is_err());
    let mut future = offer.clone();
    future.issued_at_ms = offer.grant.issued_at_ms - 1;
    assert!(future.aad().is_err());
}

#[test]
fn pv04_actual_hpke_binding_authentication() {
    let recipient = RecipientKeyPair::generate().unwrap();
    let mut offer = binding();
    offer.recipient_public = base64_url_encode(recipient.public_key());
    let aad = offer.aad().unwrap();
    let sealed = RecipientKeyPair::seal(recipient.public_key(), b"DUMMY-PV-SOURCE", &aad).unwrap();
    assert_eq!(
        recipient
            .open(&sealed.enc, &sealed.ciphertext, &aad)
            .unwrap()
            .as_bytes(),
        b"DUMMY-PV-SOURCE"
    );
    assert!(
        recipient
            .open(&sealed.enc, &sealed.ciphertext, &[])
            .is_err()
    );
    for field in [
        "offer",
        "source_unit",
        "credential",
        "operation",
        "invocation",
        "resource",
    ] {
        let mut changed = offer.clone();
        match field {
            "offer" => changed.offer_id.push('x'),
            "source_unit" => changed.source_unit = "other.service".to_owned(),
            "credential" => changed.credential = "other-credential".to_owned(),
            "operation" => changed.grant.operation_id = "op_other".to_owned(),
            "invocation" => {
                changed.grant.invocation_id = "abcdef1234567890abcdef1234567890".to_owned()
            }
            _ => changed.grant.resource_id = "other-report".to_owned(),
        }
        assert!(
            recipient
                .open(&sealed.enc, &sealed.ciphertext, &changed.aad().unwrap())
                .is_err()
        );
    }
    let tampered = SealedMessage {
        enc: sealed.enc.clone(),
        ciphertext: sealed.ciphertext[..sealed.ciphertext.len() - 1].to_vec(),
    };
    assert!(
        recipient
            .open(&tampered.enc, &tampered.ciphertext, &aad)
            .is_err()
    );
}

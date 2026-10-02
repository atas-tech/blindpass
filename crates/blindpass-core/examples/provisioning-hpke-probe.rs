// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable cryptographic interoperability probe; no broker admission,
//! controller, durable custody or production service is implemented here.
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::RecipientKeyPair;
use blindpass_core::provisioning::{BrowserProvisioningBinding, sign_browser_recipient_offer};
use blindpass_core::signing::ed25519::Ed25519KeyPair;
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use std::io::{Read, Write};

fn run() -> Result<(), &'static str> {
    let recipient = RecipientKeyPair::generate().map_err(|_| "setup")?;
    let mut binding = BrowserProvisioningBinding::from_json(include_str!(
        "../../../packages/browser-ui/tests/fixtures/fleet-provisioning-v1.json"
    ))
    .map_err(|_| "setup")?;
    binding.recipient_public = base64_url_encode(recipient.public_key());
    let aad = binding.aad().map_err(|_| "setup")?;
    let signer = Ed25519KeyPair::generate().map_err(|_| "setup")?;
    let offer = sign_browser_recipient_offer(&binding, &signer).map_err(|_| "setup")?;
    let offer_json =
        String::from_utf8(offer.to_json().map_err(|_| "setup")?).map_err(|_| "setup")?;
    let expected = Value::Object(vec![
        (
            "grant".to_owned(),
            binding.grant.to_value().map_err(|_| "setup")?,
        ),
        (
            "node_key_version".to_owned(),
            Value::Unsigned(binding.node_key_version),
        ),
        (
            "source_unit".to_owned(),
            Value::String(binding.source_unit.clone()),
        ),
        (
            "credential".to_owned(),
            Value::String(binding.credential.clone()),
        ),
        (
            "signing_public".to_owned(),
            Value::String(base64_url_encode(signer.public_key())),
        ),
    ]);
    let ready = Value::Object(vec![
        (
            "binding".to_owned(),
            binding.to_value().map_err(|_| "setup")?,
        ),
        ("aad".to_owned(), Value::String(base64_url_encode(&aad))),
        (
            "offer".to_owned(),
            parse_json(&offer_json).map_err(|_| "setup")?,
        ),
        ("expected".to_owned(), expected),
    ]);
    let mut out = std::io::stdout().lock();
    out.write_all(&canonicalize_value(&ready).map_err(|_| "setup")?)
        .map_err(|_| "setup")?;
    out.write_all(b"\n").map_err(|_| "setup")?;
    out.flush().map_err(|_| "setup")?;
    let mut input = String::new();
    std::io::stdin()
        .take(128 * 1024 + 1)
        .read_to_string(&mut input)
        .map_err(|_| "setup")?;
    if input.len() > 128 * 1024 {
        return Err("envelope");
    }
    let value = parse_json(&input).map_err(|_| "setup")?;
    let fields = value.as_object().ok_or("envelope")?;
    if fields.len() != 2
        || fields
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), "enc" | "ciphertext"))
    {
        return Err("envelope");
    }
    let enc = base64_url_decode(
        value.get("enc").and_then(Value::as_str).ok_or("envelope")?,
        32,
    )
    .ok_or("envelope")?;
    let text = value
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or("envelope")?;
    let decoded_length = text.len().checked_mul(3).ok_or("envelope")? / 4;
    if !(16..=65536 + 16).contains(&decoded_length) {
        return Err("envelope");
    }
    let ct = base64_url_decode(text, decoded_length).ok_or("envelope")?;
    let plain = recipient.open(&enc, &ct, &aad).map_err(|_| "open")?;
    if plain.as_bytes() != "  DUMMY-PV-SOURCE é 漢字 🔑\n".as_bytes() {
        return Err("envelope");
    }
    out.write_all(b"PROVISIONING-HPKE-PROBE accepted\n")
        .map_err(|_| "setup")?;
    Ok(())
}
fn main() {
    if let Err(stage) = run() {
        eprintln!("PROVISIONING-HPKE-PROBE denied stage={stage}");
        std::process::exit(1);
    }
}

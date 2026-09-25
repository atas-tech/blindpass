// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::fleet::enrollment_proof_message;
use blindpass_core::secret::wipe;
use blindpass_core::signing::{base64_url_encode, ed25519::verify};
use blindpass_node::transport::HttpsTransport;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_CONTROL_SOCKET: &str = "/run/blindpass/control.sock";
const MAX_CONTROL_RESPONSE: usize = 2_048;
const NODE_PROTOCOL_VERSION: &str = "blindpass-node/1";

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-node: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug, Default)]
struct Options {
    socket: Option<PathBuf>,
    controller: Option<String>,
    issuer_fingerprint: Option<String>,
    token_stdin: bool,
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    let Some(command) = arguments.first().map(String::as_str) else {
        print_help();
        return Err("a command is required".to_owned());
    };
    if matches!(command, "--help" | "-h" | "help") {
        print_help();
        return Ok(());
    }
    let options = parse_options(command, &arguments[1..])?;
    let socket = options
        .socket
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));
    match command {
        "status" => status(&socket),
        "run" => Err(
            "node channel polling is not available until channel authentication is configured"
                .to_owned(),
        ),
        "enroll" => enroll(
            &socket,
            options
                .controller
                .as_deref()
                .ok_or("enroll requires --controller")?,
            options
                .issuer_fingerprint
                .as_deref()
                .ok_or("enroll requires --issuer-fingerprint")?,
        ),
        unknown => Err(format!("unknown command {unknown}")),
    }
}

fn parse_options(command: &str, arguments: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--socket" => {
                index += 1;
                let value = arguments.get(index).ok_or("--socket requires a path")?;
                let socket = PathBuf::from(value);
                if !socket.is_absolute() {
                    return Err("--socket path must be absolute".to_owned());
                }
                options.socket = Some(socket);
            }
            "--controller" if command == "enroll" => {
                index += 1;
                options.controller = Some(
                    arguments
                        .get(index)
                        .ok_or("--controller requires an HTTPS origin")?
                        .clone(),
                );
            }
            "--issuer-fingerprint" if command == "enroll" => {
                index += 1;
                options.issuer_fingerprint = Some(
                    arguments
                        .get(index)
                        .ok_or("--issuer-fingerprint requires a SHA-256 hex value")?
                        .clone(),
                );
            }
            "--token-stdin" if command == "enroll" => {
                options.token_stdin = true;
            }
            unknown => return Err(format!("unknown option {unknown}")),
        }
        index += 1;
    }
    if command == "enroll" && !options.token_stdin {
        return Err("enroll requires --token-stdin".to_owned());
    }
    Ok(options)
}

fn status(socket: &Path) -> Result<(), String> {
    let response = broker_request(socket, b"STATUS\n")?;
    if response != b"OK blindpass-control/1\n" {
        return Err("the local broker did not accept the status request".to_owned());
    }
    println!("broker_control=ready protocol=blindpass-control/1");
    Ok(())
}

fn enroll(socket: &Path, controller: &str, expected_fingerprint: &str) -> Result<(), String> {
    let expected_fingerprint = parse_hex_fingerprint(expected_fingerprint)?;
    let transport = HttpsTransport::new(controller)
        .map_err(|_| "controller must be a valid HTTPS origin".to_owned())?;
    let capabilities_bytes = transport
        .get_json("/api/v3/capabilities", Duration::from_secs(8))
        .map_err(|_| "could not fetch controller capabilities".to_owned())?;
    let capabilities_text = std::str::from_utf8(&capabilities_bytes)
        .map_err(|_| "controller capabilities were malformed".to_owned())?;
    let capabilities = parse_json(capabilities_text)
        .map_err(|_| "controller capabilities were malformed".to_owned())?;
    let issuer_public = string_field(&capabilities, "issuer_pub")?;
    let issuer_key_id = string_field(&capabilities, "issuer_kid")?;
    if !valid_identifier(issuer_key_id) {
        return Err("controller issuer key id is malformed".to_owned());
    }
    let issuer_epoch = capabilities
        .get("issuer_epoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch > 0)
        .ok_or("controller issuer epoch is unavailable")?;
    let issuer_public_bytes =
        decode_base64url(issuer_public, 32).ok_or("controller issuer public key is malformed")?;
    if issuer_key_id != format!("ed25519-{issuer_public}") {
        return Err("controller issuer key id does not match its public key".to_owned());
    }
    let actual_fingerprint = sha256(&issuer_public_bytes)
        .map_err(|_| "controller issuer fingerprint could not be computed")?;
    if actual_fingerprint != expected_fingerprint {
        return Err("controller issuer fingerprint did not match the operator pin".to_owned());
    }

    let identity_response = broker_request(socket, b"IDENTITY\n")?;
    let identity = parse_identity(&identity_response)?;
    let token = read_enrollment_token()?;
    let token = Sensitive(token);
    let token_text = std::str::from_utf8(&token.0)
        .map_err(|_| "enrollment token is not valid UTF-8".to_owned())?;
    if !valid_enrollment_token(token_text) {
        return Err("enrollment token format is invalid".to_owned());
    }

    let mut sign_command = b"SIGN_ENROLLMENT ".to_vec();
    sign_command.extend_from_slice(&token.0);
    sign_command.push(b'\n');
    let proof_response = broker_request(socket, &sign_command);
    wipe(&mut sign_command);
    let proof_response = match proof_response {
        Ok(response) => response,
        Err(_) => {
            return Err(
                "the broker refused to sign the enrollment proof; run enroll as root".to_owned(),
            );
        }
    };
    let proof = std::str::from_utf8(&proof_response)
        .ok()
        .and_then(|response| response.strip_prefix("PROOF "))
        .and_then(|response| response.strip_suffix('\n'))
        .filter(|proof| decode_base64url(proof, 64).is_some())
        .ok_or_else(|| "the broker returned an invalid enrollment proof".to_owned())?
        .to_owned();

    let signing_public_bytes = decode_base64url(&identity.signing_public, 32)
        .ok_or("broker signing public key is malformed")?;
    let recipient_public_bytes = decode_base64url(&identity.recipient_public, 32)
        .ok_or("broker recipient public key is malformed")?;
    let proof_bytes =
        decode_base64url(&proof, 64).ok_or("the broker returned an invalid enrollment proof")?;
    let mut proof_message =
        enrollment_proof_message(token_text, &signing_public_bytes, &recipient_public_bytes)
            .map_err(|_| "the enrollment proof request was invalid")?;
    let proof_valid = verify(&signing_public_bytes, &proof_message, &proof_bytes)
        .map_err(|_| "the broker enrollment proof could not be verified");
    wipe(&mut proof_message);
    if !proof_valid? {
        return Err("the broker returned an invalid enrollment proof".to_owned());
    }

    let mut request_body = canonicalize_value(&Value::Object(vec![
        ("token".to_owned(), Value::String(token_text.to_owned())),
        (
            "signing_pub".to_owned(),
            Value::String(identity.signing_public.clone()),
        ),
        (
            "recipient_pub".to_owned(),
            Value::String(identity.recipient_public.clone()),
        ),
        ("proof".to_owned(), Value::String(proof)),
        (
            "protocol_version".to_owned(),
            Value::String(NODE_PROTOCOL_VERSION.to_owned()),
        ),
        (
            "capabilities".to_owned(),
            Value::Object(vec![(
                "protocol_version".to_owned(),
                Value::String(NODE_PROTOCOL_VERSION.to_owned()),
            )]),
        ),
        (
            "host_facts".to_owned(),
            Value::Object(vec![
                (
                    "os".to_owned(),
                    Value::String(std::env::consts::OS.to_owned()),
                ),
                (
                    "architecture".to_owned(),
                    Value::String(std::env::consts::ARCH.to_owned()),
                ),
            ]),
        ),
    ]))
    .map_err(|_| "enrollment request could not be encoded".to_owned())?;
    let response = transport.post_public_json(
        "/api/v3/node/enroll",
        &request_body,
        Duration::from_secs(10),
    );
    wipe(&mut request_body);
    let response = response.map_err(|_| "controller rejected the enrollment request".to_owned())?;
    let response_text = std::str::from_utf8(&response)
        .map_err(|_| "controller enrollment response was malformed".to_owned())?;
    let response = parse_json(response_text)
        .map_err(|_| "controller enrollment response was malformed".to_owned())?;
    let node_id = string_field(&response, "node_id")?;
    if !valid_identifier(node_id) {
        return Err("controller enrollment response contained an invalid node id".to_owned());
    }
    let enrollment_id = string_field(&response, "enrollment_id")?;
    let accepted_fingerprint = string_field(&response, "fingerprint")?;
    let status = string_field(&response, "status")?;
    if status != "submitted" || accepted_fingerprint != identity.fingerprint {
        return Err("controller enrollment response did not match the broker identity".to_owned());
    }

    let mut pin_command =
        format!("PIN_ISSUER {node_id} {issuer_epoch} {issuer_key_id} {issuer_public}\n")
            .into_bytes();
    let pin_result = broker_request(socket, &pin_command);
    wipe(&mut pin_command);
    match pin_result.as_deref() {
        Ok(b"OK issuer_pinned\n") => {}
        _ => return Err("the broker could not persist the verified controller pin".to_owned()),
    }
    println!(
        "enrollment_id={enrollment_id} node_id={node_id} fingerprint={accepted_fingerprint} status=submitted"
    );
    Ok(())
}

#[derive(Debug)]
struct PublicIdentity {
    signing_public: String,
    recipient_public: String,
    fingerprint: String,
}

fn parse_identity(response: &[u8]) -> Result<PublicIdentity, String> {
    let response = std::str::from_utf8(response)
        .map_err(|_| "the broker returned an invalid identity".to_owned())?;
    let mut fields = response.split_whitespace();
    if fields.next() != Some("OK") || fields.next() != Some("identity/1") {
        return Err("the broker did not return its node identity".to_owned());
    }
    let values = fields
        .filter_map(|field| field.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    let signing_public = values
        .get("signing_pub")
        .copied()
        .ok_or("broker signing public key is missing")?;
    let recipient_public = values
        .get("recipient_pub")
        .copied()
        .ok_or("broker recipient public key is missing")?;
    let fingerprint = values
        .get("fingerprint")
        .copied()
        .ok_or("broker node fingerprint is missing")?;
    if decode_base64url(signing_public, 32).is_none()
        || decode_base64url(recipient_public, 32).is_none()
        || !valid_hex_fingerprint(fingerprint)
    {
        return Err("the broker returned an invalid node identity".to_owned());
    }
    Ok(PublicIdentity {
        signing_public: signing_public.to_owned(),
        recipient_public: recipient_public.to_owned(),
        fingerprint: fingerprint.to_owned(),
    })
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("controller response is missing {key}"))
}

fn broker_request(socket: &Path, request: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "could not connect to the local broker control socket".to_owned())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "could not configure the broker control timeout".to_owned())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "could not configure the broker control timeout".to_owned())?;
    stream
        .write_all(request)
        .map_err(|_| "could not send the broker control request".to_owned())?;
    let mut response = Vec::new();
    stream
        .take((MAX_CONTROL_RESPONSE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| "could not read the broker control response".to_owned())?;
    if response.len() > MAX_CONTROL_RESPONSE || !response.ends_with(b"\n") {
        return Err("the broker returned an invalid control response".to_owned());
    }
    if response.starts_with(b"ERR ") {
        return Err("the broker refused the control request".to_owned());
    }
    Ok(response)
}

fn read_enrollment_token() -> Result<Vec<u8>, String> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(258)
        .read_to_end(&mut input)
        .map_err(|_| "could not read the enrollment token from stdin".to_owned())?;
    if input.len() > 257 {
        wipe(&mut input);
        return Err("enrollment token input exceeded the size limit".to_owned());
    }
    if input.last() == Some(&b'\n') {
        input.pop();
    }
    if input.is_empty() || input.iter().any(u8::is_ascii_whitespace) {
        wipe(&mut input);
        return Err("enrollment token input must contain one token line".to_owned());
    }
    Ok(input)
}

struct Sensitive(Vec<u8>);

impl Drop for Sensitive {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn valid_enrollment_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("en_") else {
        return false;
    };
    let Some((uuid, secret)) = rest.split_once('_') else {
        return false;
    };
    uuid.len() == 36
        && secret.len() == 43
        && uuid
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        && decode_base64url(secret, 32).is_some()
}

fn parse_hex_fingerprint(value: &str) -> Result<[u8; 32], String> {
    if !valid_hex_fingerprint(value) {
        return Err("--issuer-fingerprint must be 64 lowercase SHA-256 hex characters".to_owned());
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Ok(output)
}

fn valid_hex_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid lowercase hexadecimal fingerprint".to_owned()),
    }
}

fn decode_base64url(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits > 0 && accumulator & ((1_u32 << bits) - 1) != 0 {
        return None;
    }
    (output.len() == expected_len && base64_url_encode(&output) == value).then_some(output)
}

fn print_help() {
    println!(
        "blindpass-node <run|enroll|status> [options]\n\n\
         status [--socket PATH] queries the local broker control socket.\n\
         enroll --controller HTTPS_ORIGIN --issuer-fingerprint SHA256 --token-stdin [--socket PATH]\n\
         reads the one-use token from stdin, proves broker key possession, and pins the verified issuer."
    );
}

#[cfg(test)]
mod tests {
    use super::{parse_hex_fingerprint, parse_identity, parse_options, valid_enrollment_token};
    use blindpass_core::signing::base64_url_encode;

    #[test]
    fn enrollment_cli_requires_stdin_and_operator_issuer_pin() {
        assert!(parse_options("enroll", &[]).is_err());
        let options = parse_options(
            "enroll",
            &[
                "--controller".to_owned(),
                "https://controller.example".to_owned(),
                "--issuer-fingerprint".to_owned(),
                "a".repeat(64),
                "--token-stdin".to_owned(),
            ],
        )
        .unwrap();
        assert!(options.token_stdin);
        assert!(parse_options("status", &["--token-stdin".to_owned()]).is_err());
    }

    #[test]
    fn enrollment_cli_validates_token_and_both_node_keys() {
        let token = format!(
            "en_{}_{}",
            "12345678-1234-4234-8234-123456789abc",
            "A".repeat(42) + "A"
        );
        assert!(valid_enrollment_token(&token));
        assert!(!valid_enrollment_token("en_short_bad"));
        let response = format!(
            "OK identity/1 signing_pub={} recipient_pub={} fingerprint={}\n",
            base64_url_encode(&[1; 32]),
            base64_url_encode(&[2; 32]),
            "a".repeat(64)
        );
        assert!(parse_identity(response.as_bytes()).is_ok());
        assert!(parse_identity(b"OK identity/1 signing_pub=bad\n").is_err());
    }

    #[test]
    fn issuer_fingerprint_requires_canonical_lowercase_hex() {
        assert_eq!(parse_hex_fingerprint(&"0a".repeat(32)).unwrap()[0], 10);
        assert!(parse_hex_fingerprint(&"0A".repeat(32)).is_err());
        assert!(parse_hex_fingerprint("not-a-fingerprint").is_err());
    }
}

// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::custody::sha256;
use blindpass_core::fleet::{
    enrollment_proof_message, node_key_fingerprint, node_session_challenge_message,
};
use blindpass_core::secret::wipe;
use blindpass_core::signing::{base64_url_decode, ed25519::verify};
mod outbox;
use blindpass_node::transport::{HttpsTransport, TransportError};
use outbox::{NodeEvent, Outbox};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_CONTROL_SOCKET: &str = "/run/blindpass/control.sock";
const MAX_CONTROL_RESPONSE: usize = 64 * 1024 + 64;
const NODE_PROTOCOL_VERSION: &str = "blindpass-node/1";
const DEFAULT_STATE_DIRECTORY: &str = "/var/lib/blindpass/node";
const PROTOCOL_MISMATCH_EXIT_CODE: i32 = 78;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-node: {error}");
        std::process::exit(exit_code_for_error(&error));
    }
}

fn exit_code_for_error(error: &str) -> i32 {
    if error == "controller requires an unsupported node protocol" {
        PROTOCOL_MISMATCH_EXIT_CODE
    } else {
        1
    }
}

#[derive(Debug, Default)]
struct Options {
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
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
        "rotate-prepare" => prepare_node_key_rotation(&socket),
        "run" => run_channel(
            &socket,
            options
                .state_dir
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIRECTORY)),
            options
                .controller
                .as_deref()
                .ok_or("run requires --controller")?,
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
            "--state-dir" if command == "run" => {
                index += 1;
                let value = arguments.get(index).ok_or("--state-dir requires a path")?;
                let directory = PathBuf::from(value);
                if !directory.is_absolute() {
                    return Err("--state-dir path must be absolute".to_owned());
                }
                options.state_dir = Some(directory);
            }
            "--controller" if matches!(command, "enroll" | "run") => {
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
    if command == "run" && options.controller.is_none() {
        return Err("run requires --controller".to_owned());
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

fn prepare_node_key_rotation(socket: &Path) -> Result<(), String> {
    let response = broker_request(socket, b"PREPARE_ROTATION\n").map_err(|_| {
        "the broker refused to stage new node keys; run rotate-prepare as root".to_owned()
    })?;
    let response = std::str::from_utf8(&response)
        .map_err(|_| "the broker returned malformed rotation metadata".to_owned())?;
    let mut fields = response.split_whitespace();
    if fields.next() != Some("ROTATION") {
        return Err("the broker returned malformed rotation metadata".to_owned());
    }
    let values = fields
        .filter_map(|field| field.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    if values.len() != 4 {
        return Err("the broker returned malformed rotation metadata".to_owned());
    }
    let key_version = values
        .get("key_version")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 1)
        .ok_or("the broker returned an invalid rotation version")?;
    let signing_public = values
        .get("signing_pub")
        .copied()
        .ok_or("the broker returned no rotation signing key")?;
    let recipient_public = values
        .get("recipient_pub")
        .copied()
        .ok_or("the broker returned no rotation recipient key")?;
    let fingerprint = values
        .get("fingerprint")
        .copied()
        .ok_or("the broker returned no rotation fingerprint")?;
    let signing_key = decode_base64url(signing_public, 32)
        .ok_or("the broker returned an invalid rotation signing key")?;
    let recipient_key = decode_base64url(recipient_public, 32)
        .ok_or("the broker returned an invalid rotation recipient key")?;
    if !valid_hex_fingerprint(fingerprint)
        || node_key_fingerprint(&signing_key, &recipient_key)
            .map_or(true, |expected| expected != fingerprint)
    {
        return Err("the broker returned an invalid rotation fingerprint".to_owned());
    }
    let output = canonicalize_value(&Value::Object(vec![
        (
            "fingerprint".to_owned(),
            Value::String(fingerprint.to_owned()),
        ),
        ("key_version".to_owned(), Value::Unsigned(key_version)),
        (
            "recipient_pub".to_owned(),
            Value::String(recipient_public.to_owned()),
        ),
        (
            "signing_pub".to_owned(),
            Value::String(signing_public.to_owned()),
        ),
    ]))
    .map_err(|_| "rotation metadata could not be encoded".to_owned())?;
    println!(
        "{}",
        std::str::from_utf8(&output).map_err(|_| "rotation metadata is malformed".to_owned())?
    );
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

    let tenant_id = string_field(&response, "tenant_id")?;
    if !valid_identifier(tenant_id) {
        return Err("controller enrollment response contained an invalid tenant id".to_owned());
    }
    let mut pin_command = format!(
        "PIN_ISSUER {tenant_id} {node_id} {issuer_epoch} {issuer_key_id} {issuer_public}\n"
    )
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
struct PinnedController {
    tenant_id: String,
    node_id: String,
    epoch: u64,
    key_id: String,
    public_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelError {
    ProtocolMismatch,
    Retryable,
    Fatal(&'static str),
}

fn run_channel(socket: &Path, state_dir: PathBuf, controller: &str) -> Result<(), String> {
    let transport = HttpsTransport::new(controller)
        .map_err(|_| "controller must be a valid HTTPS origin".to_owned())?;
    let mut outbox = Outbox::open(&state_dir).map_err(str::to_owned)?;
    let mut ack_seq = None;
    let mut backoff_seconds = 1_u64;
    let mut retry_stage = "starting node channel";
    loop {
        match run_channel_session(
            socket,
            &transport,
            &mut outbox,
            &mut ack_seq,
            &mut backoff_seconds,
            &mut retry_stage,
        ) {
            Ok(()) => backoff_seconds = 1,
            Err(ChannelError::ProtocolMismatch) => {
                return Err("controller requires an unsupported node protocol".to_owned());
            }
            Err(ChannelError::Fatal(reason)) => return Err(reason.to_owned()),
            Err(ChannelError::Retryable) => {
                eprintln!(
                    "node channel unavailable during {retry_stage}; retrying with bounded backoff"
                );
                sleep_with_jitter(backoff_seconds);
                backoff_seconds = next_backoff_seconds(backoff_seconds);
            }
        }
    }
}

fn run_channel_session(
    socket: &Path,
    transport: &HttpsTransport,
    outbox: &mut Outbox,
    ack_seq: &mut Option<u64>,
    backoff_seconds: &mut u64,
    retry_stage: &mut &'static str,
) -> Result<(), ChannelError> {
    *retry_stage = "reading broker issuer pin";
    let pin_response =
        broker_request(socket, b"PIN_STATUS\n").map_err(|_| ChannelError::Retryable)?;
    let pin = parse_pinned_controller(&pin_response).map_err(ChannelError::Fatal)?;
    *retry_stage = "reading broker identity";
    let identity_response =
        broker_request(socket, b"IDENTITY\n").map_err(|_| ChannelError::Retryable)?;
    let identity = parse_identity(&identity_response).map_err(|_| ChannelError::Retryable)?;
    let signing_public =
        decode_base64url(&identity.signing_public, 32).ok_or(ChannelError::Retryable)?;
    let capabilities = Value::Object(vec![(
        "protocol_version".to_owned(),
        Value::String(NODE_PROTOCOL_VERSION.to_owned()),
    )]);
    let (_capabilities_json, capabilities_hash) =
        canonical_capabilities(&capabilities).ok_or(ChannelError::Retryable)?;

    *retry_stage = "requesting controller session challenge";
    let mut challenge_request = session_request(
        &pin.node_id,
        identity.key_version,
        &capabilities,
        None,
        None,
    )
    .map_err(|_| ChannelError::Retryable)?;
    let challenge_bytes = match transport.post_public_json(
        "/api/v3/node/session",
        &challenge_request,
        Duration::from_secs(10),
    ) {
        Ok(bytes) => bytes,
        Err(TransportError::ProtocolMismatch) => return Err(ChannelError::ProtocolMismatch),
        Err(_) => {
            wipe(&mut challenge_request);
            return Err(ChannelError::Retryable);
        }
    };
    wipe(&mut challenge_request);
    let challenge_text =
        std::str::from_utf8(&challenge_bytes).map_err(|_| ChannelError::Retryable)?;
    let challenge = parse_json(challenge_text).map_err(|_| ChannelError::Retryable)?;
    let nonce = string_field(&challenge, "nonce").map_err(|_| ChannelError::Retryable)?;
    let tenant_id = string_field(&challenge, "tenant_id").map_err(|_| ChannelError::Retryable)?;
    let node_id = string_field(&challenge, "node_id").map_err(|_| ChannelError::Retryable)?;
    let issuer_public =
        string_field(&challenge, "issuer_pub").map_err(|_| ChannelError::Retryable)?;
    let issuer_key_id =
        string_field(&challenge, "issuer_kid").map_err(|_| ChannelError::Retryable)?;
    let audience = string_field(&challenge, "audience").map_err(|_| ChannelError::Retryable)?;
    let minimum_protocol =
        string_field(&challenge, "min_protocol_version").map_err(|_| ChannelError::Retryable)?;
    let response_capabilities_hash =
        string_field(&challenge, "capabilities_hash").map_err(|_| ChannelError::Retryable)?;
    let issuer_epoch = number_field(&challenge, "issuer_epoch").ok_or(ChannelError::Retryable)?;
    let key_version = number_field(&challenge, "key_version").ok_or(ChannelError::Retryable)?;
    let controller_time_ms = number_field(&challenge, "controller_time_ms")
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(ChannelError::Retryable)?;
    let expires_at_ms = number_field(&challenge, "expires_at_ms")
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(ChannelError::Retryable)?;
    if tenant_id != pin.tenant_id
        || node_id != pin.node_id
        || issuer_epoch != pin.epoch
        || key_version != identity.key_version
        || issuer_public != pin.public_key
        || issuer_key_id != pin.key_id
        || issuer_key_id != format!("ed25519-{issuer_public}")
        || audience != "blindpass-node"
        || minimum_protocol != NODE_PROTOCOL_VERSION
        || response_capabilities_hash != capabilities_hash
    {
        return Err(ChannelError::Fatal(
            "controller challenge did not match the pinned node identity",
        ));
    }
    let _nonce_bytes = decode_base64url(nonce, 32).ok_or(ChannelError::Retryable)?;
    let _issuer_public_bytes =
        decode_base64url(issuer_public, 32).ok_or(ChannelError::Retryable)?;
    *retry_stage = "signing controller session challenge";
    let mut message = node_session_challenge_message(
        tenant_id,
        node_id,
        NODE_PROTOCOL_VERSION,
        nonce,
        &capabilities_hash,
        key_version,
        issuer_epoch,
        controller_time_ms,
        expires_at_ms,
    )
    .map_err(|_| ChannelError::Retryable)?;
    let mut sign_command = format!(
        "SIGN_NODE_CHALLENGE {tenant_id} {node_id} {NODE_PROTOCOL_VERSION} {nonce} {capabilities_hash} {key_version} {issuer_epoch} {controller_time_ms} {expires_at_ms}\n"
    )
    .into_bytes();
    let signature_response = broker_request(socket, &sign_command);
    wipe(&mut sign_command);
    let signature_response = signature_response.map_err(|_| ChannelError::Retryable)?;
    let signature_text = std::str::from_utf8(&signature_response)
        .ok()
        .and_then(|value| value.strip_prefix("CHALLENGE "))
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or(ChannelError::Retryable)?;
    let signature = decode_base64url(signature_text, 64).ok_or(ChannelError::Retryable)?;
    let signature_valid = verify(&signing_public, &message, &signature);
    wipe(&mut message);
    match signature_valid {
        Ok(true) => {}
        _ => return Err(ChannelError::Retryable),
    }

    *retry_stage = "authenticating controller session";
    let mut authenticate_request = session_request(
        &pin.node_id,
        identity.key_version,
        &capabilities,
        Some(nonce),
        Some(signature_text),
    )
    .map_err(|_| ChannelError::Retryable)?;
    let token_response = match transport.post_public_json(
        "/api/v3/node/session",
        &authenticate_request,
        Duration::from_secs(10),
    ) {
        Ok(bytes) => bytes,
        Err(TransportError::ProtocolMismatch) => {
            wipe(&mut authenticate_request);
            return Err(ChannelError::ProtocolMismatch);
        }
        Err(_) => {
            wipe(&mut authenticate_request);
            return Err(ChannelError::Retryable);
        }
    };
    wipe(&mut authenticate_request);
    let mut token_response = token_response;
    let token = std::str::from_utf8(&token_response)
        .ok()
        .and_then(|text| parse_json(text).ok())
        .and_then(|document| take_string_field(document, "token"));
    wipe(&mut token_response);
    let token = Sensitive(token.ok_or(ChannelError::Retryable)?.into_bytes());
    if token.0.len() > 4_096
        || !token
            .0
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~'))
    {
        return Err(ChannelError::Retryable);
    }
    let token = std::str::from_utf8(&token.0).map_err(|_| ChannelError::Retryable)?;

    loop {
        *retry_stage = "requesting broker time challenge";
        let challenge_response =
            broker_request(socket, b"TIME_CHALLENGE\n").map_err(|_| ChannelError::Retryable)?;
        let challenge = std::str::from_utf8(&challenge_response)
            .ok()
            .and_then(|response| response.strip_prefix("TIME "))
            .and_then(|response| response.strip_suffix('\n'))
            .filter(|challenge| decode_base64url(challenge, 32).is_some())
            .ok_or(ChannelError::Retryable)?;
        let ack_value = ack_seq.map_or(Value::Null, Value::Unsigned);
        let poll_body = Value::Object(vec![
            ("ack_seq".to_owned(), ack_value),
            ("health".to_owned(), Value::Object(Vec::new())),
            (
                "time_challenge".to_owned(),
                Value::String(challenge.to_owned()),
            ),
        ]);
        let mut poll_request =
            canonicalize_value(&poll_body).map_err(|_| ChannelError::Retryable)?;
        *retry_stage = "polling controller node channel";
        let response = transport.post_json(
            "/api/v3/node/poll",
            token,
            &poll_request,
            Duration::from_secs(35),
        );
        wipe(&mut poll_request);
        let response = response.map_err(|error| {
            if error == TransportError::ProtocolMismatch {
                ChannelError::ProtocolMismatch
            } else {
                ChannelError::Retryable
            }
        })?;
        let response_text = std::str::from_utf8(&response).map_err(|_| ChannelError::Retryable)?;
        let response_value = parse_json(response_text).map_err(|_| ChannelError::Retryable)?;
        let time_reply = response_value
            .get("time_reply")
            .filter(|reply| reply.as_object().is_some())
            .ok_or(ChannelError::Retryable)?;
        *retry_stage = "applying signed controller time";
        relay_document(socket, time_reply).map_err(|_| ChannelError::Retryable)?;
        let documents = response_value
            .get("documents")
            .and_then(Value::as_array)
            .ok_or(ChannelError::Retryable)?;
        let mut previous_seq = *ack_seq;
        *retry_stage = "applying signed controller documents";
        for item in documents {
            let seq = item
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or(ChannelError::Retryable)?;
            check_inbox_sequence(ack_seq, previous_seq, seq)?;
            let envelope = item.get("envelope").ok_or(ChannelError::Retryable)?;
            relay_document(socket, envelope).map_err(|_| ChannelError::Retryable)?;
            previous_seq = Some(seq);
            *ack_seq = Some(seq);
            if envelope.get("kind").and_then(Value::as_str) == Some("node_key_rotation") {
                *retry_stage = "reconnecting with the rotated node identity";
                return Err(ChannelError::Retryable);
            }
        }
        if outbox.free_slots() > 0 {
            *retry_stage = "pulling broker event queue";
            let mut pull_request = b"PULL_EVENTS\n".to_vec();
            let pulled = broker_request(socket, &pull_request);
            wipe(&mut pull_request);
            let pulled = pulled.map_err(|_| ChannelError::Retryable)?;
            let events = parse_broker_events(&pulled).map_err(|_| ChannelError::Retryable)?;
            outbox
                .insert_batch(events)
                .map_err(|_| ChannelError::Retryable)?;
        }
        let events = outbox.first_batch(100);
        if !events.is_empty() {
            *retry_stage = "sending broker event batch";
            let event_keys = events
                .iter()
                .map(|event| event.idempotency_key.clone())
                .collect::<Vec<_>>();
            let body = Value::Object(vec![(
                "events".to_owned(),
                Value::Array(events.iter().map(NodeEvent::to_value).collect()),
            )]);
            let mut event_request =
                canonicalize_value(&body).map_err(|_| ChannelError::Retryable)?;
            let event_response = transport.post_json(
                "/api/v3/node/events",
                token,
                &event_request,
                Duration::from_secs(10),
            );
            wipe(&mut event_request);
            let event_response = event_response.map_err(|_| ChannelError::Retryable)?;
            let response_text =
                std::str::from_utf8(&event_response).map_err(|_| ChannelError::Retryable)?;
            let response_value = parse_json(response_text).map_err(|_| ChannelError::Retryable)?;
            let ack = response_value
                .get("ack")
                .filter(|ack| ack.as_object().is_some())
                .ok_or(ChannelError::Retryable)?;
            let ack_body = ack.get("body").ok_or(ChannelError::Retryable)?;
            let acknowledged_keys = ack_body
                .get("event_keys")
                .and_then(Value::as_array)
                .ok_or(ChannelError::Retryable)?
                .iter()
                .map(|key| {
                    key.as_str()
                        .map(str::to_owned)
                        .ok_or(ChannelError::Retryable)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if acknowledged_keys.is_empty()
                || acknowledged_keys
                    .iter()
                    .any(|key| !event_keys.contains(key))
            {
                return Err(ChannelError::Retryable);
            }
            *retry_stage = "applying signed application acknowledgement";
            relay_document(socket, ack).map_err(|_| ChannelError::Retryable)?;
            outbox
                .remove_acked(&acknowledged_keys)
                .map_err(|_| ChannelError::Retryable)?;
        }
        *backoff_seconds = 1;
    }
}

fn check_inbox_sequence(
    ack_seq: &mut Option<u64>,
    previous_seq: Option<u64>,
    seq: u64,
) -> Result<(), ChannelError> {
    if previous_seq.is_some_and(|previous| seq <= previous) {
        // The poll sequence is relay-controlled. Reconcile from controller
        // state rather than retaining a forged cursor across sessions.
        *ack_seq = None;
        return Err(ChannelError::Retryable);
    }
    Ok(())
}

fn relay_document(socket: &Path, envelope: &Value) -> Result<(), String> {
    let mut document = canonicalize_value(envelope)
        .map_err(|_| "controller document could not be encoded".to_owned())?;
    if document.is_empty() || document.len() > 64 * 1024 {
        wipe(&mut document);
        return Err("controller document size is invalid".to_owned());
    }
    let mut relay_request = format!("RELAY {}\n", document.len()).into_bytes();
    relay_request.extend_from_slice(&document);
    wipe(&mut document);
    let relay_response = broker_request(socket, &relay_request);
    wipe(&mut relay_request);
    let relay_response = match relay_response {
        Ok(response) => response,
        Err(_) => {
            eprintln!("node relay could not reach the local broker control socket");
            return Err("local broker control socket is unavailable".to_owned());
        }
    };
    if !broker_document_response_succeeded(&relay_response) {
        eprintln!("node relay received a broker rejection for a signed controller document");
        return Err("broker rejected the signed controller document".to_owned());
    }
    Ok(())
}

fn broker_document_response_succeeded(response: &[u8]) -> bool {
    response.starts_with(b"OK document_applied ")
        || response == b"OK document_discarded grant_expired\n"
}

fn parse_broker_events(response: &[u8]) -> Result<Vec<NodeEvent>, &'static str> {
    let newline = response
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("broker event response is malformed")?;
    let header = &response[..newline];
    let payload = &response[newline + 1..];
    let header = std::str::from_utf8(header).map_err(|_| "broker event response is malformed")?;
    let length = header
        .strip_prefix("EVENTS ")
        .ok_or("broker event response is malformed")?
        .parse::<usize>()
        .map_err(|_| "broker event response is malformed")?;
    let payload = payload
        .strip_suffix(b"\n")
        .ok_or("broker event response is malformed")?;
    if length != payload.len() || length > 64 * 1024 {
        return Err("broker event response size is invalid");
    }
    let source = std::str::from_utf8(payload).map_err(|_| "broker event response is malformed")?;
    let value = parse_json(source).map_err(|_| "broker event response is malformed")?;
    let events = value
        .as_array()
        .filter(|events| events.len() <= 100)
        .ok_or("broker event batch is malformed")?;
    events.iter().map(NodeEvent::from_value).collect()
}

fn parse_pinned_controller(response: &[u8]) -> Result<PinnedController, &'static str> {
    let response = std::str::from_utf8(response).map_err(|_| "broker issuer pin is malformed")?;
    if response == "PIN none\n" {
        return Err("broker has no pinned controller; run enrollment first");
    }
    let mut fields = response.split_whitespace();
    if fields.next() != Some("PIN") {
        return Err("broker has no pinned controller; run enrollment first");
    }
    let tenant_id = fields.next().ok_or("broker issuer pin is malformed")?;
    let node_id = fields.next().ok_or("broker issuer pin is malformed")?;
    let epoch_text = fields.next().ok_or("broker issuer pin is malformed")?;
    let key_id = fields.next().ok_or("broker issuer pin is malformed")?;
    let public_key = fields.next().ok_or("broker issuer pin is malformed")?;
    let epoch = epoch_text
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == epoch_text)
        .ok_or("broker issuer pin is malformed")?;
    if fields.next().is_some()
        || !valid_identifier(tenant_id)
        || !valid_identifier(node_id)
        || key_id != format!("ed25519-{public_key}")
        || decode_base64url(public_key, 32).is_none()
    {
        return Err("broker issuer pin is malformed");
    }
    Ok(PinnedController {
        tenant_id: tenant_id.to_owned(),
        node_id: node_id.to_owned(),
        epoch,
        key_id: key_id.to_owned(),
        public_key: public_key.to_owned(),
    })
}

fn canonical_capabilities(capabilities: &Value) -> Option<(String, String)> {
    let bytes = canonicalize_value(capabilities).ok()?;
    let text = String::from_utf8(bytes.clone()).ok()?;
    let digest = sha256(&bytes).ok()?;
    let hash = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Some((text, hash))
}

fn session_request(
    node_id: &str,
    key_version: u64,
    capabilities: &Value,
    nonce: Option<&str>,
    signature: Option<&str>,
) -> Result<Vec<u8>, &'static str> {
    let mut fields = vec![
        ("node_id".to_owned(), Value::String(node_id.to_owned())),
        ("key_version".to_owned(), Value::Unsigned(key_version)),
        (
            "protocol_version".to_owned(),
            Value::String(NODE_PROTOCOL_VERSION.to_owned()),
        ),
        ("capabilities".to_owned(), capabilities.clone()),
    ];
    if let Some(nonce) = nonce {
        fields.push(("nonce".to_owned(), Value::String(nonce.to_owned())));
    }
    if let Some(signature) = signature {
        fields.push(("signature".to_owned(), Value::String(signature.to_owned())));
    }
    canonicalize_value(&Value::Object(fields))
        .map_err(|_| "node session request could not be encoded")
}

fn number_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn sleep_with_jitter(base_seconds: u64) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    std::thread::sleep(jittered_backoff(base_seconds, nanos));
}

fn next_backoff_seconds(current: u64) -> u64 {
    current.saturating_mul(2).min(60)
}

fn jittered_backoff(base_seconds: u64, nanos: u32) -> Duration {
    let jitter_permille = 800 + (nanos % 401);
    let milliseconds = base_seconds
        .saturating_mul(1_000)
        .saturating_mul(u64::from(jitter_permille))
        / 1_000;
    Duration::from_millis(milliseconds)
}

#[derive(Debug)]
struct PublicIdentity {
    key_version: u64,
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
    let key_version = values
        .get("key_version")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or("broker node key version is missing")?;
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
        key_version,
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

fn take_string_field(value: Value, key: &str) -> Option<String> {
    let Value::Object(fields) = value else {
        return None;
    };
    fields.into_iter().find_map(|(name, value)| {
        if name == key {
            if let Value::String(value) = value {
                Some(value)
            } else {
                None
            }
        } else {
            None
        }
    })
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
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("--issuer-fingerprint must be 64 lowercase SHA-256 hex characters".to_owned());
    }
    for (index, pair) in pairs.iter().enumerate() {
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
    base64_url_decode(value, expected_len)
}

fn print_help() {
    println!(
        "blindpass-node <run|enroll|rotate-prepare|status> [options]\n\n\
         status [--socket PATH] queries the local broker control socket.\n\
         enroll --controller HTTPS_ORIGIN --issuer-fingerprint SHA256 --token-stdin [--socket PATH]\n\
         reads the one-use token from stdin, proves broker key possession, and pins the verified issuer.\n\
         rotate-prepare [--socket PATH] stages broker-owned keys and prints public rotation metadata.\n\
         run --controller HTTPS_ORIGIN [--socket PATH] [--state-dir PATH] opens the outbound authenticated node channel."
    );
}

#[cfg(test)]
mod tests {
    use super::{
        PROTOCOL_MISMATCH_EXIT_CODE, broker_document_response_succeeded, exit_code_for_error,
        jittered_backoff, next_backoff_seconds, parse_broker_events, parse_hex_fingerprint,
        parse_identity, parse_options, valid_enrollment_token,
    };
    use crate::outbox::NodeEvent;
    use blindpass_core::canon::{Value, canonicalize_value};
    use blindpass_core::signing::base64_url_encode;
    use std::path::PathBuf;

    const NODE_SYSTEMD_UNIT: &str = include_str!("../../../deploy/native/blindpass-node.service");

    #[test]
    fn protocol_mismatch_is_reported_without_a_systemd_restart_loop() {
        assert_eq!(
            exit_code_for_error("controller requires an unsupported node protocol"),
            PROTOCOL_MISMATCH_EXIT_CODE
        );
        assert_eq!(exit_code_for_error("node channel unavailable"), 1);
        assert!(
            NODE_SYSTEMD_UNIT
                .lines()
                .any(|line| line.trim() == "RestartPreventExitStatus=78")
        );
    }

    #[test]
    fn broker_discard_of_a_verified_expired_grant_advances_the_inbox() {
        assert!(broker_document_response_succeeded(
            b"OK document_applied grant\n"
        ));
        assert!(broker_document_response_succeeded(
            b"OK document_discarded grant_expired\n"
        ));
        assert!(!broker_document_response_succeeded(
            b"OK document_discarded unsupported\n"
        ));
        assert!(!broker_document_response_succeeded(
            b"ERR invalid_controller_document\n"
        ));
    }

    #[test]
    fn reconnect_backoff_grows_to_a_fixed_cap_and_has_bounded_jitter() {
        let mut interval = 1;
        let mut observed = Vec::new();
        for _ in 0..8 {
            observed.push(interval);
            interval = next_backoff_seconds(interval);
        }
        assert_eq!(observed, [1, 2, 4, 8, 16, 32, 60, 60]);

        let minimum = jittered_backoff(60, 0);
        let maximum = jittered_backoff(60, 400);
        assert_eq!(minimum.as_millis(), 48_000);
        assert_eq!(maximum.as_millis(), 72_000);
    }

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
        assert!(parse_options("run", &[]).is_err());
        assert!(
            parse_options(
                "run",
                &[
                    "--controller".to_owned(),
                    "https://controller.example".to_owned()
                ]
            )
            .is_ok()
        );
        let options = parse_options(
            "run",
            &[
                "--controller".to_owned(),
                "https://controller.example".to_owned(),
                "--state-dir".to_owned(),
                "/tmp/blindpass-node-state".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(
            options.state_dir.unwrap(),
            PathBuf::from("/tmp/blindpass-node-state")
        );
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
            "OK identity/1 key_version=1 signing_pub={} recipient_pub={} fingerprint={}\n",
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

    #[test]
    fn broker_event_frames_are_length_bounded_and_canonical_json() {
        let event = NodeEvent {
            idempotency_key: "event-key-00000001".to_owned(),
            kind: "audit".to_owned(),
            body: Value::Object(vec![(
                "action".to_owned(),
                Value::String("audit_overflow".to_owned()),
            )]),
            broker_signature: base64_url_encode(&[9; 64]),
        };
        let body = canonicalize_value(&Value::Array(vec![event.to_value()])).unwrap();
        let response = format!(
            "EVENTS {}\n{}\n",
            body.len(),
            String::from_utf8(body).unwrap()
        );
        let parsed = parse_broker_events(response.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parse_broker_events(b"EVENTS 1\n[]\n").is_err());
    }

    #[test]
    fn conflicting_transport_sequence_clears_cursor_for_reconciliation() {
        let mut ack_seq = Some(7);
        assert!(matches!(
            super::check_inbox_sequence(&mut ack_seq, Some(7), 7),
            Err(super::ChannelError::Retryable)
        ));
        assert_eq!(ack_seq, None);
        assert!(super::check_inbox_sequence(&mut ack_seq, None, 7).is_ok());
    }
}

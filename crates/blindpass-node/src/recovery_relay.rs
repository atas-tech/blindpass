// SPDX-License-Identifier: AGPL-3.0-only

//! Recovery report relay (P06 RC09-RR03). The unprivileged node moves a
//! controller-signed report request to the local broker and the broker-signed
//! page back to the recovering controller. It never signs, never edits a byte
//! either side signed, never guesses a request field and never learns a key.
//! Every error is a fixed string, so no document or identifier can reach a log.

use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::recovery::pages::{MAX_PAGE_BYTES, SignedReportRequest};
use blindpass_core::signing::{base64_url_decode, base64_url_encode};
use std::time::{Duration, Instant};

pub(crate) const REQUEST_PATH: &str = "/api/recovery/request";
pub(crate) const PAGE_PATH: &str = "/api/recovery/page";
/// The broker challenge nonce lives 30 seconds; stop before it can expire mid-page.
pub(crate) const RELAY_DEADLINE: Duration = Duration::from_secs(25);
/// Upper bound on pages in one run; the controller's own frontier ends it earlier.
const MAX_PAGES: u32 = 64;
const MAX_CHALLENGE_BYTES: usize = 4_096;
const MAX_REQUEST_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayError {
    BrokerUnavailable,
    BrokerRefused,
    MalformedBrokerFrame,
    MalformedChallenge,
    ControllerUnavailable,
    MalformedControllerReply,
    ActivationClaimed,
    TooManyPages,
    Expired,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BrokerUnavailable => "recovery relay could not reach the local broker",
            Self::BrokerRefused => "the local broker declined the recovery report",
            Self::MalformedBrokerFrame => "the local broker returned a malformed recovery frame",
            Self::MalformedChallenge => "the local broker returned a malformed recovery challenge",
            Self::ControllerUnavailable => "recovery relay could not reach the controller",
            Self::MalformedControllerReply => "the controller returned a malformed recovery reply",
            Self::ActivationClaimed => {
                "the controller claimed activation, which recovery never grants"
            }
            Self::TooManyPages => "recovery relay stopped after its page limit",
            Self::Expired => "the broker recovery challenge expired; request a fresh reservation",
        })
    }
}

/// One bounded exchange with the local broker control socket.
pub(crate) trait Broker {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, RelayError>;
}

/// One public POST to the recovering controller, never any other path.
pub(crate) trait Controller {
    fn post(&self, path: &'static str, body: &[u8]) -> Result<Vec<u8>, RelayError>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) state: &'static str,
    pub(crate) pages: u32,
}

/// Payload of a `TAG <length>\n<bytes>` frame. Exactly `length` bytes follow;
/// a trailing newline is neither required nor allowed.
pub(crate) fn parse_frame<'a>(response: &'a [u8], tag: &str, maximum: usize) -> Option<&'a [u8]> {
    let newline = response.iter().position(|byte| *byte == b'\n')?;
    let digits = std::str::from_utf8(&response[..newline])
        .ok()?
        .strip_prefix(tag)?
        .strip_prefix(' ')?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: usize = digits.parse().ok()?;
    let payload = &response[newline + 1..];
    (length <= maximum && payload.len() == length).then_some(payload)
}

fn opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// The minimal controller request built only from fields the broker issued.
pub(crate) fn challenge_metadata(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_CHALLENGE_BYTES {
        return None;
    }
    let value = parse_json(std::str::from_utf8(payload).ok()?).ok()?;
    let fields = value.as_object()?;
    const EXPECTED: [&str; 7] = [
        "broker_challenge",
        "issuer_key_id",
        "node_id",
        "node_key_version",
        "observed_issuer_epoch",
        "tenant_id",
        "version",
    ];
    // Exactly the broker's fields, each once; nothing else is ever forwarded.
    if fields.len() != EXPECTED.len()
        || !EXPECTED
            .iter()
            .all(|name| fields.iter().filter(|(key, _)| key == name).count() == 1)
    {
        return None;
    }
    let text = |name: &str| value.get(name).and_then(Value::as_str);
    let unsigned = |name: &str| match value.get(name) {
        Some(Value::Unsigned(number)) => Some(*number),
        _ => None,
    };
    let nonce = text("broker_challenge")?;
    let node_id = text("node_id")?;
    if unsigned("version") != Some(1)
        || !base64_url_decode(nonce, 32).is_some_and(|bytes| base64_url_encode(&bytes) == nonce)
        || !opaque(node_id)
        || !opaque(text("tenant_id")?)
        || !opaque(text("issuer_key_id")?)
        || unsigned("observed_issuer_epoch").is_none()
    {
        return None;
    }
    let key_version = unsigned("node_key_version").filter(|version| *version > 0)?;
    canonicalize_value(&Value::Object(vec![
        ("version".into(), Value::Unsigned(1)),
        ("node_id".into(), Value::String(node_id.to_owned())),
        ("node_key_version".into(), Value::Unsigned(key_version)),
        ("broker_challenge".into(), Value::String(nonce.to_owned())),
    ]))
    .ok()
}

/// What the controller said about the collection, never trusted to claim activation.
fn parse_status(reply: &[u8]) -> Result<&'static str, RelayError> {
    let value = std::str::from_utf8(reply)
        .ok()
        .and_then(|text| parse_json(text).ok())
        .ok_or(RelayError::MalformedControllerReply)?;
    let fields = value
        .as_object()
        .ok_or(RelayError::MalformedControllerReply)?;
    if !fields.iter().any(|(key, _)| key == "state") {
        return Err(RelayError::MalformedControllerReply);
    }
    match value.get("activation_permitted") {
        Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => return Err(RelayError::ActivationClaimed),
        _ => return Err(RelayError::MalformedControllerReply),
    }
    if !matches!(value.get("version"), Some(Value::Unsigned(1))) {
        return Err(RelayError::MalformedControllerReply);
    }
    match value.get("state").and_then(Value::as_str) {
        Some("collecting") => Ok("collecting"),
        Some("covered") => Ok("covered"),
        Some("incomplete") => Ok("incomplete"),
        Some("rebase_required") => Ok("rebase_required"),
        _ => Err(RelayError::MalformedControllerReply),
    }
}

pub(crate) fn relay(
    broker: &dyn Broker,
    controller: &dyn Controller,
    deadline: Duration,
) -> Result<Outcome, RelayError> {
    let started = Instant::now();
    let alive = |started: &Instant| {
        if started.elapsed() >= deadline {
            Err(RelayError::Expired)
        } else {
            Ok(())
        }
    };
    alive(&started)?;
    let frame = broker.exchange(b"RECOVERY_CHALLENGE\n")?;
    let challenge = parse_frame(&frame, "RECOVERY_CHALLENGE", MAX_CHALLENGE_BYTES)
        .ok_or(RelayError::MalformedBrokerFrame)?;
    let metadata = challenge_metadata(challenge).ok_or(RelayError::MalformedChallenge)?;
    for pages in 1..=MAX_PAGES {
        alive(&started)?;
        let reply = controller.post(REQUEST_PATH, &metadata)?;
        // A typed controller-signed request is forwarded byte for byte; any other
        // reply must be a terminal status.
        let signed = reply.len() <= MAX_REQUEST_BYTES
            && std::str::from_utf8(&reply)
                .ok()
                .is_some_and(|text| SignedReportRequest::from_json(text).is_ok());
        if !signed {
            return Ok(Outcome {
                state: terminal(parse_status(&reply)?)?,
                pages: pages - 1,
            });
        }
        alive(&started)?;
        let mut command = format!("RECOVERY_REPORT {}\n", reply.len()).into_bytes();
        command.extend_from_slice(&reply);
        let frame = broker.exchange(&command)?;
        let page = parse_frame(&frame, "RECOVERY_REPORT", MAX_PAGE_BYTES)
            .ok_or(RelayError::MalformedBrokerFrame)?;
        alive(&started)?;
        let state = parse_status(&controller.post(PAGE_PATH, page)?)?;
        if state != "collecting" {
            return Ok(Outcome { state, pages });
        }
    }
    Err(RelayError::TooManyPages)
}

/// A request answered with a status means collection already ended.
fn terminal(state: &'static str) -> Result<&'static str, RelayError> {
    if state == "collecting" {
        Err(RelayError::MalformedControllerReply)
    } else {
        Ok(state)
    }
}

/// The local broker control socket. The broker checks the peer; the node only
/// sends a bounded request and reads a bounded answer (no newline required).
pub(crate) struct ControlSocket<'a>(pub(crate) &'a std::path::Path);

impl Broker for ControlSocket<'_> {
    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, RelayError> {
        use std::io::{Read, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(self.0)
            .map_err(|_| RelayError::BrokerUnavailable)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(3))))
            .and_then(|()| stream.write_all(request))
            .map_err(|_| RelayError::BrokerUnavailable)?;
        let mut response = Vec::new();
        let limit = MAX_PAGE_BYTES + 64;
        (&mut stream)
            .take((limit + 1) as u64)
            .read_to_end(&mut response)
            .map_err(|_| RelayError::BrokerUnavailable)?;
        if response.len() > limit {
            blindpass_core::secret::wipe(&mut response);
            return Err(RelayError::MalformedBrokerFrame);
        }
        if response.starts_with(b"ERR ") {
            return Err(RelayError::BrokerRefused);
        }
        Ok(response)
    }
}

/// Verified HTTPS to the recovering controller through the shared transport.
pub(crate) struct HttpsController(pub(crate) blindpass_node::transport::HttpsTransport);

impl Controller for HttpsController {
    fn post(&self, path: &'static str, body: &[u8]) -> Result<Vec<u8>, RelayError> {
        self.0
            .post_recovery_json(path, body, Duration::from_secs(10))
            .map_err(|_| RelayError::ControllerUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindpass_core::recovery::pages::MAX_PAGE_BYTES as PAGE_LIMIT;
    use std::cell::RefCell;

    fn nonce() -> String {
        base64_url_encode(&[7; 32])
    }
    fn challenge_json() -> String {
        format!(
            r#"{{"broker_challenge":"{}","issuer_key_id":"ed25519-K","node_id":"P06_DUMMY_NODE","node_key_version":1,"observed_issuer_epoch":7,"tenant_id":"P06_DUMMY_TENANT","version":1}}"#,
            nonce()
        )
    }
    fn frame(tag: &str, payload: &str) -> Vec<u8> {
        let mut bytes = format!("{tag} {}\n", payload.len()).into_bytes();
        bytes.extend_from_slice(payload.as_bytes());
        bytes
    }

    #[test]
    fn p06_rr03_frames_are_bounded_binary_length_and_need_no_trailing_newline() {
        assert_eq!(
            parse_frame(b"RECOVERY_CHALLENGE 2\n{}", "RECOVERY_CHALLENGE", 64),
            Some(&b"{}"[..])
        );
        for bad in [
            &b"RECOVERY_CHALLENGE 2\n{}\n"[..], // trailing byte
            b"RECOVERY_CHALLENGE 3\n{}",        // short
            b"RECOVERY_CHALLENGE 02\n{}",       // leading zero
            b"RECOVERY_CHALLENGE +2\n{}",
            b"RECOVERY_CHALLENGE 2 \n{}",
            b"RECOVERY_REPORT 2\n{}",   // wrong tag
            b"RECOVERY_CHALLENGE 65\n", // over the bound
            b"RECOVERY_CHALLENGE \n",
            b"RECOVERY_CHALLENGE 2{}", // no newline
            b"ERR recovery_report_denied\n",
        ] {
            assert_eq!(parse_frame(bad, "RECOVERY_CHALLENGE", 64), None, "{bad:?}");
        }
    }

    #[test]
    fn p06_rr03_the_controller_request_is_projected_only_from_broker_issued_fields() {
        let metadata = challenge_metadata(challenge_json().as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(metadata).unwrap(),
            format!(
                r#"{{"broker_challenge":"{}","node_id":"P06_DUMMY_NODE","node_key_version":1,"version":1}}"#,
                nonce()
            )
        );
        let good = challenge_json();
        for bad in [
            good.replace(r#""version":1"#, r#""version":2"#),
            good.replace(&nonce(), "short"),
            good.replace(&nonce(), &format!("{}=", nonce())),
            good.replace(r#""node_key_version":1"#, r#""node_key_version":"1""#),
            good.replace(r#""node_id":"P06_DUMMY_NODE""#, r#""node_id":"bad id""#),
            good.replace(r#""tenant_id":"P06_DUMMY_TENANT","#, ""),
            good.replace("}", r#","extra":1}"#),
            good.replace(
                r#""node_key_version":1"#,
                r#""node_key_version":1,"node_key_version":2"#,
            ),
            String::new(),
            "[]".into(),
        ] {
            assert!(challenge_metadata(bad.as_bytes()).is_none(), "{bad}");
        }
    }

    struct FakeBroker {
        replies: RefCell<Vec<Vec<u8>>>,
        seen: RefCell<Vec<Vec<u8>>>,
    }
    impl Broker for FakeBroker {
        fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, RelayError> {
            self.seen.borrow_mut().push(request.to_vec());
            let mut replies = self.replies.borrow_mut();
            if replies.is_empty() {
                return Err(RelayError::BrokerUnavailable);
            }
            let reply = replies.remove(0);
            if reply.starts_with(b"ERR ") {
                return Err(RelayError::BrokerRefused);
            }
            Ok(reply)
        }
    }
    struct FakeController {
        replies: RefCell<Vec<Vec<u8>>>,
        seen: RefCell<Vec<(&'static str, Vec<u8>)>>,
    }
    impl Controller for FakeController {
        fn post(&self, path: &'static str, body: &[u8]) -> Result<Vec<u8>, RelayError> {
            self.seen.borrow_mut().push((path, body.to_vec()));
            let mut replies = self.replies.borrow_mut();
            if replies.is_empty() {
                return Err(RelayError::ControllerUnavailable);
            }
            Ok(replies.remove(0))
        }
    }
    fn broker(replies: Vec<Vec<u8>>) -> FakeBroker {
        FakeBroker {
            replies: RefCell::new(replies),
            seen: RefCell::new(Vec::new()),
        }
    }
    fn controller(replies: Vec<Vec<u8>>) -> FakeController {
        FakeController {
            replies: RefCell::new(replies),
            seen: RefCell::new(Vec::new()),
        }
    }
    fn status(state: &str, next: u64) -> Vec<u8> {
        format!(r#"{{"activation_permitted":false,"application":null,"next_page":{next},"state":"{state}","version":1}}"#).into_bytes()
    }
    // Any bytes that parse as a typed signed request are forwarded unchanged; the
    // fixtures below build a real one with fixed dummy keys.
    fn signed_request(page: u64) -> Vec<u8> {
        crate::recovery_relay::tests_support::signed_request(page)
    }

    #[test]
    fn p06_rr03_signed_bytes_cross_the_relay_unchanged_over_the_two_allowed_paths_only() {
        let request_one = signed_request(0);
        let request_two = signed_request(1);
        let page_one = br#"{"body":{"page":0},"broker_signature":"AAAA"}"#.to_vec();
        let page_two = br#"{"body":{"page":1},"broker_signature":"BBBB"}"#.to_vec();
        let b = broker(vec![
            frame("RECOVERY_CHALLENGE", &challenge_json()),
            frame("RECOVERY_REPORT", std::str::from_utf8(&page_one).unwrap()),
            frame("RECOVERY_REPORT", std::str::from_utf8(&page_two).unwrap()),
        ]);
        let c = controller(vec![
            request_one.clone(),
            status("collecting", 1),
            request_two.clone(),
            status("covered", 2),
        ]);
        let outcome = relay(&b, &c, Duration::from_secs(25)).unwrap();
        assert_eq!(
            outcome,
            Outcome {
                state: "covered",
                pages: 2
            }
        );
        let seen = c.seen.borrow();
        assert_eq!(seen.len(), 4);
        for (index, (path, _)) in seen.iter().enumerate() {
            assert_eq!(
                *path,
                if index % 2 == 0 {
                    REQUEST_PATH
                } else {
                    PAGE_PATH
                }
            );
        }
        // The node sent the exact broker bytes to the controller and the exact
        // controller bytes to the broker.
        assert_eq!(seen[1].1, page_one);
        assert_eq!(seen[3].1, page_two);
        let sent = b.seen.borrow();
        assert_eq!(sent[0], b"RECOVERY_CHALLENGE\n");
        let mut expected = format!("RECOVERY_REPORT {}\n", request_one.len()).into_bytes();
        expected.extend_from_slice(&request_one);
        assert_eq!(sent[1], expected);
        // Both page requests carry the same broker-issued metadata, byte for byte.
        assert_eq!(seen[0].1, seen[2].1);
    }

    #[test]
    fn p06_rr03_refusals_stop_the_relay_without_guessing_or_continuing() {
        // Broker declines the report.
        let b = broker(vec![
            frame("RECOVERY_CHALLENGE", &challenge_json()),
            b"ERR recovery_report_denied\n".to_vec(),
        ]);
        let c = controller(vec![signed_request(0)]);
        assert_eq!(
            relay(&b, &c, Duration::from_secs(25)),
            Err(RelayError::BrokerRefused)
        );
        assert_eq!(c.seen.borrow().len(), 1);
        // Controller answers with junk instead of a typed request or a status.
        for junk in [
            b"{}".to_vec(),
            b"not json".to_vec(),
            br#"{"version":1,"state":"bogus","activation_permitted":false}"#.to_vec(),
            vec![b'x'; 5000],
        ] {
            let b = broker(vec![frame("RECOVERY_CHALLENGE", &challenge_json())]);
            let c = controller(vec![junk]);
            assert_eq!(
                relay(&b, &c, Duration::from_secs(25)),
                Err(RelayError::MalformedControllerReply)
            );
            assert_eq!(b.seen.borrow().len(), 1, "junk must never reach the broker");
        }
        // A claimed activation is refused outright.
        let b = broker(vec![frame("RECOVERY_CHALLENGE", &challenge_json())]);
        let c = controller(vec![br#"{"activation_permitted":true,"application":null,"next_page":0,"state":"covered","version":1}"#.to_vec()]);
        assert_eq!(
            relay(&b, &c, Duration::from_secs(25)),
            Err(RelayError::ActivationClaimed)
        );
        // Malformed broker challenge never reaches the controller.
        let b = broker(vec![frame("RECOVERY_CHALLENGE", "{}")]);
        let c = controller(vec![]);
        assert_eq!(
            relay(&b, &c, Duration::from_secs(25)),
            Err(RelayError::MalformedChallenge)
        );
        assert!(c.seen.borrow().is_empty());
        // An expired window stops before any further step.
        let b = broker(vec![frame("RECOVERY_CHALLENGE", &challenge_json())]);
        let c = controller(vec![signed_request(0)]);
        assert_eq!(relay(&b, &c, Duration::ZERO), Err(RelayError::Expired));
        assert!(c.seen.borrow().is_empty());
        // A controller that never finishes cannot loop the node.
        let replies: Vec<Vec<u8>> = (0..200)
            .flat_map(|i| vec![signed_request(i), status("collecting", i + 1)])
            .collect();
        let pages: Vec<Vec<u8>> = (0..200)
            .map(|_| {
                frame(
                    "RECOVERY_REPORT",
                    r#"{"body":{},"broker_signature":"AAAA"}"#,
                )
            })
            .collect();
        let mut broker_replies = vec![frame("RECOVERY_CHALLENGE", &challenge_json())];
        broker_replies.extend(pages);
        let (b, c) = (broker(broker_replies), controller(replies));
        assert_eq!(
            relay(&b, &c, Duration::from_secs(25)),
            Err(RelayError::TooManyPages)
        );
    }

    fn serve_once(reply: Vec<u8>) -> (std::path::PathBuf, std::thread::JoinHandle<Vec<u8>>) {
        use std::io::{Read, Write};
        let path = std::env::temp_dir().join(format!(
            "bp-rr03-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = vec![0_u8; 8192];
            let read = stream.read(&mut request).unwrap_or(0);
            request.truncate(read);
            let _ = stream.write_all(&reply);
            request
        });
        (path, handle)
    }

    #[test]
    fn p06_rr03_the_control_socket_client_reads_binary_length_frames_without_a_trailing_newline() {
        let payload = challenge_json();
        let (path, server) = serve_once(frame("RECOVERY_CHALLENGE", &payload));
        let reply = ControlSocket(&path)
            .exchange(b"RECOVERY_CHALLENGE\n")
            .unwrap();
        assert_eq!(server.join().unwrap(), b"RECOVERY_CHALLENGE\n");
        assert_eq!(
            parse_frame(&reply, "RECOVERY_CHALLENGE", 4096),
            Some(payload.as_bytes())
        );
        let _ = std::fs::remove_file(path);
        // An explicit refusal is a decision, not a transport fault.
        let (path, server) = serve_once(b"ERR recovery_report_denied\n".to_vec());
        assert_eq!(
            ControlSocket(&path).exchange(b"RECOVERY_CHALLENGE\n"),
            Err(RelayError::BrokerRefused)
        );
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
        // A frame past the bound is refused rather than buffered.
        let (path, server) = serve_once(vec![b'x'; PAGE_LIMIT + 1024]);
        assert_eq!(
            ControlSocket(&path).exchange(b"RECOVERY_CHALLENGE\n"),
            Err(RelayError::MalformedBrokerFrame)
        );
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
        // No broker at the path.
        assert_eq!(
            ControlSocket(std::path::Path::new("/nonexistent/bp-rr03.sock")).exchange(b"X"),
            Err(RelayError::BrokerUnavailable)
        );
    }

    #[test]
    fn p06_rr04_a_failed_https_exchange_fails_closed_without_any_plaintext_fallback() {
        // Nothing listens here and the scheme is never downgraded: the request
        // fails, the relay stops, and no later step is attempted.
        let transport =
            blindpass_node::transport::HttpsTransport::new("https://127.0.0.1:1").unwrap();
        let controller = HttpsController(transport);
        assert_eq!(
            controller.post(REQUEST_PATH, br#"{"version":1}"#),
            Err(RelayError::ControllerUnavailable)
        );
        assert!(blindpass_node::transport::HttpsTransport::new("http://127.0.0.1:1").is_err());
        let b = broker(vec![frame("RECOVERY_CHALLENGE", &challenge_json())]);
        assert_eq!(
            relay(&b, &controller, Duration::from_secs(25)),
            Err(RelayError::ControllerUnavailable)
        );
        assert_eq!(b.seen.borrow().len(), 1, "no broker report was attempted");
    }

    #[test]
    fn p06_rr03_a_partial_or_oversized_page_frame_never_reaches_the_controller() {
        let page = r#"{"body":{},"broker_signature":"AAAA"}"#;
        let mut partial = frame("RECOVERY_REPORT", page);
        partial.truncate(partial.len() - 4);
        for broken in [
            partial,
            frame("RECOVERY_REPORT", &"x".repeat(PAGE_LIMIT + 1)),
        ] {
            let b = broker(vec![frame("RECOVERY_CHALLENGE", &challenge_json()), broken]);
            let c = controller(vec![signed_request(0)]);
            assert_eq!(
                relay(&b, &c, Duration::from_secs(25)),
                Err(RelayError::MalformedBrokerFrame)
            );
            assert_eq!(
                c.seen.borrow().len(),
                1,
                "only the request metadata was sent"
            );
        }
    }

    #[test]
    fn p06_rr03_errors_are_fixed_strings_that_carry_no_document_or_identifier() {
        for error in [
            RelayError::BrokerUnavailable,
            RelayError::BrokerRefused,
            RelayError::MalformedBrokerFrame,
            RelayError::MalformedChallenge,
            RelayError::ControllerUnavailable,
            RelayError::MalformedControllerReply,
            RelayError::ActivationClaimed,
            RelayError::TooManyPages,
            RelayError::Expired,
        ] {
            let text = error.to_string();
            assert!(
                !text.contains("P06_DUMMY") && !text.contains("ed25519") && !text.contains('{')
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use blindpass_core::canon::canonicalize_value;
    use blindpass_core::recovery::pages::{ReportIdentity, ReportRequest, SignedReportRequest};
    use blindpass_core::signing::{base64_url_encode, ed25519::Ed25519KeyPair};

    /// A real controller-signed report request (fixed dummy key) for relay tests.
    pub(crate) fn signed_request(page: u64) -> Vec<u8> {
        let key = Ed25519KeyPair::from_seed(&[71; 32]).unwrap();
        let identity = ReportIdentity {
            tenant_id: "P06_DUMMY_TENANT".into(),
            node_id: "P06_DUMMY_NODE".into(),
            node_key_version: 1,
            issuer_key_id: format!("ed25519-{}", base64_url_encode(key.public_key())),
            recovery_id: "P06_DUMMY_RESTORE".into(),
            recovery_generation: 8,
            challenge: base64_url_encode(&[9; 32]),
        };
        let request = ReportRequest {
            identity,
            broker_challenge: base64_url_encode(&[7; 32]),
            report_id: (page > 0).then(|| base64_url_encode(&[5; 32])),
            page_index: page,
        };
        let signed = SignedReportRequest::sign(request, &key).unwrap();
        canonicalize_value(&signed.to_value().unwrap()).unwrap()
    }
}

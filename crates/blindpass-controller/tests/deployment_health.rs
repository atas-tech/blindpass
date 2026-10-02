// SPDX-License-Identifier: AGPL-3.0-only
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn probe(response: &[u8], stall: bool) -> std::process::Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response = response.to_vec();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = [0u8; 1024];
                let n = stream.read(&mut request).unwrap();
                assert!(request[..n].starts_with(b"GET /readyz HTTP/1.1\r\n"));
                assert!(!request[..n].windows(8).any(|window| window == b"P06-DUMM"));
                if stall {
                    thread::sleep(Duration::from_secs(2));
                } else {
                    let _ = stream.write_all(&response);
                }
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .env("BLINDPASS_LISTEN", address.to_string())
        .env("BLINDPASS_ROOT_SECRET", "P06-DUMMY-MUST-NOT-BE-READ")
        .arg("healthcheck")
        .output()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    server.join().unwrap();
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("P06-DUMMY"));
    output
}

#[test]
fn p06_h01_healthcheck_uses_only_loopback_readiness_without_key_config() {
    assert!(probe(b"HTTP/1.1 200 OK\r\nContent-Length: 38\r\n\r\n{\"ok\":true,\"checks\":{\"database\":\"up\"}}",false).status.success());
}

#[test]
fn p06_h02_false_redirect_malformed_oversized_and_stalled_readiness_fail() {
    for response in [
        b"HTTP/1.1 503 Service Unavailable\r\n\r\n{\"ok\":true}".as_slice(),
        b"HTTP/1.1 302 Found\r\nLocation: https://P06-DUMMY\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":false}",
        b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}",
        b"HTTP/1.1 200 OK\r\n\r\nP06-DUMMY-CANARY",
    ] {
        assert!(!probe(response, false).status.success());
    }
    for body in [
        r#"{"ok":false,"checks":{"database":"up"}}"#,
        r#"{"ok":true,"checks":{"database":"down"}}"#,
        r#"{"ok":true,"checks":{"database":"ok"}}"#,
        r#"{"ok":true}"#,
    ] {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert!(!probe(response.as_bytes(), false).status.success());
    }
    assert!(!probe(&vec![b'X'; 20000], false).status.success());
    assert!(!probe(b"", true).status.success());
}

#[test]
fn p06_h02_unavailable_listener_has_bounded_fixed_diagnostic() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_blindpass-controller"))
        .env_clear()
        .env("BLINDPASS_LISTEN", address.to_string())
        .arg("healthcheck")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"blindpass-controller: readiness probe failed\n"
    );
}

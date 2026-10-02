// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use blindpass_controller::{app::build_app, config::Config};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use support::{HttpResponse, TestDirectory};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Fixture {
    _directory: TestDirectory,
    values: BTreeMap<String, String>,
}

impl Fixture {
    fn new() -> Self {
        let directory = TestDirectory::new();
        let mut values = BTreeMap::from([
            (
                "BLINDPASS_PUBLIC_URL".into(),
                "https://blindpass.example".into(),
            ),
            (
                "BLINDPASS_UI_BASE_URL".into(),
                "https://input.example".into(),
            ),
            ("BLINDPASS_PROXY_REQUIRED".into(), "1".into()),
            ("BLINDPASS_TRUST_PROXY".into(), "127.0.0.0/8,::1/128".into()),
        ]);
        for (field, filename, bytes) in [
            ("BLINDPASS_ROOT_SECRET_FILE", "root", vec![b'R'; 32]),
            ("BLINDPASS_AGENT_JWT_SECRET_FILE", "agent", vec![b'A'; 32]),
            ("BLINDPASS_ISSUER_KEY_FILE", "issuer", vec![b'I'; 32]),
            (
                "BLINDPASS_DATABASE_URL_FILE",
                "database",
                b"sqlite::memory:".to_vec(),
            ),
        ] {
            let path = directory.file(filename);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            values.insert(field.into(), path.display().to_string());
        }
        Self {
            _directory: directory,
            values,
        }
    }
}

struct Server {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(fixture: &Fixture) -> Self {
        Self::start_with_store(fixture, None).await
    }

    async fn start_with_store(
        fixture: &Fixture,
        store: Option<blindpass_controller::store::Store>,
    ) -> Self {
        let config = Config::from_variables(fixture.values.clone()).expect("proxy config");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = build_app(config, store);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self { address, task }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        host: &str,
        headers: &[(&str, &str)],
    ) -> HttpResponse {
        let mut bytes = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n"
        );
        for (name, value) in headers {
            bytes.push_str(&format!("{name}: {value}\r\n"));
        }
        bytes.push_str("\r\n");
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream.write_all(bytes.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        HttpResponse {
            status,
            headers: lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                .collect(),
            body: serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
        }
    }
}

const FORWARDED: &[(&str, &str)] = &[
    ("X-Forwarded-Host", "blindpass.example"),
    ("X-Forwarded-Proto", "https"),
    ("X-Forwarded-For", "198.51.100.9"),
];

#[test]
fn p06_x01_specific_canonical_ipv4_ipv6_peers_and_cidrs_only() {
    let mut fixture = Fixture::new();
    for peers in [
        "127.0.0.1",
        "192.0.2.0/24,2001:db8::/32",
        "::1/128",
        "127.0.0.0/8",
    ] {
        fixture
            .values
            .insert("BLINDPASS_TRUST_PROXY".into(), peers.into());
        assert!(
            Config::from_variables(fixture.values.clone()).is_ok(),
            "denied {peers}"
        );
    }
    for peers in [
        "true",
        "1",
        "0.0.0.0/0",
        "::/0",
        "0.0.0.0",
        "::",
        "192.0.2.1/24",
        "::1/32",
        "192.0.2.0/33",
        "::/129",
        "192.0.2.0/64",
        "127.0.0.1/",
        "127.0.0.1,,::1",
    ] {
        fixture
            .values
            .insert("BLINDPASS_TRUST_PROXY".into(), peers.into());
        assert!(
            Config::from_variables(fixture.values.clone()).is_err(),
            "accepted {peers}"
        );
    }
}

#[test]
fn p06_x02_required_proxy_rejects_missing_trust_http_and_unguarded_wildcard_bind() {
    let mut fixture = Fixture::new();
    fixture
        .values
        .insert("BLINDPASS_LISTEN".into(), "0.0.0.0:3200".into());
    assert!(Config::from_variables(fixture.values.clone()).is_ok());
    for (field, value) in [
        ("BLINDPASS_TRUST_PROXY", ""),
        ("BLINDPASS_PROXY_REQUIRED", "0"),
        ("BLINDPASS_PROXY_REQUIRED", "true"),
        ("BLINDPASS_PUBLIC_URL", "http://blindpass.example"),
        ("BLINDPASS_UI_BASE_URL", "http://input.example"),
    ] {
        let mut values = fixture.values.clone();
        values.insert(field.into(), value.into());
        assert!(Config::from_variables(values).is_err(), "accepted {field}");
    }
}

#[tokio::test]
async fn p06_x03_untrusted_tcp_peer_cannot_reach_api_ui_or_preflight() {
    let mut fixture = Fixture::new();
    fixture
        .values
        .insert("BLINDPASS_TRUST_PROXY".into(), "192.0.2.0/24".into());
    let server = Server::start(&fixture).await;
    for (method, path) in [
        ("GET", "/api/v3/capabilities"),
        ("GET", "/console"),
        ("OPTIONS", "/api/v3/admin/session/login"),
    ] {
        let response = server
            .request(method, path, "blindpass.example", FORWARDED)
            .await;
        assert_eq!(response.status, 403);
        assert_eq!(response.body, serde_json::json!({"error":"proxy_required"}));
    }
    assert_eq!(
        server
            .request("GET", "/healthz", "127.0.0.1", &[])
            .await
            .status,
        200
    );
    assert_eq!(
        server
            .request("GET", "/readyz", "127.0.0.1", &[])
            .await
            .status,
        503
    );
}

#[tokio::test]
async fn p06_x04_reviewed_forwarded_authorities_are_accepted_and_hsts_is_set() {
    let fixture = Fixture::new();
    let server = Server::start(&fixture).await;
    for (host, ip) in [
        ("blindpass.example", "198.51.100.9"),
        ("input.example", "2001:db8::5"),
    ] {
        let headers = [
            ("X-Forwarded-Host", host),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-For", ip),
        ];
        let response = server
            .request("GET", "/api/v3/capabilities", host, &headers)
            .await;
        assert_eq!(response.status, 200);
        assert!(response.headers.contains(&(
            "strict-transport-security".into(),
            "max-age=31536000".into()
        )));
    }
}

#[tokio::test]
async fn p06_x05_malformed_appended_duplicate_and_spoofed_forwarding_is_denied() {
    let fixture = Fixture::new();
    let server = Server::start(&fixture).await;
    let mut cases = vec![vec![]];
    for (index, forwarded) in FORWARDED.iter().enumerate() {
        let mut headers = FORWARDED.to_vec();
        headers.remove(index);
        cases.push(headers);
        let mut headers = FORWARDED.to_vec();
        headers.push(*forwarded);
        cases.push(headers);
    }
    for (name, value) in [
        ("X-Forwarded-For", "198.51.100.9, 127.0.0.1"),
        ("X-Forwarded-For", "canary-invalid"),
        ("X-Forwarded-Proto", "http"),
        ("X-Forwarded-Proto", "https,http"),
        ("X-Forwarded-Host", "canary.example"),
        ("X-Forwarded-Host", "blindpass.example,canary.example"),
    ] {
        let mut headers = FORWARDED.to_vec();
        headers.retain(|(key, _)| *key != name);
        headers.push((name, value));
        cases.push(headers);
    }
    let mut alternate = FORWARDED.to_vec();
    alternate.push(("Forwarded", "for=canary"));
    cases.push(alternate);
    for headers in cases {
        let response = server
            .request("GET", "/api/v3/capabilities", "blindpass.example", &headers)
            .await;
        assert_eq!(response.status, 403);
        assert_eq!(response.body, serde_json::json!({"error":"proxy_required"}));
    }
    assert_eq!(
        server
            .request("GET", "/api/v3/capabilities", "canary.example", FORWARDED)
            .await
            .status,
        403
    );
}

#[tokio::test]
async fn p06_x06_only_trusted_proxy_clients_receive_independent_rate_windows() {
    for trusted in [true, false] {
        let harness = support::Harness::start().await;
        let mut fixture = Fixture::new();
        fixture
            .values
            .insert("BLINDPASS_AGENT_TOKEN_RATE_LIMIT".into(), "1".into());
        if !trusted {
            fixture
                .values
                .insert("BLINDPASS_PROXY_REQUIRED".into(), "0".into());
            fixture
                .values
                .insert("BLINDPASS_TRUST_PROXY".into(), "192.0.2.0/24".into());
        }
        let server = Server::start_with_store(&fixture, Some(harness.store.clone())).await;
        for (ip, status) in [
            ("198.51.100.9", 401),
            ("198.51.100.10", if trusted { 401 } else { 429 }),
            ("198.51.100.9", 429),
        ] {
            let headers = [
                ("X-Forwarded-Host", "blindpass.example"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-For", ip),
            ];
            let response = server
                .request(
                    "POST",
                    "/api/v2/agents/token",
                    "blindpass.example",
                    &headers,
                )
                .await;
            assert_eq!(response.status, status);
        }
    }
}

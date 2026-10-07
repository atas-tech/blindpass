// SPDX-License-Identifier: AGPL-3.0-only

//! P07-D5 follow-up: wrong-type and out-of-window JWT claims must never authenticate.
//!
//! Socket reports a medium CVE in `jsonwebtoken` 9.3.1 (fixed in 10.x); 9.3.1 ignores a
//! malformed `nbf` even with `validate_nbf` on. This test pins that every agent token
//! signed with the REAL agent secret but carrying a wrong-typed, missing or out-of-window
//! claim answers 401, so the decision not to upgrade rests on a regression test and not on
//! a code read. The external-provider path (asymmetric JWKS only) is covered by the unit
//! test on its `nbf` guard in `routes/auth.rs`.

use axum::Router;
use blindpass_controller::{app::build_app, config::Config, store::Store};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blindpass-jwt-claims-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

fn sign(claims: &Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(&[b'A'; 32]),
    )
    .expect("sign workload JWT")
}

fn valid_claims(workspace: &str) -> Value {
    let now = now();
    json!({
        "sub": "claim-type-agent",
        "role": "gateway",
        "workspace_id": workspace,
        "workload_mode": "hosted",
        "iss": "sps",
        "aud": "sps-agent",
        "iat": now,
        "exp": now + 300
    })
}

async fn post_secret_request(address: std::net::SocketAddr, token: &str) -> u16 {
    let body = json!({"public_key": "YQ==", "description": "claim type probe"}).to_string();
    let request = format!(
        "POST /api/v2/secret/request HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Authorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect HTTP test server");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read HTTP response");
    String::from_utf8(response)
        .expect("HTTP response is UTF-8")
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .expect("HTTP status")
}

struct Served {
    address: std::net::SocketAddr,
    tenant: String,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    _directory: TestDirectory,
}

async fn serve() -> Served {
    let directory = TestDirectory::new();
    for (name, value) in [
        ("root.secret", "R".repeat(32)),
        ("agent.secret", "A".repeat(32)),
    ] {
        let path = directory.file(name);
        std::fs::write(&path, value).expect("write test credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test credential");
    }
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        directory.file("controller.db").display()
    );
    let root_secret = directory.file("root.secret");
    let agent_secret = directory.file("agent.secret");
    let variables = vec![
        ("BLINDPASS_LISTEN", "127.0.0.1:0"),
        ("BLINDPASS_PUBLIC_URL", "http://127.0.0.1:8080"),
        ("BLINDPASS_UI_BASE_URL", "http://127.0.0.1:5175"),
        ("BLINDPASS_DATABASE_URL", database_url.as_str()),
        ("BLINDPASS_ROOT_SECRET_FILE", root_secret.to_str().unwrap()),
        (
            "BLINDPASS_AGENT_JWT_SECRET_FILE",
            agent_secret.to_str().unwrap(),
        ),
        ("BLINDPASS_TEST_MODE", "1"),
    ];
    let config = Config::from_variables(variables).expect("valid JWT claim test configuration");
    let store = Store::connect(&database_url)
        .await
        .expect("connect JWT claim test store");
    let tenant = store.tenant_id().to_owned();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP test listener");
    let address = listener.local_addr().expect("HTTP test listener address");
    let app: Router = build_app(config, Some(store));
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    Served {
        address,
        tenant,
        server,
        _directory: directory,
    }
}

/// The wrong-typed, missing and out-of-window variants of one valid claim set.
fn bad_cases(valid: &Value, issuer: &str, audience: &str) -> Vec<(String, Value)> {
    let now = now();
    let mutate = |claim: &str, value: Value| {
        let mut claims = valid.clone();
        claims[claim] = value;
        claims
    };
    let without = |claim: &str| {
        let mut claims = valid.clone();
        claims.as_object_mut().unwrap().remove(claim);
        claims
    };
    vec![
        (
            "exp as numeric string",
            mutate("exp", json!((now + 300).to_string())),
        ),
        ("exp as boolean", mutate("exp", json!(true))),
        (
            "exp as float",
            mutate("exp", json!((now + 300) as f64 + 0.5)),
        ),
        ("exp as array", mutate("exp", json!([now + 300]))),
        ("exp as null", mutate("exp", Value::Null)),
        ("exp expired", mutate("exp", json!(now - 5))),
        ("nbf in the future", mutate("nbf", json!(now + 3_600))),
        ("nbf as string", mutate("nbf", json!("0"))),
        (
            "nbf as future string",
            mutate("nbf", json!((now + 3_600).to_string())),
        ),
        ("nbf as boolean", mutate("nbf", json!(false))),
        ("iss as number", mutate("iss", json!(1))),
        ("iss as array", mutate("iss", json!([issuer]))),
        ("iss of another issuer", mutate("iss", json!("other"))),
        ("aud as number", mutate("aud", json!(1))),
        ("aud of another audience", mutate("aud", json!("elsewhere"))),
        ("sub as number", mutate("sub", json!(7))),
        ("role as array", mutate("role", json!(["gateway"]))),
        ("role of another kind", mutate("role", json!("admin"))),
        ("exp missing", without("exp")),
        ("aud missing", without("aud")),
        ("iss missing", without("iss")),
    ]
    .into_iter()
    .map(|(name, claims)| (name.to_owned(), claims))
    .chain(std::iter::once((
        format!("aud as array of the pinned audience {audience}"),
        mutate("aud", json!([audience])),
    )))
    .collect()
}

async fn rejected_all(
    served: &Served,
    cases: Vec<(String, Value)>,
    sign: impl Fn(&Value) -> String,
) -> Vec<String> {
    let mut accepted = Vec::new();
    for (name, claims) in &cases {
        let status = post_secret_request(served.address, &sign(claims)).await;
        if status != 401 {
            accepted.push(format!("{name}: {status}"));
        }
    }
    accepted
}

#[tokio::test]
async fn p07_jwt01_agent_token_wrong_typed_or_out_of_window_claims_never_authenticate() {
    let served = serve().await;
    let valid = valid_claims(&served.tenant);
    // Control: the same signer, secret and shape with correct types reaches the handler.
    assert_eq!(
        post_secret_request(served.address, &sign(&valid)).await,
        201,
        "the control token must authenticate, otherwise the rejections below prove nothing"
    );
    let accepted = rejected_all(&served, bad_cases(&valid, "sps", "sps-agent"), sign).await;
    served.server.abort();
    assert!(
        accepted.is_empty(),
        "agent tokens with a wrong-typed, missing or out-of-window claim must answer 401, got: {accepted:?}"
    );
}

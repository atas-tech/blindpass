// SPDX-License-Identifier: AGPL-3.0-only

//! P07-D6 / P07-I03 / pilot S04: browser security headers as the controller
//! really emits them, parsed rather than compared to a copied string, plus
//! the TLS-terminator examples that own HSTS. The controller itself sends
//! `max-age=31536000` only where it knows the connection is HTTPS (a trusted
//! edge that passes the reviewed forwarding headers, or built-in TLS), pinned
//! by `deployment_proxy.rs`; these cases cover the plain-HTTP profile. Run `npm run build` first so the
//! console and input page are embedded.

mod support;

use serde_json::json;
use std::collections::BTreeMap;
use support::{Harness, HttpResponse, ORIGIN};

fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

fn text(response: &HttpResponse) -> String {
    match &response.body {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `name -> sources` for one Content-Security-Policy value.
fn parse_csp(value: &str) -> BTreeMap<String, Vec<String>> {
    value
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .map(|directive| {
            let mut parts = directive.split_whitespace();
            let name = parts.next().expect("directive name").to_ascii_lowercase();
            (name, parts.map(str::to_owned).collect())
        })
        .collect()
}

/// A policy that cannot send anything off-origin or run injected script.
fn assert_closed_policy(policy: &BTreeMap<String, Vec<String>>, context: &str) {
    let only = |name: &str, expected: &[&str]| {
        assert_eq!(
            policy
                .get(name)
                .map(|sources| sources.iter().map(String::as_str).collect::<Vec<_>>()),
            Some(expected.to_vec()),
            "{context}: {name}"
        );
    };
    only("default-src", &["'none'"]);
    only("script-src", &["'self'"]);
    only("style-src", &["'self'"]);
    only("connect-src", &["'self'"]);
    only("font-src", &["'self'"]);
    only("img-src", &["'self'", "data:"]);
    only("frame-ancestors", &["'none'"]);
    only("base-uri", &["'none'"]);
    only("form-action", &["'self'"]);
    for (name, sources) in policy {
        for source in sources {
            let lowered = source.to_ascii_lowercase();
            assert!(
                !matches!(lowered.as_str(), "*" | "http:" | "https:" | "ws:" | "wss:"),
                "{context}: {name} admits {source}"
            );
            assert!(
                !lowered.contains("localhost")
                    && !lowered.contains("127.0.0.1")
                    && !lowered.contains("[::1]")
                    && !lowered.contains("0.0.0.0"),
                "{context}: {name} names a loopback origin {source}"
            );
            assert!(
                !lowered.contains("unsafe-eval") && !lowered.contains("unsafe-inline"),
                "{context}: {name} has {source}"
            );
            assert!(
                !lowered.contains("://"),
                "{context}: {name} names an origin {source}"
            );
        }
    }
}

fn assert_baseline_headers(response: &HttpResponse, context: &str) {
    assert_eq!(
        header(response, "x-content-type-options"),
        Some("nosniff"),
        "{context}"
    );
    assert_eq!(
        header(response, "referrer-policy"),
        Some("no-referrer"),
        "{context}"
    );
    assert_eq!(
        header(response, "cache-control"),
        Some("no-store"),
        "{context}"
    );
    assert_eq!(
        header(response, "strict-transport-security"),
        None,
        "{context}: a plain-HTTP profile never emits HSTS (only a trusted HTTPS edge or built-in TLS does; see deployment_proxy.rs)"
    );
}

const CONSOLE_PATHS: &[&str] = &[
    "/",
    "/login",
    "/setup",
    "/nodes",
    "/workloads",
    "/approvals",
    "/settings",
];
const INPUT_LINK: &str = "/?id=p07-header-fixture&metadata_sig=sig-a&submit_sig=sig-b";

#[tokio::test]
async fn p07_hd01_every_html_response_carries_a_closed_policy_and_the_framing_headers() {
    let harness = Harness::start().await;
    let mut pages = CONSOLE_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    pages.push(INPUT_LINK.to_owned());
    for path in &pages {
        let response = harness.request("GET", path, &[], None).await;
        assert_eq!(response.status, 200, "{path}");
        assert!(
            header(&response, "content-type").is_some_and(|value| value.starts_with("text/html")),
            "{path} is not HTML"
        );
        let policy = parse_csp(
            header(&response, "content-security-policy")
                .unwrap_or_else(|| panic!("{path}: no CSP")),
        );
        assert_closed_policy(&policy, path);
        assert_eq!(header(&response, "x-frame-options"), Some("DENY"), "{path}");
        assert_eq!(
            header(&response, "cross-origin-opener-policy"),
            Some("same-origin"),
            "{path}"
        );
        let permissions = header(&response, "permissions-policy").unwrap_or_default();
        for feature in ["camera=()", "microphone=()", "geolocation=()"] {
            assert!(permissions.contains(feature), "{path}: {permissions}");
        }
        assert_baseline_headers(&response, path);
    }
}

#[tokio::test]
async fn p07_hd02_embedded_pages_hold_no_inline_script_handler_or_off_origin_reference() {
    let harness = Harness::start().await;
    for path in [CONSOLE_PATHS[0], INPUT_LINK] {
        let response = harness.request("GET", path, &[], None).await;
        let html = text(&response);
        let lowered = html.to_ascii_lowercase();
        // Every <script> carries src; none has an inline body.
        let mut rest = lowered.as_str();
        while let Some(start) = rest.find("<script") {
            let tag_end = rest[start..].find('>').expect("script tag closes") + start;
            let tag = &rest[start..tag_end];
            assert!(tag.contains("src="), "{path}: inline <script> {tag}");
            let body_end = rest[tag_end..].find("</script>").expect("script closes") + tag_end;
            assert!(
                rest[tag_end + 1..body_end].trim().is_empty(),
                "{path}: script has an inline body"
            );
            rest = &rest[body_end..];
        }
        for forbidden in [
            " onclick=",
            " onload=",
            " onerror=",
            " onsubmit=",
            "javascript:",
            "<style>",
            "<iframe",
            "<object",
            "<embed",
        ] {
            assert!(!lowered.contains(forbidden), "{path}: contains {forbidden}");
        }
        // Resource references stay same-origin (relative or root-relative).
        for attribute in ["src=\"", "href=\""] {
            let mut cursor = lowered.as_str();
            while let Some(index) = cursor.find(attribute) {
                let value = &cursor[index + attribute.len()..];
                let value = &value[..value.find('"').expect("attribute closes")];
                assert!(
                    !(value.starts_with("http:")
                        || value.starts_with("https:")
                        || value.starts_with("//")
                        || value.starts_with("ws")),
                    "{path}: off-origin reference {value}"
                );
                cursor = &cursor[index + attribute.len()..];
            }
        }
        // A policy in a meta tag is never looser than the header's.
        for meta in lowered
            .split("http-equiv=\"content-security-policy\"")
            .skip(1)
        {
            let content = meta
                .split("content=\"")
                .nth(1)
                .and_then(|value| value.split('"').next())
                .unwrap_or_default()
                .replace("&#39;", "'");
            let policy = parse_csp(&content);
            for (name, sources) in &policy {
                for source in sources {
                    assert!(
                        !matches!(source.as_str(), "*" | "http:" | "https:" | "ws:" | "wss:")
                            && !source.contains("localhost")
                            && !source.contains("127.0.0.1"),
                        "{path}: meta {name} admits {source}"
                    );
                }
            }
            assert_eq!(
                policy.get("connect-src"),
                Some(&vec!["'self'".to_owned()]),
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn p07_hd03_api_and_error_responses_carry_the_baseline_and_no_hsts() {
    let harness = Harness::start().await;
    let hostile = [("origin", "https://attacker.example")];
    for (method, path, body) in [
        ("GET", "/healthz", None),
        ("GET", "/readyz", None),
        ("GET", "/api/v3/capabilities", None),
        ("GET", "/api/v3/admin/session", None),
        ("GET", "/api/v3/no-such-route", None),
        (
            "POST",
            "/api/v3/admin/session/login",
            Some(json!({"username":"nobody-p07","password":"p07-dummy-password"})),
        ),
    ] {
        let response = harness.request(method, path, &hostile, body.as_ref()).await;
        assert_baseline_headers(&response, &format!("{method} {path}"));
        assert_ne!(
            header(&response, "access-control-allow-origin"),
            Some("https://attacker.example"),
            "{method} {path} allows a hostile origin"
        );
        assert_ne!(
            header(&response, "access-control-allow-origin"),
            Some("*"),
            "{method} {path}"
        );
    }
    // The embedded profile grants no cross-origin access at all, not even to
    // its own UI origin: the console and input page are same-origin.
    let own = harness
        .request("GET", "/api/v3/capabilities", &[("origin", ORIGIN)], None)
        .await;
    assert_eq!(header(&own, "access-control-allow-origin"), None);

    // A separately hosted compatibility input names exactly one origin.
    let hosted = Harness::start_with(&[("BLINDPASS_CORS_ALLOWED_ORIGINS", ORIGIN)]).await;
    let named = hosted
        .request("GET", "/api/v3/capabilities", &[("origin", ORIGIN)], None)
        .await;
    assert_eq!(header(&named, "access-control-allow-origin"), Some(ORIGIN));
    let other = hosted
        .request("GET", "/api/v3/capabilities", &hostile, None)
        .await;
    assert_eq!(header(&other, "access-control-allow-origin"), None);
    assert_baseline_headers(&named, "CORS-enabled GET /api/v3/capabilities");
}

#[tokio::test]
async fn p07_hd04_a_client_claiming_https_cannot_make_a_plain_profile_emit_hsts() {
    let harness = Harness::start_with(&[("BLINDPASS_TRUST_PROXY", "127.0.0.0/8,::1/128")]).await;
    let response = harness
        .request(
            "GET",
            "/login",
            &[
                ("x-forwarded-proto", "https"),
                ("x-forwarded-for", "203.0.113.5"),
            ],
            None,
        )
        .await;
    assert_eq!(response.status, 200);
    assert_baseline_headers(&response, "GET /login via https edge");
}

// --- TLS terminator examples: where HSTS lives -----------------------------

fn directives(source: &str) -> Vec<String> {
    source
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn p07_hd05_the_nginx_example_owns_hsts_without_subdomains_and_cannot_be_spoofed() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/proxy/nginx.conf.example"),
    )
    .expect("read nginx example");
    let lines = directives(&source);
    let servers = lines
        .iter()
        .filter(|line| line.starts_with("server {"))
        .count();
    assert_eq!(servers, 2, "console and input authorities");
    let hsts = lines
        .iter()
        .filter(|line| line.starts_with("add_header Strict-Transport-Security"))
        .collect::<Vec<_>>();
    assert_eq!(hsts.len(), servers, "HSTS on every TLS server");
    for line in hsts {
        let value = line.split('"').nth(1).expect("quoted HSTS value");
        let max_age = value
            .split(';')
            .find_map(|part| part.trim().strip_prefix("max-age="))
            .and_then(|seconds| seconds.parse::<u64>().ok())
            .expect("numeric max-age");
        assert!(max_age >= 15_552_000, "max-age {max_age}");
        let lowered = value.to_ascii_lowercase();
        assert!(
            !lowered.contains("includesubdomains"),
            "includeSubDomains is not a default: {value}"
        );
        assert!(
            !lowered.contains("preload"),
            "preload is irreversible: {value}"
        );
        assert!(
            line.ends_with("always;"),
            "HSTS must be added to error responses too: {line}"
        );
    }
    let hidden = lines
        .iter()
        .filter(|line| line.as_str() == "proxy_hide_header Strict-Transport-Security;")
        .count();
    assert_eq!(hidden, servers, "an upstream HSTS must not double");
    // The edge, not the client, names the peer address and the authority.
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.as_str() == "proxy_set_header X-Forwarded-For $remote_addr;")
            .count(),
        servers
    );
    assert!(
        !source.contains("$proxy_add_x_forwarded_for"),
        "a client-supplied X-Forwarded-For would be appended"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.as_str() == "proxy_set_header Forwarded \"\";")
            .count(),
        servers
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("if ($host != ") && line.ends_with("{ return 421; }"))
            .count(),
        servers
    );
    for line in lines
        .iter()
        .filter(|line| line.starts_with("ssl_protocols"))
    {
        assert_eq!(line, "ssl_protocols TLSv1.2 TLSv1.3;");
    }
    assert!(
        lines
            .iter()
            .filter(|line| line.starts_with("listen "))
            .all(|line| line.contains("ssl"))
    );
}

#[test]
fn p07_hd06_the_caddy_example_owns_hsts_without_subdomains_and_cannot_be_spoofed() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/proxy/Caddyfile.example"),
    )
    .expect("read Caddyfile example");
    let lines = directives(&source);
    let sites = lines
        .iter()
        .filter(|line| line.starts_with("https://") && line.ends_with('{'))
        .count();
    assert_eq!(sites, 2);
    let hsts = lines
        .iter()
        .filter(|line| line.starts_with("header Strict-Transport-Security"))
        .collect::<Vec<_>>();
    assert_eq!(hsts.len(), sites);
    for line in hsts {
        let value = line
            .split('"')
            .nth(1)
            .expect("quoted HSTS value")
            .to_ascii_lowercase();
        assert!(value.contains("max-age="), "{line}");
        assert!(
            !value.contains("includesubdomains") && !value.contains("preload"),
            "{line}"
        );
    }
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.as_str() == "header_down -Strict-Transport-Security")
            .count(),
        sites
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.as_str() == "header_up -Forwarded")
            .count(),
        sites
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.as_str() == "header_up X-Forwarded-For {http.request.remote.host}")
            .count(),
        sites
    );
    assert!(
        lines.iter().any(|line| line == "auto_https off"),
        "certificates are the operator's, not implicit"
    );
}

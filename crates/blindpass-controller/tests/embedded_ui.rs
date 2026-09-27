// SPDX-License-Identifier: AGPL-3.0-only

//! P04-D9 / P04-E04: the controller serves the console at `/` and the
//! secret-input page for signed links, from assets embedded at build time
//! (`packages/console/dist`, `packages/browser-ui/dist-embedded`). Run
//! `npm run build` before `cargo test` to embed them; without them the
//! controller serves no UI and these tests check that instead.

mod support;

use blindpass_controller::embedded_ui;
use support::{Harness, HttpResponse};

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

fn body(response: &HttpResponse) -> String {
    match &response.body {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn assert_page_headers(response: &HttpResponse, path: &str) {
    assert_eq!(
        header(response, "content-security-policy"),
        Some(CSP),
        "{path}"
    );
    assert_eq!(header(response, "x-frame-options"), Some("DENY"), "{path}");
    assert_eq!(
        header(response, "cross-origin-opener-policy"),
        Some("same-origin"),
        "{path}"
    );
    assert_eq!(
        header(response, "permissions-policy"),
        Some("camera=(), microphone=(), geolocation=()"),
        "{path}"
    );
    assert_eq!(
        header(response, "referrer-policy"),
        Some("no-referrer"),
        "{path}"
    );
    assert_eq!(
        header(response, "x-content-type-options"),
        Some("nosniff"),
        "{path}"
    );
}

async fn get(harness: &Harness, path: &str) -> HttpResponse {
    harness
        .request("GET", path, &[("accept", "text/html")], None)
        .await
}

#[tokio::test]
async fn console_routes_fall_back_to_the_console_shell_with_the_csp() {
    let harness = Harness::start().await;
    if !embedded_ui::console_embedded() {
        eprintln!(
            "embedded_ui: console not embedded (run `npm run build` first); checking the no-UI behaviour"
        );
        assert_eq!(get(&harness, "/").await.status, 404);
        assert_eq!(get(&harness, "/approvals").await.status, 404);
        return;
    }
    for path in [
        "/",
        "/approvals",
        "/approvals/operation/oa_x",
        "/settings/operators",
        "/login?next=%2Faudit",
    ] {
        let response = get(&harness, path).await;
        assert_eq!(response.status, 200, "{path}");
        assert_eq!(
            header(&response, "content-type"),
            Some("text/html; charset=utf-8"),
            "{path}"
        );
        assert_eq!(
            header(&response, "cache-control"),
            Some("no-store"),
            "{path}"
        );
        assert_page_headers(&response, path);
        assert!(
            body(&response).contains("<div id=\"root\"></div>"),
            "{path} is the console shell"
        );
    }
}

#[tokio::test]
async fn hashed_assets_are_immutable_and_misses_do_not_fall_back() {
    let harness = Harness::start().await;
    if !embedded_ui::console_embedded() {
        eprintln!("embedded_ui: console not embedded; skipping asset checks");
        return;
    }
    let script = embedded_ui::console_paths()
        .into_iter()
        .find(|path| path.starts_with("/assets/") && path.ends_with(".js"))
        .expect("a hashed console script");
    let response = get(&harness, script).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        header(&response, "content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(
        header(&response, "cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(header(&response, "x-content-type-options"), Some("nosniff"));
    let font = embedded_ui::console_paths()
        .into_iter()
        .find(|path| path.ends_with(".woff2"))
        .expect("the self-hosted font");
    assert_eq!(
        header(
            &harness.request("HEAD", font, &[], None).await,
            "content-type"
        ),
        Some("font/woff2")
    );
    for missing in [
        "/assets/missing-abc123.js",
        "/input/assets/missing.js",
        "/favicon-missing.svg.map",
    ] {
        let response = get(&harness, missing).await;
        assert_eq!(
            response.status, 404,
            "{missing} must not return the SPA shell"
        );
    }
    let head = harness.request("HEAD", script, &[], None).await;
    assert_eq!(head.status, 200);
    let post = harness.request("POST", "/approvals", &[], None).await;
    assert_eq!(
        post.status, 405,
        "the SPA fallback answers only GET and HEAD"
    );
    assert_eq!(header(&post, "allow"), Some("GET, HEAD"));
    let elsewhere = harness
        .request("POST", "/route-that-does-not-exist", &[], None)
        .await;
    assert_eq!(
        elsewhere.status, 404,
        "outside the console a miss stays 404"
    );
}

#[tokio::test]
async fn only_console_route_sections_get_the_shell_and_other_paths_keep_the_compat_404() {
    let harness = Harness::start().await;
    // CT18: an unknown route keeps the SPS-compatible JSON 404 even with the
    // console embedded.
    for path in [
        "/route-that-does-not-exist",
        "/no-such-screen",
        "/wp-admin",
        "/approvalsx",
    ] {
        let response = get(&harness, path).await;
        assert_eq!(response.status, 404, "{path}");
        assert_eq!(
            header(&response, "content-type"),
            Some("application/json"),
            "{path}"
        );
        assert_eq!(response.body["statusCode"], 404, "{path}");
        assert_eq!(
            response.body["message"],
            format!("Route GET:{path} not found"),
            "{path}"
        );
    }
    if !embedded_ui::console_embedded() {
        return;
    }
    // Client routes, their unknown sub-paths (the console's own not-found
    // view) and the retired hosted paths (the unavailable page) get the shell.
    for path in [
        "/setup",
        "/change-password",
        "/nodes/node_1",
        "/workloads/wl_1",
        "/policy/fleet",
        "/operations/op_1",
        "/audit/exchange/ex_1",
        "/settings/unknown-tab",
        "/billing",
        "/public/offer/1",
        "/members",
    ] {
        let response = get(&harness, path).await;
        assert_eq!(response.status, 200, "{path}");
        assert!(
            body(&response).contains("<div id=\"root\"></div>"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn api_and_health_paths_are_never_the_spa() {
    let harness = Harness::start().await;
    for path in [
        "/api/v3/nope",
        "/api/v2/secret/nope",
        "/api/v3/admin/nope",
        "/api",
    ] {
        let response = get(&harness, path).await;
        assert_eq!(response.status, 404, "{path}");
        assert!(
            !body(&response).contains("<!doctype html>"),
            "{path} must not be HTML"
        );
    }
    let healthz = get(&harness, "/healthz").await;
    assert_eq!(healthz.status, 200);
    assert_eq!(healthz.body["ok"], true);
}

#[tokio::test]
async fn signed_links_open_the_input_page_on_the_same_origin() {
    let harness = Harness::start().await;
    if !embedded_ui::input_embedded() {
        eprintln!("embedded_ui: input page not embedded; skipping");
        return;
    }
    let id = "a".repeat(64);
    let path = format!("/?id={id}&metadata_sig=1.x&submit_sig=1.y");
    let response = get(&harness, &path).await;
    assert_eq!(response.status, 200);
    assert_eq!(header(&response, "cache-control"), Some("no-store"));
    assert_page_headers(&response, &path);
    let page = body(&response);
    assert!(
        page.contains("secret-form"),
        "signed link serves the input page"
    );
    assert!(
        page.contains("/input/assets/"),
        "input assets live under /input/"
    );
    assert!(!page.contains("id=\"root\""), "not the console");
    // Only a complete signed link selects the input page.
    for incomplete in [
        format!("/?id={id}"),
        "/?metadata_sig=1.x&submit_sig=1.y".to_owned(),
    ] {
        let response = get(&harness, &incomplete).await;
        if embedded_ui::console_embedded() {
            assert!(
                body(&response).contains("id=\"root\""),
                "{incomplete} is the console"
            );
        }
    }
    let asset = embedded_ui::input_paths()
        .into_iter()
        .find(|path| path.starts_with("/input/assets/") && path.ends_with(".js"))
        .expect("an input script");
    let script = get(&harness, &asset).await;
    assert_eq!(script.status, 200);
    assert_eq!(
        header(&script, "cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    // The page's own copy of the index is not served as a separate route.
    assert_eq!(get(&harness, "/input/index.html").await.status, 404);
}

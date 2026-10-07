// SPDX-License-Identifier: AGPL-3.0-only

//! The embedded operator console and secret-input page (P04-D9).
//!
//! * A GET for `/` carrying a complete signed link (`id`, `metadata_sig` and
//!   `submit_sig`) is the input page; its assets live under `/input/`.
//! * Other GET or HEAD requests are console files, or the console shell for
//!   paths in a console route section (SPA fallback). Any other miss keeps
//!   the controller's JSON 404 (CT18); asset misses, `/input/` misses and API
//!   paths are never answered with the shell.
//! * Pages carry the P04 CSP and headers and `Cache-Control: no-store`;
//!   hashed files under `assets/` are immutable.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

include!(concat!(env!("OUT_DIR"), "/embedded_ui.rs"));

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// First path segments the console router handles, including the retired
/// hosted paths it answers with its unavailable page. Kept in step with
/// `packages/console/src/app.tsx` by `src/embedded-routes.test.ts` there.
const CONSOLE_SECTIONS: &[&str] = &[
    "",
    "agents",
    "analytics",
    "approvals",
    "audit",
    "billing",
    "change-password",
    "enrollments",
    "forgot-password",
    "fulfillments",
    "grants",
    "login",
    "members",
    "nodes",
    "operations",
    "policy",
    "public",
    "public-offers",
    "register",
    "reset-password",
    "settings",
    "setup",
    "signup",
    "verify",
    "workloads",
];

fn is_console_route(path: &str) -> bool {
    let section = path
        .strip_prefix('/')
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    CONSOLE_SECTIONS.contains(&section)
}

/// Whether this build embedded the console.
pub fn console_embedded() -> bool {
    find(CONSOLE_FILES, "/index.html").is_some()
}

/// Whether this build embedded the input page.
pub fn input_embedded() -> bool {
    find(INPUT_FILES, "/index.html").is_some()
}

/// Paths the console answers, for tests and diagnostics.
pub fn console_paths() -> Vec<&'static str> {
    CONSOLE_FILES.iter().map(|(path, _)| *path).collect()
}

/// Paths of the input page's files as served (under `/input/`).
pub fn input_paths() -> Vec<String> {
    INPUT_FILES
        .iter()
        .filter(|(path, _)| *path != "/index.html")
        .map(|(path, _)| format!("/input{path}"))
        .collect()
}

fn find(files: &'static [(&'static str, &'static [u8])], path: &str) -> Option<&'static [u8]> {
    files
        .iter()
        .find(|(candidate, _)| *candidate == path)
        .map(|(_, bytes)| *bytes)
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain; charset=utf-8",
        Some("webmanifest") => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

fn is_signed_link(uri: &Uri) -> bool {
    let Some(query) = uri.query() else {
        return false;
    };
    let names: Vec<&str> = query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(name, _)| name))
        .collect();
    ["id", "metadata_sig", "submit_sig"]
        .iter()
        .all(|required| names.contains(required))
}

fn page(bytes: &'static [u8], method: &Method) -> Response {
    let mut response = file(bytes, "/index.html", "no-store", method);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

fn file(bytes: &'static [u8], path: &str, cache: &'static str, method: &Method) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(path)),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    (StatusCode::OK, headers, body).into_response()
}

fn cache_for(path: &str) -> &'static str {
    if path.starts_with("/assets/") {
        IMMUTABLE
    } else {
        "no-cache"
    }
}

/// The router fallback. Unmatched API routes keep their plain 404.
pub(crate) async fn fallback(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return StatusCode::NOT_FOUND.into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        // Console pages are read-only; any other path keeps its 404.
        return if console_embedded() && is_console_route(path) {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, HeaderValue::from_static("GET, HEAD"))],
            )
                .into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        };
    }
    if path == "/"
        && is_signed_link(&uri)
        && let Some(index) = find(INPUT_FILES, "/index.html")
    {
        return page(index, &method);
    }
    if let Some(rest) = path.strip_prefix("/input") {
        return match find(INPUT_FILES, rest)
            .filter(|_| rest != "/index.html" && rest.starts_with('/'))
        {
            Some(bytes) => file(bytes, rest, cache_for(rest), &method),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    if path != "/index.html"
        && let Some(bytes) = find(CONSOLE_FILES, path)
    {
        return file(bytes, path, cache_for(path), &method);
    }
    // Files that don't exist are 404s; only extension-less paths in a
    // console section get the console shell.
    let last = path.rsplit('/').next().unwrap_or_default();
    if last.contains('.') || !is_console_route(path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match find(CONSOLE_FILES, "/index.html") {
        Some(index) => page(index, &method),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

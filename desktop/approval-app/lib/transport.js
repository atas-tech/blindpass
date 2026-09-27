// SPDX-License-Identifier: AGPL-3.0-only
// Controller URL policy and the curl request/response format used by
// CurlTransport.qml. Pure functions so qmltestrunner can cover them.
//
// Why curl and not QML XMLHttpRequest: Qt's XHR follows cross-origin
// redirects and forwards the Authorization header (and a 307 re-POSTs the
// login body), which would hand the bearer or password to whatever a proxy
// redirects to. curl here never follows redirects, ignores ~/.curlrc (-q),
// verifies the CA chain and hostname against the system trust store and is
// limited to https (plus http for loopback development controllers).
.pragma library

var LOOPBACK = /^(127(?:\.\d{1,3}){3}|localhost|\[::1\])$/;

/**
 * Normalise an operator-entered controller URL. Returns
 * { ok: true, origin, host, loopback } or { ok: false, reason }.
 * reason is one of: empty, invalid, scheme, credentials, path.
 */
function parseController(input) {
  var text = String(input === undefined || input === null ? "" : input).trim();
  if (text === "") return { ok: false, reason: "empty" };
  var match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/.exec(text);
  if (!match) return { ok: false, reason: "invalid" };
  var scheme = match[1].toLowerCase();
  var authority = match[2];
  var path = match[3];
  if (authority.indexOf("@") !== -1) return { ok: false, reason: "credentials" };
  if (match[4] || match[5] || (path !== "" && path !== "/")) return { ok: false, reason: "path" };
  var hostMatch = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(authority);
  if (!hostMatch) return { ok: false, reason: "invalid" };
  var host = hostMatch[1].toLowerCase();
  var port = hostMatch[2];
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) return { ok: false, reason: "invalid" };
  if (host.charAt(0) !== "[" && (host.charAt(0) === "." || host.charAt(host.length - 1) === "." || host.indexOf("..") !== -1)) {
    return { ok: false, reason: "invalid" };
  }
  var loopback = LOOPBACK.test(host);
  if (scheme !== "https" && !(scheme === "http" && loopback)) return { ok: false, reason: "scheme" };
  var defaultPort = scheme === "https" ? "443" : "80";
  var origin = scheme + "://" + host + (port !== undefined && port !== defaultPort ? ":" + port : "");
  return { ok: true, origin: origin, host: host + (port !== undefined && port !== defaultPort ? ":" + port : ""), loopback: loopback, scheme: scheme };
}

/** Quote one value for a curl config file: backslash, quote and controls escaped. */
function curlQuote(value) {
  return "\"" + String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, "\\\"")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")
    .replace(/\v/g, "\\v") + "\"";
}

var STATUS_MARKER = "\n@@blindpass-status@@";

/**
 * The curl config for one controller request, written to curl's stdin so
 * no credential appears in argv or the environment.
 * request: { origin, method, path, bearer?, body?, headers?: {name: value} }
 */
function curlConfig(request) {
  var controller = parseController(request.origin);
  if (!controller.ok) throw new Error("controller URL rejected: " + controller.reason);
  if (!/^\/api\/v3\/[A-Za-z0-9._~\/%?=&:-]*$/.test(request.path)) throw new Error("request path rejected");
  var method = String(request.method || "GET").toUpperCase();
  if (["GET", "POST"].indexOf(method) === -1) throw new Error("method rejected");
  var lines = [
    "url = " + curlQuote(controller.origin + request.path),
    "request = " + curlQuote(method),
    "proto = " + curlQuote(controller.scheme === "https" ? "=https" : "=http"),
    "max-redirs = 0",
    "tlsv1.2",
    "silent",
    "show-error",
    "connect-timeout = 5",
    "max-time = 15",
    "user-agent = \"blindpass-approval-app/0.1\"",
    "header = \"Accept: application/json\"",
    "write-out = " + curlQuote(STATUS_MARKER + "%{http_code} %header{date}")
  ];
  if (request.bearer) lines.push("header = " + curlQuote("Authorization: Bearer " + request.bearer));
  var extra = request.headers || {};
  for (var name in extra) {
    if (!/^[A-Za-z0-9-]+$/.test(name) || /[\r\n]/.test(String(extra[name]))) throw new Error("header rejected");
    lines.push("header = " + curlQuote(name + ": " + extra[name]));
  }
  if (request.body !== undefined) {
    lines.push("header = \"Content-Type: application/json\"");
    lines.push("data-binary = " + curlQuote(JSON.stringify(request.body)));
  }
  return lines.join("\n") + "\n";
}

/** curl exit codes the app reports distinctly; everything else is "network". */
function failureKind(exitCode) {
  if ([35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91].indexOf(exitCode) !== -1) return "tls";
  if (exitCode === 28) return "timeout";
  if (exitCode === 1) return "scheme";
  return "network";
}

/**
 * Parse curl's stdout for a finished process.
 * Returns { ok: true, status, body, date } or { ok: false, kind }.
 * A 3xx is reported as { ok: false, kind: "redirect" } and never followed.
 */
function parseResponse(exitCode, stdout) {
  if (exitCode !== 0) return { ok: false, kind: failureKind(exitCode) };
  var text = String(stdout || "");
  var at = text.lastIndexOf(STATUS_MARKER);
  if (at === -1) return { ok: false, kind: "network" };
  var trailer = text.slice(at + STATUS_MARKER.length);
  var space = trailer.indexOf(" ");
  var status = Number(space === -1 ? trailer : trailer.slice(0, space));
  var date = space === -1 ? "" : trailer.slice(space + 1).trim();
  var raw = text.slice(0, at);
  if (!(status >= 100 && status <= 599)) return { ok: false, kind: "network" };
  if (status >= 300 && status < 400) return { ok: false, kind: "redirect", status: status };
  var body = null;
  if (raw.length > 0) {
    try {
      body = JSON.parse(raw);
    } catch (error) {
      body = null;
    }
  }
  var parsedDate = date ? Date.parse(date) : NaN;
  return { ok: true, status: status, body: body, date: isNaN(parsedDate) ? null : parsedDate };
}

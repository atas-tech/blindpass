// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import QtTest
import "../lib/transport.js" as Transport
import "../lib/model.js" as Model
import "../lib/session.js" as Session
import "../lib/strings.js" as Strings

TestCase {
  name: "ApprovalAppLib"

  function test_controller_url_policy_data() {
    return [
      { tag: "https", input: "https://controller.example", ok: true, origin: "https://controller.example" },
      { tag: "trailing slash and case", input: " HTTPS://Controller.Example/ ", ok: true, origin: "https://controller.example" },
      { tag: "explicit default port", input: "https://controller.example:443", ok: true, origin: "https://controller.example" },
      { tag: "custom port", input: "https://controller.example:8443", ok: true, origin: "https://controller.example:8443" },
      { tag: "loopback http", input: "http://127.0.0.1:3100", ok: true, origin: "http://127.0.0.1:3100" },
      { tag: "localhost http", input: "http://localhost:3100", ok: true, origin: "http://localhost:3100" },
      { tag: "ipv6 loopback http", input: "http://[::1]:3100", ok: true, origin: "http://[::1]:3100" },
      { tag: "remote http", input: "http://controller.example", ok: false, reason: "scheme" },
      { tag: "lookalike loopback", input: "http://127.0.0.1.evil.example", ok: false, reason: "scheme" },
      { tag: "other scheme", input: "ftp://controller.example", ok: false, reason: "scheme" },
      { tag: "credentials", input: "https://user:pass@controller.example", ok: false, reason: "credentials" },
      { tag: "path", input: "https://controller.example/api", ok: false, reason: "path" },
      { tag: "query", input: "https://controller.example/?x=1", ok: false, reason: "path" },
      { tag: "fragment", input: "https://controller.example#x", ok: false, reason: "path" },
      { tag: "empty", input: "  ", ok: false, reason: "empty" },
      { tag: "garbage", input: "controller.example", ok: false, reason: "invalid" },
      { tag: "bad port", input: "https://controller.example:99999", ok: false, reason: "invalid" },
      { tag: "dotted host", input: "https://controller..example", ok: false, reason: "invalid" }
    ]
  }

  function test_controller_url_policy(data) {
    var parsed = Transport.parseController(data.input)
    compare(parsed.ok, data.ok)
    if (data.ok) compare(parsed.origin, data.origin)
    else compare(parsed.reason, data.reason)
  }

  function test_curl_config_keeps_redirects_and_rc_files_out() {
    var config = Transport.curlConfig({ origin: "https://controller.example", method: "POST", path: "/api/v3/admin/session/login", body: { username: "op", password: "pa\"ss\\word\nline", kind: "desktop" } })
    verify(config.indexOf("url = \"https://controller.example/api/v3/admin/session/login\"") !== -1)
    verify(config.indexOf("proto = \"=https\"") !== -1)
    verify(config.indexOf("max-redirs = 0") !== -1)
    verify(config.indexOf("location") === -1, "never follows redirects")
    verify(config.indexOf("insecure") === -1 && config.indexOf("-k") === -1)
    verify(config.indexOf("cookie") === -1, "no cookie jar")
    verify(config.indexOf("Authorization") === -1, "login sends no bearer")
    // The body round-trips through curl's quoting.
    var line = config.split("\n").filter(function (l) { return l.indexOf("data-binary = ") === 0 })[0]
    var quoted = line.slice("data-binary = ".length)
    var unquoted = quoted.slice(1, -1).replace(/\\(.)/g, function (m, c) { return c === "n" ? "\n" : c === "r" ? "\r" : c === "t" ? "\t" : c === "v" ? "\v" : c })
    compare(JSON.parse(unquoted).password, "pa\"ss\\word\nline")
  }

  function test_curl_config_bearer_and_loopback() {
    var config = Transport.curlConfig({ origin: "http://127.0.0.1:3100", method: "GET", path: "/api/v3/approvals?status=pending&limit=50", bearer: "tok-123" })
    verify(config.indexOf("proto = \"=http\"") !== -1)
    verify(config.indexOf("header = \"Authorization: Bearer tok-123\"") !== -1)
    verify(config.indexOf("data-binary") === -1)
  }

  function test_curl_config_refusals() {
    var refused = function (request) {
      try {
        Transport.curlConfig(request)
        return false
      } catch (error) {
        return true
      }
    }
    verify(refused({ origin: "http://controller.example", method: "GET", path: "/api/v3/approvals" }), "remote http")
    verify(refused({ origin: "https://controller.example", method: "GET", path: "/api/v2/secret/retrieve/x" }), "only /api/v3")
    verify(refused({ origin: "https://controller.example", method: "GET", path: "/api/v3/approvals\nurl = \"https://evil\"" }), "no config injection via path")
    verify(refused({ origin: "https://controller.example", method: "DELETE", path: "/api/v3/nodes/x" }), "GET and POST only")
    verify(refused({ origin: "https://controller.example", method: "POST", path: "/api/v3/approvals/x/approve", headers: { "X-Bad": "a\nurl = \"https://evil\"" } }), "no header injection")
  }

  function test_parse_response() {
    var ok = Transport.parseResponse(0, "{\"count\":3}\n@@blindpass-status@@200 Mon, 28 Sep 2026 10:00:00 GMT")
    verify(ok.ok)
    compare(ok.status, 200)
    compare(ok.body.count, 3)
    compare(ok.date, Date.UTC(2026, 8, 28, 10, 0, 0))
    var redirect = Transport.parseResponse(0, "\n@@blindpass-status@@307 ")
    verify(!redirect.ok)
    compare(redirect.kind, "redirect")
    compare(Transport.parseResponse(60, "").kind, "tls")
    compare(Transport.parseResponse(51, "").kind, "tls")
    compare(Transport.parseResponse(7, "").kind, "network")
    compare(Transport.parseResponse(28, "").kind, "timeout")
    compare(Transport.parseResponse(0, "no marker").kind, "network")
    var empty = Transport.parseResponse(0, "\n@@blindpass-status@@204 ")
    verify(empty.ok)
    compare(empty.body, null)
    compare(empty.date, null)
  }

  readonly property var operation: ({
    kind: "operation", id: "oa_1", status: "pending", version: 3, operation_ids: ["op_a", "op_b"],
    requester_summary: { requester: "op_rina", operator_id: "id_rina", purpose: "rotate <b>db</b>" },
    verified_identity: { node_id: "node-7", workload_id: "wl_1", unit: "db.service", account: "postgres", action: "db.password", mode: "file", rule_id: "r1", policy_version: 2, tenant_id: "t" },
    approver_ids: ["op_hung"], rule_id: "r1", expires_at: 100000, created_at: 1, decided_by: null, decided_at: null,
    operations: [{ id: "op_a", requested_by: "id_rina" }, { id: "op_b", requested_by: "id_rina" }]
  })
  readonly property var exchange: ({ kind: "exchange", reference: "ex/1", status: "pending", requester_id: "agent-9", secret_name: "API_KEY", purpose: "deploy", created_at: 1, timeline: [] })

  function test_model_authority_uses_verified_fields() {
    var authority = Model.authority(operation)
    compare(authority.recipient.args.node, "node-7")
    compare(authority.scope.args.account, "postgres")
    compare(authority.count, 2)
    var exchangeAuthority = Model.authority(exchange)
    compare(exchangeAuthority.recipient.args.requester, "agent-9")
    compare(exchangeAuthority.scope.args.secret, "API_KEY")
    compare(Model.purpose(operation), "rotate <b>db</b>")
  }

  function test_model_decision_block() {
    compare(Model.decisionBlock(operation, { id: "id_hung", username: "op_hung" }), null)
    compare(Model.decisionBlock(operation, { id: "id_x", username: "op_x" }), "not_named")
    var own = JSON.parse(JSON.stringify(operation))
    own.approver_ids = ["op_rina"]
    compare(Model.decisionBlock(own, { id: "id_rina", username: "op_rina" }), "self")
    var done = JSON.parse(JSON.stringify(operation))
    done.status = "approved"
    compare(Model.decisionBlock(done, { id: "id_hung", username: "op_hung" }), "not_pending")
    compare(Model.decisionBlock(exchange, { id: "any", username: "any" }), null)
  }

  function test_model_decision_request() {
    var request = Model.decisionRequest(operation, "approve", "k".repeat(64))
    compare(request.path, "/api/v3/approvals/oa_1/approve")
    compare(request.body.expected_version, 3)
    compare(request.body.operation_ids, ["op_a", "op_b"])
    compare(request.headers["If-Match"], "\"3\"")
    compare(request.headers["Idempotency-Key"].length, 64)
    var exchangeRequest = Model.decisionRequest(exchange, "reject", "k".repeat(64))
    compare(exchangeRequest.path, "/api/v3/approvals/ex%2F1/reject")
    compare(exchangeRequest.headers["If-Match"], "\"1\"")
    var threw = false
    try { Model.decisionRequest(exchange, "delete", "k") } catch (error) { threw = true }
    verify(threw)
    var bytes = [0, 15, 16, 255]
    var index = 0
    var key = Model.idempotencyKey(function () { return bytes[index++ % 4] })
    compare(key.length, 64)
    compare(key.slice(0, 8), "000f10ff")
  }

  function test_model_countdown_and_summary() {
    compare(Model.remaining(operation, 40000), 60000)
    compare(Model.remaining(operation, 200000), 0)
    compare(Model.remaining(exchange, 0), null)
    compare(Model.formatRemaining(61000), "1:01")
    compare(Model.formatRemaining(3600000), "1:00:00")
    compare(Model.formatRemaining(0), "0:00")
    var summary = Model.widgetSummary("ready", 3, 1234.9)
    compare(Object.keys(summary).sort(), ["pending", "state", "updated_at", "v"])
    compare(summary.pending, 3)
    compare(summary.updated_at, 1234)
    compare(Model.widgetSummary("signed_out", 3, 1).pending, null)
    compare(Model.widgetSummary("evil", 3, 1).state, "signed_out")
    compare(Model.widgetSummary("locked", -4, 1).pending, 0)
  }

  function test_session_record_policy() {
    var record = Session.record("https://c.example", "r".repeat(40), "op", 1000)
    compare(Object.keys(record).sort(), ["controller", "last_active_at", "refresh_token", "username", "v"])
    var text = JSON.stringify(record)
    verify(Session.readRecord(text, "https://c.example").ok)
    compare(Session.readRecord(text, "https://other.example").reason, "other_controller")
    compare(Session.readRecord("{", "https://c.example").reason, "corrupt")
    compare(Session.readRecord(JSON.stringify({ v: 1, controller: "https://c.example", refresh_token: "short", username: "op", last_active_at: 1 }), "https://c.example").reason, "corrupt")
    verify(Session.startsLocked(0, Session.IDLE_LOCK_MS))
    verify(!Session.startsLocked(0, Session.IDLE_LOCK_MS - 1))
    compare(Session.nextRotationIn(0, 60 * 1000), Session.ROTATE_MS - 60 * 1000)
    compare(Session.nextRotationIn(0, Session.ROTATE_MS + 5), 0)
    verify(Session.ROTATE_MS < 20 * 60 * 1000, "rotates before the controller's 20-minute access cap")
    compare(Session.sessionEffect({ ok: true, status: 401 }), "signed_out")
    compare(Session.sessionEffect({ ok: false, kind: "network" }), "retry")
    compare(Session.loginError({ ok: true, status: 401, body: { error: "invalid_credentials" } }), "signIn.invalid")
    compare(Session.loginError({ ok: true, status: 403, body: { error: "password_change_required" } }), "signIn.changePassword")
    compare(Session.loginError({ ok: false, kind: "redirect" }), "errors.redirect")
    compare(Session.loginError({ ok: false, kind: "tls" }), "errors.tls")
  }

  function test_strings_have_both_locales() {
    var english = Strings.keys("en").sort()
    var vietnamese = Strings.keys("vi").sort()
    compare(vietnamese, english)
    english.forEach(function (key) {
      verify(Strings.t("en", key).length > 0, key)
      verify(Strings.t("vi", key).length > 0, key)
      verify(!/zero[- ]knowledge|never leaves/i.test(Strings.t("en", key)), "no absolute confidentiality claim: " + key)
    })
    compare(Strings.t("vi", "confirm.cancel"), "Hủy")
    compare(Strings.tn("en", "queue.count", 1), "1 pending")
    compare(Strings.tn("en", "row.operations", 2), "2 operations")
    compare(Strings.t("fr", "confirm.cancel"), "Cancel")
    compare(Strings.t("en", "confirm.operationRecipient", { node: "n1" }), "Broker on n1")
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
// The approval app's views and state machine against a scripted fake
// controller and vault, with real key and mouse events. The real curl
// transport and helper are covered by tests/e2e against a Rust controller.
import QtQuick
import QtTest
import ".."

Item {
  id: host
  width: 460
  height: 760

  property var requests: []
  property var routes: ({})
  property var stored: ({ code: 5, text: "" })
  property var saved: []
  property int cleared: 0
  property var summaries: []
  property var remembered: []
  property double clock: 1000000

  function reply(status, body, date) { return { ok: true, status: status, body: body === undefined ? null : body, date: date === undefined ? null : date } }

  QtObject {
    id: fakeTransport
    function request(options, done) {
      host.requests = host.requests.concat([JSON.parse(JSON.stringify(options))])
      var route = options.method + " " + options.path.split("?")[0]
      var handler = host.routes[route]
      var response = handler ? handler(options) : host.reply(404, { error: "not_found" })
      Qt.callLater(function () { done(response) })
    }
  }

  QtObject {
    id: fakeVault
    function load(done) { var s = host.stored; Qt.callLater(function () { done(s.code, s.text) }) }
    function save(text, done) { host.saved = host.saved.concat([text]); host.stored = { code: 0, text: text }; Qt.callLater(function () { done(true) }) }
    function clear(done) { host.cleared += 1; host.stored = { code: 5, text: "" }; Qt.callLater(function () { done(true) }) }
    function publish(summary) { host.summaries = host.summaries.concat([summary]) }
    function rememberController(origin) { host.remembered = host.remembered.concat([origin]) }
  }

  Component {
    id: appComponent
    ApprovalApp {
      anchors.fill: parent
      transport: fakeTransport
      vault: fakeVault
      autoStart: false
      controllerOrigin: "https://controller.example"
      Component.onCompleted: controller.now = function () { return host.clock }
    }
  }

  readonly property var operation: ({
    kind: "operation", id: "oa_7", status: "pending", version: 2, operation_ids: ["op_1"],
    requester_summary: { requester: "op_rina", operator_id: "id_rina", purpose: "<b>rotate</b> the <a href='x'>db</a> password" },
    verified_identity: { tenant_id: "t", node_id: "node-db-1", workload_id: "wl_9", unit: "db.service", account: "postgres", action: "db.password", mode: "file", rule_id: "rule-db", policy_version: 1 },
    approver_ids: ["hung"], rule_id: "rule-db", expires_at: 1000000 + 90000, created_at: 900000, decided_by: null, decided_at: null,
    operations: [{ id: "op_1", requested_by: "id_rina", invocation_id: "inv-1", resource_id: "res-1", purpose: "p", broker_event_key: "k", status: "pending", created_at: 900000 }]
  })

  function session(access, refresh) {
    return { kind: "desktop", operator: { id: "id_hung", username: "hung", display_name: "Hung", role: "operator", disabled_at: null }, access_token: access, refresh_token: refresh, expires_at: 2000000, must_change_password: false }
  }

  function standardRoutes() {
    var list = [host.operation]
    return {
      "POST /api/v3/admin/session/login": function (options) {
        return options.body.password === "right-password" ? host.reply(200, host.session("access-1", "refresh-1-long-enough")) : host.reply(401, { error: "invalid_credentials" })
      },
      "POST /api/v3/admin/session/refresh": function (options) {
        return options.body.refresh_token.indexOf("refresh-") === 0 ? host.reply(200, host.session("access-2", "refresh-2-long-enough")) : host.reply(401, { error: "refresh_invalid" })
      },
      "POST /api/v3/admin/session/logout": function () { return host.reply(204) },
      "GET /api/v3/approvals": function () { return host.reply(200, { items: list, next_cursor: null, count: list.length }, 1000000) },
      "GET /api/v3/approvals/count": function () { return host.reply(200, { count: list.length }) },
      "GET /api/v3/approvals/oa_7": function () { return host.reply(200, host.operation) },
      "POST /api/v3/approvals/oa_7/approve": function () { return host.reply(200, JSON.parse(JSON.stringify(host.operation))) }
    }
  }

  TestCase {
    id: test
    name: "ApprovalAppViews"
    when: windowShown

    property var app: null

    function init() {
      host.requests = []
      host.routes = host.standardRoutes()
      host.stored = { code: 5, text: "" }
      host.saved = []
      host.cleared = 0
      host.summaries = []
      host.remembered = []
      host.clock = 1000000
      app = appComponent.createObject(host)
      verify(app !== null)
    }

    // Deferred deletes don't run inside QtTest's loop, so hide and stop the
    // previous instance explicitly before destroying it.
    function cleanup() {
      if (!app) return
      app.visible = false
      app.enabled = false
      app.controller.phase = "starting"
      app.destroy()
      app = null
    }

    function item(name) {
      var found = findChild(app, name)
      verify(found !== null, "missing " + name)
      return found
    }

    // Click after layout has run, and only an item that is actually inside
    // the window, so a mispositioned control fails loudly.
    function click(name) {
      var target = item(name)
      waitForRendering(app)
      tryVerify(function () { return target.visible && target.width > 0 })
      var point = target.mapToItem(host, target.width / 2, target.height / 2)
      verify(point.x > 0 && point.x < host.width && point.y > 0 && point.y < host.height, name + " is outside the window at " + point.x + "," + point.y)
      mouseClick(target)
    }

    function paths() {
      return host.requests.map(function (r) { return r.method + " " + r.path })
    }

    function signIn(password) {
      app.controller.start()
      tryCompare(app.controller, "phase", "signin")
      var url = item("controller-url")
      url.text = "https://controller.example"
      item("username").text = "hung"
      item("password").text = password
      click("sign-in-submit")
    }

    function signedIn() {
      signIn("right-password")
      tryCompare(app.controller, "phase", "ready")
      tryVerify(function () { return app.controller.listLoaded })
    }

    function test_sign_in_validates_the_address_before_any_request() {
      app.controller.start()
      tryCompare(app.controller, "phase", "signin")
      item("controller-url").text = "http://controller.example"
      item("username").text = "hung"
      item("password").text = "right-password"
      click("sign-in-submit")
      wait(20)
      compare(host.requests.length, 0)
      verify(findChild(app, "sign-in").urlError.indexOf("https://") !== -1)
    }

    function test_sign_in_uses_the_desktop_transport_and_stores_only_the_refresh_token() {
      signedIn()
      var login = host.requests[0]
      compare(login.path, "/api/v3/admin/session/login")
      compare(login.body.kind, "desktop")
      verify(login.bearer === undefined)
      compare(item("password").text, "", "the password field is cleared")
      compare(host.remembered, ["https://controller.example"])
      var record = JSON.parse(host.saved[host.saved.length - 1])
      compare(record.refresh_token, "refresh-1-long-enough")
      compare(record.controller, "https://controller.example")
      verify(host.saved.every(function (text) { return text.indexOf("access-1") === -1 }), "the access token is never stored")
      verify(paths().indexOf("GET /api/v3/approvals?status=pending&limit=50") !== -1)
      host.requests.slice(1).forEach(function (r) { if (r.path !== "/api/v3/admin/session/refresh") compare(r.bearer, "access-1") })
      compare(item("controller-host").text, "controller.example")
      compare(item("signed-in-as").text, "Signed in as hung")
      var summary = host.summaries[host.summaries.length - 1]
      compare(summary.state, "ready")
      compare(summary.pending, 1)
      compare(Object.keys(summary).sort(), ["pending", "state", "updated_at", "v"])
    }

    function test_wrong_and_temporary_passwords() {
      signIn("wrong-password")
      tryCompare(item("sign-in-message"), "text", "The username or password is wrong.")
      compare(item("password").text, "")
      compare(host.saved.length, 0)
      host.routes["POST /api/v3/admin/session/login"] = function () { return host.reply(403, { error: "password_change_required" }) }
      item("password").text = "temporary-one"
      click("sign-in-submit")
      tryVerify(function () { return item("sign-in-message").text.indexOf("temporary") !== -1 })
      compare(app.controller.phase, "signin")
    }

    function test_redirect_and_tls_failures_are_named() {
      host.routes["POST /api/v3/admin/session/login"] = function () { return { ok: false, kind: "redirect", status: 307 } }
      signIn("right-password")
      tryVerify(function () { return item("sign-in-message").text.indexOf("redirect") !== -1 })
      host.routes["POST /api/v3/admin/session/login"] = function () { return { ok: false, kind: "tls" } }
      item("password").text = "right-password"
      click("sign-in-submit")
      tryVerify(function () { return item("sign-in-message").text.indexOf("certificate") !== -1 })
    }

    function test_a_stored_session_rotates_on_start() {
      host.stored = { code: 0, text: JSON.stringify({ v: 1, controller: "https://controller.example", refresh_token: "refresh-0-long-enough", username: "hung", last_active_at: host.clock - 1000 }) }
      app.controller.start()
      tryCompare(app.controller, "phase", "ready")
      compare(host.requests[0].path, "/api/v3/admin/session/refresh")
      compare(host.requests[0].body.refresh_token, "refresh-0-long-enough")
      compare(JSON.parse(host.saved[0]).refresh_token, "refresh-2-long-enough", "the rotated token replaces the used one")
      tryVerify(function () { return app.controller.listLoaded })
    }

    function test_a_session_for_another_controller_is_deleted_unsent() {
      host.stored = { code: 0, text: JSON.stringify({ v: 1, controller: "https://old.example", refresh_token: "refresh-0-long-enough", username: "hung", last_active_at: host.clock }) }
      app.controller.start()
      tryCompare(app.controller, "phase", "signin")
      compare(host.requests.length, 0)
      compare(host.cleared, 1)
      verify(item("sign-in-message").text.indexOf("different controller") !== -1)
    }

    function test_an_idle_restart_opens_locked_with_counts_only() {
      host.stored = { code: 0, text: JSON.stringify({ v: 1, controller: "https://controller.example", refresh_token: "refresh-0-long-enough", username: "hung", last_active_at: host.clock - 11 * 60 * 1000 }) }
      app.controller.start()
      tryCompare(app.controller, "phase", "locked")
      tryVerify(function () { return paths().indexOf("GET /api/v3/approvals/count") !== -1 })
      verify(paths().every(function (p) { return p.indexOf("GET /api/v3/approvals?") !== 0 }), "no list while locked")
      compare(app.controller.approvals.length, 0)
      tryCompare(item("locked-count"), "text", "1 pending")
    }

    function test_detail_leads_with_recipient_and_renders_purpose_as_plain_text() {
      signedIn()
      click("approval-oa_7")
      tryCompare(app.controller, "view", "detail")
      compare(item("authority-recipient").text, "Broker on node-db-1")
      compare(item("authority-scope").text, "db.password for db.service as postgres (file)")
      var purpose = item("purpose")
      compare(purpose.textFormat, Text.PlainText)
      compare(purpose.text, "<b>rotate</b> the <a href='x'>db</a> password")
      compare(item("detail-title").text, "db.password for db.service")
      verify(item("detail-window").text.indexOf("1:") !== -1, "countdown on the controller clock")
    }

    function test_the_confirm_dialog_defaults_to_cancel_and_has_no_approve_shortcut() {
      signedIn()
      app.controller.open(host.operation)
      tryCompare(app.controller, "view", "detail")
      click("approve")
      tryCompare(app.controller, "decisionPhase", "confirm")
      compare(item("confirm-title").text, "Approve 1 operation?")
      compare(item("confirm-recipient").text, "Broker on node-db-1")
      verify(item("confirm-cancel").activeFocus, "Cancel has focus")
      keyClick(Qt.Key_Return)
      tryCompare(app.controller, "decisionPhase", "idle")
      verify(paths().every(function (p) { return p.indexOf("/approve") === -1 }), "Return on the default button cancels")
      click("approve")
      tryCompare(app.controller, "decisionPhase", "confirm")
      keyClick(Qt.Key_A)
      keyClick(Qt.Key_Y)
      keyClick(Qt.Key_Escape)
      tryCompare(app.controller, "decisionPhase", "idle")
      verify(paths().every(function (p) { return p.indexOf("/approve") === -1 }), "no key approves")
    }

    function test_approving_rechecks_then_sends_an_idempotent_decision() {
      signedIn()
      app.controller.open(host.operation)
      tryCompare(app.controller, "view", "detail")
      click("approve")
      tryCompare(app.controller, "decisionPhase", "confirm")
      keyClick(Qt.Key_Tab)
      verify(item("confirm-decide").activeFocus)
      host.routes["GET /api/v3/approvals/count"] = function () { return host.reply(200, { count: 0 }) }
      host.routes["GET /api/v3/approvals"] = function () { return host.reply(200, { items: [], next_cursor: null, count: 0 }) }
      var before = host.requests.length
      keyClick(Qt.Key_Space)
      tryVerify(function () { return item("decision-message").text.indexOf("Approved") === 0 })
      var sent = host.requests.slice(before)
      compare(sent[0].method + " " + sent[0].path, "GET /api/v3/approvals/oa_7", "rechecks first")
      var decision = sent.filter(function (r) { return r.path === "/api/v3/approvals/oa_7/approve" })
      compare(decision.length, 1)
      compare(decision[0].bearer, "access-1")
      compare(decision[0].headers["If-Match"], "\"2\"")
      compare(decision[0].headers["Idempotency-Key"].length, 64)
      compare(decision[0].body.operation_ids, ["op_1"])
    }

    function test_a_changed_approval_is_not_decided() {
      signedIn()
      app.controller.open(host.operation)
      tryCompare(app.controller, "view", "detail")
      tryVerify(function () { return paths().indexOf("GET /api/v3/approvals/oa_7") !== -1 })
      host.routes["GET /api/v3/approvals/oa_7"] = function () {
        var changed = JSON.parse(JSON.stringify(host.operation))
        changed.version = 3
        changed.operation_ids = ["op_1", "op_2"]
        return host.reply(200, changed)
      }
      app.controller.requestDecision("approve")
      app.controller.confirmDecision()
      tryVerify(function () { return item("decision-message").text.indexOf("changed") !== -1 })
      verify(paths().every(function (p) { return p.indexOf("/approve") === -1 }))
    }

    function test_unnamed_and_self_requests_cannot_be_opened_for_decision() {
      signedIn()
      var other = JSON.parse(JSON.stringify(host.operation))
      other.approver_ids = ["someone-else"]
      host.routes["GET /api/v3/approvals/oa_7"] = function () { return host.reply(200, other) }
      app.controller.open(other)
      tryVerify(function () { return item("decision-block").text !== "" })
      verify(!item("approve").enabled)
      verify(!item("reject").enabled)
      verify(item("approve").description.indexOf("named approver") !== -1)
      app.controller.requestDecision("approve")
      compare(app.controller.decisionPhase, "idle")
    }

    function test_an_expired_access_token_rotates_once_and_retries() {
      signedIn()
      var calls = 0
      host.routes["GET /api/v3/approvals/count"] = function (options) {
        calls += 1
        return options.bearer === "access-2" ? host.reply(200, { count: 4 }) : host.reply(401, { error: "session_expired" })
      }
      app.controller.pollCount()
      tryCompare(app.controller, "pendingCount", 4)
      compare(calls, 2)
      compare(app.controller.phase, "ready")
    }

    function test_a_revoked_session_signs_out_and_deletes_the_file() {
      signedIn()
      host.routes["GET /api/v3/approvals/count"] = function () { return host.reply(401, { error: "session_expired" }) }
      host.routes["POST /api/v3/admin/session/refresh"] = function () { return host.reply(401, { error: "refresh_invalid" }) }
      app.controller.pollCount()
      tryCompare(app.controller, "phase", "signin")
      compare(host.cleared, 1)
      compare(app.controller.accessToken, "")
      compare(app.controller.refreshToken, "")
      compare(host.summaries[host.summaries.length - 1].state, "signed_out")
      compare(host.summaries[host.summaries.length - 1].pending, null)
      verify(item("sign-in-message").text.indexOf("ended") !== -1)
    }

    function test_idle_lock_clears_details_and_unlock_revokes_the_old_session() {
      signedIn()
      app.controller.open(host.operation)
      tryCompare(app.controller, "view", "detail")
      host.clock += 10 * 60 * 1000
      app.controller.checkIdle()
      compare(app.controller.phase, "locked")
      compare(app.controller.selected, null)
      compare(app.controller.approvals.length, 0)
      compare(host.summaries[host.summaries.length - 1].state, "locked")
      host.routes["POST /api/v3/admin/session/login"] = function (options) {
        compare(options.body.username, "hung")
        return options.body.password === "right-password" ? host.reply(200, host.session("access-9", "refresh-9-long-enough")) : host.reply(401, { error: "invalid_credentials" })
      }
      var before = host.requests.length
      item("unlock-password").text = "right-password"
      click("unlock")
      tryCompare(app.controller, "phase", "ready")
      var logout = host.requests.slice(before).filter(function (r) { return r.path === "/api/v3/admin/session/logout" })
      compare(logout.length, 1)
      compare(logout[0].bearer, "access-1", "the previous session is revoked")
      compare(app.controller.accessToken, "access-9")
    }

    function test_sign_out_revokes_on_the_controller_then_forgets() {
      signedIn()
      click("sign-out")
      tryCompare(app.controller, "phase", "signin")
      var logout = host.requests.filter(function (r) { return r.path === "/api/v3/admin/session/logout" })
      compare(logout.length, 1)
      compare(logout[0].bearer, "access-1")
      compare(host.cleared, 1)
      verify(item("sign-in-message").text.indexOf("ended on the controller") !== -1)
      host.routes["POST /api/v3/admin/session/logout"] = function () { return { ok: false, kind: "network" } }
      item("password").text = "right-password"
      click("sign-in-submit")
      tryCompare(app.controller, "phase", "ready")
      click("sign-out")
      tryCompare(app.controller, "phase", "signin")
      verify(item("sign-in-message").text.indexOf("couldn't be told") !== -1, "an unconfirmed revocation is said plainly")
      compare(host.cleared, 2)
    }

    function test_vietnamese() {
      click("language-vi")
      compare(app.locale, "vi")
      signedIn()
      compare(item("signed-in-as").text, "Đăng nhập với tên hung")
      app.controller.open(host.operation)
      tryCompare(app.controller, "view", "detail")
      compare(item("authority-recipient").text, "Broker trên node-db-1")
      click("reject")
      tryCompare(item("confirm-title"), "text", "Từ chối yêu cầu này?")
      compare(item("confirm-cancel").text, "Hủy")
    }
  }
}

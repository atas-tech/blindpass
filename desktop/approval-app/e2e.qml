// SPDX-License-Identifier: AGPL-3.0-only
//
// P04-E02 approval-app scenarios for crates/blindpass-controller/tests/
// desktop_app_e2e.rs. Test-only: it lives beside shell.qml because
// Quickshell resolves QML types only inside the config folder. Runs the real app (CurlTransport, SessionVault and
// the session-store helper) under Quickshell against a real controller and
// prints one "E2E PASS|FAIL <step>" line per step. The driver seeds the
// controller, picks the phase and checks the database afterwards.
//
// Steps drive the same functions the views call (signIn, open,
// requestDecision, confirmDecision, signOut); key and pointer handling is
// covered by tests/tst_app.qml.
import QtQuick
import Quickshell
import Quickshell.Io

ShellRoot {
  id: shell
  readonly property string phase: Quickshell.env("BLINDPASS_E2E_PHASE")
  readonly property string controllerUrl: Quickshell.env("BLINDPASS_E2E_CONTROLLER")
  readonly property string username: Quickshell.env("BLINDPASS_E2E_USER")
  readonly property string password: Quickshell.env("BLINDPASS_E2E_PASSWORD")
  readonly property string approvalId: Quickshell.env("BLINDPASS_E2E_APPROVAL")
  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") + "/blindpass"
  property int failures: 0
  property var steps: []
  readonly property var controller: appItem.controller

  CurlTransport { id: curlTransport }
  SessionVault { id: sessionVault }

  FloatingWindow {
    id: window
    visible: true
    implicitWidth: 460
    implicitHeight: 700
    ApprovalApp {
      id: appItem
      anchors.fill: parent
      autoStart: false
      transport: curlTransport
      vault: sessionVault
      controllerOrigin: shell.controllerUrl
    }
  }

  FileView { id: summaryFile; path: shell.runtimeDir + "/summary.json"; printErrors: false; blockLoading: true }

  function pass(name) { console.info("E2E PASS " + name) }
  function fail(name, why) { failures += 1; console.info("E2E FAIL " + name + ": " + why) }
  function check(name, condition, why) { if (condition) pass(name); else fail(name, why || "condition false") }

  // Run steps in order. A step is { name, run(next) } or { name, until, timeout }.
  function runSteps(list) { steps = list; advance() }
  function advance() {
    if (steps.length === 0) { finish(); return }
    var step = steps[0]
    steps = steps.slice(1)
    if (step.run) {
      step.run(advance)
      return
    }
    waiter.step = step
    waiter.deadline = Date.now() + (step.timeout || 15000)
    waiter.start()
  }
  Timer {
    id: waiter
    property var step: null
    property double deadline: 0
    interval: 50
    repeat: true
    onTriggered: {
      var ok = false
      try { ok = step.until() } catch (error) { ok = false }
      if (ok) { stop(); shell.pass(step.name); shell.advance(); return }
      if (Date.now() > deadline) { stop(); shell.fail(step.name, step.describe ? step.describe() : "timed out"); shell.finish() }
    }
  }
  function finish() {
    console.info("E2E DONE failures=" + failures)
    Qt.exit(failures === 0 ? 0 : 1)
  }

  function vaultRecord(done) {
    sessionVault.load(function (code, text) { done(code, text) })
  }

  function summary() {
    summaryFile.reload()
    try { return JSON.parse(summaryFile.text()) } catch (error) { return null }
  }

  function firstRun() {
    runSteps([
      { name: "starts signed out", run: function (next) { controller.start(); next() } },
      { name: "sign-in view", until: function () { return controller.phase === "signin" } },
      { name: "sign in over the desktop transport", run: function (next) { controller.signIn(controllerUrl, username, password); next() } },
      { name: "signed in", until: function () { return controller.phase === "ready" && controller.accessToken !== "" }, describe: function () { return "phase " + controller.phase + " message " + controller.signInMessage } },
      { name: "pending list includes the seeded approval", until: function () { return controller.listLoaded && controller.approvals.some(function (a) { return a.id === approvalId }) } },
      { name: "server clock known from the Date header", until: function () { return controller.serverClockKnown } },
      { name: "refresh token stored, access token not", run: function (next) {
          vaultRecord(function (code, text) {
            var record = null
            try { record = JSON.parse(text) } catch (error) {}
            check("vault record", code === 0 && record && record.refresh_token === controller.refreshToken && text.indexOf(controller.accessToken) === -1 && record.controller === controller.controllerInfo.origin, "code " + code)
            next()
          })
        } },
      { name: "widget summary is metadata only", until: function () {
          var s = summary()
          return s !== null && JSON.stringify(Object.keys(s).sort()) === JSON.stringify(["pending", "state", "updated_at", "v"]) && s.state === "ready" && s.pending >= 1
        } },
      { name: "open the approval", run: function (next) {
          controller.open(controller.approvals.filter(function (a) { return a.id === approvalId })[0])
          next()
        } },
      { name: "detail loaded with member operations", until: function () { return controller.selected && controller.selected.operations && controller.selected.operations.length === 1 } },
      { name: "approve", run: function (next) { controller.requestDecision("approve"); controller.confirmDecision(); next() } },
      { name: "controller recorded the approval", until: function () { return controller.decisionMessage === "result.approved" }, describe: function () { return "message " + controller.decisionMessage + " " + controller.decisionCode } },
      { name: "detail shows approved", until: function () { return controller.selected && controller.selected.status === "approved" } }
    ])
  }

  function restartRun() {
    runSteps([
      { name: "restart resumes from the stored session", run: function (next) { controller.start(); next() } },
      { name: "rotated and ready", until: function () { return controller.phase === "ready" && controller.accessToken !== "" }, describe: function () { return "phase " + controller.phase + " message " + controller.signInMessage } },
      { name: "rotated token stored", run: function (next) {
          vaultRecord(function (code, text) {
            var record = null
            try { record = JSON.parse(text) } catch (error) {}
            check("stored token is the rotated one", code === 0 && record && record.refresh_token === controller.refreshToken, "code " + code)
            next()
          })
        } },
      { name: "sign out", run: function (next) { controller.signOut(); next() } },
      { name: "signed out after server revocation", until: function () { return controller.phase === "signin" && controller.signInMessage === "signIn.signedOut" }, describe: function () { return controller.signInMessage } },
      { name: "session file deleted", run: function (next) {
          vaultRecord(function (code) { check("no stored session", code === 5, "code " + code); next() })
        } },
      { name: "summary says signed out", until: function () { var s = summary(); return s && s.state === "signed_out" && s.pending === null } }
    ])
  }

  function revokedRun() {
    runSteps([
      { name: "start with a revoked refresh token", run: function (next) { controller.start(); next() } },
      { name: "controller 401 signs out", until: function () { return controller.phase === "signin" && controller.signInMessage === "signIn.expired" }, describe: function () { return controller.phase + " " + controller.signInMessage } },
      { name: "revoked token deleted", run: function (next) {
          vaultRecord(function (code) { check("no stored session", code === 5, "code " + code); next() })
        } }
    ])
  }

  function refusedRun(expected) {
    runSteps([
      { name: "start", run: function (next) { controller.start(); next() } },
      { name: "sign-in view", until: function () { return controller.phase === "signin" } },
      { name: "sign in", run: function (next) { controller.signIn(controllerUrl, username, password); next() } },
      { name: "refused as " + expected, until: function () { return !controller.signInBusy && controller.signInMessage === expected }, describe: function () { return controller.signInMessage } },
      { name: "nothing stored", run: function (next) { vaultRecord(function (code) { check("no stored session", code === 5, "code " + code); next() }) } }
    ])
  }

  Component.onCompleted: Qt.callLater(function () {
    if (phase === "first") firstRun()
    else if (phase === "restart") restartRun()
    else if (phase === "revoked") revokedRun()
    else if (phase === "redirect") refusedRun("errors.redirect")
    else if (phase === "tls") refusedRun("errors.tls")
    else { fail("phase", "unknown phase " + phase); finish() }
  })
}

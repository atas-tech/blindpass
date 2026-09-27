// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "lib/transport.js" as Transport
import "lib/session.js" as Session
import "lib/model.js" as Model

// The approval app's state machine, free of Quickshell so qmltestrunner can
// drive it with a fake transport and vault. shell.qml supplies the real
// curl transport and the session-store helper.
//
//   transport.request({origin, method, path, bearer?, body?, headers?}, done(response))
//     response: { ok, status, body, date } | { ok: false, kind }
//   vault.load(done(code, text))   code 0 found, 5 none, other failure
//   vault.save(text, done(ok)) · vault.clear(done(ok)) · vault.publish(summary)
//   vault.rememberController(origin)
//
// Plaintext: none. The app handles approval metadata only; the password
// exists in the sign-in field and one login request; the access token only
// in `accessToken`; the refresh token in `refreshToken` and the vault file.
Item {
  id: root

  property var transport: null
  property var vault: null
  property var now: function () { return Date.now() }
  property var randomByte: function () { return Math.floor(Math.random() * 256) }
  property bool windowVisible: true
  property bool autoStart: true

  // Configuration.
  property string controllerOrigin: ""
  readonly property var controllerInfo: Transport.parseController(controllerOrigin)

  // Session.
  property string phase: "starting" // starting | signin | ready | locked
  property var operator: null
  property string accessToken: ""
  property string refreshToken: ""
  property double rotatedAt: 0
  property double lastInputAt: 0
  property double lastPersistedInputAt: 0
  property bool rotating: false
  property string signInMessage: ""
  property string signInTone: "info"
  property bool signInBusy: false
  property string unlockError: ""
  property bool unlockBusy: false

  // Data.
  property var approvals: []
  property int pendingCount: 0
  property bool listLoaded: false
  property bool listLoading: false
  property bool listTruncated: false
  property double listUpdatedAt: 0
  property string connectionProblem: "" // message key while the controller is unreachable
  property double serverOffset: 0
  property bool serverClockKnown: false

  // Detail and decision.
  property string view: "queue" // queue | detail
  property var selected: null
  property bool detailMissing: false
  property string decisionVerb: "" // "" | approve | reject
  property string decisionPhase: "idle" // idle | confirm | checking | sending
  property string decisionMessage: ""
  property string decisionTone: "info"
  property string pendingKey: ""

  signal lockedOut()

  function serverNow() {
    return now() + serverOffset
  }

  function noteClock(response) {
    if (response && response.ok && typeof response.date === "number") {
      // The Date header has one-second resolution; count it against the
      // remaining window so a countdown never runs long.
      serverOffset = response.date + 1000 - now()
      serverClockKnown = true
    }
  }

  // ----- lifecycle -------------------------------------------------------

  Component.onCompleted: if (autoStart) start()

  function start() {
    phase = "starting"
    if (!controllerInfo.ok) {
      phase = "signin"
      publish("signed_out")
      return
    }
    vault.load(function (code, text) {
      if (code !== 0) {
        phase = "signin"
        publish("signed_out")
        return
      }
      var stored = Session.readRecord(text, controllerInfo.origin)
      if (!stored.ok) {
        vault.clear(function () {})
        if (stored.reason === "other_controller") setSignInMessage("signIn.otherController", "warn")
        phase = "signin"
        publish("signed_out")
        return
      }
      refreshToken = stored.record.refresh_token
      operator = { username: stored.record.username }
      var lockOnStart = Session.startsLocked(stored.record.last_active_at, now())
      lastInputAt = lockOnStart ? stored.record.last_active_at : now()
      lastPersistedInputAt = lastInputAt
      // Every start rotates: the stored refresh token is used once.
      rotate(function (ok) {
        if (!ok) return
        if (lockOnStart) {
          enterLocked()
        } else {
          phase = "ready"
          loadQueue()
        }
        pollCount()
      })
    })
  }

  function setSignInMessage(key, tone) {
    signInMessage = key
    signInTone = tone || "info"
  }

  function adopt(body) {
    accessToken = body.access_token
    refreshToken = body.refresh_token
    operator = body.operator
    rotatedAt = now()
  }

  function persist(done) {
    var record = Session.record(controllerInfo.origin, refreshToken, operator ? operator.username : "", lastInputAt)
    lastPersistedInputAt = lastInputAt
    vault.save(JSON.stringify(record), function (ok) {
      if (!ok) setSignInMessage("signIn.storeFailed", "warn")
      if (done) done(ok)
    })
  }

  /** "" when the address is acceptable, else a url.* message key. */
  function validateController(controllerText) {
    var info = Transport.parseController(controllerText)
    return info.ok ? "" : "url." + info.reason
  }

  function signIn(controllerText, username, password) {
    var info = Transport.parseController(controllerText)
    if (!info.ok) return "url." + info.reason
    if (signInBusy) return ""
    signInBusy = true
    setSignInMessage("", "info")
    controllerOrigin = info.origin
    transport.request({
      origin: info.origin,
      method: "POST",
      path: "/api/v3/admin/session/login",
      body: { username: username, password: password, kind: "desktop" }
    }, function (response) {
      signInBusy = false
      noteClock(response)
      if (response.ok && response.status === 200 && response.body && response.body.access_token) {
        adopt(response.body)
        lastInputAt = now()
        vault.rememberController(info.origin)
        persist()
        phase = "ready"
        view = "queue"
        connectionProblem = ""
        loadQueue()
        pollCount()
        return
      }
      setSignInMessage(Session.loginError(response), "danger")
    })
    return ""
  }

  property var rotationWaiters: []

  /** Rotate the refresh token. Concurrent callers share one request. */
  function rotate(done) {
    if (done) rotationWaiters = rotationWaiters.concat([done])
    if (rotating) return
    rotating = true
    var finish = function (ok) {
      var waiting = rotationWaiters
      rotationWaiters = []
      waiting.forEach(function (callback) { callback(ok) })
    }
    transport.request({
      origin: controllerInfo.origin,
      method: "POST",
      path: "/api/v3/admin/session/refresh",
      body: { kind: "desktop", refresh_token: refreshToken }
    }, function (response) {
      rotating = false
      noteClock(response)
      if (response.ok && response.status === 200 && response.body && response.body.access_token) {
        adopt(response.body)
        connectionProblem = ""
        persist()
        finish(true)
        return
      }
      if (response.ok && (response.status === 401 || response.status === 403)) {
        endSession("signIn.expired", "warn")
        finish(false)
        return
      }
      // Unreachable: keep the refresh token and try again on the next tick.
      connectionProblem = "errors.offline"
      if (phase === "starting") {
        // Without a fresh access token nothing can load yet; stay locked
        // until the controller answers.
        enterLocked()
        publish("unreachable")
      }
      finish(false)
    })
  }

  /** An authenticated call. A 401 rotates once and retries; a second 401 ends the session. */
  function call(method, path, options, done, retried) {
    options = options || {}
    transport.request({
      origin: controllerInfo.origin,
      method: method,
      path: path,
      bearer: accessToken,
      body: options.body,
      headers: options.headers
    }, function (response) {
      noteClock(response)
      if (response.ok && response.status === 401 && !retried && refreshToken !== "") {
        rotate(function (ok) {
          if (ok) call(method, path, options, done, true)
          else done({ ok: true, status: 401, body: null, handled: true })
        })
        return
      }
      if (response.ok && response.status === 401) {
        endSession("signIn.expired", "warn")
        response.handled = true
      }
      if (!response.ok) connectionProblem = "errors.offline"
      else if (response.status < 500) connectionProblem = ""
      done(response)
    })
  }

  function endSession(messageKey, tone) {
    accessToken = ""
    refreshToken = ""
    approvals = []
    selected = null
    pendingCount = 0
    listLoaded = false
    view = "queue"
    decisionPhase = "idle"
    decisionVerb = ""
    phase = "signin"
    vault.clear(function () {})
    publish("signed_out")
    setSignInMessage(messageKey, tone)
  }

  function signOut() {
    var token = accessToken
    if (token === "") {
      endSession("signIn.signedOut", "info")
      return
    }
    transport.request({ origin: controllerInfo.origin, method: "POST", path: "/api/v3/admin/session/logout", bearer: token }, function (response) {
      var revoked = response.ok && (response.status === 204 || response.status === 401)
      endSession(revoked ? "signIn.signedOut" : "signIn.signedOutLocal", revoked ? "info" : "warn")
    })
  }

  // ----- idle lock ----------------------------------------------------------

  function noteInput() {
    if (phase !== "ready") return
    lastInputAt = now()
    // Persist the activity time at most once a minute so a restart knows
    // whether to open locked.
    if (lastInputAt - lastPersistedInputAt >= 60 * 1000) persist()
  }

  function checkIdle() {
    if (phase === "ready" && decisionPhase !== "sending" && Session.shouldLock(lastInputAt, now())) enterLocked()
  }

  function checkRotation() {
    if ((phase === "ready" || phase === "locked") && (accessToken === "" || Session.nextRotationIn(rotatedAt, now()) === 0)) rotate()
  }

  function enterLocked() {
    phase = "locked"
    approvals = []
    selected = null
    view = "queue"
    decisionPhase = "idle"
    decisionVerb = ""
    unlockError = ""
    publish("locked")
    lockedOut()
  }

  function lockNow() {
    if (phase !== "ready") return
    lastInputAt = now() - Session.IDLE_LOCK_MS
    persist()
    enterLocked()
  }

  /** Unlock with the password: a fresh desktop login, then the old session is revoked. */
  function unlock(password) {
    if (unlockBusy || !operator) return
    unlockBusy = true
    unlockError = ""
    var previous = accessToken
    transport.request({
      origin: controllerInfo.origin,
      method: "POST",
      path: "/api/v3/admin/session/login",
      body: { username: operator.username, password: password, kind: "desktop" }
    }, function (response) {
      unlockBusy = false
      noteClock(response)
      if (response.ok && response.status === 200 && response.body && response.body.access_token) {
        if (previous !== "") {
          transport.request({ origin: controllerInfo.origin, method: "POST", path: "/api/v3/admin/session/logout", bearer: previous }, function () {})
        }
        adopt(response.body)
        lastInputAt = now()
        persist()
        phase = "ready"
        connectionProblem = ""
        loadQueue()
        pollCount()
        return
      }
      unlockError = Session.loginError(response)
    })
  }

  // ----- data -----------------------------------------------------------------

  function publish(state) {
    if (vault) vault.publish(Model.widgetSummary(state, pendingCount, now()))
  }

  function loadQueue() {
    if (phase !== "ready" || listLoading) return
    listLoading = true
    call("GET", "/api/v3/approvals?status=pending&limit=50", {}, function (response) {
      listLoading = false
      if (response.handled) return
      if (response.ok && response.status === 200 && response.body && Array.isArray(response.body.items)) {
        approvals = response.body.items.filter(function (item) { return item.status === "pending" })
        if (typeof response.body.count === "number") pendingCount = response.body.count
        listTruncated = response.body.next_cursor !== null && response.body.next_cursor !== undefined
        listLoaded = true
        listUpdatedAt = now()
        publish("ready")
      } else if (response.ok && response.status === 403) {
        connectionProblem = "errors.forbidden"
      } else if (response.ok && response.status === 404) {
        connectionProblem = "errors.noFleet"
      }
    })
  }

  function pollCount() {
    if (phase !== "ready" && phase !== "locked") return
    call("GET", "/api/v3/approvals/count", {}, function (response) {
      if (response.handled) return
      if (response.ok && response.status === 200 && response.body && typeof response.body.count === "number") {
        pendingCount = response.body.count
        publish(phase === "locked" ? "locked" : "ready")
      } else if (!response.ok) {
        publish("unreachable")
      }
    })
  }

  function open(approval) {
    if (phase !== "ready") return
    selected = approval
    detailMissing = false
    decisionMessage = ""
    decisionPhase = "idle"
    view = "detail"
    reloadDetail()
  }

  function reloadDetail(done) {
    if (!selected) return
    call("GET", "/api/v3/approvals/" + encodeURIComponent(Model.key(selected)), {}, function (response) {
      if (response.handled) return
      if (response.ok && response.status === 200 && response.body) {
        selected = response.body
        detailMissing = false
      } else if (response.ok && response.status === 404) {
        detailMissing = true
      }
      if (done) done(response)
    })
  }

  function back() {
    view = "queue"
    selected = null
    decisionPhase = "idle"
    decisionVerb = ""
    decisionMessage = ""
    loadQueue()
  }

  function requestDecision(verb) {
    if (phase !== "ready" || !selected || decisionPhase !== "idle") return
    if (Model.decisionBlock(selected, operator) !== null) return
    decisionVerb = verb
    decisionMessage = ""
    decisionPhase = "confirm"
  }

  function cancelDecision() {
    if (decisionPhase === "sending") return
    decisionPhase = "idle"
    decisionVerb = ""
  }

  function confirmDecision() {
    if (decisionPhase !== "confirm" || !selected) return
    var verb = decisionVerb
    var before = Model.fingerprint(selected)
    decisionPhase = "checking"
    reloadDetail(function (response) {
      if (!(response.ok && response.status === 200)) {
        decisionPhase = "idle"
        decisionVerb = ""
        showDecision(response.ok && response.status === 404 ? "result.gone" : "confirm.unknown", "warn")
        return
      }
      if (Model.fingerprint(selected) !== before || Model.decisionBlock(selected, operator) !== null) {
        decisionPhase = "idle"
        decisionVerb = ""
        showDecision("confirm.changed", "warn")
        return
      }
      decisionPhase = "sending"
      pendingKey = Model.idempotencyKey(root.randomByte)
      var request = Model.decisionRequest(selected, verb, pendingKey)
      call("POST", request.path, { body: request.body, headers: request.headers }, function (result) {
        decisionPhase = "idle"
        decisionVerb = ""
        if (result.handled) return
        if (result.ok && result.status === 200) {
          showDecision(verb === "approve" ? "result.approved" : "result.rejected", "ok")
          reloadDetail()
          loadQueue()
          pollCount()
          return
        }
        var code = result.ok && result.body ? result.body.error : ""
        if (result.ok && (result.status === 409 || result.status === 404 || result.status === 412)) showDecision("result.gone", "warn")
        else if (code === "approval_scope_denied") showDecision("result.scope", "danger")
        else if (code === "self_approval_denied") showDecision("result.self", "danger")
        else if (!result.ok || result.status >= 500) showDecision("confirm.unknown", "warn")
        else showDecision("result.failed", "danger", code || String(result.status))
        reloadDetail()
      })
    })
  }

  property string decisionCode: ""
  function showDecision(key, tone, code) {
    decisionMessage = key
    decisionTone = tone
    decisionCode = code || ""
  }

  // ----- timers ---------------------------------------------------------------

  Timer {
    id: rotationTimer
    interval: 30 * 1000
    repeat: true
    running: root.phase === "ready" || root.phase === "locked"
    onTriggered: root.checkRotation()
  }

  Timer {
    id: idleTimer
    interval: 15 * 1000
    repeat: true
    running: root.phase === "ready"
    onTriggered: root.checkIdle()
  }

  Timer {
    id: countTimer
    interval: Session.COUNT_POLL_MS
    repeat: true
    running: root.phase === "ready" || root.phase === "locked"
    onTriggered: root.pollCount()
  }

  Timer {
    id: listTimer
    interval: Session.LIST_POLL_MS
    repeat: true
    running: root.phase === "ready" && root.windowVisible && root.view === "queue"
    onTriggered: root.loadQueue()
  }
}

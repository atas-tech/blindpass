// SPDX-License-Identifier: AGPL-3.0-only
// P04-I04 (widget portion): the widget's summary reader and a source
// inspection that it has no path to credentials, the controller or approval.
import QtQuick
import QtTest
import "../summary.js" as Summary

TestCase {
  name: "OmarchyWidget"

  readonly property double now: 5000000

  function summary(fields) {
    var base = { v: 1, state: "ready", pending: 2, updated_at: now - 1000 }
    for (var key in fields) base[key] = fields[key]
    return JSON.stringify(base)
  }

  function test_reads_only_the_allowed_fields() {
    var view = Summary.read(summary({ refresh_token: "should-be-ignored", access_token: "x", approvals: [{ id: "oa_1" }] }), now)
    compare(Object.keys(view).sort(), ["pending", "state"])
    compare(view.state, "ready")
    compare(view.pending, 2)
  }

  function test_states_data() {
    return [
      { tag: "ready", fields: {}, state: "ready", pending: 2, label: "2", urgent: true },
      { tag: "nothing waiting", fields: { pending: 0 }, state: "ready", pending: 0, label: "", urgent: false },
      { tag: "locked", fields: { state: "locked", pending: 3 }, state: "locked", pending: 3, label: "3", urgent: true },
      { tag: "signed out hides the count", fields: { state: "signed_out", pending: 5 }, state: "signed_out", pending: null, label: "", urgent: false },
      { tag: "unreachable", fields: { state: "unreachable", pending: null }, state: "unreachable", pending: null, label: "", urgent: false },
      { tag: "stale", fields: { updated_at: 5000000 - 91000 }, state: "not_running", pending: null, label: "", urgent: false },
      { tag: "future", fields: { updated_at: 5000000 + 91000 }, state: "not_running", pending: null, label: "", urgent: false },
      { tag: "unknown state", fields: { state: "approve_all" }, state: "not_running", pending: null, label: "", urgent: false },
      { tag: "wrong version", fields: { v: 2 }, state: "not_running", pending: null, label: "", urgent: false },
      { tag: "negative count", fields: { pending: -1 }, state: "ready", pending: null, label: "", urgent: false },
      { tag: "huge count", fields: { pending: 1e9 }, state: "ready", pending: 9999, label: "99+", urgent: true },
      { tag: "string count", fields: { pending: "7" }, state: "ready", pending: null, label: "", urgent: false }
    ]
  }

  function test_states(data) {
    var view = Summary.read(summary(data.fields), now)
    compare(view.state, data.state)
    compare(view.pending, data.pending)
    compare(Summary.label(view), data.label)
    compare(Summary.urgent(view), data.urgent)
    verify(Summary.tooltip(view).indexOf("BlindPass") === 0)
  }

  function test_missing_or_corrupt_file() {
    compare(Summary.read("", now).state, "not_running")
    compare(Summary.read("{", now).state, "not_running")
    compare(Summary.read("null", now).state, "not_running")
  }

  function source(name) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", Qt.resolvedUrl("../" + name), false)
    xhr.send()
    return xhr.responseText
  }

  function test_widget_source_has_no_credential_or_approval_path() {
    var text = source("Widget.qml") + "\n" + source("summary.js")
    verify(text.length > 1000, "sources were read")
    var forbidden = ["blindpass/session", "blindpass-session-store", "refresh_token\"", "Authorization", "curl", "/api/", "XMLHttpRequest", "approve(", "decide", "Process {", "IpcHandler"]
    forbidden.forEach(function (needle) {
      verify(text.indexOf(needle) === -1, "widget source must not contain " + needle)
    })
    verify(text.indexOf("summary.json") !== -1)
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import Quickshell
import Quickshell.Io

// Storage for the approval app, through bin/blindpass-session-store. Calls
// run one at a time in order, so a sign-out's delete can't race an earlier
// write. Records go to the helper's stdin; nothing is logged.
//
// The non-secret settings file ($XDG_CONFIG_HOME/blindpass/approval-app.json)
// holds only the controller address and language.
Item {
  id: root
  readonly property string helper: decodeURIComponent(Qt.resolvedUrl("bin/blindpass-session-store").toString().replace(/^file:\/\//, ""))
  readonly property string configDir: (Quickshell.env("XDG_CONFIG_HOME") || (Quickshell.env("HOME") + "/.config")) + "/blindpass"
  readonly property string settingsPath: configDir + "/approval-app.json"
  property var queue: []
  property bool busy: false
  property var settings: ({})

  function enqueue(argv, input, done) {
    queue = queue.concat([{ argv: argv, input: input, done: done }])
    pump()
  }

  function pump() {
    if (busy || queue.length === 0) return
    var job = queue[0]
    queue = queue.slice(1)
    busy = true
    var process = helperProcess.createObject(root, { command: job.argv, input: job.input === null ? "" : job.input, feed: job.input !== null, done: job.done })
    process.running = true
  }

  Component {
    id: helperProcess
    Process {
      id: process
      property string input: ""
      property bool feed: false
      property var done: null
      property int exitCode: -1
      property bool exited: false
      property bool drained: false
      stdinEnabled: true
      stdout: StdioCollector {
        id: output
        onStreamFinished: { process.drained = true; process.finish() }
      }
      stderr: StdioCollector {}
      onStarted: {
        if (feed) write(input)
        input = ""
        stdinEnabled = false
      }
      onExited: function (code) { exitCode = code; exited = true; finish() }
      function finish() {
        if (!exited || !drained) return
        var callback = done
        var text = output.text
        done = null
        process.destroy()
        root.busy = false
        if (callback) callback(exitCode, text)
        root.pump()
      }
    }
  }

  // ApprovalController's vault interface.
  function load(done) { enqueue([helper, "read"], null, done) }
  function save(text, done) { enqueue([helper, "write"], text, function (code) { done(code === 0) }) }
  function clear(done) { enqueue([helper, "delete"], null, function (code) { done(code === 0) }) }
  function publish(summary) { enqueue([helper, "summary"], JSON.stringify(summary), null) }

  function rememberController(origin) { saveSettings({ controller_url: origin }) }
  function rememberLocale(locale) { saveSettings({ locale: locale }) }

  function saveSettings(change) {
    var next = {}
    for (var name in settings) next[name] = settings[name]
    for (var key in change) next[key] = change[key]
    settings = next
    var clean = { controller_url: typeof next.controller_url === "string" ? next.controller_url : "", locale: next.locale === "vi" ? "vi" : "en" }
    enqueue(["sh", "-c", "umask 077 && mkdir -p -- \"$1\" && cat > \"$2.tmp\" && mv -f -- \"$2.tmp\" \"$2\"", "sh", configDir, settingsPath], JSON.stringify(clean) + "\n", null)
  }

  FileView {
    id: settingsFile
    path: root.settingsPath
    blockLoading: true
    printErrors: false
  }

  Component.onCompleted: {
    try {
      var parsed = JSON.parse(settingsFile.text())
      settings = parsed && typeof parsed === "object" ? parsed : {}
    } catch (error) {
      settings = {}
    }
  }
}

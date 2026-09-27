// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import Quickshell.Io
import "lib/transport.js" as Transport

// Controller requests through curl (see lib/transport.js for why not XHR).
// The whole request, including the bearer or password, is written to curl's
// stdin as a config file; argv carries only `-q --config -`.
Item {
  id: root
  property string curl: "curl"

  Component {
    id: requestProcess
    Process {
      id: process
      property string config: ""
      property var done: null
      property int exitCode: -1
      property bool exited: false
      property bool drained: false

      command: [root.curl, "-q", "--config", "-"]
      stdinEnabled: true
      stdout: StdioCollector {
        id: output
        onStreamFinished: {
          process.drained = true
          process.finish()
        }
      }
      stderr: StdioCollector {}
      onStarted: {
        write(config)
        config = ""
        stdinEnabled = false
      }
      onExited: function (code) {
        exitCode = code
        exited = true
        finish()
      }

      function finish() {
        if (!exited || !drained || done === null) return
        var callback = done
        done = null
        var response = Transport.parseResponse(exitCode, output.text)
        process.destroy()
        callback(response)
      }
    }
  }

  function request(options, done) {
    var config
    try {
      config = Transport.curlConfig(options)
    } catch (error) {
      done({ ok: false, kind: "scheme" })
      return
    }
    var process = requestProcess.createObject(root, { config: config, done: done })
    process.running = true
  }
}

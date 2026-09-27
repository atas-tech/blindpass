// SPDX-License-Identifier: AGPL-3.0-only
//
// BlindPass approval app: a Quickshell process of its own, separate from
// omarchy-shell. Run with bin/blindpass-approvals (or `quickshell -p` this
// directory). The Omarchy widget never loads this file and has no access to
// its session; it reads only the metadata summary the app writes.
import QtQuick
import Quickshell
import Quickshell.Io
import "lib/transport.js" as Transport

ShellRoot {
  id: shell

  CurlTransport { id: curlTransport }
  SessionVault { id: sessionVault }

  // BLINDPASS_CONTROLLER_URL wins over the saved address.
  readonly property string configuredController: {
    var fromEnv = Quickshell.env("BLINDPASS_CONTROLLER_URL") || ""
    var chosen = fromEnv !== "" ? fromEnv : (sessionVault.settings.controller_url || "")
    var parsed = Transport.parseController(chosen)
    return parsed.ok ? parsed.origin : ""
  }

  FloatingWindow {
    id: window
    title: "BlindPass approvals"
    visible: Quickshell.env("BLINDPASS_APPROVALS_HIDDEN") !== "1"
    implicitWidth: 460
    implicitHeight: 700
    color: "#0b0e0d"

    ApprovalApp {
      id: app
      anchors.fill: parent
      focus: true
      autoStart: false
      transport: curlTransport
      vault: sessionVault
      controllerOrigin: shell.configuredController
      windowVisible: window.visible
      locale: sessionVault.settings.locale === "vi" ? "vi" : "en"
      onLocaleChosen: function (locale) { sessionVault.rememberLocale(locale) }
    }
  }

  // Start once the saved settings and every component have loaded.
  Component.onCompleted: Qt.callLater(function () { app.controller.start() })

  // Same-user IPC exposes window control only. There is deliberately no
  // function that reads approvals, decides, or returns any session value.
  IpcHandler {
    target: "blindpass-approvals"
    function show(): void { window.visible = true }
    function hide(): void { window.visible = false }
  }
}

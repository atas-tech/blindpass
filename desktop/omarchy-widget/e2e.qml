// SPDX-License-Identifier: AGPL-3.0-only
// Loads Widget.qml under Quickshell with a stand-in for the Omarchy bar and
// checks it follows the summary file the approval app's helper writes.
// Driven by tests/widget-e2e.test.mjs. Test-only: it sits beside Widget.qml
// because Quickshell loads QML only from inside the config folder.
import QtQuick
import Quickshell

ShellRoot {
  id: shell
  property var runs: []
  QtObject {
    id: fakeBar
    property int barSize: 26
    property color foreground: "#f0f3ed"
    property string fontFamily: "monospace"
    function run(command) { shell.runs = shell.runs.concat([command]); console.info("E2E RUN " + command) }
    function showTooltip(target, text) {}
    function hideTooltip(target) {}
  }
  FloatingWindow {
    visible: true
    implicitWidth: 80
    implicitHeight: 30
    Loader {
      id: loader
      source: Qt.resolvedUrl("Widget.qml")
      onLoaded: {
        item.bar = fakeBar
        item.settings = { launchCommand: "blindpass-approvals --from-widget" }
      }
    }
  }
  property int step: 0
  Timer {
    interval: 200
    repeat: true
    running: loader.status === Loader.Ready
    onTriggered: {
      var view = loader.item.view
      console.info("E2E VIEW " + JSON.stringify(view) + " label=" + (view.pending || ""))
      if (Quickshell.env("E2E_CLICK") === "1" && shell.runs.length === 0) loader.item.open()
    }
  }
}

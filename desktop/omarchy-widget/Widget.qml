// SPDX-License-Identifier: AGPL-3.0-only
//
// Omarchy bar widget for BlindPass approvals. It runs inside omarchy-shell,
// whose QML scene other plugins can traverse, so it holds nothing worth
// taking: it reads the approval app's metadata-only summary and its one
// action is to open the separate approval app. It never reads the session
// file, never talks to the controller and has no way to approve.
import QtQuick
import Quickshell
import Quickshell.Io
import "summary.js" as Summary

Item {
  id: root
  property var bar: null
  property string moduleName: "blindpass.approvals"
  property var settings: ({})

  readonly property string summaryPath: (Quickshell.env("XDG_RUNTIME_DIR") || "/run/user/0") + "/blindpass/summary.json"
  property var view: ({ state: "not_running", pending: null })
  readonly property string launchCommand: settings && typeof settings.launchCommand === "string" && settings.launchCommand !== "" ? settings.launchCommand : "blindpass-approvals"
  readonly property bool hideWhenNotRunning: settings && settings.hideWhenNotRunning === true

  visible: !(hideWhenNotRunning && view.state === "not_running")
  implicitWidth: visible ? row.implicitWidth + 12 : 0
  implicitHeight: bar ? bar.barSize : 26

  property bool summaryMissing: false

  function refresh() {
    if (summaryMissing) {
      // FileView doesn't retry a path whose load failed; set it again so a
      // summary created after the widget loaded is picked up.
      summaryMissing = false
      summaryFile.path = ""
      summaryFile.path = root.summaryPath
    } else {
      summaryFile.reload()
    }
    root.view = Summary.read(summaryFile.text(), Date.now())
  }

  function open() {
    if (root.bar && typeof root.bar.run === "function") root.bar.run(root.launchCommand)
    else Quickshell.execDetached(["sh", "-c", root.launchCommand])
  }

  FileView {
    id: summaryFile
    path: root.summaryPath
    watchChanges: true
    // A small local file: read synchronously so text() after reload() is current.
    blockLoading: true
    printErrors: false
    onFileChanged: root.refresh()
    onLoaded: root.refresh()
    onLoadFailed: {
      root.summaryMissing = true
      root.view = ({ state: "not_running", pending: null })
    }
  }

  // Staleness, and a file created after the widget loaded, have to be
  // noticed without a change notification.
  Timer {
    interval: 5000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Row {
    id: row
    anchors.centerIn: parent
    spacing: 4

    // A padlock drawn in QML so the widget doesn't depend on an icon font.
    Item {
      width: 12
      height: 14
      anchors.verticalCenter: parent.verticalCenter
      opacity: root.view.state === "ready" || root.view.state === "locked" ? 1 : 0.55
      Rectangle {
        x: 2.5; y: 0; width: 7; height: 8; radius: 3.5
        color: "transparent"
        border.width: 1.5
        border.color: body.color
      }
      Rectangle {
        id: body
        x: 0; y: 6; width: 12; height: 8; radius: 2
        color: Summary.urgent(root.view) ? "#c5f277" : root.view.state === "unreachable" ? "#ebc17c" : (root.bar ? root.bar.foreground : "#f0f3ed")
      }
    }

    Text {
      anchors.verticalCenter: parent.verticalCenter
      visible: text !== ""
      text: Summary.label(root.view)
      textFormat: Text.PlainText
      color: Summary.urgent(root.view) ? "#c5f277" : (root.bar ? root.bar.foreground : "#f0f3ed")
      font.family: root.bar ? root.bar.fontFamily : "monospace"
      font.pixelSize: 12
      font.bold: true
    }
  }

  Accessible.role: Accessible.Button
  Accessible.name: Summary.tooltip(root.view)
  Accessible.onPressAction: root.open()

  MouseArea {
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onClicked: root.open()
    onEntered: if (root.bar && root.bar.showTooltip) root.bar.showTooltip(root, Summary.tooltip(root.view))
    onExited: if (root.bar && root.bar.hideTooltip) root.bar.hideTooltip(root)
  }
}

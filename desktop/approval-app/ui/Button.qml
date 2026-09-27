// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme

// A keyboard-operable button: Tab focus, Space/Enter activate, a visible
// focus ring and a 44 px minimum target. Disabled buttons stay focusable so
// the reason next to them is reachable.
Rectangle {
  id: root
  property string text: ""
  property string tone: "secondary" // primary | secondary | danger | ghost
  property bool busy: false
  property string description: ""
  signal activated()

  readonly property bool interactive: enabled && !busy
  readonly property color fg: tone === "primary" ? Theme.color.limeInk : tone === "danger" ? Theme.color.dangerStrong : Theme.color.ink

  implicitWidth: Math.max(Theme.target, label.implicitWidth + 2 * Theme.space.s4)
  implicitHeight: Theme.target
  radius: Theme.radius.md
  opacity: enabled ? 1 : 0.55
  color: tone === "primary" ? (mouse.containsMouse && interactive ? Theme.color.limeStrong : Theme.color.lime)
    : tone === "danger" ? (mouse.containsMouse && interactive ? Theme.color.dangerHover : Theme.color.dangerSoft)
    : tone === "ghost" ? (mouse.containsMouse && interactive ? Theme.color.raised : "transparent")
    : (mouse.containsMouse && interactive ? Theme.color.overlay : Theme.color.raised)
  border.width: tone === "primary" || tone === "ghost" ? 0 : 1
  border.color: tone === "danger" ? Theme.color.dangerLine : (mouse.containsMouse ? Theme.color.controlHover : Theme.color.control)
  activeFocusOnTab: true

  Accessible.role: Accessible.Button
  Accessible.name: text
  Accessible.description: description
  Accessible.focusable: true
  Accessible.onPressAction: if (interactive) root.activated()

  Text {
    id: label
    anchors.centerIn: parent
    text: root.text
    textFormat: Text.PlainText
    color: root.fg
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.md
    font.weight: Font.DemiBold
    font.variableAxes: ({ "wght": 600 })
    elide: Text.ElideRight
    width: Math.min(implicitWidth, root.width - 2 * Theme.space.s3)
    horizontalAlignment: Text.AlignHCenter
  }

  Rectangle {
    anchors.fill: parent
    anchors.margins: -4
    radius: root.radius + 4
    color: "transparent"
    border.width: 2
    border.color: Theme.color.lime
    visible: root.activeFocus
  }

  MouseArea {
    id: mouse
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: root.interactive ? Qt.PointingHandCursor : Qt.ArrowCursor
    onClicked: {
      root.forceActiveFocus(Qt.MouseFocusReason)
      if (root.interactive) root.activated()
    }
    // The second press of a double-click arrives here instead of onClicked.
    // Treat it as another activation; every handler is idempotent for its
    // phase, so a double-click can't skip the confirmation step.
    onDoubleClicked: if (root.interactive) root.activated()
  }

  Keys.onPressed: function (event) {
    if (event.key === Qt.Key_Space || event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
      event.accepted = true
      if (root.interactive) root.activated()
    }
  }
}

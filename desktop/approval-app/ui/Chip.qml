// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme

Rectangle {
  id: root
  property string text: ""
  property string tone: "neutral"
  readonly property var colors: Theme.tone(tone)
  implicitWidth: label.implicitWidth + 2 * Theme.space.s2
  implicitHeight: label.implicitHeight + 8
  radius: Theme.radius.pill
  color: colors.bg
  border.width: 1
  border.color: colors.line
  Accessible.role: Accessible.StaticText
  Accessible.name: text
  Text {
    id: label
    anchors.centerIn: parent
    text: root.text
    textFormat: Text.PlainText
    color: root.colors.fg
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.xs
    font.weight: Font.DemiBold
    font.variableAxes: ({ "wght": 600 })
  }
}

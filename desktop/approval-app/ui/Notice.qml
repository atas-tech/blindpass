// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme

// A status message with a tone. The tone is never the only signal: the text
// carries the meaning.
Rectangle {
  id: root
  property string text: ""
  property string tone: "info"
  readonly property var colors: Theme.tone(tone)
  width: parent ? parent.width : 320
  implicitHeight: body.implicitHeight + 2 * Theme.space.s3
  height: implicitHeight
  radius: Theme.radius.md
  color: colors.bg
  border.width: 1
  border.color: colors.line
  visible: text !== ""
  Accessible.role: tone === "danger" || tone === "warn" ? Accessible.AlertMessage : Accessible.StaticText
  Accessible.name: text

  Rectangle {
    width: 3
    radius: 1
    anchors.left: parent.left
    anchors.top: parent.top
    anchors.bottom: parent.bottom
    anchors.margins: Theme.space.s2
    color: root.colors.fg
  }

  Text {
    id: body
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.verticalCenter: parent.verticalCenter
    anchors.leftMargin: Theme.space.s5
    anchors.rightMargin: Theme.space.s3
    text: root.text
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    color: Theme.color.ink
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.sm
    lineHeight: 1.35
  }
}

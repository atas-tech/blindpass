// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme

// Labelled single-line input with hint and error text.
Column {
  id: root
  property alias label: labelText.text
  property alias text: input.text
  property alias echoMode: input.echoMode
  property alias readOnly: input.readOnly
  property alias input: input
  property string hint: ""
  property string error: ""
  property string inputName: ""
  signal accepted()

  spacing: Theme.space.s2
  width: parent ? parent.width : 320

  Text {
    id: labelText
    textFormat: Text.PlainText
    color: Theme.color.ink
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.sm
    font.weight: Font.DemiBold
    font.variableAxes: ({ "wght": 600 })
  }

  Rectangle {
    width: root.width
    height: Theme.target
    radius: Theme.radius.md
    color: input.readOnly ? Theme.color.panel : Theme.color.sunken
    border.width: input.activeFocus ? 2 : 1
    border.color: root.error !== "" ? Theme.color.danger : input.activeFocus ? Theme.color.lime : Theme.color.control

    TextInput {
      id: input
      objectName: root.inputName
      anchors.fill: parent
      anchors.leftMargin: Theme.space.s3
      anchors.rightMargin: Theme.space.s3
      verticalAlignment: TextInput.AlignVCenter
      color: Theme.color.ink
      selectionColor: Theme.color.limeLine
      selectedTextColor: Theme.color.ink
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.base
      clip: true
      activeFocusOnTab: true
      inputMethodHints: echoMode === TextInput.Password ? (Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase) : (Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase)
      Accessible.role: Accessible.EditableText
      Accessible.name: root.label
      Accessible.description: root.error !== "" ? root.error : root.hint
      Accessible.passwordEdit: echoMode === TextInput.Password
      onAccepted: root.accepted()
    }
  }

  Text {
    visible: root.hint !== "" && root.error === ""
    width: root.width
    text: root.hint
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    color: Theme.color.muted
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.xs
  }

  Text {
    visible: root.error !== ""
    width: root.width
    text: root.error
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    color: Theme.color.danger
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.sm
    Accessible.role: Accessible.AlertMessage
    Accessible.name: text
  }
}

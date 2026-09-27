// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme

// Idle lock. The list and details are cleared from memory; only the pending
// count keeps updating. Unlocking signs in again with the password and
// revokes the previous session.
Column {
  id: root
  property var app
  readonly property var controller: app.controller
  spacing: Theme.space.s4

  onVisibleChanged: {
    password.text = ""
    if (visible) password.input.forceActiveFocus()
  }

  Connections {
    target: root.controller
    function onUnlockBusyChanged() {
      if (!root.controller.unlockBusy) password.text = ""
    }
  }

  Text {
    width: parent.width
    text: app.t("lock.title")
    textFormat: Text.PlainText
    color: Theme.color.ink
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.xl
    font.weight: Font.DemiBold
    font.variableAxes: ({ "wght": 600 })
    Accessible.role: Accessible.Heading
    Accessible.name: text
  }
  Chip {
    objectName: "locked-count"
    text: app.tn("queue.count", controller.pendingCount)
    tone: controller.pendingCount > 0 ? "pending" : "neutral"
  }
  Text {
    width: parent.width
    text: app.t("lock.body")
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    color: Theme.color.inkSoft
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.md
    lineHeight: 1.4
  }
  Field {
    id: password
    inputName: "unlock-password"
    label: app.t("signIn.password")
    echoMode: TextInput.Password
    error: controller.unlockError !== "" ? app.t(controller.unlockError) : ""
    onAccepted: if (text !== "") controller.unlock(text)
  }
  Button {
    objectName: "unlock"
    width: parent.width
    tone: "primary"
    text: controller.unlockBusy ? app.t("lock.working") : app.t("lock.unlock")
    busy: controller.unlockBusy
    onActivated: if (password.text !== "") controller.unlock(password.text)
  }
}

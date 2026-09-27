// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme

Flickable {
  id: root
  property var app
  readonly property var controller: app.controller
  property string urlError: ""
  property string usernameError: ""
  property string passwordError: ""

  contentHeight: column.implicitHeight
  clip: true
  boundsBehavior: Flickable.StopAtBounds

  function submit() {
    urlError = ""
    usernameError = ""
    passwordError = ""
    var problem = controller.validateController(url.text)
    if (username.text.trim() === "") usernameError = app.t("signIn.usernameRequired")
    if (password.text === "") passwordError = app.t("signIn.passwordRequired")
    if (problem !== "") urlError = app.t(problem)
    if (problem !== "") url.input.forceActiveFocus()
    else if (usernameError !== "") username.input.forceActiveFocus()
    else if (passwordError !== "") password.input.forceActiveFocus()
    if (problem !== "" || usernameError !== "" || passwordError !== "") return
    controller.signIn(url.text, username.text.trim(), password.text)
  }

  onVisibleChanged: {
    if (visible) {
      password.text = ""
      if (url.text === "") url.text = controller.controllerOrigin
      ;(url.text === "" ? url.input : username.text === "" ? username.input : password.input).forceActiveFocus()
    } else {
      password.text = ""
    }
  }

  Connections {
    target: root.controller
    function onSignInBusyChanged() {
      if (!root.controller.signInBusy) password.text = ""
    }
  }

  Column {
    id: column
    width: root.width
    spacing: Theme.space.s4

    Text {
      width: parent.width
      text: app.t("signIn.title")
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      color: Theme.color.ink
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.xl
      font.weight: Font.DemiBold
      font.variableAxes: ({ "wght": 600 })
      Accessible.role: Accessible.Heading
      Accessible.name: text
    }
    Text {
      width: parent.width
      text: app.t("signIn.body")
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      color: Theme.color.inkSoft
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.md
      lineHeight: 1.4
    }
    Notice {
      objectName: "sign-in-message"
      text: controller.signInMessage !== "" ? app.t(controller.signInMessage) : ""
      tone: controller.signInTone
    }
    Field {
      id: url
      inputName: "controller-url"
      label: app.t("signIn.controller")
      hint: app.t("signIn.controllerHint")
      error: root.urlError
      input.font.family: Theme.font.mono
      onAccepted: username.input.forceActiveFocus()
    }
    Field {
      id: username
      inputName: "username"
      label: app.t("signIn.username")
      error: root.usernameError
      onAccepted: password.input.forceActiveFocus()
    }
    Field {
      id: password
      inputName: "password"
      label: app.t("signIn.password")
      echoMode: TextInput.Password
      error: root.passwordError
      onAccepted: root.submit()
    }
    Button {
      objectName: "sign-in-submit"
      width: parent.width
      tone: "primary"
      text: controller.signInBusy ? app.t("signIn.working") : app.t("signIn.submit")
      busy: controller.signInBusy
      onActivated: root.submit()
    }
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "lib/theme.js" as Theme
import "lib/strings.js" as Strings
import "ui"

// The approval app's window content. Pure QtQuick: shell.qml hosts it in a
// Quickshell FloatingWindow; the tests host it in a qmltestrunner window.
Rectangle {
  id: app
  property alias controller: controller
  property alias transport: controller.transport
  property alias vault: controller.vault
  property alias controllerOrigin: controller.controllerOrigin
  property alias autoStart: controller.autoStart
  property alias windowVisible: controller.windowVisible
  property string locale: "en"
  signal localeChosen(string locale)

  function t(key, args) { return Strings.t(locale, key, args) }
  function tn(key, count, args) { return Strings.tn(locale, key, count, args) }

  color: Theme.color.bg
  implicitWidth: 460
  implicitHeight: 680

  ApprovalController { id: controller }

  // The shared self-hosted Inter (assets/ui). If it can't load, Qt falls
  // back to the system sans font.
  FontLoader { source: Qt.resolvedUrl("../../assets/ui/fonts/InterVariable.woff2") }

  // Any pointer or key input in the window counts as activity for the
  // idle lock. The handlers observe without consuming events.
  HoverHandler { onPointChanged: controller.noteInput() }
  TapHandler { onTapped: controller.noteInput(); gesturePolicy: TapHandler.DragThreshold }
  Keys.onPressed: function (event) { controller.noteInput(); event.accepted = false }

  Column {
    id: header
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.top: parent.top
    anchors.margins: Theme.space.s5
    spacing: Theme.space.s3

    Item {
      width: parent.width
      height: Theme.target

      Row {
        anchors.verticalCenter: parent.verticalCenter
        spacing: Theme.space.s2
        Grid {
          anchors.verticalCenter: parent.verticalCenter
          columns: 2
          spacing: 2
          Repeater {
            model: 4
            Rectangle { width: 6; height: 6; radius: 1; color: index === 3 ? Theme.color.lime : Theme.color.inkSoft }
          }
        }
        Text {
          anchors.verticalCenter: parent.verticalCenter
          text: "blindpass"
          textFormat: Text.PlainText
          color: Theme.color.ink
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.lg
          font.weight: Font.DemiBold
          font.variableAxes: ({ "wght": 600 })
          Accessible.ignored: true
        }
        Text {
          anchors.verticalCenter: parent.verticalCenter
          text: app.t("app.surface")
          textFormat: Text.PlainText
          color: Theme.color.muted
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.sm
          Accessible.role: Accessible.Heading
          Accessible.name: text
        }
      }

      Row {
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Theme.space.s1
        Accessible.role: Accessible.Grouping
        Accessible.name: app.t("language.label")
        Repeater {
          model: ["en", "vi"]
          Button {
            objectName: "language-" + modelData
            text: modelData === "en" ? "EN" : "VI"
            tone: app.locale === modelData ? "secondary" : "ghost"
            implicitWidth: Theme.target
            Accessible.name: modelData === "en" ? "English" : "Tiếng Việt"
            Accessible.checkable: true
            Accessible.checked: app.locale === modelData
            onActivated: { app.locale = modelData; app.localeChosen(modelData) }
          }
        }
      }
    }

    // Who and where: shown whenever a session exists so the operator always
    // sees which controller and account a decision goes to.
    Rectangle {
      objectName: "identity"
      visible: controller.phase === "ready" || controller.phase === "locked"
      width: parent.width
      height: visible ? identity.implicitHeight + 2 * Theme.space.s3 : 0
      radius: Theme.radius.md
      color: Theme.color.panel
      border.width: 1
      border.color: Theme.color.line

      Column {
        id: identity
        anchors.left: parent.left
        anchors.right: actions.left
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: Theme.space.s3
        anchors.rightMargin: Theme.space.s2
        spacing: 2
        Text {
          objectName: "controller-host"
          width: parent.width
          text: controller.controllerInfo.ok ? controller.controllerInfo.host : ""
          textFormat: Text.PlainText
          elide: Text.ElideMiddle
          color: Theme.color.ink
          font.family: Theme.font.mono
          font.pixelSize: Theme.font.sm
        }
        Text {
          width: parent.width
          text: controller.controllerInfo.loopback ? app.t("trust.loopback") : app.t("trust.verified")
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          color: controller.controllerInfo.loopback ? Theme.color.warn : Theme.color.muted
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.xs
        }
        Text {
          objectName: "signed-in-as"
          width: parent.width
          text: controller.operator ? app.t("session.signedInAs", { user: controller.operator.username }) : ""
          textFormat: Text.PlainText
          elide: Text.ElideRight
          color: Theme.color.inkSoft
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.xs
        }
      }

      Row {
        id: actions
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.rightMargin: Theme.space.s2
        spacing: Theme.space.s1
        Button {
          objectName: "lock"
          visible: controller.phase === "ready"
          text: app.t("session.lock")
          tone: "ghost"
          onActivated: controller.lockNow()
        }
        Button {
          objectName: "sign-out"
          text: app.t("session.signOut")
          tone: "ghost"
          onActivated: controller.signOut()
        }
      }
    }

    Notice {
      objectName: "connection-problem"
      text: controller.connectionProblem !== "" && controller.phase !== "signin" ? app.t(controller.connectionProblem) : ""
      tone: "warn"
    }
  }

  Item {
    id: body
    anchors.top: header.bottom
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: footer.top
    anchors.leftMargin: Theme.space.s5
    anchors.rightMargin: Theme.space.s5
    anchors.topMargin: Theme.space.s4
    anchors.bottomMargin: Theme.space.s3

    SignInView {
      objectName: "sign-in"
      anchors.fill: parent
      visible: controller.phase === "signin"
      app: app
    }
    Text {
      anchors.centerIn: parent
      visible: controller.phase === "starting"
      text: app.t("queue.loading")
      textFormat: Text.PlainText
      color: Theme.color.muted
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.md
    }
    LockView {
      objectName: "lock-view"
      anchors.fill: parent
      visible: controller.phase === "locked"
      app: app
    }
    QueueView {
      objectName: "queue"
      anchors.fill: parent
      visible: controller.phase === "ready" && controller.view === "queue"
      app: app
    }
    DetailView {
      objectName: "detail"
      anchors.fill: parent
      visible: controller.phase === "ready" && controller.view === "detail"
      app: app
    }
  }

  Text {
    id: footer
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    anchors.margins: Theme.space.s5
    text: app.t("app.metadataOnly")
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    color: Theme.color.dim
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.xs
  }

  ConfirmDialog {
    objectName: "confirm"
    anchors.fill: parent
    app: app
  }
}

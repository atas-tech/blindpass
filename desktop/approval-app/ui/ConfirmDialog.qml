// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme
import "../lib/model.js" as Model

// Modal confirmation for a decision. It names the recipient and scope,
// focuses Cancel, closes on Escape and has no keyboard shortcut that
// approves: approving takes Tab to the button and an explicit activation.
FocusScope {
  id: root
  property var app
  readonly property var controller: app.controller
  readonly property var approval: controller.selected
  readonly property bool open: controller.decisionPhase === "confirm" || controller.decisionPhase === "checking" || controller.decisionPhase === "sending"
  readonly property bool working: controller.decisionPhase === "checking" || controller.decisionPhase === "sending"
  readonly property bool reject: controller.decisionVerb === "reject"
  readonly property var authority: approval ? Model.authority(approval) : null

  visible: open
  z: 50
  focus: open
  onOpenChanged: if (open) cancel.forceActiveFocus()

  Keys.onEscapePressed: if (!root.working) root.controller.cancelDecision()
  // Swallow keys so nothing behind the dialog reacts.
  Keys.onPressed: function (event) { event.accepted = event.key !== Qt.Key_Tab && event.key !== Qt.Key_Backtab }

  Rectangle {
    anchors.fill: parent
    color: Theme.color.scrim
    MouseArea { anchors.fill: parent; hoverEnabled: true; onClicked: {} }
  }

  Rectangle {
    id: panel
    objectName: "confirm-panel"
    anchors.centerIn: parent
    width: Math.min(parent.width - 2 * Theme.space.s5, 420)
    height: content.implicitHeight + 2 * Theme.space.s5
    radius: Theme.radius.lg
    color: Theme.color.overlay
    border.width: 1
    border.color: root.reject ? Theme.color.dangerLine : Theme.color.lineStrong
    Accessible.role: Accessible.Dialog
    Accessible.name: title.text

    Column {
      id: content
      anchors.fill: parent
      anchors.margins: Theme.space.s5
      spacing: Theme.space.s4

      Text {
        id: title
        objectName: "confirm-title"
        width: parent.width
        text: !root.approval || !root.authority ? "" : root.reject ? app.t("confirm.reject")
          : Model.isOperation(root.approval) ? app.tn("confirm.approveOperation", root.authority.count) : app.t("confirm.approveExchange")
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        color: Theme.color.ink
        font.family: Theme.font.sans
        font.pixelSize: Theme.font.lg
        font.weight: Font.DemiBold
        font.variableAxes: ({ "wght": 600 })
        Accessible.role: Accessible.Heading
        Accessible.name: text
      }

      Rectangle {
        width: parent.width
        height: scopeColumn.implicitHeight + 2 * Theme.space.s3
        radius: Theme.radius.md
        color: Theme.color.panel
        border.width: 1
        border.color: Theme.color.line
        Column {
          id: scopeColumn
          anchors.fill: parent
          anchors.margins: Theme.space.s3
          spacing: Theme.space.s2
          Repeater {
            model: ["recipient", "scope"]
            Row {
              width: scopeColumn.width
              spacing: Theme.space.s3
              Text {
                width: Math.round(parent.width * 0.3)
                text: app.t("confirm." + modelData)
                textFormat: Text.PlainText
                color: Theme.color.muted
                font.family: Theme.font.sans
                font.pixelSize: Theme.font.sm
              }
              Text {
                objectName: "confirm-" + modelData
                width: parent.width - Math.round(parent.width * 0.3) - Theme.space.s3
                text: !root.authority ? "" : modelData === "scope" && Model.isOperation(root.approval)
                  ? app.t(root.authority.scope.key, Object.assign({}, root.authority.scope.args, { mode: app.t("mode." + root.authority.scope.args.mode) }))
                  : app.t(root.authority[modelData].key, root.authority[modelData].args)
                textFormat: Text.PlainText
                wrapMode: Text.WrapAnywhere
                color: Theme.color.ink
                font.family: Theme.font.sans
                font.pixelSize: Theme.font.sm
                font.weight: Font.DemiBold
                font.variableAxes: ({ "wght": 600 })
              }
            }
          }
        }
      }

      Text {
        width: parent.width
        text: root.reject ? app.t("confirm.rejectBody") : app.t("confirm.approveBody")
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        color: Theme.color.inkSoft
        font.family: Theme.font.sans
        font.pixelSize: Theme.font.sm
        lineHeight: 1.35
      }

      Text {
        objectName: "confirm-progress"
        width: parent.width
        visible: root.working
        text: controller.decisionPhase === "checking" ? app.t("confirm.checking") : app.t("confirm.sending")
        textFormat: Text.PlainText
        color: Theme.color.muted
        font.family: Theme.font.sans
        font.pixelSize: Theme.font.sm
        Accessible.role: Accessible.StaticText
        Accessible.name: text
      }

      Row {
        anchors.right: parent.right
        spacing: Theme.space.s3
        Button {
          id: cancel
          objectName: "confirm-cancel"
          text: app.t("confirm.cancel")
          enabled: !root.working
          onActivated: root.controller.cancelDecision()
          KeyNavigation.tab: confirm
          KeyNavigation.backtab: confirm
        }
        Button {
          id: confirm
          objectName: "confirm-decide"
          text: root.reject ? app.t("confirm.rejectAction") : app.t("confirm.approve")
          tone: root.reject ? "danger" : "primary"
          busy: root.working
          onActivated: root.controller.confirmDecision()
          KeyNavigation.tab: cancel
          KeyNavigation.backtab: cancel
        }
      }
    }
  }
}

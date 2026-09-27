// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme
import "../lib/model.js" as Model

// One approval. The recipient and scope lead because they are what the
// decision grants; requester-written purpose is shown as quoted plain text
// in its own block and never as a heading.
Item {
  id: root
  property var app
  readonly property var controller: app.controller
  readonly property var approval: controller.selected
  readonly property bool operation: Model.isOperation(approval)
  readonly property var scope: operation ? (approval.verified_identity || {}) : ({})
  readonly property var authority: approval ? Model.authority(approval) : null
  readonly property string block: approval ? (Model.decisionBlock(approval, controller.operator) || "") : ""
  property double tick: 0

  Timer {
    interval: 1000
    repeat: true
    running: root.visible && root.operation
    onTriggered: root.tick = root.controller.serverNow()
  }

  onVisibleChanged: if (visible) backButton.forceActiveFocus()

  function line(key) {
    return authority ? app.t(authority[key].key, key === "scope" && operation ? Object.assign({}, authority.scope.args, { mode: app.t("mode." + authority.scope.args.mode) }) : authority[key].args) : ""
  }

  Flickable {
    id: scroller
    anchors.top: parent.top
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: actionBar.top
    anchors.bottomMargin: Theme.space.s2
    contentHeight: column.implicitHeight + Theme.space.s6
    clip: true
    boundsBehavior: Flickable.StopAtBounds

  Column {
    id: column
    // Inset so focus rings aren't clipped by the scroller.
    x: 4
    y: 4
    width: scroller.width - 8
    spacing: Theme.space.s4

    Button {
      id: backButton
      objectName: "back"
      text: "← " + app.t("detail.back")
      tone: "ghost"
      onActivated: controller.back()
    }

    Notice {
      objectName: "detail-missing"
      text: controller.detailMissing ? app.t("detail.notFound") : ""
      tone: "warn"
    }

    Column {
      width: parent.width
      spacing: Theme.space.s2
      visible: root.approval !== null
      Row {
        spacing: Theme.space.s2
        Chip { text: root.approval ? app.t(root.operation ? "kind.operation" : "kind.exchange") : ""; tone: "neutral" }
        Chip {
          objectName: "detail-status"
          text: root.approval ? app.t("status." + root.approval.status) : ""
          tone: root.approval ? root.approval.status : "neutral"
        }
      }
      Text {
        objectName: "detail-title"
        width: parent.width
        text: !root.approval ? "" : root.operation
          ? app.t("row.operation", { action: root.scope.action || "—", unit: root.scope.unit || "—" })
          : app.t("row.exchange", { requester: Model.requester(root.approval), secret: root.approval.secret_name || "—" })
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
        objectName: "detail-window"
        width: parent.width
        readonly property var remainingMs: root.approval ? Model.remaining(root.approval, root.tick || root.controller.serverNow()) : null
        visible: root.operation && root.approval && root.approval.status === "pending"
        text: remainingMs === null ? "" : !root.controller.serverClockKnown
          ? app.t("detail.clockUnknown", { time: Qt.formatDateTime(new Date(root.approval.expires_at), "HH:mm:ss") })
          : remainingMs > 0 ? app.t("detail.closes") + " " + Model.formatRemaining(remainingMs) : app.t("detail.closed")
        textFormat: Text.PlainText
        color: remainingMs !== null && remainingMs < 60000 ? Theme.color.warn : Theme.color.inkSoft
        font.family: Theme.font.sans
        font.pixelSize: Theme.font.sm
      }
    }

    // Recipient and scope: the authority this decision grants.
    Rectangle {
      objectName: "authority"
      visible: root.approval !== null
      width: parent.width
      height: authorityColumn.implicitHeight + 2 * Theme.space.s4
      radius: Theme.radius.lg
      color: Theme.color.limeSoft
      border.width: 1
      border.color: Theme.color.limeLine
      Column {
        id: authorityColumn
        anchors.fill: parent
        anchors.margins: Theme.space.s4
        spacing: Theme.space.s3
        Repeater {
          model: ["recipient", "scope"]
          Column {
            width: authorityColumn.width
            spacing: 2
            Text {
              text: app.t("detail." + modelData)
              textFormat: Text.PlainText
              color: Theme.color.muted
              font.family: Theme.font.sans
              font.pixelSize: Theme.font.xs
              font.weight: Font.DemiBold
              font.variableAxes: ({ "wght": 600 })
              font.capitalization: Font.AllUppercase
              font.letterSpacing: 0.8
            }
            Text {
              objectName: "authority-" + modelData
              width: parent.width
              text: root.line(modelData)
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              color: Theme.color.ink
              font.family: Theme.font.sans
              font.pixelSize: Theme.font.base
              font.weight: Font.DemiBold
              font.variableAxes: ({ "wght": 600 })
            }
          }
        }
      }
    }

    // Facts from the controller's verified record.
    Column {
      width: parent.width
      spacing: Theme.space.s2
      visible: root.approval !== null
      Repeater {
        model: root.approval ? (root.operation ? [
          ["detail.requester", Model.requester(root.approval)],
          ["detail.node", root.scope.node_id],
          ["detail.workload", root.scope.workload_id],
          ["detail.account", root.scope.account],
          ["detail.rule", root.scope.rule_id || root.approval.rule_id],
          ["detail.approvers", (root.approval.approver_ids || []).join(", ")],
          ["detail.requested", Qt.formatDateTime(new Date(root.approval.created_at), "yyyy-MM-dd HH:mm")]
        ] : [
          ["detail.requester", Model.requester(root.approval)],
          ["detail.requested", Qt.formatDateTime(new Date(root.approval.created_at), "yyyy-MM-dd HH:mm")]
        ]).concat(root.approval.decided_by ? [["detail.decided", root.approval.decided_by]] : []) : []
        Row {
          width: parent.width
          spacing: Theme.space.s3
          Text {
            width: Math.round(parent.width * 0.32)
            text: app.t(modelData[0])
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            color: Theme.color.muted
            font.family: Theme.font.sans
            font.pixelSize: Theme.font.sm
          }
          Text {
            width: parent.width - Math.round(parent.width * 0.32) - Theme.space.s3
            text: modelData[1] === undefined || modelData[1] === null || modelData[1] === "" ? "—" : String(modelData[1])
            textFormat: Text.PlainText
            wrapMode: Text.WrapAnywhere
            color: Theme.color.ink
            font.family: Theme.font.mono
            font.pixelSize: Theme.font.sm
          }
        }
      }
    }

    // Requester-written purpose: untrusted text.
    Column {
      width: parent.width
      spacing: Theme.space.s2
      visible: root.approval !== null
      Text {
        text: app.t("detail.purpose")
        textFormat: Text.PlainText
        color: Theme.color.muted
        font.family: Theme.font.sans
        font.pixelSize: Theme.font.xs
        font.weight: Font.DemiBold
        font.variableAxes: ({ "wght": 600 })
      }
      Rectangle {
        width: parent.width
        height: purpose.implicitHeight + 2 * Theme.space.s3
        radius: Theme.radius.md
        color: Theme.color.sunken
        border.width: 1
        border.color: Theme.color.line
        Text {
          id: purpose
          objectName: "purpose"
          anchors.fill: parent
          anchors.margins: Theme.space.s3
          readonly property string value: root.approval ? (Model.purpose(root.approval) || "") : ""
          text: value !== "" ? value : app.t("detail.noPurpose")
          textFormat: Text.PlainText
          wrapMode: Text.WrapAnywhere
          maximumLineCount: 12
          elide: Text.ElideRight
          color: value !== "" ? Theme.color.inkSoft : Theme.color.dim
          font.family: Theme.font.mono
          font.pixelSize: Theme.font.sm
        }
      }
    }

    // Each member operation with its own evidence.
    Column {
      width: parent.width
      spacing: Theme.space.s2
      visible: root.operation && (root.approval.operations || []).length > 0
      Text {
        text: app.t("detail.members")
        textFormat: Text.PlainText
        color: Theme.color.muted
        font.family: Theme.font.sans
        font.pixelSize: Theme.font.xs
        font.weight: Font.DemiBold
        font.variableAxes: ({ "wght": 600 })
      }
      Repeater {
        model: root.operation ? (root.approval.operations || []) : []
        Text {
          width: parent.width
          text: app.t("detail.member", { resource: modelData.resource_id, invocation: modelData.invocation_id, requester: modelData.requested_by })
          textFormat: Text.PlainText
          wrapMode: Text.WrapAnywhere
          color: Theme.color.inkSoft
          font.family: Theme.font.mono
          font.pixelSize: Theme.font.xs
        }
      }
    }

  }
  }

  // Sticky decision bar: the outcome, any reason a decision isn't offered,
  // and the two actions stay in view however long the record is.
  Rectangle {
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: actionBar.top
    anchors.bottomMargin: Theme.space.s2
    height: 1
    color: Theme.color.line
    visible: scroller.contentHeight > scroller.height
  }

  Column {
    id: actionBar
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    spacing: Theme.space.s2
    Notice {
      objectName: "decision-message"
      text: controller.decisionMessage !== "" ? app.t(controller.decisionMessage, { code: controller.decisionCode }) : ""
      tone: controller.decisionTone
    }

    Notice {
      objectName: "decision-block"
      text: root.block !== "" && root.approval && !(root.block === "not_pending" && controller.decisionMessage.indexOf("result.") === 0) ? app.t("block." + root.block) : ""
      tone: root.block === "not_pending" ? "info" : "warn"
    }

    Row {
      width: parent.width
      spacing: Theme.space.s3
      visible: root.approval !== null && root.approval.status === "pending"
      Button {
        id: rejectButton
        width: (parent.width - parent.spacing) / 2
        objectName: "reject"
        text: app.t("detail.reject")
        tone: "danger"
        enabled: root.block === "" && controller.decisionPhase === "idle"
        description: root.block !== "" ? app.t("block." + root.block) : ""
        onActivated: controller.requestDecision("reject")
      }
      Button {
        id: approveButton
        width: (parent.width - parent.spacing) / 2
        objectName: "approve"
        text: app.t("detail.approve")
        tone: "primary"
        enabled: root.block === "" && controller.decisionPhase === "idle"
        description: root.block !== "" ? app.t("block." + root.block) : ""
        onActivated: controller.requestDecision("approve")
      }
    }
  }
}

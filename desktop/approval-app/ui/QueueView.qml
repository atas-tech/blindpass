// SPDX-License-Identifier: AGPL-3.0-only
import QtQuick
import "../lib/theme.js" as Theme
import "../lib/model.js" as Model

Item {
  id: root
  property var app
  readonly property var controller: app.controller
  property double tick: 0

  Timer {
    interval: 1000
    repeat: true
    running: root.visible
    onTriggered: root.tick = root.controller.serverNow()
  }

  function rowTitle(item) {
    if (Model.isOperation(item)) {
      var scope = item.verified_identity || {}
      return app.t("row.operation", { action: scope.action || "—", unit: scope.unit || "—" })
    }
    return app.t("row.exchange", { requester: Model.requester(item), secret: item.secret_name || "—" })
  }

  Row {
    id: titleRow
    width: parent.width
    height: Theme.target
    spacing: Theme.space.s3
    Text {
      anchors.verticalCenter: parent.verticalCenter
      text: app.t("queue.title")
      textFormat: Text.PlainText
      color: Theme.color.ink
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.lg
      font.weight: Font.DemiBold
      font.variableAxes: ({ "wght": 600 })
      Accessible.role: Accessible.Heading
      Accessible.name: text
    }
    Chip {
      objectName: "pending-count"
      anchors.verticalCenter: parent.verticalCenter
      text: app.tn("queue.count", controller.pendingCount)
      tone: controller.pendingCount > 0 ? "pending" : "neutral"
    }
  }
  Button {
    objectName: "refresh"
    anchors.right: parent.right
    anchors.top: parent.top
    text: app.t("queue.refresh")
    tone: "ghost"
    busy: controller.listLoading
    onActivated: controller.loadQueue()
  }

  Text {
    id: updated
    anchors.top: titleRow.bottom
    width: parent.width
    visible: controller.listLoaded
    text: controller.listLoaded ? app.t("queue.updated", { time: Qt.formatTime(new Date(controller.listUpdatedAt), "HH:mm:ss") }) : ""
    textFormat: Text.PlainText
    color: Theme.color.dim
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.xs
  }

  Column {
    anchors.top: updated.bottom
    anchors.topMargin: Theme.space.s6
    width: parent.width
    spacing: Theme.space.s2
    visible: controller.listLoaded && controller.approvals.length === 0
    objectName: "empty"
    Text {
      width: parent.width
      text: app.t("queue.empty")
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      color: Theme.color.ink
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.base
      font.weight: Font.DemiBold
      font.variableAxes: ({ "wght": 600 })
    }
    Text {
      width: parent.width
      text: app.t("queue.emptyBody")
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      color: Theme.color.muted
      font.family: Theme.font.sans
      font.pixelSize: Theme.font.sm
    }
  }

  ListView {
    id: list
    objectName: "approval-list"
    anchors.top: updated.bottom
    anchors.topMargin: Theme.space.s3
    anchors.bottom: parent.bottom
    width: parent.width
    clip: true
    spacing: Theme.space.s2
    model: controller.approvals
    activeFocusOnTab: true
    keyNavigationEnabled: true
    boundsBehavior: Flickable.StopAtBounds
    Accessible.role: Accessible.List
    Accessible.name: app.t("queue.title")
    footer: Item {
      width: list.width
      height: controller.listTruncated ? more.height + Theme.space.s4 : 0
      Notice {
        id: more
        y: Theme.space.s2
        text: controller.listTruncated ? app.t("queue.more") : ""
        tone: "info"
      }
    }

    delegate: Rectangle {
      id: row
      required property var modelData
      required property int index
      objectName: "approval-" + Model.key(modelData)
      width: list.width
      height: content.implicitHeight + 2 * Theme.space.s3
      radius: Theme.radius.md
      color: hover.hovered || ListView.isCurrentItem && list.activeFocus ? Theme.color.raised : Theme.color.panel
      border.width: ListView.isCurrentItem && list.activeFocus ? 2 : 1
      border.color: ListView.isCurrentItem && list.activeFocus ? Theme.color.lime : Theme.color.line
      Accessible.role: Accessible.ListItem
      Accessible.name: root.rowTitle(modelData)
      Accessible.onPressAction: root.controller.open(modelData)

      HoverHandler { id: hover; cursorShape: Qt.PointingHandCursor }
      TapHandler { onTapped: root.controller.open(row.modelData) }

      Column {
        id: content
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: Theme.space.s4
        anchors.rightMargin: Theme.space.s4
        spacing: Theme.space.s1
        Row {
          spacing: Theme.space.s2
          Chip { text: root.app.t(Model.isOperation(row.modelData) ? "kind.operation" : "kind.exchange"); tone: "neutral" }
          Chip {
            visible: Model.isOperation(row.modelData)
            text: Model.isOperation(row.modelData) ? root.app.tn("row.operations", (row.modelData.operation_ids || []).length) : ""
            tone: "info"
          }
        }
        Text {
          width: parent.width
          text: root.rowTitle(row.modelData)
          textFormat: Text.PlainText
          elide: Text.ElideRight
          color: Theme.color.ink
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.base
          font.weight: Font.DemiBold
          font.variableAxes: ({ "wght": 600 })
        }
        Text {
          objectName: "row-recipient"
          width: parent.width
          readonly property var authority: Model.authority(row.modelData)
          text: root.app.t("detail.recipient") + ": " + root.app.t(authority.recipient.key, authority.recipient.args)
          textFormat: Text.PlainText
          elide: Text.ElideRight
          color: Theme.color.inkSoft
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.sm
        }
        Text {
          width: parent.width
          readonly property var remainingMs: Model.remaining(row.modelData, root.tick || root.controller.serverNow())
          visible: remainingMs !== null && root.controller.serverClockKnown
          text: remainingMs !== null ? root.app.t("row.closes", { time: Model.formatRemaining(remainingMs) }) : ""
          textFormat: Text.PlainText
          color: remainingMs !== null && remainingMs < 60000 ? Theme.color.warn : Theme.color.muted
          font.family: Theme.font.sans
          font.pixelSize: Theme.font.xs
        }
      }
    }

    Keys.onReturnPressed: if (currentIndex >= 0) controller.open(controller.approvals[currentIndex])
    Keys.onSpacePressed: if (currentIndex >= 0) controller.open(controller.approvals[currentIndex])
  }

  Text {
    anchors.centerIn: parent
    visible: !controller.listLoaded && controller.listLoading
    text: app.t("queue.loading")
    textFormat: Text.PlainText
    color: Theme.color.muted
    font.family: Theme.font.sans
    font.pixelSize: Theme.font.md
  }
}

import QtQuick 2.12
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.12

Rectangle {
    property var viewData

    ScrollView {
        anchors.fill: parent
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
        ScrollBar.vertical.policy: ScrollBar.AlwaysOn
        clip: true
        contentWidth: parent.width
        id: sv

        GridLayout {
            columns: 2
            width: sv.availableWidth
            Text {
                text: "Genesis"
            }
            TextEdit {
                text: viewData.genesis
                readOnly: true
                selectByMouse: true
                Layout.fillWidth: true
                wrapMode: TextEdit.Wrap
            }

            Text {
                text: "Heads"
            }
            TextEdit {
                text: viewData.heads
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
                Layout.fillWidth: true
                onLinkActivated: main.openUrl(link)
            }

            Text {
                text: "Identity"
            }
            TextEdit {
                text: viewData.identity
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
                Layout.fillWidth: true
                wrapMode: TextEdit.Wrap
            }

            Text {
                text: "Version"
            }
            TextEdit {
                text: viewData.version
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Health"
            }
            TextEdit {
                text: viewData.health
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }
        }
    }
}

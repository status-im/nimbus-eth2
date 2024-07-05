import QtQuick 2.12
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.12

Rectangle {
    property var viewData

    ColumnLayout {
        anchors.fill: parent
        RowLayout {
            Label {
                text: "Block / slot"
            }
            TextField {
                selectByMouse: true
                id: urlTextField
                width: 640
                text: "head"
            }
            Button {
                text: "Load"
                onClicked: main.onLoadBlock(urlTextField.text)
                enabled: urlTextField.text !== ""
            }
        }

        GridLayout {
            columns: 2

            Text {
                text: "Slot"
            }
            TextEdit {
                text: viewData.slot
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Time"
            }
            TextEdit {
                text: viewData.time
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Block root"
            }
            TextEdit {
                text: viewData.root
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Proposer"
            }
            TextEdit {
                text: viewData.proposer_index
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Parent root"
            }
            TextEdit {
                text: viewData.parent_root
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
                onLinkActivated: main.openUrl(link)
            }

            Text {
                text: "State root"
            }
            TextEdit {
                text: viewData.state_root
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Randao reveal"
            }
            TextEdit {
                text: viewData.randao_reveal
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Eth1"
            }
            TextEdit {
                text: viewData.eth1_data
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Graffiti"
            }
            TextEdit {
                text: viewData.graffiti
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }

            Text {
                text: "Signature"
            }
            TextEdit {
                text: viewData.signature
                textFormat: TextEdit.RichText
                readOnly: true
                selectByMouse: true
            }
        }

        TabBar {
            id: tabBar

            TabButton {
                text: "Attestations: " + viewData.attestations.rowCount()
                width: implicitWidth
            }
            TabButton {
                text: "Deposits: " + viewData.deposits.rowCount()
                width: implicitWidth
            }
            TabButton {
                text: "Attester slashings: " + viewData.attester_slashings.rowCount()
                width: implicitWidth
            }
            TabButton {
                text: "Proposer slashings: " + viewData.proposer_slashings.rowCount()
                width: implicitWidth
            }
            TabButton {
                text: "Voluntary exits: " + viewData.voluntary_exits.rowCount()
                width: implicitWidth
            }
        }

        StackLayout {
            Layout.fillHeight: true
            Layout.fillWidth: true
            currentIndex: tabBar.currentIndex

            ObjectTableView {
                model: viewData.attestations
                columnWidthProvider: function (column) {
                    if (column == 0)
                        return 120
                    if (column == 1)
                        return 60
                    if (column == 2)
                        return 250
                    if (column == 3)
                        return 100
                    if (column == 4)
                        return 250
                    if (column == 5)
                        return 100
                    if (column == 6)
                        return 250
                    return 350
                }
            }

            ObjectTableView {
                model: viewData.deposits
                columnWidthProvider: function (column) {
                    if (column == 0)
                        return 250
                    if (column == 1)
                        return 250
                    if (column == 2)
                        return 100
                    return 350
                }
            }

            ObjectTableView {
                model: viewData.attester_slashings
                columnWidthProvider: function (column) {
                    return 350
                }
            }
            ObjectTableView {
                model: viewData.proposer_slashings
                columnWidthProvider: function (column) {
                    return 350
                }
            }
            ObjectTableView {
                model: viewData.voluntary_exits
                columnWidthProvider: function (column) {
                    return 350
                }
            }
        }
    }
}

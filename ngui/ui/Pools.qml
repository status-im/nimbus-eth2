import QtQuick 2.12
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.12

Rectangle {
    property var viewData

    ColumnLayout {
        anchors.fill: parent

        TabBar {
            id: tabBar

            TabButton {
                text: "Attestations"
                width: implicitWidth
                onClicked: viewData.updateAttestations()
            }
            TabButton {
                text: "Attester slashings"
                width: implicitWidth
                onClicked: viewData.updateAttesterSlashings()
            }
            TabButton {
                text: "Proposer slashings"
                width: implicitWidth
                onClicked: viewData.updatProposerSlashings()
            }
            TabButton {
                text: "Voluntary exits"
                width: implicitWidth
                onClicked: viewData.updateVoluntaryExits()
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
                model: viewData.attesterSlashings
                columnWidthProvider: function (column) {
                    return 350
                }
            }
            ObjectTableView {
                model: viewData.proposerSlashings
                columnWidthProvider: function (column) {
                    return 350
                }
            }
            ObjectTableView {
                model: viewData.voluntaryExits
                columnWidthProvider: function (column) {
                    return 350
                }
            }
        }
    }
}

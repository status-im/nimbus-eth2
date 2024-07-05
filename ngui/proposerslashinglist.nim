import
  std/[sequtils, tables],
  NimQml,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  ../beacon_chain/spec/helpers,
  ./objecttablemodel, ./utils

type
  ProposerSlashingInfo* = object
    info*: string

proc toProposerSlashingInfo*(v: ProposerSlashing): ProposerSlashingInfo =
  ProposerSlashingInfo(
    info: $v
  )

QtObject:
  type ProposerSlashingList* = ref object of QAbstractTableModel
    # TODO this could be a generic ObjectTableModel, except generics + method don't work..
    data: ObjectTableModelImpl[ProposerSlashingInfo]

  proc setup(self: ProposerSlashingList) = self.QAbstractTableModel.setup

  proc delete(self: ProposerSlashingList) =
    self.QAbstractTableModel.delete

  proc newProposerSlashingList*(data: openArray[ProposerSlashing]): ProposerSlashingList =
    new(result, delete)
    result.data = ObjectTableModelImpl[ProposerSlashingInfo](items: data.mapIt(it.toProposerSlashingInfo()))
    result.setup

  method rowCount(self: ProposerSlashingList, index: QModelIndex = nil): int =
    self.data.rowCount(index)

  method columnCount(self: ProposerSlashingList, index: QModelIndex = nil): int =
    self.data.columnCount(index)

  method headerData*(self: ProposerSlashingList, section: int, orientation: QtOrientation, role: int): QVariant =
    self.data.headerData(section, orientation, role)

  method data(self: ProposerSlashingList, index: QModelIndex, role: int): QVariant =
    self.data.data(index, role)

  method roleNames(self: ProposerSlashingList): Table[int, string] =
    self.data.roleNames()

  proc setNewData*(self: ProposerSlashingList, v: seq[ProposerSlashing]) =
    self.data.setNewData(self, v.mapIt(it.toProposerSlashingInfo()))

  proc sort*(self: ProposerSlashingList, section: int) {.slot.} =
    self.data.sort(self, section)

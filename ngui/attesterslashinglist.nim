import
  std/[sequtils, tables],
  NimQml,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  ../beacon_chain/spec/[helpers],
  ./objecttablemodel, ./utils

type
  AttesterSlashingInfo* = object
    info*: string

proc toAttesterSlashingInfo*(v: AttesterSlashing): AttesterSlashingInfo =
  AttesterSlashingInfo(
    info: $v
  )

QtObject:
  type AttesterSlashingList* = ref object of QAbstractTableModel
    # TODO this could be a generic ObjectTableModel, except generics + method don't work..
    data: ObjectTableModelImpl[AttesterSlashingInfo]

  proc setup(self: AttesterSlashingList) = self.QAbstractTableModel.setup

  proc delete(self: AttesterSlashingList) =
    self.QAbstractTableModel.delete

  proc newAttesterSlashingList*(data: openArray[AttesterSlashing]): AttesterSlashingList =
    new(result, delete)
    result.data = ObjectTableModelImpl[AttesterSlashingInfo](items: data.mapIt(it.toAttesterSlashingInfo()))
    result.setup

  method rowCount(self: AttesterSlashingList, index: QModelIndex = nil): int =
    self.data.rowCount(index)

  method columnCount(self: AttesterSlashingList, index: QModelIndex = nil): int =
    self.data.columnCount(index)

  method headerData*(self: AttesterSlashingList, section: int, orientation: QtOrientation, role: int): QVariant =
    self.data.headerData(section, orientation, role)

  method data(self: AttesterSlashingList, index: QModelIndex, role: int): QVariant =
    self.data.data(index, role)

  method roleNames(self: AttesterSlashingList): Table[int, string] =
    self.data.roleNames()

  proc setNewData*(self: AttesterSlashingList, v: openArray[AttesterSlashing]) =
    self.data.setNewData(self, v.mapIt(it.toAttesterSlashingInfo()))

  proc sort*(self: AttesterSlashingList, section: int) {.slot.} =
    self.data.sort(self, section)

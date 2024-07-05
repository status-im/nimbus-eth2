import
  std/[sequtils, tables],
  NimQml,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  ../beacon_chain/spec/helpers,
  ./objecttablemodel, ./utils

type
  VoluntaryExitInfo* = object
    info*: string

proc toVoluntaryExitInfo*(v: SignedVoluntaryExit): VoluntaryExitInfo =
  VoluntaryExitInfo(
    info: $v
  )

QtObject:
  type VoluntaryExitList* = ref object of QAbstractTableModel
    # TODO this could be a generic ObjectTableModel, except generics + method don't work..
    data: ObjectTableModelImpl[VoluntaryExitInfo]

  proc setup(self: VoluntaryExitList) = self.QAbstractTableModel.setup

  proc delete(self: VoluntaryExitList) =
    self.QAbstractTableModel.delete

  proc newVoluntaryExitList*(data: openArray[SignedVoluntaryExit]): VoluntaryExitList =
    new(result, delete)
    result.data = ObjectTableModelImpl[VoluntaryExitInfo](items: data.mapIt(it.toVoluntaryExitInfo()))
    result.setup

  method rowCount(self: VoluntaryExitList, index: QModelIndex = nil): int =
    self.data.rowCount(index)

  method columnCount(self: VoluntaryExitList, index: QModelIndex = nil): int =
    self.data.columnCount(index)

  method headerData*(self: VoluntaryExitList, section: int, orientation: QtOrientation, role: int): QVariant =
    self.data.headerData(section, orientation, role)

  method data(self: VoluntaryExitList, index: QModelIndex, role: int): QVariant =
    self.data.data(index, role)

  method roleNames(self: VoluntaryExitList): Table[int, string] =
    self.data.roleNames()

  proc setNewData*(self: VoluntaryExitList, v: openArray[SignedVoluntaryExit]) =
    self.data.setNewData(self, v.mapIt(it.toVoluntaryExitInfo()))

  proc sort*(self: VoluntaryExitList, section: int) {.slot.} =
    self.data.sort(self, section)

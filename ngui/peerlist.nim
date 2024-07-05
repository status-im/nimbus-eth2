import
  std/tables,
  NimQml,
  ../beacon_chain/spec/eth2_apis/rest_types,
  ./objecttablemodel

QtObject:
  type PeerList* = ref object of QAbstractTableModel
    # TODO this could be a generic ObjectTableModel, except generics + method don't work..
    data: ObjectTableModelImpl[RestNodePeer]

  proc setup(self: PeerList) = self.QAbstractTableModel.setup
  proc delete(self: PeerList) = self.QAbstractTableModel.delete

  proc newPeerList*(items: seq[RestNodePeer]): PeerList =
    new(result, delete)
    result.data = ObjectTableModelImpl[RestNodePeer].init(items)
    result.setup

  method rowCount(self: PeerList, index: QModelIndex = nil): int =
    self.data.rowCount(index)

  method columnCount(self: PeerList, index: QModelIndex = nil): int =
    self.data.columnCount(index)

  method headerData*(self: PeerList, section: int, orientation: QtOrientation, role: int): QVariant =
    self.data.headerData(section, orientation, role)

  method data(self: PeerList, index: QModelIndex, role: int): QVariant =
    self.data.data(index, role)

  method roleNames(self: PeerList): Table[int, string] =
    self.data.roleNames()

  proc setNewData*(self: PeerList, v: seq[RestNodePeer]) =
    self.data.setNewData(self, v)

  proc sort*(self: PeerList, section: int) {.slot.} =
    self.data.sort(self, section)

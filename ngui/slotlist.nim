import
  std/[tables],
  NimQml,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  ../beacon_chain/spec/[eth2_merkleization, helpers],
  ./objecttablemodel, ./utils

type
  SlotInfo* = object
    slot*: int
    proposer_index*: int
    block_root*: string

proc loadSlots*(client: RestClientRef, epoch: Epoch): seq[SlotInfo] {.raises: [Defect].} =
  var res: seq[SlotInfo]
  let proposers = try:
    (waitFor client.getProposerDuties(epoch)).data.data
  except CatchableError:
    newSeq[RestProposerDuty](SLOTS_PER_EPOCH)

  for i in 0..<SLOTS_PER_EPOCH:
    let
      slot = epoch.start_slot() + i
      block_root =
        try:
          let h = waitFor client.getBlockHeader(BlockIdent.init(slot))
          if h.isSome() and h[].data.header.message.slot == slot:
            toBlockLink(h[].data.root)
          else:
            "N/A"
        except CatchableError as exc:
          "N/A"
    res.add SlotInfo(
      slot: slot.int,
      proposer_index: proposers[i].validator_index.int,
      block_root: block_root
      )
  res

QtObject:
  type SlotList* = ref object of QAbstractTableModel
    # TODO this could be a generic ObjectTableModel, except generics + method don't work..
    data: ObjectTableModelImpl[SlotInfo]

  proc setup(self: SlotList) = self.QAbstractTableModel.setup

  proc delete(self: SlotList) =
    self.QAbstractTableModel.delete

  proc newSlotList*(data: seq[SlotInfo]): SlotList =
    new(result, delete)
    result.data = ObjectTableModelImpl[SlotInfo](items: data)
    result.setup

  method rowCount(self: SlotList, index: QModelIndex = nil): int =
    self.data.rowCount(index)

  method columnCount(self: SlotList, index: QModelIndex = nil): int =
    self.data.columnCount(index)

  method headerData*(self: SlotList, section: int, orientation: QtOrientation, role: int): QVariant =
    self.data.headerData(section, orientation, role)

  method data(self: SlotList, index: QModelIndex, role: int): QVariant =
    self.data.data(index, role)

  method roleNames(self: SlotList): Table[int, string] =
    self.data.roleNames()

  proc setNewData*(self: SlotList,  v: seq[SlotInfo]) =
    self.data.setNewData(self, v)

  proc sort*(self: SlotList, section: int) {.slot.} =
    self.data.sort(self, section)

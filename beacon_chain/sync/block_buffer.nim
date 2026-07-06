# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Std lib
  std/tables,
  # Status libs
  results,
  ../consensus_object_pools/block_pools_types,
  ./[sync_response, sync_queue],
  ../spec/forks

export sync_response, sync_queue

type
  BlocksRangeBuffer* = object
    direction: SyncQueueKind
    items: seq[SyncResponseItem]
    roots: Table[Eth2Digest, ref ForkedSignedBeaconBlock]
    maxBufferSize: int

  BlocksRootBuffer* = object
    roots: Table[Eth2Digest, ForkedSignedBeaconBlock]

func startSlot*(buffer: BlocksRangeBuffer): Slot =
  buffer.items[0].slot

func lastSlot*(buffer: BlocksRangeBuffer): Slot =
  buffer.items[^1].slot

func startItem*(buffer: BlocksRangeBuffer): SyncResponseItem =
  buffer.items[0]

func lastItem*(buffer: BlocksRangeBuffer): SyncResponseItem =
  buffer.items[^1]

func shortLog*(buffer: BlocksRangeBuffer): string =
  if len(buffer.items) == 0:
    return "[empty]"
  "[" & $buffer.startSlot & ":" & $buffer.lastSlot & "]/" & $len(buffer.items)

func getIndex(buffer: BlocksRangeBuffer, slot: Slot): Opt[int] =
  case buffer.direction
  of SyncQueueKind.Forward:
    if (slot < buffer.startSlot):
      return Opt.none(int)
    let res = uint64(slot - buffer.startSlot)
    if res >= lenu64(buffer.items):
      return Opt.none(int)
    # `int` conversion is safe here, because we compared `res` value with
    # length of `items` sequence.
    Opt.some(int(res))
  of SyncQueueKind.Backward:
    if (slot > buffer.startSlot):
      return Opt.none(int)
    let res = uint64(buffer.startSlot - slot)
    if res >= lenu64(buffer.items):
      return Opt.none(int)
    # `int` conversion is safe here, because we compared `res` value with
    # length of `items` sequence.
    Opt.some(int(res))

func toSlot(buffer: BlocksRangeBuffer, index: int): Opt[Slot] =
  if (index < 0) or (index >= len(buffer.items)):
    return Opt.none(Slot)
  case buffer.direction
  of SyncQueueKind.Forward:
    Opt.some(buffer.startSlot + uint64(index))
  of SyncQueueKind.Backward:
    Opt.some(buffer.startSlot - uint64(index))

func `[]`*(
    buffer: BlocksRangeBuffer,
    slot: Slot
): Opt[SyncResponseItem] =
  if len(buffer.items) == 0:
    return Opt.none(SyncResponseItem)
  let index = buffer.getIndex(slot).valueOr:
    return Opt.none(SyncResponseItem)
  let item = buffer.items[index]
  if item.slot != slot:
    return Opt.none(SyncResponseItem)
  Opt.some(item)

template isNew(buffer: BlocksRangeBuffer, s: Slot): bool =
  case buffer.direction
  of SyncQueueKind.Forward:
    buffer.lastSlot < s
  of SyncQueueKind.Backward:
    buffer.lastSlot > s

func fillGap(
    buffer: var BlocksRangeBuffer,
    slot: Slot
) =
  let lastItem = buffer.lastItem
  case buffer.direction
  of SyncQueueKind.Forward:
    let count = int(slot - lastItem.slot) - 1
    for i in 0 ..< count:
      buffer.items.add(lastItem)
  of SyncQueueKind.Backward:
    let count = int(lastItem.slot - slot) - 1
    for i in 0 ..< count:
      buffer.items.add(lastItem)

func resetBuffer(buffer: var BlocksRangeBuffer, count: int) =
  for index in count ..< len(buffer.items):
    # let item = buffer.items[index]
    # buffer.roots.del(blck[].root)
    buffer.items[index] = default(SyncResponseItem)
  buffer.items.setLen(count)

func before(buffer: BlocksRangeBuffer, slota, slotb: Slot): bool =
  case buffer.direction
  of SyncQueueKind.Forward:
    slota < slotb
  of SyncQueueKind.Backward:
    slota > slotb

func beforeOrEq(buffer: BlocksRangeBuffer, slota, slotb: Slot): bool =
  case buffer.direction
  of SyncQueueKind.Forward:
    slota <= slotb
  of SyncQueueKind.Backward:
    slota >= slotb

func after(buffer: BlocksRangeBuffer, slota, slotb: Slot): bool =
  case buffer.direction
  of SyncQueueKind.Forward:
    slota > slotb
  of SyncQueueKind.Backward:
    slota < slotb

func prev(buffer: BlocksRangeBuffer, slot: Slot): Slot =
  case buffer.direction
  of SyncQueueKind.Forward:
    if slot == GENESIS_SLOT:
      return slot
    slot - 1
  of SyncQueueKind.Backward:
    if slot == FAR_FUTURE_SLOT:
      return FAR_FUTURE_SLOT
    slot + 1

func checkRoots(
    buffer: BlocksRangeBuffer,
    newBlock, lastBlock: ref ForkedSignedBeaconBlock
): bool =
  case buffer.direction
  of SyncQueueKind.Forward:
    lastBlock[].root() == newBlock[].parent_root()
  of SyncQueueKind.Backward:
    newBlock[].root() == lastBlock[].parent_root()

proc add*(
    buffer: var BlocksRangeBuffer,
    item: SyncResponseItem
): Result[void, VerifierError] =
  let
    (blockSlot, blockRoot, blockParentRoot) =
      withBlck(item.signedBlock[]):
        (forkyBlck.message.slot, forkyBlck.root, forkyBlck.message.parent_root)

  if len(buffer.items) == 0:
    buffer.items.add(item)
    # buffer.roots[blockRoot] = blck
    return ok()

  if buffer.before(blockSlot, buffer.startSlot):
    buffer.resetBuffer(0)
    buffer.items.add(item)
    # buffer.roots[blockRoot] = blck
    return ok()

  if buffer.isNew(blockSlot):
    # This is new block
    let lastItem = buffer.lastItem()
    if not(buffer.checkRoots(item.signedBlock, lastItem.signedBlock)):
      return err(VerifierError.MissingParent)
    buffer.fillGap(blockSlot)
    buffer.items.add(item)
    # buffer.roots[blockRoot] = blck
    ok()
  else:
    # Block replacement
    let
      index = buffer.getIndex(blockSlot).get()
      innerItem = buffer.items[index]
    if (innerItem.slot == blockSlot) and (innerItem.root == blockRoot) and
       (innerItem.parent_root == blockParentRoot):
      return err(VerifierError.Duplicate)
    if index == 0:
      buffer.resetBuffer(0)
      buffer.items.add(item)
      # buffer.roots[blockRoot] = blck
      return ok()

    let prevItem = buffer.items[index - 1]
    if not(buffer.checkRoots(item.signedBlock, prevItem.signedBlock)):
      return err(VerifierError.MissingParent)
    buffer.resetBuffer(index)
    buffer.items.add(item)
    # buffer.roots[blockRoot] = blck
    ok()

iterator items(
    buffer: BlocksRangeBuffer,
    index, count: int
): SyncResponseItem =
  case buffer.direction
  of SyncQueueKind.Forward:
    let lastIndex = min(len(buffer.items) - 1, index + count - 1)
    for i in countup(index, lastIndex):
      let item = buffer.items[i]
      if item.slot == buffer.toSlot(i).get():
        yield item
  of SyncQueueKind.Backward:
    let lastIndex = max(0, index - count + 1)
    for i in countdown(index, lastIndex):
      if buffer.items[i].slot == buffer.toSlot(i).get():
        let item = buffer.items[i]
        if item.slot == buffer.toSlot(i).get():
          yield item

func contains*(buffer: BlocksRangeBuffer, srange: SyncRange): bool =
  doAssert(srange.count > 0)
  if len(buffer.items) == 0:
    return false
  if (srange.last_slot() < buffer.startSlot()) or
     (srange.start_slot() > buffer.lastSlot()):
    return false
  true

func peekRange*(
    buffer: BlocksRangeBuffer,
    srange: SyncRange
): seq[SyncResponseItem] =
  var res: seq[SyncResponseItem]

  if len(buffer.items) == 0:
    return res

  let
    (startSlot, lastSlot, ecount) =
      case buffer.direction
      of SyncQueueKind.Forward:
        if srange.start_slot() > buffer.lastSlot:
          return res
        if srange.last_slot() < buffer.startSlot:
          return res
        let
          slota =
            if srange.start_slot() <= buffer.startSlot:
              buffer.startSlot
            else:
              srange.start_slot()
          startGap = slota - srange.start_slot()
          slotb = slota + uint64(srange.count - 1) - startGap
        (slota, slotb, int(slotb - slota + 1))
      of SyncQueueKind.Backward:
        if srange.start_slot() > buffer.startSlot:
          return res
        if srange.last_slot() < buffer.lastSlot:
          return res
        let
          slota =
            if srange.start_slot() <= buffer.lastSlot:
              buffer.lastSlot
            else:
              srange.start_slot()
          lastGap = slota - srange.start_slot()
          slotb = slota + uint64(srange.count - 1) - lastGap
        (slota, slotb, int(slotb - slota + 1))
    startIndex = buffer.getIndex(startSlot).valueOr:
      return res

  for item in buffer.items(startIndex, ecount):
    if len(res) == 0:
      res.add(item)
    else:
      if res[^1] != item:
        res.add(item)
    if item.slot == lastSlot:
      break
  res

func getNonEmptyIndex(
    buffer: BlocksRangeBuffer,
    slot: Slot,
    forward: bool
): Opt[int] =
  var res = ? buffer.getIndex(slot)
  if buffer.items[res].slot == slot:
    return Opt.some(res)
  if forward:
    for index in countup(res, len(buffer.items) - 1):
      if buffer.items[index].slot == buffer.toSlot(index).get():
        return Opt.some(index)
  else:
    for index in countdown(res, 0):
      if buffer.items[index].slot == buffer.toSlot(index).get():
        return Opt.some(index)
  Opt.none(int)

proc advance*(
    buffer: var BlocksRangeBuffer,
    slot: Slot
) =
  if len(buffer.items) == 0:
    return
  if buffer.beforeOrEq(slot, buffer.startSlot):
    return
  if buffer.after(slot, buffer.lastSlot):
    buffer.resetBuffer(0)
    return
  let startIndex = buffer.getNonEmptyIndex(slot, true).valueOr:
    buffer.resetBuffer(0)
    return

  var count = 0
  for index in startIndex ..< len(buffer.items):
    # let item = buffer.items[count]
    # buffer.roots.del(item.root)
    buffer.items[count] = buffer.items[index]
    inc(count)
  buffer.resetBuffer(count)

proc invalidate*(
    buffer: var BlocksRangeBuffer,
    slot: Slot
) =
  if len(buffer.items) == 0:
    return
  if buffer.beforeOrEq(slot, buffer.startSlot):
    buffer.resetBuffer(0)
    return
  if buffer.after(slot, buffer.lastSlot):
    return

  let startIndex = buffer.getNonEmptyIndex(buffer.prev(slot), false).valueOr:
    buffer.resetBuffer(0)
    return

  buffer.resetBuffer(startIndex + 1)

func len*(buffer: BlocksRangeBuffer): int =
  len(buffer.items)

func almostFull*(buffer: BlocksRangeBuffer): bool =
  # len(buffer.blocks) >= 2/3 * maxBufferSize
  len(buffer.items) >= 2 * (buffer.maxBufferSize div 3)

func reset*(buffer: var BlocksRangeBuffer) =
  buffer.resetBuffer(0)

func init*(
    t: typedesc[BlocksRangeBuffer],
    kind: SyncQueueKind,
): BlocksRangeBuffer =
  BlocksRangeBuffer(
    direction: kind,
  )

func init*(
    t: typedesc[BlocksRangeBuffer],
    kind: SyncQueueKind,
    maxBufferSize: int,
): BlocksRangeBuffer =
  doAssert(maxBufferSize > 0, "Buffer size could not be negative or zero")
  BlocksRangeBuffer(
    direction: kind,
    maxBufferSize: maxBufferSize,
  )

const
  MissingBlock = ForkedSignedBeaconBlock.init(
    phase0.SignedBeaconBlock(
      message: phase0.BeaconBlock(slot: FAR_FUTURE_SLOT)))

func new*(
    t: typedesc[BlocksRangeBuffer],
    kind: SyncQueueKind,
    maxBufferSize: int
): ref BlocksRangeBuffer =
  newClone BlocksRangeBuffer.init(kind, maxBufferSize)

proc add*(
    buffer: var BlocksRootBuffer,
    blck: ForkedSignedBeaconBlock
) =
  buffer.roots[blck.root] = blck

proc add*(
    buffer: var BlocksRootBuffer,
    blcks: openArray[ForkedSignedBeaconBlock]
) =
  for blck in blcks:
    buffer.roots[blck.root] = blck

func popRoot*(
    buffer: var BlocksRootBuffer,
    root: Eth2Digest
): Opt[ForkedSignedBeaconBlock] =
  var res: ForkedSignedBeaconBlock
  if buffer.roots.pop(root, res):
    return ok(res)
  Opt.none(ForkedSignedBeaconBlock)

func remove*(
    buffer: var BlocksRootBuffer,
    root: Eth2Digest
) =
  buffer.roots.del(root)

func prune*(
    buffer: var BlocksRootBuffer,
    epoch: Epoch
) =
  var entriesToDelete: seq[Eth2Digest]

  let startSlot = epoch.start_slot()
  for key, blck in buffer.roots.pairs():
    let slot = blck.slot()
    if slot < startSlot:
      entriesToDelete.add(key)

  for key in entriesToDelete:
    buffer.roots.del(key)

func getBlock*(
    buffer: BlocksRootBuffer,
    root: Eth2Digest
): Opt[ForkedSignedBeaconBlock] =
  let blck = buffer.roots.getOrDefault(root, MissingBlock)
  if blck.slot == FAR_FUTURE_SLOT:
    return Opt.none(ForkedSignedBeaconBlock)
  Opt.some(blck)

func len*(buffer: BlocksRootBuffer): int =
  len(buffer.roots)

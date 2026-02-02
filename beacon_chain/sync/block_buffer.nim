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
  ../sync/sync_queue,
  ../spec/forks

type
  BlocksRangeBuffer* = object
    direction: SyncQueueKind
    blocks: seq[ref ForkedSignedBeaconBlock]
    roots: Table[Eth2Digest, ref ForkedSignedBeaconBlock]
    maxBufferSize: int

  BlocksRootBuffer* = object
    roots: Table[Eth2Digest, ref ForkedSignedBeaconBlock]

func startSlot*(buffer: BlocksRangeBuffer): Slot =
  buffer.blocks[0][].slot

func lastSlot*(buffer: BlocksRangeBuffer): Slot =
  buffer.blocks[^1][].slot

func startBlock*(buffer: BlocksRangeBuffer): ref ForkedSignedBeaconBlock =
  buffer.blocks[0]

func lastBlock*(buffer: BlocksRangeBuffer): ref ForkedSignedBeaconBlock =
  buffer.blocks[^1]

func shortLog*(buffer: BlocksRangeBuffer): string =
  if len(buffer.blocks) == 0:
    return "[empty]"
  "[" & $buffer.startSlot & ":" & $buffer.lastSlot & "]/" & $len(buffer.blocks)

func getIndex(buffer: BlocksRangeBuffer, slot: Slot): Opt[int] =
  case buffer.direction
  of SyncQueueKind.Forward:
    if (slot < buffer.startSlot):
      return Opt.none(int)
    let res = uint64(slot - buffer.startSlot)
    if res >= lenu64(buffer.blocks):
      return Opt.none(int)
    # `int` conversion is safe here, because we compared `res` value with
    # length of `blocks` sequence.
    Opt.some(int(res))
  of SyncQueueKind.Backward:
    if (slot > buffer.startSlot):
      return Opt.none(int)
    let res = uint64(buffer.startSlot - slot)
    if res >= lenu64(buffer.blocks):
      return Opt.none(int)
    # `int` conversion is safe here, because we compared `res` value with
    # length of `blocks` sequence.
    Opt.some(int(res))

func toSlot(buffer: BlocksRangeBuffer, index: int): Opt[Slot] =
  if (index < 0) or (index >= len(buffer.blocks)):
    return Opt.none(Slot)
  case buffer.direction
  of SyncQueueKind.Forward:
    Opt.some(buffer.startSlot + uint64(index))
  of SyncQueueKind.Backward:
    Opt.some(buffer.startSlot - uint64(index))

func `[]`*(
    buffer: BlocksRangeBuffer,
    root: Eth2Digest
): ref ForkedSignedBeaconBlock =
  buffer.roots.getOrDefault(root)

func `[]`*(
    buffer: BlocksRangeBuffer,
    slot: Slot
): ref ForkedSignedBeaconBlock =
  if len(buffer.blocks) == 0:
    return nil
  let index = buffer.getIndex(slot).valueOr:
    return nil
  let blck = buffer.blocks[index]
  if blck[].slot != slot:
    return nil
  blck

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
  let lastBlock = buffer.lastBlock
  case buffer.direction
  of SyncQueueKind.Forward:
    let count = int(slot - lastBlock[].slot) - 1
    for i in 0 ..< count:
      buffer.blocks.add(lastBlock)
  of SyncQueueKind.Backward:
    let count = int(lastBlock[].slot - slot) - 1
    for i in 0 ..< count:
      buffer.blocks.add(lastBlock)

func resetBuffer(buffer: var BlocksRangeBuffer, count: int) =
  for index in count ..< len(buffer.blocks):
    let blck = buffer.blocks[index]
    buffer.roots.del(blck[].root)
    buffer.blocks[index] = nil
  buffer.blocks.setLen(count)

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
    blck: ref ForkedSignedBeaconBlock
): Result[void, VerifierError] =
  doAssert(not(isNil(blck)), "Block should not be nil at this point!")

  let
    (blockSlot, blockRoot, blockParentRoot) =
      withBlck(blck[]):
        (forkyBlck.message.slot, forkyBlck.root, forkyBlck.message.parent_root)

  if len(buffer.blocks) == 0:
    buffer.blocks.add(blck)
    buffer.roots[blockRoot] = blck
    return ok()

  if buffer.before(blockSlot, buffer.startSlot):
    buffer.resetBuffer(0)
    buffer.blocks.add(blck)
    buffer.roots[blockRoot] = blck
    return ok()

  if buffer.isNew(blockSlot):
    # This is new block
    let lastBlock = buffer.blocks[^1]
    if not(buffer.checkRoots(blck, lastBlock)):
      return err(VerifierError.MissingParent)
    buffer.fillGap(blockSlot)
    buffer.blocks.add(blck)
    buffer.roots[blockRoot] = blck
    ok()
  else:
    # Block replacement
    let
      index = buffer.getIndex(blockSlot).get()
      innerBlock = buffer.blocks[index]
    if (innerBlock[].slot == blockSlot) and (innerBlock[].root == blockRoot) and
       (innerBlock[].parent_root == blockParentRoot):
      return err(VerifierError.Duplicate)
    if index == 0:
      buffer.resetBuffer(0)
      buffer.blocks.add(blck)
      buffer.roots[blockRoot] = blck
      return ok()

    let prevBlock = buffer.blocks[index - 1]
    if not(buffer.checkRoots(blck, prevBlock)):
      return err(VerifierError.MissingParent)
    buffer.resetBuffer(index)
    buffer.blocks.add(blck)
    buffer.roots[blockRoot] = blck
    ok()

iterator blocks(
    buffer: BlocksRangeBuffer,
    index, count: int
): ref ForkedSignedBeaconBlock =
  case buffer.direction
  of SyncQueueKind.Forward:
    let lastIndex = min(len(buffer.blocks) - 1, index + count - 1)
    for i in countup(index, lastIndex):
      let blck = buffer.blocks[i]
      if blck[].slot == buffer.toSlot(i).get():
        yield blck
  of SyncQueueKind.Backward:
    let lastIndex = max(0, index - count + 1)
    for i in countdown(index, lastIndex):
      if buffer.blocks[i][].slot == buffer.toSlot(i).get():
        let blck = buffer.blocks[i]
        if blck[].slot == buffer.toSlot(i).get():
          yield blck

func contains*(buffer: BlocksRangeBuffer, srange: SyncRange): bool =
  doAssert(srange.count > 0)
  if len(buffer.blocks) == 0:
    return false
  if (srange.last_slot() < buffer.startSlot()) or
    (srange.start_slot() > buffer.lastSlot()):
    return false
  true

func peekRange*(
    buffer: BlocksRangeBuffer,
    srange: SyncRange
): seq[ref ForkedSignedBeaconBlock] =
  var res: seq[ref ForkedSignedBeaconBlock]

  if len(buffer.blocks) == 0:
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

  for blck in buffer.blocks(startIndex, ecount):
    if len(res) == 0:
      res.add(blck)
    else:
      if res[^1] != blck:
        res.add(blck)
    if blck[].slot == lastSlot:
      break
  res

func getNonEmptyIndex(
    buffer: BlocksRangeBuffer,
    slot: Slot,
    forward: bool
): Opt[int] =
  var res = ? buffer.getIndex(slot)
  if buffer.blocks[res][].slot == slot:
    return Opt.some(res)
  if forward:
    for index in countup(res, len(buffer.blocks) - 1):
      if buffer.blocks[index][].slot == buffer.toSlot(index).get():
        return Opt.some(index)
  else:
    for index in countdown(res, 0):
      if buffer.blocks[index][].slot == buffer.toSlot(index).get():
        return Opt.some(index)
  Opt.none(int)

proc advance*(
    buffer: var BlocksRangeBuffer,
    slot: Slot
) =
  if len(buffer.blocks) == 0:
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
  for index in startIndex ..< len(buffer.blocks):
    let blck = buffer.blocks[count]
    buffer.roots.del(blck[].root)
    buffer.blocks[count] = buffer.blocks[index]
    inc(count)
  buffer.resetBuffer(count)

proc invalidate*(
    buffer: var BlocksRangeBuffer,
    slot: Slot
) =
  if len(buffer.blocks) == 0:
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

proc add*(
    buffer: var BlocksRootBuffer,
    blck: ref ForkedSignedBeaconBlock
) =
  buffer.roots[blck[].root] = blck

proc add*(
    buffer: var BlocksRootBuffer,
    blcks: openArray[ref ForkedSignedBeaconBlock]
) =
  for blck in blcks:
    buffer.roots[blck[].root] = blck

func popRoot*(
    buffer: var BlocksRootBuffer,
    root: Eth2Digest
): ref ForkedSignedBeaconBlock =
  var res: ref ForkedSignedBeaconBlock
  discard buffer.roots.pop(root, res)
  res

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
    let slot = blck[].slot()
    if slot < startSlot:
      entriesToDelete.add(key)

  for key in entriesToDelete:
    buffer.roots.del(key)

func getOrDefault*(
    buffer: BlocksRootBuffer,
    root: Eth2Digest
): ref ForkedSignedBeaconBlock =
  buffer.roots.getOrDefault(root)

func len*(buffer: BlocksRootBuffer): int =
  len(buffer.roots)

func len*(buffer: BlocksRangeBuffer): int =
  len(buffer.blocks)

func almostFull*(buffer: BlocksRangeBuffer): bool =
  # len(buffer.blocks) >= 2/3 * maxBufferSize
  len(buffer.blocks) >= 2 * (buffer.maxBufferSize div 3)

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

func new*(
    t: typedesc[BlocksRangeBuffer],
    kind: SyncQueueKind,
    maxBufferSize: int
): ref BlocksRangeBuffer =
  newClone BlocksRangeBuffer.init(kind, maxBufferSize)

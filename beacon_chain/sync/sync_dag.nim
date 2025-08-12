# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
{.push raises: [].}

import std/[sets, tables, strutils]
import stew/base10, chronos, chronicles, results
import ../spec/[forks, block_id, column_map]
import ./sync_queue

type
  DagEntryFlag* {.pure.} = enum
    Local, Unviable, Finalized, Pending, MissingSidecars

  SyncDagEntryRef* = ref object
    blockId*: BlockId
    parent*: SyncDagEntryRef
    flags*: set[DagEntryFlag]

  PeerEntryRef*[A] = ref object
    peer*: A
    pendingRoots*: Deque[Eth2Digest]
    maxBlocksPerRequest*: int
    maxSidecarsPerRequest*: int
    columnsMap*: Opt[ColumnMap]
    peerLoopFut*: Future[void].Raising([])

  SyncDag*[A, B] = object
    roots*: Table[Eth2Digest, SyncDagEntryRef]
    slots*: Table[Slot, HashSet[Eth2Digest]]
    peers*: Table[B, PeerEntryRef[A]]
    lastSlot*: Slot

const
  EmptyBlockId* = BlockId(slot: FAR_FUTURE_SLOT)

func toBlockId*(checkpoint: Checkpoint): BlockId =
  BlockId(root: checkpoint.root, slot: checkpoint.epoch.start_slot())

func init*(
    t: typedesc[SyncDagEntryRef],
    blockId: BlockId
): SyncDagEntryRef =
  SyncDagEntryRef(
    blockId: blockId,
    flags: {DagEntryFlag.Pending})

func init*(
    t: typedesc[SyncDagEntryRef],
    root: Eth2Digest
): SyncDagEntryRef =
  SyncDagEntryRef(
    blockId: BlockId(root: root, slot: FAR_FUTURE_SLOT),
    flags: {DagEntryFlag.Pending})

func init*(
    t: typedesc[SyncDagEntryRef],
    checkpoint: Checkpoint
): SyncDagEntryRef =
  SyncDagEntryRef(
    blockId: checkpoint.toBlockId(),
    flags: {DagEntryFlag.Finalized, DagEntryFlag.Pending})

func init*[T](
    t: typedesc[PeerEntryRef],
    peer: T,
): PeerEntryRef[T] =
  PeerEntryRef[T](
    pendingRoots: initDeque[Eth2Digest](16),
    peer: peer,
    maxBlocksPerRequest: 2,
    maxSidecarsPerRequest: 16
  )

func init*[T](
    t: typedesc[PeerEntryRef],
    peer: T,
    columns: ColumnMap
): PeerEntryRef[T] =
  PeerEntryRef[T](
    pendingRoots: initDeque[Eth2Digest](16),
    peer: peer,
    maxBlocksPerRequest: 2,
    maxSidecarsPerRequest: 16,
    columnsMap: Opt.some(columns)
  )

iterator parents*(entry: SyncDagEntryRef): SyncDagEntryRef =
  doAssert(not(isNil(entry)), "Entry should not be nil")
  var currentEntry = entry
  while true:
    if isNil(currentEntry.parent):
      break
    yield currentEntry.parent
    currentEntry = currentEntry.parent

proc getPendingParent*(
    entry: SyncDagEntryRef
): Opt[SyncDagEntryRef] =
  for currentEntry in entry.parents():
    if DagEntryFlag.Finalized in currentEntry.flags:
      # We reach finalized root, so this is finish.
      return Opt.none(SyncDagEntryRef)
    if isNil(currentEntry.parent):
      # Entry missing parent root, so its good candidate
      return Opt.some(currentEntry)
  Opt.some(entry)

proc getPendingParentRoot*(
    entry: SyncDagEntryRef
): Opt[Eth2Digest] =
  let res = getPendingParent(entry).valueOr:
    return Opt.none(Eth2Digest)
  Opt.some(res.blockId.root)

proc getFinalizedParent*(
    entry: SyncDagEntryRef
): Opt[SyncDagEntryRef] =
  for currentEntry in entry.parents():
    if DagEntryFlag.Finalized in currentEntry.flags:
      return Opt.some(currentEntry)
  Opt.none(SyncDagEntryRef)

proc getFinalizedParent*[A, B](
    sdag: SyncDag[A, B],
    root: Eth2Digest
): Opt[SyncDagEntryRef] =
  let entry = sdag.roots.getOrDefault(root)
  if isNil(entry):
    return Opt.none(SyncDagEntryRef)
  getFinalizedParent(entry)

proc updateSlot*[A, B](
    sdag: var SyncDag[A, B],
    slot: Slot,
    root: Eth2Digest
) =
  sdag.slots.mgetOrPut(slot, default(HashSet[Eth2Digest])).incl(root)
  if sdag.lastSlot < slot:
    sdag.lastSlot = slot

proc shortLog*(a: set[DagEntryFlag]): string =
  var res = ""
  if DagEntryFlag.Pending in a:
    res.add("P")
  if DagEntryFlag.Finalized in a:
    res.add("F")
  if DagEntryFlag.MissingSidecars in a:
    res.add("M")
  if DagEntryFlag.Unviable in a:
    res.add("U")
  res

func getRootItem(
    root: Eth2Digest,
    slot: Slot,
    flags: set[DagEntryFlag]
): string =
  $slot & "@" & shortLog(root) & "[" & shortLog(flags) & "]"

proc getRootMap*[A, B](sdag: SyncDag[A, B], root: Eth2Digest): string =
  let entry = sdag.roots.getOrDefault(root)
  if isNil(entry):
    return "<none>"
  var res: seq[string]
  res.add(getRootItem(entry.blockId.root, entry.blockId.slot, entry.flags))
  for centry in entry.parents():
    res.add(getRootItem(centry.blockId.root, centry.blockId.slot, centry.flags))
    if DagEntryFlag.Finalized in centry.flags:
      break
  res.join(",")

func getShortRootMap*[A, B](sdag: SyncDag[A, B], root: Eth2Digest): string =
  var
    missingSidecars = 0
    pendingBlocks = 0
    count = 0
  let entry = sdag.roots.getOrDefault(root)
  if isNil(entry):
    return "<none>"
  var res: seq[string]
  res.add(getRootItem(entry.blockId.root, entry.blockId.slot, entry.flags))
  inc(count)
  if DagEntryFlag.Pending in entry.flags:
    inc(pendingBlocks)
  if DagEntryFlag.MissingSidecars in entry.flags:
    inc(missingSidecars)
  for centry in entry.parents():
    if DagEntryFlag.Pending in centry.flags:
      inc(pendingBlocks)
    if DagEntryFlag.MissingSidecars in centry.flags:
      inc(missingSidecars)
    inc(count)
    res.add(getRootItem(centry.blockId.root, centry.blockId.slot, centry.flags))
    if DagEntryFlag.Finalized in centry.flags:
      break
  res[^1] & "..." & res[0] &
  "[P:" & $pendingBlocks & "/M:" & $missingSidecars & " of " & $count & "]"

proc updateRoot*[A, B](
    sdag: var SyncDag[A, B],
    root: Eth2Digest,
    slot: Slot,
    parent_root: Eth2Digest,
    sidecarsMissed: bool
): Opt[Eth2Digest] =
  let entry = sdag.roots.getOrDefault(root)
  if isNil(entry):
    # This could happen, when data from peer come later than pruning has been
    # made.
    return Opt.none(Eth2Digest)

  let
    bid = BlockId(root: parent_root, slot: GENESIS_SLOT)
    parentEntry = sdag.roots.mgetOrPut(parent_root, SyncDagEntryRef.init(bid))

  # It is possible that data is already in SyncDag, because different peers
  # could follow same history and we could receive equal data from 2 peers.
  if DagEntryFlag.Pending in entry.flags:
    # Only update entry's data if it was in `Pending` state.
    entry.flags.excl(DagEntryFlag.Pending)
    if sidecarsMissed:
      entry.flags.incl(DagEntryFlag.MissingSidecars)
    entry.blockId.slot = slot
    entry.parent = parentEntry
    sdag.updateSlot(slot, root)

  if DagEntryFlag.Finalized in entry.flags:
    # If we downloaded finalized checkpoint's root block - update `epochs`
    # table.
    entry.parent = nil
    return Opt.none(Eth2Digest)

  if (DagEntryFlag.Pending notin parentEntry.flags) and
     (DagEntryFlag.Finalized in parentEntry.flags):
    # Our parent is finalized entry, so we should not continue anymore.
    return Opt.none(Eth2Digest)

  if DagEntryFlag.Pending in parentEntry.flags:
    # Parent entry is still in `pending` state, so we return `parent_root`
    # as missing.
    Opt.some(parent_root)
  else:
    # Parent entry is already present and has its own parent, so we need
    # to find last pending root.
    getPendingParentRoot(parentEntry)

proc prune*[A, B](
    sdag: var SyncDag[A, B],
    epoch: Epoch
) =
  var
    entriesToDelete: seq[Eth2Digest]
    slotsToDelete: seq[Slot]

  let startSlot = epoch.start_slot()
  for cslot, roots in sdag.slots.pairs():
    if cslot < startSlot:
      slotsToDelete.add(cslot)
      entriesToDelete.add(roots.toSeq())

  for slot in slotsToDelete:
    sdag.slots.del(slot)

  var entry: SyncDagEntryRef = nil
  for item in entriesToDelete:
    if sdag.roots.pop(item, entry):
      entry.parent = nil
      entry = nil

proc init*(
    t: typedesc[SyncDag],
    A: typedesc,
    B: typedesc
): SyncDag[A, B] =
  SyncDag[A, B]()

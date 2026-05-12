# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[sets, tables, strutils, hashes, algorithm]
import stew/base10, chronos, chronicles, results
import ../spec/[forks, block_id, column_map]
import ../consensus_object_pools/blockchain_dag
import ./sync_queue

from std/sequtils import mapIt

type
  DagEntryFlag* {.pure.} = enum
    Local, Unviable, Finalized, Pending, MissingSidecars

  DagBlockSourceType* {.pure.} = enum
    Orphan, Sidecarless, Dag, Unviable

  SyncDagEntryRef* = ref object
    blockId*: BlockId
    parent*: SyncDagEntryRef
    flags*: set[DagEntryFlag]
    source*: set[DagBlockSourceType]
    moment*: chronos.Moment

  RootQueue* = object
    queue: Deque[Eth2Digest]
    roots: HashSet[Eth2Digest]

  PeerEntryRef*[A] = ref object
    peer*: A
    pendingRoots*: RootQueue
    maxBlocksPerRequest*: int
    maxSidecarsPerRequest*: int
    peerLoopFut*: Future[void].Raising([])

  SyncDag*[A, B] = object
    roots*: Table[Eth2Digest, SyncDagEntryRef]
    slots*: Table[Slot, HashSet[Eth2Digest]]
    peers*: Table[B, PeerEntryRef[A]]
    lastSlot*: Slot

const
  EmptyBlockId* = BlockId(slot: FAR_FUTURE_SLOT)
  PendingExpirationTime = 5.minutes

proc init*(t: typedesc[RootQueue]): RootQueue =
  RootQueue(queue: initDeque[Eth2Digest](16))

proc add*(rq: var RootQueue, root: Eth2Digest) =
  if root notin rq.roots:
    rq.queue.addLast(root)
    rq.roots.incl(root)

proc len*(rq: RootQueue): int =
  len(rq.queue)

proc pop*(rq: var RootQueue): Eth2Digest =
  let root = rq.queue.popFirst()
  rq.roots.excl(root)
  root

func isExpired(s: SyncDagEntryRef, currentTime: Moment): bool =
  doAssert(not(isNil(s)))
  if DagEntryFlag.Pending notin s.flags:
    return false
  if currentTime < s.moment:
    return false
  if (currentTime - s.moment) >= PendingExpirationTime:
    true
  else:
    false

func shortLog*(s: SyncDagEntryRef): string =
  if isNil(s):
    return "not available"
  shortLog(s.blockId)

func fullLog*(s: set[DagEntryFlag], isHead, isFinalizedHead: bool): string =
  var res: seq[string]
  if DagEntryFlag.Local in s: res.add("local")
  if DagEntryFlag.Pending in s: res.add("pending")
  if DagEntryFlag.Unviable in s: res.add("unviable")
  if DagEntryFlag.Finalized in s: res.add("finalized")
  if DagEntryFlag.MissingSidecars in s: res.add("missing_sidecars")
  if isHead: res.add("current_head")
  if isFinalizedHead: res.add("current_finalized_head")
  "[" & res.join(",") & "]"

func fullLog*(s: set[DagBlockSourceType]): string =
  var res: seq[string]
  if DagBlockSourceType.Orphan in s: res.add("missing")
  if DagBlockSourceType.Unviable in s: res.add("unviable")
  if DagBlockSourceType.Dag in s: res.add("dag")
  if DagBlockSourceType.Sidecarless in s: res.add("sidecarless")
  "[" & res.join(",") & "]"

proc hash*(entry: SyncDagEntryRef): Hash =
  hash(cast[pointer](entry))

func toBlockId*(checkpoint: Checkpoint): BlockId =
  BlockId(root: checkpoint.root, slot: checkpoint.epoch.start_slot())

proc init*(
    t: typedesc[SyncDagEntryRef],
    blockId: BlockId
): SyncDagEntryRef =
  SyncDagEntryRef(
    blockId: blockId,
    flags: {DagEntryFlag.Pending},
    moment: Moment.now())

proc init*(
    t: typedesc[SyncDagEntryRef],
    root: Eth2Digest
): SyncDagEntryRef =
  SyncDagEntryRef(
    blockId: BlockId(root: root, slot: FAR_FUTURE_SLOT),
    flags: {DagEntryFlag.Pending},
    moment: Moment.now())

proc init*(
    t: typedesc[SyncDagEntryRef],
    checkpoint: Checkpoint
): SyncDagEntryRef =
  SyncDagEntryRef(
    blockId: checkpoint.toBlockId(),
    flags: {DagEntryFlag.Finalized, DagEntryFlag.Pending},
    moment: Moment.now())

func init*[T](
    t: typedesc[PeerEntryRef],
    peer: T,
): PeerEntryRef[T] =
  PeerEntryRef[T](
    pendingRoots: RootQueue.init(),
    peer: peer,
    maxBlocksPerRequest: 4,
    maxSidecarsPerRequest: 128
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
    sidecarsMissed: bool,
    src: DagBlockSourceType
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
    entry.source.incl(src)
    sdag.updateSlot(slot, root)

  if DagEntryFlag.Finalized in entry.flags:
    # If we downloaded finalized checkpoint's root block - update `epochs`
    # table.
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
    rootsToDelete: HashSet[Eth2Digest]
    slotsToDelete: seq[Slot]
    entriesToDelete: HashSet[SyncDagEntryRef]

  let
    startSlot = epoch.start_slot()
    currentTime = Moment.now()
  for cslot, roots in sdag.slots.pairs():
    if cslot < startSlot:
      slotsToDelete.add(cslot)
      for root in roots:
        rootsToDelete.incl(root)

  for slot in slotsToDelete:
    sdag.slots.del(slot)
  slotsToDelete.reset()

  # Next two loops to cleanup ancestor->parent reference relation, and to
  # delete `Pending` entries whose time has expired.
  for root, entry in sdag.roots.mpairs():
    if root in rootsToDelete:
      entriesToDelete.incl(entry)
    if entry.isExpired(currentTime):
      rootsToDelete.incl(entry.blockId.root)
      entriesToDelete.incl(entry)
  for entry in sdag.roots.mvalues():
    if entry.parent in entriesToDelete:
      entry.parent = nil
  entriesToDelete.clear()

  var entry: SyncDagEntryRef = nil
  for root in rootsToDelete:
    if sdag.roots.pop(root, entry):
      entry.parent = nil
      entry = nil
  rootsToDelete.clear()

iterator ancestors*[A, B](
    sdag: SyncDag[A, B],
    entry: SyncDagEntryRef
): SyncDagEntryRef =
  doAssert(not(isNil(entry)))
  var slot = entry[].blockId.slot + 1'u64
  while slot <= sdag.lastSlot:
    for blockRoot in sdag.slots.getOrDefault(slot):
      let mentry = sdag.roots.getOrDefault(blockRoot)
      if not(isNil(mentry)):
        if mentry.parent == entry:
          yield mentry
    inc(slot)

iterator ancestors*[A, B](
    sdag: SyncDag[A, B],
    blockRoot: Eth2Digest
): SyncDagEntryRef =
  let entry = sdag.roots.getOrDefault(blockRoot)
  if not(isNil(entry)):
    for item in sdag.ancestors(entry):
      yield item

proc init*(
    t: typedesc[SyncDag],
    A: typedesc,
    B: typedesc
): SyncDag[A, B] =
  SyncDag[A, B]()

proc debugJsonDump*(sdag: SyncDag, dag: ChainDAGRef): string =
  var
    res: seq[tuple[bid: BlockId, item: string]]
    minSlot: Opt[Slot]
    maxSlot: Opt[Slot]

  proc cmp(a, b: tuple[bid: BlockId, item: string]): int =
    cmp(uint64(a.bid.slot), uint64(b.bid.slot))

  let currentTime = Moment.now()
  for item in sdag.roots.values():
    let
      bid =
        if DagEntryFlag.Pending in item.flags:
          shortLog(item.blockId.root)
        else:
          shortLog(item.blockId)
      currentHead =
        if dag.head.bid.root == item.blockId.root:
          true
        else:
          false
      currentFinHead =
        if dag.finalizedHead.blck.bid.root == item.blockId.root:
          true
        else:
          false
      data = "{" & "\"bid\":\"" & bid &
        "\",\"flags\":\"" & fullLog(item.flags, currentHead, currentFinHead) &
        "\",\"source\":\"" & fullLog(item.source) &
        "\",\"parent_bid\":\"" & shortLog(item.parent) &
        "\",\"duration\":\"" & shortLog(currentTime - item.moment) & "\"}"
    res.add((item.blockId, data))
    if DagEntryFlag.Pending notin item.flags:
      if minSlot.isNone() or item.blockId.slot < minSlot.get():
        minSlot = Opt.some(item.blockId.slot)
      if maxSlot.isNone() or item.blockId.slot > maxSlot.get():
        maxSlot = Opt.some(item.blockId.slot)
  res.sort(cmp)
  let
    sminSlot = if minSlot.isNone(): "not available" else: $minSlot.get()
    smaxSlot = if maxSlot.isNone(): "not available" else: $maxSlot.get()
  "{\"min_slot\":\"" & sminSlot &
    "\",\"max_slot\":\"" & smaxSlot &
    "\",\"records\":[" & res.mapIt(it.item).join(",") & "]}"

# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[lists, sets, tables],
  results, metrics,
  ../spec/[presets, column_map],
  ../spec/datatypes/[fulu, gloas],
  ../beacon_chain_db_quarantine

from std/sequtils import mapIt, toSeq
from std/strutils import join

export results

declareGauge blob_quarantine_memory_slots_total,
  "Total count of available memory slots inside blob quarantine"
declareGauge blob_quarantine_memory_slots_occupied,
  "Number of occupied memory slots inside blob quarantine"
declareGauge blob_quarantine_database_slots_total,
  "Total count of availble database slots inside blob quarantine"
declareGauge blob_quarantine_database_slots_occupied,
  "Number of occupied database slots inside blob quarantine"

type
  SidecarHolderKind {.pure.} = enum
    Empty, Loaded, Unloaded

  SidecarHolder[A] = object
    index: uint64
    proposer_index: uint64
    slot: Slot
    verified: bool
    case kind: SidecarHolderKind
    of SidecarHolderKind.Empty:
      discard
    of SidecarHolderKind.Unloaded:
      discard
    of SidecarHolderKind.Loaded:
      data: ref A

  RootTableRecord[A] = object
    blockRoot: Eth2Digest
    slot: Slot
    unloaded: int
    count: int
    sidecars: seq[SidecarHolder[A]]

  SidecarQuarantine[A, B, C] = object
    minEpochsForSidecarsRequests: uint64
    maxMemSidecarsCount*: int
    memSidecarsCount: int
    maxDiskSidecarsCount*: int
    diskSidecarsCount: int
    maxSidecarsPerBlockCount: int
    custodyColumns*: seq[ColumnIndex]
    custodyMap*: ColumnMap
    lastMemoryNode: DoublyLinkedNode[RootTableRecord[A]]
    roots: Table[Eth2Digest, DoublyLinkedNode[RootTableRecord[A]]]
    pendingVerify: Table[Eth2Digest, ColumnMap]
    list: DoublyLinkedList[RootTableRecord[A]]
    indexMap: seq[int]
    db: QuarantineDB
    onSidecarCallback*: B
    onColumnAddedCallback*: C

  OnDataColumnSidecarCallback* = proc(
    data: DataColumnSidecarInfoObject) {.gcsafe, raises: [].}
  OnFuluDataColumnSidecarAddedCallback* = proc(
    data: ref fulu.DataColumnSidecar) {.gcsafe, raises: [].}
  OnGloasDataColumnSidecarAddedCallback* = proc(
    data: ref gloas.DataColumnSidecar) {.gcsafe, raises: [].}

  SomeSidecarRef* = ref fulu.DataColumnSidecar | ref gloas.DataColumnSidecar
  SomeSidecarIndex* = fulu.ColumnIndex
  SomeDataColumnSidecar = fulu.DataColumnSidecar | gloas.DataColumnSidecar
  SomeSidecarAddedCallback* =
    OnFuluDataColumnSidecarAddedCallback | OnGloasDataColumnSidecarAddedCallback

  FuluColumnQuarantine* =
    SidecarQuarantine[
      fulu.DataColumnSidecar, OnDataColumnSidecarCallback,
      OnFuluDataColumnSidecarAddedCallback]

  GloasColumnQuarantine* =
    SidecarQuarantine[
      gloas.DataColumnSidecar, OnDataColumnSidecarCallback,
      OnGloasDataColumnSidecarAddedCallback]

  SomeColumnQuarantine* = FuluColumnQuarantine | GloasColumnQuarantine

  ColumnQuarantineNode*[A: SomeDataColumnSidecar] =
    DoublyLinkedNode[RootTableRecord[A]]

func indexLog*[T: SomeSidecarRef](sidecars: openArray[ref T]): string =
  "[" & sidecars.mapIt($uint64(it[].index)).join(",") & "]"

func indexLog*[T: SomeSidecarIndex](indices: openArray[T]): string =
  "[" & indices.mapIt($uint64(it)).join(",") & "]"

func isEmpty[A: SomeDataColumnSidecar](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Empty

func isUnloaded[A: SomeDataColumnSidecar](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Unloaded

func isLoaded[A: SomeDataColumnSidecar](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Loaded

func maxSidecars(maxSidecarsPerBlock: uint64): int =
  # Same limit as `MaxOrphans` in `block_quarantine`;
  # blobs may arrive before an orphan is tagged `blobless`
  3 * int(SLOTS_PER_EPOCH) * int(maxSidecarsPerBlock)

func enoughColumns(q: SomeColumnQuarantine, count: int): bool =
  if count >= NUMBER_OF_COLUMNS div 2:
    return true
  if count == len(q.custodyMap):
    return true
  false

func init[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    t: typedesc[RootTableRecord],
    q: SidecarQuarantine[A, B, C]
): RootTableRecord[A] =
  RootTableRecord[A](
    sidecars: newSeq[SidecarHolder[A]](q.maxSidecarsPerBlockCount),
    count: 0, unloaded: 0, slot: FAR_FUTURE_SLOT)

func init[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    t: typedesc[RootTableRecord],
    q: SidecarQuarantine[A, B, C],
    blockRoot: Eth2Digest
): RootTableRecord[A] =
  RootTableRecord[A](
    blockRoot: blockRoot,
    sidecars: newSeq[SidecarHolder[A]](q.maxSidecarsPerBlockCount),
    count: 0, unloaded: 0, slot: FAR_FUTURE_SLOT)

func shortLog*(quarantine: SomeColumnQuarantine): string =
  "[M:" & $quarantine.memSidecarsCount & "/" &
    $quarantine.maxMemSidecarsCount & ";D:" &
    $quarantine.diskSidecarsCount & "/" &
    $quarantine.maxDiskSidecarsCount & "]/" & $len(quarantine.roots)

func len*(q: SomeColumnQuarantine): int =
  q.memSidecarsCount + q.diskSidecarsCount

func lenMemory*(q: SomeColumnQuarantine): int =
  q.memSidecarsCount

func lenDisk*(q: SomeColumnQuarantine): int =
  q.diskSidecarsCount

func size*(q: SomeColumnQuarantine): int =
  q.maxMemSidecarsCount + q.maxDiskSidecarsCount

func sizeMemory*(q: SomeColumnQuarantine): int =
  q.maxMemSidecarsCount

func sizeDisk*(q: SomeColumnQuarantine): int =
  q.maxDiskSidecarsCount

func unload[A: SomeDataColumnSidecar](holder: var SidecarHolder[A]): ref A =
  let res = holder.data
  holder.data = nil
  holder = SidecarHolder[A](
    kind: SidecarHolderKind.Unloaded,
    slot: holder.slot,
    index: holder.index,
    proposer_index: holder.proposer_index,
    verified: holder.verified,
  )
  res

func getIndex(quarantine: SomeColumnQuarantine, index: ColumnIndex): int =
  quarantine.indexMap[int(index)]

template slot*(b: fulu.DataColumnSidecar): Slot =
  b.signed_block_header.message.slot

template slot*(b: gloas.DataColumnSidecar): Slot =
  b.slot

template proposer_index(b: fulu.DataColumnSidecar): uint64 =
  b.signed_block_header.message.proposer_index

template proposer_index(b: gloas.DataColumnSidecar): uint64 =
  # Gloas's sidecar doesn't have this information
  0'u64

proc removeNode[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    quarantine: var SidecarQuarantine[A, B, C],
    node: DoublyLinkedNode[RootTableRecord[A]],
    databaseCount: int
) =
  # This procedore removes all the sidecars associated with ``node`` from
  # memory, disk and data structures.
  var sidecarsOnDisk = 0

  let blockRoot = node[].value.blockRoot

  for index in 0 ..< len(node[].value.sidecars):
    case node[].value.sidecars[index].kind
    of SidecarHolderKind.Empty:
        discard
    of SidecarHolderKind.Loaded:
      node[].value.sidecars[index].data = nil
      dec(quarantine.memSidecarsCount)
      blob_quarantine_memory_slots_occupied.set(
        int64(quarantine.memSidecarsCount))
    of SidecarHolderKind.Unloaded:
      dec(quarantine.diskSidecarsCount)
      blob_quarantine_database_slots_occupied.set(
        int64(quarantine.diskSidecarsCount))
      inc(sidecarsOnDisk)

  if (sidecarsOnDisk > 0) or (databaseCount > 0):
    quarantine.db.removeDataSidecars(A, blockRoot)
    if databaseCount > 0:
      dec(quarantine.diskSidecarsCount, databaseCount)
      blob_quarantine_database_slots_occupied.set(
        int64(quarantine.diskSidecarsCount))

  if quarantine.lastMemoryNode == node:
    quarantine.lastMemoryNode = node.prev

  quarantine.roots.del(blockRoot)
  quarantine.list.remove(node)

proc offloadRoot[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    quarantine: var SidecarQuarantine[A, B, C],
    blockRoot: Eth2Digest
) =
  # This procedore offloads all the sidecars associated with `blockRoot` from
  # memory to disk.

  let node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return

  var res: seq[ref A]
  for index in 0 ..< len(node[].value.sidecars):
    if node[].value.sidecars[index].kind == SidecarHolderKind.Loaded:
      res.add(node[].value.sidecars[index].unload())

  if len(res) > 0:
    quarantine.db.putDataSidecars(blockRoot, res)
    dec(quarantine.memSidecarsCount, len(res))
    inc(quarantine.diskSidecarsCount, len(res))
    blob_quarantine_memory_slots_occupied.set(
      int64(quarantine.memSidecarsCount))
    blob_quarantine_database_slots_occupied.set(
      int64(quarantine.diskSidecarsCount))
    inc(node[].value.unloaded, len(res))

func fitsInMemory(q: SomeColumnQuarantine, count: int): bool =
  q.memSidecarsCount + count <= q.maxMemSidecarsCount

func fitsInQuarantine(q: SomeColumnQuarantine, count: int): bool =
  (q.memSidecarsCount + q.diskSidecarsCount + count) <=
    (q.maxMemSidecarsCount + q.maxDiskSidecarsCount)

proc ensureSidecarsFits(
    q: var SomeColumnQuarantine,
    count: int
): Result[void, cstring] =
  while not(q.fitsInQuarantine(count)):
    # Pruning process.
    let node = q.list.tail
    if isNil(node):
      return err("Tail node is nil")
    q.removeNode(node, 0)

  while not(q.fitsInMemory(count)):
    # Offloading process
    let node = q.lastMemoryNode
    if isNil(node):
      return err("Last memory node is nil")
    q.offloadRoot(node[].value.blockRoot)
    q.lastMemoryNode = node[].prev

  ok()

proc moveToFront[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    q: var SidecarQuarantine[A, B, C],
    node: DoublyLinkedNode[RootTableRecord[A]]
) =
  # We should preserve `lastMemoryNode` reference.
  if q.lastMemoryNode == node:
    q.lastMemoryNode = node.prev

  q.list.remove(node)
  if isNil(q.list.head) and isNil(q.list.tail):
    # In case when list empty, we could not use `prepend` operation.
    q.list.add(node)
  else:
    q.list.prepend(node)

proc put*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    q: var SidecarQuarantine[A, B, C],
    blockRoot: Eth2Digest,
    sidecars: openArray[ref A],
    verified: bool
) =
  # Note: Sidecars with indices that are not in the current column custody set
  # are IGNORED.
  let
    (node, missing) =
      block:
        let res = q.roots.getOrDefault(blockRoot)
        if isNil(res):
          (newDoublyLinkedNode(RootTableRecord.init(q, blockRoot)), true)
        else:
          (res, false)
    newSidecarsCount =
      block:
        var res = 0
        for sidecar in sidecars:
          let index = q.getIndex(sidecar.index)
          # Because custody set could change - it is possible that we could get
          # sidecars with indices which are not suitable for current set, so
          # we should not assert, but just continue looking for compatible
          # sidecars.
          if index < 0: continue
          if isEmpty(node[].value.sidecars[index]):
            inc(res)
        res

  if newSidecarsCount == 0:
    return

  q.ensureSidecarsFits(newSidecarsCount).isOkOr:
    return

  for sidecar in sidecars:
    let index = q.getIndex(sidecar.index)
    if index < 0: continue
    if isEmpty(node[].value.sidecars[index]):
      inc(node[].value.count)
      node[].value.slot = sidecar[].slot()
      node[].value.sidecars[index] =
        SidecarHolder[A](
          kind: SidecarHolderKind.Loaded,
          slot: sidecar[].slot(),
          index: uint64(sidecar[].index),
          proposer_index: sidecar[].proposer_index(),
          verified: verified,
          data: sidecar)

  q.memSidecarsCount += newSidecarsCount
  blob_quarantine_memory_slots_occupied.set(
    int64(q.memSidecarsCount))

  if missing:
    # Add first
    q.roots[blockRoot] = node
    if isNil(q.list.head) and isNil(q.list.tail):
      # In case when list empty, we could not use `prepend` operation.
      q.list.add(node)
    else:
      q.list.prepend(node)
  else:
    q.moveToFront(node)

  if isNil(q.lastMemoryNode):
    q.lastMemoryNode = node

proc put*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    q: var SidecarQuarantine[A, B, C],
    blockRoot: Eth2Digest,
    sidecar: ref A,
    verified: bool
) =
  q.put(blockRoot, [sidecar], verified)

proc remove*(q: var SomeColumnQuarantine, blockRoot: Eth2Digest) =
  ## Remove all the data columns or blobs related to the block root ``blockRoot`
  ## from the quarantine ``q``.
  ##
  ## Function do nothing, if ``blockRoot` is not part of the quarantine.
  let node = q.roots.getOrDefault(blockRoot)
  if isNil(node):
    return
  q.removeNode(node, 0)

func load[A: SomeDataColumnSidecar](
    holder: var SidecarHolder[A],
    sidecar: ref A
) =
  holder = SidecarHolder[A](
    kind: SidecarHolderKind.Loaded,
    slot: holder.slot,
    index: holder.index,
    proposer_index: holder.proposer_index,
    verified: holder.verified,
    data: sidecar
  )

proc loadRoot[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    quarantine: var SidecarQuarantine[A, B, C],
    blockRoot: Eth2Digest,
    record: var RootTableRecord[A]
) =
  for sidecar in quarantine.db.sidecars(A, blockRoot):
    let index = quarantine.getIndex(sidecar.index)
    doAssert(index >= 0,
      "Incorrect sidecar index " & $sidecar.index & " points to " & $index)
    doAssert(record.sidecars[index].isUnloaded(),
      "Database storage is inconsistent, record should be `Unloaded`, " &
      "but it is `" & $record.sidecars[index].kind & "`")
    record.sidecars[index].load(newClone(sidecar))
    dec(record.unloaded)
    inc(quarantine.memSidecarsCount)

  doAssert(record.unloaded == 0,
    "Record's unloaded count should be zero, but it is " & $record.unloaded)

template hasSidecarImpl(
    blockRoot: Eth2Digest,
    slot: Slot,
    proposerIndex: uint64,
    sidecarIndex: typed
): bool =
  let node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return false
  let index = quarantine.getIndex(index)
  if (index == -1) or node[].value.sidecars[index].isEmpty():
    return false
  if (node[].value.sidecars[index].proposer_index != proposer_index) or
     (node[].value.sidecars[index].slot != slot):
    return false
  true

template hasSidecarImpl(
    blockRoot: Eth2Digest,
    sidecarIndex: typed
): bool =
  let node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return false
  let index = quarantine.getIndex(sidecarIndex)
  (index != -1) and not node[].value.sidecars[index].isEmpty()

func hasSidecar*(
    quarantine: FuluColumnQuarantine,
    blockRoot: Eth2Digest,
    slot: Slot,
    proposer_index: uint64,
    index: ColumnIndex
): bool =
  ## Function returns ``true``if quarantine has column corresponding to specific
  ## ``index``, ``slot`` and ``proposer_index``.
  hasSidecarImpl(blockRoot, slot, proposer_index, index)

func hasSidecar*(
    quarantine: GloasColumnQuarantine,
    blockRoot: Eth2Digest,
    slot: Slot,
    index: ColumnIndex
): bool =
  ## Shorthand function for Gloas as proposer index is removed.
  let proposer_index = 0'u64
  hasSidecarImpl(blockRoot, slot, proposer_index, index)

func hasSidecar*(
    quarantine: SomeColumnQuarantine,
    blockRoot: Eth2Digest,
    index: ColumnIndex
): bool =
  hasSidecarImpl(blockRoot, index)

func hasSidecars*(
    quarantine: SomeColumnQuarantine,
    blockRoot: Eth2Digest,
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  let node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return false
  if quarantine.enoughColumns(node[].value.count):
    # Quarantine holds enough column sidecars.
    return true
  false

func hasSidecars*(
    quarantine: FuluColumnQuarantine,
    blck: fulu.SignedBeaconBlock,
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  hasSidecars(quarantine, blck.root)

func hasSidecars*(
    quarantine: GloasColumnQuarantine,
    blck: gloas.SignedBeaconBlock,
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  hasSidecars(quarantine, blck.root)

proc popSidecars*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    quarantine: var SidecarQuarantine[A, B, C],
    blockRoot: Eth2Digest
): Opt[seq[ref A]] =
  ## Function returns sequence of column sidecars for block root ``blockRoot``.
  ## If some of the column sidecars are missing Opt.none() is returned.
  ## Note: Blocks should be checked for sidecars count first, otherwise
  ## result of this function would be always Opt.none().
  var node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return Opt.none(seq[ref A])

  quarantine.moveToFront(node)

  let
    supernode = (len(quarantine.custodyMap) == NUMBER_OF_COLUMNS)

  if not(quarantine.enoughColumns(node[].value.count)):
    # Quarantine does not hold enough column sidecars.
    return Opt.none(seq[ref A])

  let databaseCount = node[].value.unloaded
  if databaseCount > 0:
    # Quarantine unloaded some blobs to disk, we should load it back.
    quarantine.loadRoot(blockRoot, node[].value)

  var
    sidecars: seq[ref A]
    unverified: ColumnMap

  if supernode:
    # When supernode - we pop all sidecars.
    for sidecar in node[].value.sidecars:
      # Supernode could have some of the columns not filled.
      if not(sidecar.isEmpty()):
        doAssert(sidecar.isLoaded(),
          "Record should only have loaded values, but it is `" &
            $sidecar.kind & "`")
        sidecars.add(sidecar.data)
        if not sidecar.verified:
          unverified.incl(ColumnIndex(sidecar.index))
  else:
    let allowPartial = node[].value.count >= NUMBER_OF_COLUMNS div 2
    for cindex in quarantine.custodyMap:
      let sidecar = node[].value.sidecars[quarantine.getIndex(cindex)]
      if allowPartial and sidecar.isEmpty():
        continue
      doAssert(sidecar.isLoaded(),
        "Record should only have loaded values, but it is `" &
          $sidecar.kind & "`")
      sidecars.add(sidecar.data)
      if not sidecar.verified:
        unverified.incl(ColumnIndex(sidecar.index))

    doAssert(
      (allowPartial and len(sidecars) >= NUMBER_OF_COLUMNS div 2) or
        len(sidecars) == len(quarantine.custodyMap),
      "Incorrect amount of sidecars in record for node - " & $len(sidecars))

  # popSidecars() should remove all the artifacts from the quarantine in both
  # memory and disk.
  quarantine.removeNode(node, databaseCount)

  # Gloas and newer forks verify columns separately
  if not unverified.empty:
    quarantine.pendingVerify[blockRoot] = unverified

  Opt.some(sidecars)

func popPendingVerify*(
    quarantine: var SomeColumnQuarantine,
    blockRoot: Eth2Digest
): ColumnMap =
  var res: ColumnMap
  discard quarantine.pendingVerify.pop(blockRoot, res)
  res

func fetchMissingSidecars*(
    quarantine: SomeColumnQuarantine,
    blockRoot: Eth2Digest,
    peerMap: ColumnMap
): DataColumnsByRootIdentifier =
  ## Function returns a DataColumnsByRootIdentifier for data columns
  ## which are missing for the block associated with root ``blockRoot`` and
  ## block ``blockOrEnvelope``.
  ##
  ## Note: If there is no missing columns - DataColumnByRootIdentifier.indices
  ## array will be empty.
  var res: ColumnMap

  let node = quarantine.roots.getOrDefault(blockRoot)

  if peerMap.empty():
    # Fast-path if peer's columns map is empty, we can't figure which columns
    # we could ask.
    return DataColumnsByRootIdentifier(
      block_root: blockRoot,
      indices: DataColumnIndices(default(seq[ColumnIndex])))

  let
    supernode = (len(quarantine.custodyMap) == NUMBER_OF_COLUMNS)

  if supernode:
    if isNil(node):
      for column in peerMap.items():
        res.incl(column)
    else:
      if quarantine.enoughColumns(node[].value.count):
        return
          DataColumnsByRootIdentifier(
            block_root: blockRoot,
            indices: DataColumnIndices(default(seq[ColumnIndex])))

      for column in peerMap.items():
        let index = quarantine.getIndex(column)
        if (index == -1) or node[].value.sidecars[index].isEmpty():
          res.incl(column)
  else:
    if isNil(node):
      for column in (peerMap and quarantine.custodyMap).items():
        res.incl(column)
    else:
      for column in (peerMap and quarantine.custodyMap).items():
        let index = quarantine.getIndex(column)
        if (index == -1) or (node[].value.sidecars[index].isEmpty()):
          res.incl(column)

  DataColumnsByRootIdentifier(
    block_root: blockRoot, indices: DataColumnIndices(res.items().toSeq()))

func fetchMissingSidecars*(
    quarantine: SomeColumnQuarantine,
    blockRoot: Eth2Digest,
    peerCustodyColumns: openArray[ColumnIndex] = []
): DataColumnsByRootIdentifier =
  if len(peerCustodyColumns) == 0:
    quarantine.fetchMissingSidecars(
      blockRoot, quarantine.custodyMap)
  else:
    quarantine.fetchMissingSidecars(
      blockRoot, ColumnMap.init(peerCustodyColumns))

func getMissingColumnsMap*(
    quarantine: SomeColumnQuarantine,
    blockRoot: Eth2Digest,
): ColumnMap =
  let
    node = quarantine.roots.getOrDefault(blockRoot)
    supernode = (len(quarantine.custodyMap) == NUMBER_OF_COLUMNS)

  if supernode:
    if isNil(node):
      supernodeMap
    else:
      var res: ColumnMap
      if quarantine.enoughColumns(node[].value.count):
        return default(ColumnMap)
      for index in 0 ..< NUMBER_OF_COLUMNS:
        if node[].value.sidecars[index].isEmpty():
          res.incl(ColumnIndex(index))
  else:
    var res: ColumnMap
    for column in quarantine.custodyMap.items():
      let index = quarantine.getIndex(column)
      if isNil(node) or (index == -1) or node[].value.sidecars[index].isEmpty():
        res.incl(column)
    res

func getMissingSidecarIndices*(
    quarantine: SomeColumnQuarantine,
    blockRoot: Eth2Digest,
): seq[ColumnIndex] =
  var res: seq[ColumnIndex]
  for item in quarantine.getMissingColumnsMap(blockRoot):
    res.add(item)
  res

proc pruneAfterFinalization*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    quarantine: var SidecarQuarantine[A, B, C],
    epoch: Epoch,
    backfillNeeded: bool
) =
  let
    startEpoch =
      if backfillNeeded:
        # Because ColumnQuarantine could be used as temporary storage for
        # incoming data column sidecars, we should not prune data columns which
        # are behind `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` epoch.
        # Otherwise we will not be able to backfill data columns.
        if epoch < quarantine.minEpochsForSidecarsRequests:
          Epoch(0)
        else:
          epoch - quarantine.minEpochsForSidecarsRequests
      else:
        epoch
    epochSlot = (startEpoch + 1).start_slot()

  var nodes: seq[DoublyLinkedNode[RootTableRecord[A]]]
  for node in quarantine.list.nodes():
    if (node[].value.count > 0) and (node[].value.slot < epochSlot):
      nodes.add(node)

  for node in nodes:
    quarantine.removeNode(node, 0)

template onDataColumnSidecarCallback*(
    quarantine: SomeColumnQuarantine
): OnDataColumnSidecarCallback =
  quarantine.onSidecarCallback

template onFuluDataColumnSidecarAddedCallback*(
    quarantine: FuluColumnQuarantine
): OnFuluDataColumnSidecarAddedCallback =
  quarantine.onColumnAddedCallback

template onGloasDataColumnSidecarAddedCallback*(
    quarantine: GloasColumnQuarantine
): OnGloasDataColumnSidecarAddedCallback =
  quarantine.onColumnAddedCallback

proc init*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    T: typedesc[SidecarQuarantine[A, B, C]],
    cfg: RuntimeConfig,
    custodyColumns: openArray[ColumnIndex],
    database: QuarantineDB,
    maxDiskSizeMultipler: int,
    onDataColumnSidecarCallback: B,
    onColumnAddedCallback: C = nil
): SidecarQuarantine[A, B, C] =
  doAssert(len(custodyColumns) <= NUMBER_OF_COLUMNS)
  let custodyMap = ColumnMap.init(custodyColumns)
  T.init(
    cfg, custodyMap, database, maxDiskSizeMultipler,
    onDataColumnSidecarCallback, onColumnAddedCallback)

proc init*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    T: typedesc[SidecarQuarantine[A, B, C]],
    cfg: RuntimeConfig,
    custodyMap: ColumnMap,
    database: QuarantineDB,
    maxDiskSizeMultipler: int,
    onDataColumnSidecarCallback: B,
    onColumnAddedCallback: C = nil
): SidecarQuarantine[A, B, C] =
  var indexMap = newSeqUninit[int](NUMBER_OF_COLUMNS)
  if len(custodyMap) < NUMBER_OF_COLUMNS:
    for i in 0 ..< len(indexMap):
      indexMap[i] = -1
  for index, item in custodyMap.pairs():
    indexMap[int(item)] = index

  let size = maxSidecars(NUMBER_OF_COLUMNS)

  blob_quarantine_memory_slots_total.set(int64(size))
  blob_quarantine_database_slots_total.set(
    int64(size) * int64(maxDiskSizeMultipler))
  blob_quarantine_memory_slots_occupied.set(0'i64)
  blob_quarantine_database_slots_occupied.set(0'i64)

  SidecarQuarantine[A, B, C](
    minEpochsForSidecarsRequests:
      cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS,
    maxSidecarsPerBlockCount: len(custodyMap),
    maxMemSidecarsCount: size,
    maxDiskSidecarsCount: size * maxDiskSizeMultipler,
    memSidecarsCount: 0,
    diskSidecarsCount: 0,
    indexMap: indexMap,
    custodyColumns: toSeq(custodyMap.items),
    custodyMap: custodyMap,
    list: initDoublyLinkedList[RootTableRecord[A]](),
    db: database,
    onSidecarCallback: onDataColumnSidecarCallback,
    onColumnAddedCallback: onColumnAddedCallback
  )

proc update*[
    A: SomeDataColumnSidecar,
    B: OnDataColumnSidecarCallback,
    C: SomeSidecarAddedCallback
](
    quarantine: var SidecarQuarantine[A, B, C],
    cfg: RuntimeConfig,
    custodyMap: ColumnMap
) =
  let maxSidecarsPerBlockCount = len(custodyMap)

  var indexMap = newSeqUninit[int](NUMBER_OF_COLUMNS)
  if len(custodyMap) < NUMBER_OF_COLUMNS:
    for i in 0 ..< len(indexMap):
      indexMap[i] = -1
  for index, item in custodyMap.pairs():
    indexMap[int(item)] = index

  var
    memSidecarsCount = 0
    diskSidecarsCount = 0
    nodesToRemove: seq[ColumnQuarantineNode[A]]

  for node in quarantine.list.nodes():
    var
      sidecars =
        newSeq[SidecarHolder[A]](len(custodyMap))
      count = 0
      unloaded = 0

    for cindex in quarantine.custodyMap.items():
      let
        index = quarantine.getIndex(cindex)
        sidecar = node[].value.sidecars[index]

      if not(isEmpty(sidecar)):
        if cindex in custodyMap:
          let dindex = indexMap[int(cindex)]
          if dindex >= 0:
            sidecars[dindex] = sidecar
            inc(count)
            if not(sidecar.isLoaded()):
              inc(unloaded)

    node.value.sidecars.reset()

    if count > 0:
      node[].value.sidecars = sidecars
      node[].value.count = count
      node[].value.unloaded = unloaded
      # We do account sidecars which are useful in new configuration, but
      # its possible that some sidecars will be left on disk which can't be
      # used in new configuration, and we can't delete it easily. But this
      # sidecars will be deleted as soon as sidecars with same `block_root`
      # will be popped out from quarantine.
      diskSidecarsCount.inc(unloaded)
      memSidecarsCount.inc(count - unloaded)
    else:
      # If there no useful columns, we will mark this node for deletion.
      nodesToRemove.add(node)

  for node in nodesToRemove:
    quarantine.removeNode(node, 0)

  quarantine.diskSidecarsCount = diskSidecarsCount
  quarantine.memSidecarsCount = memSidecarsCount
  blob_quarantine_memory_slots_occupied.set(
    int64(quarantine.memSidecarsCount))
  blob_quarantine_database_slots_occupied.set(
    int64(quarantine.diskSidecarsCount))

  quarantine.maxSidecarsPerBlockCount = maxSidecarsPerBlockCount
  quarantine.indexMap = indexMap
  quarantine.custodyColumns = toSeq(custodyMap.items)
  quarantine.custodyMap = custodyMap

proc update*(
    quarantine: var SomeColumnQuarantine,
    cfg: RuntimeConfig,
    custodyColumns: openArray[ColumnIndex]
) =
  doAssert(len(custodyColumns) <= NUMBER_OF_COLUMNS)
  let custodyMap = ColumnMap.init(custodyColumns)
  quarantine.update(cfg, custodyMap)

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

  SidecarQuarantine[A, B] = object
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
    list: DoublyLinkedList[RootTableRecord[A]]
    indexMap: seq[int]
    db: QuarantineDB
    onSidecarCallback*: B

  OnDataColumnSidecarCallback* = proc(
    data: DataColumnSidecarInfoObject) {.gcsafe, raises: [].}

  SomeSidecarRef* = ref fulu.DataColumnSidecar | ref gloas.DataColumnSidecar
  SomeSidecarIndex* = fulu.ColumnIndex
  SomeDataColumnSidecar = fulu.DataColumnSidecar | gloas.DataColumnSidecar

  ColumnQuarantine* =
    SidecarQuarantine[fulu.DataColumnSidecar, OnDataColumnSidecarCallback]
  GloasColumnQuarantine* =
    SidecarQuarantine[gloas.DataColumnSidecar, OnDataColumnSidecarCallback]

  ColumnQuarantineNode*[A: SomeDataColumnSidecar] =
    DoublyLinkedNode[RootTableRecord[A]]

func indexLog*[T: SomeSidecarRef](sidecars: openArray[ref T]): string =
  "[" & sidecars.mapIt($uint64(it[].index)).join(",") & "]"

func indexLog*[T: SomeSidecarIndex](indices: openArray[T]): string =
  "[" & indices.mapIt($uint64(it)).join(",") & "]"

func isEmpty[A](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Empty

func isUnloaded[A](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Unloaded

func isLoaded[A](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Loaded

func maxSidecars(maxSidecarsPerBlock: uint64): int =
  # Same limit as `MaxOrphans` in `block_quarantine`;
  # blobs may arrive before an orphan is tagged `blobless`
  3 * int(SLOTS_PER_EPOCH) * int(maxSidecarsPerBlock)

func init[A, B](
    t: typedesc[RootTableRecord],
    q: SidecarQuarantine[A, B]
): RootTableRecord[A] =
  RootTableRecord[A](
    sidecars: newSeq[SidecarHolder[A]](q.maxSidecarsPerBlockCount),
    count: 0, unloaded: 0, slot: FAR_FUTURE_SLOT)

func init[A, B](
    t: typedesc[RootTableRecord],
    q: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
  ): RootTableRecord[A] =
  RootTableRecord[A](
    blockRoot: blockRoot,
    sidecars: newSeq[SidecarHolder[A]](q.maxSidecarsPerBlockCount),
    count: 0, unloaded: 0, slot: FAR_FUTURE_SLOT)

func shortLog*[A, B](quarantine: SidecarQuarantine[A, B]): string =
  "[M:" & $quarantine.memSidecarsCount & "/" &
    $quarantine.maxMemSidecarsCount & ";D:" &
    $quarantine.diskSidecarsCount & "/" &
    $quarantine.maxDiskSidecarsCount & "]/" & $len(quarantine.roots)

func len*[A, B](q: SidecarQuarantine[A, B]): int =
  q.memSidecarsCount + q.diskSidecarsCount

func lenMemory*[A, B](q: SidecarQuarantine[A, B]): int =
  q.memSidecarsCount

func lenDisk*[A, B](q: SidecarQuarantine[A, B]): int =
  q.diskSidecarsCount

func size*[A, B](q: SidecarQuarantine[A, B]): int =
  q.maxMemSidecarsCount + q.maxDiskSidecarsCount

func sizeMemory*[A, B](q: SidecarQuarantine[A, B]): int =
  q.maxMemSidecarsCount

func sizeDisk*[A, B](q: SidecarQuarantine[A, B]): int =
  q.maxDiskSidecarsCount

func unload[A](holder: var SidecarHolder[A]): ref A =
  let res = holder.data
  holder.data = nil
  holder = SidecarHolder[A](
    kind: SidecarHolderKind.Unloaded,
    slot: holder.slot,
    index: holder.index,
    proposer_index: holder.proposer_index,
  )
  res

func getIndex[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B], index: ColumnIndex
): int =
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

proc removeNode[A, B](
    quarantine: var SidecarQuarantine[A, B],
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

proc offloadRoot[A, B](
    quarantine: var SidecarQuarantine[A, B],
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

func fitsInMemory[A, B](q: SidecarQuarantine[A, B], count: int): bool =
  q.memSidecarsCount + count <= q.maxMemSidecarsCount

func fitsInQuarantine[A, B](q: SidecarQuarantine[A, B], count: int): bool =
  (q.memSidecarsCount + q.diskSidecarsCount + count) <=
    (q.maxMemSidecarsCount + q.maxDiskSidecarsCount)

proc ensureSidecarsFits[A, B](
    q: var SidecarQuarantine[A, B],
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

proc put*[A, B](
    q: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    sidecars: openArray[ref A]
) =
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
          doAssert(index >= 0,
            "Incorrect sidecar index " & $sidecar.index & " points to " &
            $index)
          if isEmpty(node[].value.sidecars[index]):
            inc(res)
        res

  q.ensureSidecarsFits(newSidecarsCount).isOkOr:
    return

  for sidecar in sidecars:
    let index = q.getIndex(sidecar.index)
    if isEmpty(node[].value.sidecars[index]):
      inc(node[].value.count)
      node[].value.slot = sidecar[].slot()
      node[].value.sidecars[index] =
        SidecarHolder[A](
          kind: SidecarHolderKind.Loaded,
          slot: sidecar[].slot(),
          index: uint64(sidecar[].index),
          proposer_index: sidecar[].proposer_index(),
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
    # Move to first
    q.list.remove(node)
    if isNil(q.list.head) and isNil(q.list.tail):
      # In case when list empty, we could not use `prepend` operation.
      q.list.add(node)
    else:
      q.list.prepend(node)

  if isNil(q.lastMemoryNode):
    q.lastMemoryNode = node

proc put*[A, B](
    q: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    sidecar: ref A
) =
  q.put(blockRoot, [sidecar])

proc remove*[A, B](
    q: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
) =
  ## Remove all the data columns or blobs related to the block root ``blockRoot`
  ## from the quarantine ``q``.
  ##
  ## Function do nothing, if ``blockRoot` is not part of the quarantine.
  let node = q.roots.getOrDefault(blockRoot)
  if isNil(node):
    return
  q.removeNode(node, 0)

func load[A](holder: var SidecarHolder[A], sidecar: ref A) =
  holder = SidecarHolder[A](
    kind: SidecarHolderKind.Loaded,
    slot: holder.slot,
    index: holder.index,
    proposer_index: holder.proposer_index,
    data: sidecar
  )

proc loadRoot[A, B](
    quarantine: var SidecarQuarantine[A, B],
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

func hasSidecar*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    slot: Slot,
    proposer_index: uint64,
    index: ColumnIndex
): bool =
  ## Function returns ``true``if quarantine has column corresponding to specific
  ## ``index``, ``slot`` and ``proposer_index``.
  hasSidecarImpl(blockRoot, slot, proposer_index, index)

func hasSidecar*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    slot: Slot,
    index: ColumnIndex
): bool =
  ## Shorthand function for Gloas as proposer index is removed.
  let proposer_index = 0'u64
  hasSidecarImpl(blockRoot, slot, proposer_index, index)

func hasSidecar*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    index: ColumnIndex
): bool =
  hasSidecarImpl(blockRoot, index)

func hasSidecars*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  let node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return false

  let
    supernode = (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS)
    columnsCount =
      if supernode:
        (NUMBER_OF_COLUMNS div 2 + 1)
      else:
        len(quarantine.custodyColumns)

  if node[].value.count < columnsCount:
    # Quarantine does not hold enough column sidecars.
    return false
  true

func hasSidecars*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blck: fulu.SignedBeaconBlock,
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  hasSidecars(quarantine, blck.root)

func hasSidecars*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    envelope: gloas.SignedExecutionPayloadEnvelope,
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``envelope`` with block root ``blockRoot``.
  hasSidecars(quarantine, envelope.message.beacon_block_root)

proc popSidecars*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
): Opt[seq[ref A]] =
  ## Function returns sequence of column sidecars for block root ``blockRoot``.
  ## If some of the column sidecars are missing Opt.none() is returned.
  ## Note: Blocks should be checked for sidecars count first, otherwise
  ## result of this function would be always Opt.none().
  var node = quarantine.roots.getOrDefault(blockRoot)
  if isNil(node):
    return Opt.none(seq[ref A])

  let
    supernode = (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS)
    columnsCount =
      if supernode:
        (NUMBER_OF_COLUMNS div 2 + 1)
      else:
        len(quarantine.custodyColumns)

  if node[].value.count < columnsCount:
    # Quarantine does not hold enough column sidecars.
    return Opt.none(seq[ref A])

  let databaseCount = node[].value.unloaded
  if databaseCount > 0:
    # Quarantine unloaded some blobs to disk, we should load it back.
    quarantine.loadRoot(blockRoot, node[].value)

  var sidecars: seq[ref A]
  if supernode:
    for sidecar in node[].value.sidecars:
      # Supernode could have some of the columns not filled.
      if not(sidecar.isEmpty()):
        doAssert(sidecar.isLoaded(),
          "Record should only have loaded values, but it is `" &
            $sidecar.kind & "`")
        sidecars.add(sidecar.data)
      if len(sidecars) >= (NUMBER_OF_COLUMNS div 2 + 1):
        break

    doAssert(len(sidecars) >= (NUMBER_OF_COLUMNS div 2 + 1),
      "Incorrect amount of sidecars in record for supernode - " &
        $len(sidecars))
  else:
    for cindex in quarantine.custodyColumns:
      let index = quarantine.getIndex(cindex)
      doAssert(node[].value.sidecars[index].isLoaded(),
        "Record should only have loaded values, but it is `" &
          $node[].value.sidecars[index].kind & "`")
      sidecars.add(node[].value.sidecars[index].data)

    doAssert(len(sidecars) == len(quarantine.custodyColumns),
      "Incorrect amount of sidecars in record for node - " & $len(sidecars))

  # popSidecars() should remove all the artifacts from the quarantine in both
  # memory and disk.
  quarantine.removeNode(node, databaseCount)

  Opt.some(sidecars)

func fetchMissingSidecars*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
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
    supernode = (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS)
    columnsCount =
      if supernode:
        (NUMBER_OF_COLUMNS div 2)
      else:
        len(quarantine.custodyColumns)

  if supernode:
    if isNil(node):
      for column in peerMap.items():
        if len(res) > columnsCount:
          # We don't need to request more than (NUMBER_OF_COLUMNS div 2)
          # columns.
          break
        res.incl(column)
    else:
      if node[].value.count > columnsCount:
        # We already have enough columns for reconstruction.
        return
          DataColumnsByRootIdentifier(
            block_root: blockRoot,
            indices: DataColumnIndices(default(seq[ColumnIndex])))

      for column in peerMap.items():
        if node[].value.count + len(res) > columnsCount:
          # We don't need to request more than (NUMBER_OF_COLUMNS div 2)
          # columns.
          break
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

func fetchMissingSidecars*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    peerCustodyColumns: openArray[ColumnIndex] = []
): DataColumnsByRootIdentifier =
  if len(peerCustodyColumns) == 0:
    quarantine.fetchMissingSidecars(
      blockRoot, quarantine.custodyMap)
  else:
    quarantine.fetchMissingSidecars(
      blockRoot, ColumnMap.init(peerCustodyColumns))

func getMissingColumnsMap*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
): ColumnMap =
  var res: ColumnMap
  let node = quarantine.roots.getOrDefault(blockRoot)

  if (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS):
    if isNil(node):
      for index in 0 ..< NUMBER_OF_COLUMNS:
        res.incl(ColumnIndex(index))
    else:
      if len(node[].value.sidecars) > NUMBER_OF_COLUMNS div 2:
        return res
      for index in 0 ..< NUMBER_OF_COLUMNS:
        if node[].value.sidecars[index].isEmpty():
          res.incl(ColumnIndex(index))
  else:
    for column in quarantine.custodyMap.items():
      let index = quarantine.getIndex(column)
      if isNil(node) or (index == -1) or node[].value.sidecars[index].isEmpty():
        res.incl(column)
  res

func getMissingSidecarIndices*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
): seq[ColumnIndex] =
  var res: seq[ColumnIndex]
  for item in quarantine.getMissingColumnsMap(blockRoot):
    res.add(item)
  res

proc pruneAfterFinalization*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: var SidecarQuarantine[A, B],
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

template onDataColumnSidecarCallback*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: SidecarQuarantine[A, B]
): OnDataColumnSidecarCallback =
  quarantine.onSidecarCallback

proc init*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    T: typedesc[SidecarQuarantine[A, B]],
    cfg: RuntimeConfig,
    custodyColumns: openArray[ColumnIndex],
    database: QuarantineDB,
    maxDiskSizeMultipler: int,
    onDataColumnSidecarCallback: OnDataColumnSidecarCallback
): SidecarQuarantine[A, B] =
  doAssert(len(custodyColumns) <= NUMBER_OF_COLUMNS)
  let custodyMap = ColumnMap.init(custodyColumns)
  T.init(
    cfg, custodyMap, database, maxDiskSizeMultipler,
    onDataColumnSidecarCallback)

proc init*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    T: typedesc[SidecarQuarantine[A, B]],
    cfg: RuntimeConfig,
    custodyMap: ColumnMap,
    database: QuarantineDB,
    maxDiskSizeMultipler: int,
    onDataColumnSidecarCallback: OnDataColumnSidecarCallback
): SidecarQuarantine[A, B] =
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

  SidecarQuarantine[A, B](
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
    onSidecarCallback: onDataColumnSidecarCallback
  )

proc update*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: var SidecarQuarantine[A, B],
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

proc update*[A: SomeDataColumnSidecar, B: OnDataColumnSidecarCallback](
    quarantine: var SidecarQuarantine[A, B],
    cfg: RuntimeConfig,
    custodyColumns: openArray[ColumnIndex]
) =
  doAssert(len(custodyColumns) <= NUMBER_OF_COLUMNS)
  let custodyMap = ColumnMap.init(custodyColumns)
  quarantine.update(cfg, custodyMap)

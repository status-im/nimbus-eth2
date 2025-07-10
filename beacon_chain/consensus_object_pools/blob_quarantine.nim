# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/bitops2,
  std/[sets, tables],
  results, metrics,
  ../spec/datatypes/[deneb, electra, fulu],
  ../spec/[presets, helpers],
  ../beacon_chain_db_quarantine

from std/sequtils import mapIt, toSeq
from std/strutils import join

export results

declareGauge blob_quarantine_memory_slots_total, "Total count of available memory slots inside blob quarantine"
declareGauge blob_quarantine_memory_slots_occupied, "Number of occupied memory slots inside blob quarantine"
declareGauge blob_quarantine_database_slots_total, "Total count of availble database slots inside blob quarantine"
declareGauge blob_quarantine_database_slots_occupied, "Number of occupied database slots inside blob quarantine"

static:
  doAssert(NUMBER_OF_COLUMNS == 2 * 64, "ColumnMap should be updated")

type
  ColumnMap* = object
    data: array[2, uint64]

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
    sidecars: seq[SidecarHolder[A]]
    slot: Slot
    unloaded: int
    count: int

  SidecarQuarantine[A, B] = object
    maxMemSidecarsCount: int
    memSidecarsCount: int
    maxDiskSidecarsCount: int
    diskSidecarsCount: int
    maxSidecarsPerBlockCount: int
    custodyColumns: seq[ColumnIndex]
    custodyMap: ColumnMap
    roots: Table[Eth2Digest, RootTableRecord[A]]
    memUsage: OrderedSet[Eth2Digest]
    diskUsage: OrderedSet[Eth2Digest]
    indexMap: seq[int]
    db: QuarantineDB
    onSidecarCallback*: B

  OnBlobSidecarCallback* = proc(
    data: BlobSidecarInfoObject) {.gcsafe, raises: [].}
  OnDataColumnSidecarCallback* = proc(
    data: DataColumnSidecar) {.gcsafe, raises: [].}

  BlobQuarantine* =
    SidecarQuarantine[BlobSidecar, OnBlobSidecarCallback]
  ColumnQuarantine* =
    SidecarQuarantine[DataColumnSidecar, OnDataColumnSidecarCallback]

func isEmpty[A](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Empty

func isUnloaded[A](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Unloaded

func isLoaded[A](holder: SidecarHolder[A]): bool =
  holder.kind == SidecarHolderKind.Loaded

func init*(t: typedesc[ColumnMap], columns: openArray[ColumnIndex]): ColumnMap =
  var res: ColumnMap
  for column in columns:
    let
      index = int(uint64(column) shr 6)
      offset = int(uint64(column) and 0x3F'u64)
    res.data[index].setBit(offset)
  res

func `and`*(a, b: ColumnMap): ColumnMap =
  ColumnMap(data: [a.data[0] and b.data[0], a.data[1] and b.data[1]])

iterator items*(a: ColumnMap): ColumnIndex =
  var
    data0 = a.data[0]
    data1 = a.data[1]

  while data0 != 0'u64:
    let
      # t = data0 and -data0
      t = data0 and (not(data0) + 1'u64)
      res = firstOne(data0)
    yield ColumnIndex(res - 1)
    data0 = data0 xor t

  while data1 != 0'u64:
    let
      # t = data0 and -data0
      t = data1 and (not(data1) + 1'u64)
      res = firstOne(data1)
    yield ColumnIndex(64 + res - 1)
    data1 = data1 xor t

func `$`*(a: ColumnMap): string =
  "[" & a.items().toSeq().mapIt($it).join(", ") & "]"

func maxSidecars*(maxSidecarsPerBlock: uint64): int =
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

func len*[A, B](quarantine: SidecarQuarantine[A, B]): int =
  quarantine.memSidecarsCount + quarantine.diskSidecarsCount

func lenMemory*[A, B](quarantine: SidecarQuarantine[A, B]): int =
  quarantine.memSidecarsCount

func lenDisk*[A, B](quarantine: SidecarQuarantine[A, B]): int =
  quarantine.diskSidecarsCount

proc removeRoot[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
) =
  # This procedore removes all the sidecars associated with `blockRoot` from
  # memory and from disk.
  var
    rootRecord: RootTableRecord[A]
    sidecarsOnDisk = 0

  if quarantine.roots.pop(blockRoot, rootRecord):
    for index in 0 ..< len(rootRecord.sidecars):
      case rootRecord.sidecars[index].kind
      of SidecarHolderKind.Empty:
        discard
      of SidecarHolderKind.Loaded:
        rootRecord.sidecars[index].data = nil
        dec(quarantine.memSidecarsCount)
        blob_quarantine_memory_slots_occupied.set(
          int64(quarantine.memSidecarsCount))
      of SidecarHolderKind.Unloaded:
        dec(quarantine.diskSidecarsCount)
        blob_quarantine_database_slots_occupied.set(
          int64(quarantine.diskSidecarsCount))
        inc(sidecarsOnDisk)

    if sidecarsOnDisk > 0 and quarantine.maxMemSidecarsCount > 0:
      quarantine.db.removeDataSidecars(A, blockRoot)
      quarantine.diskUsage.excl(blockRoot)

    quarantine.memUsage.excl(blockRoot)

proc remove*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
) =
  ## Remove all the data columns or blobs related to the block root ``blockRoot`
  ## from the quarantine ``quarantine``.
  ##
  ## Function do nothing, if ``blockRoot` is not part of the quarantine.
  quarantine.removeRoot(blockRoot)

func getOldestInMemoryRoot[A, B](
    quarantine: SidecarQuarantine[A, B]
): Eth2Digest =
  var oldestRoot: Eth2Digest
  for blockRoot in quarantine.memUsage:
    oldestRoot = blockRoot
    break
  oldestRoot

func getOldestOnDiskRoot[A, B](
    quarantine: SidecarQuarantine[A, B]
): Eth2Digest =
  var oldestRoot: Eth2Digest
  for blockRoot in quarantine.diskUsage:
    oldestRoot = blockRoot
    break
  oldestRoot

func fitsInMemory[A, B](quarantine: SidecarQuarantine[A, B], count: int): bool =
  quarantine.memSidecarsCount + count <= quarantine.maxMemSidecarsCount

func fitsOnDisk[A, B](quarantine: SidecarQuarantine[A, B], count: int): bool =
  quarantine.diskSidecarsCount + count <= quarantine.maxDiskSidecarsCount

proc pruneInMemoryRoot[A, B](quarantine: var SidecarQuarantine[A, B]) =
  # Remove the all the blobs related to the oldest block root from the memory
  # storage of quarantine ``quarantine``.
  if len(quarantine.memUsage) == 0:
    return
  quarantine.remove(quarantine.getOldestInMemoryRoot())

proc pruneOnDiskRoot[A, B](quarantine: var SidecarQuarantine[A, B]) =
  # Remove the all the blobs related to the oldest block root from the disk
  # storage of quarantine ``quarantine``.
  # Returns `true` if oldest block root on disk is equal to `unloadRoot`.
  if len(quarantine.diskUsage) == 0:
    return
  quarantine.remove(quarantine.getOldestOnDiskRoot())

func getIndex(quarantine: BlobQuarantine, index: BlobIndex): int =
  quarantine.indexMap[int(index)]

func getIndex(quarantine: ColumnQuarantine, index: ColumnIndex): int =
  quarantine.indexMap[int(index)]

template slot(b: BlobSidecar|DataColumnSidecar): Slot =
  b.signed_block_header.message.slot

template proposer_index(b: BlobSidecar|DataColumnSidecar): uint64 =
  b.signed_block_header.message.proposer_index

func unload[A](holder: var SidecarHolder[A]): ref A =
  doAssert(holder.kind == SidecarHolderKind.Loaded)
  let res = holder.data
  holder.data = nil
  holder = SidecarHolder[A](
    kind: SidecarHolderKind.Unloaded,
    slot: holder.slot,
    index: holder.index,
    proposer_index: holder.proposer_index,
  )
  res

func load[A](holder: var SidecarHolder[A], sidecar: ref A) =
  holder = SidecarHolder[A](
    kind: SidecarHolderKind.Loaded,
    slot: holder.slot,
    index: holder.index,
    proposer_index: holder.proposer_index,
    data: sidecar
  )

proc unloadRoot[A, B](quarantine: var SidecarQuarantine[A, B]) =
  doAssert(len(quarantine.memUsage) > 0)

  if quarantine.maxDiskSidecarsCount == 0:
    # Disk storage is disabled, so we use should prune memory storage instead.
    quarantine.pruneInMemoryRoot()
    return

  let blockRoot = quarantine.getOldestInMemoryRoot()

  quarantine.roots.withValue(blockRoot, record):
    if not(quarantine.fitsOnDisk(record[].count)):
      quarantine.pruneOnDiskRoot()
      # Pruning on disk also removes sidecars from memory, so this could be
      # enough
      return

    var res: seq[ref A]
    for index in 0 ..< len(record[].sidecars):
      if record[].sidecars[index].kind == SidecarHolderKind.Loaded:
        res.add(record[].sidecars[index].unload())
        dec(quarantine.memSidecarsCount)
        inc(quarantine.diskSidecarsCount)
        blob_quarantine_memory_slots_occupied.set(
          int64(quarantine.memSidecarsCount))
        blob_quarantine_database_slots_occupied.set(
          int64(quarantine.diskSidecarsCount))
        inc(record[].unloaded)

    if len(res) > 0:
      quarantine.db.putDataSidecars(blockRoot, res)
      quarantine.memUsage.excl(blockRoot)
      quarantine.diskUsage.incl(blockRoot)

proc loadRoot[A, B](quarantine: var SidecarQuarantine[A, B],
                    blockRoot: Eth2Digest,
                    record: var RootTableRecord[A]) =
  for sidecar in quarantine.db.sidecars(A, blockRoot):
    let index = quarantine.getIndex(sidecar.index)
    doAssert(index >= 0, "Incorrect sidecar index [" & $sidecar.index & "]")
    doAssert(record.sidecars[index].isUnloaded(),
             "Database storage is inconsistent")
    record.sidecars[index].load(newClone(sidecar))
    dec(record.unloaded)
  doAssert(record.unloaded == 0, "Record's unload counter should be zero")

proc put[A, B](record: var RootTableRecord[A], q: var SidecarQuarantine[A, B],
               sidecars: openArray[ref A]) =
  for sidecar in sidecars:
    # Sidecar should pass validation before being added to quarantine,
    # so we assume that
    # 1. sidecar.index is < MAX_BLOBS_PER_BLOCK for `deneb` and.
    # 2. sidecar.index is < MAX_BLOBS_PER_BLOCK_ELECTRA for `electra`.
    # 3. sidecar.index is in custody columns set for `fulu`.
    let index = q.getIndex(sidecar.index)
    doAssert(index >= 0, "Incorrect sidecar index [" & $sidecar.index & "]")

    if isEmpty(record.sidecars[index]):
      inc(q.memSidecarsCount)
      blob_quarantine_memory_slots_occupied.set(int64(q.memSidecarsCount))
      inc(record.count)
      record.slot = sidecar[].slot()

    record.sidecars[index] = SidecarHolder[A](
      kind: SidecarHolderKind.Loaded,
      slot: sidecar[].slot(),
      index: uint64(sidecar[].index),
      proposer_index: sidecar[].proposer_index(),
      data: sidecar
    )

proc put*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    sidecar: ref A
) =
  ## Function adds blob or data column sidecar associated with block root
  ## ``blockRoot`` to the quarantine ``quarantine``.
  while not(quarantine.fitsInMemory(1)):
    # FIFO if full. For example, sync manager and request manager can race to
    # put blobs in at the same time, so one gets blob insert -> block resolve
    # -> blob insert sequence, which leaves garbage blobs.
    #
    # This also therefore automatically garbage-collects otherwise valid garbage
    # blobs which are correctly signed, point to either correct block roots or a
    # block root which isn't ever seen, and then are for any reason simply never
    # used.
    quarantine.unloadRoot()

  let rootRecord = RootTableRecord.init(quarantine)
  quarantine.roots.mgetOrPut(blockRoot, rootRecord).put(
    quarantine, [sidecar])
  quarantine.memUsage.incl(blockRoot)

proc put*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    sidecars: openArray[ref A]
) =
  ## Function adds number of blobs or data columns sidecars associated to single
  ## block with root ``blockRoot`` to the quarantine ``quarantine``.
  if len(sidecars) == 0:
    return

  while not(quarantine.fitsInMemory(len(sidecars))):
    # FIFO if full. For example, sync manager and request manager can race to
    # put blobs in at the same time, so one gets blob insert -> block resolve
    # -> blob insert sequence, which leaves garbage blobs.
    #
    # This also therefore automatically garbage-collects otherwise valid garbage
    # blobs which are correctly signed, point to either correct block roots or a
    # block root which isn't ever seen, and then are for any reason simply never
    # used.
    quarantine.unloadRoot()

  let rootRecord = RootTableRecord.init(quarantine)

  quarantine.roots.mgetOrPut(blockRoot, rootRecord).put(
    quarantine, sidecars)
  quarantine.memUsage.incl(blockRoot)

template hasSidecarImpl(
    blockRoot: Eth2Digest,
    slot: Slot,
    proposerIndex: uint64,
    sidecarIndex: typed
): bool =
  let rootRecord = quarantine.roots.getOrDefault(blockRoot)
  if rootRecord.count == 0:
    return false
  let index = quarantine.getIndex(index)
  if (index == -1) or rootRecord.sidecars[index].isEmpty():
    return false
  if (rootRecord.sidecars[index].proposer_index != proposer_index) or
     (rootRecord.sidecars[index].slot != slot):
    return false
  true

func hasSidecar*(
    quarantine: BlobQuarantine,
    blockRoot: Eth2Digest,
    slot: Slot,
    proposer_index: uint64,
    index: BlobIndex,
): bool =
  ## Function returns ``true``if quarantine has blob corresponding to specific
  ## ``block root``, ``index``, ``slot`` and ``proposer_index``.
  hasSidecarImpl(blockRoot, slot, proposer_index, index)

func hasSidecar*(
    quarantine: ColumnQuarantine,
    blockRoot: Eth2Digest,
    slot: Slot,
    proposer_index: uint64,
    index: ColumnIndex
): bool =
  ## Function returns ``true``if quarantine has column corresponding to specific
  ## ``index``, ``slot`` and ``proposer_index``.
  hasSidecarImpl(blockRoot, slot, proposer_index, index)

func hasSidecars*(
    quarantine: BlobQuarantine,
    blockRoot: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): bool =
  ## Function returns ``true`` if quarantine has all the blobs for block
  ## ``blck`` with block root ``blockRoot``.
  if len(blck.message.body.blob_kzg_commitments) == 0:
    return true

  let record = quarantine.roots.getOrDefault(blockRoot)
  if record.count == 0:
    # block root not found.
    return false

  if record.count < len(blck.message.body.blob_kzg_commitments):
    # Quarantine does not hold enough blob sidecars.
    return false
  true

func hasSidecars*(
    quarantine: ColumnQuarantine,
    blockRoot: Eth2Digest,
    blck: fulu.SignedBeaconBlock
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  if len(blck.message.body.blob_kzg_commitments) == 0:
    return true

  let record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not initialized.
    return false

  let
    supernode = (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS)
    columnsCount =
      if supernode:
        (NUMBER_OF_COLUMNS div 2 + 1)
      else:
        len(quarantine.custodyColumns)

  if record.count < columnsCount:
    # Quarantine does not hold enough column sidecars.
    return false
  true

func hasSidecars*(
    quarantine: BlobQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): bool =
  ## Function returns ``true`` if quarantine has all the blobs for block
  ## ``blck`` with block root ``blockRoot``.
  hasSidecars(quarantine, blck.root, blck)

func hasSidecars*(
    quarantine: ColumnQuarantine,
    blck: fulu.SignedBeaconBlock
): bool =
  ## Function returns ``true`` if quarantine has all the columns for block
  ## ``blck`` with block root ``blockRoot``.
  hasSidecars(quarantine, blck.root, blck)

proc popSidecars*(
    quarantine: var BlobQuarantine,
    blockRoot: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): Opt[seq[ref BlobSidecar]] =
  ## Function returns sequence of blob sidecars for block root ``blockRoot`` and
  ## block ``blck``.
  ## If some of the blob sidecars are missing Opt.none() is returned.
  ## If block do not have any blob sidecars Opt.some([]) is returned.
  let sidecarsCount = len(blck.message.body.blob_kzg_commitments)
  if sidecarsCount == 0:
    # Block does not have any blob sidecars.
    quarantine.remove(blockRoot)
    return Opt.some(default(seq[ref BlobSidecar]))

  var record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not initialized.
    return Opt.none(seq[ref BlobSidecar])

  if record.count < sidecarsCount:
    # Quarantine does not hold enough blob sidecars.
    return Opt.none(seq[ref BlobSidecar])

  if record.unloaded > 0:
    # Quarantine unloaded some blobs to disk, we should load it back.
    quarantine.loadRoot(blockRoot, record)

  var sidecars: seq[ref BlobSidecar]
  for bindex in 0 ..< len(blck.message.body.blob_kzg_commitments):
    let index = quarantine.getIndex(BlobIndex(bindex))
    doAssert(record.sidecars[index].isLoaded(),
      "Record should only have loaded values at this point")
    sidecars.add(record.sidecars[index].data)

  # popSidecars() should remove all the artifacts from the quarantine in both
  # memory and disk.
  quarantine.removeRoot(blockRoot)

  Opt.some(sidecars)

proc popSidecars*(
    quarantine: var ColumnQuarantine,
    blockRoot: Eth2Digest,
    blck: fulu.SignedBeaconBlock
): Opt[seq[ref DataColumnSidecar]] =
  ## Function returns sequence of column sidecars for block root ``blockRoot``
  ## and block ``blck``.
  ## If some of the column sidecars are missing Opt.none() is returned.
  ## If block do not have any column sidecars bundledd Opt.some([]) is returned.
  let sidecarsCount = len(blck.message.body.blob_kzg_commitments)
  if sidecarsCount == 0:
    # Block does not have any blob sidecars.
    quarantine.remove(blockRoot)
    return Opt.some(default(seq[ref DataColumnSidecar]))

  var record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not allocated.
    return Opt.none(seq[ref DataColumnSidecar])

  let
    supernode = (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS)
    columnsCount =
      if supernode:
        (NUMBER_OF_COLUMNS div 2 + 1)
      else:
        len(quarantine.custodyColumns)

  if record.count < columnsCount:
    # Quarantine does not hold enough column sidecars.
    return Opt.none(seq[ref DataColumnSidecar])

  if record.unloaded > 0:
    # Quarantine unloaded some blobs to disk, we should load it back.
    quarantine.loadRoot(blockRoot, record)

  var sidecars: seq[ref DataColumnSidecar]
  if supernode:
    for sidecar in record.sidecars:
      # Supernode could have some of the columns not filled.
      if not(sidecar.isEmpty()):
        doAssert(sidecar.isLoaded(),
                 "Sidecars should be loaded at this moment")
        sidecars.add(sidecar.data)
      if len(sidecars) >= (NUMBER_OF_COLUMNS div 2 + 1):
        break

    doAssert(len(sidecars) >= (NUMBER_OF_COLUMNS div 2 + 1),
             "Incorrect amount of sidecars in record")
  else:
    for cindex in quarantine.custodyColumns:
      let index = quarantine.getIndex(cindex)
      doAssert(record.sidecars[index].isLoaded(),
               "Sidecars should be loaded at this moment")
      sidecars.add(record.sidecars[index].data)

    doAssert(len(sidecars) == len(quarantine.custodyColumns),
             "Incorrect amount of sidecars in record")

  # popSidecars() should remove all the artifacts from the quarantine in both
  # memory and disk.
  quarantine.removeRoot(blockRoot)

  Opt.some(sidecars)

proc popSidecars*(
    quarantine: var BlobQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): Opt[seq[ref BlobSidecar]] =
  ## Alias for `popSidecars()`.
  popSidecars(quarantine, blck.root, blck)

proc popSidecars*(
    quarantine: var ColumnQuarantine,
    blck: fulu.SignedBeaconBlock
): Opt[seq[ref DataColumnSidecar]] =
  ## Alias for `popSidecars()`.
  popSidecars(quarantine, blck.root, blck)

func fetchMissingSidecars*(
    quarantine: BlobQuarantine,
    blockRoot: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
    fulu.SignedBeaconBlock
): seq[BlobIdentifier] =
  ## Function returns sequence of BlobIdentifiers for blobs which are missing
  ## for block root ``blockRoot`` and block ``blck``.
  var res: seq[BlobIdentifier]
  let record = quarantine.roots.getOrDefault(blockRoot)

  let commitmentsCount = len(blck.message.body.blob_kzg_commitments)
  if (commitmentsCount == 0) or (record.count == commitmentsCount):
    # Fast-path if ``blck`` does not have any blobs or if quarantine's record
    # holds enough blobs.
    return res

  for bindex in 0 ..< commitmentsCount:
    let index = quarantine.getIndex(BlobIndex(bindex))
    if len(record.sidecars) == 0 or record.sidecars[index].isEmpty():
      res.add(BlobIdentifier(block_root: blockRoot, index: BlobIndex(bindex)))
  res

func fetchMissingSidecars*(
    quarantine: ColumnQuarantine,
    blockRoot: Eth2Digest,
    blck: fulu.SignedBeaconBlock,
    peerCustodyColumns: openArray[ColumnIndex] = []
): seq[DataColumnIdentifier] =
  ## Function returns sequence of DataColumnIdentifier's for data columns which
  ## are missing for block associated with root ``blockRoot`` and block ``blck``.
  var res: seq[DataColumnIdentifier]
  let record = quarantine.roots.getOrDefault(blockRoot)

  if len(blck.message.body.blob_kzg_commitments) == 0:
    # Fast-path if block do not have any columns
    return res

  let
    supernode = (len(quarantine.custodyColumns) == NUMBER_OF_COLUMNS)
    columnsCount =
      if supernode:
        (NUMBER_OF_COLUMNS div 2 + 1)
      else:
        len(quarantine.custodyColumns)

  if supernode:
    let
      columns =
        if len(peerCustodyColumns) > 0:
          @peerCustodyColumns
        else:
          quarantine.custodyColumns
    if len(record.sidecars) == 0:
      var columnsRequested = 0
      for column in columns:
        if columnsRequested >= columnsCount:
          # We don't need to request more than (NUMBER_OF_COLUMNS div 2 + 1)
          # columns.
          break
        res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
        inc(columnsRequested)
    else:
      if record.count >= columnsCount:
        return res
      var columnsRequested = 0
      for column in columns:
        if record.count + columnsRequested >= columnsCount:
          # We don't need to request more than (NUMBER_OF_COLUMNS div 2 + 1)
          # columns.
          break
        let index = quarantine.getIndex(column)
        if (index == -1) or record.sidecars[index].isEmpty():
          res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
          inc(columnsRequested)
  else:
    let peerMap =
      if len(peerCustodyColumns) > 0:
        ColumnMap.init(peerCustodyColumns)
      else:
        ColumnMap.init(quarantine.custodyColumns)
    if len(record.sidecars) == 0:
      for column in (peerMap and quarantine.custodyMap).items():
        res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
    else:
      for column in (peerMap and quarantine.custodyMap).items():
        let index = quarantine.getIndex(column)
        if (index == -1) or record.sidecars[index].isEmpty():
          res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
  res

proc pruneAfterFinalization*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    epoch: Epoch
) =
  let epochSlot = (epoch + 1).start_slot()
  var rootsToRemove: seq[Eth2Digest]

  for mkey, mrecord in quarantine.roots.mpairs():
    if (mrecord.count > 0) and (mrecord.slot < epochSlot):
      rootsToRemove.add(mkey)

  for root in rootsToRemove:
    quarantine.removeRoot(root)

template onBlobSidecarCallback*(
    quarantine: BlobQuarantine
): OnBlobSidecarCallback =
  quarantine.onSidecarCallback

template onDataColumnSidecarCallback*(
    quarantine: ColumnQuarantine
): OnDataColumnSidecarCallback =
  quarantine.onSidecarCallback

proc init*(
    T: typedesc[BlobQuarantine],
    cfg: RuntimeConfig,
    database: QuarantineDB,
    maxDiskSizeMultipler: int,
    onBlobSidecarCallback: OnBlobSidecarCallback
): BlobQuarantine =
  # BlobSidecars maps are trivial, but still useful
  var indexMap = newSeqUninit[int](cfg.MAX_BLOBS_PER_BLOCK_ELECTRA)
  for index in 0 ..< len(indexMap):
    indexMap[index] = index

  let size = maxSidecars(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA)

  blob_quarantine_memory_slots_total.set(int64(size))
  blob_quarantine_database_slots_total.set(
    int64(size) * int64(maxDiskSizeMultipler))
  blob_quarantine_memory_slots_occupied.set(0'i64)
  blob_quarantine_database_slots_occupied.set(0'i64)

  BlobQuarantine(
    maxSidecarsPerBlockCount: int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA),
    maxMemSidecarsCount: size,
    maxDiskSidecarsCount: size * maxDiskSizeMultipler,
    memSidecarsCount: 0,
    diskSidecarsCount: 0,
    indexMap: indexMap,
    onSidecarCallback: onBlobSidecarCallback,
    db: database
  )

proc init*(
    T: typedesc[ColumnQuarantine],
    cfg: RuntimeConfig,
    custodyColumns: openArray[ColumnIndex],
    database: QuarantineDB,
    maxDiskSizeMultipler: int,
    onBlobSidecarCallback: OnDataColumnSidecarCallback
): ColumnQuarantine =
  doAssert(len(custodyColumns) <= NUMBER_OF_COLUMNS)
  var indexMap = newSeqUninit[int](NUMBER_OF_COLUMNS)
  if len(custodyColumns) < NUMBER_OF_COLUMNS:
    for i in 0 ..< len(indexMap):
      indexMap[i] = -1
  for index, item in custodyColumns.pairs():
    doAssert(item < uint64(NUMBER_OF_COLUMNS))
    indexMap[int(item)] = index

  let size = maxSidecars(NUMBER_OF_COLUMNS)

  blob_quarantine_memory_slots_total.set(int64(size))
  blob_quarantine_database_slots_total.set(
    int64(size) * int64(maxDiskSizeMultipler))
  blob_quarantine_memory_slots_occupied.set(0'i64)
  blob_quarantine_database_slots_occupied.set(0'i64)

  ColumnQuarantine(
    maxSidecarsPerBlockCount: len(custodyColumns),
    maxMemSidecarsCount: size,
    maxDiskSidecarsCount: size * maxDiskSizeMultipler,
    memSidecarsCount: 0,
    diskSidecarsCount: 0,
    indexMap: indexMap,
    custodyColumns: @custodyColumns,
    custodyMap: ColumnMap.init(custodyColumns),
    db: database,
    onSidecarCallback: onBlobSidecarCallback
  )

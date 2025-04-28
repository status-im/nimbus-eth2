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
  results,
  ../spec/datatypes/[deneb, electra, fulu],
  ../spec/[presets, helpers]

from std/sequtils import mapIt
from std/strutils import join

export results

type
  ColumnMap* = object
    data: array[2, uint64]

  RootTableRecord[A] = object
    sidecars: seq[ref A]
    count: int

  SlotRecord[A] = object
    blockRoot: Eth2Digest
    sidecar: ref A

  SlotTableRecord[A] = seq[seq[SlotRecord[A]]]

  SidecarQuarantine[A, B] = object
    maxSidecarsCount: int
    maxSidecarsPerBlockCount: int
    sidecarsCount: int
    custodyColumns: seq[ColumnIndex]
    custodyMap: ColumnMap
    roots: Table[Eth2Digest, RootTableRecord[A]]
    slots: Table[Slot, SlotTableRecord[A]]
    usage: OrderedSet[Eth2Digest]
    indexMap: seq[int]
    onSidecarCallback*: B

  OnBlobSidecarCallback* = proc(
    data: BlobSidecarInfoObject) {.gcsafe, raises: [].}
  OnDataColumnSidecarCallback* = proc(
    data: DataColumnSidecar) {.gcsafe, raises: [].}

  BlobQuarantine* =
    SidecarQuarantine[BlobSidecar, OnBlobSidecarCallback]
  ColumnQuarantine* =
    SidecarQuarantine[DataColumnSidecar, OnDataColumnSidecarCallback]

func init*(t: typedesc[ColumnMap], columns: openArray[ColumnIndex]): ColumnMap =
  var res: ColumnMap
  for column in columns:
    let
      index = int(uint64(column) shr 6)
      offset = int(uint64(column) and 0x3F'u64)
    res.data[index].setBit(offset)
  res

# func `xor`(a, b: ColumnMap): ColumnMap =
#   ColumnMap(data: [a.data[0] xor b.data[0], a.data[1] xor b.data[1]])

func `and`*(a, b: ColumnMap): ColumnMap =
  ColumnMap(data: [a.data[0] and b.data[0], a.data[1] and b.data[1]])

# func `or`(a, b: ColumnMap): ColumnMap =
#   ColumnMap(data: [a.data[0] or b.data[0], a.data[1] or b.data[1]])

# func `not`(a: ColumnMap): ColumnMap =
#   ColumnMap(data: [not(a.data[0]), not(a.data[1])])

# func `==`(a, b: ColumnMap): bool =
#   (a.data[0] == b.data[0]) and (a.data[1] == b.data[1])

func asSeq(a: ColumnMap): seq[ColumnIndex] =
  var
    res1: seq[ColumnIndex]
    res2: seq[ColumnIndex]
  for i in 0 ..< 64:
    if a.data[0].getBit(i):
      res1.add(ColumnIndex(i))
    if a.data[1].getBit(i):
      res2.add(ColumnIndex(64 + i))
  res1 & res2

func `$`*(a: ColumnMap): string =
  "[" & a.asSeq().mapIt($it).join(", ") & "]"

func maxSidecars(maxSidecarsPerBlock: uint64): int =
  # Same limit as `MaxOrphans` in `block_quarantine`;
  # blobs may arrive before an orphan is tagged `blobless`
  3 * int(SLOTS_PER_EPOCH) * int(maxSidecarsPerBlock)

func shortLog*(x: seq[BlobIndex]): string =
  "<" & x.mapIt($it).join(", ") & ">"

func init[A, B](
    t: typedesc[RootTableRecord],
    q: SidecarQuarantine[A, B]
): RootTableRecord[A] =
  RootTableRecord[A](
    sidecars: newSeq[ref A](q.maxSidecarsPerBlockCount), count: 0)

func init[A, B](
  t: typedesc[SlotTableRecord],
  q: SidecarQuarantine[A, B]
): SlotTableRecord[A] =
  newSeq[seq[SlotRecord[A]]](q.maxSidecarsPerBlockCount)

func len*[A, B](quarantine: SidecarQuarantine[A, B]): int =
  quarantine.sidecarsCount

func `$`*[A](r: RootTableRecord[A]): string =
  if len(r.sidecars) == 0:
    return "<empty>"
  r.sidecars.mapIt(if isNil(it): "." else: "x").join("")

func del[A](records: var seq[SlotRecord[A]], blockRoot: Eth2Digest) =
  for index in 0 ..< len(records):
    if records[index].blockRoot == blockRoot:
      records.del(index)
      return

func removeRootsInSlot[A, B](
    quarantine: var SidecarQuarantine[A, B],
    slot: Slot,
    indices: openArray[int],
    blockRoot: Eth2Digest
) =
  quarantine.slots.withValue(slot, records):
    for index in indices:
      if index < len(records[]):
        records[][index].del(blockRoot)

func removeRoot[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    cleanSlot: bool,
) =
  var
    slot = FAR_FUTURE_SLOT
    indices: seq[int]
    rootRecord: RootTableRecord[A]

  if quarantine.roots.pop(blockRoot, rootRecord):
    for index in 0 ..< len(rootRecord.sidecars):
      if not(rootRecord.sidecars[index].isNil()):
        slot = rootRecord.sidecars[index].signed_block_header.message.slot
        rootRecord.sidecars[index] = nil
        if cleanSlot:
          indices.add(index)
        dec(quarantine.sidecarsCount)

  if cleanSlot and slot != FAR_FUTURE_SLOT:
    quarantine.removeRootsInSlot(slot, indices, blockRoot)

  quarantine.usage.excl(blockRoot)

func remove*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    slot: Slot
) =
  ## Remove all the data columns or blobs related to the slot ``slot`` from the
  ## quarantine ``quarantine``.
  ##
  ## Function do nothing, if ``slot`` is not part of quarantine.
  var slotRecords: SlotTableRecord[A]

  if quarantine.slots.pop(slot, slotRecords):
    for recordsList in slotRecords.mitems():
      for record in recordsList.mitems():
        record.sidecar = nil
        quarantine.removeRoot(record.blockRoot, false)
    slotRecords.reset()

func remove*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
) =
  ## Remove all the data columns or blobs related to the block root ``blockRoot`
  ## from the quarantine ``quarantine``.
  ##
  ## Function do nothing, if ``blockRoot` is not part of the quarantine.
  quarantine.removeRoot(blockRoot, true)

func pruneRoot[A, B](quarantine: var SidecarQuarantine[A, B]) =
  # Remove the all the blobs related to the oldest block root from the
  # quarantine ``quarantine``.
  if len(quarantine.usage) == 0:
    return
  var oldestRoot: Eth2Digest
  for blockRoot in quarantine.usage:
    oldestRoot = blockRoot
    break
  quarantine.remove(oldestRoot)

func getIndex(quarantine: BlobQuarantine, index: BlobIndex): int =
  doAssert(index < lenu64(quarantine.indexMap))
  quarantine.indexMap[int(index)]

func getIndex(quarantine: ColumnQuarantine, index: ColumnIndex): int =
  doAssert(index < lenu64(quarantine.indexMap))
  quarantine.indexMap[int(index)]

template slot(b: BlobSidecar|DataColumnSidecar): Slot =
  b.signed_block_header.message.slot

template proposer_index(b: BlobSidecar|DataColumnSidecar): uint64 =
  b.signed_block_header.message.proposer_index

func put[A, B](record: var RootTableRecord[A], q: SidecarQuarantine[A, B],
               sidecars: openArray[ref A]) =
  for sidecar in sidecars:
    # Sidecar should pass validation before being added to quarantine,
    # so we assume that
    # 1. sidecar.index is < MAX_BLOBS_PER_BLOCK for `deneb` and.
    # 2. sidecar.index is < MAX_BLOBS_PER_BLOCK_ELECTRA for `electra`.
    # 3. sidecar.index is in custody columns set for `fulu`.
    let index = q.getIndex(sidecar.index)
    doAssert(index >= 0, "Incorrect sidecar index [" & $sidecar.index & "]")
    record.sidecars[index] = sidecar
    inc(record.count)

func put[A, B](record: var SlotTableRecord[A], q: SidecarQuarantine[A, B],
               blockRoot: Eth2Digest, sidecars: openArray[ref A]) =
  for sidecar in sidecars:
    # Sidecar should pass validation before being added to quarantine,
    # so we assume that
    # 1. sidecar.index is < MAX_BLOBS_PER_BLOCK for `deneb` and.
    # 2. sidecar.index is < MAX_BLOBS_PER_BLOCK_ELECTRA for `electra`.
    # 3. sidecar.index is in custody columns set for `fulu`.
    let index = q.getIndex(sidecar.index)
    doAssert(index >= 0, "Incorrect sidecar index [" & $sidecar.index & "]")
    record[index].add(SlotRecord[A](block_root: blockRoot, sidecar: sidecar))

func put*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    sidecar: ref A
) =
  ## Function adds blob or data column sidecar associated with block root
  ## ``blockRoot`` to the quarantine ``quarantine``.
  while quarantine.sidecarsCount >= quarantine.maxSidecarsCount:
    # FIFO if full. For example, sync manager and request manager can race to
    # put blobs in at the same time, so one gets blob insert -> block resolve
    # -> blob insert sequence, which leaves garbage blobs.
    #
    # This also therefore automatically garbage-collects otherwise valid garbage
    # blobs which are correctly signed, point to either correct block roots or a
    # block root which isn't ever seen, and then are for any reason simply never
    # used.
    quarantine.pruneRoot()

  let
    rootRecord = RootTableRecord.init(quarantine)
    slotRecord = SlotTableRecord.init(quarantine)
  quarantine.roots.mgetOrPut(blockRoot, rootRecord).put(
    quarantine, [sidecar])
  quarantine.slots.mgetOrPut(sidecar[].slot(), slotRecord).put(
    quarantine, blockRoot, [sidecar])
  discard quarantine.usage.containsOrIncl(blockRoot)
  inc(quarantine.sidecarsCount)

func put*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    blobSidecars: openArray[ref A]
) =
  ## Function adds number of blobs or data columns sidecars associated to single
  ## block with root ``blockRoot`` to the quarantine ``quarantine``.
  if len(blobSidecars) == 0:
    return

  while quarantine.sidecarsCount >= quarantine.maxSidecarsCount:
    # FIFO if full. For example, sync manager and request manager can race to
    # put blobs in at the same time, so one gets blob insert -> block resolve
    # -> blob insert sequence, which leaves garbage blobs.
    #
    # This also therefore automatically garbage-collects otherwise valid garbage
    # blobs which are correctly signed, point to either correct block roots or a
    # block root which isn't ever seen, and then are for any reason simply never
    # used.
    quarantine.pruneRoot()

  let
    slot =
      # All the blobs related to single block we could get `slot` once.
      blobSidecars[0][].slot()
    rootRecord = RootTableRecord.init(quarantine)
    slotRecord = SlotTableRecord.init(quarantine)

  quarantine.roots.mgetOrPut(blockRoot, rootRecord).put(
    quarantine, blobSidecars)
  quarantine.slots.mgetOrPut(slot, slotRecord).put(
      quarantine, blockRoot, blobSidecars)
  discard quarantine.usage.containsOrIncl(blockRoot)
  inc(quarantine.sidecarsCount, len(blobSidecars))

template hasSidecarImpl(slot: Slot, proposerIndex: uint64,
                        sidecarIndex: typed): bool =
  let
    slotRecord = quarantine.slots.getOrDefault(slot)
    sindex = quarantine.getIndex(sidecarIndex)
  if (sindex == -1) or (sindex >= len(slotRecord)):
    return false
  for record in slotRecord[sindex]:
    if record.sidecar[].proposer_index() == proposerIndex:
      return true
  false

func hasSidecar*(
    quarantine: BlobQuarantine,
    slot: Slot,
    proposer_index: uint64,
    index: BlobIndex,
): bool =
  ## Function returns ``true``if quarantine has blob corresponding to specific
  ## ``index``, ``slot`` and ``proposer_index``.
  hasSidecarImpl(slot, proposer_index, index)

func hasSidecar*(
    quarantine: ColumnQuarantine,
    slot: Slot,
    proposer_index: uint64,
    index: ColumnIndex
): bool =
  ## Function returns ``true``if quarantine has column corresponding to specific
  ## ``index``, ``slot`` and ``proposer_index``.
  hasSidecarImpl(slot, proposer_index, index)

func hasSidecars*(
    quarantine: BlobQuarantine,
    blockRoot: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): bool =
  ## Function returns ``true`` if quarantine has all the blobs for block
  ## ``blck`` with block root ``blockRoot``.
  let record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not initialized.
    return false
  if len(blck.message.body.blob_kzg_commitments) == 0:
    return true

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
  let record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not initialized.
    return false
  if len(blck.message.body.blob_kzg_commitments) == 0:
    return true

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

func popSidecars*(
    quarantine: var BlobQuarantine,
    blockRoot: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): Opt[seq[ref BlobSidecar]] =
  ## Function returns sequence of blob sidecars for block root ``blockRoot`` and
  ## block ``blck``.
  ## If some of the blob sidecars are missing Opt.none() is returned.
  ## If block do not have any blob sidecars Opt.some([]) is returned.
  let record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not initialized.
    return Opt.none(seq[ref BlobSidecar])

  let sidecarsCount = len(blck.message.body.blob_kzg_commitments)

  if sidecarsCount == 0:
    # Block does not have any blob sidecars.
    quarantine.remove(blck.message.slot)
    return Opt.some(default(seq[ref BlobSidecar]))

  if record.count < sidecarsCount:
    # Quarantine does not hold enough blob sidecars.
    return Opt.none(seq[ref BlobSidecar])

  var sidecars: seq[ref BlobSidecar]
  for bindex in 0 ..< len(blck.message.body.blob_kzg_commitments):
    let index = quarantine.getIndex(BlobIndex(bindex))
    doAssert(not(isNil(record.sidecars[index])),
      "Record should not store nil values when record's count is correct")
    sidecars.add(record.sidecars[index])
  quarantine.remove(blck.message.slot)
  Opt.some(sidecars)

func popSidecars*(
    quarantine: var ColumnQuarantine,
    blockRoot: Eth2Digest,
    blck: fulu.SignedBeaconBlock
): Opt[seq[ref DataColumnSidecar]] =
  ## Function returns sequence of column sidecars for block root ``blockRoot``
  ## and block ``blck``.
  ## If some of the column sidecars are missing Opt.none() is returned.
  ## If block do not have any column sidecars bundledd Opt.some([]) is returned.
  let record = quarantine.roots.getOrDefault(blockRoot)
  if len(record.sidecars) == 0:
    # block root not found, record.sidecars sequence was not allocated.
    return Opt.none(seq[ref DataColumnSidecar])

  let sidecarsCount = len(blck.message.body.blob_kzg_commitments)

  if sidecarsCount == 0:
    # Block does not have any blob sidecars.
    quarantine.remove(blck.message.slot)
    return Opt.some(default(seq[ref DataColumnSidecar]))

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

  var sidecars: seq[ref DataColumnSidecar]
  if supernode:
    for sidecar in record.sidecars:
      # Supernode could have some of the columns not filled.
      if not(isNil(sidecar)):
        sidecars.add(sidecar)
    doAssert(len(sidecars) >= (NUMBER_OF_COLUMNS div 2 + 1),
             "Incorrect amount of sidecars in record")
    quarantine.remove(blck.message.slot)
    Opt.some(sidecars)
  else:
    for cindex in quarantine.custodyColumns:
      let index = quarantine.getIndex(cindex)
      doAssert(not(isNil(record.sidecars[index])),
        "Record should not store nil values when record's count is correct")
      sidecars.add(record.sidecars[index])
    quarantine.remove(blck.message.slot)
    Opt.some(sidecars)

func popSidecars*(
    quarantine: var BlobQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock
): Opt[seq[ref BlobSidecar]] =
  ## Alias for `popSidecars()`.
  popSidecars(quarantine, blck.root, blck)

func popSidecars*(
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
    # Fast-path if block do not have any blobs or record holds all the blobs.
    return res

  for bindex in 0 ..< commitmentsCount:
    let index = quarantine.getIndex(BlobIndex(bindex))
    if len(record.sidecars) == 0 or (record.sidecars[index].isNil()):
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
        if (index == -1) or record.sidecars[index].isNil():
          res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
          inc(columnsRequested)
  else:
    let peerMap =
      if len(peerCustodyColumns) > 0:
        ColumnMap.init(peerCustodyColumns)
      else:
        ColumnMap.init(quarantine.custodyColumns)
    if len(record.sidecars) == 0:
      for column in (peerMap and quarantine.custodyMap).asSeq():
        res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
    else:
      for column in (peerMap and quarantine.custodyMap).asSeq():
        let index = quarantine.getIndex(column)
        if (index == -1) or (record.sidecars[index].isNil()):
          res.add(DataColumnIdentifier(block_root: blockRoot, index: column))
  res

template onBlobSidecarCallback*(
    quarantine: BlobQuarantine
): OnBlobSidecarCallback =
  quarantine.onSidecarCallback

template onDataColumnSidecarCallback*(
    quarantine: ColumnQuarantine
): OnDataColumnSidecarCallback =
  quarantine.onSidecarCallback

func init*(
    T: typedesc[BlobQuarantine],
    cfg: RuntimeConfig,
    onBlobSidecarCallback: OnBlobSidecarCallback
): BlobQuarantine =
  # BlobSidecars maps are trivial, but still useful
  var indexMap = newSeqUninit[int](cfg.MAX_BLOBS_PER_BLOCK_ELECTRA)
  for index in 0 ..< len(indexMap):
    indexMap[index] = index

  let size = maxSidecars(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA)
  BlobQuarantine(
    maxSidecarsPerBlockCount: int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA),
    maxSidecarsCount: size,
    sidecarsCount: 0,
    indexMap: indexMap,
    onSidecarCallback: onBlobSidecarCallback
  )

func init*(
    T: typedesc[ColumnQuarantine],
    cfg: RuntimeConfig,
    custodyColumns: openArray[ColumnIndex],
    onBlobSidecarCallback: OnDataColumnSidecarCallback
): ColumnQuarantine =
  doAssert(len(custodyColumns) <= NUMBER_OF_COLUMNS)
  let size = maxSidecars(NUMBER_OF_COLUMNS)
  var indexMap = newSeqUninit[int](NUMBER_OF_COLUMNS)
  if len(custodyColumns) < NUMBER_OF_COLUMNS:
    for i in 0 ..< len(indexMap):
      indexMap[i] = -1
  for index, item in custodyColumns.pairs():
    doAssert(item < uint64(NUMBER_OF_COLUMNS))
    indexMap[int(item)] = index

  ColumnQuarantine(
    maxSidecarsPerBlockCount: len(custodyColumns),
    maxSidecarsCount: size,
    sidecarsCount: 0,
    indexMap: indexMap,
    custodyColumns: @custodyColumns,
    custodyMap: ColumnMap.init(custodyColumns),
    onSidecarCallback: onBlobSidecarCallback
  )

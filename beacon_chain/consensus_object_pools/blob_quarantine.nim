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

from std/sequtils import mapIt, toSeq
from std/strutils import join

export results

static:
  doAssert(NUMBER_OF_COLUMNS == 2 * 64, "ColumnMap should be updated")

type
  ColumnMap* = object
    data: array[2, uint64]

  RootTableRecord[A] = object
    sidecars: seq[ref A]
    count: int

  SidecarQuarantine[A, B] = object
    maxSidecarsCount: int
    maxSidecarsPerBlockCount: int
    sidecarsCount: int
    custodyColumns: seq[ColumnIndex]
    custodyMap: ColumnMap
    roots: Table[Eth2Digest, RootTableRecord[A]]
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

func `and`*(a, b: ColumnMap): ColumnMap =
  ColumnMap(data: [a.data[0] and b.data[0], a.data[1] and b.data[1]])

iterator items*(a: ColumnMap): ColumnIndex =
  var
    data0 = a.data[0]
    data1 = a.data[1]

  while data0 != 0'u64:
    let
      # t = data0 and -data0
      t = data0 and ((0xFFFF_FFFF_FFFF_FFFF'u64 - data0) + 1'u64)
      res = firstOne(data0)
    yield ColumnIndex(res - 1)
    data0 = data0 xor t

  while data1 != 0'u64:
    let
      # t = data0 and -data0
      t = data1 and ((0xFFFF_FFFF_FFFF_FFFF'u64 - data1) + 1'u64)
      res = firstOne(data1)
    yield ColumnIndex(64 + res - 1)
    data1 = data1 xor t

func `$`*(a: ColumnMap): string =
  "[" & a.items().toSeq().mapIt($it).join(", ") & "]"

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

func len*[A, B](quarantine: SidecarQuarantine[A, B]): int =
  quarantine.sidecarsCount

func `$`*[A](r: RootTableRecord[A]): string =
  if len(r.sidecars) == 0:
    return "<empty>"
  r.sidecars.mapIt(if isNil(it): "." else: "x").join("")

func removeRoot[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
) =
  var
    rootRecord: RootTableRecord[A]

  if quarantine.roots.pop(blockRoot, rootRecord):
    for index in 0 ..< len(rootRecord.sidecars):
      if not(rootRecord.sidecars[index].isNil()):
        rootRecord.sidecars[index] = nil
        dec(quarantine.sidecarsCount)

  quarantine.usage.excl(blockRoot)

func remove*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest
) =
  ## Remove all the data columns or blobs related to the block root ``blockRoot`
  ## from the quarantine ``quarantine``.
  ##
  ## Function do nothing, if ``blockRoot` is not part of the quarantine.
  quarantine.removeRoot(blockRoot)

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
  quarantine.indexMap[int(index)]

func getIndex(quarantine: ColumnQuarantine, index: ColumnIndex): int =
  quarantine.indexMap[int(index)]

template slot(b: BlobSidecar|DataColumnSidecar): Slot =
  b.signed_block_header.message.slot

template proposer_index(b: BlobSidecar|DataColumnSidecar): uint64 =
  b.signed_block_header.message.proposer_index

func put[A, B](record: var RootTableRecord[A], q: var SidecarQuarantine[A, B],
               sidecars: openArray[ref A]) =
  for sidecar in sidecars:
    # Sidecar should pass validation before being added to quarantine,
    # so we assume that
    # 1. sidecar.index is < MAX_BLOBS_PER_BLOCK for `deneb` and.
    # 2. sidecar.index is < MAX_BLOBS_PER_BLOCK_ELECTRA for `electra`.
    # 3. sidecar.index is in custody columns set for `fulu`.
    let index = q.getIndex(sidecar.index)
    doAssert(index >= 0, "Incorrect sidecar index [" & $sidecar.index & "]")
    if isNil(record.sidecars[index]):
      inc(q.sidecarsCount)
      inc(record.count)
    record.sidecars[index] = sidecar

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

  let rootRecord = RootTableRecord.init(quarantine)
  quarantine.roots.mgetOrPut(blockRoot, rootRecord).put(
    quarantine, [sidecar])
  quarantine.usage.incl(blockRoot)

func put*[A, B](
    quarantine: var SidecarQuarantine[A, B],
    blockRoot: Eth2Digest,
    sidecars: openArray[ref A]
) =
  ## Function adds number of blobs or data columns sidecars associated to single
  ## block with root ``blockRoot`` to the quarantine ``quarantine``.
  if len(sidecars) == 0:
    return

  while quarantine.sidecarsCount + len(sidecars) >= quarantine.maxSidecarsCount:
    # FIFO if full. For example, sync manager and request manager can race to
    # put blobs in at the same time, so one gets blob insert -> block resolve
    # -> blob insert sequence, which leaves garbage blobs.
    #
    # This also therefore automatically garbage-collects otherwise valid garbage
    # blobs which are correctly signed, point to either correct block roots or a
    # block root which isn't ever seen, and then are for any reason simply never
    # used.
    quarantine.pruneRoot()

  let rootRecord = RootTableRecord.init(quarantine)

  quarantine.roots.mgetOrPut(blockRoot, rootRecord).put(
    quarantine, sidecars)
  quarantine.usage.incl(blockRoot)

template hasSidecarImpl(
    blockRoot: Eth2Digest,
    slot: Slot,
    proposer_index: uint64,
    index: BlobIndex): bool =
  for blob_sidecar in quarantine.blobs.values:
    template block_header: untyped = blob_sidecar.signed_block_header.message
    if block_header.slot == slot and
        block_header.proposer_index == proposer_index and
        blob_sidecar.index == index:
      return true
  false

func popBlobs*(
    quarantine: var BlobQuarantine, digest: Eth2Digest,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock):
    seq[ref BlobSidecar] =
  var r: seq[ref BlobSidecar] = @[]
  when typeof(blck).kind == ConsensusFork.Fulu:
    return r
  else:
    for idx, kzg_commitment in blck.message.body.blob_kzg_commitments:
      var b: ref BlobSidecar
      if quarantine.blobs.pop((digest, BlobIndex idx, kzg_commitment), b):
        r.add(b)
  r

func hasBlobs*(quarantine: BlobQuarantine,
    blck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
          fulu.SignedBeaconBlock): bool =
    # Having a fulu SignedBeaconBlock is incorrect atm, but
    # shall be fixed once data columns are rebased to fulu
  # KZG commitments are no longer included in the beacon block 
  # but rather in the ExecutionPayloadEnvelope
  when typeof(blck).kind == ConsensusFork.Fulu:
    return false # there should be a check against the commitmnets root
  else:
    for idx, kzg_commitment in blck.message.body.blob_kzg_commitments:
      if (blck.root, BlobIndex idx, kzg_commitment) notin quarantine.blobs:
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
          fulu.SignedBeaconBlock): BlobFetchRecord =
  var indices: seq[BlobIndex]
  when typeof(blck).kind == ConsensusFork.Fulu:
    return BlobFetchRecord(block_root: blck.root, indices: indices)  # Empty record
  else:
    for i in 0..<len(blck.message.body.blob_kzg_commitments):
      let idx = BlobIndex(i)
      if not quarantine.blobs.hasKey(
          (blck.root, idx, blck.message.body.blob_kzg_commitments[i])):
        indices.add(idx)
    BlobFetchRecord(block_root: blck.root, indices: indices)

func init*(
    T: type BlobQuarantine, onBlobSidecarCallback: OnBlobSidecarCallback): T =
  T(onBlobSidecarCallback: onBlobSidecarCallback)

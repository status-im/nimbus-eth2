# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[sequtils, strutils],
       results,
       ../spec/[helpers, forks, peerdas_helpers, column_map],
       ../spec/datatypes/[deneb, electra, fulu],
       ../consensus_object_pools/blob_quarantine,
       ./sync_queue

export results

type
  SidecarType = BlobSidecar | fulu.DataColumnSidecar
  SidecarResponseRecord*[T: SidecarType] = object
    block_root*: Eth2Digest
    sidecar*: ref T

  BlobSidecarResponseRecord* =
    SidecarResponseRecord[BlobSidecar]
  DataColumnSidecarResponseRecord* =
    SidecarResponseRecord[fulu.DataColumnSidecar]

func shortLog*[T: SidecarType](
    a: openArray[SidecarResponseRecord[T]]
): string =
  "[" & a.mapIt(shortLog(it.block_root) & "/" & $it.sidecar[].index).join(",") & "]"

func groupSidecars*(
    srange: SyncRange,
    blobs: openArray[ref BlobSidecar]
): Result[seq[BlobSidecarResponseRecord], cstring] =
  # We do not do signature verifications here, just because it will be done
  # later by block_processor. So the only thing we validating is that we
  # received sidecars in proper order and in proper range.
  var
    grouped: seq[BlobSidecarResponseRecord]
    slot = srange.start_slot()

  for sidecar in blobs:
    let
      block_root = hash_tree_root(sidecar[].signed_block_header.message)
      block_slot = sidecar[].signed_block_header.message.slot

    if (block_slot < slot) or (block_slot > srange.last_slot()):
      return err("Invalid blob sidecar slot")

    slot = block_slot

    if len(grouped) != 0:
      if grouped[^1].block_root == block_root:
        if grouped[^1].sidecar[].index >= uint64(sidecar[].index):
          return err("Invalid index order of blob sidecars")

    # TODO (cheatfate): Batch verification could improve performance here.
    sidecar[].verify_blob_sidecar_inclusion_proof().isOkOr:
      return err("BlobSidecar: inclusion proof not valid")

    grouped.add(
      BlobSidecarResponseRecord(block_root: block_root, sidecar: sidecar))

  ok(grouped)

func groupSidecars*(
    srange: SyncRange,
    map: ColumnMap,
    columns: openArray[ref fulu.DataColumnSidecar]
): Result[seq[DataColumnSidecarResponseRecord], cstring] =
  # We do not do signature verifications here, just because it will be done
  # later by block_processor. So the only thing we validating is that we
  # received sidecars in proper order and in proper range.
  var
    grouped: seq[DataColumnSidecarResponseRecord]
    slot = srange.start_slot()

  for sidecar in columns:
    let
      block_root = hash_tree_root(sidecar[].signed_block_header.message)
      block_slot = sidecar[].signed_block_header.message.slot

    if block_slot < slot or block_slot > srange.last_slot():
      return err("Invalid data column sidecar slot")
    if sidecar[].index notin map:
      return err("Invalid data column index")

    slot = block_slot
    if len(grouped) != 0:
      if grouped[^1].block_root == block_root:
        if uint64(grouped[^1].sidecar[].index) >= uint64(sidecar[].index):
          return err("Invalid order of data column sidecars")

    # TODO (cheatfate): Batch verification could improve performance here.
    ? verify_data_column_sidecar_inclusion_proof(sidecar[])

    grouped.add(
      DataColumnSidecarResponseRecord(block_root: block_root, sidecar: sidecar))

  ok(grouped)

func groupSidecars*(
    idents: openArray[BlobIdentifier],
    blobs: openArray[ref BlobSidecar]
): Result[seq[BlobSidecarResponseRecord], cstring] =
  # Cannot respond more than what I have asked
  if len(blobs) > len(idents):
    return err("Number of blobs received is greater than number of requested")

  var
    checks = idents.toHashSet()
    grouped: seq[BlobSidecarResponseRecord]

  for sidecar in blobs:
    let
      block_root = hash_tree_root(sidecar[].signed_block_header.message)
      sidecarIdent =
        BlobIdentifier(block_root: block_root, index: sidecar[].index)

    if checks.missingOrExcl(sidecarIdent):
      return err("Received blobs outside the request")

    # TODO (cheatfate): Batch verification could improve performance here.
    sidecar[].verify_blob_sidecar_inclusion_proof().isOkOr:
      return err("BlobSidecar: inclusion proof not valid")

    grouped.add(
      BlobSidecarResponseRecord(block_root: block_root, sidecar: sidecar))

  ok(grouped)

func groupSidecars*(
    idents: openArray[DataColumnsByRootIdentifier],
    columnsRequested: int,
    columns: openArray[ref fulu.DataColumnSidecar]
): Result[seq[DataColumnSidecarResponseRecord], cstring] =
  if len(columns) > columnsRequested:
    return err(
      "Number of data columns received is greater than number of requested")

  var
    checks =
      block:
        var res: HashSet[DataColumnIdentifier]
        for rident in idents:
          for rindex in rident.indices:
            res.incl(
              DataColumnIdentifier(
                block_root: rident.block_root, index: rindex))
        res
    grouped: seq[DataColumnSidecarResponseRecord]

  for sidecar in columns:
    let
      block_root = hash_tree_root(sidecar[].signed_block_header.message)
      sidecarIdent =
        DataColumnIdentifier(block_root: block_root, index: sidecar[].index)

    if checks.missingOrExcl(sidecarIdent):
      return err("Received data column outside the request")

    # TODO (cheatfate): Batch verification could improve performance here.
    ? verify_data_column_sidecar_inclusion_proof(sidecar[])

    grouped.add(
      DataColumnSidecarResponseRecord(block_root: block_root, sidecar: sidecar))

  ok(grouped)

func validateBlocks*(
    blocks: openArray[ref ForkedSignedBeaconBlock],
    sidecars: openArray[BlobSidecarResponseRecord]
): Result[int, cstring] =
  var sindex = 0
  for blck in blocks:
    withBlck(blck[]):
      when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
        let blobsCount = len(forkyBlck.message.body.blob_kzg_commitments)
        if blobsCount == 0:
          continue
        if (sindex >= len(sidecars)) or (sindex + blobsCount > len(sidecars)):
          return err("Not enough blob sidecars")
        for index in 0 ..< blobsCount:
          let record = sidecars[sindex + index]
          if record.block_root != forkyBlck.root:
            return err("Some blob sidecars missing for block")
          if record.sidecar[].index != BlobIndex(index):
            return err("Some blob sidecars sent in wrong order for block")
        sindex += blobsCount
      else:
        return err("Found block with incorrect fork")

  ok(sindex)

func validateBlocks*(
    blocks: openArray[ref ForkedSignedBeaconBlock],
    sidecars: openArray[DataColumnSidecarResponseRecord],
    map: ColumnMap
): Result[int, cstring] =
  let mapCount = len(map)
  var sindex = 0
  for blck in blocks:
    withBlck(blck[]):
      when consensusFork == ConsensusFork.Fulu:
        let columnsCount = len(forkyBlck.message.body.blob_kzg_commitments)
        if columnsCount == 0:
          continue
        if (sindex >= len(sidecars)) or (sindex + mapCount > len(sidecars)):
          return err("Not enough data column sidecars")
        for index in 0 ..< mapCount:
          let record = sidecars[sindex + index]
          if record.block_root != forkyBlck.root:
            return err("Some data column sidecars missing for block")
        sindex += mapCount
      else:
        return err("Found block with incorrect fork")

  ok(sindex)

func checkResponse*(
    srange: SyncRange,
    blocks: openArray[ref ForkedSignedBeaconBlock]
): Result[void, cstring] =
  ## This procedure checks peer's getBlockByRange() response.
  if len(blocks) == 0:
    return ok()

  if lenu64(blocks) > srange.count:
    return err("Number of received blocks greater than number of requested")

  var
    slot = FAR_FUTURE_SLOT
    root: Eth2Digest

  for blk in blocks:
    let block_slot = blk[].slot()
    if block_slot notin srange:
      return err("Some of the blocks are outside the requested range")
    if slot != FAR_FUTURE_SLOT:
      if slot >= block_slot:
        return err("Incorrect order or duplicate blocks found")
      if blk[].parent_root() != root:
        return err("Incorrect order or chain of blocks, invalid parent_root")
    root = blk[].root()
    slot = blk[].slot()
  ok()

func checkResponse*(
    roots: openArray[Eth2Digest],
    blocks: openArray[ref ForkedSignedBeaconBlock]
): Result[void, cstring] =
  ## This procedure checks peer's getBlocksByRoot() response.
  var checks = @roots
  if len(blocks) == 0:
    return ok()
  if len(blocks) > len(roots):
    return err("Number of received blocks greater than number of requested")
  for blk in blocks:
    let res = checks.find(blk[].root)
    if res == -1:
      return err("Unexpected block root encountered")
    checks.del(res)
  ok()

func getShortMap*[T](
    request: SyncRequest[T],
    blobs: openArray[BlobSidecarResponseRecord]
): string =
  let sidecars = blobs.mapIt(it.sidecar)
  getShortMap(request, sidecars)

when isMainModule:
  type
    BlobsDataItem = tuple[slot: int, index: int]

    TestData = object
      blocks: seq[ref ForkedSignedBeaconBlock]
      blobs: seq[BlobSidecarResponseRecord]

  const
    BlocksData = [
      #1253024,
      1253025, 1253026, 1253027, 1253028, 1253029,
      #1253030,
      1253031, 1253032, 1253033, 1253034, 1253035,
      #1253036,
      1253037, 1253038, 1253039, 1253040, 1253041,
      #1253042, 1253043,
      1253044, 1253045, 1253046,
      #1253047,
      1253048, 1253049, 1253050, 1253051, 1253052, 1253053, 1253054,
      #1253055
    ]

    BlobsData = [
      (slot: 1253025, index: 0), (slot: 1253025, index: 1), (slot: 1253025, index: 2), (slot: 1253025, index: 3),
      (slot: 1253026, index: 0),(slot: 1253026, index: 1),
      (slot: 1253027, index: 0),(slot: 1253027, index: 1),(slot: 1253027, index: 2),
      (slot: 1253028, index: 0),(slot: 1253028, index: 1),(slot: 1253028, index: 2),(slot: 1253028, index: 3),
      (slot: 1253029, index: 0),(slot: 1253029, index: 1),(slot: 1253029, index: 2),(slot: 1253029, index: 3),
      (slot: 1253031, index: 0),(slot: 1253031, index: 1),(slot: 1253031, index: 2),
      (slot: 1253032, index: 0),(slot: 1253032, index: 1),(slot: 1253032, index: 2),
      (slot: 1253033, index: 0),(slot: 1253033, index: 1),(slot: 1253033, index: 2),(slot: 1253033, index: 3),
      (slot: 1253035, index: 0),(slot: 1253035, index: 1),(slot: 1253035, index: 2),(slot: 1253035, index: 3),
      (slot: 1253037, index: 0),(slot: 1253037, index: 1),(slot: 1253037, index: 2),(slot: 1253037, index: 3),
      (slot: 1253038, index: 0),(slot: 1253038, index: 1),(slot: 1253038, index: 2),(slot: 1253038, index: 3),(slot: 1253038, index: 4),
      (slot: 1253039, index: 0),
      (slot: 1253040, index: 0),(slot: 1253040, index: 1),(slot: 1253040, index: 2),(slot: 1253040, index: 3),
      (slot: 1253041, index: 0),(slot: 1253041, index: 1),(slot: 1253041, index: 2),(slot: 1253041, index: 3),(slot: 1253041, index: 4),
      (slot: 1253044, index: 0),(slot: 1253044, index: 1),(slot: 1253044, index: 2),(slot: 1253044, index: 3),
      (slot: 1253045, index: 0),(slot: 1253045, index: 1),(slot: 1253045, index: 2),
      (slot: 1253046, index: 0),(slot: 1253046, index: 1),(slot: 1253046, index: 2),(slot: 1253046, index: 3),
      (slot: 1253048, index: 0),(slot: 1253048, index: 1),(slot: 1253048, index: 2),
      (slot: 1253049, index: 0),(slot: 1253049, index: 1),(slot: 1253049, index: 2),
      (slot: 1253050, index: 0),(slot: 1253050, index: 1),(slot: 1253050, index: 2),
      (slot: 1253051, index: 0),(slot: 1253051, index: 1),(slot: 1253051, index: 2),(slot: 1253051, index: 3),
      (slot: 1253052, index: 0),(slot: 1253052, index: 1),(slot: 1253052, index: 2),
      (slot: 1253053, index: 0),(slot: 1253053, index: 1),
      (slot: 1253054, index: 0),(slot: 1253054, index: 1),(slot: 1253054, index: 2),(slot: 1253054, index: 3)
    ]

  func createBlobSidecar(
      data: tuple[slot: int, index: int]
  ): ref BlobSidecar =
    newClone BlobSidecar(
      index: BlobIndex(data.index),
      signed_block_header: SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(data.slot))))

  func createRoot(root: int): Eth2Digest =
    var res = Eth2Digest()
    res.data[0] = byte(root and 0xFF)
    res

  func createBlockWithBlobs(root, slot, count: int): ref ForkedSignedBeaconBlock =
    newClone ForkedSignedBeaconBlock.init(deneb.SignedBeaconBlock(
      message: deneb.BeaconBlock(
        slot: Slot(slot),
        body: deneb.BeaconBlockBody(
          blob_kzg_commitments: List[KzgCommitment, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK](newSeq[KzgCommitment](count))
        )
      ),
      root: createRoot(root)))

  func createBlockWithoutBlobs(root, slot: int): ref ForkedSignedBeaconBlock =
    newClone ForkedSignedBeaconBlock.init(deneb.SignedBeaconBlock(
      message: deneb.BeaconBlock(slot: Slot(slot)),
      root: createRoot(root)))

  func find*(b: openArray[BlobsDataItem], a: int): int =
    for index, item in b.pairs():
      if item.slot == a:
        return index
    -1

  func getBlobRecords*(
      b: openArray[BlobsDataItem],
      r, a: int
  ): seq[BlobSidecarResponseRecord] =
    var res: seq[BlobSidecarResponseRecord]
    let slot = b[a].slot
    for index in a ..< len(b):
      if b[index].slot != slot:
        break
      res.add(BlobSidecarResponseRecord(
        block_root: createRoot(r),
        sidecar: createBlobSidecar((slot, b[index].index))))
    res

  func createTestData(
      blockSlots: openArray[int],
      blobsData: openArray[BlobsDataItem]
  ): TestData =
    var res: TestData
    for index, slot in blockSlots.pairs():
      let index = blobsData.find(slot)
      if index == -1:
        res.blocks.add(
          createBlockWithoutBlobs(index, slot))
      else:
        let records = blobsData.getBlobRecords(index, index)
        res.blocks.add(
          createBlockWithBlobs(index, slot, len(records)))
        res.blobs.add(records)
    res

  let data = createTestData(BlocksData, BlobsData)

  echo validateBlocks(data.blocks, data.blobs)

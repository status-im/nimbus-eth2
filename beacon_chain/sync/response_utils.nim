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
       ../consensus_object_pools/column_quarantine,
       ./sync_queue

export results, sync_queue

type
  SidecarType = fulu.DataColumnSidecar
  SidecarResponseRecord*[T: SidecarType] = object
    block_root*: Eth2Digest
    sidecar*: ref T

  DataColumnSidecarResponseRecord* =
    SidecarResponseRecord[fulu.DataColumnSidecar]

func shortLog*[T: SidecarType](
    a: openArray[SidecarResponseRecord[T]]
): string =
  "[" & a.mapIt(shortLog(it.block_root) & "/" & $it.sidecar[].index).join(",") & "]"

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

    if (block_slot < slot) or (block_slot > srange.last_slot()):
      return err("Invalid data column sidecar slot")
    if sidecar[].index notin map:
      return err("Invalid data column index")

    slot = block_slot
    if len(grouped) != 0:
      if grouped[^1].block_root == block_root:
        if uint64(grouped[^1].sidecar[].index) >= uint64(sidecar[].index):
          return err("Invalid order or duplicate data column sidecars found")

    # TODO (cheatfate): Batch verification could improve performance here.
    ? verify_data_column_sidecar_inclusion_proof(sidecar[])

    grouped.add(
      DataColumnSidecarResponseRecord(block_root: block_root, sidecar: sidecar))

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
    items: openArray[SyncResponseItem],
    sidecars: openArray[DataColumnSidecarResponseRecord],
    map: ColumnMap
): Result[tuple[sidecars: int, blocks: int], cstring] =
  var
    sindex = 0
    bcount = 0
  for item in items:
    withBlck(item.signedBlock[]):
      when consensusFork == ConsensusFork.Fulu:
        let columnsCount = len(forkyBlck.message.body.blob_kzg_commitments)
        if columnsCount == 0:
          continue
        inc(bcount)
        while sindex < len(sidecars):
          let record = sidecars[sindex]
          if record.block_root != forkyBlck.root:
            break
          inc(sindex)
      else:
        return err("Found block with incorrect fork")

  ok((sindex, bcount))

func checkResponse*(
    srange: SyncRange,
    items: openArray[SyncResponseItem]
): Result[void, cstring] =
  ## This procedure checks peer's getBlockByRange() response.
  if len(items) == 0:
    return ok()

  if lenu64(items) > srange.count:
    return err("Number of received blocks greater than number of requested")

  var
    slot = FAR_FUTURE_SLOT
    root: Eth2Digest

  for ritem in items:
    let block_slot = ritem.slot
    if block_slot notin srange:
      return err("Some of the blocks are outside the requested range")
    if slot != FAR_FUTURE_SLOT:
      if slot >= block_slot:
        return err("Incorrect order or duplicate blocks found")
      if ritem.parent_root() != root:
        return err("Incorrect order or chain of blocks, invalid parent_root")
    root = ritem.root
    slot = ritem.slot
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

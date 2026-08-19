# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[sequtils, strutils],
       results,
       ../spec/[helpers, forks, peerdas_helpers, column_map],
       ../spec/datatypes/[deneb, electra, fulu, gloas],
       ../consensus_object_pools/column_quarantine,
       ./[sync_range, sync_response]

export results, sync_range, sync_response

type
  SidecarType = fulu.DataColumnSidecar | gloas.DataColumnSidecar
  SidecarResponseRecord*[T: SidecarType] = object
    block_root*: Eth2Digest
    sidecar*: ref T

  EnvelopeHid* = object
    root*: Eth2Digest
    parent_root*: Eth2Digest
    slot*: Slot

  BlockHid* = object
    root*: Eth2Digest
    parent_root*: Eth2Digest
    slot*: Slot

  FuluColumnSidecarResponseRecord* =
    SidecarResponseRecord[fulu.DataColumnSidecar]
  GloasColumnSidecarResponseRecord* =
    SidecarResponseRecord[gloas.DataColumnSidecar]

  MissingErrorKind* {.pure.} = enum
    Blocks, Sidecars, Envelopes

func `$`*(m: MissingErrorKind): string =
  case m
  of MissingErrorKind.Blocks:
    "Some of the blocks are missing"
  of MissingErrorKind.Sidecars:
    "Some of the sidecars are missing"
  of MissingErrorKind.Envelopes:
    "Some of the envelopes are missing"

func toEnvelopeHid*(
  envelope: gloas.SignedExecutionPayloadEnvelope
): EnvelopeHid =
  EnvelopeHid(
    root: envelope.message.beacon_block_root,
    parent_root: envelope.message.parent_beacon_block_root,
    slot: envelope.message.payload.slot_number)

func toBlockHid*(
  blck: ForkedSignedBeaconBlock
): BlockHid =
  withBlck(blck):
    BlockHid(
      root: forkyBlck.root,
      parent_root: forkyBlck.message.parent_root,
      slot: forkyBlck.message.slot)

func shortLog*[T: SidecarType](
    a: openArray[SidecarResponseRecord[T]]
): string =
  "[" & a.mapIt(shortLog(it.block_root) & "/" &
     $it.sidecar[].index).join(",") & "]"

func shortLog*(eid: EnvelopeHid): string =
  $eid.slot & "@" & shortLog(eid.root) & ">" & shortLog(eid.parent_root)

func shortLog*(bid: BlockHid): string =
  $bid.slot & "@" & shortLog(bid.root) & ">" & shortLog(bid.parent_root)

func groupSidecars*(
    srange: SyncRange,
    map: ColumnMap,
    columns: openArray[ref fulu.DataColumnSidecar]
): Result[seq[FuluColumnSidecarResponseRecord], cstring] =
  # We do not do signature verifications here, just because it will be done
  # later by block_processor. So the only thing we validating is that we
  # received sidecars in proper order and in proper range.
  var
    grouped: seq[FuluColumnSidecarResponseRecord]
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
      FuluColumnSidecarResponseRecord(
        block_root: block_root, sidecar: sidecar))

  ok(grouped)

func groupSidecars*(
    srange: SyncRange,
    map: ColumnMap,
    columns: openArray[ref gloas.DataColumnSidecar]
): Result[seq[GloasColumnSidecarResponseRecord], cstring] =
  # We do not do signature verifications here, just because it will be done
  # later by block_processor. So the only thing we validating is that we
  # received sidecars in proper order and in proper range.
  var
    grouped: seq[GloasColumnSidecarResponseRecord]
    slot = srange.start_slot()

  for sidecar in columns:
    let
      block_root = sidecar[].beacon_block_root
      block_slot = sidecar[].slot

    if (block_slot < slot) or (block_slot > srange.last_slot()):
      return err("Invalid data column sidecar slot")
    if sidecar[].index notin map:
      return err("Invalid data column index")

    slot = block_slot
    if len(grouped) != 0:
      if grouped[^1].block_root == block_root:
        if uint64(grouped[^1].sidecar[].index) >= uint64(sidecar[].index):
          return err("Invalid order or duplicate data column sidecars found")

    grouped.add(
      GloasColumnSidecarResponseRecord(
        block_root: block_root, sidecar: sidecar))

  ok(grouped)

func groupSidecars*(
    idents: openArray[DataColumnsByRootIdentifier],
    columnsRequested: int,
    columns: openArray[ref fulu.DataColumnSidecar]
): Result[seq[FuluColumnSidecarResponseRecord], cstring] =
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
    grouped: seq[FuluColumnSidecarResponseRecord]

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
      FuluColumnSidecarResponseRecord(
        block_root: block_root, sidecar: sidecar))

  ok(grouped)

func groupSidecars*(
    idents: openArray[DataColumnsByRootIdentifier],
    columnsRequested: int,
    columns: openArray[ref gloas.DataColumnSidecar]
): Result[seq[GloasColumnSidecarResponseRecord], cstring] =
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
    grouped: seq[GloasColumnSidecarResponseRecord]

  for sidecar in columns:
    let
      block_root = sidecar[].beacon_block_root
      sidecarIdent =
        DataColumnIdentifier(block_root: block_root, index: sidecar[].index)

    if checks.missingOrExcl(sidecarIdent):
      return err("Received data column outside the request")

    grouped.add(
      GloasColumnSidecarResponseRecord(
        block_root: block_root, sidecar: sidecar))

  ok(grouped)

func validateBlocks*(
    srange: SyncRange,
    items: openArray[SyncResponseItem],
    sidecars: openArray[FuluColumnSidecarResponseRecord],
): Result[void, MissingErrorKind] =
  var
    bindex = 0
    sindex = 0

  template slot(record: FuluColumnSidecarResponseRecord): Slot =
    record.sidecar[].signed_block_header.message.slot

  for slot in srange:
    let
      blck =
        if bindex < len(items):
          if items[bindex].signedBlock[].slot() == slot:
            Opt.some(items[bindex].signedBlock)
          else:
            Opt.none(ref ForkedSignedBeaconBlock)
        else:
          Opt.none(ref ForkedSignedBeaconBlock)
      sidecarsCount =
        block:
          var res = 0
          if sindex < len(sidecars):
            if sidecars[sindex].slot() == slot:
              while sindex < len(sidecars):
                let record = sidecars[sindex]
                if record.slot() != slot:
                  break
                inc(res)
                inc(sindex)
          res

    if blck.isNone():
      if sidecarsCount > 0:
        return err(MissingErrorKind.Blocks)
    else:
      withBlck(blck.get()[]):
        when consensusFork == ConsensusFork.Fulu:
          let commitmentsLen = len(forkyBlck.message.body.blob_kzg_commitments)
          if (commitmentsLen > 0) and (sidecarsCount == 0):
            return err(MissingErrorKind.Sidecars)
        else:
          raiseAssert("checkResponse() already checked the fork!")
      inc(bindex)
  ok()

func validateBlocks*(
    srange: SyncRange,
    items: openArray[SyncResponseItem],
    sidecars: openArray[GloasColumnSidecarResponseRecord]
): Result[void, MissingErrorKind] =
  var
    bindex = 0
    sindex = 0

  template slot(record: GloasColumnSidecarResponseRecord): Slot =
    record.sidecar[].slot

  template slot(e: SignedExecutionPayloadEnvelope): Slot =
    e.message.payload.slot_number

  for slot in srange:
    let
      blck =
        if bindex < len(items):
          if items[bindex].signedBlock[].slot() == slot:
            Opt.some(items[bindex].signedBlock)
          else:
            Opt.none(ref ForkedSignedBeaconBlock)
        else:
          Opt.none(ref ForkedSignedBeaconBlock)
      envelope =
        if bindex < len(items):
          if isNil(items[bindex].signedEnvelope):
            Opt.none(ref SignedExecutionPayloadEnvelope)
          else:
            if items[bindex].signedEnvelope[].slot() == slot:
              Opt.some(items[bindex].signedEnvelope)
            else:
              Opt.none(ref SignedExecutionPayloadEnvelope)
        else:
          Opt.none(ref SignedExecutionPayloadEnvelope)
      sidecarsCount =
        block:
          var res = 0
          if sindex < len(sidecars):
            if sidecars[sindex].slot() == slot:
              while sindex < len(sidecars):
                let record = sidecars[sindex]
                if record.slot() != slot:
                  break
                inc(res)
                inc(sindex)
          res

    if blck.isNone():
      if (sidecarsCount > 0) or (envelope.isSome()):
        return err(MissingErrorKind.Blocks)
    else:
      if (sidecarsCount > 0) and envelope.isNone():
        return err(MissingErrorKind.Envelopes)

      if (sidecarsCount == 0) and envelope.isSome():
        return err(MissingErrorKind.Sidecars)

      inc(bindex)
  ok()

func checkResponse*(
    srange: SyncRange,
    consensusFork: ConsensusFork,
    items: openArray[ref ForkedSignedBeaconBlock]
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
    if ritem.kind != consensusFork:
      return err("Some of the blocks from incorrect fork")
    let bid = ritem[].toBlockHid()
    if bid.slot notin srange:
      return err("Some of the blocks are outside the requested range")
    if slot != FAR_FUTURE_SLOT:
      if slot >= bid.slot:
        return err("Incorrect order or duplicate blocks found")
      if bid.parent_root != root:
        return err("Incorrect order or chain of blocks, invalid parent_root")
    root = bid.root
    slot = bid.slot
  ok()

func checkResponse*(
    srange: SyncRange,
    items: openArray[ref gloas.SignedExecutionPayloadEnvelope]
): Result[void, cstring] =
  ## This procedure checks peer's getEnvelopeByRange() response.
  if len(items) == 0:
    return ok()

  if lenu64(items) > srange.count:
    return err("Number of received envelopes greater than number of requested")

  var slot = FAR_FUTURE_SLOT

  for ritem in items:
    let eid = ritem[].toEnvelopeHid()
    if eid.slot notin srange:
      return err("Some of the envelopes are outside the requested range")
    if slot != FAR_FUTURE_SLOT:
      if slot >= eid.slot:
        return err("Incorrect order or duplicate envelopes found")
    slot = eid.slot
  ok()

func checkResponse*(
    roots: openArray[Eth2Digest],
    blocks: openArray[ref ForkedSignedBeaconBlock]
): Result[void, cstring] =
  ## This procedure checks peer's getBlocksByRoot() response.
  if len(blocks) == 0:
    return ok()
  if len(blocks) > len(roots):
    return err("Number of received blocks greater than number of requested")
  var checks = roots.toHashSet()
  for blk in blocks:
    if blk[].root notin checks:
      return err("Unexpected block root encountered")
    checks.excl(blk[].root)
  ok()

func checkResponse*(
    roots: openArray[Eth2Digest],
    envelopes: openArray[ref SignedExecutionPayloadEnvelope]
): Result[void, cstring] =
  ## This procedure checks peer's getEnvelopesByRoot() response.
  if len(envelopes) == 0:
    return ok()
  if len(envelopes) > len(roots):
    return err("Number of received envelopes greater than number of requested")
  var checks = roots.toHashSet()
  for envelope in envelopes:
    if envelope.message.beacon_block_root notin checks:
      return err("Unexpected beacon block root encountered")
    checks.excl(envelope.message.beacon_block_root)
  ok()

func combineResponse*(
    srange: SyncRange,
    blocks: openArray[ref ForkedSignedBeaconBlock],
    envelopes: openArray[ref SignedExecutionPayloadEnvelope]
): Result[seq[SyncResponseItem], string] =
  ## Important: This procedure assume that the block and envelope lists passed
  ## corresponding `checkResponse()` call. It means that list is ordered by
  ## slot number and does not contain duplicate items.
  if (len(blocks) == 0) and (len(envelopes) == 0):
    return ok(
      default(seq[GloasSyncResponseRecord[ref ForkedSignedBeaconBlock]]))

  var
    res: seq[SyncResponseItem]
    bindex = 0
    eindex = 0
    parentBlock: Opt[ref ForkedSignedBeaconBlock]

  for slot in srange:
    var check = SyncResponseItem()
    if bindex >= len(blocks):
      check.signedBlock = nil
    else:
      let bid = blocks[bindex][].toBlockHid()
      if blocks[bindex][].kind != ConsensusFork.Gloas:
        return err("Received block from incorrect fork")
      if bid.slot < slot:
        return err("The range of received blocks is not ordered correctly")
      if bid.slot > slot:
        check.signedBlock = nil
      else:
        check.signedBlock = blocks[bindex]
        inc(bindex)

    if eindex >= len(envelopes):
      check.signedEnvelope = nil
    else:
      let eid = envelopes[eindex][].toEnvelopeHid()
      if eid.slot < slot:
        return err("The range of received envelopes is not ordered correctly")
      if eid.slot > slot:
        check.signedEnvelope = nil
      else:
        check.signedEnvelope = envelopes[eindex]
        inc(eindex)

    if isNil(check.signedBlock):
      if not(isNil(check.signedEnvelope)):
        return err("Some blocks are missing in range")
    else:
      let bid = check.signedBlock[].toBlockHid()
      if isNil(check.signedEnvelope):
        # At this case we could not know if envelope is present or not.
        parentBlock = Opt.some(check.signedBlock)
        res.add(check)
      else:
        let eid = check.signedEnvelope[].toEnvelopeHid()
        if bid.root != eid.root:
          return err(
            "The root of the block and the root of the envelope do not match")
        if parentBlock.isSome():
          let pid = parentBlock.get()[].toBlockHid()
          if eid.parent_root != pid.root:
            return err(
              "The parent root of the envelope and the root of the parent " &
              "envelope do not match")
        parentBlock = Opt.some(check.signedBlock)
        res.add(check)

  ok(res)

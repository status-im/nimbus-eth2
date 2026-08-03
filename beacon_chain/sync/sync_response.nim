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
       ../spec/datatypes/[fulu, gloas]

type
  ForkedSignedBeaconBlocks =
    ForkedSignedBeaconBlock | ref ForkedSignedBeaconBlock

  GloasSyncResponseRecord*[T: ForkedSignedBeaconBlocks] = object
    signedBlock*: T
    signedEnvelope*: ref SignedExecutionPayloadEnvelope

  SyncResponseItem* = GloasSyncResponseRecord[ref ForkedSignedBeaconBlock]

func slot*[T: ForkedSignedBeaconBlocks](
    r: GloasSyncResponseRecord[T]
): Slot {.inline.} =
  when T is ForkedSignedBeaconBlock:
    r.signedBlock.slot
  else:
    r.signedBlock[].slot

func root*[T: ForkedSignedBeaconBlocks](
    r: GloasSyncResponseRecord[T]
): Eth2Digest {.inline.} =
  when T is ForkedSignedBeaconBlock:
    r.signedBlock.root
  else:
    r.signedBlock[].root

func parent_root*[T: ForkedSignedBeaconBlocks](
    r: GloasSyncResponseRecord[T]
): Eth2Digest {.inline.} =
  when T is ForkedSignedBeaconBlock:
    r.signedBlock.parent_root
  else:
    r.signedBlock[].parent_root

func toBlockId*[T: ForkedSignedBeaconBlocks](
    r: GloasSyncResponseRecord[T]
): BlockId {.inline.} =
  when T is ForkedSignedBeaconBlock:
    r.signedBlock.toBlockId()
  else:
    r.signedBlock[].toBlockId()

func privLog(a: ref SignedExecutionPayloadEnvelope): string =
  if isNil(a): "(0)" else: "(X)"

func shortLog*[T: ForkedSignedBeaconBlocks](
    a: openArray[GloasSyncResponseRecord[T]]
): string =
  when T is ForkedSignedBeaconBlock:
    "[" & a.mapIt(
      shortLog(it.signedBlock.toBlockId()) & ":" &
        privLog(it.signedEnvelope)).join(",") &
    "]"
  else:
    "[" & a.mapIt(
      shortLog(it.signedBlock[].toBlockId()) & ":" &
        privLog(it.signedEnvelope)).join(",") &
    "]"

func init*(
    t: typedesc[GloasSyncResponseRecord],
    blck: ref ForkedSignedBeaconBlock,
    payload: ref SignedExecutionPayloadEnvelope
): GloasSyncResponseRecord[ref ForkedSignedBeaconBlock] =
  GloasSyncResponseRecord[ref ForkedSignedBeaconBlock](
    signedBlock: blck,
    signedEnvelope: payload
  )

func init*(
    t: typedesc[GloasSyncResponseRecord],
    blck: ForkedSignedBeaconBlock,
    payload: ref SignedExecutionPayloadEnvelope
): GloasSyncResponseRecord[ForkedSignedBeaconBlock] =
  GloasSyncResponseRecord[ForkedSignedBeaconBlock](
    signedBlock: blck,
    signedEnvelope: payload
  )

func init*(
    t: typedesc[SyncResponseItem],
    blck: ref ForkedSignedBeaconBlock,
    payload: ref SignedExecutionPayloadEnvelope
): SyncResponseItem =
  GloasSyncResponseRecord.init(blck, payload)

func init*(
    t: typedesc[GloasSyncResponseRecord],
    blck: ref ForkedSignedBeaconBlock,
): SyncResponseItem =
  GloasSyncResponseRecord.init(blck, nil)

func `==`*(a, b: SyncResponseItem): bool =
  (cast[pointer](a.signedBlock) == cast[pointer](b.signedBlock)) and
    (cast[pointer](a.signedEnvelope) == cast[pointer](b.signedEnvelope))

func toResponse*(
    a: openArray[ref ForkedSignedBeaconBlock]
): seq[SyncResponseItem] =
  a.mapIt(GloasSyncResponseRecord.init(it, nil))

func toResponse*(
    blocks: openArray[ForkedSignedBeaconBlock],
    envelopes: openArray[ref SignedExecutionPayloadEnvelope]
): seq[GloasSyncResponseRecord[ForkedSignedBeaconBlock]] =
  var res: seq[GloasSyncResponseRecord[ForkedSignedBeaconBlock]]
  let envelopesTable =
    envelopes.mapIt((it[].message.beacon_block_root, it)).toTable()
  for signedBlock in blocks:
    let envelope = envelopesTable.getOrDefault(signedBlock.root)
    res.add(GloasSyncResponseRecord.init(signedBlock, envelope))
  res

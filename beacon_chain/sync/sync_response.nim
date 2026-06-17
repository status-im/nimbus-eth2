# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ../spec/[helpers, forks]

from std/sequtils import mapIt
from std/strutils import join

type
  SyncResponseItem* = object
    signedBlock*: ref ForkedSignedBeaconBlock
    signedPayloadEnvelope*: ref SignedExecutionPayloadEnvelope

func slot*(r: SyncResponseItem): Slot {.inline.} =
  r.signedBlock[].slot

func root*(r: SyncResponseItem): Eth2Digest {.inline.} =
  r.signedBlock[].root

func parent_root*(r: SyncResponseItem): Eth2Digest {.inline.} =
  r.signedBlock[].parent_root

func toBlockId*(r: SyncResponseItem): BlockId {.inline.} =
  r.signedBlock[].toBlockId()

func init*(
    t: typedesc[SyncResponseItem],
    blck: ref ForkedSignedBeaconBlock,
    payload: ref SignedExecutionPayloadEnvelope
): SyncResponseItem =
  SyncResponseItem(signedBlock: blck, signedPayloadEnvelope: payload)

func toResponse*(
    a: openArray[ref ForkedSignedBeaconBlock]
): seq[SyncResponseItem] =
  a.mapIt(SyncResponseItem.init(it, nil))

func toResponse*(
    items: var seq[SyncResponseItem],
    envelopes: openArray[ref SignedExecutionPayloadEnvelope]
): int =
  var count = 0
  for envelope in envelopes:
    for item in items.mitems():
      if item.signedBlock[].root == envelope[].message.beacon_block_root:
        item.signedPayloadEnvelope = envelope
        inc(count)
  count

func `==`*(a, b: SyncResponseItem): bool =
  (cast[pointer](a.signedBlock) == cast[pointer](b.signedBlock)) and
    (cast[pointer](a.signedPayloadEnvelope) ==
      cast[pointer](b.signedPayloadEnvelope))

func shortLog*(items: openArray[SyncResponseItem]): string =
  "[" &
    items.mapIt("(slot:" & $it.slot & ",root:" & shortLog(it.root) &
      ",parent_root:" & shortLog(it.parent_root) & ")").join(",") &
  "]"

# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/tables
import ../spec/[digest, forks]

type
  EnvelopeQuarantine* = object
    orphans*: Table[Eth2Digest, Table[uint64, SignedExecutionPayloadEnvelope]]
      ## Envelopes that we have received but did not have a block yet. In the
      ## ideal scenario, block should arrive before envelope but that is not
      ## guaranteed.

    missing*: HashSet[Eth2Digest]
      ## List of block roots that we would like to have the envelopes but we
      ## have not got yet. Missing envelopes should usually be found when we
      ## received a block, blob or data column.

func init*(T: typedesc[EnvelopeQuarantine]): T =
  T()

template root(v: SignedExecutionPayloadEnvelope): Eth2Digest =
  v.message.beacon_block_root

func addMissing*(
    self: var EnvelopeQuarantine,
    root: Eth2Digest) =
  self.missing.incl(root)

func addOrphan*(
    self: var EnvelopeQuarantine,
    envelope: SignedExecutionPayloadEnvelope) =
  discard self.orphans
    .mgetOrPut(envelope.root)
    .hasKeyOrPut(envelope.message.builder_index, envelope)

func popOrphan*(
    self: var EnvelopeQuarantine,
    blck: gloas.SignedBeaconBlock,
): Opt[SignedExecutionPayloadEnvelope] =
  if blck.root notin self.orphans:
    return Opt.none(SignedExecutionPayloadEnvelope)

  template builderIdx(): auto =
    blck.message.body.signed_execution_payload_bid.message.builder_index
  try:
    var envelope: SignedExecutionPayloadEnvelope
    if self.orphans[blck.root].pop(builderIdx, envelope):
      Opt.some(envelope)
    else:
      Opt.none(SignedExecutionPayloadEnvelope)
  except KeyError:
    Opt.none(SignedExecutionPayloadEnvelope)

func delOrphan*(self: var EnvelopeQuarantine, blck: gloas.SignedBeaconBlock) =
  self.orphans.del(blck.root)

func cleanupOrphans*(self: var EnvelopeQuarantine, finalizedSlot: Slot) =
  var toDel: seq[Eth2Digest]

  for k, v in self.orphans:
    for _, e in v:
      if finalizedSlot >= e.message.slot:
        toDel.add(k)
      # check only the first envelope as slot should be the same by block root.
      break

  for k in toDel:
    self.orphans.del(k)

# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/tables
import ../spec/[digest, forks]

type
  EnvelopeQuarantine* = object
    orphans*: Table[Eth2Digest, SignedExecutionPayloadEnvelope]
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
    envelope: SignedExecutionPayloadEnvelope) =
  self.missing.incl(envelope.root)

func addOrphan*(
    self: var EnvelopeQuarantine,
    envelope: SignedExecutionPayloadEnvelope) =
  self.orphans[envelope.root] = envelope

func removeOrphan*(self: var EnvelopeQuarantine, root: Eth2Digest) =
  self.orphans.del(root)

func cleanupOrphans*(self: var EnvelopeQuarantine, finalizedSlot: Slot) =
  var toDel: seq[Eth2Digest]

  for k, v in self.orphans:
    if finalizedSlot >= v.message.slot:
      toDel.add(k)

  for k in toDel:
    self.orphans.del(k)

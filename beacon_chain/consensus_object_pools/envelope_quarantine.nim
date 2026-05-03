# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  minilru,
  ../spec/[digest, forks]

const
  MaxRetriesPerMissingItem = 7
    ## Exponential backoff, double interval between each attempt
  MaxMissingItems* = 1024
    ## Revisit the setting and same as block quarantine for now
  MaxUnviables = 16 * 1024
    ## Set to same as max unviable blocks.

type
  UnviableLru = LruCache[Eth2Digest, ()]

  MissingEnvelope* = object
    tries*: int

  EnvelopeQuarantine* = object
    orphans*: Table[Eth2Digest, Table[uint64, SignedExecutionPayloadEnvelope]]
      ## Envelopes that we have received but did not have a block yet. In the
      ## ideal scenario, block should arrive before envelope but that is not
      ## guaranteed.

    missing*: Table[Eth2Digest, MissingEnvelope]
      ## List of block roots that we would like to have the envelopes but we
      ## have not got yet. Missing envelopes should usually be found when we
      ## received a block, blob or data column.

    unviable*: UnviableLru
      ## List of block roots that their envelopes are unviable.

func init*(T: typedesc[EnvelopeQuarantine]): T =
  T(
    unviable: UnviableLru.init(MaxUnviables),
  )

template root(v: SignedExecutionPayloadEnvelope): Eth2Digest =
  v.message.beacon_block_root

func addMissing*(
    self: var EnvelopeQuarantine,
    root: Eth2Digest) =
  if self.missing.len() >= MaxMissingItems:
    return
  discard self.missing.hasKeyOrPut(root, MissingEnvelope())

func checkMissing*(self: var EnvelopeQuarantine, max: int): seq[Eth2Digest] =
  # Remove items that have reached max retries
  var done: seq[Eth2Digest]
  for k, v in self.missing.mpairs():
    if v.tries > static(1 shl MaxRetriesPerMissingItem):
      done.add(k)
  for k in done:
    self.missing.del(k)

  # Get items
  for k, v in self.missing.mpairs():
    v.tries += 1
    if countOnes(v.tries.uint64) == 1:
      result.add(k)
      if result.len >= max:
        break

func addOrphan*(
    self: var EnvelopeQuarantine,
    envelope: SignedExecutionPayloadEnvelope) =
  discard self.orphans
    .mgetOrPut(envelope.root)
    .hasKeyOrPut(envelope.message.builder_index, envelope)

func popOrphan*(
    self: var EnvelopeQuarantine,
    blck: gloas.SignedBeaconBlock | heze.SignedBeaconBlock,
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

func remove*(self: var EnvelopeQuarantine, root: Eth2Digest) =
  self.orphans.del(root)
  self.missing.del(root)

func addUnviable*(self: var EnvelopeQuarantine, root: Eth2Digest) =
  self.remove(root)
  self.unviable.put(root, ())

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

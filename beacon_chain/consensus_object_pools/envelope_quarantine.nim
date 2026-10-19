# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  minilru, chronos,
  ./quarantine_types,
  ../spec/[digest, forks]

export tables, minilru, forks, quarantine_types

from std/sequtils import countIt, toSeq, mapIt
from std/strutils import join

const
  MaxOrphans = int(SLOTS_PER_EPOCH * 3)
    ## Set to same as max block orphans
  MaxUnviables = 16 * 1024
    ## Set to same as max unviable blocks
  MaxUntrustedEnvelopes = 8
    ## Limit space and cpu usage on signature verification

type
  OrphanCacheKey = (Eth2Digest, uint64, ValidatorSig)
  OrphanRecord = object
    envelope: SignedExecutionPayloadEnvelope
    trusted: bool
      ## It is set to true when there is source from gossip validated, by root
      ## and by range requests. When it is true, the queue from not-validated
      ## gossip source will be ignored.

  OrphanLru = LruCache[OrphanCacheKey, OrphanRecord]
  UnviableLru = LruCache[Eth2Digest, ()]

  EnvelopeQuarantine* = object
    orphans*: OrphanLru
      ## Envelopes that we have received but did not have a block yet. In the
      ## ideal scenario, block should arrive before envelope but that is not
      ## guaranteed. Indexed by `(beacon_block_root, builder_index)` as the
      ## canonical builder is unknown until the block arrives.

    missing*: MissingTable
      ## List of block roots that we would like to have the envelopes but we
      ## have not got yet. Missing envelopes should usually be found when we
      ## received a block, blob or data column.

    unviable*: UnviableLru
      ## List of block roots whose canonical envelopes are unviable.

    missingEvent*: AsyncEvent
      ## This asynchronous event is triggered when a new orphaned block is added
      ## to the quarantine.

template toOrphanCacheKey(
    envelope: SignedExecutionPayloadEnvelope): OrphanCacheKey =
  (
    envelope.message.beacon_block_root,
    envelope.message.builder_index, envelope.signature,
  )

proc init*(T: typedesc[EnvelopeQuarantine]): T =
  let missingEvent = newAsyncEvent()
  T(
    orphans: OrphanLru.init(MaxOrphans),
    unviable: UnviableLru.init(MaxUnviables),
    missing: MissingTable.init(missingEvent),
    missingEvent: missingEvent
  )

proc addMissing*(self: var EnvelopeQuarantine, root: Eth2Digest) =
  self.missing.add(root)
  self.missingEvent.fire()

proc checkMissing*(self: var EnvelopeQuarantine, max: int): seq[FetchRecord] =
  self.missing.checkMissing(max)

func cleanupOrphans(self: var EnvelopeQuarantine, finalizedSlot: Slot) =
  var toDel: seq[OrphanCacheKey]

  for k, v in self.orphans:
    if v.envelope.message.slot <= finalizedSlot:
      toDel.add k

  for k in toDel:
    self.orphans.del k

iterator peekOrphans(
    self: EnvelopeQuarantine, root: Eth2Digest,
    builderIdx: uint64): (lent OrphanCacheKey, lent OrphanRecord) =
  for k, v in self.orphans:
    if k[0] == root and k[1] == builderIdx:
      yield (k, v)

func delOrphan(
    self: var EnvelopeQuarantine, root: Eth2Digest, builderIdx: uint64) =
  var toDel: seq[OrphanCacheKey]

  for k, _ in self.peekOrphans(root, builderIdx):
    toDel.add(k)

  for k in toDel:
    self.orphans.del(k)

func hasTrustedOrphan(
    self: EnvelopeQuarantine, root: Eth2Digest, builderIdx: uint64): bool =
  for _, v in self.peekOrphans(root, builderIdx):
    return v.trusted
  false

func addOrphan(
    self: var EnvelopeQuarantine,
    envelope: SignedExecutionPayloadEnvelope,
    trusted: bool) =
  let cacheKey = envelope.toOrphanCacheKey()

  if self.hasTrustedOrphan(cacheKey[0], cacheKey[1]):
    # Overwrite the trusted orphan with the new one.
    if trusted:
      self.delOrphan(cacheKey[0], cacheKey[1])
    # ignore untrusted source when there is trusted source.
    else:
      return
  else:
    # remove untrusted envelopes when a trsuted source comes in.
    if trusted:
      self.delOrphan(cacheKey[0], cacheKey[1])
    # ignore if we already have one with the same signature.
    else:
      if cacheKey in self.orphans:
        return

    if countIt(self.peekOrphans(cacheKey[0], cacheKey[1]), true) >=
        MaxUntrustedEnvelopes:
      return

  self.orphans.put(cacheKey, OrphanRecord(envelope: envelope, trusted: trusted))

func addOrphan*(
    self: var EnvelopeQuarantine,
    finalizedSlot: Slot,
    envelope: SignedExecutionPayloadEnvelope) =
  self.cleanupOrphans(finalizedSlot)
  self.addOrphan(envelope, true)

func addUntrustedOrphan*(
    self: var EnvelopeQuarantine,
    finalizedSlot: Slot,
    envelope: SignedExecutionPayloadEnvelope) =
  self.cleanupOrphans(finalizedSlot)
  self.addOrphan(envelope, false)

func popOrphan*(
    self: var EnvelopeQuarantine,
    blck: gloas.SignedBeaconBlock | heze.SignedBeaconBlock,
): Opt[SignedExecutionPayloadEnvelope] =
  ## Pop orphaned envelope from trusted source
  let builderIdx =
    blck.message.body.signed_execution_payload_bid.message.builder_index

  for k, v in self.peekOrphans(blck.root, builderIdx):
    if v.trusted:
      self.orphans.pop(k).isErrOr:
        return Opt.some(value().envelope)
    break
  Opt.none(SignedExecutionPayloadEnvelope)

func popUntrustedOrphans*(
    self: var EnvelopeQuarantine,
    blck: gloas.SignedBeaconBlock | heze.SignedBeaconBlock,
): seq[SignedExecutionPayloadEnvelope] =
  ## Pop orphaned envelope from untrusted source
  let builderIdx =
    blck.message.body.signed_execution_payload_bid.message.builder_index

  var
    res: seq[SignedExecutionPayloadEnvelope]
    toDel: seq[OrphanCacheKey]

  for k, v in self.peekOrphans(blck.root, builderIdx):
    if v.trusted:
      return default(seq[SignedExecutionPayloadEnvelope])
    toDel.add(k)
    res.add(v.envelope)

  for k in toDel:
    self.orphans.del(k)

  res

func hasOrphan*(self: EnvelopeQuarantine, root: Eth2Digest): bool =
  for k, _ in self.orphans:
    if k[0] == root:
      return true
  false

func hasOrphan*(
    self: EnvelopeQuarantine,
    envelope: SignedExecutionPayloadEnvelope): bool =
  envelope.toOrphanCacheKey() in self.orphans

proc remove*(self: var EnvelopeQuarantine, root: Eth2Digest) =
  var toDel: seq[OrphanCacheKey]
  for k, _ in self.orphans:
    if k[0] == root:
      toDel.add k
  for k in toDel:
    self.orphans.del k
  self.missing.del(root)

proc addUnviable*(self: var EnvelopeQuarantine, root: Eth2Digest) =
  self.remove(root)
  self.unviable.put(root, ())

func jsonLog*(envelope: gloas.SignedExecutionPayloadEnvelope): string =
  $envelope.message.payload.slot_number & "@" &
    shortLog(envelope.message.beacon_block_root) & ">" &
    shortLog(envelope.message.parent_beacon_block_root)

func debugMissingJsonDump*(q: EnvelopeQuarantine): string =
  let res =
    q.missing.items.keys().toSeq().mapIt("\"" & shortLog(it) & "\"").join(",")
  "{\"count\":" & $len(q.missing.items) & ",\"items\":[" & res & "]}"

func debugUnviablesJsonDump*(q: EnvelopeQuarantine): string =
  let res =
    q.unviable.keys().toSeq().mapIt("\"" & shortLog(it) & "\"").join(",")
  "{\"count\":" & $len(q.unviable) & ",\"items\":[" & res & "]}"

func debugOrphansJsonDump*(q: EnvelopeQuarantine): string =
  var
    res: seq[string]
    minBlockSlot = FAR_FUTURE_SLOT
    maxBlockSlot = GENESIS_SLOT

  for value in q.orphans.values():
    let slot = value.envelope.message.payload.slot_number
    if slot < minBlockSlot:
      minBlockSlot = slot
    if slot > maxBlockSlot:
      maxBlockSlot = slot
    res.add("\"" & jsonLog(value.envelope) & "\"")

  let
    sminBlockSlot = if len(q.orphans) == 0: "not available" else: $minBlockSlot
    smaxBlockSlot = if len(q.orphans) == 0: "not available" else: $maxBlockSlot

  "{\"count\":" & $len(q.orphans) &
    ",\"max_orphans_items\":" & $MaxOrphans &
    ",\"min_block_slot\":\"" & sminBlockSlot & "\"" &
    ",\"max_block_slot\":\"" & smaxBlockSlot & "\"" &
    ",\"items\":[" & res.join(",") & "]}"

func debugJsonDump*(q: EnvelopeQuarantine): string =
  "{\"orphans\":" & q.debugOrphansJsonDump() &
    ",\"missing\":" & q.debugMissingJsonDump() &
    ",\"unviable\":" & q.debugUnviablesJsonDump() & "}"

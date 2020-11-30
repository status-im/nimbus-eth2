# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[deques, sequtils, sets, tables, options],
  # Status libraries
  chronicles, stew/[byteutils], json_serialization/std/sets as jsonSets,
  # Internal
  ./spec/[beaconstate, datatypes, crypto, digest, helpers],
  ssz/merkleization,
  ./block_pools/[spec_cache, chain_dag, clearance, quarantine],
  ./beacon_node_types,
  ./fork_choice/fork_choice

export beacon_node_types, sets

logScope: topics = "attpool"

proc init*(T: type AttestationPool, chainDag: ChainDAGRef, quarantine: QuarantineRef): T =
  ## Initialize an AttestationPool from the chainDag `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  let finalizedEpochRef = chainDag.getFinalizedEpochRef()

  var forkChoice = ForkChoice.init(
    finalizedEpochRef,
    chainDag.finalizedHead.blck)

  # Feed fork choice with unfinalized history - during startup, block pool only
  # keeps track of a single history so we just need to follow it
  doAssert chainDag.heads.len == 1, "Init only supports a single history"

  var blocks: seq[BlockRef]
  var cur = chainDag.head

  # When the chain is finalizing, the votes between the head block and the
  # finalized checkpoint should be enough for a stable fork choice - when the
  # chain is not finalizing, we want to seed it with as many votes as possible
  # since the whole history of each branch might be significant. It is however
  # a game of diminishing returns, and we have to weigh it against the time
  # it takes to replay that many blocks during startup and thus miss _new_
  # votes.
  const ForkChoiceHorizon = 256
  while cur != chainDag.finalizedHead.blck:
    blocks.add cur
    cur = cur.parent

  info "Initializing fork choice", unfinalized_blocks = blocks.len

  var epochRef = finalizedEpochRef
  for i in 0..<blocks.len:
    let
      blck = blocks[blocks.len - i - 1]
      status =
        if i < (blocks.len - ForkChoiceHorizon) and (i mod 1024 != 0):
          # Fork choice needs to know about the full block tree up to the
          # finalization point, but doesn't really need to have overly accurate
          # justification and finalization points until we get close to head -
          # nonetheless, we'll make sure to pass a fresh finalization point now
          # and then to make sure the fork choice data structure doesn't grow
          # too big - getting an EpochRef can be expensive.
          forkChoice.backend.process_block(
            blck.root, blck.parent.root,
            epochRef.current_justified_checkpoint.epoch,
            epochRef.finalized_checkpoint.epoch)
        else:
          epochRef = chainDag.getEpochRef(blck, blck.slot.epoch)
          forkChoice.process_block(
            chainDag, epochRef, blck, chainDag.get(blck).data.message, blck.slot)

    doAssert status.isOk(), "Error in preloading the fork choice: " & $status.error

  info "Fork choice initialized",
    justified_epoch = chainDag.headState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = chainDag.headState.data.data.finalized_checkpoint.epoch,
    finalized_root = shortlog(chainDag.finalizedHead.blck.root)

  T(
    chainDag: chainDag,
    quarantine: quarantine,
    forkChoice: forkChoice
  )

proc addForkChoiceVotes(
    pool: var AttestationPool, slot: Slot, participants: HashSet[ValidatorIndex],
    block_root: Eth2Digest, wallSlot: Slot) =
  # Add attestation votes to fork choice
  if (let v = pool.forkChoice.on_attestation(
    pool.chainDag, slot, block_root, participants, wallSlot);
    v.isErr):
      # This indicates that the fork choice and the chain dag are out of sync -
      # this is most likely the result of a bug, but we'll try to keep going -
      # hopefully the fork choice will heal itself over time.
      error "Couldn't add attestation to fork choice, bug?", err = v.error()

func candidateIdx(pool: AttestationPool, slot: Slot): Option[uint64] =
  if slot >= pool.startingSlot and
      slot < (pool.startingSlot + pool.candidates.lenu64):
    some(slot mod pool.candidates.lenu64)
  else:
    none(uint64)

proc updateCurrent(pool: var AttestationPool, wallSlot: Slot) =
  if wallSlot + 1 < pool.candidates.lenu64:
    return

  if pool.startingSlot + pool.candidates.lenu64 - 1 > wallSlot:
    error "Current slot older than attestation pool view, clock reset?",
      poolSlot = pool.startingSlot, wallSlot
    return

  # As time passes we'll clear out any old attestations as they are no longer
  # viable to be included in blocks

  let newWallSlot = wallSlot + 1 - pool.candidates.lenu64
  for i in pool.startingSlot..newWallSlot:
    pool.candidates[i.uint64 mod pool.candidates.lenu64] = AttestationsSeen()

  pool.startingSlot = newWallSlot

  # now also clear old aggregated attestations
  var keysToRemove: seq[Slot] = @[]
  for k, v in pool.attestationAggregates.pairs:
    if k < pool.startingSlot:
      keysToRemove.add k
  for k in keysToRemove:
    pool.attestationAggregates.del k

proc addToAggregates(pool: var AttestationPool, attestation: Attestation) =
  # do a lookup for the current slot and get it's associated htrs/attestations
  var aggreated_attestation = pool.attestationAggregates.mgetOrPut(
    attestation.data.slot, Table[Eth2Digest, Attestation]()).
    # do a lookup for the same attestation data htr and get the attestation
    mgetOrPut(attestation.data.hash_tree_root, attestation)
  # if the aggregation bits differ (we didn't just insert it into the table)
  # and only if there is no overlap of the signatures ==> aggregate!
  if not aggreated_attestation.aggregation_bits.overlaps(attestation.aggregation_bits):
    var agg {.noInit.}: AggregateSignature
    agg.init(aggreated_attestation.signature)
    aggreated_attestation.aggregation_bits.combine(attestation.aggregation_bits)
    agg.aggregate(attestation.signature)
    aggreated_attestation.signature = agg.finish()

proc addAttestation*(pool: var AttestationPool,
                     attestation: Attestation,
                     participants: HashSet[ValidatorIndex],
                     wallSlot: Slot) =
  ## Add an attestation to the pool, assuming it's been validated already.
  ## Attestations may be either agggregated or not - we're pursuing an eager
  ## strategy where we'll drop validations we already knew about and combine
  ## the new attestation with an existing one if possible.
  ##
  ## This strategy is not optimal in the sense that it would be possible to find
  ## a better packing of attestations by delaying the aggregation, but because
  ## it's possible to include more than one aggregate in a block we can be
  ## somewhat lazy instead of looking for a perfect packing.
  logScope:
    attestation = shortLog(attestation)

  updateCurrent(pool, wallSlot)

  let candidateIdx = pool.candidateIdx(attestation.data.slot)
  if candidateIdx.isNone:
    debug "Skipping old attestation for block production",
      startingSlot = pool.startingSlot
    return

  pool.addToAggregates(attestation)

  let
    attestationsSeen = addr pool.candidates[candidateIdx.get]
    validation = Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: attestation.signature)

  var found = false
  for a in attestationsSeen.attestations.mitems():
    if a.data == attestation.data:
      for v in a.validations:
        if validation.aggregation_bits.isSubsetOf(v.aggregation_bits):
          # The validations in the new attestation are a subset of one of the
          # attestations that we already have on file - no need to add this
          # attestation to the database
          trace "Ignoring subset attestation", newParticipants = participants
          found = true
          break

      if not found:
        # Attestations in the pool that are a subset of the new attestation
        # can now be removed per same logic as above

        trace "Removing subset attestations", newParticipants = participants

        a.validations.keepItIf(
          not it.aggregation_bits.isSubsetOf(validation.aggregation_bits))

        a.validations.add(validation)
        pool.addForkChoiceVotes(
          attestation.data.slot, participants, attestation.data.beacon_block_root,
          wallSlot)

        debug "Attestation resolved",
          attestation = shortLog(attestation),
          validations = a.validations.len()

        found = true

      break

  if not found:
    attestationsSeen.attestations.add(AttestationEntry(
      data: attestation.data,
      validations: @[validation]
    ))
    pool.addForkChoiceVotes(
      attestation.data.slot, participants, attestation.data.beacon_block_root,
      wallSlot)

    debug "Attestation resolved",
      attestation = shortLog(attestation),
      validations = 1

proc addForkChoice*(pool: var AttestationPool,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    blck: BeaconBlock,
                    wallSlot: Slot) =
  ## Add a verified block to the fork choice context
  let state = pool.forkChoice.process_block(
    pool.chainDag, epochRef, blckRef, blck, wallSlot)

  if state.isErr:
    # This indicates that the fork choice and the chain dag are out of sync -
    # this is most likely the result of a bug, but we'll try to keep going -
    # hopefully the fork choice will heal itself over time.
    error "Couldn't add block to fork choice, bug?",
      blck = shortLog(blck), err = state.error

proc getAttestationsForSlot*(pool: AttestationPool, newBlockSlot: Slot):
    Option[AttestationsSeen] =
  if newBlockSlot < (GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY):
    debug "Too early for attestations", newBlockSlot = shortLog(newBlockSlot)
    return none(AttestationsSeen)

  let
    attestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY
    candidateIdx = pool.candidateIdx(attestationSlot)

  if candidateIdx.isNone:
    trace "No attestations matching the slot range",
      attestationSlot = shortLog(attestationSlot),
      startingSlot = shortLog(pool.startingSlot)
    return none(AttestationsSeen)

  some(pool.candidates[candidateIdx.get()])

iterator attestations*(pool: AttestationPool, slot: Option[Slot],
                       index: Option[CommitteeIndex]): Attestation =
  for seenAttestations in pool.candidates.items():
    for entry in seenAttestations.attestations.items():
      let slotInclude =
        if slot.isSome():
          entry.data.slot == slot.get()
        else:
          true
      let committeeInclude =
        if index.isSome():
          CommitteeIndex(entry.data.index) == index.get()
        else:
          true
      if slotInclude or committeeInclude:
        for validation in entry.validations.items():
          yield Attestation(
            aggregation_bits: validation.aggregation_bits,
            data: entry.data,
            signature: validation.aggregate_signature
          )

proc getAttestationsForBlock*(pool: AttestationPool,
                              state: BeaconState,
                              cache: var StateCache): seq[Attestation] =
  ## Retrieve attestations that may be added to a new block at the slot of the
  ## given state
  let newBlockSlot = state.slot
  var attestations: seq[AttestationEntry]

  # This potentially creates problems with lots of repeated attestations,
  # as a bunch of synchronized beacon_nodes do almost the opposite of the
  # intended thing -- sure, _blocks_ have to be popular (via attestation)
  # but _attestations_ shouldn't have to be so frequently repeated, as an
  # artifact of this state-free, identical-across-clones choice basis. In
  # addAttestation, too, the new attestations get added to the end, while in
  # these functions, it's reading from the beginning, et cetera. This all
  # needs a single unified strategy.
  for i in max(1, newBlockSlot.int64 - ATTESTATION_LOOKBACK.int64) .. newBlockSlot.int64:
    let maybeSlotData = getAttestationsForSlot(pool, i.Slot)
    if maybeSlotData.isSome:
      insert(attestations, maybeSlotData.get.attestations)

  if attestations.len == 0:
    return

  for a in attestations:
    var
      # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#construct-attestation
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        signature: a.validations[0].aggregate_signature
      )

      agg {.noInit.}: AggregateSignature
    agg.init(a.validations[0].aggregate_signature)

    # Signature verification here is more of a sanity check - it could
    # be optimized away, though for now it's easier to reuse the logic from
    # the state transition function to ensure that the new block will not
    # fail application.
    if (let v = check_attestation(state, attestation, {}, cache); v.isErr):
      warn "Attestation no longer validates...",
        attestation = shortLog(attestation),
        err = v.error

      continue

    for i in 1..a.validations.high:
      if not attestation.aggregation_bits.overlaps(
          a.validations[i].aggregation_bits):
        attestation.aggregation_bits.combine(a.validations[i].aggregation_bits)
        agg.aggregate(a.validations[i].aggregate_signature)

    attestation.signature = agg.finish()
    result.add(attestation)

    if result.lenu64 >= MAX_ATTESTATIONS:
      debug "getAttestationsForBlock: returning early after hitting MAX_ATTESTATIONS",
        attestationSlot = newBlockSlot - 1
      return

proc getAggregatedAttestation*(pool: AttestationPool,
                               slot: Slot,
                               ad_htr: Eth2Digest): Option[Attestation] =
  try:
    if pool.attestationAggregates.contains(slot) and
        pool.attestationAggregates[slot].contains(ad_htr):
      return some pool.attestationAggregates[slot][ad_htr]
  except KeyError:
    doAssert(false) # shouldn't be possible because we check with `contains`
  return none(Attestation)

proc getAggregatedAttestation*(pool: AttestationPool,
                               slot: Slot,
                               index: CommitteeIndex): Option[Attestation] =
  let attestations = pool.getAttestationsForSlot(
    slot + MIN_ATTESTATION_INCLUSION_DELAY)
  if attestations.isNone:
    return none(Attestation)

  for a in attestations.get.attestations:
    doAssert a.data.slot == slot
    if index.uint64 != a.data.index:
      continue

    var
      # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#construct-attestation
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        signature: a.validations[0].aggregate_signature
      )

      agg {.noInit.}: AggregateSignature

    agg.init(a.validations[0].aggregate_signature)
    for v in a.validations[1..^1]:
      if not attestation.aggregation_bits.overlaps(v.aggregation_bits):
        attestation.aggregation_bits.combine(v.aggregation_bits)
        agg.aggregate(v.aggregate_signature)

      attestation.signature = agg.finish()

    return some(attestation)

  none(Attestation)

proc selectHead*(pool: var AttestationPool, wallSlot: Slot): BlockRef =
  ## Trigger fork choice and returns the new head block.
  ## Can return `nil`
  let newHead = pool.forkChoice.get_head(pool.chainDag, wallSlot)

  if newHead.isErr:
    error "Couldn't select head", err = newHead.error
    nil
  else:
    let ret = pool.chainDag.getRef(newHead.get())
    if ret.isNil:
      # This should normally not happen, but if the chain dag and fork choice
      # get out of sync, we'll need to try to download the selected head - in
      # the meantime, return nil to indicate that no new head was chosen
      warn "Fork choice selected unknown head, trying to sync", root = newHead.get()
      pool.quarantine.addMissing(newHead.get())

    ret

proc prune*(pool: var AttestationPool) =
  if (let v = pool.forkChoice.prune(); v.isErr):
    # If pruning fails, it's likely the result of a bug - this shouldn't happen
    # but we'll keep running hoping that the fork chocie will recover eventually
    error "Couldn't prune fork choice, bug?", err = v.error()

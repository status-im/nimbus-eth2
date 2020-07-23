# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[algorithm, deques, sequtils, tables, options],
  # Status libraries
  chronicles, stew/[byteutils], json_serialization/std/sets,
  # Internal
  ./spec/[beaconstate, datatypes, crypto, digest, helpers],
  ./extras, ./block_pool, ./block_pools/candidate_chains, ./beacon_node_types,
  ./fork_choice/fork_choice

logScope: topics = "attpool"

proc init*(T: type AttestationPool, blockPool: BlockPool): T =
  ## Initialize an AttestationPool from the blockPool `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  # TODO blockPool is only used when resolving orphaned attestations - it should
  #      probably be removed as a dependency of AttestationPool (or some other
  #      smart refactoring)

  blockPool.withState(blockPool.tmpState, blockPool.finalizedHead):
    var forkChoice = initForkChoice(
      blockPool.tmpState,
    ).get()

  # Feed fork choice with unfinalized history
  var blocks: seq[BlockRef]
  var cur = blockPool.head.blck
  while cur != blockPool.finalizedHead.blck:
    blocks.add cur
    cur = cur.parent

  for blck in reversed(blocks):
    blockPool.withState(blockPool.tmpState, blck.atSlot(blck.slot)):
      debug "Preloading fork choice with block",
        block_root = shortlog(blck.root),
        parent_root = shortlog(blck.parent.root),
        justified_epoch = state.current_justified_checkpoint.epoch,
        finalized_epoch = state.finalized_checkpoint.epoch,
        slot = blck.slot

      let status =
        forkChoice.process_block(
          blockPool, state, blck, blockPool.get(blck).data.message, blck.slot)

      doAssert status.isOk(), "Error in preloading the fork choice: " & $status.error

  info "Fork choice initialized",
    justified_epoch = blockPool.headState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = blockPool.headState.data.data.finalized_checkpoint.epoch,
    finalized_root = shortlog(blockPool.finalizedHead.blck.root)

  T(
    mapSlotsToAttestations: initDeque[AttestationsSeen](),
    blockPool: blockPool,
    unresolved: initTable[Eth2Digest, UnresolvedAttestation](),
    forkChoice: forkChoice
  )

proc combine*(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  ## Combine the signature and participation bitfield, with the assumption that
  ## the same data is being signed - if the signatures overlap, they are not
  ## combined.
  # TODO: Exported only for testing, all usage are internals

  doAssert tgt.data == src.data

  # In a BLS aggregate signature, one needs to count how many times a
  # particular public key has been added - since we use a single bit per key, we
  # can only it once, thus we can never combine signatures that overlap already!
  if not tgt.aggregation_bits.overlaps(src.aggregation_bits):
    tgt.aggregation_bits.combine(src.aggregation_bits)

    if skipBlsValidation notin flags:
      tgt.signature.aggregate(src.signature)
  else:
    trace "Ignoring overlapping attestations"

proc slotIndex(
    pool: var AttestationPool, state: BeaconState, attestationSlot: Slot): int =
  ## Grow and garbage collect pool, returning the deque index of the slot

  # We keep a sliding window of attestations, roughly from the last finalized
  # epoch to now, because these are the attestations that may affect the voting
  # outcome. Some of these attestations will already have been added to blocks,
  # while others are fresh off the network.
  # TODO only the latest vote of each validator counts. Can we use that somehow?
  logScope: pcs = "atp_slot_maintenance"

  doAssert attestationSlot >= pool.startingSlot,
    """
    We should have checked in addResolved that attestation is newer than
    finalized_slot and we never prune things before that, per below condition!
    """ &
    ", attestationSlot: " & $shortLog(attestationSlot) &
    ", startingSlot: " & $shortLog(pool.startingSlot)

  if pool.mapSlotsToAttestations.len == 0:
    # Because the first attestations may arrive in any order, we'll make sure
    # to start counting at the last finalized epoch start slot - anything
    # earlier than that is thrown out by the above check
    info "First attestation!",
      attestationSlot =  shortLog(attestationSlot)
    pool.startingSlot =
      state.finalized_checkpoint.epoch.compute_start_slot_at_epoch()

  if pool.startingSlot + pool.mapSlotsToAttestations.len.uint64 <= attestationSlot:
    trace "Growing attestation pool",
      attestationSlot =  shortLog(attestationSlot),
      startingSlot = shortLog(pool.startingSlot)

    # Make sure there's a pool entry for every slot, even when there's a gap
    while pool.startingSlot + pool.mapSlotsToAttestations.len.uint64 <= attestationSlot:
      pool.mapSlotsToAttestations.addLast(AttestationsSeen())

  if pool.startingSlot <
      state.finalized_checkpoint.epoch.compute_start_slot_at_epoch():
    debug "Pruning attestation pool",
      startingSlot = shortLog(pool.startingSlot),
      finalizedSlot = shortLog(
        state.finalized_checkpoint
             .epoch.compute_start_slot_at_epoch())

    # TODO there should be a better way to remove a whole epoch of stuff..
    while pool.startingSlot <
        state.finalized_checkpoint.epoch.compute_start_slot_at_epoch():
      pool.mapSlotsToAttestations.popFirst()
      pool.startingSlot += 1

  int(attestationSlot - pool.startingSlot)

func processAttestation(
    pool: var AttestationPool, state: BeaconState,
    participants: seq[ValidatorIndex], block_root: Eth2Digest, target_epoch: Epoch) =
  for validator in participants:
    # ForkChoice v2
    pool.forkChoice.process_attestation(validator, block_root, target_epoch)

func addUnresolved(pool: var AttestationPool, attestation: Attestation) =
  pool.unresolved[attestation.data.beacon_block_root] =
    UnresolvedAttestation(
      attestation: attestation,
    )

proc addResolved(pool: var AttestationPool, blck: BlockRef, attestation: Attestation) =
  doAssert blck.root == attestation.data.beacon_block_root

  # TODO Which state should we use to validate the attestation? It seems
  #      reasonable to involve the head being voted for as well as the intended
  #      slot of the attestation - double-check this with spec

  # TODO: filter valid attestation as much as possible before state rewind
  # TODO: the below check does not respect the inclusion delay
  #       we should use isValidAttestationSlot instead
  if blck.slot > attestation.data.slot:
    notice "Invalid attestation (too new!)",
      attestation = shortLog(attestation),
      blockSlot = shortLog(blck.slot)
    return

  if attestation.data.slot < pool.startingSlot:
    # It can happen that attestations in blocks for example are included even
    # though they no longer are relevant for finalization - let's clear
    # these out
    debug "Old attestation",
      attestation = shortLog(attestation),
      startingSlot = pool.startingSlot
    return

  # if not isValidAttestationSlot(attestation.data.slot, blck.slot):
  #   # Logging in isValidAttestationSlot
  #   return

  # Check that the attestation is indeed valid
  # TODO: we might want to split checks that depend
  #       on the state and those that don't to cheaply
  #       discard invalid attestations before rewinding state.
  if not isValidAttestationTargetEpoch(
      attestation.data.target.epoch, attestation.data):
    notice "Invalid attestation",
      attestation = shortLog(attestation),
      current_epoch = attestation.data.slot.compute_epoch_at_slot
    return

  # Get a temporary state at the (block, slot) targeted by the attestation
  updateStateData(
    pool.blockPool, pool.blockPool.tmpState,
    BlockSlot(blck: blck, slot: attestation.data.slot),
    true)

  template state(): BeaconState = pool.blockPool.tmpState.data.data

  # TODO inefficient data structures..

  var cache = getEpochCache(blck, state)
  let
    attestationSlot = attestation.data.slot
    idx = pool.slotIndex(state, attestationSlot)
    attestationsSeen = addr pool.mapSlotsToAttestations[idx]
    validation = Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: attestation.signature)
    participants = toSeq(items(get_attesting_indices(
      state, attestation.data, validation.aggregation_bits, cache)))

  var found = false
  for a in attestationsSeen.attestations.mitems():
    if a.data == attestation.data:
      for v in a.validations:
        if validation.aggregation_bits.isSubsetOf(v.aggregation_bits):
          # The validations in the new attestation are a subset of one of the
          # attestations that we already have on file - no need to add this
          # attestation to the database
          # TODO what if the new attestation is useful for creating bigger
          #      sets by virtue of not overlapping with some other attestation
          #      and therefore being useful after all?
          trace "Ignoring subset attestation",
            newParticipants = participants
          found = true
          break

      if not found:
        # Attestations in the pool that are a subset of the new attestation
        # can now be removed per same logic as above

        trace "Removing subset attestations",
          newParticipants = participants

        a.validations.keepItIf(
          not it.aggregation_bits.isSubsetOf(validation.aggregation_bits))

        a.validations.add(validation)
        pool.processAttestation(
          state, participants, a.blck.root, attestation.data.target.epoch)

        info "Attestation resolved",
          attestation = shortLog(attestation),
          validations = a.validations.len(),
          current_epoch = get_current_epoch(state),
          blockSlot = shortLog(blck.slot)

        found = true

      break

  if not found:
    attestationsSeen.attestations.add(AttestationEntry(
      data: attestation.data,
      blck: blck,
      validations: @[validation]
    ))
    pool.processAttestation(
      state, participants, blck.root, attestation.data.target.epoch)

    info "Attestation resolved",
      attestation = shortLog(attestation),
      current_epoch = get_current_epoch(state),
      validations = 1,
      blockSlot = shortLog(blck.slot)

proc addAttestation*(pool: var AttestationPool, attestation: Attestation) =
  ## Add a verified attestation to the fork choice context
  logScope: pcs = "atp_add_attestation"

  # Fetch the target block or notify the block pool that it's needed
  let blck = pool.blockPool.getOrResolve(attestation.data.beacon_block_root)

  # If the block exist, add it to the fork choice context
  # Otherwise delay until it resolves
  if blck.isNil:
    pool.addUnresolved(attestation)
    return

  pool.addResolved(blck, attestation)

proc addForkChoice*(pool: var AttestationPool,
                    state: BeaconState,
                    blckRef: BlockRef,
                    blck: BeaconBlock,
                    wallSlot: Slot) =
  ## Add a verified block to the fork choice context
  ## The current justifiedState of the block pool is used as reference
  let state = pool.forkChoice.process_block(
    pool.blockPool, state, blckRef, blck, wallSlot)

  if state.isErr:
    # TODO If this happens, it is effectively a bug - the BlockRef structure
    #      guarantees that the DAG is valid and the state transition should
    #      guarantee that the justified and finalized epochs are ok! However,
    #      we'll log it for now to avoid crashes
    error "Unexpected error when applying block",
      blck = shortLog(blck), err = state.error

proc getAttestationsForSlot*(pool: AttestationPool, newBlockSlot: Slot):
    Option[AttestationsSeen] =
  if newBlockSlot < (GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY):
    debug "Too early for attestations",
      newBlockSlot = shortLog(newBlockSlot)
    return none(AttestationsSeen)

  if pool.mapSlotsToAttestations.len == 0: # startingSlot not set yet!
    info "No attestations found (pool empty)",
      newBlockSlot = shortLog(newBlockSlot)
    return none(AttestationsSeen)

  let
    # TODO in theory we could include attestations from other slots also, but
    # we're currently not tracking which attestations have already been included
    # in blocks on the fork we're aiming for.. this is a conservative approach
    # that's guaranteed to not include any duplicates, because it's the first
    # time the attestations are up for inclusion!
    attestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY

  if attestationSlot < pool.startingSlot or
      attestationSlot >= pool.startingSlot + pool.mapSlotsToAttestations.len.uint64:
    info "No attestations matching the slot range",
      attestationSlot = shortLog(attestationSlot),
      startingSlot = shortLog(pool.startingSlot),
      endingSlot = shortLog(pool.startingSlot + pool.mapSlotsToAttestations.len.uint64)
    return none(AttestationsSeen)

  let slotDequeIdx = int(attestationSlot - pool.startingSlot)
  some(pool.mapSlotsToAttestations[slotDequeIdx])

proc getAttestationsForBlock*(pool: AttestationPool,
                              state: BeaconState): seq[Attestation] =
  ## Retrieve attestations that may be added to a new block at the slot of the
  ## given state
  logScope: pcs = "retrieve_attestation"

  # TODO this shouldn't really need state -- it's to recheck/validate, but that
  # should be refactored
  let newBlockSlot = state.slot
  var attestations: seq[AttestationEntry]

  # This isn't maximally efficient -- iterators or other approaches would
  # avoid lots of memory allocations -- but this provides a more flexible
  # base upon which to experiment with, and isn't yet profiling hot-path,
  # while avoiding penalizing slow attesting too much (as, in the spec it
  # is supposed to be available two epochs back; it's not meant as). This
  # isn't a good solution, either -- see the set-packing comment below as
  # one issue. It also creates problems with lots of repeat attestations,
  # as a bunch of synchronized beacon_nodes do almost the opposite of the
  # intended thing -- sure, _blocks_ have to be popular (via attestation)
  # but _attestations_ shouldn't have to be so frequently repeated, as an
  # artifact of this state-free, identical-across-clones choice basis. In
  # addResolved, too, the new attestations get added to the end, while in
  # these functions, it's reading from the beginning, et cetera. This all
  # needs a single unified strategy.
  const LOOKBACK_WINDOW = 3
  for i in max(1, newBlockSlot.int64 - LOOKBACK_WINDOW) .. newBlockSlot.int64:
    let maybeSlotData = getAttestationsForSlot(pool, i.Slot)
    if maybeSlotData.isSome:
      insert(attestations, maybeSlotData.get.attestations)

  if attestations.len == 0:
    return

  var cache = StateCache()
  for a in attestations:
    var
      # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#construct-attestation
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        signature: a.validations[0].aggregate_signature
      )

    # TODO what's going on here is that when producing a block, we need to
    #      include only such attestations that will not cause block validation
    #      to fail. How this interacts with voting and the acceptance of
    #      attestations into the pool in general is an open question that needs
    #      revisiting - for example, when attestations are added, against which
    #      state should they be validated, if at all?
    # TODO we're checking signatures here every time which is very slow and we don't want
    #      to include a broken attestation
    if not check_attestation(state, attestation, {}, cache):
      warn "Attestation no longer validates...",
        attestation = shortLog(attestation)
      continue

    for v in a.validations[1..^1]:
      # TODO We need to select a set of attestations that maximise profit by
      #      adding the largest combined attestation set that we can find - this
      #      unfortunately looks an awful lot like
      #      https://en.wikipedia.org/wiki/Set_packing - here we just iterate
      #      and naively add as much as possible in one go, by we could also
      #      add the same attestation data twice, as long as there's at least
      #      one new attestation in there
      if not attestation.aggregation_bits.overlaps(v.aggregation_bits):
        attestation.aggregation_bits.combine(v.aggregation_bits)
        attestation.signature.aggregate(v.aggregate_signature)

    result.add(attestation)

    if result.len >= MAX_ATTESTATIONS.int:
      debug "getAttestationsForBlock: returning early after hitting MAX_ATTESTATIONS",
        attestationSlot = newBlockSlot - 1
      return

proc resolve*(pool: var AttestationPool) =
  ## Check attestations in our unresolved deque
  ## if they can be integrated to the fork choice
  logScope: pcs = "atp_resolve"

  var
    done: seq[Eth2Digest]
    resolved: seq[tuple[blck: BlockRef, attestation: Attestation]]

  for k, v in pool.unresolved.mpairs():
    if (let blck = pool.blockPool.getRef(k); not blck.isNil()):
      resolved.add((blck, v.attestation))
      done.add(k)
    elif v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    pool.unresolved.del(k)

  for a in resolved:
    pool.addResolved(a.blck, a.attestation)

proc selectHead*(pool: var AttestationPool, wallSlot: Slot): BlockRef =
  let newHead = pool.forkChoice.find_head(wallSlot, pool.blockPool)

  if newHead.isErr:
    error "Couldn't select head", err = newHead.error
    nil
  else:
    pool.blockPool.getRef(newHead.get())

proc prune*(pool: var AttestationPool) =
  if (let v = pool.forkChoice.prune(); v.isErr):
    error "Pruning failed", err = v.error() # TODO should never happen

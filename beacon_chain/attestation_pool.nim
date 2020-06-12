# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  deques, sequtils, tables, options,
  chronicles, stew/[byteutils], json_serialization/std/sets,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator],
  ./extras, ./block_pool, ./block_pools/candidate_chains, ./beacon_node_types,
  ./fork_choice/[fork_choice_types, fork_choice]

logScope: topics = "attpool"

func init*(T: type AttestationPool, blockPool: BlockPool): T =
  ## Initialize an AttestationPool from the blockPool `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  # TODO blockPool is only used when resolving orphaned attestations - it should
  #      probably be removed as a dependency of AttestationPool (or some other
  #      smart refactoring)

  # TODO: In tests, on blockpool.init the finalized root
  #       from the `headState` and `justifiedState` is zero
  let forkChoice = initForkChoice(
    finalized_block_slot = default(Slot),             # This is unnecessary for fork choice but may help external components
    finalized_block_state_root = default(Eth2Digest), # This is unnecessary for fork choice but may help external components
    justified_epoch = blockPool.headState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = blockPool.headState.data.data.finalized_checkpoint.epoch,
    # finalized_root = blockPool.headState.data.data.finalized_checkpoint.root
    finalized_root = blockPool.finalizedHead.blck.root
  ).get()

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
    We should have checked in validate that attestation is newer than
    finalized_slot and we never prune things before that, per below condition!
    """ &
    ", attestationSlot: " & $shortLog(attestationSlot) &
    ", startingSlot: " & $shortLog(pool.startingSlot)

  if pool.mapSlotsToAttestations.len == 0:
    # Because the first attestations may arrive in any order, we'll make sure
    # to start counting at the last finalized epoch start slot - anything
    # earlier than that is thrown out by the above check
    info "First attestation!",
      attestationSlot =  $shortLog(attestationSlot),
      cat = "init"
    pool.startingSlot =
      state.finalized_checkpoint.epoch.compute_start_slot_at_epoch()

  if pool.startingSlot + pool.mapSlotsToAttestations.len.uint64 <= attestationSlot:
    trace "Growing attestation pool",
      attestationSlot =  $shortLog(attestationSlot),
      startingSlot = $shortLog(pool.startingSlot),
      cat = "caching"

    # Make sure there's a pool entry for every slot, even when there's a gap
    while pool.startingSlot + pool.mapSlotsToAttestations.len.uint64 <= attestationSlot:
      pool.mapSlotsToAttestations.addLast(AttestationsSeen())

  if pool.startingSlot <
      state.finalized_checkpoint.epoch.compute_start_slot_at_epoch():
    debug "Pruning attestation pool",
      startingSlot = $shortLog(pool.startingSlot),
      finalizedSlot = $shortLog(
        state.finalized_checkpoint
             .epoch.compute_start_slot_at_epoch()),
      cat = "pruning"

    # TODO there should be a better way to remove a whole epoch of stuff..
    while pool.startingSlot <
        state.finalized_checkpoint.epoch.compute_start_slot_at_epoch():
      pool.mapSlotsToAttestations.popFirst()
      pool.startingSlot += 1

  int(attestationSlot - pool.startingSlot)

func updateLatestVotes(
    pool: var AttestationPool, attestationSlot: Slot,
    participants: seq[ValidatorIndex], blck: BlockRef) =

  let target_epoch = compute_epoch_at_slot(attestationSlot)
  for validator in participants:
    pool.forkChoice.process_attestation(validator, blck.root, target_epoch)

func get_attesting_indices_seq(state: BeaconState,
                               attestation_data: AttestationData,
                               bits: CommitteeValidatorsBits,
                               cache: var StateCache): seq[ValidatorIndex] =
  toSeq(items(get_attesting_indices(
    state, attestation_data, bits, cache)))

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

  # TODO: How fast is state rewind?
  #       Can this be a DOS vector.

  # TODO: filter valid attestation as much as possible before state rewind
  # TODO: the below check does not respect the inclusion delay
  #       we should use isValidAttestationSlot instead
  if blck.slot > attestation.data.slot:
    notice "Invalid attestation (too new!)",
      attestation = shortLog(attestation),
      blockSlot = shortLog(blck.slot)
    return
  # if not isValidAttestationSlot(attestation.data.slot, blck.slot):
  #   # Logging in isValidAttestationSlot
  #   return

  # Get a temporary state at the (block, slot) targeted by the attestation
  updateStateData(
    pool.blockPool, pool.blockPool.tmpState,
    BlockSlot(blck: blck, slot: attestation.data.slot))

  template state(): BeaconState = pool.blockPool.tmpState.data.data

  # Check that the attestation is indeed valid
  # TODO: we might want to split checks that depend
  #       on the state and those that don't to cheaply
  #       discard invalid attestations before rewinding state.

  # TODO: stateCache usage
  var stateCache = get_empty_per_epoch_cache()
  if not isValidAttestationTargetEpoch(state, attestation):
    notice "Invalid attestation",
      attestation = shortLog(attestation),
      current_epoch = get_current_epoch(state),
      cat = "filtering"
    return

  # TODO inefficient data structures..

  var cache = getEpochCache(blck, state)
  let
    attestationSlot = attestation.data.slot
    idx = pool.slotIndex(state, attestationSlot)
    attestationsSeen = addr pool.mapSlotsToAttestations[idx]
    validation = Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: attestation.signature)
    participants = get_attesting_indices_seq(
      state, attestation.data, validation.aggregation_bits, cache)

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
            existingParticipants = get_attesting_indices_seq(
              state, a.data, v.aggregation_bits, cache),
            newParticipants = participants,
            cat = "filtering"
          found = true
          break

      if not found:
        # Attestations in the pool that are a subset of the new attestation
        # can now be removed per same logic as above

        trace "Removing subset attestations",
          existingParticipants = a.validations.filterIt(
            it.aggregation_bits.isSubsetOf(validation.aggregation_bits)
          ).mapIt(get_attesting_indices_seq(
            state, a.data, it.aggregation_bits, cache)),
          newParticipants = participants,
          cat = "pruning"

        a.validations.keepItIf(
          not it.aggregation_bits.isSubsetOf(validation.aggregation_bits))

        a.validations.add(validation)
        pool.updateLatestVotes(attestationSlot, participants, a.blck)

        info "Attestation resolved",
          attestation = shortLog(attestation),
          validations = a.validations.len(),
          current_epoch = get_current_epoch(state),
          blockSlot = shortLog(blck.slot),
          cat = "filtering"

        found = true

      break

  if not found:
    attestationsSeen.attestations.add(AttestationEntry(
      data: attestation.data,
      blck: blck,
      validations: @[validation]
    ))
    pool.updateLatestVotes(attestationSlot, participants, blck)

    info "Attestation resolved",
      attestation = shortLog(attestation),
      current_epoch = get_current_epoch(state),
      validations = 1,
      blockSlot = shortLog(blck.slot),
      cat = "filtering"

proc add*(pool: var AttestationPool, attestation: Attestation) =
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

proc add*(pool: var AttestationPool, blck: BlockRef) =
  ## Add a verified block to the fork choice context
  ## The current justifiedState of the block pool is used as reference

  # TODO: add(BlockPool, blockRoot: Eth2Digest, SignedBeaconBlock): BlockRef
  # should ideally return the justified_epoch and finalized_epoch
  # so that we can pass them directly to this proc without having to
  # redo "updateStateData"
  #
  # In any case, `updateStateData` should shortcut
  # to `getStateDataCached`

  updateStateData(
    pool.blockPool,
    pool.blockPool.tmpState,
    BlockSlot(blck: blck, slot: blck.slot)
  )

  let blockData = pool.blockPool.get(blck)
  pool.forkChoice.process_block(
    slot = blck.slot,
    block_root = blck.root,
    parent_root = if not blck.parent.isNil: blck.parent.root else: default(Eth2Digest),
    state_root = default(Eth2Digest), # This is unnecessary for fork choice but may help external components
    justified_epoch = pool.blockPool.tmpState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = pool.blockPool.tmpState.data.data.finalized_checkpoint.epoch,
  ).get()

proc getAttestationsForSlot*(pool: AttestationPool, newBlockSlot: Slot):
    Option[AttestationsSeen] =
  if newBlockSlot < (GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY):
    debug "Too early for attestations",
      newBlockSlot = shortLog(newBlockSlot),
      cat = "query"
    return none(AttestationsSeen)

  if pool.mapSlotsToAttestations.len == 0: # startingSlot not set yet!
    info "No attestations found (pool empty)",
      newBlockSlot = shortLog(newBlockSlot),
      cat = "query"
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
      endingSlot = shortLog(pool.startingSlot + pool.mapSlotsToAttestations.len.uint64),
      cat = "query"
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

  var cache = get_empty_per_epoch_cache()
  for a in attestations:
    var
      # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#construct-attestation
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
        cat = "query"
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

    if result.len >= MAX_ATTESTATIONS:
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

func getAttesterBalances(state: StateData): seq[Gwei] {.noInit.}=
  ## Get the balances from a state
  result.newSeq(state.data.data.validators.len) # zero-init

  let epoch = state.data.data.slot.compute_epoch_at_slot()

  for i in 0 ..< result.len:
    # All non-active validators have a 0 balance
    template validator: Validator = state.data.data.validators[i]
    if validator.is_active_validator(epoch):
      result[i] = validator.effective_balance

proc selectHead*(pool: var AttestationPool): BlockRef =
  let attesterBalances = pool.blockPool.justifiedState.getAttesterBalances()

  let newHead = pool.forkChoice.find_head(
    justified_epoch = pool.blockPool.justifiedState.data.data.slot.compute_epoch_at_slot(),
    justified_root = pool.blockPool.head.justified.blck.root,
    finalized_epoch = pool.blockPool.justifiedState.data.data.finalized_checkpoint.epoch,
    justified_state_balances = attesterBalances
  ).get()

  pool.blockPool.getRef(newHead)

proc pruneBefore*(pool: var AttestationPool, finalizedhead: BlockSlot) =
  pool.forkChoice.maybe_prune(finalizedHead.blck.root).get()

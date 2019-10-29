import
  deques, options, sequtils, tables,
  chronicles, stew/bitseqs, json_serialization/std/sets,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator],
  ./extras, ./ssz, ./block_pool,
  beacon_node_types

logScope: topics = "attpool"

proc init*(T: type AttestationPool, blockPool: BlockPool): T =
  # TODO blockPool is only used when resolving orphaned attestations - it should
  #      probably be removed as a dependency of AttestationPool (or some other
  #      smart refactoring)
  T(
    slots: initDeque[SlotData](),
    blockPool: blockPool,
    unresolved: initTable[Eth2Digest, UnresolvedAttestation](),
    latestAttestations: initTable[ValidatorPubKey, BlockRef]()
  )

proc combine*(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  ## Combine the signature and participation bitfield, with the assumption that
  ## the same data is being signed - if the signatures overlap, they are not
  ## combined.

  doAssert tgt.data == src.data

  # In a BLS aggregate signature, one needs to count how many times a
  # particular public key has been added - since we use a single bit per key, we
  # can only it once, thus we can never combine signatures that overlap already!
  if not tgt.aggregation_bits.overlaps(src.aggregation_bits):
    tgt.aggregation_bits.combine(src.aggregation_bits)

    if skipValidation notin flags:
      tgt.signature.combine(src.signature)
  else:
    trace "Ignoring overlapping attestations"

proc validate(
    state: BeaconState, attestation: Attestation): bool =
  # TODO what constitutes a valid attestation when it's about to be added to
  #      the pool? we're interested in attestations that will become viable
  #      for inclusion in blocks in the future and on any fork, so we need to
  #      consider that validations might happen using the state of a different
  #      fork.
  #      Some things are always invalid (like out-of-bounds issues etc), but
  #      others are more subtle - how do we validate the signature for example?
  #      It might be valid on one fork but not another. One thing that helps
  #      is that committees are stable per epoch and that it should be OK to
  #      include an attestation in a block even if the corresponding validator
  #      was slashed in the same epoch - there's no penalty for doing this and
  #      the vote counting logic will take care of any ill effects (TODO verify)
  let data = attestation.data
  if not (data.crosslink.shard < SHARD_COUNT):
    notice "Attestation shard too high",
      attestation_shard = data.crosslink.shard
    return

  # Without this check, we can't get a slot number for the attestation as
  # certain helpers will assert
  # TODO this could probably be avoided by being smart about the specific state
  #      used to validate the attestation: most likely if we pick the state of
  #      the beacon block being voted for and a slot in the target epoch
  #      of the attestation, we'll be safe!
  # TODO the above state selection logic should probably live here in the
  #      attestation pool
  if not (data.target.epoch == get_previous_epoch(state) or
      data.target.epoch == get_current_epoch(state)):
    notice "Target epoch not current or previous epoch"

    return

  true

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

  if pool.slots.len == 0:
    # Because the first attestations may arrive in any order, we'll make sure
    # to start counting at the last finalized epoch start slot - anything
    # earlier than that is thrown out by the above check
    info "First attestation!",
      attestationSlot =  $shortLog(attestationSlot),
      cat = "init"
    pool.startingSlot =
      state.finalized_checkpoint.epoch.compute_start_slot_of_epoch()

  if pool.startingSlot + pool.slots.len.uint64 <= attestationSlot:
    trace "Growing attestation pool",
      attestationSlot =  $shortLog(attestationSlot),
      startingSlot = $shortLog(pool.startingSlot),
      cat = "caching"

    # Make sure there's a pool entry for every slot, even when there's a gap
    while pool.startingSlot + pool.slots.len.uint64 <= attestationSlot:
      pool.slots.addLast(SlotData())

  if pool.startingSlot <
      state.finalized_checkpoint.epoch.compute_start_slot_of_epoch():
    debug "Pruning attestation pool",
      startingSlot = $shortLog(pool.startingSlot),
      finalizedSlot = $shortLog(
        state.finalized_checkpoint
             .epoch.compute_start_slot_of_epoch()),
      cat = "pruning"

    # TODO there should be a better way to remove a whole epoch of stuff..
    while pool.startingSlot <
        state.finalized_checkpoint.epoch.compute_start_slot_of_epoch():
      pool.slots.popFirst()
      pool.startingSlot += 1

  int(attestationSlot - pool.startingSlot)

proc updateLatestVotes(
    pool: var AttestationPool, state: BeaconState, attestationSlot: Slot,
    participants: seq[ValidatorIndex], blck: BlockRef) =
  for validator in participants:
    let
      pubKey = state.validators[validator].pubkey
      current = pool.latestAttestations.getOrDefault(pubKey)
    if current.isNil or current.slot < attestationSlot:
      pool.latestAttestations[pubKey] = blck

proc add*(pool: var AttestationPool,
          state: BeaconState,
          blck: BlockRef,
          attestation: Attestation) =
  # TODO there are constraints on the state and block being passed in here
  #      but what these are is unclear.. needs analyzing from a high-level
  #      perspective / spec intent
  # TODO should update the state correctly in here instead of forcing the caller
  #      to do it...
  logScope: pcs = "atp_add_attestation"

  doAssert blck.root == attestation.data.beacon_block_root

  if not validate(state, attestation):
    notice "Invalid attestation",
      attestationData = shortLog(attestation.data),
      current_epoch = get_current_epoch(state),
      target_epoch = attestation.data.target.epoch,
      stateSlot = state.slot,
      cat = "filtering"
    return

  # TODO inefficient data structures..

  let
    attestationSlot = get_attestation_data_slot(state, attestation.data)
    idx = pool.slotIndex(state, attestationSlot)
    slotData = addr pool.slots[idx]
    validation = Validation(
      aggregation_bits: attestation.aggregation_bits,
      custody_bits: attestation.custody_bits,
      aggregate_signature: attestation.signature)
    participants = get_attesting_indices_seq(
      state, attestation.data, validation.aggregation_bits)

  var found = false
  for a in slotData.attestations.mitems():
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
              state, a.data, v.aggregation_bits),
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
            state, a.data, it.aggregation_bits)),
          newParticipants = participants,
          cat = "pruning"

        a.validations.keepItIf(
          not it.aggregation_bits.isSubsetOf(validation.aggregation_bits))

        a.validations.add(validation)
        pool.updateLatestVotes(state, attestationSlot, participants, a.blck)

        info "Attestation resolved",
          attestationData = shortLog(attestation.data),
          validations = a.validations.len(),
          current_epoch = get_current_epoch(state),
          target_epoch = attestation.data.target.epoch,
          stateSlot = state.slot,
          cat = "filtering"

        found = true

      break

  if not found:
    slotData.attestations.add(AttestationEntry(
      data: attestation.data,
      blck: blck,
      validations: @[validation]
    ))
    pool.updateLatestVotes(state, attestationSlot, participants, blck)

    info "Attestation resolved",
      attestationData = shortLog(attestation.data),
      current_epoch = get_current_epoch(state),
      target_epoch = attestation.data.target.epoch,
      stateSlot = state.slot,
      validations = 1,
      cat = "filtering"

proc addUnresolved*(pool: var AttestationPool, attestation: Attestation) =
  pool.unresolved[attestation.data.beacon_block_root] =
    UnresolvedAttestation(
      attestation: attestation,
    )

proc getAttestationsForBlock*(
    pool: AttestationPool, state: BeaconState,
    newBlockSlot: Slot): seq[Attestation] =
  logScope: pcs = "retrieve_attestation"

  if newBlockSlot < (GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY):
    debug "[Attestion Pool] Too early for attestations",
      newBlockSlot = shortLog(newBlockSlot),
      cat = "query"
    return

  if pool.slots.len == 0: # startingSlot not set yet!
    info "No attestations found (pool empty)",
      newBlockSlot = shortLog(newBlockSlot),
      cat = "query"
    return

  var cache = get_empty_per_epoch_cache()
  let
    # TODO in theory we could include attestations from other slots also, but
    # we're currently not tracking which attestations have already been included
    # in blocks on the fork we're aiming for.. this is a conservative approach
    # that's guaranteed to not include any duplicates, because it's the first
    # time the attestations are up for inclusion!
    attestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY

  if attestationSlot < pool.startingSlot or
      attestationSlot >= pool.startingSlot + pool.slots.len.uint64:
    info "No attestations matching the slot range",
      attestationSlot = shortLog(attestationSlot),
      startingSlot = shortLog(pool.startingSlot),
      endingSlot = shortLog(pool.startingSlot + pool.slots.len.uint64),
      cat = "query"
    return

  let
    slotDequeIdx = int(attestationSlot - pool.startingSlot)
    slotData = pool.slots[slotDequeIdx]

  for a in slotData.attestations:
    var
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        custody_bits: a.validations[0].custody_bits,
        signature: a.validations[0].aggregate_signature
      )

    if not validate(state, attestation):
      warn "Attestation no longer validates...",
        cat = "query"
      continue

    # TODO what's going on here is that when producing a block, we need to
    #      include only such attestations that will not cause block validation
    #      to fail. How this interacts with voting and the acceptance of
    #      attestations into the pool in general is an open question that needs
    #      revisiting - for example, when attestations are added, against which
    #      state should they be validated, if at all?
    # TODO we're checking signatures here every time which is very slow - this
    #      is needed because validate does nothing for now and we don't want
    #      to include a broken attestation
    if not check_attestation(
        state, attestation, {nextSlot}, cache):
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
        attestation.custody_bits.combine(v.custody_bits)
        attestation.signature.combine(v.aggregate_signature)

    result.add(attestation)

    if result.len >= MAX_ATTESTATIONS:
      return

proc getAttestationsForTargetEpoch*(
  pool: AttestationPool, state: var BeaconState,
    epoch: Epoch): seq[Attestation] =
  # TODO quick testing kludge
  let begin_slot = compute_start_slot_of_epoch(epoch).uint64
  let end_slot_minus1 = (compute_start_slot_of_epoch(epoch+1) - 1).uint64
  for s in begin_slot .. end_slot_minus1:
    result.add getAttestationsForBlock(pool, state, s.Slot)

proc resolve*(pool: var AttestationPool, cache: var StateData) =
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
    pool.blockPool.updateStateData(
      cache, BlockSlot(blck: a.blck, slot: a.blck.slot))

    pool.add(cache.data.data, a.blck, a.attestation)

proc latestAttestation*(
    pool: AttestationPool, pubKey: ValidatorPubKey): BlockRef =
  pool.latestAttestations.getOrDefault(pubKey)

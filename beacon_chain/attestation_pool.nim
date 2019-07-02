import
  deques, options, sequtils, tables,
  chronicles,
  ./spec/[beaconstate, bitfield, datatypes, crypto, digest, helpers, validator],
  ./extras, ./beacon_chain_db, ./ssz, ./block_pool,
  beacon_node_types

proc init*(T: type AttestationPool, blockPool: BlockPool): T =
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

proc validate(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags): bool =
  # TODO these validations should probably be done elsewhere, and really bad
  # attestations should probably cause some sort of feedback to the network
  # layer so they don't spread further.. is there a sliding scale here of
  # badness?

  # TODO half of this stuff is from beaconstate.validateAttestation - merge?

  let attestationSlot = get_attestation_data_slot(state, attestation.data)

  if attestationSlot < state.finalized_epoch.compute_start_slot_of_epoch():
    debug "Old attestation",
      attestationSlot = humaneSlotNum(attestationSlot),
      attestationEpoch = humaneEpochNum(attestationSlot.compute_epoch_of_slot),
      stateSlot = humaneSlotNum(state.slot),
      finalizedEpoch = humaneEpochNum(state.finalized_epoch)

    return

  # TODO what makes sense here? If an attestation is from the future with
  # regards to the state, something is wrong - it's a bad attestation, we're
  # desperatly behind or someone is sending bogus attestations...
  if attestationSlot > state.slot + 64:
    debug "Future attestation",
      attestationSlot = humaneSlotNum(attestationSlot),
      attestationEpoch = humaneEpochNum(attestationSlot.compute_epoch_of_slot),
      stateSlot = humaneSlotNum(state.slot),
      finalizedEpoch = humaneEpochNum(state.finalized_epoch)
    return

  if not allIt(attestation.custody_bits.bits, it == 0):
    notice "Invalid custody bitfield for phase 0"
    return false

  if not anyIt(attestation.aggregation_bits.bits, it != 0):
    notice "Empty aggregation bitfield"
    return false

  ## the rest; turns into expensive NOP until then.
  if skipValidation notin flags:
    let
      participants = get_attesting_indices_seq(
        state, attestation.data, attestation.aggregation_bits)

      ## TODO when the custody_bits assertion-to-emptiness disappears do this
      ## and fix the custody_bit_0_participants check to depend on it.
      # custody_bit_1_participants = {nothing, always, because assertion above}
      custody_bit_1_participants: seq[ValidatorIndex] = @[]
      custody_bit_0_participants = participants

      group_public_key = bls_aggregate_pubkeys(
        participants.mapIt(state.validators[it].pubkey))

    # Verify that aggregate_signature verifies using the group pubkey.
    if not bls_verify_multiple(
        @[
          bls_aggregate_pubkeys(mapIt(custody_bit_0_participants,
                                      state.validators[it].pubkey)),
          bls_aggregate_pubkeys(mapIt(custody_bit_1_participants,
                                      state.validators[it].pubkey)),
        ],
        @[
          hash_tree_root(AttestationDataAndCustodyBit(
            data: attestation.data, custody_bit: false)),
          hash_tree_root(AttestationDataAndCustodyBit(
            data: attestation.data, custody_bit: true)),
        ],
        attestation.signature,
        get_domain(state, DOMAIN_ATTESTATION,
          compute_epoch_of_slot(get_attestation_data_slot(state, attestation.data))),
      ):
      notice "Invalid signature", participants
      return false

  true

proc slotIndex(
    pool: var AttestationPool, state: BeaconState, attestationSlot: Slot): int =
  ## Grow and garbage collect pool, returning the deque index of the slot

  # We keep a sliding window of attestations, roughly from the last finalized
  # epoch to now, because these are the attestations that may affect the voting
  # outcome. Some of these attestations will already have been added to blocks,
  # while others are fresh off the network.
  # TODO only the latest vote of each validator counts. Can we use that somehow?

  doAssert attestationSlot >= pool.startingSlot,
    """
    We should have checked in validate that attestation is newer than
    finalized_slot and we never prune things before that, per below condition!
    """ &
    ", attestationSlot: " & $humaneSlotNum(attestationSlot) &
    ", startingSlot: " & $humaneSlotNum(pool.startingSlot)

  if pool.slots.len == 0:
    # Because the first attestations may arrive in any order, we'll make sure
    # to start counting at the last finalized epoch start slot - anything
    # earlier than that is thrown out by the above check
    info "First attestation!",
      attestationSlot =  $humaneSlotNum(attestationSlot)
    pool.startingSlot = state.finalized_epoch.compute_start_slot_of_epoch()

  if pool.startingSlot + pool.slots.len.uint64 <= attestationSlot:
    debug "Growing attestation pool",
      attestationSlot =  $humaneSlotNum(attestationSlot),
      startingSlot = $humaneSlotNum(pool.startingSlot)

    # Make sure there's a pool entry for every slot, even when there's a gap
    while pool.startingSlot + pool.slots.len.uint64 <= attestationSlot:
      pool.slots.addLast(SlotData())

  if pool.startingSlot < state.finalized_epoch.compute_start_slot_of_epoch():
    debug "Pruning attestation pool",
      startingSlot = $humaneSlotNum(pool.startingSlot),
      finalizedSlot =
        $humaneSlotNum(state.finalized_epoch.compute_start_slot_of_epoch())

    # TODO there should be a better way to remove a whole epoch of stuff..
    while pool.startingSlot < state.finalized_epoch.compute_start_slot_of_epoch():
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
          attestation: Attestation) =
  # TODO should validate against the state of the block being attested to?
  if not validate(state, attestation, {skipValidation}):
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
          debug "Ignoring subset attestation",
            existingParticipants = get_attesting_indices_seq(
              state, a.data, v.aggregation_bits),
            newParticipants = participants
          found = true
          break

      if not found:
        # Attestations in the pool that are a subset of the new attestation
        # can now be removed per same logic as above
        a.validations.keepItIf(
          if it.aggregation_bits.isSubsetOf(
              validation.aggregation_bits):
            debug "Removing subset attestation",
              existingParticipants = get_attesting_indices_seq(
                state, a.data, it.aggregation_bits),
              newParticipants = participants
            false
          else:
            true)

        a.validations.add(validation)
        pool.updateLatestVotes(state, attestationSlot, participants, a.blck)

        info "Attestation resolved",
          attestationData = shortLog(attestation.data),
          validations = a.validations.len()

        found = true

      break

  if not found:
    if (let blck = pool.blockPool.getOrResolve(
          attestation.data.beacon_block_root); blck != nil):
      slotData.attestations.add(AttestationEntry(
        data: attestation.data,
        blck: blck,
        validations: @[validation]
      ))
      pool.updateLatestVotes(state, attestationSlot, participants, blck)

      info "Attestation resolved",
        attestationData = shortLog(attestation.data),
        validations = 1

    else:
      pool.unresolved[attestation.data.beacon_block_root] =
        UnresolvedAttestation(
          attestation: attestation,
        )

proc getAttestationsForBlock*(
  pool: AttestationPool, state: BeaconState,
    newBlockSlot: Slot): seq[Attestation] =
  if newBlockSlot - GENESIS_SLOT < MIN_ATTESTATION_INCLUSION_DELAY:
    debug "Too early for attestations",
      newBlockSlot = humaneSlotNum(newBlockSlot)
    return

  if pool.slots.len == 0: # startingSlot not set yet!
    info "No attestations found (pool empty)",
      newBlockSlot = humaneSlotNum(newBlockSlot)
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
    info "No attestations",
      attestationSlot = humaneSlotNum(attestationSlot),
      startingSlot = humaneSlotNum(pool.startingSlot),
      endingSlot = humaneSlotNum(pool.startingSlot + pool.slots.len.uint64)

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

    # TODO what's going on here is that when producing a block, we need to
    #      include only such attestations that will not cause block validation
    #      to fail. How this interacts with voting and the acceptance of
    #      attestations into the pool in general is an open question that needs
    #      revisiting - for example, when attestations are added, against which
    #      state should they be validated, if at all?
    if not process_attestation(
        state, attestation, {skipValidation, nextSlot}, cache):
      continue

    for v in a.validations[1..^1]:
      # TODO We need to select a set of attestations that maximise profit by
      #      adding the largest combined attestation set that we can find - this
      #      unfortunately looks an awful lot like
      #      https://en.wikipedia.org/wiki/Set_packing - here we just iterate
      #      and naively add as much as possible in one go, by we could also
      #      add the same attestation data twice, as long as there's at least
      #      one new attestation in there
      if not attestation.aggregation_bits.overlaps(
          v.aggregation_bits):
        attestation.aggregation_bits.combine(
          v.aggregation_bits)
        attestation.custody_bits.combine(v.custody_bits)
        attestation.signature.combine(v.aggregate_signature)

    result.add(attestation)

    if result.len >= MAX_ATTESTATIONS:
      return

proc resolve*(pool: var AttestationPool, state: BeaconState) =
  var done: seq[Eth2Digest]
  var resolved: seq[Attestation]

  for k, v in pool.unresolved.mpairs():
    let attestation_slot = get_attestation_data_slot(state, v.attestation.data)
    if v.tries > 8 or attestation_slot < pool.startingSlot:
      done.add(k)
    else:
      if pool.blockPool.get(k).isSome():
        resolved.add(v.attestation)
        done.add(k)
      else:
        inc v.tries

  for k in done:
    pool.unresolved.del(k)

  for a in resolved:
    pool.add(state, a)

proc latestAttestation*(
    pool: AttestationPool, pubKey: ValidatorPubKey): BlockRef =
  pool.latestAttestations.getOrDefault(pubKey)

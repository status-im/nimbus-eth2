import
  deques, options, sequtils, tables,
  chronicles,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator], extras,
  ./beacon_chain_db, ./ssz, ./block_pool,
  beacon_node_types


proc init*(T: type AttestationPool, blockPool: BlockPool): T =
  T(
    slots: initDeque[SlotData](),
    blockPool: blockPool,
    unresolved: initTable[Eth2Digest, UnresolvedAttestation]()
  )

proc overlaps(a, b: seq[byte]): bool =
  for i in 0..<a.len:
    if (a[i] and b[i]) > 0'u8:
      return true

proc combineBitfield(tgt: var seq[byte], src: seq[byte]) =
  for i in 0 ..< tgt.len:
    # TODO:
    # when BLS signatures are combined, we must ensure that
    # the same participant key is not included on both sides
    tgt[i] = tgt[i] or src[i]

proc combine*(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  # Combine the signature and participation bitfield, with the assumption that
  # the same data is being signed!

  assert tgt.data == src.data

  # TODO:
  # when BLS signatures are combined, we must ensure that
  # the same participant key is not included on both sides
  tgt.aggregation_bitfield.combineBitfield(src.aggregation_bitfield)

  if skipValidation notin flags:
    tgt.aggregate_signature.combine(src.aggregate_signature)

proc validate(
    state: BeaconState, attestation: Attestation, flags: UpdateFlags): bool =
  # TODO these validations should probably be done elsewhere, and really bad
  # attestations should probably cause some sort of feedback to the network
  # layer so they don't spread further.. is there a sliding scale here of
  # badness?

  # TODO half of this stuff is from beaconstate.validateAttestation - merge?

  let attestationSlot = attestation.data.slot.Slot

  if attestationSlot < state.finalized_epoch.get_epoch_start_slot():
    debug "Old attestation",
      attestationSlot = humaneSlotNum(attestationSlot),
      attestationEpoch = humaneEpochNum(attestationSlot.slot_to_epoch),
      stateSlot = humaneSlotNum(state.slot),
      finalizedEpoch = humaneEpochNum(state.finalized_epoch)

    return

  # TODO what makes sense here? If an attestation is from the future with
  # regards to the state, something is wrong - it's a bad attestation, we're
  # desperatly behind or someone is sending bogus attestations...
  if attestationSlot > state.slot + 64:
    debug "Future attestation",
      attestationSlot = humaneSlotNum(attestationSlot),
      attestationEpoch = humaneEpochNum(attestationSlot.slot_to_epoch),
      stateSlot = humaneSlotNum(state.slot),
      finalizedEpoch = humaneEpochNum(state.finalized_epoch)
    return

  if not allIt(attestation.custody_bitfield, it == 0):
    notice "Invalid custody bitfield for phase 0"
    return false

  if not anyIt(attestation.aggregation_bitfield, it != 0):
    notice "Empty aggregation bitfield"
    return false

  let crosslink_committee = mapIt(
    filterIt(get_crosslink_committees_at_slot(
               state, attestation.data.slot.Slot),
             it.shard == attestation.data.shard),
    it.committee)[0]

  # Extra checks not in specs
  # https://github.com/status-im/nim-beacon-chain/pull/105#issuecomment-462432544
  if attestation.aggregation_bitfield.len != (crosslink_committee.len + 7) div 8:
    notice "Invalid aggregation bitfield length",
      attestationLen = attestation.aggregation_bitfield.len,
      committeeLen = crosslink_committee.len
    return false

  if attestation.custody_bitfield.len != (crosslink_committee.len + 7) div 8:
    notice "Invalid custody bitfield length",
      attestationLen = attestation.aggregation_bitfield.len,
      committeeLen = crosslink_committee.len
    return false
  # End extra checks

  ## the rest; turns into expensive NOP until then.
  if skipValidation notin flags:
    let
      participants = get_attestation_participants(
        state, attestation.data, attestation.aggregation_bitfield)

      ## TODO when the custody_bitfield assertion-to-emptiness disappears do this
      ## and fix the custody_bit_0_participants check to depend on it.
      # custody_bit_1_participants = {nothing, always, because assertion above}
      custody_bit_1_participants: seq[ValidatorIndex] = @[]
      custody_bit_0_participants = participants

      group_public_key = bls_aggregate_pubkeys(
        participants.mapIt(state.validator_registry[it].pubkey))

    # Verify that aggregate_signature verifies using the group pubkey.
    if not bls_verify_multiple(
        @[
          bls_aggregate_pubkeys(mapIt(custody_bit_0_participants,
                                      state.validator_registry[it].pubkey)),
          bls_aggregate_pubkeys(mapIt(custody_bit_1_participants,
                                      state.validator_registry[it].pubkey)),
        ],
        @[
          hash_tree_root(AttestationDataAndCustodyBit(
            data: attestation.data, custody_bit: false)),
          hash_tree_root(AttestationDataAndCustodyBit(
            data: attestation.data, custody_bit: true)),
        ],
        attestation.aggregate_signature,
        get_domain(state.fork, slot_to_epoch(attestation.data.slot.Slot),
                  DOMAIN_ATTESTATION),
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
    pool.startingSlot = state.finalized_epoch.get_epoch_start_slot()

  if pool.startingSlot + pool.slots.len.Slot <= attestationSlot:
    debug "Growing attestation pool",
      attestationSlot =  $humaneSlotNum(attestationSlot),
      startingSlot = $humaneSlotNum(pool.startingSlot)

    # Make sure there's a pool entry for every slot, even when there's a gap
    while pool.startingSlot + pool.slots.len.Slot <= attestationSlot:
      pool.slots.addLast(SlotData())

  if pool.startingSlot < state.finalized_epoch.get_epoch_start_slot():
    debug "Pruning attestation pool",
      startingSlot = $humaneSlotNum(pool.startingSlot),
      finalizedSlot =
        $humaneSlotNum(state.finalized_epoch.get_epoch_start_slot())

    # TODO there should be a better way to remove a whole epoch of stuff..
    while pool.startingSlot < state.finalized_epoch.get_epoch_start_slot():
      pool.slots.popFirst()
      pool.startingSlot += 1

  int(attestationSlot - pool.startingSlot)

proc add*(pool: var AttestationPool,
          state: BeaconState,
          attestation: Attestation) =
  if not validate(state, attestation, {skipValidation}):
    return

  # TODO inefficient data structures..

  let
    attestationSlot = attestation.data.slot.Slot
    idx = pool.slotIndex(state, attestationSlot)
    slotData = addr pool.slots[idx]
    validation = Validation(
      aggregation_bitfield: attestation.aggregation_bitfield,
      custody_bitfield: attestation.custody_bitfield,
      aggregate_signature: attestation.aggregate_signature)

  var found = false
  for a in slotData.attestations.mitems():
    if a.data == attestation.data:
      for v in a.validations:
        if v.aggregation_bitfield.overlaps(validation.aggregation_bitfield):
          # TODO this check is here so that later, when we combine signatures,
          #      there is no overlap (each validator must be represented once
          #      only). this is wrong - we could technically receive
          #      attestations that have already been combined (for example when
          #      feeding in attestations from blocks, which we're not doing yet)
          #      but then we'll also have to update the combine logic to deal
          #      with this complication.
          debug "Ignoring overlapping attestation",
            existingParticipants = get_attestation_participants(
              state, a.data, v.aggregation_bitfield),
            newParticipants = get_attestation_participants(
              state, a.data, validation.aggregation_bitfield)
          found = true
          break

      if not found:
        a.validations.add(validation)
        info "Attestation resolved",
          slot = humaneSlotNum(attestation.data.slot),
          shard = attestation.data.shard,
          beaconBlockRoot = shortLog(attestation.data.beacon_block_root),
          justifiedEpoch = humaneEpochNum(attestation.data.justified_epoch),
          justifiedBlockRoot = shortLog(attestation.data.justified_block_root),
          signature = shortLog(attestation.aggregate_signature),
          validations = a.validations.len() # TODO popcount of union

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
      info "Attestation resolved",
        slot = humaneSlotNum(attestation.data.slot),
        shard = attestation.data.shard,
        beaconBlockRoot = shortLog(attestation.data.beacon_block_root),
        justifiedEpoch = humaneEpochNum(attestation.data.justified_epoch),
        justifiedBlockRoot = shortLog(attestation.data.justified_block_root),
        signature = shortLog(attestation.aggregate_signature),
        validations = 1

    else:
      pool.unresolved[attestation.data.beacon_block_root] =
        UnresolvedAttestation(
          attestation: attestation,
        )

proc getAttestationsForBlock*(pool: AttestationPool,
                              newBlockSlot: Slot): seq[Attestation] =
  if newBlockSlot - GENESIS_SLOT < MIN_ATTESTATION_INCLUSION_DELAY:
    debug "Too early for attestations",
      newBlockSlot = humaneSlotNum(newBlockSlot)
    return

  if pool.slots.len == 0: # startingSlot not set yet!
    info "No attestations found (pool empty)",
      newBlockSlot = humaneSlotNum(newBlockSlot)
    return

  let
    # TODO in theory we could include attestations from other slots also, but
    # we're currently not tracking which attestations have already been included
    # in blocks on the fork we're aiming for.. this is a conservative approach
    # that's guaranteed to not include any duplicates, because it's the first
    # time the attestations are up for inclusion!
    attestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY

  if attestationSlot < pool.startingSlot or
      attestationSlot >= pool.startingSlot + pool.slots.len.Slot:
    info "No attestations",
      attestationSlot = humaneSlotNum(attestationSlot),
      startingSlot = humaneSlotNum(pool.startingSlot),
      endingSlot = humaneSlotNum(pool.startingSlot + pool.slots.len.Slot)

    return

  let
    slotDequeIdx = int(attestationSlot - pool.startingSlot)
    slotData = pool.slots[slotDequeIdx]

  for a in slotData.attestations:
    var
      attestation = Attestation(
        aggregation_bitfield: a.validations[0].aggregation_bitfield,
        data: a.data,
        custody_bitfield: a.validations[0].custody_bitfield,
        aggregate_signature: a.validations[0].aggregate_signature
      )

    for v in a.validations[1..^1]:
      if not attestation.aggregation_bitfield.overlaps(
          v.aggregation_bitfield):
        attestation.aggregation_bitfield.combineBitfield(
          v.aggregation_bitfield)
        attestation.custody_bitfield.combineBitfield(v.custody_bitfield)
        attestation.aggregate_signature.combine(v.aggregate_signature)

    result.add(attestation)

    if result.len >= MAX_ATTESTATIONS:
      return

proc resolve*(pool: var AttestationPool, state: BeaconState) =
  var done: seq[Eth2Digest]
  var resolved: seq[Attestation]

  for k, v in pool.unresolved.mpairs():
    if v.tries > 8 or v.attestation.data.slot < pool.startingSlot:
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

import
  std/sets,
  stew/[bitops2, objects],
  datatypes/altair,
  helpers

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/sync-protocol.md#validate_light_client_update
proc validate_light_client_update*(snapshot: LightClientSnapshot,
                                   update: LightClientUpdate,
                                   genesis_validators_root: Eth2Digest): bool =
  # Verify update slot is larger than snapshot slot
  if update.header.slot <= snapshot.header.slot:
    return false

  # Verify update does not skip a sync committee period
  let
    snapshot_period = sync_committee_period(snapshot.header.slot)
    update_period = sync_committee_period(update.header.slot)
  if update_period notin [snapshot_period, snapshot_period + 1]:
    return false

  # Verify update header root is the finalized root of the finality header, if specified
  # TODO: Use a view type instead of `unsafeAddr`
  let signed_header = if update.finality_header.isZeroMemory:
    if not update.finality_branch.isZeroMemory:
      return false
    unsafeAddr update.header
  else:
    if not is_valid_merkle_branch(hash_tree_root(update.header),
                                  update.finality_branch,
                                  log2trunc(FINALIZED_ROOT_INDEX),
                                  get_subtree_index(FINALIZED_ROOT_INDEX),
                                  update.finality_header.state_root):
      return false
    unsafeAddr update.finality_header

  # Verify update next sync committee if the update period incremented
  # TODO: Use a view type instead of `unsafeAddr`
  let sync_committee = if update_period == snapshot_period:
    if not update.next_sync_committee_branch.isZeroMemory:
      return false
    unsafeAddr snapshot.current_sync_committee
  else:
    if not is_valid_merkle_branch(hash_tree_root(update.next_sync_committee),
                                  update.next_sync_committee_branch,
                                  log2trunc(NEXT_SYNC_COMMITTEE_INDEX),
                                  get_subtree_index(NEXT_SYNC_COMMITTEE_INDEX),
                                  update.header.state_root):
      return false
    unsafeAddr snapshot.next_sync_committee

  let sync_committee_participants_count = countOnes(update.sync_committee_bits)
  # Verify sync committee has sufficient participants
  if sync_committee_participants_count < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return false

  # Verify sync committee aggregate signature
  # participant_pubkeys = [pubkey for (bit, pubkey) in zip(update.sync_committee_bits, sync_committee.pubkeys) if bit]
  var participant_pubkeys = newSeqOfCap[ValidatorPubKey](sync_committee_participants_count)
  for idx, bit in update.sync_committee_bits:
    if bit:
      participant_pubkeys.add(sync_committee.pubkeys[idx])

  let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, update.fork_version, genesis_validators_root)
  let signing_root = compute_signing_root(signed_header[], domain)

  blsFastAggregateVerify(participant_pubkeys, signing_root.data, update.sync_committee_signature)

# https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/altair/sync-protocol.md#apply_light_client_update
proc apply_light_client_update(snapshot: var LightClientSnapshot, update: LightClientUpdate) =
  let
    snapshot_period = sync_committee_period(snapshot.header.slot)
    update_period = sync_committee_period(update.header.slot)
  if update_period == snapshot_period + 1:
    snapshot.current_sync_committee = snapshot.next_sync_committee
    snapshot.next_sync_committee = update.next_sync_committee
  snapshot.header = update.header

# https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/altair/sync-protocol.md#process_light_client_update
proc process_light_client_update*(store: var LightClientStore,
                                  update: LightClientUpdate,
                                  current_slot: Slot,
                                  genesis_validators_root: Eth2Digest): bool =
  if not validate_light_client_update(store.snapshot, update, genesis_validators_root):
    return false
  store.valid_updates.incl(update)

  var update_timeout = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD
  let sync_committee_participants_count = countOnes(update.sync_committee_bits)
  if sync_committee_participants_count * 3 >= update.sync_committee_bits.len * 2 and
     not update.finality_header.isZeroMemory:
    # Apply update if (1) 2/3 quorum is reached and (2) we have a finality proof.
    # Note that (2) means that the current light client design needs finality.
    # It may be changed to re-organizable light client design. See the on-going issue eth2.0-specs#2182.
    apply_light_client_update(store.snapshot, update)
    store.valid_updates.clear()
  elif current_slot > store.snapshot.header.slot + update_timeout:
    var best_update_participants = 0
    # TODO:
    #  Use a view type to avoid the copying when a new best update
    #  is discovered.
    #  Alterantively, we could have a `set.max` operation returning
    #  the best item as a `lent` value. We would need an `OrderedSet`
    #  type with support for a custom comparison operation.
    var best_update: LightClientUpdate
    for update in store.valid_updates:
      let update_participants = countOnes(update.sync_committee_bits)
      if update_participants > best_update_participants:
        best_update = update
        best_update_participants = update_participants

    # Forced best update when the update timeout has elapsed
    apply_light_client_update(store.snapshot, best_update)
    store.valid_updates.clear()
  true

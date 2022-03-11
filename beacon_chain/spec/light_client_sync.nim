# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# References to `vFuture` refer to the pre-release proposal of the libp2p based
# light client sync protocol. Conflicting release versions are not in use.
# https://github.com/ethereum/consensus-specs/pull/2802

import
  stew/[bitops2, objects],
  datatypes/altair,
  helpers

func period_contains_fork_version(
    cfg: RuntimeConfig,
    period: SyncCommitteePeriod,
    fork_version: Version): bool =
  ## Determine whether a given `fork_version` is used during a given `period`.
  let
    periodStartEpoch = period.start_epoch
    periodEndEpoch = periodStartEpoch + EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 1
  return
    if fork_version == cfg.SHARDING_FORK_VERSION:
      periodEndEpoch >= cfg.SHARDING_FORK_EPOCH
    elif fork_version == cfg.BELLATRIX_FORK_VERSION:
      periodStartEpoch < cfg.SHARDING_FORK_EPOCH and
      cfg.SHARDING_FORK_EPOCH != cfg.BELLATRIX_FORK_EPOCH and
      periodEndEpoch >= cfg.BELLATRIX_FORK_EPOCH
    elif fork_version == cfg.ALTAIR_FORK_VERSION:
      periodStartEpoch < cfg.BELLATRIX_FORK_EPOCH and
      cfg.BELLATRIX_FORK_EPOCH != cfg.ALTAIR_FORK_EPOCH and
      periodEndEpoch >= cfg.ALTAIR_FORK_EPOCH
    elif fork_version == cfg.GENESIS_FORK_VERSION:
      # Light client sync protocol requires Altair
      false
    else:
      # Unviable fork
      false

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#get_active_header
func is_finality_update(update: altair.LightClientUpdate): bool =
  not update.finalized_header.isZeroMemory

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#get_active_header
func get_active_header(update: altair.LightClientUpdate): BeaconBlockHeader =
  # The "active header" is the header that the update is trying to convince
  # us to accept. If a finalized header is present, it's the finalized
  # header, otherwise it's the attested header
  if update.is_finality_update:
    update.finalized_header
  else:
    update.attested_header

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#get_safety_threshold
func get_safety_threshold(store: LightClientStore): uint64 =
  max(
    store.previous_max_active_participants,
    store.current_max_active_participants
  ) div 2

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#initialize_light_client_store
func initialize_light_client_store*(
    trusted_block_root: Eth2Digest,
    bootstrap: altair.LightClientBootstrap
): Opt[LightClientStore] =
  if hash_tree_root(bootstrap.header) != trusted_block_root:
    return err()

  if not is_valid_merkle_branch(
      hash_tree_root(bootstrap.current_sync_committee),
      bootstrap.current_sync_committee_branch,
      log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX),
      get_subtree_index(altair.CURRENT_SYNC_COMMITTEE_INDEX),
      bootstrap.header.state_root):
    return err()

  return ok(LightClientStore(
    finalized_header: bootstrap.header,
    current_sync_committee: bootstrap.current_sync_committee,
    optimistic_header: bootstrap.header))

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#validate_light_client_update
proc validate_light_client_update*(
    store: LightClientStore,
    update: altair.LightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): bool =
  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return false

  # Determine update header
  template attested_header(): auto = update.attested_header
  if current_slot < attested_header.slot:
    return false
  let active_header = get_active_header(update)
  if attested_header.slot < active_header.slot:
    return false

  # Verify update is relevant
  let is_next_sync_committee_known = not store.next_sync_committee.isZeroMemory
  if is_next_sync_committee_known:
    if active_header.slot < store.finalized_header.slot:
      return false
    if active_header.slot == store.finalized_header.slot:
      if attested_header.slot <= store.optimistic_header.slot:
        return false

  # Verify update does not skip a sync committee period
  let
    finalized_period = store.finalized_header.slot.sync_committee_period
    update_period = active_header.slot.sync_committee_period
  if update_period notin [finalized_period, finalized_period + 1]:
    return false
  let
    is_signed_by_next_sync_committee =
      update.next_sync_committee.isZeroMemory
    signature_period =
      if is_signed_by_next_sync_committee:
        update_period + 1
      else:
        update_period
    current_period = current_slot.sync_committee_period
  if current_period < signature_period:
    return false
  if is_next_sync_committee_known:
    if signature_period notin [finalized_period, finalized_period + 1]:
      return false
  else:
    if signature_period != finalized_period:
      return false

  # Verify fork version is acceptable
  let fork_version = update.fork_version
  if not cfg.period_contains_fork_version(signature_period, fork_version):
    return false

  # Verify that the `finalized_header`, if present, actually is the finalized
  # header saved in the state of the `attested_header`
  if not update.is_finality_update:
    if not update.finality_branch.isZeroMemory:
      return false
  else:
    if not is_valid_merkle_branch(
        hash_tree_root(update.finalized_header),
        update.finality_branch,
        log2trunc(altair.FINALIZED_ROOT_INDEX),
        get_subtree_index(altair.FINALIZED_ROOT_INDEX),
        update.attested_header.state_root):
      return false

  # Verify that the `next_sync_committee`, if present, actually is the
  # next sync committee saved in the state of the `active_header`
  if is_signed_by_next_sync_committee:
    if not update.next_sync_committee_branch.isZeroMemory:
      return false
  else:
    if update_period == finalized_period and is_next_sync_committee_known:
      if update.next_sync_committee != store.next_sync_committee:
        return false
    if not is_valid_merkle_branch(
        hash_tree_root(update.next_sync_committee),
        update.next_sync_committee_branch,
        log2trunc(altair.NEXT_SYNC_COMMITTEE_INDEX),
        get_subtree_index(altair.NEXT_SYNC_COMMITTEE_INDEX),
        active_header.state_root):
      return false

  # Verify sync committee aggregate signature
  let sync_committee =
    if signature_period == finalized_period:
      unsafeAddr store.current_sync_committee
    else:
      unsafeAddr store.next_sync_committee
  var participant_pubkeys =
    newSeqOfCap[ValidatorPubKey](num_active_participants)
  for idx, bit in sync_aggregate.sync_committee_bits:
    if bit:
      participant_pubkeys.add(sync_committee.pubkeys[idx])
  let
    domain = compute_domain(
      DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
    signing_root = compute_signing_root(attested_header, domain)
  if not blsFastAggregateVerify(
      participant_pubkeys, signing_root.data,
      sync_aggregate.sync_committee_signature):
    return false

  true

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#validate_optimistic_light_client_update
proc validate_optimistic_light_client_update*(
    store: LightClientStore,
    optimistic_update: OptimisticLightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): bool =
  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = optimistic_update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return false

  # Determine update header
  template attested_header(): auto = optimistic_update.attested_header
  if current_slot < attested_header.slot:
    return false
  template active_header(): auto = attested_header

  # Verify update is relevant
  if attested_header.slot <= store.optimistic_header.slot:
    return false

  # Verify update does not skip a sync committee period
  let
    finalized_period = store.finalized_header.slot.sync_committee_period
    update_period = active_header.slot.sync_committee_period
  if update_period notin [finalized_period, finalized_period + 1]:
    return false
  let
    is_signed_by_next_sync_committee =
      optimistic_update.is_signed_by_next_sync_committee
    signature_period =
      if is_signed_by_next_sync_committee:
        update_period + 1
      else:
        update_period
    current_period = current_slot.sync_committee_period
  if current_period < signature_period:
    return false
  let is_next_sync_committee_known = not store.next_sync_committee.isZeroMemory
  if is_next_sync_committee_known:
    if signature_period notin [finalized_period, finalized_period + 1]:
      return false
  else:
    if signature_period != finalized_period:
      return false

  # Verify fork version is acceptable
  let fork_version = optimistic_update.fork_version
  if not cfg.period_contains_fork_version(signature_period, fork_version):
    return false

  # Verify sync committee aggregate signature
  let sync_committee =
    if signature_period == finalized_period:
      unsafeAddr store.current_sync_committee
    else:
      unsafeAddr store.next_sync_committee
  var participant_pubkeys =
    newSeqOfCap[ValidatorPubKey](num_active_participants)
  for idx, bit in sync_aggregate.sync_committee_bits:
    if bit:
      participant_pubkeys.add(sync_committee.pubkeys[idx])
  let
    domain = compute_domain(
      DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
    signing_root = compute_signing_root(attested_header, domain)
  if not blsFastAggregateVerify(
      participant_pubkeys, signing_root.data,
      sync_aggregate.sync_committee_signature):
    return false

  true

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#apply_light_client_update
func apply_light_client_update(
    store: var LightClientStore,
    update: altair.LightClientUpdate) =
  let
    active_header = get_active_header(update)
    finalized_period = store.finalized_header.slot.sync_committee_period
    update_period = active_header.slot.sync_committee_period
  if store.next_sync_committee.isZeroMemory:
    assert update_period == finalized_period
    store.next_sync_committee = update.next_sync_committee
  elif update_period == finalized_period + 1:
    store.previous_max_active_participants =
      store.current_max_active_participants
    store.current_max_active_participants = 0
    store.current_sync_committee = store.next_sync_committee
    store.next_sync_committee = update.next_sync_committee
    assert not store.next_sync_committee.isZeroMemory
  if active_header.slot > store.finalized_header.slot:
    store.finalized_header = active_header

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#apply_optimistic_light_client_header
func apply_optimistic_light_client_header(
    store: var LightClientStore,
    attested_header: BeaconBlockHeader,
    num_active_participants: uint64) =
  if store.current_max_active_participants < num_active_participants:
    store.current_max_active_participants = num_active_participants

  if num_active_participants > get_safety_threshold(store) and
      attested_header.slot > store.optimistic_header.slot:
    store.optimistic_header = attested_header

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#process_slot_for_light_client_store
func process_slot_for_light_client_store*(
    store: var LightClientStore,
    current_slot: Slot) =
  if store.best_valid_update.isSome and
      current_slot > store.finalized_header.slot + UPDATE_TIMEOUT:
    apply_light_client_update(store, store.best_valid_update.get)
    store.best_valid_update = none(altair.LightClientUpdate)

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#process_light_client_update
proc process_light_client_update*(
    store: var LightClientStore,
    update: altair.LightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest,
    allowForceUpdate = true): bool =
  if not validate_light_client_update(
      store, update, current_slot, cfg, genesis_validators_root):
    return false

  template sync_aggregate(): auto = update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64

  # Update the optimistic header
  apply_optimistic_light_client_header(
    store, update.attested_header, num_active_participants)

  # Update the best update in case we have to force-update to it
  # if the timeout elapses
  let best_active_participants =
    if store.best_valid_update.isNone:
      0.uint64
    else:
      template best_sync_aggregate(): auto =
        store.best_valid_update.get.sync_aggregate
      countOnes(best_sync_aggregate.sync_committee_bits).uint64
  if num_active_participants > best_active_participants:
    store.best_valid_update = some(update)

  # Update finalized header
  if num_active_participants * 3 >= static(sync_committee_bits.len * 2) and
      update.is_finality_update:
    # Normal update through 2/3 threshold
    apply_light_client_update(store, update)
    store.best_valid_update = none(altair.LightClientUpdate)
  else:
    if allowForceUpdate:
      # Force-update to best update if the timeout elapsed
      process_slot_for_light_client_store(store, current_slot)

  true

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#process_light_client_update
proc process_optimistic_light_client_update*(
    store: var LightClientStore,
    optimistic_update: OptimisticLightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): bool =
  if not validate_optimistic_light_client_update(
      store, optimistic_update, current_slot, cfg, genesis_validators_root):
    return false

  template sync_aggregate(): auto = optimistic_update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64

  # Update the optimistic header
  apply_optimistic_light_client_header(
    store, optimistic_update.attested_header, num_active_participants)

  true

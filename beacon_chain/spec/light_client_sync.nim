# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

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

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#validate_light_client_update
proc validate_light_client_update*(
    store: LightClientStore,
    update: altair.LightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): bool =
  # Verify update slot is larger than slot of current best finalized header
  let active_header = get_active_header(update)
  if not (current_slot >= active_header.slot and
          active_header.slot > store.finalized_header.slot):
    return false

  # Verify update does not skip a sync committee period
  let
    finalized_period = sync_committee_period(store.finalized_header.slot)
    update_period = sync_committee_period(active_header.slot)

  if update_period notin [finalized_period, finalized_period + 1]:
    return false

  # Verify fork version is acceptable
  let fork_version = update.fork_version
  if not cfg.period_contains_fork_version(update_period, fork_version):
    return false

  # Verify that the `finalized_header`, if present, actually is the finalized
  # header saved in the state of the `attested header`
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

  # Verify update next sync committee if the update period incremented
  # TODO: Use a view type instead of `unsafeAddr`
  let sync_committee = if update_period == finalized_period:
    if not update.next_sync_committee_branch.isZeroMemory:
      return false
    unsafeAddr store.current_sync_committee
  else:
    if not is_valid_merkle_branch(
        hash_tree_root(update.next_sync_committee),
        update.next_sync_committee_branch,
        log2trunc(altair.NEXT_SYNC_COMMITTEE_INDEX),
        get_subtree_index(altair.NEXT_SYNC_COMMITTEE_INDEX),
        active_header.state_root):
      return false
    unsafeAddr store.next_sync_committee

  template sync_aggregate(): auto = update.sync_aggregate
  let sync_committee_participants_count = countOnes(sync_aggregate.sync_committee_bits)

  # Verify sync committee has sufficient participants
  if sync_committee_participants_count < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return false

  # Verify sync committee aggregate signature
  # participant_pubkeys = [pubkey for (bit, pubkey) in zip(sync_aggregate.sync_committee_bits, sync_committee.pubkeys) if bit]
  var participant_pubkeys = newSeqOfCap[ValidatorPubKey](sync_committee_participants_count)
  for idx, bit in sync_aggregate.sync_committee_bits:
    if bit:
      participant_pubkeys.add(sync_committee.pubkeys[idx])
  let
    domain = compute_domain(
      DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
    signing_root = compute_signing_root(update.attested_header, domain)
  if not blsFastAggregateVerify(
      participant_pubkeys, signing_root.data,
      sync_aggregate.sync_committee_signature):
    return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#apply_light_client_update
func apply_light_client_update(
    store: var LightClientStore,
    update: altair.LightClientUpdate) =
  let
    active_header = get_active_header(update)
    finalized_period = sync_committee_period(store.finalized_header.slot)
    update_period = sync_committee_period(active_header.slot)
  if update_period == finalized_period + 1:
    store.current_sync_committee = store.next_sync_committee
    store.next_sync_committee = update.next_sync_committee
  store.finalized_header = active_header
  if store.finalized_header.slot > store.optimistic_header.slot:
    store.optimistic_header = store.finalized_header

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#process_light_client_update
proc process_light_client_update*(
    store: var LightClientStore,
    update: altair.LightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): bool =
  if not validate_light_client_update(
      store, update, current_slot, cfg, genesis_validators_root):
    return false

  let
    sync_committee_bits = update.sync_aggregate.sync_committee_bits
    sum_sync_committee_bits = countOnes(sync_committee_bits)

  # Update the best update in case we have to force-update to it if the
  # timeout elapses
  if  store.best_valid_update.isNone or
      sum_sync_committee_bits > countOnes(
        store.best_valid_update.get.sync_aggregate.sync_committee_bits):
    store.best_valid_update = some(update)

  # Track the maximum number of active participants in the committee signatures
  store.current_max_active_participants = max(
    store.current_max_active_participants,
    sum_sync_committee_bits.uint64,
  )

  # Update the optimistic header
  if  sum_sync_committee_bits.uint64 > get_safety_threshold(store) and
      update.attested_header.slot > store.optimistic_header.slot:
    store.optimistic_header = update.attested_header

  # Update finalized header
  if  sum_sync_committee_bits * 3 >= len(sync_committee_bits) * 2 and
      update.is_finality_update:
    # Normal update through 2/3 threshold
    apply_light_client_update(store, update)
    store.best_valid_update = none(altair.LightClientUpdate)

  true

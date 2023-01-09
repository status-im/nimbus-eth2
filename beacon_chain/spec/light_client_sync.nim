# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  stew/[bitops2, objects],
  datatypes/altair,
  helpers

from ../consensus_object_pools/block_pools_types import VerifierError
export block_pools_types.VerifierError

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.0/specs/altair/light-client/sync-protocol.md#initialize_light_client_store
func initialize_light_client_store*(
    trusted_block_root: Eth2Digest,
    bootstrap: altair.LightClientBootstrap
): Result[LightClientStore, VerifierError] =
  if hash_tree_root(bootstrap.header) != trusted_block_root:
    return err(VerifierError.Invalid)

  if not is_valid_merkle_branch(
      hash_tree_root(bootstrap.current_sync_committee),
      bootstrap.current_sync_committee_branch,
      log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX),
      get_subtree_index(altair.CURRENT_SYNC_COMMITTEE_INDEX),
      bootstrap.header.state_root):
    return err(VerifierError.Invalid)

  return ok(LightClientStore(
    finalized_header: bootstrap.header,
    current_sync_committee: bootstrap.current_sync_committee,
    optimistic_header: bootstrap.header))

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/altair/light-client/sync-protocol.md#validate_light_client_update
proc validate_light_client_update*(
    store: LightClientStore,
    update: SomeLightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): Result[void, VerifierError] =
  # Verify sync committee has sufficient participants
  template sync_aggregate(): auto = update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    return err(VerifierError.Invalid)

  # Verify update does not skip a sync committee period
  when update is SomeLightClientUpdateWithFinality:
    if update.attested_header.slot < update.finalized_header.slot:
      return err(VerifierError.Invalid)
  if update.signature_slot <= update.attested_header.slot:
    return err(VerifierError.Invalid)
  if current_slot < update.signature_slot:
    return err(VerifierError.UnviableFork)
  let
    store_period = store.finalized_header.slot.sync_committee_period
    signature_period = update.signature_slot.sync_committee_period
    is_next_sync_committee_known = store.is_next_sync_committee_known
  if is_next_sync_committee_known:
    if signature_period notin [store_period, store_period + 1]:
      return err(VerifierError.MissingParent)
  else:
    if signature_period != store_period:
      return err(VerifierError.MissingParent)

  # Verify update is relevant
  let attested_period = update.attested_header.slot.sync_committee_period
  when update is SomeLightClientUpdateWithSyncCommittee:
    let is_sync_committee_update = update.is_sync_committee_update
  if update.attested_header.slot <= store.finalized_header.slot:
    when update is SomeLightClientUpdateWithSyncCommittee:
      if is_next_sync_committee_known:
        return err(VerifierError.Duplicate)
      if attested_period != store_period or not is_sync_committee_update:
        return err(VerifierError.Duplicate)
    else:
      return err(VerifierError.Duplicate)

  # Verify that the `finalized_header`, if present, actually is the
  # finalized header saved in the state of the `attested_header`
  when update is SomeLightClientUpdateWithFinality:
    if not update.is_finality_update:
      if not update.finalized_header.isZeroMemory:
        return err(VerifierError.Invalid)
    else:
      var finalized_root {.noinit.}: Eth2Digest
      if update.finalized_header.slot != GENESIS_SLOT:
        finalized_root = hash_tree_root(update.finalized_header)
      elif update.finalized_header.isZeroMemory:
        finalized_root.reset()
      else:
        return err(VerifierError.Invalid)
      if not is_valid_merkle_branch(
          finalized_root,
          update.finality_branch,
          log2trunc(altair.FINALIZED_ROOT_INDEX),
          get_subtree_index(altair.FINALIZED_ROOT_INDEX),
          update.attested_header.state_root):
        return err(VerifierError.Invalid)

  # Verify that the `next_sync_committee`, if present, actually is the
  # next sync committee saved in the state of the `attested_header`
  when update is SomeLightClientUpdateWithSyncCommittee:
    if not is_sync_committee_update:
      if not update.next_sync_committee.isZeroMemory:
        return err(VerifierError.Invalid)
    else:
      if attested_period == store_period and is_next_sync_committee_known:
        if update.next_sync_committee != store.next_sync_committee:
          return err(VerifierError.UnviableFork)
      if not is_valid_merkle_branch(
          hash_tree_root(update.next_sync_committee),
          update.next_sync_committee_branch,
          log2trunc(altair.NEXT_SYNC_COMMITTEE_INDEX),
          get_subtree_index(altair.NEXT_SYNC_COMMITTEE_INDEX),
          update.attested_header.state_root):
        return err(VerifierError.Invalid)

  # Verify sync committee aggregate signature
  let sync_committee =
    if signature_period == store_period:
      unsafeAddr store.current_sync_committee
    else:
      unsafeAddr store.next_sync_committee
  var participant_pubkeys =
    newSeqOfCap[ValidatorPubKey](num_active_participants)
  for idx, bit in sync_aggregate.sync_committee_bits:
    if bit:
      participant_pubkeys.add(sync_committee.pubkeys.data[idx])
  let
    fork_version = cfg.forkVersionAtEpoch(update.signature_slot.epoch)
    domain = compute_domain(
      DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
    signing_root = compute_signing_root(update.attested_header, domain)
  if not blsFastAggregateVerify(
      participant_pubkeys, signing_root.data,
      sync_aggregate.sync_committee_signature):
    return err(VerifierError.UnviableFork)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/altair/light-client/sync-protocol.md#apply_light_client_update
func apply_light_client_update(
    store: var LightClientStore,
    update: SomeLightClientUpdate): bool =
  var didProgress = false
  let
    store_period = store.finalized_header.slot.sync_committee_period
    finalized_period = update.finalized_header.slot.sync_committee_period
  if not store.is_next_sync_committee_known:
    assert finalized_period == store_period
    when update is SomeLightClientUpdateWithSyncCommittee:
      store.next_sync_committee = update.next_sync_committee
      if store.is_next_sync_committee_known:
        didProgress = true
  elif finalized_period == store_period + 1:
    store.current_sync_committee = store.next_sync_committee
    when update is SomeLightClientUpdateWithSyncCommittee:
      store.next_sync_committee = update.next_sync_committee
    else:
      store.next_sync_committee.reset()
    store.previous_max_active_participants =
      store.current_max_active_participants
    store.current_max_active_participants = 0
    didProgress = true
  if update.finalized_header.slot > store.finalized_header.slot:
    store.finalized_header = update.finalized_header
    if store.finalized_header.slot > store.optimistic_header.slot:
      store.optimistic_header = store.finalized_header
    didProgress = true
  didProgress

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/altair/light-client/sync-protocol.md#process_light_client_store_force_update
type
  ForceUpdateResult* = enum
    NoUpdate,
    DidUpdateWithoutSupermajority,
    DidUpdateWithoutFinality

func process_light_client_store_force_update*(
    store: var LightClientStore,
    current_slot: Slot): ForceUpdateResult {.discardable.} =
  var res = NoUpdate
  if store.best_valid_update.isSome and
      current_slot > store.finalized_header.slot + UPDATE_TIMEOUT:
    # Forced best update when the update timeout has elapsed
    template best(): auto = store.best_valid_update.get
    if best.finalized_header.slot <= store.finalized_header.slot:
      best.finalized_header = best.attested_header
    if apply_light_client_update(store, best):
      template sync_aggregate(): auto = best.sync_aggregate
      template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
      let num_active_participants = countOnes(sync_committee_bits).uint64
      if num_active_participants * 3 < static(sync_committee_bits.len * 2):
        res = DidUpdateWithoutSupermajority
      else:
        res = DidUpdateWithoutFinality
    store.best_valid_update.reset()
  res

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/specs/altair/light-client/sync-protocol.md#process_light_client_update
proc process_light_client_update*(
    store: var LightClientStore,
    update: SomeLightClientUpdate,
    current_slot: Slot,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest): Result[void, VerifierError] =
  ? validate_light_client_update(
    store, update, current_slot, cfg, genesis_validators_root)

  var didProgress = false

  # Update the best update in case we have to force-update to it
  # if the timeout elapses
  if store.best_valid_update.isNone or
      is_better_update(update, store.best_valid_update.get):
    store.best_valid_update = some(update.toFull)
    didProgress = true

  # Track the maximum number of active participants in the committee signatures
  template sync_aggregate(): auto = update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants > store.current_max_active_participants:
    store.current_max_active_participants = num_active_participants

  # Update the optimistic header
  if num_active_participants > get_safety_threshold(store) and
      update.attested_header.slot > store.optimistic_header.slot:
    store.optimistic_header = update.attested_header
    didProgress = true

  # Update finalized header
  when update is SomeLightClientUpdateWithFinality:
    if num_active_participants * 3 >= static(sync_committee_bits.len * 2):
      var improvesFinality =
        update.finalized_header.slot > store.finalized_header.slot
      when update is SomeLightClientUpdateWithSyncCommittee:
        if not improvesFinality and not store.is_next_sync_committee_known:
          improvesFinality =
            update.is_sync_committee_update and update.is_finality_update and
            update.finalized_header.slot.sync_committee_period ==
            update.attested_header.slot.sync_committee_period
      if improvesFinality:
        # Normal update through 2/3 threshold
        if apply_light_client_update(store, update):
          didProgress = true
        store.best_valid_update.reset()

  if not didProgress:
    return err(VerifierError.Duplicate)
  ok()

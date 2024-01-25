# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/[bitops2, bitseqs, objects],
  datatypes/altair,
  helpers

from ../consensus_object_pools/block_pools_types import VerifierError
export block_pools_types.VerifierError

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#initialize_light_client_store
func initialize_light_client_store*(
    trusted_block_root: Eth2Digest,
    bootstrap: ForkyLightClientBootstrap,
    cfg: RuntimeConfig
): auto =
  type ResultType =
    Result[typeof(bootstrap).kind.LightClientStore, VerifierError]

  if not is_valid_light_client_header(bootstrap.header, cfg):
    return ResultType.err(VerifierError.Invalid)
  if hash_tree_root(bootstrap.header.beacon) != trusted_block_root:
    return ResultType.err(VerifierError.Invalid)

  if not is_valid_merkle_branch(
      hash_tree_root(bootstrap.current_sync_committee),
      bootstrap.current_sync_committee_branch,
      log2trunc(altair.CURRENT_SYNC_COMMITTEE_GINDEX),
      get_subtree_index(altair.CURRENT_SYNC_COMMITTEE_GINDEX),
      bootstrap.header.beacon.state_root):
    return ResultType.err(VerifierError.Invalid)

  return ResultType.ok(typeof(bootstrap).kind.LightClientStore(
    finalized_header: bootstrap.header,
    current_sync_committee: bootstrap.current_sync_committee,
    optimistic_header: bootstrap.header))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#validate_light_client_update
proc validate_light_client_update*(
    store: ForkyLightClientStore,
    update: SomeForkyLightClientUpdate,
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
  if not is_valid_light_client_header(update.attested_header, cfg):
    return err(VerifierError.Invalid)
  when update is SomeForkyLightClientUpdateWithFinality:
    if update.attested_header.beacon.slot < update.finalized_header.beacon.slot:
      return err(VerifierError.Invalid)
  if update.signature_slot <= update.attested_header.beacon.slot:
    return err(VerifierError.Invalid)
  if current_slot < update.signature_slot:
    return err(VerifierError.UnviableFork)
  let
    store_period = store.finalized_header.beacon.slot.sync_committee_period
    signature_period = update.signature_slot.sync_committee_period
    is_next_sync_committee_known = store.is_next_sync_committee_known
  if is_next_sync_committee_known:
    if signature_period notin [store_period, store_period + 1]:
      return err(VerifierError.MissingParent)
  else:
    if signature_period != store_period:
      return err(VerifierError.MissingParent)

  # Verify update is relevant
  when update is SomeForkyLightClientUpdateWithSyncCommittee:
    let
      attested_period = update.attested_header.beacon.slot.sync_committee_period
      is_sync_committee_update = update.is_sync_committee_update
  if update.attested_header.beacon.slot <= store.finalized_header.beacon.slot:
    when update is SomeForkyLightClientUpdateWithSyncCommittee:
      if is_next_sync_committee_known:
        return err(VerifierError.Duplicate)
      if attested_period != store_period or not is_sync_committee_update:
        return err(VerifierError.Duplicate)
    else:
      return err(VerifierError.Duplicate)

  # Verify that the `finality_branch`, if present, confirms `finalized_header`
  # to match the finalized checkpoint root saved in the state of
  # `attested_header`. Note that the genesis finalized checkpoint root is
  # represented as a zero hash.
  when update is SomeForkyLightClientUpdateWithFinality:
    if not update.is_finality_update:
      if update.finalized_header != default(typeof(update.finalized_header)):
        return err(VerifierError.Invalid)
    else:
      var finalized_root {.noinit.}: Eth2Digest
      if update.finalized_header.beacon.slot != GENESIS_SLOT:
        if not is_valid_light_client_header(update.finalized_header, cfg):
          return err(VerifierError.Invalid)
        finalized_root = hash_tree_root(update.finalized_header.beacon)
      elif update.finalized_header == default(typeof(update.finalized_header)):
        finalized_root.reset()
      else:
        return err(VerifierError.Invalid)
      if not is_valid_merkle_branch(
          finalized_root,
          update.finality_branch,
          log2trunc(altair.FINALIZED_ROOT_GINDEX),
          get_subtree_index(altair.FINALIZED_ROOT_GINDEX),
          update.attested_header.beacon.state_root):
        return err(VerifierError.Invalid)

  # Verify that the `next_sync_committee`, if present, actually is the
  # next sync committee saved in the state of the `attested_header`
  when update is SomeForkyLightClientUpdateWithSyncCommittee:
    if not is_sync_committee_update:
      if update.next_sync_committee !=
          default(typeof(update.next_sync_committee)):
        return err(VerifierError.Invalid)
    else:
      if attested_period == store_period and is_next_sync_committee_known:
        if update.next_sync_committee != store.next_sync_committee:
          return err(VerifierError.UnviableFork)
      if not is_valid_merkle_branch(
          hash_tree_root(update.next_sync_committee),
          update.next_sync_committee_branch,
          log2trunc(altair.NEXT_SYNC_COMMITTEE_GINDEX),
          get_subtree_index(altair.NEXT_SYNC_COMMITTEE_GINDEX),
          update.attested_header.beacon.state_root):
        return err(VerifierError.Invalid)

  # Verify sync committee aggregate signature
  let sync_committee =
    if signature_period == store_period:
      unsafeAddr store.current_sync_committee
    else:
      unsafeAddr store.next_sync_committee
  let
    fork_version_slot = max(update.signature_slot, 1.Slot) - 1
    fork_version = cfg.forkVersionAtEpoch(fork_version_slot.epoch)
    domain = compute_domain(
      DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
    signing_root = compute_signing_root(update.attested_header.beacon, domain)
  const maxParticipants = typeof(sync_aggregate.sync_committee_bits).bits
  if not blsFastAggregateVerify(
      allPublicKeys = sync_committee.pubkeys.data,
      fullParticipationAggregatePublicKey = sync_committee.aggregate_pubkey,
      bitseqs.BitArray[maxParticipants](
        bytes: sync_aggregate.sync_committee_bits.bytes),
      signing_root.data, sync_aggregate.sync_committee_signature):
    return err(VerifierError.UnviableFork)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#apply_light_client_update
func apply_light_client_update(
    store: var ForkyLightClientStore,
    update: SomeForkyLightClientUpdate): bool =
  var didProgress = false
  let
    store_period = store.finalized_header.beacon.slot.sync_committee_period
    finalized_period = update.finalized_header.beacon.slot.sync_committee_period
  if not store.is_next_sync_committee_known:
    assert finalized_period == store_period
    when update is SomeForkyLightClientUpdateWithSyncCommittee:
      store.next_sync_committee = update.next_sync_committee
      if store.is_next_sync_committee_known:
        didProgress = true
  elif finalized_period == store_period + 1:
    store.current_sync_committee = store.next_sync_committee
    when update is SomeForkyLightClientUpdateWithSyncCommittee:
      store.next_sync_committee = update.next_sync_committee
    else:
      store.next_sync_committee.reset()
    store.previous_max_active_participants =
      store.current_max_active_participants
    store.current_max_active_participants = 0
    didProgress = true
  if update.finalized_header.beacon.slot > store.finalized_header.beacon.slot:
    store.finalized_header = update.finalized_header
    if store.finalized_header.beacon.slot > store.optimistic_header.beacon.slot:
      store.optimistic_header = store.finalized_header
    didProgress = true
  didProgress

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#process_light_client_store_force_update
type
  ForceUpdateResult* = enum
    NoUpdate,
    DidUpdateWithoutSupermajority,
    DidUpdateWithoutFinality

func process_light_client_store_force_update*(
    store: var ForkyLightClientStore,
    current_slot: Slot): ForceUpdateResult {.discardable.} =
  var res = NoUpdate
  if store.best_valid_update.isSome and
      current_slot > store.finalized_header.beacon.slot + UPDATE_TIMEOUT:
    # Forced best update when the update timeout has elapsed.
    # Because the apply logic waits for `finalized_header.beacon.slot`
    # to indicate sync committee finality, the `attested_header` may be
    # treated as `finalized_header` in extended periods of non-finality
    # to guarantee progression into later sync committee periods according
    # to `is_better_update`.
    template best(): auto = store.best_valid_update.get
    if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot:
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#process_light_client_update
proc process_light_client_update*(
    store: var ForkyLightClientStore,
    update: SomeForkyLightClientUpdate,
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
    store.best_valid_update = Opt.some(update.toFull)
    didProgress = true

  # Track the maximum number of active participants in the committee signatures
  template sync_aggregate(): auto = update.sync_aggregate
  template sync_committee_bits(): auto = sync_aggregate.sync_committee_bits
  let num_active_participants = countOnes(sync_committee_bits).uint64
  if num_active_participants > store.current_max_active_participants:
    store.current_max_active_participants = num_active_participants

  # Update the optimistic header
  if num_active_participants > get_safety_threshold(store) and
      update.attested_header.beacon.slot > store.optimistic_header.beacon.slot:
    store.optimistic_header = update.attested_header
    didProgress = true

  # Update finalized header
  when update is SomeForkyLightClientUpdateWithFinality:
    if num_active_participants * 3 >= static(sync_committee_bits.len * 2):
      var improvesFinality =
        update.finalized_header.beacon.slot > store.finalized_header.beacon.slot
      when update is SomeForkyLightClientUpdateWithSyncCommittee:
        if not improvesFinality and not store.is_next_sync_committee_known:
          improvesFinality =
            update.is_sync_committee_update and update.is_finality_update and
            update.finalized_header.beacon.slot.sync_committee_period ==
            update.attested_header.beacon.slot.sync_committee_period
      if improvesFinality:
        # Normal update through 2/3 threshold
        if apply_light_client_update(store, update):
          didProgress = true
        store.best_valid_update.reset()

  if not didProgress:
    return err(VerifierError.Duplicate)
  ok()

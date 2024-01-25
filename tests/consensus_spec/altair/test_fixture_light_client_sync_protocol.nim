# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[algorithm, sequtils, sets],
  # Status libraries
  stew/bitops2,
  # Beacon chain internals
  ../../../beacon_chain/spec/datatypes/altair,
  ../../../beacon_chain/spec/
    [beaconstate, forks, helpers, light_client_sync, signatures,
    state_transition],
  # Mock helpers
  ../../mocking/mock_genesis,
  # Test utilities
  ../../testutil, ../../testblockutil

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/core/pyspec/eth2spec/test/helpers/sync_committee.py#L27-L44
proc compute_aggregate_sync_committee_signature(
    cfg: RuntimeConfig,
    forked: ForkedHashedBeaconState,
    signature_slot: Slot,
    participants: openArray[ValidatorIndex],
    block_root: Eth2Digest): ValidatorSig =
  template state(): auto = forked.altairData.data

  if len(participants) == 0:
    return ValidatorSig.infinity

  var
    aggregateSig {.noinit.}: AggregateSignature
    initialized = false
  for validator_index in participants:
    let
      privkey = MockPrivKeys[validator_index]
      signature = get_sync_committee_message_signature(
        state.fork,
        state.genesis_validators_root,
        signature_slot,
        block_root,
        privkey)
    if not initialized:
      initialized = true
      aggregateSig.init(signature)
    else:
      aggregateSig.aggregate(signature)
  aggregateSig.finish.toValidatorSig

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.3/tests/core/pyspec/eth2spec/test/helpers/light_client.py#L11-L41
proc get_sync_aggregate(
    cfg: RuntimeConfig,
    forked: ForkedHashedBeaconState,
    num_participants = SYNC_COMMITTEE_SIZE.uint64,
    signature_slot = FAR_FUTURE_SLOT): (SyncAggregate, Slot) =
  template state(): auto = forked.altairData.data

  let
    block_root =
      BeaconBlockHeader(
        slot: state.latest_block_header.slot,
        proposer_index: state.latest_block_header.proposer_index,
        parent_root: state.latest_block_header.parent_root,
        state_root: hash_tree_root(state),
        body_root: state.latest_block_header.body_root
      ).hash_tree_root()

  # By default, the sync committee signs the previous slot
    sig_slot =
      if signature_slot == FAR_FUTURE_SLOT:
        state.slot + 1
      else:
        signature_slot

  # Ensure correct sync committee and fork version are selected
  var
    signature_forked = assignClone(forked)
    cache: StateCache
    info: ForkedEpochInfo
  template signature_state(): auto = signature_forked.altairData.data
  process_slots(cfg, signature_forked[], sig_slot, cache, info, flags = {})
    .expect("no failure")

  # Fetch sync committee
  let
    all_pubkeys = signature_state.validators.mapIt(it.pubkey)
    committee_indices = signature_state.current_sync_committee.pubkeys
      .mapIt(all_pubkeys.find(it).ValidatorIndex)
    committee_size = lenu64(committee_indices)

  # By default, use full participation
  doAssert committee_size == SYNC_COMMITTEE_SIZE
  doAssert committee_size >= num_participants

  # Compute sync aggregate
  var sync_committee_bits: BitArray[SYNC_COMMITTEE_SIZE]
  for i in 0 ..< num_participants:
    sync_committee_bits[i] = true
  let
    sync_committee_signature = compute_aggregate_sync_committee_signature(
      cfg,
      signature_forked[],
      sig_slot,
      committee_indices[0 ..< num_participants],
      block_root)
    sync_aggregate = SyncAggregate(
      sync_committee_bits: sync_committee_bits,
      sync_committee_signature: sync_committee_signature
    )
  (sync_aggregate, sig_slot)

proc block_for_next_slot(
    cfg: RuntimeConfig,
    forked: var ForkedHashedBeaconState,
    cache: var StateCache,
    withAttestations = false): ForkedSignedBeaconBlock =
  template state(): auto = forked.altairData.data

  let attestations =
    if withAttestations:
      let block_root = withState(forked): forkyState.latest_block_root
      makeFullAttestations(forked, block_root, state.slot, cache)
    else:
      @[]

  addTestBlock(
    forked, cache, attestations = attestations, cfg = cfg)

let full_sync_committee_bits = block:
  var res: BitArray[SYNC_COMMITTEE_SIZE]
  res.bytes.fill(byte.high)
  res

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#initialize_light_client_store
func initialize_light_client_store(
    state: auto, storeDataFork: static LightClientDataFork): auto =
  storeDataFork.LightClientStore(
    finalized_header: default(storeDataFork.LightClientHeader),
    current_sync_committee: state.current_sync_committee,
    next_sync_committee: state.next_sync_committee,
    best_valid_update: Opt.none(storeDataFork.LightClientUpdate),
    optimistic_header: default(storeDataFork.LightClientHeader),
    previous_max_active_participants: 0,
    current_max_active_participants: 0,
  )

proc runTest(storeDataFork: static LightClientDataFork) =
  suite "EF - " & $storeDataFork &
      " - Unittests - Light client - Sync protocol" & preset():
    let
      cfg = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
        res
      genesisState = newClone(initGenesisState(cfg = cfg))

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.0/tests/core/pyspec/eth2spec/test/altair/unittests/light_client/test_sync_protocol.py#L32-L61
    test "test_process_light_client_update_not_timeout":
      let forked = assignClone(genesisState[])
      template state(): auto = forked[].altairData.data
      var store = initialize_light_client_store(state, storeDataFork)

      # Block at slot 1 doesn't increase sync committee period,
      # so it won't update snapshot
      var cache: StateCache
      let
        attested_block = block_for_next_slot(cfg, forked[], cache).altairData
        attested_header = attested_block.toLightClientHeader(storeDataFork)

      # Sync committee signing the attested_header
        (sync_aggregate, signature_slot) = get_sync_aggregate(cfg, forked[])
        next_sync_committee = SyncCommittee()
        next_sync_committee_branch = default(altair.NextSyncCommitteeBranch)

      # Ensure that finality checkpoint is genesis
      check state.finalized_checkpoint.epoch == 0
      # Finality is unchanged
      let
        finality_header = default(storeDataFork.LightClientHeader)
        finality_branch = default(altair.FinalityBranch)

        update = storeDataFork.LightClientUpdate(
          attested_header: attested_header,
          next_sync_committee: next_sync_committee,
          next_sync_committee_branch: next_sync_committee_branch,
          finalized_header: finality_header,
          finality_branch: finality_branch,
          sync_aggregate: sync_aggregate,
          signature_slot: signature_slot)

        pre_store_finalized_header = store.finalized_header

        res = process_light_client_update(
          store, update, signature_slot, cfg, state.genesis_validators_root)

      check:
        res.isOk
        store.finalized_header == pre_store_finalized_header
        store.best_valid_update.get == update
        store.optimistic_header == update.attested_header
        store.current_max_active_participants > 0

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.0/tests/core/pyspec/eth2spec/test/altair/unittests/light_client/test_sync_protocol.py#L64-L96
    test "test_process_light_client_update_at_period_boundary":
      var forked = assignClone(genesisState[])
      template state(): auto = forked[].altairData.data
      var store = initialize_light_client_store(state, storeDataFork)

      # Forward to slot before next sync committee period so that next block is
      # final one in period
      var
        cache: StateCache
        info: ForkedEpochInfo
      process_slots(
        cfg, forked[], Slot(UPDATE_TIMEOUT - 2), cache, info, flags = {}
      ).expect("no failure")
      let
        store_period = sync_committee_period(store.optimistic_header.beacon.slot)
        update_period = sync_committee_period(state.slot)
      check: store_period == update_period

      let
        attested_block = block_for_next_slot(cfg, forked[], cache).altairData
        attested_header = attested_block.toLightClientHeader(storeDataFork)

      # Sync committee signing the attested_header
        (sync_aggregate, signature_slot) = get_sync_aggregate(cfg, forked[])
        next_sync_committee = SyncCommittee()
        next_sync_committee_branch = default(altair.NextSyncCommitteeBranch)

      # Finality is unchanged
        finality_header = default(storeDataFork.LightClientHeader)
        finality_branch = default(altair.FinalityBranch)

        update = storeDataFork.LightClientUpdate(
          attested_header: attested_header,
          next_sync_committee: next_sync_committee,
          next_sync_committee_branch: next_sync_committee_branch,
          finalized_header: finality_header,
          finality_branch: finality_branch,
          sync_aggregate: sync_aggregate,
          signature_slot: signature_slot)

        pre_store_finalized_header = store.finalized_header

        res = process_light_client_update(
          store, update, signature_slot, cfg, state.genesis_validators_root)

      check:
        res.isOk
        store.finalized_header == pre_store_finalized_header
        store.best_valid_update.get == update
        store.optimistic_header == update.attested_header
        store.current_max_active_participants > 0

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.0/tests/core/pyspec/eth2spec/test/altair/unittests/light_client/test_sync_protocol.py#L99-L131
    test "process_light_client_update_timeout":
      let forked = assignClone(genesisState[])
      template state(): auto = forked[].altairData.data
      var store = initialize_light_client_store(state, storeDataFork)

      # Forward to next sync committee period
      var
        cache: StateCache
        info: ForkedEpochInfo
      process_slots(
        cfg, forked[], Slot(UPDATE_TIMEOUT), cache, info, flags = {}
      ).expect("no failure")
      let
        store_period = sync_committee_period(store.optimistic_header.beacon.slot)
        update_period = sync_committee_period(state.slot)
      check: store_period + 1 == update_period

      let
        attested_block = block_for_next_slot(cfg, forked[], cache).altairData
        attested_header = attested_block.toLightClientHeader(storeDataFork)

      # Sync committee signing the attested_header
        (sync_aggregate, signature_slot) = get_sync_aggregate(cfg, forked[])

      # Sync committee is updated
      template next_sync_committee(): auto = state.next_sync_committee
      let
        next_sync_committee_branch =
          state.build_proof(altair.NEXT_SYNC_COMMITTEE_GINDEX).get

      # Finality is unchanged
        finality_header = default(storeDataFork.LightClientHeader)
        finality_branch = default(altair.FinalityBranch)

        update = storeDataFork.LightClientUpdate(
          attested_header: attested_header,
          next_sync_committee: next_sync_committee,
          next_sync_committee_branch: next_sync_committee_branch,
          finalized_header: finality_header,
          finality_branch: finality_branch,
          sync_aggregate: sync_aggregate,
          signature_slot: signature_slot)

        pre_store_finalized_header = store.finalized_header

        res = process_light_client_update(
          store, update, signature_slot, cfg, state.genesis_validators_root)

      check:
        res.isOk
        store.finalized_header == pre_store_finalized_header
        store.best_valid_update.get == update
        store.optimistic_header == update.attested_header
        store.current_max_active_participants > 0

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.0/tests/core/pyspec/eth2spec/test/altair/unittests/light_client/test_sync_protocol.py#L134-L176
    test "process_light_client_update_finality_updated":
      let forked = assignClone(genesisState[])
      template state(): auto = forked[].altairData.data
      var store = initialize_light_client_store(state, storeDataFork)

      # Change finality
      var
        cache: StateCache
        info: ForkedEpochInfo
        blocks = newSeq[ForkedSignedBeaconBlock]()
      process_slots(
        cfg, forked[], Slot(SLOTS_PER_EPOCH * 2), cache, info, flags = {})
          .expect("no failure")
      for slot in 0 ..< 3 * SLOTS_PER_EPOCH:
        blocks.add block_for_next_slot(cfg, forked[], cache,
                                      withAttestations = true)
      # Ensure that finality checkpoint has changed
      check: state.finalized_checkpoint.epoch == 3
      # Ensure that it's same period
      let
        store_period = sync_committee_period(store.optimistic_header.beacon.slot)
        update_period = sync_committee_period(state.slot)
      check: store_period == update_period

      let
        attested_block = blocks[^1].altairData
        attested_header = attested_block.toLightClientHeader(storeDataFork)

      # Sync committee signing the attested_header
        (sync_aggregate, signature_slot) = get_sync_aggregate(cfg, forked[])

      # Updated sync_committee and finality
        next_sync_committee = SyncCommittee()
        next_sync_committee_branch = default(altair.NextSyncCommitteeBranch)
        finalized_block = blocks[SLOTS_PER_EPOCH - 1].altairData
        finalized_header = finalized_block.toLightClientHeader(storeDataFork)
      check:
        finalized_header.beacon.slot ==
          start_slot(state.finalized_checkpoint.epoch)
        finalized_header.beacon.hash_tree_root() ==
          state.finalized_checkpoint.root
      let
        finality_branch = state.build_proof(altair.FINALIZED_ROOT_GINDEX).get

        update = storeDataFork.LightClientUpdate(
          attested_header: attested_header,
          next_sync_committee: next_sync_committee,
          next_sync_committee_branch: next_sync_committee_branch,
          finalized_header: finalized_header,
          finality_branch: finality_branch,
          sync_aggregate: sync_aggregate,
          signature_slot: signature_slot)

        res = process_light_client_update(
          store, update, signature_slot, cfg, state.genesis_validators_root)

      check:
        res.isOk
        store.finalized_header == update.finalized_header
        store.best_valid_update.isNone
        store.optimistic_header == update.attested_header
        store.current_max_active_participants > 0

withAll(LightClientDataFork):
  when lcDataFork > LightClientDataFork.None:
    runTest(lcDataFork)

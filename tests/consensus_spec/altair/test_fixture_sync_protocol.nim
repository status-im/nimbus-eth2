# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
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
  ../../../beacon_chain/spec/
    [forks, helpers, light_client_sync, signatures, state_transition],
  # Mock helpers
  ../../mocking/[mock_blocks, mock_genesis],
  # Test utilities
  ../../testutil, ../../testblockutil

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/tests/core/pyspec/eth2spec/test/helpers/sync_committee.py#L27-L44
proc compute_aggregate_sync_committee_signature(
    forked: ForkedHashedBeaconState,
    participants: openArray[ValidatorIndex],
    block_root = ZERO_HASH): ValidatorSig =
  template state: untyped {.inject.} = forked.altairData.data

  if len(participants) == 0:
    return ValidatorSig.infinity

  let
    root =
      if block_root != ZERO_HASH: block_root
      else: mockBlockForNextSlot(forked).altairData.message.parent_root
    signing_root = sync_committee_msg_signing_root(
      state.fork, state.slot.epoch, state.genesis_validators_root, root)

  var
    aggregateSig {.noInit.}: AggregateSignature
    initialized = false
  for validator_index in participants:
    let
      privkey = MockPrivKeys[validator_index]
      signature = blsSign(privkey, signing_root.data)
    if not initialized:
      initialized = true
      aggregateSig.init(signature)
    else:
      aggregateSig.aggregate(signature)
  aggregateSig.finish.toValidatorSig

proc block_for_next_slot(
    cfg: RuntimeConfig,
    forked: var ForkedHashedBeaconState,
    cache: var StateCache,
    withAttestations = false): ForkedSignedBeaconBlock =
  template state: untyped {.inject.} = forked.altairData.data

  let parent_root = block:
    var previous_block_header = state.latest_block_header
    if previous_block_header.state_root == ZERO_HASH:
      previous_block_header.state_root = state.hash_tree_root()
    previous_block_header.hash_tree_root()

  let attestations =
    if withAttestations:
      makeFullAttestations(forked, parent_root, state.slot, cache)
    else:
      @[]

  addTestBlock(
    forked, parent_root, cache, attestations = attestations, cfg = cfg)

let full_sync_committee_bits = block:
  var res: BitArray[SYNC_COMMITTEE_SIZE]
  res.bytes.fill(byte.high)
  res

suite "Ethereum Foundation - Altair - Unittests - Sync protocol" & preset():
  let
    cfg = block:
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
      res
    genesisState = newClone(initGenesisState(cfg = cfg))

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/tests/core/pyspec/eth2spec/test/altair/unittests/test_sync_protocol.py#L22-L78
  test "process_light_client_update_not_updated":
    var forked = assignClone(genesisState[])
    template state: untyped {.inject.} = forked[].altairData.data

    let pre_snapshot = LightClientSnapshot(
      current_sync_committee: state.current_sync_committee,
      next_sync_committee: state.next_sync_committee)
    var store = LightClientStore(snapshot: pre_snapshot)

    # Block at slot 1 doesn't increase sync committee period,
    # so it won't update snapshot
    var cache = StateCache()
    let
      signed_block = block_for_next_slot(cfg, forked[], cache).altairData
      block_header = BeaconBlockHeader(
        slot: signed_block.message.slot,
        proposer_index: signed_block.message.proposer_index,
        parent_root: signed_block.message.parent_root,
        state_root: signed_block.message.state_root,
        body_root: signed_block.message.body.hash_tree_root())
    # Sync committee signing the header
      all_pubkeys = state.validators.mapIt(it.pubkey)
      committee = state.current_sync_committee.pubkeys
        .mapIt(all_pubkeys.find(it).ValidatorIndex)
      sync_committee_bits = full_sync_committee_bits
      sync_committee_signature = compute_aggregate_sync_committee_signature(
        forked[], committee)
    var next_sync_committee_branch:
      array[log2trunc(NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]

    # Ensure that finality checkpoint is genesis
    check: state.finalized_checkpoint.epoch == 0
    # Finality is unchanged
    let finality_header = BeaconBlockHeader()
    var finality_branch: array[log2trunc(FINALIZED_ROOT_INDEX), Eth2Digest]

    let update = LightClientUpdate(
      header: block_header,
      next_sync_committee: state.next_sync_committee,
      next_sync_committee_branch: next_sync_committee_branch,
      finality_header: finality_header,
      finality_branch: finality_branch,
      sync_committee_bits: sync_committee_bits,
      sync_committee_signature: sync_committee_signature,
      fork_version: state.fork.current_version)

    check:
      process_light_client_update(
        store, update, state.slot, state.genesis_validators_root)

      len(store.valid_updates) == 1
      store.valid_updates.pop() == update
      store.snapshot == pre_snapshot

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0/tests/core/pyspec/eth2spec/test/altair/unittests/test_sync_protocol.py#L84-L147
  test "process_light_client_update_timeout":
    var forked = assignClone(genesisState[])
    template state: untyped {.inject.} = forked[].altairData.data

    let pre_snapshot = LightClientSnapshot(
      current_sync_committee: state.current_sync_committee,
      next_sync_committee: state.next_sync_committee)
    var store = LightClientStore(snapshot: pre_snapshot)

    # Forward to next sync committee period
    var
      cache = StateCache()
      info = ForkedEpochInfo()
    doAssert process_slots(
      cfg, forked[], Slot(SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD),
      cache, info, flags = {})
    let
      snapshot_period = sync_committee_period(pre_snapshot.header.slot)
      update_period = sync_committee_period(state.slot)
    check: snapshot_period + 1 == update_period

    let
      signed_block = block_for_next_slot(cfg, forked[], cache).altairData
      block_header = BeaconBlockHeader(
        slot: signed_block.message.slot,
        proposer_index: signed_block.message.proposer_index,
        parent_root: signed_block.message.parent_root,
        state_root: signed_block.message.state_root,
        body_root: signed_block.message.body.hash_tree_root())

    # Sync committee signing the finalized_block_header
      all_pubkeys = state.validators.mapIt(it.pubkey)
      committee = state.current_sync_committee.pubkeys
        .mapIt(all_pubkeys.find(it).ValidatorIndex)
      sync_committee_bits = full_sync_committee_bits
      sync_committee_signature = compute_aggregate_sync_committee_signature(
        forked[], committee, block_root = block_header.hash_tree_root())

    # Sync committee is updated
    var next_sync_committee_branch {.noinit.}:
      array[log2trunc(NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]
    build_proof(state, NEXT_SYNC_COMMITTEE_INDEX, next_sync_committee_branch)
    # Finality is unchanged
    let finality_header = BeaconBlockHeader()
    var finality_branch: array[log2trunc(FINALIZED_ROOT_INDEX), Eth2Digest]

    let update = LightClientUpdate(
      header: block_header,
      next_sync_committee: state.next_sync_committee,
      next_sync_committee_branch: next_sync_committee_branch,
      finality_header: finality_header,
      finality_branch: finality_branch,
      sync_committee_bits: sync_committee_bits,
      sync_committee_signature: sync_committee_signature,
      fork_version: state.fork.current_version)

    check:
      process_light_client_update(
        store, update, state.slot, state.genesis_validators_root)

      # snapshot has been updated
      len(store.valid_updates) == 0
      store.snapshot.header == update.header

  # https://github.com/ethereum/consensus-specs/blob/v1.1.3/tests/core/pyspec/eth2spec/test/altair/unittests/test_sync_protocol.py#L150-L218
  test "process_light_client_update_finality_updated":
    var forked = assignClone(genesisState[])
    template state: untyped {.inject.} = forked[].altairData.data

    let pre_snapshot = LightClientSnapshot(
      current_sync_committee: state.current_sync_committee,
      next_sync_committee: state.next_sync_committee)
    var store = LightClientStore(snapshot: pre_snapshot)

    # Change finality
    var
      cache = StateCache()
      info = ForkedEpochInfo()
      blocks = newSeq[ForkedSignedBeaconBlock]()
    doAssert process_slots(
      cfg, forked[], Slot(SLOTS_PER_EPOCH * 2), cache, info, flags = {})
    for epoch in 0 ..< 3:
      for slot in 0 ..< SLOTS_PER_EPOCH:
        blocks.add block_for_next_slot(cfg, forked[], cache,
                                        withAttestations = true)
    # Ensure that finality checkpoint has changed
    check: state.finalized_checkpoint.epoch == 3
    # Ensure that it's same period
    let
      snapshot_period = sync_committee_period(pre_snapshot.header.slot)
      update_period = sync_committee_period(state.slot)
    check: snapshot_period == update_period

    # Updated sync_committee and finality
    var next_sync_committee_branch:
      array[log2trunc(NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]
    let
      finalized_block = blocks[SLOTS_PER_EPOCH - 1].altairData
      finalized_block_header = BeaconBlockHeader(
        slot: finalized_block.message.slot,
        proposer_index: finalized_block.message.proposer_index,
        parent_root: finalized_block.message.parent_root,
        state_root: finalized_block.message.state_root,
        body_root: finalized_block.message.body.hash_tree_root())
    check:
      finalized_block_header.slot ==
        compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
      finalized_block_header.hash_tree_root() ==
        state.finalized_checkpoint.root
    var finality_branch {.noinit.}:
      array[log2trunc(FINALIZED_ROOT_INDEX), Eth2Digest]
    build_proof(state, FINALIZED_ROOT_INDEX, finality_branch)

    # Build block header
    let
      blck = mockBlock(forked[], state.slot, cfg = cfg).altairData.message
      block_header = BeaconBlockHeader(
        slot: blck.slot,
        proposer_index: blck.proposer_index,
        parent_root: blck.parent_root,
        state_root: state.hash_tree_root(),
        body_root: blck.body.hash_tree_root())

    # Sync committee signing the finalized_block_header
      all_pubkeys = state.validators.mapIt(it.pubkey)
      committee = state.current_sync_committee.pubkeys
        .mapIt(all_pubkeys.find(it).ValidatorIndex)
      sync_committee_bits = full_sync_committee_bits
      sync_committee_signature = compute_aggregate_sync_committee_signature(
        forked[], committee, block_root = block_header.hash_tree_root())

      update = LightClientUpdate(
        header: finalized_block_header,
        next_sync_committee: state.next_sync_committee,
        next_sync_committee_branch: next_sync_committee_branch,
        finality_header: block_header,
        finality_branch: finality_branch,
        sync_committee_bits: sync_committee_bits,
        sync_committee_signature: sync_committee_signature,
        fork_version: state.fork.current_version)

    check:
      process_light_client_update(
        store, update, state.slot, state.genesis_validators_root)

      # snapshot has been updated
      len(store.valid_updates) == 0
      store.snapshot.header == update.header

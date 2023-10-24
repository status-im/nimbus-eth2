# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

# Test for spec functions and helpers outside of the EF test vectors - mainly
# helpers that extend or make the spec functions usable outside of the state
# transition functions

import
  unittest2,
  ../beacon_chain/spec/beaconstate,
  ./testutil, ./testblockutil

from ../beacon_chain/spec/state_transition import process_slots

suite "Beacon state" & preset():
  setup:
    let cfg = defaultRuntimeConfig

  test "Smoke test initialize_beacon_state_from_eth1" & preset():
    let state = newClone(initialize_beacon_state_from_eth1(
      cfg, ZERO_HASH, 0, makeInitialDeposits(SLOTS_PER_EPOCH, {}),
      default(bellatrix.ExecutionPayloadHeader), {}))
    check: state.validators.lenu64 == SLOTS_PER_EPOCH

  test "process_slots":
    var
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipBlsValidation}))
      cache: StateCache
      info: ForkedEpochInfo
    check:
      process_slots(cfg, state[], Slot 1, cache, info, {}).isOk()
      process_slots(cfg, state[], Slot 1, cache, info, {}).isErr()
      process_slots(cfg, state[], Slot 1, cache, info, {slotProcessed}).isOk()

  test "latest_block_root":
    var
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipBlsValidation}))
      genBlock = get_initial_beacon_block(state[])
      cache: StateCache
      info: ForkedEpochInfo

    check: # Works for genesis block
      state[].phase0Data.latest_block_root == genBlock.root
      state[].phase0Data.latest_block_id == genBlock.toBlockId()

      process_slots(cfg, state[], Slot 1, cache, info, {}).isOk()
      state[].phase0Data.latest_block_root == genBlock.root

    let blck = addTestBlock(
      state[], cache, nextSlot = false, flags = {skipBlsValidation}).phase0Data

    check: # Works for random blocks
      state[].phase0Data.latest_block_root == blck.root
      process_slots(cfg, state[], Slot 2, cache, info, {}).isOk()
      state[].phase0Data.latest_block_root == blck.root

  test "get_beacon_proposer_index":
    var
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipBlsValidation}))
      cache: StateCache
      info: ForkedEpochInfo

    check:
      get_beacon_proposer_index(state[].phase0Data.data, cache, Slot 1).isSome()
      get_beacon_proposer_index(
        state[].phase0Data.data, cache, Epoch(1).start_slot()).isNone()
      get_beacon_proposer_index(
        state[].phase0Data.data, cache, Epoch(2).start_slot()).isNone()

    check:
      process_slots(cfg, state[], Epoch(1).start_slot(), cache, info, {}).isOk()
      get_beacon_proposer_index(state[].phase0Data.data, cache, Slot 1).isNone()
      get_beacon_proposer_index(
        state[].phase0Data.data, cache, Epoch(1).start_slot()).isSome()
      get_beacon_proposer_index(
        state[].phase0Data.data, cache, Epoch(2).start_slot()).isNone()

  test "dependent_root":
    var
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipBlsValidation}))
      genBlock = get_initial_beacon_block(state[])
      cache: StateCache
      info: ForkedEpochInfo

    check:
      state[].phase0Data.dependent_root(Epoch(0)) == genBlock.root

    while getStateField(state[], slot).epoch < Epoch(1):
      discard addTestBlock(state[], cache)

    check:
      state[].phase0Data.dependent_root(Epoch(1)) ==
        state[].phase0Data.data.get_block_root_at_slot(Epoch(1).start_slot - 1)
      state[].phase0Data.dependent_root(Epoch(0)) == genBlock.root

    while getStateField(state[], slot).epoch < Epoch(2):
      discard addTestBlock(state[], cache)

    check:
      state[].phase0Data.dependent_root(Epoch(2)) ==
        state[].phase0Data.data.get_block_root_at_slot(Epoch(2).start_slot - 1)
      state[].phase0Data.dependent_root(Epoch(1)) ==
        state[].phase0Data.data.get_block_root_at_slot(Epoch(1).start_slot - 1)
      state[].phase0Data.dependent_root(Epoch(0)) == genBlock.root

  test "merklizer state roundtrip":
    let
      dcs = DepositContractState()
      merkleizer = DepositsMerkleizer.init(dcs)

    check:
      dcs == merkleizer.toDepositContractState()

  test "can_advance_slots":
    var
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipBlsValidation}))
      genBlock = get_initial_beacon_block(state[])
      cache: StateCache
      info: ForkedEpochInfo

    check:
      state[].can_advance_slots(genBlock.root, Slot(0))
      state[].can_advance_slots(genBlock.root, Slot(0))
      state[].can_advance_slots(genBlock.root, Slot(0))

    let blck = addTestBlock(
      state[], cache, flags = {skipBlsValidation})

    check:
      not state[].can_advance_slots(genBlock.root, Slot(0))
      not state[].can_advance_slots(genBlock.root, Slot(0))
      not state[].can_advance_slots(genBlock.root, Slot(0))
      not state[].can_advance_slots(blck.root, Slot(0))
      state[].can_advance_slots(blck.root, Slot(1))
      state[].can_advance_slots(blck.root, Slot(2))

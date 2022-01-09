# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
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
  ../beacon_chain/spec/datatypes/phase0,
  ../beacon_chain/spec/[beaconstate, state_transition],
  ./testutil, ./testblockutil

suite "Beacon state" & preset():
  test "Smoke test initialize_beacon_state_from_eth1" & preset():
    let state = newClone(initialize_beacon_state_from_eth1(
      defaultRuntimeConfig, Eth2Digest(), 0,
      makeInitialDeposits(SLOTS_PER_EPOCH, {}), {}))
    check: state.validators.lenu64 == SLOTS_PER_EPOCH

  test "latest_block_root":
    var
      cfg = defaultRuntimeConfig
      state = (ref ForkedHashedBeaconState)(
        kind: BeaconStateFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, Eth2Digest(), 0,
          makeInitialDeposits(SLOTS_PER_EPOCH, {}), {skipBlsValidation}))
      genBlock = get_initial_beacon_block(state[])
      cache: StateCache
      info: ForkedEpochInfo

    check: # Works for genesis block
      state[].phase0Data.latest_block_root() == genBlock.root
      process_slots(cfg, state[], Slot 1, cache, info, {})
      state[].phase0Data.latest_block_root() == genBlock.root

    let blck = addTestBlock(
      state[], cache, nextSlot = false, flags = {skipBlsValidation}).phase0Data

    check: # Works for random blocks
      state[].phase0Data.latest_block_root() == blck.root
      process_slots(cfg, state[], Slot 2, cache, info, {})
      state[].phase0Data.latest_block_root() == blck.root

  test "get_beacon_proposer_index":
    var
      cfg = defaultRuntimeConfig
      state = (ref ForkedHashedBeaconState)(
        kind: BeaconStateFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, Eth2Digest(), 0,
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
      process_slots(cfg, state[], Epoch(1).start_slot(), cache, info, {})
      get_beacon_proposer_index(state[].phase0Data.data, cache, Slot 1).isNone()
      get_beacon_proposer_index(
        state[].phase0Data.data, cache, Epoch(1).start_slot()).isSome()
      get_beacon_proposer_index(
        state[].phase0Data.data, cache, Epoch(2).start_slot()).isNone()

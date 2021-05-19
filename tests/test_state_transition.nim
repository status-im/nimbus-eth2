# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronicles,
  unittest2,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[beaconstate, datatypes, digest, crypto,
                        validator, state_transition, presets],
  ../beacon_chain/ssz

proc makeAttestation(
    state: BeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, cache: var StateCache): Attestation =
  # The called functions don't use the extra-BeaconState parts of StateData.
  let
    stateData = (ref StateData)(
      data: HashedBeaconState(data: state),
      blck: BlockRef(root: beacon_block_root, slot: state.slot))
    (committee, slot, index) =
      find_beacon_committee(stateData[], validator_index, cache)
  makeAttestation(stateData[], beacon_block_root, committee, slot, index,
    validator_index, cache)

suite "Block processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  let
    # Genesis state with minimal number of deposits
    # TODO bls verification is a bit of a bottleneck here
    genesisState = newClone(initialize_hashed_beacon_state_from_eth1(
      defaultRuntimePreset, Eth2Digest(), 0, makeInitialDeposits(), {}))
    genesisBlock = get_initial_beacon_block(genesisState.data)
    genesisRoot = hash_tree_root(genesisBlock.message)

  setup:
    var
      state = newClone(genesisState[])
      cache = StateCache()
      rewards = RewardInfo()

  test "Passes from genesis state, no block" & preset():
    check:
      process_slots(state[], state.data.slot + 1, cache, rewards)
      state.data.slot == genesisState.data.slot + 1

  test "Passes from genesis state, empty block" & preset():
    var
      previous_block_root = genesisBlock.root
      new_block = makeTestBlock(state[], previous_block_root, cache)

    let block_ok = state_transition(
      defaultRuntimePreset, state[], new_block, cache, rewards, {}, noRollback)

    check:
      block_ok

      state.data.slot == genesisState.data.slot + 1

  test "Passes through epoch update, no block" & preset():
    check:
      process_slots(state[], Slot(SLOTS_PER_EPOCH), cache, rewards)
      state.data.slot == genesisState.data.slot + SLOTS_PER_EPOCH

  test "Passes through epoch update, empty block" & preset():
    var
      previous_block_root = genesisRoot

    for i in 1..SLOTS_PER_EPOCH:
      let new_block = makeTestBlock(state[], previous_block_root, cache)

      let block_ok = state_transition(
        defaultRuntimePreset, state[], new_block, cache, rewards, {}, noRollback)

      check:
        block_ok

      previous_block_root = new_block.root

    check:
      state.data.slot == genesisState.data.slot + SLOTS_PER_EPOCH

  test "Attestation gets processed at epoch" & preset():
    var
      previous_block_root = genesisRoot

    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(state[], state.data.slot + 1, cache, rewards)

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      beacon_committee =
        get_beacon_committee(state.data, state.data.slot, 0.CommitteeIndex, cache)
      attestation = makeAttestation(
        state.data, previous_block_root, beacon_committee[0], cache)

    # Some time needs to pass before attestations are included - this is
    # to let the attestation propagate properly to interested participants
    check:
      process_slots(
        state[], GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY + 1, cache,
        rewards)

    let
      new_block = makeTestBlock(state[], previous_block_root, cache,
        attestations = @[attestation]
      )
    check state_transition(
      defaultRuntimePreset, state[], new_block, cache, rewards, {}, noRollback)

    check:
      # TODO epoch attestations can get multiplied now; clean up paths to
      # enable exact 1-check again and keep finalization.
      state.data.current_epoch_attestations.len >= 1

    check:
      process_slots(state[], Slot(191), cache, rewards)

    # Would need to process more epochs for the attestation to be removed from
    # the state! (per above bug)
    #
    # check:
    #  state.latest_attestations.len == 0

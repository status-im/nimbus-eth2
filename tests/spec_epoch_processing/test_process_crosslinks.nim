# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# process_crosslinks (state_transition_epoch.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#crosslinks
# ---------------------------------------------------------------

import
  # Standard library
  unittest,
  # Specs
  ../../beacon_chain/spec/[beaconstate, datatypes, validator, helpers, state_transition_epoch],
  # Internals

  # Mock helpers
  ../mocking/[mock_genesis, mock_attestations, mock_state, mock_blocks],
  ./epoch_utils,
  ../testutil

suite "[Unit - Spec - Epoch processing] Crosslinks " & preset():

  const NumValidators = uint64(8) * SLOTS_PER_EPOCH
  let genesisState = initGenesisState(NumValidators)
  doAssert genesisState.validators.len == int NumValidators

  var state: BeaconState
  template resetState: untyped =
    deepCopy(state, genesisState)

  test "No attestations":
    resetState()

    transitionEpochUntilCrosslinks(state)

    for shard in 0 ..< SHARD_COUNT:
      check state.previous_crosslinks[shard] == state.current_crosslinks[shard]

  test "Single crosslink update from current epoch":
    resetState()

    nextEpoch(state)
    var attestation = mockAttestation(state)
    fillAggregateAttestation(state, attestation)

    state.add(attestation, state.slot + MIN_ATTESTATION_INCLUSION_DELAY)

    # TODO: all attestations are duplicated at the moment
    # pending fix of https://github.com/status-im/nim-beacon-chain/issues/361
    check: state.current_epoch_attestations.len == 2

    # For sanity checks
    let shard = attestation.data.crosslink.shard
    let pre_crosslink = state.current_crosslinks[shard]

    transitionEpochUntilCrosslinks(state)

    check:
      state.previous_crosslinks[shard] != state.current_crosslinks[shard]
      pre_crosslink != state.current_crosslinks[shard]

  test "Double late crosslink":
    resetState()

    if get_committee_count(state, get_current_epoch(state)) < SHARD_COUNT:
      echo "        [Warning] Skipping Double-late crosslink test: Committee.len < SHARD_COUNT for preset " & const_preset
    else:
      nextEpoch(state)
      state.slot += 4

      var attestation_1 = mockAttestation(state)
      fillAggregateAttestation(state, attestation_1)

      # Add attestation_1 to next epoch
      nextEpoch(state)
      state.add(attestation_1, state.slot + 1)

      var attestation_2: Attestation
      for _ in 0 ..< SLOTS_PER_EPOCH:
        attestation_2 = mockAttestation(state)
        if attestation_2.data.crosslink.shard == attestation_1.data.crosslink.shard:
          signMockAttestation(state, attestation_2)
          break
        nextSlot(state)
      applyEmptyBlock(state)

      fillAggregateAttestation(state, attestation_2)

      # Add attestation_2 in the next epoch after attestation_1 has already
      # updated the relevant crosslink
      nextEpoch(state)
      state.add(attestation_2, state.slot + 1)

      # TODO: all attestations are duplicated at the moment
      # pending fix of https://github.com/status-im/nim-beacon-chain/issues/361
      check: state.previous_epoch_attestations.len == 2
      check: state.current_epoch_attestations.len == 0

      var cache = get_empty_per_epoch_cache()
      let crosslink_deltas = get_crosslink_deltas(state, cache)

      transitionEpochUntilCrosslinks(state)

      let shard = attestation_2.data.crosslink.shard

      # ensure that the current crosslinks were not updated by the second attestation
      check: state.previous_crosslinks[shard] == state.current_crosslinks[shard]
      # ensure no reward, only penalties for the failed crosslink
      for index in get_crosslink_committee(
                     state,
                     attestation_2.data.target.epoch,
                     attestation_2.data.crosslink.shard,
                     cache
                   ):
        check:
          crosslink_deltas[0][index] == 0.Gwei
          crosslink_deltas[1][index]  > 0.Gwei

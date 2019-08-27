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
  ../../beacon_chain/spec/[beaconstate, datatypes, validator],
  # Internals

  # Mock helpers
  ../mocking/[mock_genesis, mock_attestations, mock_state],
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

    # TODO: pending fix of https://github.com/status-im/nim-beacon-chain/issues/361
    # check: state.current_epoch_attestations.len == 1

    # For sanity checks
    let shard = attestation.data.crosslink.shard
    let pre_crosslink = state.current_crosslinks[shard]

    transitionEpochUntilCrosslinks(state)

    check:
      state.previous_crosslinks[shard] != state.current_crosslinks[shard]
      pre_crosslink != state.current_crosslinks[shard]

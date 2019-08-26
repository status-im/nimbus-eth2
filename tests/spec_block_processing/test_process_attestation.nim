# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# process_attestation (beaconstate.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/core/0_beacon-chain.md#attestations
# ---------------------------------------------------------------

import
  # Standard library
  unittest, math,
  # Specs
  ../../beacon_chain/spec/[beaconstate, datatypes, helpers, validator],
  # Internals
  ../../beacon_chain/[state_transition],
  # Mock helpers
  ../mocking/[mock_genesis, mock_attestations],
  ../testutil

suite "[Unit - Spec - Block processing] Attestations " & preset():

  const NumValidators = uint64(8) * SLOTS_PER_EPOCH
  let genesisState = initGenesisState(NumValidators)
  doAssert genesisState.validators.len == int NumValidators

  template valid_attestation(name: string, body: untyped): untyped {.dirty.}=
    # Process a valid attestation
    #
    # The BeaconState is exposed as "state" in the calling context
    # The attestation to process must be named "attestation" in the calling context

    test name:
      var state{.inject.}: BeaconState
      deepCopy(state, genesisState)

      # Attestation setup body
      # ----------------------------------------
      body

      # Params for sanity checks
      # ----------------------------------------
      let
        current_epoch_count = state.current_epoch_attestations.len
        previous_epoch_count = state.previous_epoch_attestations.len

      # State transition
      # ----------------------------------------
      var cache = get_empty_per_epoch_cache()
      check process_attestation(
        state, attestation, flags = {}, cache
      )

      # Check that the attestation was processed
      if attestation.data.target.epoch == state.get_current_epoch():
        check(state.current_epoch_attestations.len == current_epoch_count + 1)
      else:
        check(state.previous_epoch_attestations.len == previous_epoch_count + 1)

  valid_attestation("Valid attestation"):
    let attestation = mockAttestation(state)
    state.slot += MIN_ATTESTATION_INCLUSION_DELAY

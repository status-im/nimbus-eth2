# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# process_attestation (beaconstate.nim)
# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#attestations
# ---------------------------------------------------------------

{.used.}

import
  stew/results,
  # Specs
  ../../beacon_chain/spec/[beaconstate, forks, helpers],
  ../../beacon_chain/spec/datatypes/base,
  # Mock helpers
  ../mocking/[mock_genesis, mock_attestations, mock_state],
  ../testutil

suite "[Unit - Spec - Block processing] Attestations " & preset():

  const NumValidators = uint64(8) * SLOTS_PER_EPOCH
  let genesisState = initGenesisState(NumValidators)

  doAssert getStateField(genesisState[], validators).lenu64 == NumValidators

  template valid_attestation(name: string, body: untyped): untyped {.dirty.}=
    # Process a valid attestation
    #
    # The BeaconState is exposed as "state" in the calling context
    # The attestation to process must be named "attestation" in the calling context

    test name:
      var state {.inject.} = newClone(genesisState[])

      # Attestation setup body
      # ----------------------------------------
      body

      # Params for sanity checks
      # ----------------------------------------
      let
        current_epoch_count =
          state.phase0Data.data.current_epoch_attestations.len
        previous_epoch_count =
          state.phase0Data.data.previous_epoch_attestations.len

      # State transition
      # ----------------------------------------
      var cache = StateCache()
      check process_attestation(
        state.phase0Data.data, attestation, flags = {}, 0.Gwei, cache
      ).isOk

      # Check that the attestation was processed
      if attestation.data.target.epoch == get_current_epoch(state[]):
        check(state.phase0Data.data.current_epoch_attestations.len ==
          current_epoch_count + 1)
      else:
        check(state.phase0Data.data.previous_epoch_attestations.len ==
          previous_epoch_count + 1)

  valid_attestation("Valid attestation"):
    let attestation = mockAttestation(state.phase0Data.data)
    getStateField(state[], slot) += MIN_ATTESTATION_INCLUSION_DELAY

  valid_attestation("Valid attestation from previous epoch"):
    nextSlot(state[])
    let attestation = mockAttestation(state.phase0Data.data)
    getStateField(state[], slot) = Slot(SLOTS_PER_EPOCH - 1)
    nextEpoch(state[])

  # TODO: regression BLS V0.10.1
  echo "[Skipping] \"Empty aggregation bit\""

  # valid_attestation("Empty aggregation bit"):
  #   var attestation = mockAttestation(state)
  #   state.data.slot += MIN_ATTESTATION_INCLUSION_DELAY

  #   # Overwrite committee
  #   attestation.aggregation_bits = init(CommitteeValidatorsBits, attestation.aggregation_bits.len)
  #   signMockAttestation(state, attestation)

# TODO - invalid attestations
# - Wrong end epoch
# - Invalid signature
# - Before inclusion delay
# - past last inclusion slot
# - before oldest known source epoch
# - wrong shard
# - invalid shard
# - target epoch too old
# - target epoch too far in the future
# - source epoch in the future
# - invalid current source root
# - bad source root
# - inconsistent custody bits length
# - non-empty custody bits in phase 0

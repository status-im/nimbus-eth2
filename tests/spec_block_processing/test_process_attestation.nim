# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# process_attestation (beaconstate.nim)
# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/core/0_beacon-chain.md#attestations
# ---------------------------------------------------------------

{.used.}

import
  # Standard library
  unittest,
  # Specs
  ../../beacon_chain/spec/[beaconstate, datatypes, helpers, validator],
  # Mock helpers
  ../mocking/[mock_genesis, mock_attestations, mock_state, mock_blocks],
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

    timedTest name:
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

  valid_attestation("Valid attestation from previous epoch"):
    let attestation = mockAttestation(state)
    state.slot = Slot(SLOTS_PER_EPOCH - 1)
    nextEpoch(state)
    applyEmptyBlock(state)

  # TODO check if this should be replaced
  when false:
    when MAX_EPOCHS_PER_CROSSLINK > 4'u64:
      timedTest "Valid attestation since max epochs per crosslinks [Skipped for preset: " & const_preset & ']':
        discard
    else:
      valid_attestation("Valid attestation since max epochs per crosslinks"):
        for _ in 0 ..< MAX_EPOCHS_PER_CROSSLINK + 2:
          nextEpoch(state)
        applyEmptyBlock(state)

        let attestation = mockAttestation(state)
        check: attestation.data.crosslink.end_epoch - attestation.data.crosslink.start_epoch == MAX_EPOCHS_PER_CROSSLINK

        for _ in 0 ..< MIN_ATTESTATION_INCLUSION_DELAY:
          nextSlot(state)

  valid_attestation("Empty aggregation bit"):
    var attestation = mockAttestation(state)
    state.slot += MIN_ATTESTATION_INCLUSION_DELAY

    # Overwrite committee
    attestation.aggregation_bits = init(CommitteeValidatorsBits, attestation.aggregation_bits.len)
    signMockAttestation(state, attestation)

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


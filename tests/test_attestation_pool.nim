# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils, unittest,
  ./testutil,
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[attestation_pool, extras, state_transition, ssz]

suite "Attestation pool processing":
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  let
    # Genesis state with minimal number of deposits
    # TODO bls verification is a bit of a bottleneck here
    genesisState = get_initial_beacon_state(
      makeInitialDeposits(), 0, Eth1Data(), {skipValidation})
    genesisBlock = makeGenesisBlock(genesisState)
    genesisRoot = hash_tree_root_final(genesisBlock)

  test "Can add and retrieve simple attestation":
    var
      pool = init(AttestationPool, 42)
      state = genesisState
    # Slot 0 is a finalized slot - won't be making attestations for it..
    discard updateState(
        state, genesisRoot, none(BeaconBlock), {skipValidation})

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      crosslink_committees = get_crosslink_committees_at_slot(state, state.slot)
      attestation = makeAttestation(
        state, genesisRoot, crosslink_committees[0].committee[0])

    pool.add(attestation, state)

    let attestations = pool.getAttestationsForBlock(
      state, state.slot + MIN_ATTESTATION_INCLUSION_DELAY)

    check:
      attestations.len == 1

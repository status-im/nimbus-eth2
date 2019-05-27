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
  ../beacon_chain/[beacon_node_types, attestation_pool, block_pool, extras, state_transition, ssz]

suite "Attestation pool processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  # Genesis state with minimal number of deposits
  let
    genState = get_genesis_beacon_state(
      makeInitialDeposits(flags = {skipValidation}), 0, Eth1Data(),
        {skipValidation})
    genBlock = get_initial_beacon_block(genState)

  test "Can add and retrieve simple attestation" & preset():
    var
      blockPool = BlockPool.init(makeTestDB(genState, genBlock))
      pool = AttestationPool.init(blockPool)
      state = blockPool.loadTailState()
    # Slot 0 is a finalized slot - won't be making attestations for it..
    advanceState(state.data)

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      crosslink_committees =
        get_crosslink_committees_at_slot(state.data.data, state.data.data.slot)
      attestation = makeAttestation(
        state.data.data, state.blck.root, crosslink_committees[0].committee[0])

    pool.add(state.data.data, attestation)

    let attestations = pool.getAttestationsForBlock(
      state.data.data, state.data.data.slot + MIN_ATTESTATION_INCLUSION_DELAY)

    # TODO test needs fixing for new attestation validation
    # check:
    #   attestations.len == 1

  test "Attestations may arrive in any order" & preset():
    var
      blockPool = BlockPool.init(makeTestDB(genState, genBlock))
      pool = AttestationPool.init(blockPool)
      state = blockPool.loadTailState()
    # Slot 0 is a finalized slot - won't be making attestations for it..
    advanceState(state.data)

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      crosslink_committees1 =
        get_crosslink_committees_at_slot(state.data.data, state.data.data.slot)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, crosslink_committees1[0].committee[0])

    advanceState(state.data)

    let
      crosslink_committees2 =
        get_crosslink_committees_at_slot(state.data.data, state.data.data.slot)
      attestation2 = makeAttestation(
        state.data.data, state.blck.root, crosslink_committees2[0].committee[0])

    # test reverse order
    pool.add(state.data.data, attestation2)
    pool.add(state.data.data, attestation1)

    let attestations = pool.getAttestationsForBlock(
      state.data.data, state.data.data.slot + MIN_ATTESTATION_INCLUSION_DELAY)

    # TODO test needs fixing for new attestation validation
    # check:
    #   attestations.len == 1

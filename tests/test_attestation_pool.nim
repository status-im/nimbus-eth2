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
  ../beacon_chain/[attestation_pool, block_pool, extras, state_transition, ssz]

suite "Attestation pool processing":
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  # Genesis state with minimal number of deposits
  var
    genState = get_genesis_beacon_state(
      makeInitialDeposits(flags = {skipValidation}), 0, Eth1Data(),
        {skipValidation})
    genBlock = get_initial_beacon_block(genState)

    blockPool = BlockPool.init(makeTestDB(genState, genBlock))

  test "Can add and retrieve simple attestation":
    var
      pool = AttestationPool.init(blockPool)
      state = blockPool.loadTailState()
    # Slot 0 is a finalized slot - won't be making attestations for it..
    advanceState(state.data, state.blck.root)

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      crosslink_committees =
        get_crosslink_committees_at_slot(state.data, state.data.slot)
      attestation = makeAttestation(
        state.data, state.blck.root, crosslink_committees[0].committee[0])

    pool.add(state.data, attestation)

    let attestations = pool.getAttestationsForBlock(
      state.data.slot + MIN_ATTESTATION_INCLUSION_DELAY)

    check:
      attestations.len == 1

  test "Attestations may arrive in any order":
    var
      pool = AttestationPool.init(blockPool)
      state = blockPool.loadTailState()
    # Slot 0 is a finalized slot - won't be making attestations for it..
    advanceState(state.data, state.blck.root)

    let
      # Create an attestation for slot 1 signed by the only attester we have!
      crosslink_committees1 =
        get_crosslink_committees_at_slot(state.data, state.data.slot)
      attestation1 = makeAttestation(
        state.data, state.blck.root, crosslink_committees1[0].committee[0])

    advanceState(state.data, state.blck.root)

    let
      crosslink_committees2 =
        get_crosslink_committees_at_slot(state.data, state.data.slot)
      attestation2 = makeAttestation(
        state.data, state.blck.root, crosslink_committees2[0].committee[0])

    # test reverse order
    pool.add(state.data, attestation2)
    pool.add(state.data, attestation1)

    let attestations = pool.getAttestationsForBlock(
      state.data.slot + MIN_ATTESTATION_INCLUSION_DELAY)

    check:
      attestations.len == 1

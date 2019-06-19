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

template withPool(body: untyped) =
  mixin genState, genBlock

  var
    blockPool {.inject.} = BlockPool.init(makeTestDB(genState, genBlock))
    pool {.inject.} = AttestationPool.init(blockPool)
    state {.inject.} = loadTailState(blockPool)
  # Slot 0 is a finalized slot - won't be making attestations for it..
  advanceState(state.data)

  body

suite "Attestation pool processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  # Genesis state that results in 2 members per committee
  let
    genState = get_genesis_beacon_state(
      makeInitialDeposits(SLOTS_PER_EPOCH * 2, {skipValidation}), 0, Eth1Data(),
        {skipValidation})
    genBlock = get_initial_beacon_block(genState)

  test "Can add and retrieve simple attestation" & preset():
    withPool:
      let
        # Create an attestation for slot 1!
        crosslink_committee = get_crosslink_committee(state.data.data,
          slot_to_epoch(state.data.data.slot), 0)
        attestation = makeAttestation(
          state.data.data, state.blck.root, crosslink_committee[0])

      pool.add(state.data.data, attestation)

      for i in 0..<MIN_ATTESTATION_INCLUSION_DELAY.int - 1:
        advanceState(state.data)

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  test "Attestations may arrive in any order" & preset():
    withPool:
      let
        # Create an attestation for slot 1!
        cc0 = get_crosslink_committee(state.data.data,
          slot_to_epoch(state.data.data.slot), 0)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, cc0[0])

      advanceState(state.data)

      let
        cc1 = get_crosslink_committee(state.data.data,
          slot_to_epoch(state.data.data.slot), 0)
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, cc1[0])

      # test reverse order
      pool.add(state.data.data, attestation1)
      pool.add(state.data.data, attestation0)

      for i in 0..<MIN_ATTESTATION_INCLUSION_DELAY.int - 1: advanceState(state.data)

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  test "Attestations should be combined" & preset():
    withPool:
      let
        # Create an attestation for slot 1!
        cc0 = get_crosslink_committee(state.data.data,
          slot_to_epoch(state.data.data.slot), 0)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, cc0[0])
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, cc0[1])

      pool.add(state.data.data, attestation0)
      pool.add(state.data.data, attestation1)

      for i in 0..<MIN_ATTESTATION_INCLUSION_DELAY.int - 1: advanceState(state.data)

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  test "Attestations may overlap, bigger first" & preset():
    withPool:

      var
        # Create an attestation for slot 1!
        cc0 = get_crosslink_committee(state.data.data,
          slot_to_epoch(state.data.data.slot), 0)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, cc0[0])
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, cc0[1])

      attestation0.combine(attestation1, {skipValidation})

      pool.add(state.data.data, attestation0)
      pool.add(state.data.data, attestation1)

      for i in 0..<MIN_ATTESTATION_INCLUSION_DELAY.int - 1: advanceState(state.data)

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  test "Attestations may overlap, smaller first" & preset():
    withPool:
      var
        # Create an attestation for slot 1!
        cc0 = get_crosslink_committee(state.data.data,
          slot_to_epoch(state.data.data.slot), 0)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, cc0[0])
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, cc0[1])

      attestation0.combine(attestation1, {skipValidation})

      pool.add(state.data.data, attestation1)
      pool.add(state.data.data, attestation0)

      for i in 0..<MIN_ATTESTATION_INCLUSION_DELAY.int - 1: advanceState(state.data)

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, unittest,
  chronicles,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[beacon_node_types, attestation_pool, block_pool, extras, state_transition, ssz]

template withPool(body: untyped) =
  mixin genState, genBlock

  var
    blockPool {.inject.} = BlockPool.init(makeTestDB(genState, genBlock))
    pool {.inject.} = AttestationPool.init(blockPool)
    state {.inject.} = loadTailState(blockPool)
  # Slot 0 is a finalized slot - won't be making attestations for it..
  process_slots(state.data, state.data.data.slot + 1)

  body

suite "Attestation pool processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  # Genesis state that results in 2 members per committee
  let
    genState = initialize_beacon_state_from_eth1(
      Eth2Digest(), 0,
      makeInitialDeposits(SLOTS_PER_EPOCH * 2, {skipValidation}),
      {skipValidation})
    genBlock = get_initial_beacon_block(genState)

  timedTest "Can add and retrieve simple attestation" & preset():
    var cache = get_empty_per_epoch_cache()
    withPool:
      let
        # Create an attestation for slot 1!
        beacon_committee = get_beacon_committee(state.data.data,
          state.data.data.slot, 0, cache)
        attestation = makeAttestation(
          state.data.data, state.blck.root, beacon_committee[0], cache)

      pool.add(state.data.data, state.blck, attestation)

      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot) # minus 1?

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  timedTest "Attestations may arrive in any order" & preset():
    var cache = get_empty_per_epoch_cache()
    withPool:
      let
        # Create an attestation for slot 1!
        bc0 = get_beacon_committee(state.data.data,
          state.data.data.slot, 0, cache)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, bc0[0], cache)

      process_slots(state.data, state.data.data.slot + 1)

      let
        bc1 = get_beacon_committee(state.data.data,
          state.data.data.slot, 0, cache)
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, bc1[0], cache)

      # test reverse order
      pool.add(state.data.data, state.blck, attestation1)
      pool.add(state.data.data, state.blck, attestation0)

      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot) # minus 1?

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  timedTest "Attestations should be combined" & preset():
    var cache = get_empty_per_epoch_cache()
    withPool:
      let
        # Create an attestation for slot 1!
        bc0 = get_beacon_committee(state.data.data,
          state.data.data.slot, 0, cache)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, bc0[0], cache)
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, bc0[1], cache)

      pool.add(state.data.data, state.blck, attestation0)
      pool.add(state.data.data, state.blck, attestation1)

      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot) # minus 1?

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  timedTest "Attestations may overlap, bigger first" & preset():
    var cache = get_empty_per_epoch_cache()
    withPool:

      var
        # Create an attestation for slot 1!
        bc0 = get_beacon_committee(state.data.data,
          state.data.data.slot, 0, cache)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, bc0[0], cache)
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, bc0[1], cache)

      attestation0.combine(attestation1, {skipValidation})

      pool.add(state.data.data, state.blck, attestation0)
      pool.add(state.data.data, state.blck, attestation1)

      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot) # minus 1?

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

  timedTest "Attestations may overlap, smaller first" & preset():
    var cache = get_empty_per_epoch_cache()
    withPool:
      var
        # Create an attestation for slot 1!
        bc0 = get_beacon_committee(state.data.data,
          state.data.data.slot, 0, cache)
        attestation0 = makeAttestation(
          state.data.data, state.blck.root, bc0[0], cache)
        attestation1 = makeAttestation(
          state.data.data, state.blck.root, bc0[1], cache)

      attestation0.combine(attestation1, {skipValidation})

      pool.add(state.data.data, state.blck, attestation1)
      pool.add(state.data.data, state.blck, attestation0)

      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot) # minus 1?

      let attestations = pool.getAttestationsForBlock(
        state.data.data, state.data.data.slot + 1)

      check:
        attestations.len == 1

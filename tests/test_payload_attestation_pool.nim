# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Status libraries
  unittest2,
  chronicles,
  # Internal
  ../beacon_chain/consensus_object_pools/[
    blockchain_dag, payload_attestation_pool, spec_cache],
  ../beacon_chain/spec/[
    forks, helpers, signatures, state_transition],
  ../beacon_chain/beacon_clock,
  # Test utilities
  ./testutil, ./testdbutil, ./testblockutil, ./consensus_spec/fixtures_utils

from ../beacon_chain/spec/beaconstate import get_ptc
from std/sugar import collect

proc makePayloadAttestationMessage(
    state: gloas.HashedBeaconState,
    beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex,
    privkey: ValidatorPrivKey,
    cache: var StateCache,
    payload_present: bool = true,
    blob_data_available: bool = true
  ): PayloadAttestationMessage =

  let
    slot = state.data.slot
    fork = Fork(
      previous_version: state.data.fork.current_version,
      current_version: state.data.fork.current_version,
      epoch: state.data.slot.epoch)
    genesis_validators_root = state.data.genesis_validators_root

    data = PayloadAttestationData(
      beacon_block_root: beacon_block_root,
      slot: slot,
      payload_present: payload_present,
      blob_data_available: blob_data_available)

    domain = get_domain(
      fork, DOMAIN_PTC_ATTESTER, slot.epoch(), genesis_validators_root)
    signing_root = compute_signing_root(data, domain)
    signature = blsSign(privkey, signing_root.data)

  PayloadAttestationMessage(
    validator_index: validator_index.uint64,
    data: data,
    signature: signature.toValidatorSig())

suite "Payload attestation pool" & preset():
  setup:
    # Genesis state that results in 512 members in a committee
    const TOTAL_COMMITTEES = 1
    var
      cfg = genesisTestRuntimeConfig(ConsensusFork.Gloas)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(
        ChainDAGRef, cfg,
        cfg.makeTestDB(
          TOTAL_COMMITTEES * PTC_SIZE),
        validatorMonitor, {})
      pool = newClone(PayloadAttestationPool.init(dag))
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()
    check:
      process_slots(
        dag.cfg,
        state[],
        state[].slot + 1,
        cache,
        info,
        {}).isOk()

  test "Can add and retrieve payload attestations" & preset():
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)

    withState(state[]):
      when consensusFork == ConsensusFork.Gloas:
        debugHezeComment "..."
        var ptc_member: ValidatorIndex
        var found = false
        for validator_index in get_ptc(forkyState.data, slot):
            ptc_member = validator_index
            found = true
            break

        check found

        let
          privkey = MockPrivKeys[ptc_member]
          message = makePayloadAttestationMessage(
            forkyState, beacon_block_root, ptc_member, privkey, cache)

        check pool[].addPayloadAttestation(message, wallTime)

        # Should not be able to add the same attestation twice
        check not pool[].addPayloadAttestation(message, wallTime)

        let aggregated = pool[].getAggregatedPayloadAttestation(
            slot, (beacon_block_root, true, true))

        check aggregated.isSome()
        check aggregated.get().data == message.data
        check aggregated.get().aggregation_bits.countOnes() > 0

  test "Multiple validators in PTC can attest" & preset():
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)

    withState(state[]):
      when consensusFork == ConsensusFork.Gloas:
        debugHezeComment "..."
        var messages: seq[PayloadAttestationMessage]
        var ptc_members: seq[ValidatorIndex]

        for validator_index in get_ptc(forkyState.data, slot):
          if ptc_members.len >= 3:
            break
          ptc_members.add(validator_index)

        check ptc_members.len >= 3

        for ptc_member in ptc_members:
          let
            privkey = MockPrivKeys[ptc_member]
            message = makePayloadAttestationMessage(
              forkyState, beacon_block_root, ptc_member, privkey, cache)
          messages.add(message)
          check pool[].addPayloadAttestation(message, wallTime)

        let aggregated = pool[].getAggregatedPayloadAttestation(
          slot, (beacon_block_root, true, true))
        check aggregated.isSome()
        check aggregated.get().aggregation_bits.countOnes() >= ptc_members.len

  test "Duplicate validator in PTC - multiple signatures" & preset():
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)

    withState(state[]):
      when consensusFork == ConsensusFork.Gloas:
        debugHezeComment "..."
        var
          validator_positions: Table[ValidatorIndex, seq[int]]
          ptc_index = 0

        for validator_index in get_ptc(forkyState.data, slot):
          if validator_index notin validator_positions:
            validator_positions[validator_index] = @[]
          validator_positions[validator_index].add(ptc_index)
          ptc_index += 1

        var
          multi_position_validator: ValidatorIndex
          positions: seq[int]
          found = false

        for validator_index, position_list in validator_positions:
          if position_list.len > 1:
            multi_position_validator = validator_index
            positions = position_list
            found = true
            break

        if found:
          let
            privkey = MockPrivKeys[multi_position_validator]
            message = makePayloadAttestationMessage(
              forkyState, beacon_block_root,
              multi_position_validator, privkey, cache)

          check pool[].addPayloadAttestation(message, wallTime)

          let aggregated =
            pool[].getAggregatedPayloadAttestation(
              slot, (beacon_block_root, true, true))
          check aggregated.isSome()

          # Check that all positions are set in aggregation bits
          for pos in positions:
            check aggregated.get().aggregation_bits[pos]

  test "Can get payload attestations for block production" & preset():
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)
      target_slot = slot + 1

    withState(state[]):
      when consensusFork == ConsensusFork.Gloas:
        debugHezeComment "..."
        var added_count = 0
        for validator_index in get_ptc(forkyState.data, slot):
          if added_count >= 2:
            break
          let
            privkey = MockPrivKeys[validator_index]
            message = makePayloadAttestationMessage(
              forkyState, beacon_block_root, validator_index, privkey, cache)
          check pool[].addPayloadAttestation(message, wallTime)
          added_count += 1

        let attestations =
          pool[].getPayloadAttestationsForBlock(target_slot)
        check attestations.len > 0
        check attestations[0].data.slot == slot

  test "Payload attestations get pruned" & preset():
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)
      future_time = (slot + 5).start_beacon_time(dag.cfg.timeParams)

    withState(state[]):
      when consensusFork == ConsensusFork.Gloas:
        debugHezeComment "..."
        var ptc_member: ValidatorIndex
        for validator_index in get_ptc(forkyState.data, slot):
          ptc_member = validator_index
          break

        let
          privkey = MockPrivKeys[ptc_member]
          message = makePayloadAttestationMessage(
            forkyState, beacon_block_root, ptc_member, privkey, cache)

        # Add attestation
        check pool[].addPayloadAttestation(message, wallTime)

        # Add another attestation at a future time (should trigger pruning)
        check pool[].addPayloadAttestation(message, future_time)

        # Old attestation should no longer be retrievable
        let attestations =
          pool[].getPayloadAttestationsForBlock(slot + 6)
        check attestations.len == 0

  test "Different 'blob data available' and 'payload presence' values" & preset():
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)

    withState(state[]):
      when consensusFork == ConsensusFork.Gloas:
        debugHezeComment "..."
        var ptc_members: seq[ValidatorIndex]
        for validator_index in get_ptc(forkyState.data, slot):
          if ptc_members.len >= 4:
            break
          ptc_members.add(validator_index)

        check ptc_members.len >= 4

        let
          message1 = makePayloadAttestationMessage(
            forkyState, beacon_block_root, ptc_members[0],
            MockPrivKeys[ptc_members[0]], cache,
            payload_present = true, blob_data_available = true)
          message2 = makePayloadAttestationMessage(
            forkyState, beacon_block_root, ptc_members[1],
            MockPrivKeys[ptc_members[1]], cache,
            payload_present = false, blob_data_available = false)
          message3 = makePayloadAttestationMessage(
            forkyState, beacon_block_root, ptc_members[1],
            MockPrivKeys[ptc_members[2]], cache,
            payload_present = false, blob_data_available = true)
          message4 = makePayloadAttestationMessage(
            forkyState, beacon_block_root, ptc_members[1],
            MockPrivKeys[ptc_members[3]], cache,
            payload_present = true, blob_data_available = false)

        check pool[].addPayloadAttestation(message1, wallTime)
        check pool[].addPayloadAttestation(message2, wallTime)
        check pool[].addPayloadAttestation(message3, wallTime)
        check pool[].addPayloadAttestation(message4, wallTime)

        let
          agg1 = pool[].getAggregatedPayloadAttestation(
            slot, (beacon_block_root, true, true))
          agg2 = pool[].getAggregatedPayloadAttestation(
            slot, (beacon_block_root, false, false))
          agg3 = pool[].getAggregatedPayloadAttestation(
            slot, (beacon_block_root, false, true))
          agg4 = pool[].getAggregatedPayloadAttestation(
            slot, (beacon_block_root, true, false))

        check agg1.isSome()
        check agg2.isSome()
        check agg3.isSome()
        check agg4.isSome()
        check agg1.get().data == message1.data
        check agg2.get().data == message2.data
        check agg3.get().data == message3.data
        check agg4.get().data == message4.data

  test "get_ptc with ShufflingRef matches StateCache version" & preset():
    let slot = state[].slot

    withState(state[]):
      when consensusFork >= ConsensusFork.Gloas:
        # Get PTC using StateCache version
        var cache = StateCache()
        let stateCacheResults = collect(newSeq):
          for validator_index in get_ptc(forkyState.data, slot):
            validator_index

        let epochRef = dag.getEpochRef(
          dag.head, slot.epoch, false).expect("EpochRef should exist")

        # Get PTC using ShufflingRef version
        let shufflingRefResults = collect(newSeq):
          for validator_index in get_ptc(
              forkyState.data, epochRef.shufflingRef, slot):
            validator_index

        check:
          stateCacheResults == shufflingRefResults
          stateCacheResults.len.uint64 == PTC_SIZE
          shufflingRefResults.len.uint64 == PTC_SIZE

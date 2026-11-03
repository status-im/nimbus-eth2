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
  chronos,
  taskpools,
  # Internal
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, block_clearance, block_quarantine, blockchain_dag,
    payload_attestation_pool, spec_cache],
  ../beacon_chain/fork_choice/fork_choice,
  ../beacon_chain/gossip_processing/[batch_validation, gossip_validation],
  ../beacon_chain/spec/[
    forks, helpers, signatures, state_transition],
  ../beacon_chain/beacon_clock,
  # Test utilities
  ./testutil, ./testdbutil, ./testblockutil, ./consensus_spec/fixtures_utils

from ../beacon_chain/spec/beaconstate import get_ptc
from std/sugar import collect
from std/sequtils import count, countIt, deduplicate, filterIt
from ./testbcutil import addHeadBlock

proc makePayloadAttestationMessage(
    state: gloas.HashedBeaconState | heze.HashedBeaconState,
    beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex,
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
    signature = blsSign(MockPrivKeys[validator_index], signing_root.data)

  PayloadAttestationMessage(
    validator_index: validator_index.uint64,
    data: data,
    signature: signature.toValidatorSig())

proc makePayloadAttestationMessage(
    state: ForkedHashedBeaconState,
    beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex,
    payload_present: bool = true,
    blob_data_available: bool = true
  ): PayloadAttestationMessage =
  withState(state):
    when consensusFork >= ConsensusFork.Gloas:
      makePayloadAttestationMessage(
        forkyState, beacon_block_root, validator_index,
        payload_present, blob_data_available)
    else:
      raiseAssert "Pre-Gloas state not supported"

proc getPtcMembers(
    state: ForkedHashedBeaconState, cfg: RuntimeConfig, slot: Slot,
    n = int(PTC_SIZE)): seq[ValidatorIndex] =
  var members: seq[ValidatorIndex]
  withState(state):
    when consensusFork >= ConsensusFork.Gloas:
      for validator_index in get_ptc(cfg, forkyState.data, slot):
        members.add(validator_index)
        if members.len >= n:
          break
  members

suite "Payload attestation pool" & preset():
  setup:
    # Genesis state that results in 512 members in a committee
    const TOTAL_COMMITTEES = 1
    let
      cfg = genesisTestRuntimeConfig(ConsensusFork.Gloas)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(
        ChainDAGRef, cfg,
        cfg.makeTestDB(
          TOTAL_COMMITTEES * PTC_SIZE),
        validatorMonitor, {})
      pool = newClone(PayloadAttestationPool.init(dag))
      state = newClone(dag.headState)
    var
      cache: StateCache
      info = ForkedEpochInfo()
    check:
      process_slots(
        dag.cfg,
        state[],
        state[].slot + 1,
        cache,
        info,
        {}).isOk()
    let
      slot = state[].slot
      beacon_block_root =
        withState(state[]): hash_tree_root(forkyState.data.latest_block_header)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)

    check dag.getEpochRef(dag.head, slot.epoch, preFinalized = false).isOk()

  test "Can add and retrieve payload attestations" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot, 1)
    check members.len == 1

    let message = state[].makePayloadAttestationMessage(
      beacon_block_root, members[0])

    check not pool[].isSeen(message)
    check pool[].addPayloadAttestation(message, wallTime)
    check pool[].isSeen(message)

    # Should not be able to add the same attestation twice
    check not pool[].addPayloadAttestation(message, wallTime)

    let aggregated = pool[].getAggregatedPayloadAttestation(
        slot, (beacon_block_root, true, true))

    check aggregated.isSome()
    check aggregated.get().data == message.data
    check aggregated.get().aggregation_bits.countOnes() > 0

  test "Same validator, conflicting votes are ignored" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot, 1)
    check members.len == 1

    let first = state[].makePayloadAttestationMessage(
      beacon_block_root, members[0],
      payload_present = true, blob_data_available = true)
    check not pool[].isSeen(first)
    check pool[].addPayloadAttestation(first, wallTime)

    # Same validator, same slot, but conflicting votes are ignored.
    let conflicting = state[].makePayloadAttestationMessage(
      beacon_block_root, members[0],
      payload_present = false, blob_data_available = false)
    check conflicting.data != first.data
    check pool[].isSeen(conflicting)
    check not pool[].addPayloadAttestation(conflicting, wallTime)

    # Only the first vote's data is kept; the conflicting vote is ignored.
    check pool[].getAggregatedPayloadAttestation(
      slot, (beacon_block_root, true, true)).isSome()
    check pool[].getAggregatedPayloadAttestation(
      slot, (beacon_block_root, false, false)).isNone()

  test "Multiple validators in PTC can attest" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot, 3)
    check members.len == 3

    for member in members:
      check pool[].addPayloadAttestation(
        state[].makePayloadAttestationMessage(beacon_block_root, member),
        wallTime)

    let aggregated = pool[].getAggregatedPayloadAttestation(
      slot, (beacon_block_root, true, true))
    check aggregated.isSome()
    check aggregated.get().aggregation_bits.countOnes() >= members.len

  test "Duplicate validator in PTC - multiple signatures" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot)
    var validator_positions: Table[ValidatorIndex, seq[int]]
    for ptc_index, validator_index in members:
      validator_positions.mgetOrPut(validator_index, @[]).add(ptc_index)

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
      let message = state[].makePayloadAttestationMessage(
        beacon_block_root, multi_position_validator)

      check pool[].addPayloadAttestation(message, wallTime)

      let aggregated =
        pool[].getAggregatedPayloadAttestation(
          slot, (beacon_block_root, true, true))
      check aggregated.isSome()

      # Check that all positions are set in aggregation bits
      for pos in positions:
        check aggregated.get().aggregation_bits[pos]

  test "Votes that cancel out are skipped" & preset():
    func times(sig: CookedSig, n: int): CookedSig =
      var res = AggregateSignature.init(sig)
      for _ in 1 ..< n:
        res.aggregate(sig)
      res.finish().get()

    # Votes count once per position in the PTC
    let
      ptc = state[].getPtcMembers(dag.cfg, slot)
      v1 = ptc[0]
      v2 = ptc.filterIt(it != v1)[0]
    var
      message1 = state[].makePayloadAttestationMessage(beacon_block_root, v1)
      message2 = state[].makePayloadAttestationMessage(beacon_block_root, v2)
    let sig = message1.signature.load.get
    message1.signature = sig.times(ptc.count(v2)).toValidatorSig
    message2.signature = sig.times(ptc.count(v1)).negate.toValidatorSig

    check:
      pool[].addPayloadAttestation(message1, wallTime)
      pool[].addPayloadAttestation(message2, wallTime)
      pool[].getAggregatedPayloadAttestation(
        slot, (beacon_block_root, true, true)).isNone
      pool[].getPayloadAttestationsForBlock(
        slot + 1, beacon_block_root).len == 0

  test "Can get payload attestations for block production" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot, 2)
    check members.len == 2

    for member in members:
      check pool[].addPayloadAttestation(
        state[].makePayloadAttestationMessage(beacon_block_root, member),
        wallTime)

    let attestations =
      pool[].getPayloadAttestationsForBlock(slot + 1, beacon_block_root)
    check attestations.len > 0
    check attestations[0].data.slot == slot

  test "Payload attestations get pruned" & preset():
    let
      future_time = (slot + 5).start_beacon_time(dag.cfg.timeParams)
      members = state[].getPtcMembers(dag.cfg, slot, 1)
      message = state[].makePayloadAttestationMessage(
        beacon_block_root, members[0])

    # Add attestation
    check pool[].addPayloadAttestation(message, wallTime)

    # Add another attestation at a future time (should trigger pruning)
    check pool[].addPayloadAttestation(message, future_time)

    # Old attestation should no longer be retrievable
    let attestations =
      pool[].getPayloadAttestationsForBlock(slot + 6, beacon_block_root)
    check attestations.len == 0

  test "Different 'blob data available' and 'payload presence' values" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot, 4)
    check members.len == 4

    let
      message1 = state[].makePayloadAttestationMessage(
        beacon_block_root, members[0],
        payload_present = true, blob_data_available = true)
      message2 = state[].makePayloadAttestationMessage(
        beacon_block_root, members[1],
        payload_present = false, blob_data_available = false)
      message3 = state[].makePayloadAttestationMessage(
        beacon_block_root, members[2],
        payload_present = false, blob_data_available = true)
      message4 = state[].makePayloadAttestationMessage(
        beacon_block_root, members[3],
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

  test "get_ptc with ShufflingRef or EpochRef matches StateCache" & preset():
    withState(state[]):
      when consensusFork >= ConsensusFork.Gloas:
        # Get PTC using StateCache version
        let stateCacheResults = collect(newSeq):
          for validator_index in get_ptc(dag.cfg, forkyState.data, slot):
            validator_index

        let epochRef = dag.getEpochRef(
          dag.head, slot.epoch, false).expect("EpochRef should exist")

        # Get PTC using ShufflingRef version
        let shufflingRefResults = collect(newSeq):
          for validator_index in get_ptc(
              forkyState.data, epochRef.shufflingRef, slot):
            validator_index

        # Get PTC using EpochRef version
        let epochRefResults = collect(newSeq):
          for validator_index in epochRef.get_ptc(slot):
            validator_index

        check:
          stateCacheResults == shufflingRefResults
          stateCacheResults == epochRefResults
          stateCacheResults.len.uint64 == PTC_SIZE
          shufflingRefResults.len.uint64 == PTC_SIZE

  test "Get all payload attestations in the pool" & preset():
    let members = state[].getPtcMembers(dag.cfg, slot, 3)
    check members.len == 3

    check pool[].addPayloadAttestation(
      state[].makePayloadAttestationMessage(beacon_block_root, members[0]),
      wallTime)
    check pool[].addPayloadAttestation(
      state[].makePayloadAttestationMessage(
        beacon_block_root, members[1], payload_present = false),
      wallTime)
    check pool[].addPayloadAttestation(
      state[].makePayloadAttestationMessage(
        beacon_block_root, members[2], payload_present = false,
        blob_data_available = false),
      wallTime)

    check:
      pool[].getPayloadAttestations(Opt.none(Slot)).countIt(true) == 3
      pool[].getPayloadAttestations(Opt.some(slot)).countIt(true) == 3
      pool[].getPayloadAttestations(Opt.some(slot + 1)).countIt(true) == 0

  test "PTC comes from the attested block's branch" & preset():
    let
      quarantine = newClone(Quarantine.init(dag.cfg))
      rng = HmacDrbgContext.new()
    var
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      stateA = assignClone(dag.headState)
      stateB = assignClone(dag.headState)
      cacheA, cacheB: StateCache
    const nilCallback = OnBlockAdded[ConsensusFork.Gloas](nil)

    # The PTC of epoch 2 is fixed by the last block of epoch 0,
    # so branches forked inside epoch 0 disagree on it
    let ptcSlot = Epoch(2).start_slot + 1
    check process_slots(dag.cfg, stateB[], Slot(1), cacheB, info, {}).isOk()
    let
      a1 = addTestBlock(stateA[], cacheA, cfg = dag.cfg).gloasData
      b1 = addTestBlock(stateB[], cacheB, cfg = dag.cfg).gloasData
      a1Add = dag.addHeadBlock(verifier, a1, nilCallback)
      b1Add = dag.addHeadBlock(verifier, b1, nilCallback)
    check:
      process_slots(dag.cfg, stateA[], ptcSlot - 1, cacheA, info, {}).isOk()
      process_slots(dag.cfg, stateB[], ptcSlot - 1, cacheB, info, {}).isOk()
    let
      a2 = addTestBlock(stateA[], cacheA, cfg = dag.cfg).gloasData
      b2 = addTestBlock(stateB[], cacheB, cfg = dag.cfg).gloasData
      a2Add = dag.addHeadBlock(verifier, a2, nilCallback)
      b2Add = dag.addHeadBlock(verifier, b2, nilCallback)
      attestedPtc = stateB[].getPtcMembers(dag.cfg, ptcSlot)
      otherPtc = stateA[].getPtcMembers(dag.cfg, ptcSlot)
      voters = attestedPtc.deduplicate().filterIt(it notin otherPtc)
      nonMember = block:
        var validator_index = ValidatorIndex(0)
        while validator_index in attestedPtc:
          inc validator_index
        validator_index
      ptcWallTime = ptcSlot.start_beacon_time(dag.cfg.timeParams)
      data = PayloadAttestationData(
        beacon_block_root: b2.root, slot: ptcSlot,
        payload_present: true, blob_data_available: true)
    check:
      a1Add.isOk()
      b1Add.isOk()
      a2Add.isOk()
      b2Add.isOk()
      voters.len > 0

    template validate(vidx: ValidatorIndex): untyped =
      validatePayloadAttestationMessage(
        dag, quarantine, pool, (ref BatchCrypto)(nil),
        PayloadAttestationMessage(validator_index: vidx.uint64, data: data),
        ptcWallTime, checkSignature = false).waitFor()

    # Gossip accepts the attested block's PTC regardless of where the head is
    for head in [b2Add[], a2Add[], b1Add[]]:
      dag.updateHead(head, quarantine[], [])
      for validator_index in attestedPtc.deduplicate():
        check validate(validator_index).isOk()
      let res = validate(nonMember)
      check:
        res.isErr()
        res.error()[0] == ValidationResult.Reject

    # Pool and fork choice use the positions in the attested block's PTC
    dag.updateHead(a2Add[], quarantine[], [])
    let attPool = newClone(AttestationPool.init(dag, quarantine, ptcWallTime))
    for validator_index in voters:
      check:
        pool[].addPayloadAttestation(
          stateB[].makePayloadAttestationMessage(b2.root, validator_index),
          ptcWallTime)
        attPool[].forkChoice.on_payload_attestation_message(
          dag, validator_index.uint64, data).isOk()
    let
      aggregated = pool[].getAggregatedPayloadAttestation(
        ptcSlot, (b2.root, true, true))
      tally = attPool[].forkChoice.backend.mgetPtcTally(b2.root, ptcSlot)
    check aggregated.isSome()
    for i, validator_index in attestedPtc:
      check:
        aggregated.get().aggregation_bits[i] == (validator_index in voters)
        tally.voted[i] == (validator_index in voters)

    taskpool.shutdown()

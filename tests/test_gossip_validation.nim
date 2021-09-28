# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/sequtils,
  # Status lib
  unittest2,
  chronicles, chronos,
  eth/keys, taskpools,
  # Internal
  ../beacon_chain/[beacon_node_types, beacon_clock],
  ../beacon_chain/gossip_processing/[gossip_validation, batch_validation],
  ../beacon_chain/fork_choice/[fork_choice_types, fork_choice],
  ../beacon_chain/consensus_object_pools/[
    block_quarantine, blockchain_dag, block_clearance, attestation_pool,
    sync_committee_msg_pool],
  ../beacon_chain/spec/datatypes/[phase0, altair],
  ../beacon_chain/spec/[forks, state_transition, helpers, network],
  ../beacon_chain/validators/validator_pool,
  # Test utilities
  ./testutil, ./testdbutil, ./testblockutil

proc pruneAtFinalization(dag: ChainDAGRef, attPool: AttestationPool) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()
    # pool[].prune() # We test logic without att_1_0 pool / fork choice pruning

suite "Gossip validation " & preset():
  setup:
    # Genesis state that results in 3 members per committee
    var
      dag = init(ChainDAGRef, defaultRuntimeConfig, makeTestDB(SLOTS_PER_EPOCH * 3), {})
      taskpool = Taskpool.new()
      quarantine = QuarantineRef.init(keys.newRng(), taskpool)
      pool = newClone(AttestationPool.init(dag, quarantine))
      state = newClone(dag.headState)
      cache = StateCache()
      rewards = RewardInfo()
      batchCrypto = BatchCrypto.new(keys.newRng(), eager = proc(): bool = false, taskpool)
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(
        defaultRuntimeConfig, state.data, getStateField(state.data, slot) + 1,
        cache, rewards, {})

  test "Any committee index is valid":
    template committee(idx: uint64): untyped =
      get_beacon_committee(
        dag.headState.data, dag.head.slot, idx.CommitteeIndex, cache)

    template committeeLen(idx: uint64): untyped =
      get_beacon_committee_len(
        dag.headState.data, dag.head.slot, idx.CommitteeIndex, cache)

    check:
      committee(0).len > 0
      committee(10000).len == 0
      committee(uint64.high).len == 0

    check:
      committeeLen(2) > 0
      committeeLen(10000) == 0
      committeeLen(uint64.high) == 0

  test "Validation sanity":
    # TODO: refactor tests to avoid skipping BLS validation
    dag.updateFlags.incl {skipBLSValidation}

    var
      cache: StateCache
    for blck in makeTestBlocks(
        dag.headState.data, dag.head.root, cache,
        int(SLOTS_PER_EPOCH * 5), false):
      let added = dag.addRawBlock(quarantine, blck.phase0Block) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

      check: added.isOk()
      dag.updateHead(added[], quarantine)
      pruneAtFinalization(dag, pool[])

    var
      # Create attestations for slot 1
      beacon_committee = get_beacon_committee(
        dag.headState.data, dag.head.slot, 0.CommitteeIndex, cache)
      att_1_0 = makeAttestation(
        dag.headState.data, dag.head.root, beacon_committee[0], cache)
      att_1_1 = makeAttestation(
        dag.headState.data, dag.head.root, beacon_committee[1], cache)

      committees_per_slot =
        get_committee_count_per_slot(dag.headState.data,
          att_1_0.data.slot.epoch, cache)

      subnet = compute_subnet_for_attestation(
        committees_per_slot,
        att_1_0.data.slot, att_1_0.data.index.CommitteeIndex)

      beaconTime = att_1_0.data.slot.toBeaconTime()

    check:
      validateAttestation(pool, batchCrypto, att_1_0, beaconTime, subnet, true).waitFor().isOk

      # Same validator again
      validateAttestation(pool, batchCrypto, att_1_0, beaconTime, subnet, true).waitFor().error()[0] ==
        ValidationResult.Ignore

    pool[].nextAttestationEpoch.setLen(0) # reset for test
    check:
      # Wrong subnet
      validateAttestation(
        pool, batchCrypto, att_1_0, beaconTime, SubnetId(subnet.uint8 + 1), true).waitFor().isErr

    pool[].nextAttestationEpoch.setLen(0) # reset for test
    check:
      # Too far in the future
      validateAttestation(
        pool, batchCrypto, att_1_0, beaconTime - 1.seconds, subnet, true).waitFor().isErr

    pool[].nextAttestationEpoch.setLen(0) # reset for test
    check:
      # Too far in the past
      validateAttestation(
        pool, batchCrypto, att_1_0,
        beaconTime - (SECONDS_PER_SLOT * SLOTS_PER_EPOCH - 1).int.seconds,
        subnet, true).waitFor().isErr

    block:
      var broken = att_1_0
      broken.signature.blob[0] += 1
      pool[].nextAttestationEpoch.setLen(0) # reset for test
      check:
        # Invalid signature
        validateAttestation(
          pool, batchCrypto, broken, beaconTime, subnet, true).waitFor().
            error()[0] == ValidationResult.Reject

    block:
      var broken = att_1_0
      broken.signature.blob[5] += 1
      pool[].nextAttestationEpoch.setLen(0) # reset for test
      # One invalid, one valid (batched)
      let
        fut_1_0 = validateAttestation(
          pool, batchCrypto, broken, beaconTime, subnet, true)
        fut_1_1 = validateAttestation(
          pool, batchCrypto, att_1_1, beaconTime, subnet, true)

      check:
        fut_1_0.waitFor().error()[0] == ValidationResult.Reject
        fut_1_1.waitFor().isOk()

    block:
      var broken = att_1_0
      # This shouldn't deserialize, which is a different way to break it
      broken.signature.blob = default(type broken.signature.blob)
      pool[].nextAttestationEpoch.setLen(0) # reset for test
      # One invalid, one valid (batched)
      let
        fut_1_0 = validateAttestation(
          pool, batchCrypto, broken, beaconTime, subnet, true)
        fut_1_1 = validateAttestation(
          pool, batchCrypto, att_1_1, beaconTime, subnet, true)

      check:
        fut_1_0.waitFor().error()[0] == ValidationResult.Reject
        fut_1_1.waitFor().isOk()

suite "Gossip validation - Extra": # Not based on preset config
  test "validateSyncCommitteeMessage":
    const num_validators = SLOTS_PER_EPOCH
    let 
      cfg = block:
        var cfg = defaultRuntimeConfig
        cfg.ALTAIR_FORK_EPOCH = (GENESIS_EPOCH + 1).Epoch
        cfg
      dag = block:
        let 
          dag = ChainDAGRef.init(cfg, makeTestDB(num_validators), {})
          taskpool = Taskpool.new()
          quarantine = QuarantineRef.init(keys.newRng(), taskpool)
        var cache = StateCache()
        for blck in makeTestBlocks(
            dag.headState.data, dag.head.root, cache,
            int(SLOTS_PER_EPOCH), false, cfg = cfg):
          let added = 
            case blck.kind
            of BeaconBlockFork.Phase0:
              const nilCallback = OnPhase0BlockAdded(nil)
              dag.addRawBlock(quarantine, blck.phase0Block, nilCallback)
            of BeaconBlockFork.Altair:
              const nilCallback = OnAltairBlockAdded(nil)
              dag.addRawBlock(quarantine, blck.altairBlock, nilCallback)
            of BeaconBlockFork.Merge:
              const nilCallback = OnMergeBlockAdded(nil)
              dag.addRawBlock(quarantine, blck.mergeBlock, nilCallback)
          check: added.isOk()
          dag.updateHead(added[], quarantine)
        dag
      state = newClone(dag.headState.data.hbsAltair)

      syncCommitteeIdx = 0.SyncCommitteeIndex
      syncCommittee = @(dag.syncCommitteeParticipants(state[].data.slot))
      subcommittee = syncCommittee.syncSubcommittee(syncCommitteeIdx)

      pubkey = subcommittee[0]
      expectedCount = subcommittee.count(pubkey)
      index = ValidatorIndex(
        state[].data.validators.mapIt(it.pubkey).find(pubKey))
      validator = AttachedValidator(
        pubKey: pubkey,
        kind: inProcess, privKey: hackPrivKey(state[].data.validators[index]),
        index: some(index))
      msg = waitFor signSyncCommitteeMessage(
        validator, state[].data.slot,
        state[].data.fork, state[].data.genesis_validators_root, state[].root)

      syncCommitteeMsgPool = newClone(SyncCommitteeMsgPool.init())
      res = validateSyncCommitteeMessage(
        dag, syncCommitteeMsgPool, msg, syncCommitteeIdx, 
        state[].data.slot.toBeaconTime(), true)
      contribution = block:
        var contribution: SyncCommitteeContribution
        check: syncCommitteeMsgPool[].produceContribution(
          state[].data.slot, state[].root, syncCommitteeIdx, contribution)
        syncCommitteeMsgPool[].addSyncContribution(
          contribution, contribution.signature.load.get)
        contribution
      aggregate = syncCommitteeMsgPool[].produceSyncAggregate(state[].root)

    check:
      expectedCount > 1 # Cover edge case
      res.isOk
      contribution.aggregation_bits.countOnes == expectedCount
      aggregate.sync_committee_bits.countOnes == expectedCount

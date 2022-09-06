# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
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
  chronos,
  eth/keys, taskpools,
  # Internal
  ../beacon_chain/[beacon_clock],
  ../beacon_chain/gossip_processing/[gossip_validation, batch_validation],
  ../beacon_chain/fork_choice/fork_choice,
  ../beacon_chain/consensus_object_pools/[
    block_quarantine, blockchain_dag, block_clearance, attestation_pool,
    sync_committee_msg_pool],
  ../beacon_chain/spec/datatypes/[phase0, altair],
  ../beacon_chain/spec/[state_transition, helpers, network, validator],
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
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(
        ChainDAGRef, defaultRuntimeConfig, makeTestDB(SLOTS_PER_EPOCH * 3),
        validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)
      quarantine = newClone(Quarantine.init())
      pool = newClone(AttestationPool.init(dag, quarantine))
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()
      batchCrypto = BatchCrypto.new(keys.newRng(), eager = proc(): bool = false, taskpool)
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(
        defaultRuntimeConfig, state[], getStateField(state[], slot) + 1,
        cache, info, {}).isOk()

  test "Empty committee when no committee for slot":
    template committee(idx: uint64): untyped =
      get_beacon_committee(
        dag.headState, dag.head.slot, idx.CommitteeIndex, cache)

    template committeeLen(idx: uint64): untyped =
      get_beacon_committee_len(
        dag.headState, dag.head.slot, idx.CommitteeIndex, cache)

    check:
      committee(0).len > 0
      committee(63).len == 0

    check:
      committeeLen(2) > 0
      committeeLen(63) == 0

  test "validateAttestation":
    var
      cache: StateCache
    for blck in makeTestBlocks(
        dag.headState, cache, int(SLOTS_PER_EPOCH * 5), false):
      let added = dag.addHeadBlock(verifier, blck.phase0Data) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef, unrealized: FinalityCheckpoints):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, unrealized, signedBlock.message,
          blckRef.slot.start_beacon_time)

      check: added.isOk()
      dag.updateHead(added[], quarantine[])
      pruneAtFinalization(dag, pool[])

    var
      # Create attestations for slot 1
      beacon_committee = get_beacon_committee(
        dag.headState, dag.head.slot, 0.CommitteeIndex, cache)
      att_1_0 = makeAttestation(
        dag.headState, dag.head.root, beacon_committee[0], cache)
      att_1_1 = makeAttestation(
        dag.headState, dag.head.root, beacon_committee[1], cache)

      committees_per_slot =
        get_committee_count_per_slot(
          dag.headState, att_1_0.data.slot.epoch, cache)

      subnet = compute_subnet_for_attestation(
        committees_per_slot,
        att_1_0.data.slot, att_1_0.data.index.CommitteeIndex)

      beaconTime = att_1_0.data.slot.start_beacon_time()

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
      taskpool = Taskpool.new()
      quarantine = newClone(Quarantine.init())
      batchCrypto = BatchCrypto.new(keys.newRng(), eager = proc(): bool = false, taskpool)
    var
      verifier = BatchVerifier(rng: keys.newRng(), taskpool: Taskpool.new())
      dag = block:
        let
          validatorMonitor = newClone(ValidatorMonitor.init())
          dag = ChainDAGRef.init(
            cfg, makeTestDB(num_validators), validatorMonitor, {})
        var cache = StateCache()
        for blck in makeTestBlocks(
            dag.headState, cache, int(SLOTS_PER_EPOCH), false, cfg = cfg):
          let added =
            case blck.kind
            of BeaconBlockFork.Phase0:
              const nilCallback = OnPhase0BlockAdded(nil)
              dag.addHeadBlock(verifier, blck.phase0Data, nilCallback)
            of BeaconBlockFork.Altair:
              const nilCallback = OnAltairBlockAdded(nil)
              dag.addHeadBlock(verifier, blck.altairData, nilCallback)
            of BeaconBlockFork.Bellatrix:
              const nilCallback = OnBellatrixBlockAdded(nil)
              dag.addHeadBlock(verifier, blck.bellatrixData, nilCallback)
          check: added.isOk()
          dag.updateHead(added[], quarantine[])
        dag
      state = assignClone(dag.headState.altairData)
      slot = state[].data.slot

      subcommitteeIdx = 0.SyncSubcommitteeIndex
      syncCommittee = @(dag.syncCommitteeParticipants(slot))
      subcommittee = toSeq(syncCommittee.syncSubcommittee(subcommitteeIdx))
      index = subcommittee[0]
      expectedCount = subcommittee.count(index)
      pubkey = state[].data.validators.item(index).pubkey
      keystoreData = KeystoreData(kind: KeystoreKind.Local,
                                  pubkey: pubkey,
                                  privateKey: MockPrivKeys[index])
      validator = AttachedValidator(
        kind: ValidatorKind.Local, data: keystoreData, index: Opt.some index)
      resMsg = waitFor getSyncCommitteeMessage(
        validator, state[].data.fork, state[].data.genesis_validators_root, slot,
        state[].root)
      msg = resMsg.get()

      syncCommitteeMsgPool = newClone(SyncCommitteeMsgPool.init(keys.newRng()))
      res = waitFor validateSyncCommitteeMessage(
        dag, batchCrypto, syncCommitteeMsgPool, msg, subcommitteeIdx,
        slot.start_beacon_time(), true)
      (positions, cookedSig) = res.get()

    syncCommitteeMsgPool[].addSyncCommitteeMessage(
      msg.slot,
      msg.beacon_block_root,
      msg.validator_index,
      cookedSig,
      subcommitteeIdx,
      positions)

    let
      contribution = block:
        let contribution = (ref SignedContributionAndProof)()
        check:
          syncCommitteeMsgPool[].produceContribution(
            slot, state[].root, subcommitteeIdx,
            contribution.message.contribution)
        let addContributionRes = syncCommitteeMsgPool[].addContribution(
          contribution[], contribution.message.contribution.signature.load.get)
        check addContributionRes == newBest
        let signRes = waitFor validator.getContributionAndProofSignature(
          state[].data.fork, state[].data.genesis_validators_root,
          contribution[].message)
        doAssert(signRes.isOk())
        contribution[].signature = signRes.get()
        contribution
      aggregate = syncCommitteeMsgPool[].produceSyncAggregate(state[].root)

    check:
      expectedCount > 1 # Cover edge case
      res.isOk
      contribution.message.contribution.aggregation_bits.countOnes == expectedCount
      aggregate.sync_committee_bits.countOnes == expectedCount

      # Same message twice should be ignored
      validateSyncCommitteeMessage(
        dag, batchCrypto, syncCommitteeMsgPool, msg, subcommitteeIdx,
        state[].data.slot.start_beacon_time(), true).waitFor().isErr()

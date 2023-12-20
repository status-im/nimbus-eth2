# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
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
  taskpools,
  # Internal
  ../beacon_chain/[beacon_clock],
  ../beacon_chain/gossip_processing/[gossip_validation, batch_validation],
  ../beacon_chain/fork_choice/fork_choice,
  ../beacon_chain/consensus_object_pools/[
    block_quarantine, blockchain_dag, block_clearance, attestation_pool,
    sync_committee_msg_pool,
  ],
  ../beacon_chain/spec/datatypes/[phase0, altair],
  ../beacon_chain/spec/[beaconstate, state_transition, helpers, network, validator],
  ../beacon_chain/validators/validator_pool,
  # Test utilities
  ./testutil,
  ./testdbutil,
  ./testblockutil

proc pruneAtFinalization(dag: ChainDAGRef, attPool: AttestationPool) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()
    # pool[].prune() # We test logic without att_1_0 pool / fork choice pruning

suite "Gossip validation " & preset():
  setup:
    # Genesis state that results in 3 members per committee
    let rng = HmacDrbgContext.new()
    var
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(
        ChainDAGRef,
        defaultRuntimeConfig,
        makeTestDB(SLOTS_PER_EPOCH * 3),
        validatorMonitor,
        {},
      )
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = newClone(Quarantine.init())
      pool = newClone(AttestationPool.init(dag, quarantine))
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()
      batchCrypto = BatchCrypto
        .new(
          rng,
          eager = proc(): bool =
            false,
          genesis_validators_root = dag.genesis_validators_root,
          taskpool,
        )
        .expect("working batcher")
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(
        defaultRuntimeConfig, state[], getStateField(state[], slot) + 1, cache, info, {}
      )
      .isOk()

  test "Empty committee when no committee for slot":
    template committee(idx: uint64): untyped =
      get_beacon_committee(dag.headState, dag.head.slot, idx.CommitteeIndex, cache)

    template committeeLen(idx: uint64): untyped =
      get_beacon_committee_len(dag.headState, dag.head.slot, idx.CommitteeIndex, cache)

    check:
      committee(0).len > 0
      committee(63).len == 0

    check:
      committeeLen(2) > 0
      committeeLen(63) == 0

  test "validateAttestation":
    var cache: StateCache
    for blck in makeTestBlocks(
      dag.headState, cache, int(SLOTS_PER_EPOCH * 5), attested = false
    ):
      let added = dag.addHeadBlock(verifier, blck.phase0Data) do(
        blckRef: BlockRef,
        signedBlock: phase0.TrustedSignedBeaconBlock,
        epochRef: EpochRef,
        unrealized: FinalityCheckpoints
      ):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, unrealized, signedBlock.message,
          blckRef.slot.start_beacon_time,
        )

      check:
        added.isOk()
      dag.updateHead(added[], quarantine[], [])
      pruneAtFinalization(dag, pool[])

    var
      # Create attestations for slot 1
      beacon_committee =
        get_beacon_committee(dag.headState, dag.head.slot, 0.CommitteeIndex, cache)
      att_1_0 =
        makeAttestation(dag.headState, dag.head.root, beacon_committee[0], cache)
      att_1_1 =
        makeAttestation(dag.headState, dag.head.root, beacon_committee[1], cache)

      committees_per_slot =
        get_committee_count_per_slot(dag.headState, att_1_0.data.slot.epoch, cache)

      subnet = compute_subnet_for_attestation(
        committees_per_slot, att_1_0.data.slot, att_1_0.data.index.CommitteeIndex
      )

      beaconTime = att_1_0.data.slot.start_beacon_time()

    check:
      validateAttestation(pool, batchCrypto, att_1_0, beaconTime, subnet, true)
      .waitFor().isOk

      # Same validator again
      validateAttestation(pool, batchCrypto, att_1_0, beaconTime, subnet, true)
      .waitFor()
      .error()[0] == ValidationResult.Ignore

    pool[].nextAttestationEpoch.setLen(0) # reset for test
    check:
      # Wrong subnet

      validateAttestation(
        pool, batchCrypto, att_1_0, beaconTime, SubnetId(subnet.uint8 + 1), true
      )
      .waitFor().isErr

    pool[].nextAttestationEpoch.setLen(0) # reset for test
    check:
      # Too far in the future

      validateAttestation(
        pool, batchCrypto, att_1_0, beaconTime - 1.seconds, subnet, true
      )
      .waitFor().isErr

    pool[].nextAttestationEpoch.setLen(0) # reset for test
    check:
      # Too far in the past

      validateAttestation(
        pool,
        batchCrypto,
        att_1_0,
        beaconTime - (SECONDS_PER_SLOT * SLOTS_PER_EPOCH - 1).int.seconds,
        subnet,
        true,
      )
      .waitFor().isErr

    block:
      var broken = att_1_0
      broken.signature.blob[0] += 1
      pool[].nextAttestationEpoch.setLen(0) # reset for test
      check:
        # Invalid signature

        validateAttestation(pool, batchCrypto, broken, beaconTime, subnet, true)
        .waitFor()
        .error()[0] == ValidationResult.Reject

    block:
      var broken = att_1_0
      broken.signature.blob[5] += 1
      pool[].nextAttestationEpoch.setLen(0) # reset for test
      # One invalid, one valid (batched)
      let
        fut_1_0 =
          validateAttestation(pool, batchCrypto, broken, beaconTime, subnet, true)
        fut_1_1 =
          validateAttestation(pool, batchCrypto, att_1_1, beaconTime, subnet, true)

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
        fut_1_0 =
          validateAttestation(pool, batchCrypto, broken, beaconTime, subnet, true)
        fut_1_1 =
          validateAttestation(pool, batchCrypto, att_1_1, beaconTime, subnet, true)

      check:
        fut_1_0.waitFor().error()[0] == ValidationResult.Reject
        fut_1_1.waitFor().isOk()

suite "Gossip validation - Altair":
  let cfg = block:
    var res = defaultRuntimeConfig
    res.ALTAIR_FORK_EPOCH = (EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 2).Epoch
    res

  proc addBlock(
      dag: ChainDAGRef,
      cache: var StateCache,
      verifier: var BatchVerifier,
      quarantine: var Quarantine,
  ) =
    for blck in makeTestBlocks(
      dag.headState, cache, blocks = 1, attested = false, cfg = cfg
    ):
      let added = withBlck(blck):
        const nilCallback = (consensusFork.OnBlockAddedCallback)(nil)
        dag.addHeadBlock(verifier, forkyBlck, nilCallback)
      check:
        added.isOk()
      dag.updateHead(added[], quarantine, [])

  proc getFirstAggregator(
      dag: ChainDAGRef, signatureSlot: Slot
  ): tuple[subcommitteeIdx: SyncSubcommitteeIndex, indexInSubcommittee: int] =
    const indicesPerSubcommittee = SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT
    for i, index in dag.syncCommitteeParticipants(signatureSlot):
      if (signatureSlot + 1).is_sync_committee_period:
        var isAlsoInNextCommittee = false
        for other in dag.syncCommitteeParticipants(signatureSlot + 1):
          if other == index:
            isAlsoInNextCommittee = true
            break
        if isAlsoInNextCommittee:
          continue
      let
        subcommitteeIndex = SyncSubcommitteeIndex(i div indicesPerSubcommittee)
        pubkey = getStateField(dag.headState, validators).item(index).pubkey
        keystoreData = KeystoreData(
          kind: KeystoreKind.Local, pubkey: pubkey, privateKey: MockPrivKeys[index]
        )
        validator = AttachedValidator(
          kind: ValidatorKind.Local, data: keystoreData, index: Opt.some index
        )
        proofFut = validator.getSyncCommitteeSelectionProof(
          getStateField(dag.headState, fork),
          getStateField(dag.headState, genesis_validators_root),
          getStateField(dag.headState, slot),
          subcommitteeIndex,
        )
      check proofFut.completed # Local signatures complete synchronously
      let proof = proofFut.value
      check proof.isOk
      if is_sync_committee_aggregator(proof.get):
        return (
          subcommitteeIdx: subcommitteeIndex,
          indexInSubcommittee: i mod indicesPerSubcommittee,
        )
    raiseAssert "No sync aggregator found who's not also part of next committee"

  proc getSyncCommitteeMessage(
      dag: ChainDAGRef,
      msgSlot: Slot,
      subcommitteeIdx: SyncSubcommitteeIndex,
      indexInSubcommittee: int,
      signatureSlot = Opt.none(Slot),
  ): tuple[validator: AttachedValidator, numPresent: int, msg: SyncCommitteeMessage] =
    let
      signatureSlot = signatureSlot.get(msgSlot + 1)
      syncCommittee = @(dag.syncCommitteeParticipants(signatureSlot))
      subcommittee = toSeq(syncCommittee.syncSubcommittee(subcommitteeIdx))
      index = subcommittee[indexInSubcommittee]
      numPresent = subcommittee.count(index)
      pubkey = getStateField(dag.headState, validators).item(index).pubkey
      keystoreData = KeystoreData(
        kind: KeystoreKind.Local, pubkey: pubkey, privateKey: MockPrivKeys[index]
      )
      validator = AttachedValidator(
        kind: ValidatorKind.Local, data: keystoreData, index: Opt.some index
      )
      msgFut = validator.getSyncCommitteeMessage(
        getStateField(dag.headState, fork),
        getStateField(dag.headState, genesis_validators_root),
        msgSlot,
        dag.headState.latest_block_root,
      )
    check msgFut.completed # Local signatures complete synchronously
    let msg = msgFut.value
    check msg.isOk
    (validator: validator, numPresent: numPresent, msg: msg.get)

  setup:
    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      quarantine = newClone(Quarantine.init())
      rng = HmacDrbgContext.new()
      syncCommitteePool = newClone(SyncCommitteeMsgPool.init(rng, cfg))
    var
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)

  template prepare(numValidators: Natural): untyped {.dirty.} =
    let
      dag = ChainDAGRef.init(
        cfg, makeTestDB(numValidators, cfg = cfg), validatorMonitor, {}
      )
      batchCrypto = BatchCrypto
        .new(
          rng,
          eager = proc(): bool =
            false,
          genesis_validators_root = dag.genesis_validators_root,
          taskpool,
        )
        .expect("working batcher")
    var
      cache: StateCache
      info: ForkedEpochInfo
    doAssert process_slots(
      cfg,
      dag.headState,
      (cfg.ALTAIR_FORK_EPOCH - 1).start_slot(),
      cache,
      info,
      flags = {},
    ).isOk
    for i in 0 ..< SLOTS_PER_EPOCH:
      dag.addBlock(cache, verifier, quarantine[])

  teardown:
    taskpool.shutdown()

  test "Period boundary":
    prepare(numValidators = SYNC_COMMITTEE_SIZE * 2)

    # Advance to the last slot before period 2.
    # The first two periods share the same sync committee,
    # so are not suitable for the test
    for i in 0 ..< SLOTS_PER_EPOCH:
      dag.addBlock(cache, verifier, quarantine[])
    doAssert process_slots(
      cfg,
      dag.headState,
      (2.SyncCommitteePeriod.start_epoch() - 1).start_slot(),
      cache,
      info,
      flags = {},
    ).isOk
    for i in 0 ..< SLOTS_PER_EPOCH - 1:
      dag.addBlock(cache, verifier, quarantine[])
    let slot = getStateField(dag.headState, slot)

    # The following slots determine what the sync committee signs:
    # 1. `state.latest_block_header.slot` --> ConsensusFork of signed block
    # 2. `state.slot` --> ForkDigest of signature
    # 3. `state.slot + 1` --> Sync committee
    proc checkWithSignatureSlot(signatureSlot: Slot, expectValid: bool) =
      warn "checkWithSignatureSlot", signatureSlot, expectValid

      let
        (subcommitteeIdx, indexInSubcommittee) = dag.getFirstAggregator(signatureSlot)
        (validator, expectedCount, msg) = dag.getSyncCommitteeMessage(
          slot,
          subcommitteeIdx,
          indexInSubcommittee,
          signatureSlot = Opt.some(signatureSlot),
        )
        msgVerdict = waitFor dag.validateSyncCommitteeMessage(
          quarantine,
          batchCrypto,
          syncCommitteePool,
          msg,
          subcommitteeIdx,
          slot.start_beacon_time(),
          checkSignature = true,
        )
      check msgVerdict.isOk == expectValid

      let (bid, cookedSig, positions) =
        if msgVerdict.isOk:
          msgVerdict.get
        else:
          let
            blockRoot = msg.beacon_block_root
            blck = dag.getBlockRef(blockRoot).expect("Block present")
            sig = msg.signature.load().expect("Signature OK")
            positionsInSubcommittee = dag.getSubcommitteePositions(
              signatureSlot, subcommitteeIdx, msg.validator_index
            )
          (blck.bid, sig, positionsInSubcommittee)

      syncCommitteePool[] = SyncCommitteeMsgPool.init(rng, cfg)
      syncCommitteePool[].addSyncCommitteeMessage(
        msg.slot, bid, msg.validator_index, cookedSig, subcommitteeIdx, positions
      )
      let contrib = block:
        let contrib = (ref SignedContributionAndProof)(
          message: ContributionAndProof(
            aggregator_index: distinctBase(validator.index.get),
            selection_proof: validator.getSyncCommitteeSelectionProof(
              getStateField(dag.headState, fork),
              getStateField(dag.headState, genesis_validators_root),
              getStateField(dag.headState, slot),
              subcommitteeIdx,
            ).value.get,
          )
        )
        check syncCommitteePool[].produceContribution(
          slot, bid, subcommitteeIdx, contrib.message.contribution
        )
        syncCommitteePool[].addContribution(
          contrib[], bid, contrib.message.contribution.signature.load.get
        )
        let signRes = waitFor validator.getContributionAndProofSignature(
          getStateField(dag.headState, fork),
          getStateField(dag.headState, genesis_validators_root),
          contrib[].message,
        )
        doAssert(signRes.isOk())
        contrib[].signature = signRes.get()
        contrib
      syncCommitteePool[] = SyncCommitteeMsgPool.init(rng, cfg)
      let contribVerdict = waitFor dag.validateContribution(
        quarantine,
        batchCrypto,
        syncCommitteePool,
        contrib[],
        slot.start_beacon_time(),
        checkSignature = true,
      )
      check contribVerdict.isOk == expectValid

    # We are at the last slot of a sync committee period:
    check slot == (slot.sync_committee_period + 1).start_slot() - 1

    # Therefore, messages from `current_sync_committee` are no longer allowed
    checkWithSignatureSlot(signatureSlot = slot, expectValid = false)

    # Messages signed from `next_sync_committee` are accepted
    checkWithSignatureSlot(signatureSlot = slot + 1, expectValid = true)

  test "validateSyncCommitteeMessage - Duplicate pubkey":
    prepare(numValidators = SLOTS_PER_EPOCH)

    for i in 0 ..< SLOTS_PER_EPOCH:
      dag.addBlock(cache, verifier, quarantine[])

    const
      subcommitteeIdx = 0.SyncSubcommitteeIndex
      indexInSubcommittee = 0
    let
      state = assignClone(dag.headState.altairData)
      slot = state[].data.slot
      (validator, expectedCount, msg) =
        dag.getSyncCommitteeMessage(slot, subcommitteeIdx, indexInSubcommittee)

      res = waitFor validateSyncCommitteeMessage(
        dag,
        quarantine,
        batchCrypto,
        syncCommitteePool,
        msg,
        subcommitteeIdx,
        slot.start_beacon_time(),
        checkSignature = true,
      )
      (bid, cookedSig, positions) = res.get()

    syncCommitteePool[].addSyncCommitteeMessage(
      msg.slot, bid, msg.validator_index, cookedSig, subcommitteeIdx, positions
    )

    let
      contrib = block:
        let contrib = (ref SignedContributionAndProof)()
        check:
          syncCommitteePool[].produceContribution(
            slot, bid, subcommitteeIdx, contrib.message.contribution
          )
        syncCommitteePool[].addContribution(
          contrib[], bid, contrib.message.contribution.signature.load.get
        )
        let signRes = waitFor validator.getContributionAndProofSignature(
          state[].data.fork, state[].data.genesis_validators_root, contrib[].message
        )
        doAssert(signRes.isOk())
        contrib[].signature = signRes.get()
        contrib
      aggregate = syncCommitteePool[].produceSyncAggregate(bid, slot + 1)

    check:
      expectedCount > 1 # Cover edge case
      res.isOk
      contrib.message.contribution.aggregation_bits.countOnes == expectedCount
      aggregate.sync_committee_bits.countOnes == expectedCount

      # Same message twice should be ignored

      validateSyncCommitteeMessage(
        dag,
        quarantine,
        batchCrypto,
        syncCommitteePool,
        msg,
        subcommitteeIdx,
        state[].data.slot.start_beacon_time(),
        true,
      )
      .waitFor()
      .isErr()

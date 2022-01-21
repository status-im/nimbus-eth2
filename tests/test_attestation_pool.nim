# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/sequtils,
  # Status lib
  unittest2,
  chronicles, chronos,
  stew/byteutils,
  eth/keys, taskpools,
  # Internal
  ../beacon_chain/gossip_processing/[gossip_validation],
  ../beacon_chain/fork_choice/[fork_choice_types, fork_choice],
  ../beacon_chain/consensus_object_pools/[
    block_quarantine, blockchain_dag, block_clearance, attestation_pool],
  ../beacon_chain/spec/datatypes/phase0,
  ../beacon_chain/spec/[beaconstate, helpers, state_transition, validator],
  ../beacon_chain/beacon_clock,
  # Test utilities
  ./testutil, ./testdbutil, ./testblockutil

func combine(tgt: var Attestation, src: Attestation) =
  ## Combine the signature and participation bitfield, with the assumption that
  ## the same data is being signed - if the signatures overlap, they are not
  ## combined.

  doAssert tgt.data == src.data

  # In a BLS aggregate signature, one needs to count how many times a
  # particular public key has been added - since we use a single bit per key, we
  # can only it once, thus we can never combine signatures that overlap already!
  doAssert not tgt.aggregation_bits.overlaps(src.aggregation_bits)

  tgt.aggregation_bits.incl(src.aggregation_bits)

  var agg {.noInit.}: AggregateSignature
  agg.init(tgt.signature.load().get())
  agg.aggregate(src.signature.load.get())
  tgt.signature = agg.finish().toValidatorSig()

func loadSig(a: Attestation): CookedSig =
  a.signature.load.get()

proc pruneAtFinalization(dag: ChainDAGRef, attPool: AttestationPool) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()
    # pool[].prune() # We test logic without attestation pool / fork choice pruning

suite "Attestation pool processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  setup:
    # Genesis state that results in 6 members per committee
    var
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(
        ChainDAGRef, defaultRuntimeConfig, makeTestDB(SLOTS_PER_EPOCH * 6),
        validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)
      quarantine = newClone(Quarantine.init())
      pool = newClone(AttestationPool.init(dag, quarantine))
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(
        dag.cfg, state.data, getStateField(state.data, slot) + 1, cache, info,
        {}).isOk()

  test "Can add and retrieve simple attestations" & preset():
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)
      attestation = makeAttestation(state[].data, state.blck.root, bc0[0], cache)

    pool[].addAttestation(
      attestation, @[bc0[0]], attestation.loadSig,
      attestation.data.slot.start_beacon_time)

    check:
      # Added attestation, should get it back
      toSeq(pool[].attestations(none(Slot), none(CommitteeIndex))) ==
        @[attestation]
      toSeq(pool[].attestations(
        some(attestation.data.slot), none(CommitteeIndex))) == @[attestation]
      toSeq(pool[].attestations(
        some(attestation.data.slot), some(attestation.data.index.CommitteeIndex))) ==
        @[attestation]
      toSeq(pool[].attestations(none(Slot), some(attestation.data.index.CommitteeIndex))) ==
        @[attestation]
      toSeq(pool[].attestations(some(
        attestation.data.slot + 1), none(CommitteeIndex))) == []
      toSeq(pool[].attestations(
        none(Slot), some(CommitteeIndex(attestation.data.index + 1)))) == []

      process_slots(
        defaultRuntimeConfig, state.data,
        getStateField(state.data, slot) + MIN_ATTESTATION_INCLUSION_DELAY, cache,
        info, {}).isOk()

    let attestations = pool[].getAttestationsForBlock(state.data, cache)

    check:
      attestations.len == 1
      pool[].getAggregatedAttestation(1.Slot, 0.CommitteeIndex).isSome()

    let
      root1 = addTestBlock(
        state.data, cache, attestations = attestations,
        nextSlot = false).phase0Data.root
      bc1 = get_beacon_committee(
        state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)
      att1 = makeAttestation(state[].data, root1, bc1[0], cache)

    check:
      withState(state.data): state.latest_block_root == root1

      process_slots(
        defaultRuntimeConfig, state.data,
        getStateField(state.data, slot) + MIN_ATTESTATION_INCLUSION_DELAY, cache,
        info, {}).isOk()

      withState(state.data): state.latest_block_root == root1

    check:
      # shouldn't include already-included attestations
      pool[].getAttestationsForBlock(state.data, cache) == []

    pool[].addAttestation(
      att1, @[bc1[0]], att1.loadSig, att1.data.slot.start_beacon_time)

    check:
      # but new ones should go in
      pool[].getAttestationsForBlock(state.data, cache).len() == 1

    let
      att2 = makeAttestation(state[].data, root1, bc1[1], cache)
    pool[].addAttestation(
      att2, @[bc1[1]], att2.loadSig, att2.data.slot.start_beacon_time)

    let
      combined = pool[].getAttestationsForBlock(state.data, cache)

    check:
      # New attestations should be combined with old attestations
      combined.len() == 1
      combined[0].aggregation_bits.countOnes() == 2

    pool[].addAttestation(
      combined[0], @[bc1[1], bc1[0]], combined[0].loadSig,
      combined[0].data.slot.start_beacon_time)

    check:
      # readding the combined attestation shouldn't have an effect
      pool[].getAttestationsForBlock(state.data, cache).len() == 1

    let
      # Someone votes for a different root
      att3 = makeAttestation(state[].data, Eth2Digest(), bc1[2], cache)
    pool[].addAttestation(
      att3, @[bc1[2]], att3.loadSig, att3.data.slot.start_beacon_time)

    check:
      # We should now get both attestations for the block, but the aggregate
      # should be the one with the most votes
      pool[].getAttestationsForBlock(state.data, cache).len() == 2
      pool[].getAggregatedAttestation(2.Slot, 0.CommitteeIndex).
        get().aggregation_bits.countOnes() == 2
      pool[].getAggregatedAttestation(2.Slot, hash_tree_root(att2.data)).
        get().aggregation_bits.countOnes() == 2

    let
      # Someone votes for a different root
      att4 = makeAttestation(state[].data, Eth2Digest(), bc1[2], cache)
    pool[].addAttestation(
      att4, @[bc1[2]], att3.loadSig, att3.data.slot.start_beacon_time)

  test "Working with aggregates" & preset():
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)

    var
      att0 = makeAttestation(state[].data, state.blck.root, bc0[0], cache)
      att0x = att0
      att1 = makeAttestation(state[].data, state.blck.root, bc0[1], cache)
      att2 = makeAttestation(state[].data, state.blck.root, bc0[2], cache)
      att3 = makeAttestation(state[].data, state.blck.root, bc0[3], cache)

    # Both attestations include member 2 but neither is a subset of the other
    att0.combine(att2)
    att1.combine(att2)

    pool[].addAttestation(
      att0, @[bc0[0], bc0[2]], att0.loadSig, att0.data.slot.start_beacon_time)
    pool[].addAttestation(
      att1, @[bc0[1], bc0[2]], att1.loadSig, att1.data.slot.start_beacon_time)

    check:
      process_slots(
        defaultRuntimeConfig, state.data,
        getStateField(state.data, slot) + MIN_ATTESTATION_INCLUSION_DELAY, cache,
        info, {}).isOk()

    check:
      pool[].getAttestationsForBlock(state.data, cache).len() == 2
      # Can get either aggregate here, random!
      pool[].getAggregatedAttestation(1.Slot, 0.CommitteeIndex).isSome()

    # Add in attestation 3 - both aggregates should now have it added
    pool[].addAttestation(
      att3, @[bc0[3]], att3.loadSig, att3.data.slot.start_beacon_time)

    block:
      let attestations = pool[].getAttestationsForBlock(state.data, cache)
      check:
        attestations.len() == 2
        attestations[0].aggregation_bits.countOnes() == 3
        # Can get either aggregate here, random!
        pool[].getAggregatedAttestation(1.Slot, 0.CommitteeIndex).isSome()

    # Add in attestation 0 as single - attestation 1 is now a superset of the
    # aggregates in the pool, so everything else should be removed
    pool[].addAttestation(
      att0x, @[bc0[0]], att0x.loadSig, att0x.data.slot.start_beacon_time)

    block:
      let attestations = pool[].getAttestationsForBlock(state.data, cache)
      check:
        attestations.len() == 1
        attestations[0].aggregation_bits.countOnes() == 4
        pool[].getAggregatedAttestation(1.Slot, 0.CommitteeIndex).isSome()

  test "Everyone voting for something different" & preset():
    var attestations: int
    for i in 0..<SLOTS_PER_EPOCH:
      var root: Eth2Digest
      root.data[0..<8] = toBytesBE(i.uint64)
      let
        bc0 = get_beacon_committee(
          state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)

      for j in 0..<bc0.len():
        root.data[8..<16] = toBytesBE(j.uint64)
        var att = makeAttestation(state[].data, root, bc0[j], cache)
        pool[].addAttestation(
          att, @[bc0[j]], att.loadSig, att.data.slot.start_beacon_time)
        inc attestations

      check:
        process_slots(
          defaultRuntimeConfig, state.data,
          getStateField(state.data, slot) + 1, cache, info, {}).isOk()

    doAssert attestations.uint64 > MAX_ATTESTATIONS,
      "6*SLOTS_PER_EPOCH validators > 128 mainnet MAX_ATTESTATIONS"
    check:
      # Fill block with attestations
      pool[].getAttestationsForBlock(state.data, cache).lenu64() ==
        MAX_ATTESTATIONS
      pool[].getAggregatedAttestation(
        getStateField(state.data, slot) - 1, 0.CommitteeIndex).isSome()

  test "Attestations may arrive in any order" & preset():
    var cache = StateCache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(state[].data, state.blck.root, bc0[0], cache)

    check:
      process_slots(
        defaultRuntimeConfig, state.data, getStateField(state.data, slot) + 1,
        cache, info, {}).isOk()

    let
      bc1 = get_beacon_committee(state[].data,
        getStateField(state.data, slot), 0.CommitteeIndex, cache)
      attestation1 = makeAttestation(state[].data, state.blck.root, bc1[0], cache)

    # test reverse order
    pool[].addAttestation(
      attestation1, @[bc1[0]], attestation1.loadSig,
      attestation1.data.slot.start_beacon_time)
    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.loadSig,
      attestation0.data.slot.start_beacon_time)

    let attestations = pool[].getAttestationsForBlock(state.data, cache)

    check:
      attestations.len == 1

  test "Attestations should be combined" & preset():
    var cache = StateCache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)
      attestation0 =
        makeAttestation(state[].data, state.blck.root, bc0[0], cache)
      attestation1 =
        makeAttestation(state[].data, state.blck.root, bc0[1], cache)

    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.loadSig,
      attestation0.data.slot.start_beacon_time)
    pool[].addAttestation(
      attestation1, @[bc0[1]], attestation1.loadSig,
      attestation1.data.slot.start_beacon_time)

    check:
      process_slots(
        defaultRuntimeConfig, state.data,
        MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1, cache, info, {}).isOk()

    let attestations = pool[].getAttestationsForBlock(state.data, cache)

    check:
      attestations.len == 1

  test "Attestations may overlap, bigger first" & preset():
    var cache = StateCache()

    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[].data, getStateField(state.data, slot), 0.CommitteeIndex, cache)
      attestation0 =
        makeAttestation(state[].data, state.blck.root, bc0[0], cache)
      attestation1 =
        makeAttestation(state[].data, state.blck.root, bc0[1], cache)

    attestation0.combine(attestation1)

    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.loadSig,
      attestation0.data.slot.start_beacon_time)
    pool[].addAttestation(
      attestation1, @[bc0[1]], attestation1.loadSig,
      attestation1.data.slot.start_beacon_time)

    check:
      process_slots(
        defaultRuntimeConfig, state.data,
        MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1, cache, info, {}).isOk()

    let attestations = pool[].getAttestationsForBlock(state.data, cache)

    check:
      attestations.len == 1

  test "Attestations may overlap, smaller first" & preset():
    var cache = StateCache()
    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(state[].data,
        getStateField(state.data, slot), 0.CommitteeIndex, cache)
      attestation0 =
        makeAttestation(state[].data, state.blck.root, bc0[0], cache)
      attestation1 =
        makeAttestation(state[].data, state.blck.root, bc0[1], cache)

    attestation0.combine(attestation1)

    pool[].addAttestation(
      attestation1, @[bc0[1]], attestation1.loadSig,
      attestation1.data.slot.start_beacon_time)
    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.loadSig,
      attestation0.data.slot.start_beacon_time)

    check:
      process_slots(
        defaultRuntimeConfig, state.data,
        MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1, cache, info, {}).isOk()

    let attestations = pool[].getAttestationsForBlock(state.data, cache)

    check:
      attestations.len == 1

  test "Fork choice returns latest block with no attestations":
    var cache = StateCache()
    let
      b1 = addTestBlock(state.data, cache).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

    let head = pool[].selectHead(b1Add[].slot.start_beacon_time).get()
    check:
      head == b1Add[]

    let
      b2 = addTestBlock(state.data, cache).phase0Data
      b2Add = dag.addHeadBlock(verifier, b2) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

    let head2 = pool[].selectHead(b2Add[].slot.start_beacon_time).get()

    check:
      head2 == b2Add[]

  test "Fork choice returns block with attestation":
    var cache = StateCache()
    let
      b10 = makeTestBlock(state.data, cache).phase0Data
      b10Add = dag.addHeadBlock(verifier, b10) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

    let head = pool[].selectHead(b10Add[].slot.start_beacon_time).get()

    check:
      head == b10Add[]

    let
      b11 = makeTestBlock(state.data, cache,
        graffiti = GraffitiBytes [1'u8, 0, 0, 0 ,0 ,0 ,0 ,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      ).phase0Data
      b11Add = dag.addHeadBlock(verifier, b11) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

      bc1 = get_beacon_committee(
        state[].data, getStateField(state.data, slot) - 1, 1.CommitteeIndex,
        cache)
      attestation0 = makeAttestation(state[].data, b10.root, bc1[0], cache)

    pool[].addAttestation(
      attestation0, @[bc1[0]], attestation0.loadSig,
      attestation0.data.slot.start_beacon_time)

    let head2 = pool[].selectHead(b10Add[].slot.start_beacon_time).get()

    check:
      # Single vote for b10 and no votes for b11
      head2 == b10Add[]

    let
      attestation1 = makeAttestation(state[].data, b11.root, bc1[1], cache)
      attestation2 = makeAttestation(state[].data, b11.root, bc1[2], cache)
    pool[].addAttestation(
      attestation1, @[bc1[1]], attestation1.loadSig,
      attestation1.data.slot.start_beacon_time)

    let head3 = pool[].selectHead(b10Add[].slot.start_beacon_time).get()
    let bigger = if b11.root.data < b10.root.data: b10Add else: b11Add

    check:
      # Ties broken lexicographically in spec -> ?
      head3 == bigger[]

    pool[].addAttestation(
      attestation2, @[bc1[2]], attestation2.loadSig,
      attestation2.data.slot.start_beacon_time)

    let head4 = pool[].selectHead(b11Add[].slot.start_beacon_time).get()

    check:
      # Two votes for b11
      head4 == b11Add[]

  test "Trying to add a block twice tags the second as an error":
    var cache = StateCache()
    let
      b10 = makeTestBlock(state.data, cache).phase0Data
      b10Add = dag.addHeadBlock(verifier, b10) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message,
        blckRef.slot.start_beacon_time)

    let head = pool[].selectHead(b10Add[].slot.start_beacon_time).get()

    check:
      head == b10Add[]

    # -------------------------------------------------------------
    # Add back the old block to ensure we have a duplicate error
    let b10_clone = b10 # Assumes deep copy
    let b10Add_clone = dag.addHeadBlock(verifier, b10_clone) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

    doAssert: b10Add_clone.error == BlockError.Duplicate

  test "Trying to add a duplicate block from an old pruned epoch is tagged as an error":
    # Note: very sensitive to stack usage

    dag.updateFlags.incl {skipBLSValidation}
    var cache = StateCache()
    let
      b10 = addTestBlock(state.data, cache).phase0Data
      b10Add = dag.addHeadBlock(verifier, b10) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

    let head = pool[].selectHead(b10Add[].slot.start_beacon_time).get()

    doAssert: head == b10Add[]

    # -------------------------------------------------------------
    let b10_clone = b10 # Assumes deep copy

    # -------------------------------------------------------------
    # Pass an epoch
    var attestations: seq[Attestation]

    for epoch in 0 ..< 5:
      let start_slot = start_slot(Epoch epoch)
      let committees_per_slot =
        get_committee_count_per_slot(state[].data, Epoch epoch, cache)
      for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
        let new_block = addTestBlock(
          state.data, cache, attestations = attestations).phase0Data

        let blockRef = dag.addHeadBlock(verifier, new_block) do (
            blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
            epochRef: EpochRef):
          # Callback add to fork choice if valid
          pool[].addForkChoice(
            epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

        let head = pool[].selectHead(blockRef[].slot.start_beacon_time).get()
        doAssert: head == blockRef[]
        dag.updateHead(head, quarantine[])
        pruneAtFinalization(dag, pool[])

        attestations.setlen(0)
        for committee_index in get_committee_indices(committees_per_slot):
          let committee = get_beacon_committee(
            state[].data, getStateField(state.data, slot), committee_index,
            cache)

          # Create a bitfield filled with the given count per attestation,
          # exactly on the right-most part of the committee field.
          var aggregation_bits = init(CommitteeValidatorsBits, committee.len)
          for v in 0 ..< committee.len * 2 div 3 + 1:
            aggregation_bits[v] = true

          attestations.add Attestation(
            aggregation_bits: aggregation_bits,
            data: makeAttestationData(
              state[].data, getStateField(state.data, slot),
              committee_index, blockRef.get().root)
            # signature: ValidatorSig()
          )

      cache = StateCache()

    # -------------------------------------------------------------
    # Prune

    doAssert: dag.finalizedHead.slot != 0

    pool[].prune()
    doAssert: b10.root notin pool.forkChoice.backend

    # Add back the old block to ensure we have a duplicate error
    let b10Add_clone = dag.addHeadBlock(verifier, b10_clone) do (
          blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
          epochRef: EpochRef):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, signedBlock.message, blckRef.slot.start_beacon_time)

    doAssert: b10Add_clone.error == BlockError.Duplicate

# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Status lib
  unittest2,
  chronicles,
  # Internal
  ../beacon_chain/consensus_object_pools/[
    blockchain_dag, block_clearance, attestation_pool],
  ../beacon_chain/spec/state_transition,
  ../beacon_chain/beacon_clock,
  # Test utilities
  ./testutil, ./testdbutil, ./testblockutil, ./consensus_spec/fixtures_utils

from std/sequtils import mapIt, toSeq
from stew/byteutils import `<`
from ../beacon_chain/consensus_object_pools/block_quarantine import
  Quarantine, init
from ../beacon_chain/fork_choice/fork_choice import mark_root_invalid
from ../beacon_chain/fork_choice/proto_array import checkpoints
from ../beacon_chain/spec/beaconstate import
  attester_dependent_root, check_attestation, get_attesting_indices,
  latest_block_root
from ../beacon_chain/spec/validator import
  get_beacon_committee, get_committee_count_per_slot, get_committee_indices,
  get_committee_index_one
from ./testbcutil import addHeadBlock, willSelectNewHead

func combine(tgt: var electra.Attestation, src: electra.Attestation) =
  ## Combine the signature and participation bitfield, with the assumption that
  ## the same data is being signed - if the signatures overlap, they are not
  ## combined.

  doAssert tgt.data == src.data

  # In a BLS aggregate signature, one needs to count how many times a
  # particular public key has been added - since we use a single bit per key, we
  # can only it once, thus we can never combine signatures that overlap already!
  doAssert not tgt.aggregation_bits.overlaps(src.aggregation_bits)

  tgt.aggregation_bits.incl(src.aggregation_bits)

  var agg {.noinit.}: AggregateSignature
  agg.init(tgt.signature.load().get())
  agg.aggregate(src.signature.load.get())
  tgt.signature = agg.finish().toValidatorSig()

func loadSig(a: electra.Attestation): CookedSig =
  a.signature.load.get()

proc pruneAtFinalization(dag: ChainDAGRef, attPool: AttestationPool) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()
    # pool[].prune() # We test logic without attestation pool / fork choice pruning

# -1 here is the notional index in committee for which the attestation pool
# only requires external input regarding SingleAttestation messages. If, or
# when, this module starts testing SingleAttestation, those can't use this.
template addAttestation(a, b, c, d, e, f: untyped): untyped =
  addAttestation(a, b, c, d, -1, e, f)

proc getElectraAttestationsForBlock(
    pool: var AttestationPool, state: ForkedHashedBeaconState,
    cache: var StateCache): seq[electra.Attestation] =
  withState(state):
    when consensusFork >= ConsensusFork.Electra:
      pool.getAttestationsForBlock(forkyState, cache)
    else:
      raiseAssert "invalid fork"

suite "Attestation pool electra processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  setup:
    # Genesis state that results in 6 members per committee (2 committees total)
    let rng = HmacDrbgContext.new()
    const TOTAL_COMMITTEES = 2
    var
      cfg = genesisTestRuntimeConfig(ConsensusFork.Electra)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(
        ChainDAGRef, cfg,
        cfg.makeTestDB(
          TOTAL_COMMITTEES * TARGET_COMMITTEE_SIZE * SLOTS_PER_EPOCH),
        validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier {.used.} = BatchVerifier.init(rng, taskpool)
      quarantine = newClone(Quarantine.init(dag.cfg))
      pool = newClone(AttestationPool.init(dag, quarantine))
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(
        dag.cfg,
        state[],
        state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
        cache,
        info,
        {}).isOk()

    template startTime(attestation: electra.Attestation): BeaconTime =
      attestation.data.slot.start_beacon_time(cfg.timeParams)

    template addHeadBlockToForkChoice(
        blck: electra.SignedBeaconBlock,
        wallTime: BeaconTime): Result[BlockRef, VerifierError] =
      dag.addHeadBlock(verifier, blck) do (
          blckRef: BlockRef, signedBlock: electra.TrustedSignedBeaconBlock,
          state: electra.BeaconState,
          epochRef: EpochRef, unrealized: FinalityCheckpoints):
        # Callback add to fork choice if valid
        pool[].addForkChoice(
          epochRef, blckRef, unrealized, signedBlock.message, wallTime)

    template addHeadBlockToForkChoice(
        blck: electra.SignedBeaconBlock): Result[BlockRef, VerifierError] =
      addHeadBlockToForkChoice(
        blck, blck.message.slot.start_beacon_time(cfg.timeParams))

  test "Attestation from different branch" & preset():
    # Create two alternate histories with different shufflings
    check process_slots(
      dag.cfg, state[], (SLOTS_PER_EPOCH - 2).Slot, cache, info, {}).isOk
    var state2 = newClone(state[])

    const epoch = 3.Epoch
    template fillToEpoch(
        state: ref ForkedHashedBeaconState, cache: var StateCache) =
      while state[].slot.epoch <= epoch:
        check process_slots(
          dag.cfg, state[], state[].slot + 1, cache, info, {}).isOk
        let
          parent_root = withState(state[]): forkyState.latest_block_root
          attestations = makeFullAttestations(
            state[], parent_root, state[].slot, cache)
          blck = addTestBlock(
            state[], cache, attestations = attestations, cfg = dag.cfg)
        check dag.addHeadBlock(
          verifier, blck.electraData, OnBlockAdded[ConsensusFork.Electra](nil)).isOk

    # History 1 contains all odd blocks
    state.fillToEpoch(cache)

    # History 2 contains all even blocks
    var cache2 = StateCache()
    check process_slots(
      dag.cfg, state2[], state2[].slot + 1, cache2, info, {}).isOk
    state2.fillToEpoch(cache2)

    # The shuffling for epoch 3 among both chains should now be different
    let
      dependent_root1 = withState(state[]): forkyState.attester_dependent_root
      dependent_root2 = withState(state2[]): forkyState.attester_dependent_root
    check dependent_root1 != dependent_root2

    # Fill pool with attestations from both chains
    let
      cIndex = 0.CommitteeIndex
      att1 = block:
        let
          slot = state[].slot
          parent_root = withState(state[]): forkyState.latest_block_root
          committee = get_beacon_committee(state[], slot, cIndex, cache)
        makeElectraAttestation(state[], parent_root, committee[0], cache)
      att2 = block:
        let
          slot = state2[].slot
          parent_root = withState(state2[]): forkyState.latest_block_root
          committee = get_beacon_committee(state2[], slot, cIndex, cache2)
        makeElectraAttestation(state2[], parent_root, committee[0], cache2)
      maxSlot = max(att1.data.slot, att2.data.slot)

    # Advance time so attestations become valid
    check:
      process_slots(
        dag.cfg, state[], maxSlot + MIN_ATTESTATION_INCLUSION_DELAY,
        cache, info, {}).isOk
      process_slots(
        dag.cfg, state2[], maxSlot + MIN_ATTESTATION_INCLUSION_DELAY,
        cache2, info, {}).isOk

    # They should remain valid only within a compatible state
    withState(state[]):
      when consensusFork >= ConsensusFork.Electra:
        check:
          check_attestation(forkyState.data, att1, {}, cache).isOk
          check_attestation(forkyState.data, att2, {}, cache).isErr
    withState(state2[]):
      when consensusFork >= ConsensusFork.Electra:
        check:
          check_attestation(forkyState.data, att1, {}, cache2).isErr
          check_attestation(forkyState.data, att2, {}, cache2).isOk

    # If signature checks are skipped, state incompatibility is not detected
    const flags = {skipBlsValidation}
    withState(state[]):
      when consensusFork >= ConsensusFork.Electra:
        check:
          check_attestation(forkyState.data, att1, flags, cache).isOk
          check_attestation(forkyState.data, att2, flags, cache).isOk
    withState(state2[]):
      when consensusFork >= ConsensusFork.Electra:
        check:
          check_attestation(forkyState.data, att1, flags, cache2).isOk
          check_attestation(forkyState.data, att2, flags, cache2).isOk

    # An additional compatibility check catches that (used in block production)
    withState(state[]):
      check:
        check_attestation_compatible(dag, forkyState, att1).isOk
        check_attestation_compatible(dag, forkyState, att2).isErr
    withState(state2[]):
      check:
        check_attestation_compatible(dag, forkyState, att1).isErr
        check_attestation_compatible(dag, forkyState, att2).isOk

  test "Can add and retrieve simple electra attestations" & preset():
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)
      attestation = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)

    pool[].addAttestation(
      attestation, @[bc0[0]], attestation.aggregation_bits.len,
      attestation.loadSig, attestation.startTime)

    check cfg.process_slots(
      state[], state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      attestations.len == 1

    let
      root1 = addTestBlock(
        state[], cache, electraAttestations = attestations,
        nextSlot = false).electraData.root
      bc1 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)
      att1 = makeElectraAttestation(state[], root1, bc1[0], cache)

    check:
      withState(state[]): forkyState.latest_block_root == root1

      cfg.process_slots(
        state[], state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
        cache, info, {}).isOk()

      withState(state[]): forkyState.latest_block_root == root1

    check:
      # shouldn't include already-included attestations
      pool[].getElectraAttestationsForBlock(state[], cache) == []

    pool[].addAttestation(
      att1, @[bc1[0]], att1.aggregation_bits.len, att1.loadSig, att1.startTime)

    check:
      # but new ones should go in
      pool[].getElectraAttestationsForBlock(state[], cache).len() == 1

    let
      att2 = makeElectraAttestation(state[], root1, bc1[1], cache)
    pool[].addAttestation(
      att2, @[bc1[1]], att2.aggregation_bits.len, att2.loadSig, att2.startTime)

    let
      combined = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      # New attestations should be combined with old attestations
      combined.len() == 1
      combined[0].aggregation_bits.countOnes() == 2

    pool[].addAttestation(
      combined[0], @[bc1[1], bc1[0]], combined[0].aggregation_bits.len,
      combined[0].loadSig, combined[0].startTime)

    check:
      # readding the combined attestation shouldn't have an effect
      pool[].getElectraAttestationsForBlock(state[], cache).len() == 1

    let
      # Someone votes for a different root
      att3 = makeElectraAttestation(state[], ZERO_HASH, bc1[2], cache)
    pool[].addAttestation(
      att3, @[bc1[2]], att3.aggregation_bits.len, att3.loadSig, att3.startTime)

    check:
      # We should now get both attestations for the block, but the aggregate
      # should be the one with the most votes
      pool[].getElectraAttestationsForBlock(state[], cache).len() == 2
      pool[].getElectraAggregatedAttestation(2.Slot, hash_tree_root(combined[0].data),
        0.CommitteeIndex).get().aggregation_bits.countOnes() == 2
      pool[].getElectraAggregatedAttestation(2.Slot, hash_tree_root(att2.data), 0.CommitteeIndex).
         get().aggregation_bits.countOnes() == 2
      # requests to get and aggregate from different committees should be empty
      pool[].getElectraAggregatedAttestation(
        2.Slot, hash_tree_root(combined[0].data), 1.CommitteeIndex).isNone()

  test "Attestations with disjoint comittee bits and equal data into single on-chain aggregate" & preset():
    let
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)

      bc1 = get_beacon_committee(
        state[], state[].slot, 1.CommitteeIndex, cache)

      # atestation from committee 1
      attestation1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)

      # atestation from different committee with same data as
      # attestaton 1
      attestation2 = makeElectraAttestation(
        state[], state[].latest_block_root, bc1[1], cache)

    pool[].addAttestation(
      attestation1, @[bc0[0]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)

    pool[].addAttestation(
      attestation2, @[bc1[1]], attestation2.aggregation_bits.len,
      attestation2.loadSig, attestation2.startTime)

    check cfg.process_slots(
      state[], state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      # A single inal chain aggregated attestation should be created
      # with same data and joint committee,aggregation bits
      attestations.len == 1
      attestations[0].aggregation_bits.countOnes() == 2
      attestations[0].committee_bits.countOnes() == 2

  test "Aggregated attestations with disjoint comittee bits into a single on-chain aggregate" & preset():
    proc verifyAttestationSignature(attestation: electra.Attestation): bool =
      withState(state[]):
        let
          fork = pool.dag.cfg.forkAtEpoch(forkyState.data.slot.epoch)
          attesting_indices =
            forkyState.data.get_attesting_indices(attestation, cache)
        verify_attestation_signature(
          fork, pool.dag.genesis_validators_root, attestation.data,
          attesting_indices.mapIt(forkyState.data.validators.item(it).pubkey),
          attestation.signature)

    let
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)

      bc1 = get_beacon_committee(
        state[], state[].slot, 1.CommitteeIndex, cache)

      # attestation from first committee
      attestation1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)

      # another attestation from first committee with same data
      attestation2 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[1], cache)

      # attestation from different committee with same data as
      # attestation 1
      attestation3 = makeElectraAttestation(
        state[], state[].latest_block_root, bc1[1], cache)

    check:
      verifyAttestationSignature(attestation1)
      verifyAttestationSignature(attestation2)
      verifyAttestationSignature(attestation3)

    pool[].addAttestation(
      attestation1, @[bc0[0]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)

    pool[].addAttestation(
      attestation2, @[bc0[1]], attestation2.aggregation_bits.len,
      attestation2.loadSig, attestation2.startTime)

    pool[].addAttestation(
      attestation3, @[bc1[1]], attestation3.aggregation_bits.len,
      attestation3.loadSig, attestation3.startTime)

    check cfg.process_slots(
      state[], state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      verifyAttestationSignature(attestations[0])
      check_attestation(
        state[].electraData.data, attestations[0], {}, cache).isOk

      # A single final chain aggregated attestation should be created
      # with same data, 2 committee bits and 3 aggregation bits
      attestations.len == 1
      attestations[0].aggregation_bits.countOnes() == 3
      attestations[0].committee_bits.countOnes() == 2

  test "Everyone voting for something different" & preset():
    var attestations: int
    for i in 0..<SLOTS_PER_EPOCH:
      var root: Eth2Digest
      root.data[0..<8] = toBytesBE(i.uint64)
      let bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)

      for j in 0..<bc0.len():
        root.data[8..<16] = toBytesBE(j.uint64)
        let att = makeElectraAttestation(state[], root, bc0[j], cache)
        pool[].addAttestation(
          att, @[bc0[j]], att.aggregation_bits.len, att.loadSig, att.startTime)
        inc attestations

      check cfg.process_slots(
        state[], state[].slot + 1, cache, info, {}).isOk()

    doAssert attestations.uint64 > MAX_ATTESTATIONS_ELECTRA,
      "6*SLOTS_PER_EPOCH validators > 8 mainnet MAX_ATTESTATIONS_ELECTRA"
    check:
      # Fill block with attestations
      pool[].getElectraAttestationsForBlock(state[], cache).lenu64() ==
        MAX_ATTESTATIONS_ELECTRA
      pool[].getElectraAggregatedAttestation(
        state[].slot - 1, 0.CommitteeIndex).isSome()

  test "Attestations may arrive in any order" & preset():
    var cache = StateCache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)
      attestation0 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)

    check cfg.process_slots(
      state[], state[].slot + 1, cache, info, {}).isOk()

    let
      bc1 = get_beacon_committee(state[],
        state[].slot, 0.CommitteeIndex, cache)
      attestation1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc1[0], cache)

    # test reverse order
    pool[].addAttestation(
      attestation1, @[bc1[0]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)
    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.aggregation_bits.len,
      attestation0.loadSig, attestation0.startTime)

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      attestations.len == 1

  test "Attestations should be combined" & preset():
    var cache = StateCache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)
      attestation0 =
        makeElectraAttestation(state[], state[].latest_block_root, bc0[0], cache)
      attestation1 =
        makeElectraAttestation(state[], state[].latest_block_root, bc0[1], cache)

    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.aggregation_bits.len,
      attestation0.loadSig, attestation0.startTime)
    pool[].addAttestation(
      attestation1, @[bc0[1]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)

    check cfg.process_slots(
      state[], MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      attestations.len == 1

  test "Attestations may overlap, bigger first" & preset():
    var cache = StateCache()

    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)
      attestation0 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)
      attestation1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[1], cache)

    attestation0.combine(attestation1)

    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.aggregation_bits.len,
      attestation0.loadSig, attestation0.startTime)
    pool[].addAttestation(
      attestation1, @[bc0[1]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)

    check cfg.process_slots(
      state[], MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      attestations.len == 1

  test "Attestations may overlap, smaller first" & preset():
    var cache = StateCache()
    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(state[],
        state[].slot, 0.CommitteeIndex, cache)
      attestation0 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)
      attestation1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[1], cache)

    attestation0.combine(attestation1)

    pool[].addAttestation(
      attestation1, @[bc0[1]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)
    pool[].addAttestation(
      attestation0, @[bc0[0]], attestation0.aggregation_bits.len,
      attestation0.loadSig, attestation0.startTime)

    check cfg.process_slots(
      state[], MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)

    check:
      attestations.len == 1

  test "Fork choice returns latest block with no attestations":
    var cache = StateCache()
    let
      b1 = addTestBlock(state[], cache).electraData
      b1Add = addHeadBlockToForkChoice(b1)

    let head = pool[].selectOptimisticHead(
      b1Add[].slot.start_beacon_time(cfg.timeParams)).get().blck
    check:
      head == b1Add[]

    let
      b2 = addTestBlock(state[], cache).electraData
      b2Add = addHeadBlockToForkChoice(b2)

    let head2 = pool[].selectOptimisticHead(
      b2Add[].slot.start_beacon_time(cfg.timeParams)).get().blck

    check:
      head2 == b2Add[]

  test "Fork choice returns block with attestation":
    var cache = StateCache()
    let
      b10 = makeTestBlock(state[], cache).electraData
      b10Add = addHeadBlockToForkChoice(b10)

    let head = pool[].selectOptimisticHead(
      b10Add[].slot.start_beacon_time(cfg.timeParams)).get().blck

    check:
      head == b10Add[]

    # Add a block too late to be timely enough to be proposer-boosted, which
    # would otherwise cause it to be selected as head
    let
      b11 = makeTestBlock(state[], cache,
        graffiti = GraffitiBytes [
          1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).electraData
      b11Add = addHeadBlockToForkChoice(b11,
        b11.message.slot.start_beacon_time(cfg.timeParams) +
        cfg.timeParams.SLOT_DURATION)

      bc1 = get_beacon_committee(
        state[], state[].slot - 1, 1.CommitteeIndex,
        cache)
      attestation0 = makeElectraAttestation(state[], b10.root, bc1[0], cache)

    pool[].addAttestation(
      attestation0, @[bc1[0]], attestation0.aggregation_bits.len,
      attestation0.loadSig, attestation0.startTime)

    let head2 = pool[].selectOptimisticHead(
      b10Add[].slot.start_beacon_time(cfg.timeParams)).get().blck

    check:
      # Single vote for b10 and no votes for b11
      head2 == b10Add[]

    let
      attestation1 = makeElectraAttestation(state[], b11.root, bc1[1], cache)
      attestation2 = makeElectraAttestation(state[], b11.root, bc1[2], cache)
    pool[].addAttestation(
      attestation1, @[bc1[1]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)

    let head3 = pool[].selectOptimisticHead(
      b10Add[].slot.start_beacon_time(cfg.timeParams)).get().blck
    let bigger = if b11.root.data < b10.root.data: b10Add else: b11Add

    check:
      # Ties broken lexicographically in spec -> ?
      head3 == bigger[]

    pool[].addAttestation(
      attestation2, @[bc1[2]], attestation2.aggregation_bits.len,
      attestation2.loadSig, attestation2.startTime)

    let head4 = pool[].selectOptimisticHead(
      b11Add[].slot.start_beacon_time(cfg.timeParams)).get().blck

    check:
      # Two votes for b11
      head4 == b11Add[]

  test "Invalid block weight does not propagate to ancestors":
    var cache = StateCache()
    let
      b1 = addTestBlock(state[], cache).electraData
      b1Add = addHeadBlockToForkChoice(b1)

      forkState = assignClone(state[])

      b2 = addTestBlock(state[], cache).electraData
      b2Add = addHeadBlockToForkChoice(b2)

      bInvalid = addTestBlock(state[], cache).electraData
      bInvalidAdd = addHeadBlockToForkChoice(bInvalid)

      b3 = makeTestBlock(forkState[], cache,
        graffiti = GraffitiBytes [
          1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).electraData
      b3Add = addHeadBlockToForkChoice(b3,
        b3.message.slot.start_beacon_time(cfg.timeParams) +
        cfg.timeParams.SLOT_DURATION)

    # Attest to (eventually) invalid block
    block:
      let bc = get_beacon_committee(
        state[], state[].slot - 1, 0.CommitteeIndex, cache)
      for i in 0 ..< min(4, bc.len):
        let att = makeElectraAttestation(state[], bInvalid.root, bc[i], cache)
        pool[].addAttestation(
          att, @[bc[i]], att.aggregation_bits.len,
          att.loadSig, att.startTime)

    # Attest to canonical block with 1 validator
    block:
      let
        bc = get_beacon_committee(
          forkState[], forkState[].slot, 1.CommitteeIndex, cache)
        att = makeElectraAttestation(forkState[], b3.root, bc[0], cache)
      pool[].addAttestation(
        att, @[bc[0]], att.aggregation_bits.len,
        att.loadSig, att.startTime)

    block:
      let head = pool[].selectOptimisticHead(
        bInvalidAdd[].slot.start_beacon_time(cfg.timeParams)).get().blck
      check head == bInvalidAdd[]

    pool[].forkChoice.mark_root_invalid(bInvalid.root)

    block:
      let head = pool[].selectOptimisticHead(
        bInvalidAdd[].slot.start_beacon_time(cfg.timeParams)).get().blck
      check head == b3Add[]

  test "Trying to add a block twice tags the second as an error":
    var cache = StateCache()
    let
      b10 = makeTestBlock(state[], cache).electraData
      b10Add = addHeadBlockToForkChoice(b10)

    let head = pool[].selectOptimisticHead(
      b10Add[].slot.start_beacon_time(cfg.timeParams)).get().blck

    check:
      head == b10Add[]

    # -------------------------------------------------------------
    # Add back the old block to ensure we have a duplicate error
    let b10_clone = b10 # Assumes deep copy
    let b10Add_clone = addHeadBlockToForkChoice(b10_clone)

    doAssert: b10Add_clone.error == VerifierError.Duplicate

  test "Trying to add a duplicate block from an old pruned epoch is tagged as an error":
    # Note: very sensitive to stack usage

    dag.updateFlags.incl {skipBlsValidation}
    var cache = StateCache()
    let
      b10 = addTestBlock(state[], cache).electraData
      b10Add = addHeadBlockToForkChoice(b10)

    let head = pool[].selectOptimisticHead(
      b10Add[].slot.start_beacon_time(cfg.timeParams)).get().blck

    doAssert: head == b10Add[]

    # -------------------------------------------------------------
    let b10_clone = b10 # Assumes deep copy

    # -------------------------------------------------------------
    # Pass an epoch
    var attestations: seq[electra.Attestation]

    for epoch in 0 ..< 5:
      let start_slot = start_slot(Epoch epoch)
      let committees_per_slot =
        get_committee_count_per_slot(state[], Epoch epoch, cache)
      for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
        let new_block = addTestBlock(
          state[], cache, electraAttestations = attestations).electraData

        let blockRef = addHeadBlockToForkChoice(new_block)

        let head = pool[].selectOptimisticHead(
          blockRef[].slot.start_beacon_time(cfg.timeParams)).get().blck
        doAssert: head == blockRef[]
        discard pool[].willSelectNewHead(head)
        dag.updateHead(head, quarantine[], [])
        pruneAtFinalization(dag, pool[])

        attestations.setLen(0)
        for committee_index in get_committee_indices(committees_per_slot):
          let committee = get_beacon_committee(
            state[], state[].slot, committee_index,
            cache)

          # Create a bitfield filled with the given count per attestation,
          # exactly on the right-most part of the committee field.
          var aggregation_bits = init(ElectraCommitteeValidatorsBits, committee.len)
          for v in 0 ..< committee.len * 2 div 3 + 1:
            aggregation_bits[v] = true

          var committee_bits: AttestationCommitteeBits
          committee_bits[committee_index.int] = true

          attestations.add electra.Attestation(
            committee_bits: committee_bits,
            aggregation_bits: aggregation_bits,
            data: makeAttestationData(state[], state[].slot,
              0.CommitteeIndex, blockRef.get().root)
            # signature: ValidatorSig()
          )

      cache = StateCache()

    # -------------------------------------------------------------
    # Prune

    doAssert: dag.finalizedHead.slot != 0

    pool[].prune()
    doAssert: b10.root notin pool.forkChoice.backend

    # Add back the old block to ensure we have a duplicate error
    let b10Add_clone = addHeadBlockToForkChoice(b10_clone)

    doAssert: b10Add_clone.error == VerifierError.Duplicate

  proc addElectraBlock(
      state: var ForkedHashedBeaconState, dag: ChainDAGRef,
      pool: ref AttestationPool, verifier: var BatchVerifier,
      quarantine: ref Quarantine, cache: var StateCache,
      attested = true, validator_changes = BeaconBlockValidatorChanges()) =
    let
      attestations =
        if attested:
          makeFullElectraAttestations(
            state, dag.head.root, state.slot, cache)
        else:
          newSeq[electra.Attestation]()
      blck = addTestBlock(
        state, cache, electraAttestations = attestations,
        validator_changes = validator_changes,
        cfg = dag.cfg).electraData
      added = dag.addHeadBlock(verifier, blck) do (
          blckRef: BlockRef,
          signedBlock: electra.TrustedSignedBeaconBlock,
          state: electra.BeaconState,
          epochRef: EpochRef, unrealized: FinalityCheckpoints):
        pool[].addForkChoice(
          epochRef, blckRef, unrealized, signedBlock.message,
          blckRef.slot.start_beacon_time(dag.cfg.timeParams))
    doAssert added.isOk
    dag.updateHead(added[], quarantine[], [])

  test "Attester slashing marks validator as equivocating":
    check process_slots(
      cfg, state[], state[].slot + 1, cache, info, {}).isOk

    var validator_changes: BeaconBlockValidatorChanges
    doAssert validator_changes.electra_attester_slashings.add(
      state[].makeElectraAttesterSlashing([0'u64], state[].slot))
    state[].addElectraBlock(
      dag, pool, verifier, quarantine, cache,
      attested = false, validator_changes = validator_changes)

    check:
      pool[].forkChoice.backend.votes.len > 0
      pool[].forkChoice.backend.votes[0].slot == FAR_FUTURE_SLOT

  test "Attester slashing retains unrealized checkpoints":
    template proto_array: ProtoArray =
      pool[].forkChoice.backend.proto_array

    for i in 0 ..< SLOTS_PER_EPOCH * 2 + 1:
      state[].addElectraBlock(dag, pool, verifier, quarantine, cache)

    let
      root = dag.head.root
      unrealized = proto_array.checkpoints(root).get().unrealized
    check unrealized.epoch >
      proto_array.checkpoints(root).get().voting_source.epoch

    var slashed_indices: seq[uint64]
    for i in 0'u64 ..< dag.headState.validators.lenu64 div 2:
      slashed_indices.add i
    var validator_changes: BeaconBlockValidatorChanges
    doAssert validator_changes.electra_attester_slashings.add(
      state[].makeElectraAttesterSlashing(slashed_indices, state[].slot))
    state[].addElectraBlock(
      dag, pool, verifier, quarantine, cache,
      validator_changes = validator_changes)

    check proto_array.checkpoints(root).get().unrealized == unrealized

  test "Working with electra aggregates" & preset():
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)

    var
      att0 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)
      att0x = att0
      att1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[1], cache)
      att2 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[2], cache)
      att3 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[3], cache)

    proc verifyAttestationSignature(attestation: electra.Attestation): bool =
      withState(state[]):
        let
          fork = pool.dag.cfg.forkAtEpoch(forkyState.data.slot.epoch)
          attesting_indices =
            forkyState.data.get_attesting_indices(attestation, cache)
        verify_attestation_signature(
          fork, pool.dag.genesis_validators_root, attestation.data,
          attesting_indices.mapIt(forkyState.data.validators.item(it).pubkey),
          attestation.signature)

    check:
      verifyAttestationSignature(att0)
      verifyAttestationSignature(att0x)
      verifyAttestationSignature(att1)
      verifyAttestationSignature(att2)
      verifyAttestationSignature(att3)

    # Both attestations include member 2 but neither is a subset of the other
    att0.combine(att2)
    att1.combine(att2)

    check:
      verifyAttestationSignature(att0)
      verifyAttestationSignature(att1)
      not pool[].covers(att0.data, att0.aggregation_bits, att0.committee_bits.get_committee_index_one()[])
      not pool[].covers(att1.data, att1.aggregation_bits, att1.committee_bits.get_committee_index_one()[])
      not pool[].covers(att2.data, att2.aggregation_bits, att2.committee_bits.get_committee_index_one()[])

    pool[].addAttestation(
      att0, @[bc0[0], bc0[2]], att0.aggregation_bits.len,
      att0.loadSig, att0.startTime)
    pool[].addAttestation(
      att1, @[bc0[1], bc0[2]], att1.aggregation_bits.len,
      att1.loadSig, att1.startTime)

    for att in pool[].electraAttestations(Opt.none Slot, Opt.none CommitteeIndex):
      check: verifyAttestationSignature(att)

    check:
      pool[].covers(att0.data, att0.aggregation_bits, att0.committee_bits.get_committee_index_one()[])
      pool[].covers(att1.data, att1.aggregation_bits, att1.committee_bits.get_committee_index_one()[])
      pool[].covers(att2.data, att2.aggregation_bits, att2.committee_bits.get_committee_index_one()[])

      cfg.process_slots(
        state[], state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
        cache, info, {}).isOk()

    for att in pool[].electraAttestations(Opt.none Slot, Opt.none CommitteeIndex):
      check: verifyAttestationSignature(att)

    check:
      pool[].getElectraAttestationsForBlock(state[], cache).len() == 1
      # Can get either aggregate here, random!
      verifyAttestationSignature(pool[].getElectraAggregatedAttestation(
        1.Slot, hash_tree_root(att0.data), 0.CommitteeIndex).get)

    # Add in attestation 3 - both aggregates should now have it added
    pool[].addAttestation(
      att3, @[bc0[3]], att3.aggregation_bits.len, att3.loadSig, att3.startTime)

    block:
      let attestations = pool[].getElectraAttestationsForBlock(state[], cache)
      check:
        attestations.len() == 1
        attestations[0].aggregation_bits.countOnes() == 3
        check_attestation(
          state[].electraData.data, attestations[0], {}, cache).isOk
        verifyAttestationSignature(attestations[0])
        # Can get either aggregate here, random!
        verifyAttestationSignature(pool[].getElectraAggregatedAttestation(
          1.Slot, hash_tree_root(attestations[0].data), 0.CommitteeIndex).get)

    # Add in attestation 0 as single - attestation 1 is now a superset of the
    # aggregates in the pool, so everything else should be removed
    pool[].addAttestation(
      att0x, @[bc0[0]], att0x.aggregation_bits.len,
      att0x.loadSig, att0x.startTime)

    block:
      let attestations = pool[].getElectraAttestationsForBlock(state[], cache)
      check:
        attestations.len() == 1
        attestations[0].aggregation_bits.countOnes() == 4
        check_attestation(
          state[].electraData.data, attestations[0], {}, cache).isOk
        verifyAttestationSignature(attestations[0])
        verifyAttestationSignature(pool[].getElectraAggregatedAttestation(
          1.Slot, hash_tree_root(attestations[0].data), 0.CommitteeIndex).get)

    # Someone votes for a different root
    let att4 = makeElectraAttestation(state[], ZERO_HASH, bc0[4], cache)
    check: verifyAttestationSignature(att4)
    pool[].addAttestation(
      att4, @[bc0[4]], att4.aggregation_bits.len, att4.loadSig, att4.startTime)

    # Total aggregations size should be one for that root
    check:
      pool[].getElectraAggregatedAttestation(1.Slot, hash_tree_root(att4.data),
      0.CommitteeIndex).get().aggregation_bits.countOnes() == 1

  proc verifyAttestationSignature(
      pool: AttestationPool,
      state: ref ForkedHashedBeaconState,
      cache: var StateCache,
      attestation: electra.Attestation): bool =
    withState(state[]):
      let
        fork = pool.dag.cfg.forkAtEpoch(forkyState.data.slot.epoch)
        attesting_indices =
          forkyState.data.get_attesting_indices(attestation, cache)
      verify_attestation_signature(
        fork, pool.dag.genesis_validators_root, attestation.data,
        attesting_indices.mapIt(forkyState.data.validators.item(it).pubkey),
        attestation.signature)

  test "Aggregating across committees" & preset():
    # Add attestation from different committee
    var maxSlot = 0.Slot
    for i in 0 ..< 4:
      let
        bc = get_beacon_committee(
          state[], state[].slot, i.CommitteeIndex, cache)
        att = makeElectraAttestation(
          state[], state[].latest_block_root, bc[0], cache)
      var att2 = makeElectraAttestation(
        state[], state[].latest_block_root, bc[1], cache)
      att2.combine(att)

      pool[].addAttestation(
        att, @[bc[0]], att.aggregation_bits.len,
        att.loadSig, att.startTime)

      pool[].addAttestation(
        att2, @[bc[0], bc[1]], att2.aggregation_bits.len,
        att2.loadSig, att2.startTime)

      pool[].addAttestation(
        att, @[bc[0]], att.aggregation_bits.len,
        att.loadSig, att.startTime)

      pool[].addAttestation(
        att2, @[bc[0], bc[1]], att2.aggregation_bits.len,
        att2.loadSig, att2.startTime)

      if att.data.slot > maxSlot:
        maxSlot = att.data.slot

    check cfg.process_slots(
      state[], maxSlot + MIN_ATTESTATION_INCLUSION_DELAY,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)
    check:
      attestations.len() == 2
      attestations[0].aggregation_bits.countOnes() == 4
      attestations[0].committee_bits.countOnes() == 2
      attestations[1].aggregation_bits.countOnes() == 4
      attestations[1].committee_bits.countOnes() == 2
      check_attestation(
        state[].electraData.data, attestations[0], {}, cache).isOk
      check_attestation(
        state[].electraData.data, attestations[1], {}, cache).isOk
      pool[].verifyAttestationSignature(state, cache, attestations[0])
      pool[].verifyAttestationSignature(state, cache, attestations[1])

  test "Simple add and get with electra nonzero committee" & preset():
    let
      bc0 = get_beacon_committee(
        state[], state[].slot, 0.CommitteeIndex, cache)

      bc1 = get_beacon_committee(
        state[], state[].slot, 1.CommitteeIndex, cache)

      attestation1 = makeElectraAttestation(
        state[], state[].latest_block_root, bc0[0], cache)

      attestation2 = makeElectraAttestation(
        state[], state[].latest_block_root, bc1[0], cache)

    pool[].addAttestation(
      attestation1, @[bc0[0]], attestation1.aggregation_bits.len,
      attestation1.loadSig, attestation1.startTime)

    pool[].addAttestation(
      attestation2, @[bc1[0]], attestation2.aggregation_bits.len,
      attestation2.loadSig, attestation2.startTime)

    check:
      cfg.process_slots(
        state[], state[].slot + MIN_ATTESTATION_INCLUSION_DELAY,
        cache, info, {}).isOk()

      pool[].getElectraAggregatedAttestation(1.Slot, hash_tree_root(attestation1.data),
          0.CommitteeIndex).isOk
      pool[].getElectraAggregatedAttestation(1.Slot, hash_tree_root(attestation2.data),
          1.CommitteeIndex).isOk

  test "Cache coherence on chain aggregates" & preset():
    # Add attestation from different committee
    var maxSlot = 0.Slot

    for i in 0 ..< 4:
      let
        bc = get_beacon_committee(
          state[], state[].slot, i.CommitteeIndex, cache)
        att = makeElectraAttestation(
          state[], state[].latest_block_root, bc[0], cache)
      var att2 = makeElectraAttestation(
        state[], state[].latest_block_root, bc[1], cache)

      pool[].addAttestation(
        att, @[bc[0]], att.aggregation_bits.len,
        att.loadSig, att.startTime)

      if att.data.slot < 2:
        pool[].addAttestation(
          att2, @[bc[1]], att2.aggregation_bits.len,
          att2.loadSig, att2.startTime)

      if att.data.slot > maxSlot:
        maxSlot = att.data.slot

    check cfg.process_slots(
      state[], maxSlot + MIN_ATTESTATION_INCLUSION_DELAY,
      cache, info, {}).isOk()

    let attestations = pool[].getElectraAttestationsForBlock(state[], cache)
    check:
      ## Considering that all structures in getElectraAttestationsForBlock
      ## are sorted, the most relevant should be at sequence head.
      ## Given the attestations added, the most "scored" is on
      ## slot 1
      attestations.len() == 2

      attestations[0].aggregation_bits.countOnes() == 4
      attestations[0].committee_bits.countOnes() == 2
      attestations[0].data.slot == 1.Slot


      attestations[1].aggregation_bits.countOnes() == 2
      attestations[1].committee_bits.countOnes() == 2
      attestations[1].data.slot == 2.Slot

      check_attestation(
        state[].electraData.data, attestations[0], {}, cache).isOk
      check_attestation(
        state[].electraData.data, attestations[1], {}, cache).isOk
      pool[].verifyAttestationSignature(state, cache, attestations[0])
      pool[].verifyAttestationSignature(state, cache, attestations[1])

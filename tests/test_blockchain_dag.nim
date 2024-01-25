# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[random, sequtils],
  unittest2,
  taskpools,
  ../beacon_chain/el/merkle_minimal,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/[beaconstate, forks, helpers, signatures, state_transition],
  ../beacon_chain/[beacon_chain_db],
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, block_quarantine, block_clearance],
  ./testutil, ./testdbutil, ./testblockutil

from ../beacon_chain/spec/datatypes/capella import
  SignedBLSToExecutionChangeList

func `$`(x: BlockRef): string = shortLog(x)

const
  nilPhase0Callback = OnPhase0BlockAdded(nil)
  nilAltairCallback = OnAltairBlockAdded(nil)
  nilBellatrixCallback = OnBellatrixBlockAdded(nil)

proc pruneAtFinalization(dag: ChainDAGRef) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()

type
  AddHeadRes = Result[BlockRef, VerifierError]
  AddBackRes = Result[void, VerifierError]

suite "Block pool processing" & preset():
  setup:
    let rng = HmacDrbgContext.new()
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init()
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()
      att0 = makeFullAttestations(state[], dag.tail.root, 0.Slot, cache)
      b1 = addTestBlock(state[], cache, attestations = att0).phase0Data
      b2 = addTestBlock(state[], cache).phase0Data

  test "basic ops":
    check:
      dag.getBlockRef(default Eth2Digest).isNone()

    let
      b0 = dag.getForkedBlock(dag.tail.root)
      bh = dag.getForkedBlock(dag.head.root)
      bh2 = dag.getForkedBlock(dag.head.bid)
    check:
      b0.isSome()
      bh.isSome()
      bh2.isSome()

      dag.getBlockRef(dag.finalizedHead.blck.root).get() ==
        dag.finalizedHead.blck
      dag.getBlockRef(dag.head.root).get() == dag.head

  test "Simple block add&get" & preset():
    let
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)
      b1Get = dag.getForkedBlock(b1.root)

    check:
      b1Get.isSome()
      b1Get.get().root == b1.root
      b1Add[].root == b1Get.get().root
      dag.heads.len == 1
      dag.heads[0] == b1Add[]

    let
      b2Add = dag.addHeadBlock(verifier, b2, nilPhase0Callback)
      b2Get = dag.getForkedBlock(b2.root)
      sr = dag.findShufflingRef(b1Add[].bid, b1Add[].slot.epoch)
      er = dag.findEpochRef(b1Add[].bid, b1Add[].slot.epoch)
      validators = getStateField(dag.headState, validators).lenu64()

    check:
      b2Get.isSome()
      b2Get.get().root == b2.root
      b2Add[].root == b2Get.get().root
      dag.heads.len == 1
      dag.heads[0] == b2Add[]
      dag.containsForkBlock(b2.root)
      dag.parent(b2Add[].bid).get() == b1Add[].bid
      # head not updated yet - getBlockIdAtSlot won't give those blocks
      dag.getBlockIdAtSlot(b2Add[].slot).get() ==
        BlockSlotId.init(dag.getBlockIdAtSlot(GENESIS_SLOT).get().bid, b2Add[].slot)

      sr.isSome()
      er.isSome()
      # er reuses shuffling ref instance
      er[].shufflingRef == sr[]
      # Same epoch - same epochRef
      er[] == dag.findEpochRef(b2Add[].bid, b2Add[].slot.epoch)[]
      # Different epoch that was never processed
      dag.findEpochRef(b1Add[].bid, b1Add[].slot.epoch + 1).isNone()
      # ... but we know the shuffling already!
      dag.findShufflingRef(b1Add[].bid, b1Add[].slot.epoch + 1).isSome()

      dag.validatorKey(0'u64).isSome()
      dag.validatorKey(validators - 1).isSome()
      dag.validatorKey(validators).isNone()

    # Skip one slot to get a gap
    check:
      process_slots(
        defaultRuntimeConfig, state[], getStateField(state[], slot) + 1, cache,
        info, {}).isOk()

    let
      b4 = addTestBlock(state[], cache).phase0Data
      b4Add = dag.addHeadBlock(verifier, b4, nilPhase0Callback)

    check:
      b4Add[].parent == b2Add[]

    dag.updateHead(b4Add[], quarantine, [])
    dag.pruneAtFinalization()

    check: # getBlockIdAtSlot operates on the head chain!
      dag.getBlockIdAtSlot(b2Add[].slot).get() ==
        BlockSlotId.init(b2Add[].bid, b2Add[].slot)
      dag.parentOrSlot(dag.getBlockIdAtSlot(b2Add[].slot).get()).get() ==
        BlockSlotId.init(b1Add[].bid, b2Add[].slot)
      dag.parentOrSlot(dag.getBlockIdAtSlot(b2Add[].slot + 1).get()).get() ==
        BlockSlotId.init(b2Add[].bid, b2Add[].slot)

    var blocks: array[3, BlockId]

    check:
      dag.getBlockRange(Slot(0), 1, blocks.toOpenArray(0, 0)) == 0
      blocks[0..<1] == [dag.tail]

      dag.getBlockRange(Slot(0), 1, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [dag.tail, b1Add[].bid]

      dag.getBlockRange(Slot(0), 2, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [dag.tail, b2Add[].bid]

      dag.getBlockRange(Slot(0), 3, blocks.toOpenArray(0, 1)) == 1
      blocks[1..<2] == [dag.tail] # block 3 is missing!

      dag.getBlockRange(Slot(2), 2, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [b2Add[].bid, b4Add[].bid] # block 3 is missing!

      # large skip step
      dag.getBlockRange(Slot(0), uint64.high, blocks.toOpenArray(0, 2)) == 2
      blocks[2..2] == [dag.tail]

      # large skip step
      dag.getBlockRange(Slot(2), uint64.high, blocks.toOpenArray(0, 1)) == 1
      blocks[1..1] == [b2Add[].bid]

      # empty length
      dag.getBlockRange(Slot(2), 2, blocks.toOpenArray(0, -1)) == 0

      # No blocks in sight
      dag.getBlockRange(Slot(5), 1, blocks.toOpenArray(0, 1)) == 2

      # No blocks in sight
      dag.getBlockRange(Slot(uint64.high), 1, blocks.toOpenArray(0, 1)) == 2

      # No blocks in sight either due to gaps
      dag.getBlockRange(Slot(3), 2, blocks.toOpenArray(0, 1)) == 2
      blocks[2..<2].len == 0

    # A fork forces the clearance state to a point where it cannot be advanced
    let
      nextEpoch = dag.head.slot.epoch + 1
      nextEpochSlot = nextEpoch.start_slot()
      parentBsi = dag.head.parent.atSlot(nextEpochSlot).toBlockSlotId().get()
      stateCheckpoint = dag.stateCheckpoint(parentBsi)
      shufflingRef = dag.getShufflingRef(dag.head, nextEpoch, false).valueOr:
        raiseAssert "false"
      nextEpochProposers = withState(dag.headState):
        get_beacon_proposer_indices(
          forkyState.data, shufflingRef.shuffled_active_validator_indices,
          nextEpoch)

    check:
      # get_beacon_proposer_indices based on ShufflingRef matches EpochRef
      nextEpochProposers == dag.getEpochRef(
        dag.head, nextEpoch, true).get.beacon_proposers

      parentBsi.bid == dag.head.parent.bid
      parentBsi.slot == nextEpochSlot
      # Pre-heated caches
      dag.findShufflingRef(dag.head.parent.bid, dag.head.slot.epoch).isOk()
      dag.findShufflingRef(dag.head.parent.bid, nextEpoch).isOk()
      dag.getEpochRef(dag.head.parent, nextEpoch, true).isOk()

      # Getting an EpochRef should not result in states being stored
      db.getStateRoot(stateCheckpoint.bid.root, stateCheckpoint.slot).isErr()
      # this is required for the test to work - it's not a "public"
      # post-condition of getEpochRef
      getStateField(dag.epochRefState, slot) == nextEpochSlot

    assign(state[], dag.epochRefState)

    let
      bnext = addTestBlock(state[], cache).phase0Data
      bnextAdd = dag.addHeadBlock(verifier, bnext, nilPhase0Callback)

    check:
      # Getting an EpochRef should not result in states being stored
      db.getStateRoot(stateCheckpoint.bid.root, stateCheckpoint.slot).isOk()

  test "Adding the same block twice returns a Duplicate error" & preset():
    let
      b10 = dag.addHeadBlock(verifier, b1, nilPhase0Callback)
      b11 = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check:
      b11 == AddHeadRes.err VerifierError.Duplicate
      not b10[].isNil

  test "updateHead updates head and headState" & preset():
    let
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    dag.updateHead(b1Add[], quarantine, [])
    dag.pruneAtFinalization()

    check:
      dag.head == b1Add[]
      getStateField(dag.headState, slot) == b1Add[].slot

  test "updateState sanity" & preset():
    let
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)
      b2Add = dag.addHeadBlock(verifier, b2, nilPhase0Callback)
      bs1 = BlockSlotId.init(b1Add[].bid, b1.message.slot)
      bs1_3 = BlockSlotId.init(b1Add[].bid, 3.Slot)
      bs2_3 = BlockSlotId.init(b2Add[].bid, 3.Slot)

    let tmpState = assignClone(dag.headState)

    # move to specific block
    var cache = StateCache()
    check:
      dag.updateState(tmpState[], bs1, false, cache)
      tmpState[].latest_block_root == b1Add[].root
      getStateField(tmpState[], slot) == bs1.slot

    # Skip slots
    check:
      dag.updateState(tmpState[], bs1_3, false, cache) # skip slots
      tmpState[].latest_block_root == b1Add[].root
      getStateField(tmpState[], slot) == bs1_3.slot

    # Move back slots, but not blocks
    check:
      dag.updateState(
        tmpState[], dag.parent(bs1_3.bid).expect("block").atSlot(), false, cache)
      tmpState[].latest_block_root == b1Add[].parent.root
      getStateField(tmpState[], slot) == b1Add[].parent.slot

    # Move to different block and slot
    check:
      dag.updateState(tmpState[], bs2_3, false, cache)
      tmpState[].latest_block_root == b2Add[].root
      getStateField(tmpState[], slot) == bs2_3.slot

    # Move back slot and block
    check:
      dag.updateState(tmpState[], bs1, false, cache)
      tmpState[].latest_block_root == b1Add[].root
      getStateField(tmpState[], slot) == bs1.slot

    # Move back to genesis
    check:
      dag.updateState(
        tmpState[], dag.parent(bs1.bid).expect("block").atSlot(), false, cache)
      tmpState[].latest_block_root == b1Add[].parent.root
      getStateField(tmpState[], slot) == b1Add[].parent.slot

suite "Block pool altair processing" & preset():
  setup:
    let rng = HmacDrbgContext.new()

    var
      cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = Epoch(1)

    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init()
      state = newClone(dag.headState)
      cache = StateCache()
      info = ForkedEpochInfo()

    # Advance to altair
    check:
      process_slots(
        cfg, state[], cfg.ALTAIR_FORK_EPOCH.start_slot(), cache,
        info, {}).isOk()

      state[].kind == ConsensusFork.Altair

    var
      b1 = addTestBlock(state[], cache).altairData
      att1 = makeFullAttestations(state[], b1.root, b1.message.slot, cache)
      b2 = addTestBlock(state[], cache, attestations = att1).altairData

  test "Invalid signatures" & preset():
    let badSignature = get_slot_signature(
      Fork(), ZERO_HASH, 42.Slot,
      MockPrivKeys[ValidatorIndex(0)]).toValidatorSig()

    check:
      dag.addHeadBlock(verifier, b1, nilAltairCallback).isOk()

    block: # Main signature
      var b = b2
      b.signature = badSignature
      let
        bAdd = dag.addHeadBlock(verifier, b, nilAltairCallback)
      check:
        bAdd == AddHeadRes.err VerifierError.Invalid

    block: # Randao reveal
      var b = b2
      b.message.body.randao_reveal = badSignature
      let
        bAdd = dag.addHeadBlock(verifier, b, nilAltairCallback)
      check:
        bAdd == AddHeadRes.err VerifierError.Invalid

    block: # Attestations
      var b = b2
      b.message.body.attestations[0].signature = badSignature
      let
        bAdd = dag.addHeadBlock(verifier, b, nilAltairCallback)
      check:
        bAdd == AddHeadRes.err VerifierError.Invalid

    block: # SyncAggregate empty
      var b = b2
      b.message.body.sync_aggregate.sync_committee_signature = badSignature
      let
        bAdd = dag.addHeadBlock(verifier, b, nilAltairCallback)
      check:
        bAdd == AddHeadRes.err VerifierError.Invalid

    block: # SyncAggregate junk
      var b = b2
      b.message.body.sync_aggregate.sync_committee_signature = badSignature
      b.message.body.sync_aggregate.sync_committee_bits[0] = true

      let
        bAdd = dag.addHeadBlock(verifier, b, nilAltairCallback)
      check:
        bAdd == AddHeadRes.err VerifierError.Invalid

suite "chain DAG finalization tests" & preset():
  setup:
    let rng = HmacDrbgContext.new()
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init()
      cache = StateCache()
      info = ForkedEpochInfo()

  test "prune heads on finalization" & preset():
    # Create a fork that will not be taken
    var
      blck = makeTestBlock(dag.headState, cache).phase0Data
      tmpState = assignClone(dag.headState)
    check:
      process_slots(
        defaultRuntimeConfig, tmpState[],
        getStateField(tmpState[], slot) + (5 * SLOTS_PER_EPOCH).uint64,
        cache, info, {}).isOk()

    let lateBlock = addTestBlock(tmpState[], cache).phase0Data
    block:
      let status = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: status.isOk()

    assign(tmpState[], dag.headState)

    # skip slots so we can test gappy getBlockIdAtSlot
    check process_slots(
      defaultRuntimeConfig, tmpState[],
      getStateField(tmpState[], slot) + 2.uint64,
      cache, info, {}).isOk()

    for i in 0 ..< (SLOTS_PER_EPOCH * 6):
      if i == 1:
        # There are 2 heads now because of the fork at slot 1
        check:
          dag.heads.len == 2

      blck = addTestBlock(
        tmpState[], cache,
        attestations = makeFullAttestations(
          tmpState[], dag.head.root, getStateField(tmpState[], slot), cache, {})).phase0Data
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    check:
      dag.heads.len() == 1
      dag.getBlockIdAtSlot(0.Slot).get().bid.slot == 0.Slot
      dag.getBlockIdAtSlot(2.Slot).get() ==
        BlockSlotId.init(dag.getBlockIdAtSlot(1.Slot).get().bid, 2.Slot)

      dag.getBlockIdAtSlot(dag.head.slot).get() == BlockSlotId.init(
        dag.head.bid, dag.head.slot)
      dag.getBlockIdAtSlot(dag.head.slot + 1).get() == BlockSlotId.init(
        dag.head.bid, dag.head.slot + 1)

      not dag.containsForkBlock(dag.getBlockIdAtSlot(5.Slot).get().bid.root)
      dag.containsForkBlock(dag.finalizedHead.blck.root)

      dag.getBlockRef(dag.getBlockIdAtSlot(0.Slot).get().bid.root).isNone() # Finalized - no BlockRef

      dag.getBlockRef(dag.finalizedHead.blck.root).isSome()

      isNil dag.finalizedHead.blck.parent

    check:
      dag.db.immutableValidators.len() == getStateField(dag.headState, validators).len()

    block:
      var cur = dag.head.bid
      while true:
        let parent = dag.parent(cur)
        if cur.slot > 0:
          check:
            parent.isSome and parent.get().slot < cur.slot
          cur = parent.get()
        else:
          check:
            parent.isErr()
          break
      check: cur.slot == 0

    block:
      var cur = dag.head.bid.atSlot()
      while true:
        let parent = dag.parentOrSlot(cur)
        if cur.slot > 0:
          check:
            parent.isSome and (parent.get().slot < cur.slot or parent.get().bid != cur.bid)
          cur = parent.get()
        else:
          check:
            parent.isErr()
          break
      check: cur.slot == 0

    let
      finalER = dag.getEpochRef(
        dag.finalizedHead.blck, dag.finalizedHead.slot.epoch, false)

      # The EpochRef for the finalized block is needed for eth1 voting, so we
      # should never drop it!
    check:
      not finalER.isErr()

    block:
      for er in dag.epochRefs.entries:
        check: er.value == nil or er.value.epoch >= dag.finalizedHead.slot.epoch

    block:
      let tmpStateData = assignClone(dag.headState)

      # Check that cached data is available after updateState - since we
      # just processed the head the relevant epochrefs should not have been
      # evicted yet
      cache = StateCache()
      check: updateState(
        dag, tmpStateData[],
        dag.head.atSlot(dag.head.slot).toBlockSlotId().expect("not nil"),
        false, cache)

      check:
        dag.head.slot.epoch in cache.shuffled_active_validator_indices
        (dag.head.slot.epoch - 1) in cache.shuffled_active_validator_indices

        dag.head.slot in cache.beacon_proposer_indices

    block:
      # The late block is a block whose parent was finalized long ago and thus
      # is no longer a viable head candidate
      let status = dag.addHeadBlock(verifier, lateBlock, nilPhase0Callback)
      # This _should_ be Unviable, but we can't tell, from the data that we have
      # so MissingParent is the least wrong thing to reply
      check: status == AddHeadRes.err VerifierError.UnviableFork

    block:
      let
        finalizedCheckpoint = dag.stateCheckpoint(dag.finalizedHead.toBlockSlotId().get())
        headCheckpoint = dag.stateCheckpoint(dag.head.bid.atSlot())
        prunedCheckpoint = dag.stateCheckpoint(dag.parent(dag.finalizedHead.blck.bid).get().atSlot())
      check:
        db.getStateRoot(headCheckpoint.bid.root, headCheckpoint.slot).isSome
        db.getStateRoot(finalizedCheckpoint.bid.root, finalizedCheckpoint.slot).isSome
        db.getStateRoot(prunedCheckpoint.bid.root, prunedCheckpoint.slot).isNone

    # Roll back head block (e.g., because it was declared INVALID)
    let parentRoot = dag.head.parent.root
    dag.updateHead(dag.head.parent, quarantine, [])
    check: dag.head.root == parentRoot

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init())
      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})

    # check that the state reloaded from database resembles what we had before
    check:
      dag2.tail.root == dag.tail.root
      dag2.head.root == dag.head.root
      dag2.head.root == parentRoot
      dag2.finalizedHead.blck.root == dag.finalizedHead.blck.root
      dag2.finalizedHead.slot == dag.finalizedHead.slot
      getStateRoot(dag2.headState) == getStateRoot(dag.headState)

    # No canonical block data should be pruned by the removal of the fork
    for i in Slot(0)..dag2.head.slot:
      let bids = dag.getBlockIdAtSlot(i).expect("found it")
      if bids.isProposed:
        check: dag2.getForkedBlock(bids.bid).isSome

    # The unviable block should have been pruned however
    check: dag2.getForkedBlock(lateBlock.root).isNone

  test "orphaned epoch block" & preset():
    let prestate = (ref ForkedHashedBeaconState)(kind: ConsensusFork.Phase0)
    for i in 0 ..< SLOTS_PER_EPOCH:
      if i == SLOTS_PER_EPOCH - 1:
        assign(prestate[], dag.headState)

      let blck = makeTestBlock(dag.headState, cache).phase0Data
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    check:
      dag.heads.len() == 1

    # The loop creates multiple branches, which StateCache isn't suitable for
    cache = StateCache()

    doAssert process_slots(
      defaultRuntimeConfig, prestate[], getStateField(prestate[], slot) + 1,
      cache, info, {}).isOk()

    # create another block, orphaning the head
    let blck = makeTestBlock(prestate[], cache).phase0Data

    # Add block, but don't update head
    let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
    check: added.isOk()

    var
      validatorMonitor2 = newClone(ValidatorMonitor.init())
      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})

    # check that we can apply the block after the orphaning
    let added2 = dag2.addHeadBlock(verifier, blck, nilPhase0Callback)
    check: added2.isOk()

  test "init with gaps" & preset():
    for blck in makeTestBlocks(
        dag.headState, cache, int(SLOTS_PER_EPOCH * 6 - 2), attested = true):
      let added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    # Advance past epoch so that the epoch transition is gapped
    check:
      process_slots(
        defaultRuntimeConfig, dag.headState, Slot(SLOTS_PER_EPOCH * 6 + 2),
        cache, info, {}).isOk()

    let blck = makeTestBlock(
      dag.headState, cache,
      attestations = makeFullAttestations(
        dag.headState, dag.head.root, getStateField(dag.headState, slot),
        cache, {})).phase0Data

    let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
    check: added.isOk()
    dag.updateHead(added[], quarantine, [])
    dag.pruneAtFinalization()

    block:
      # Check that we can rewind to every block from head to finalized
      var
        cur = dag.head
        tmpStateData = assignClone(dag.headState)
      while cur != nil: # Go all the way to dag.finalizedHead
        assign(tmpStateData[], dag.headState)
        check:
          dag.updateState(tmpStateData[], cur.bid.atSlot(), false, cache)
          dag.getForkedBlock(cur.bid).get().phase0Data.message.state_root ==
            getStateRoot(tmpStateData[])
          getStateRoot(tmpStateData[]) == hash_tree_root(
            tmpStateData[].phase0Data.data)
        cur = cur.parent

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init())
      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})

    # check that the state reloaded from database resembles what we had before
    check:
      dag2.tail.root == dag.tail.root
      dag2.head.root == dag.head.root
      dag2.finalizedHead.blck.root == dag.finalizedHead.blck.root
      dag2.finalizedHead.slot == dag.finalizedHead.slot
      getStateRoot(dag2.headState) == getStateRoot(dag.headState)

  test "shutdown during finalization" & preset():
    var testPassed: bool

    # Configure a hook that is called during finalization while the
    # database has been partially written, to test behaviour if the
    # beacon node is exited while the database is inconsistent.
    proc onHeadChanged(data: HeadChangeInfoObject) =
      if data.epoch_transition:
        # Check test assumption: Head block was written before this callback
        let headBlock = dag.db.getHeadBlock().expect("Valid DB")
        doAssert headBlock == data.block_root, "Head was written before CB"

        # Check test assumption: New finalized blocks were not written yet
        let
          stateFinalizedSlot =
            dag.headState.getStateField(finalized_checkpoint).epoch.start_slot
          dbFinalizedSlot =
            dag.db.finalizedBlocks.high.expect("Valid DB")
        doAssert stateFinalizedSlot > dbFinalizedSlot, "Finalized not written"

        # If the beacon node were to exit _now_, this is what the DB looks like.
        # Validate that we can initialize a new DAG from this database.
        let validatorMonitor2 = newClone(ValidatorMonitor.init())
        discard ChainDAGRef.init(
          defaultRuntimeConfig, db, validatorMonitor2, {})
        testPassed = true
    dag.setHeadCb(onHeadChanged)

    for blck in makeTestBlocks(
        dag.headState, cache, int(SLOTS_PER_EPOCH * 4), attested = true):
      let added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
      check: added.isOk
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    check testPassed

suite "Old database versions" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      genState = newClone(initialize_hashed_beacon_state_from_eth1(
        defaultRuntimeConfig, ZERO_HASH, 0,
        makeInitialDeposits(SLOTS_PER_EPOCH.uint64, flags = {skipBlsValidation}),
        {skipBlsValidation}))
      genBlock = get_initial_beacon_block(genState[])
    var
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init()

  test "pre-1.1.0":
    # only kvstore, no immutable validator keys
    let
      sq = SqStoreRef.init("", "test", inMemory = true).expect(
        "working database (out of memory?)")
      v0 = BeaconChainDBV0.new(sq, readOnly = false)
      db = BeaconChainDB.new(sq)

    # preInit a database to a v1.0.12 state
    v0.putStateV0(genState[].root, genState[].data)
    v0.putBlockV0(genBlock)

    db.putStateRoot(
      genState[].latest_block_root, genState[].data.slot, genState[].root)
    db.putTailBlock(genBlock.root)
    db.putHeadBlock(genBlock.root)
    db.putGenesisBlock(genBlock.root)

    var
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db,validatorMonitor, {})
      state = newClone(dag.headState)
      cache = StateCache()
      att0 = makeFullAttestations(state[], dag.tail.root, 0.Slot, cache)
      b1 = addTestBlock(state[], cache, attestations = att0).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check:
      b1Add.isOk()

suite "Diverging hardforks":
  setup:
    let rng = HmacDrbgContext.new()

    var
      phase0RuntimeConfig = defaultRuntimeConfig
      altairRuntimeConfig = defaultRuntimeConfig

    phase0RuntimeConfig.ALTAIR_FORK_EPOCH = FAR_FUTURE_EPOCH
    altairRuntimeConfig.ALTAIR_FORK_EPOCH = 2.Epoch

    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, phase0RuntimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = newClone(Quarantine.init())
      cache = StateCache()
      info = ForkedEpochInfo()
      tmpState = assignClone(dag.headState)

  test "Tail block only in common":
    check:
      process_slots(
        phase0RuntimeConfig, tmpState[],
        getStateField(tmpState[], slot) + (3 * SLOTS_PER_EPOCH).uint64,
        cache, info, {}).isOk()

    # Because the first block is after the Altair transition, the only block in
    # common is the tail block
    var
      b1 = addTestBlock(tmpState[], cache).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check b1Add.isOk()
    dag.updateHead(b1Add[], quarantine[], [])

    let validatorMonitorAltair = newClone(ValidatorMonitor.init())

    let dagAltair = init(
      ChainDAGRef, altairRuntimeConfig, db, validatorMonitorAltair, {})
    discard AttestationPool.init(dagAltair, quarantine)

  test "Non-tail block in common":
    check:
      process_slots(
        phase0RuntimeConfig, tmpState[],
        getStateField(tmpState[], slot) + SLOTS_PER_EPOCH.uint64,
        cache, info, {}).isOk()

    # There's a block in the shared-correct phase0 hardfork, before epoch 2
    var
      b1 = addTestBlock(tmpState[], cache).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check:
      b1Add.isOk()
      process_slots(
        phase0RuntimeConfig, tmpState[],
        getStateField(tmpState[], slot) + (3 * SLOTS_PER_EPOCH).uint64,
        cache, info, {}).isOk()

    var
      b2 = addTestBlock(tmpState[], cache).phase0Data
      b2Add = dag.addHeadBlock(verifier, b2, nilPhase0Callback)

    check b2Add.isOk()
    dag.updateHead(b2Add[], quarantine[], [])

    let validatorMonitor = newClone(ValidatorMonitor.init())

    let dagAltair = init(
      ChainDAGRef, altairRuntimeConfig, db, validatorMonitor, {})
    discard AttestationPool.init(dagAltair, quarantine)

suite "Backfill":
  setup:
    let
      genState = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH.uint64, flags = {skipBlsValidation}),
          {skipBlsValidation}))
      tailState = assignClone(genState[])

      blocks = block:
        var blocks: seq[ForkedSignedBeaconBlock]
        var cache: StateCache
        for i in 0..<SLOTS_PER_EPOCH * 2:
          blocks.add addTestBlock(tailState[], cache)
        blocks

    let
      db = BeaconChainDB.new("", inMemory = true)

  test "backfill to genesis":
    let
      tailBlock = blocks[^1]
      genBlock = get_initial_beacon_block(genState[])

    ChainDAGRef.preInit(db, genState[])
    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})

    var cache = StateCache()

    check:
      dag.getBlockRef(tailBlock.root).get().bid == dag.tail
      dag.getBlockRef(blocks[^2].root).isNone()

      dag.getBlockId(tailBlock.root).get() == dag.tail
      dag.getBlockId(blocks[^2].root).isNone()

      dag.getBlockIdAtSlot(dag.tail.slot).get().bid == dag.tail
      dag.getBlockIdAtSlot(dag.tail.slot - 1).isNone()

      dag.getBlockIdAtSlot(Slot(0)).isSome() # genesis stored in db
      dag.getBlockIdAtSlot(Slot(1)).isNone()

      # No EpochRef for pre-tail epochs
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch - 1, true).isErr()

      # Should get EpochRef for the tail however
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch, true).isOk()
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      # Should not get EpochRef for random block
      dag.getEpochRef(
        BlockId(root: blocks[^2].root, slot: dag.tail.slot), # root/slot mismatch
        dag.tail.slot.epoch, true).isErr()

      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      dag.getFinalizedEpochRef() != nil

      dag.backfill == tailBlock.phase0Data.message.toBeaconBlockSummary()

      # Check that we can propose right from the checkpoint state
      dag.getProposalState(dag.head, dag.head.slot + 1, cache).isOk()

    var
      badBlock = blocks[^2].phase0Data
    badBlock.signature = blocks[^3].phase0Data.signature

    check:
      dag.addBackfillBlock(badBlock) == AddBackRes.err VerifierError.Invalid

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data) ==
        AddBackRes.err VerifierError.MissingParent
      dag.addBackfillBlock(genBlock.phase0Data.asSigned()) ==
        AddBackRes.err VerifierError.MissingParent

      dag.addBackfillBlock(tailBlock.phase0Data).isOk()

    check:
      dag.addBackfillBlock(blocks[^2].phase0Data).isOk()

      dag.getBlockRef(tailBlock.root).get().bid == dag.tail
      dag.getBlockRef(blocks[^2].root).isNone()

      dag.getBlockId(tailBlock.root).get() == dag.tail
      dag.getBlockId(blocks[^2].root).get().root == blocks[^2].root

      dag.getBlockIdAtSlot(dag.tail.slot).get().bid == dag.tail
      dag.getBlockIdAtSlot(dag.tail.slot - 1).get() ==
        blocks[^2].toBlockId().atSlot()
      dag.getBlockIdAtSlot(dag.tail.slot - 2).isNone

      dag.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data).isOk()

      dag.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()
      dag.getBlockIdAtSlot(dag.tail.slot - 3).isNone

    for i in 3..<blocks.len:
      check: dag.addBackfillBlock(blocks[blocks.len - i - 1].phase0Data).isOk()

    check:
      dag.addBackfillBlock(genBlock.phase0Data.asSigned) ==
        AddBackRes.err VerifierError.Duplicate

      dag.backfill.slot == GENESIS_SLOT

    dag.rebuildIndex()

    check:
      dag.getFinalizedEpochRef() != nil

  test "reload backfill position":
    let
      tailBlock = blocks[^1]

    ChainDAGRef.preInit(db, genState[])
    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})

    check:
      dag.addBackfillBlock(blocks[^2].phase0Data).isOk()
      dag.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init())

      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})

    check:
      dag2.getFinalizedEpochRef() != nil

      dag2.getBlockRef(tailBlock.root).get().root == dag.tail.root
      dag2.getBlockRef(blocks[^2].root).isNone()

      dag2.getBlockIdAtSlot(dag.tail.slot).get().bid.root == dag.tail.root

      dag2.getBlockIdAtSlot(dag.tail.slot - 1).get() ==
        blocks[^2].toBlockId().atSlot()
      dag2.getBlockIdAtSlot(dag.tail.slot - 2).isNone
      dag2.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

  test "Init without genesis / block":
    let
      tailBlock = blocks[^1]
      genBlock = get_initial_beacon_block(genState[])

    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})

    check:
      dag.getFinalizedEpochRef() != nil

    for i in 0..<blocks.len:
      check: dag.addBackfillBlock(
        blocks[blocks.len - i - 1].phase0Data).isOk()

    check:
      dag.addBackfillBlock(genBlock.phase0Data.asSigned).isOk()
      dag.addBackfillBlock(
        genBlock.phase0Data.asSigned) == AddBackRes.err VerifierError.Duplicate

    let
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()
    var
      cache: StateCache
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = newClone(Quarantine.init())

    let
      next = addTestBlock(tailState[], cache).phase0Data
      nextAdd = dag.addHeadBlock(verifier, next, nilPhase0Callback).get()
    dag.updateHead(nextAdd, quarantine[], [])

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init())

      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})
    check:
      dag2.head.root == next.root

suite "Starting states":
  setup:
    let
      genState = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Phase0,
        phase0Data: initialize_hashed_beacon_state_from_eth1(
          defaultRuntimeConfig, ZERO_HASH, 0,
          makeInitialDeposits(SLOTS_PER_EPOCH.uint64, flags = {skipBlsValidation}),
          {skipBlsValidation}))
      tailState = assignClone(genState[])
      db = BeaconChainDB.new("", inMemory = true)
      quarantine = newClone(Quarantine.init())

  test "Starting state without block":
    var
      cache: StateCache
      info: ForkedEpochInfo
    let
      genBlock = get_initial_beacon_block(genState[])
      blocks = block:
        var blocks: seq[ForkedSignedBeaconBlock]
        while getStateField(tailState[], slot).uint64 + 1 < SLOTS_PER_EPOCH:
          blocks.add addTestBlock(tailState[], cache)
        blocks
      tailBlock = blocks[^1]

    check process_slots(
      defaultRuntimeConfig, tailState[], Slot(SLOTS_PER_EPOCH), cache, info,
      {}).isOk()

    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})

    # check that we can update head to itself
    dag.updateHead(dag.head, quarantine[], [])

    check:
      dag.finalizedHead.toBlockSlotId()[] == BlockSlotId(
        bid: dag.tail, slot: (dag.tail.slot.epoch+1).start_slot)
      dag.getBlockRef(tailBlock.root).get().bid == dag.tail
      dag.getBlockRef(blocks[^2].root).isNone()

      dag.getBlockId(tailBlock.root).get() == dag.tail
      dag.getBlockId(blocks[^2].root).isNone()

      dag.getBlockIdAtSlot(Slot(0)).isNone() # no genesis stored in db
      dag.getBlockIdAtSlot(Slot(1)).isNone()

      # Should get EpochRef for the tail however
      # dag.getEpochRef(dag.tail, dag.tail.slot.epoch, true).isOk()
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      # Should not get EpochRef for random block
      dag.getEpochRef(
        BlockId(root: blocks[^2].root, slot: dag.tail.slot), # root/slot mismatch
        dag.tail.slot.epoch, true).isErr()

      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      dag.getFinalizedEpochRef() != nil

      dag.backfill == tailBlock.phase0Data.message.toBeaconBlockSummary()

      # Check that we can propose right from the checkpoint state
      dag.getProposalState(dag.head, dag.head.slot + 1, cache).isOk()

    var
      badBlock = blocks[^2].phase0Data
    badBlock.signature = blocks[^3].phase0Data.signature
    check:
      dag.addBackfillBlock(badBlock) == AddBackRes.err VerifierError.Invalid

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data) ==
        AddBackRes.err VerifierError.MissingParent
      dag.addBackfillBlock(genBlock.phase0Data.asSigned()) ==
        AddBackRes.err VerifierError.MissingParent

      dag.addBackfillBlock(tailBlock.phase0Data) == AddBackRes.ok()

    check:
      dag.addBackfillBlock(blocks[^2].phase0Data).isOk()

      dag.getBlockRef(tailBlock.root).get().bid == dag.tail
      dag.getBlockRef(blocks[^2].root).isNone()

      dag.getBlockId(tailBlock.root).get() == dag.tail
      dag.getBlockId(blocks[^2].root).get().root == blocks[^2].root

      dag.getBlockIdAtSlot(dag.tail.slot).get().bid == dag.tail

      dag.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data).isOk()

      dag.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()
      dag.getBlockIdAtSlot(dag.tail.slot - 3).isNone

    for i in 3..<blocks.len:
      check: dag.addBackfillBlock(blocks[blocks.len - i - 1].phase0Data).isOk()

    check:
      dag.addBackfillBlock(genBlock.phase0Data.asSigned).isOk()

      dag.backfill.slot == GENESIS_SLOT

    check:
      dag.getFinalizedEpochRef() != nil

suite "Latest valid hash" & preset():
  setup:
    let rng = HmacDrbgContext.new()

    var runtimeConfig = defaultRuntimeConfig
    runtimeConfig.ALTAIR_FORK_EPOCH = 1.Epoch
    runtimeConfig.BELLATRIX_FORK_EPOCH = 2.Epoch

    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, runtimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = newClone(Quarantine.init())
      cache = StateCache()
      info = ForkedEpochInfo()
      state = newClone(dag.headState)

  test "LVH searching":
    # Reach Bellatrix, where execution payloads exist
    check process_slots(
      runtimeConfig, state[],
      getStateField(state[], slot) + (3 * SLOTS_PER_EPOCH).uint64,
      cache, info, {}).isOk()

    var
      b1 = addTestBlock(state[], cache, cfg = runtimeConfig).bellatrixData
      b1Add = dag.addHeadBlock(verifier, b1, nilBellatrixCallback)
      b2 = addTestBlock(state[], cache, cfg = runtimeConfig).bellatrixData
      b2Add = dag.addHeadBlock(verifier, b2, nilBellatrixCallback)
      b3 = addTestBlock(state[], cache, cfg = runtimeConfig).bellatrixData
      b3Add = dag.addHeadBlock(verifier, b3, nilBellatrixCallback)

    dag.updateHead(b3Add[], quarantine[], [])
    check: dag.head.root == b3.root

    # Ensure that head can go backwards in case of head being marked invalid
    dag.updateHead(b2Add[], quarantine[], [])
    check: dag.head.root == b2.root

    dag.updateHead(b1Add[], quarantine[], [])
    check: dag.head.root == b1.root

    const fallbackEarliestInvalid =
      Eth2Digest.fromHex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    check:
      # Represents where LVH is two behind the invalid-marked block (because
      # first param is parent). It searches using LVH (i.e. execution hash),
      # but returns CL block hash, because that's what fork choice and other
      # Nimbus components mostly use as a coordinate system. Since b1 is set
      # to be valid here by being the LVH, it means that b2 must be invalid.
      dag.getEarliestInvalidBlockRoot(
        b2Add[].root, b1.message.body.execution_payload.block_hash,
          fallbackEarliestInvalid) == b2Add[].root

      # This simulates calling it based on b3 (child of b2), where there's no
      # gap in detecting the invalid blocks. Because the API, due to testcase
      # design, does not assume the block being tested is in the DAG, there's
      # a manually specified fallback (CL) block root to use, because it does
      # not have access to this information otherwise, because the very first
      # newest block in the chain it's examining is already valid.
      dag.getEarliestInvalidBlockRoot(
        b2Add[].root, b2.message.body.execution_payload.block_hash,
          fallbackEarliestInvalid) == fallbackEarliestInvalid

suite "Pruning":
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var res = defaultRuntimeConfig
        res.MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 4
        res.CHURN_LIMIT_QUOTIENT = 1
        res.MIN_EPOCHS_FOR_BLOCK_REQUESTS = res.safeMinEpochsForBlockRequests()
        doAssert res.MIN_EPOCHS_FOR_BLOCK_REQUESTS == 4
        res
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      tmpState = assignClone(dag.headState)

    var
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init()
      cache = StateCache()
      blocks = @[dag.head]

    for i in 0 ..< (SLOTS_PER_EPOCH * (EPOCHS_PER_STATE_SNAPSHOT + cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS)):
      let blck = addTestBlock(
        tmpState[], cache,
        attestations = makeFullAttestations(
          tmpState[], dag.head.root, getStateField(tmpState[], slot), cache, {})).phase0Data
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      blocks.add(added[])
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

  test "prune states":
    dag.pruneHistory()

    check:
      dag.tail.slot == Epoch(EPOCHS_PER_STATE_SNAPSHOT).start_slot - 1
      db.containsBlock(blocks[0].root)
      db.containsBlock(blocks[1].root)

    # Add a block
    for i in 0..2:
      let blck = addTestBlock(
        tmpState[], cache,
        attestations = makeFullAttestations(
          tmpState[], dag.head.root, getStateField(tmpState[], slot), cache, {})).phase0Data
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    dag.pruneHistory()

    check:
      dag.tail.slot == Epoch(EPOCHS_PER_STATE_SNAPSHOT).start_slot - 1
      not db.containsBlock(blocks[1].root)

suite "Ancestry":
  test "ancestorSlot":
    const numValidators = SLOTS_PER_EPOCH
    let
      cfg = defaultRuntimeConfig
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = ChainDAGRef.init(
        cfg, makeTestDB(numValidators, cfg = cfg),
        validatorMonitor, {})
      quarantine = newClone(Quarantine.init())
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()

    type Node = tuple[blck: BlockRef, state: ref phase0.HashedBeaconState]
    template bid(n: Node): BlockId = n.blck.bid

    var verifier = BatchVerifier.init(rng, taskpool)
    proc addBlock(parent: Node, slot: Slot): Node =
      dag.updateHead(parent.blck, quarantine[], [])

      var
        cache: StateCache
        info: ForkedEpochInfo
      let res = process_slots(cfg, dag.headState, slot, cache, info, flags = {})
      check res.isOk

      let
        blck = dag.headState.addTestBlock(cache, nextSlot = false, cfg = cfg)
        added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
      check added.isOk()
      dag.updateHead(added[], quarantine[], [])
      (blck: dag.head, state: newClone(dag.headState.phase0Data))

    #             s0
    #            /  \
    #           s1  s3
    #          /      \
    #         s2      s6
    #        /  \       \
    #       s4  s5      s7
    #        \
    #         s8
    #          \
    #           s9
    let
      sg = (blck: dag.head, state: newClone(dag.headState.phase0Data))
      s0 = sg.addBlock(Slot(10))
      s1 = s0.addBlock(Slot(11))
      s2 = s1.addBlock(Slot(12))
      s3 = s0.addBlock(Slot(13))
      s4 = s2.addBlock(Slot(14))
      s5 = s2.addBlock(Slot(15))
      s6 = s3.addBlock(Slot(16))
      s7 = s6.addBlock(Slot(17))
      s8 = s4.addBlock(Slot(18))
      s9 = s8.addBlock(Slot(19))

    check:
      dag.ancestorSlot(s0.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s1.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s2.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s4.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s5.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s8.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s0.state[], s9.bid, Slot(10)) == Opt.some(s0.bid.slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s0.state[], b.bid, Slot(11)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s1.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s1.state[], s1.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s1.state[], s2.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s1.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s1.state[], s4.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s1.state[], s5.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s1.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s1.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s1.state[], s8.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s1.state[], s9.bid, Slot(10)) == Opt.some(s1.bid.slot)
    for b in [s0, s3, s6, s7]:
      check dag.ancestorSlot(s1.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s1.state[], b.bid, Slot(12)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s2.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s2.state[], s1.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s2.state[], s2.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s2.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s2.state[], s4.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s2.state[], s5.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s2.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s2.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s2.state[], s8.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s2.state[], s9.bid, Slot(10)) == Opt.some(s2.bid.slot)
    for b in [s0, s3, s6, s7]:
      check dag.ancestorSlot(s2.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s3, s6, s7]:
      check dag.ancestorSlot(s2.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s2.state[], b.bid, Slot(13)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s3.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s3.state[], s1.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s3.state[], s2.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s3.state[], s3.bid, Slot(10)) == Opt.some(s3.bid.slot)
      dag.ancestorSlot(s3.state[], s4.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s3.state[], s5.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s3.state[], s6.bid, Slot(10)) == Opt.some(s3.bid.slot)
      dag.ancestorSlot(s3.state[], s7.bid, Slot(10)) == Opt.some(s3.bid.slot)
      dag.ancestorSlot(s3.state[], s8.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s3.state[], s9.bid, Slot(10)) == Opt.some(s0.bid.slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s3.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s3.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s3.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s3.state[], b.bid, Slot(14)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s4.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s4.state[], s1.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s4.state[], s2.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s4.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s4.state[], s4.bid, Slot(10)) == Opt.some(s4.bid.slot)
      dag.ancestorSlot(s4.state[], s5.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s4.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s4.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s4.state[], s8.bid, Slot(10)) == Opt.some(s4.bid.slot)
      dag.ancestorSlot(s4.state[], s9.bid, Slot(10)) == Opt.some(s4.bid.slot)
    for b in [s0, s3, s6, s7]:
      check dag.ancestorSlot(s4.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s3, s6, s7]:
      check dag.ancestorSlot(s4.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check dag.ancestorSlot(s4.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check dag.ancestorSlot(s4.state[], b.bid, Slot(14)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s4.state[], b.bid, Slot(15)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s5.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s5.state[], s1.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s5.state[], s2.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s5.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s5.state[], s4.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s5.state[], s5.bid, Slot(10)) == Opt.some(s5.bid.slot)
      dag.ancestorSlot(s5.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s5.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s5.state[], s8.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s5.state[], s9.bid, Slot(10)) == Opt.some(s2.bid.slot)
    for b in [s0, s3, s6, s7]:
      check dag.ancestorSlot(s5.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s3, s6, s7]:
      check dag.ancestorSlot(s5.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s6, s7, s8, s9]:
      check dag.ancestorSlot(s5.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s6, s7, s8, s9]:
      check dag.ancestorSlot(s5.state[], b.bid, Slot(14)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s6, s7, s8, s9]:
      check dag.ancestorSlot(s5.state[], b.bid, Slot(15)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s5.state[], b.bid, Slot(16)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s6.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s6.state[], s1.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s6.state[], s2.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s6.state[], s3.bid, Slot(10)) == Opt.some(s3.bid.slot)
      dag.ancestorSlot(s6.state[], s4.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s6.state[], s5.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s6.state[], s6.bid, Slot(10)) == Opt.some(s6.bid.slot)
      dag.ancestorSlot(s6.state[], s7.bid, Slot(10)) == Opt.some(s6.bid.slot)
      dag.ancestorSlot(s6.state[], s8.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s6.state[], s9.bid, Slot(10)) == Opt.some(s0.bid.slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(14)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(15)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(16)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s6.state[], b.bid, Slot(17)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s7.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s7.state[], s1.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s7.state[], s2.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s7.state[], s3.bid, Slot(10)) == Opt.some(s3.bid.slot)
      dag.ancestorSlot(s7.state[], s4.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s7.state[], s5.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s7.state[], s6.bid, Slot(10)) == Opt.some(s6.bid.slot)
      dag.ancestorSlot(s7.state[], s7.bid, Slot(10)) == Opt.some(s7.bid.slot)
      dag.ancestorSlot(s7.state[], s8.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s7.state[], s9.bid, Slot(10)) == Opt.some(s0.bid.slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s4, s5, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(14)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(15)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(16)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(17)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s7.state[], b.bid, Slot(18)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s8.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s8.state[], s1.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s8.state[], s2.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s8.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s8.state[], s4.bid, Slot(10)) == Opt.some(s4.bid.slot)
      dag.ancestorSlot(s8.state[], s5.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s8.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s8.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s8.state[], s8.bid, Slot(10)) == Opt.some(s8.bid.slot)
      dag.ancestorSlot(s8.state[], s9.bid, Slot(10)) == Opt.some(s8.bid.slot)
    for b in [s0, s3, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s3, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(14)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(15)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(16)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(17)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(18)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s8.state[], b.bid, Slot(19)) == Opt.none(Slot)

    check:
      dag.ancestorSlot(s9.state[], s0.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s9.state[], s1.bid, Slot(10)) == Opt.some(s1.bid.slot)
      dag.ancestorSlot(s9.state[], s2.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s9.state[], s3.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s9.state[], s4.bid, Slot(10)) == Opt.some(s4.bid.slot)
      dag.ancestorSlot(s9.state[], s5.bid, Slot(10)) == Opt.some(s2.bid.slot)
      dag.ancestorSlot(s9.state[], s6.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s9.state[], s7.bid, Slot(10)) == Opt.some(s0.bid.slot)
      dag.ancestorSlot(s9.state[], s8.bid, Slot(10)) == Opt.some(s8.bid.slot)
      dag.ancestorSlot(s9.state[], s9.bid, Slot(10)) == Opt.some(s9.bid.slot)
    for b in [s0, s3, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(11)) == Opt.none(Slot)
    for b in [s0, s1, s3, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(12)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(13)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s5, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(14)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(15)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(16)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(17)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(18)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(19)) == Opt.none(Slot)
    for b in [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9]:
      check dag.ancestorSlot(s9.state[], b.bid, Slot(20)) == Opt.none(Slot)

template runShufflingTests(cfg: RuntimeConfig, numRandomTests: int) =
  const
    numValidators = SLOTS_PER_EPOCH
    targetNumValidators = 20 * SLOTS_PER_EPOCH * MAX_DEPOSITS
  var deposits = newSeqOfCap[Deposit](targetNumValidators)
  for depositIndex in 0 ..< targetNumValidators:
    deposits.add Deposit(data: makeDeposit(depositIndex.int, cfg = cfg))
  let
    eth1Data = Eth1Data(
      deposit_root: deposits.attachMerkleProofs(),
      deposit_count: deposits.lenu64)
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(
      cfg, makeTestDB(
        numValidators, eth1Data = Opt.some(eth1Data),
        flags = {}, cfg = cfg),
      validatorMonitor, {})
    quarantine = newClone(Quarantine.init())
    rng = HmacDrbgContext.new()
    taskpool = Taskpool.new()

  var
    verifier = BatchVerifier.init(rng, taskpool)
    graffiti: GraffitiBytes
  proc addBlocks(blocks: uint64, attested: bool, cache: var StateCache) =
    inc distinctBase(graffiti)[0]  # Avoid duplicate blocks across branches
    for forkedBlck in makeTestBlocks(
        dag.headState, cache, blocks.int, eth1_data = eth1Data,
        attested = attested, allDeposits = deposits,
        graffiti = graffiti, cfg = cfg):
      let added = withBlck(forkedBlck):
        const nilCallback = (consensusFork.OnBlockAddedCallback)(nil)
        dag.addHeadBlock(verifier, forkyBlck, nilCallback)
      check added.isOk()
      dag.updateHead(added[], quarantine[], [])

  var states: seq[ref ForkedHashedBeaconState]

  # Genesis state
  states.add newClone(dag.headState)

  # Create a segment and cache the post state (0.75 epochs + empty slots)
  proc createSegment(attested: bool, delaySlots = 0.uint64) =
    var cache: StateCache

    # Add some empty slots to have different deposit history
    if delaySlots > 0:
      var info: ForkedEpochInfo
      check cfg.process_slots(
        dag.headState,
        getStateField(dag.headState, slot) + delaySlots,
        cache, info, flags = {}).isOk

    # Add 0.75 epochs
    addBlocks((SLOTS_PER_EPOCH * 3) div 4, attested = attested, cache)
    states.add newClone(dag.headState)

  # Linear part of history (3.75 epochs)
  for _ in 0 ..< 5:
    createSegment(attested = true)

  # Start branching (6 epochs + up to 0.5 epoch)
  func numDelaySlots(branchId: int): uint64 =
    branchId.uint64 * SLOTS_PER_EPOCH div 8
  for a in 0 ..< 2:
    let oldHead = dag.head
    createSegment(attested = false, delaySlots = a.numDelaySlots)
    for b in 0 ..< 2:
      let oldHead = dag.head
      createSegment(attested = false, delaySlots = b.numDelaySlots)
      for _ in 0 ..< 3:
        createSegment(attested = false, delaySlots = a.numDelaySlots)
        createSegment(attested = false, delaySlots = b.numDelaySlots)
      dag.updateHead(oldHead, quarantine[], [])
    dag.updateHead(oldHead, quarantine[], [])

  # Cover entire range of epochs plus some extra
  const maxEpochOfInterest = compute_activation_exit_epoch(11.Epoch) + 2

  template checkShuffling(
      epochRef: Result[EpochRef, cstring],
      computedShufflingRefParam: Opt[ShufflingRef]) =
    ## Check that computed shuffling matches the one from `EpochRef`.
    block:
      let computedShufflingRef = computedShufflingRefParam
      if computedShufflingRef.isSome:
        check computedShufflingRef.get[] == epochRef.get.shufflingRef[]

  test "Accelerated shuffling computation":
    randomize()
    let forkBlocks = dag.forkBlocks.toSeq()
    for _ in 0 ..< numRandomTests:  # Each test runs against _all_ cached states
      let
        blck = sample(forkBlocks).data
        epoch = rand(GENESIS_EPOCH .. maxEpochOfInterest)
      checkpoint "blck: " & $shortLog(blck) & " / epoch: " & $shortLog(epoch)

      let epochRef = dag.getEpochRef(blck, epoch, true)
      check epochRef.isOk

      let dependentBsi = dag.atSlot(blck.bid, epoch.attester_dependent_slot)
      check dependentBsi.isSome
      let
        memoryMix = dag.computeRandaoMixFromMemory(
          dependentBsi.get.bid, epoch.lowSlotForAttesterShuffling)
        databaseMix = dag.computeRandaoMixFromDatabase(
          dependentBsi.get.bid, epoch.lowSlotForAttesterShuffling)

      # If shuffling is computable from DAG, check its correctness
      epochRef.checkShuffling dag.computeShufflingRefFromMemory(blck, epoch)

      # If shuffling is computable from DB, check its correctness
      epochRef.checkShuffling dag.computeShufflingRefFromDatabase(blck, epoch)

      # Shuffling should be correct when starting from any cached state
      for state in states:
        withState(state[]):
          let
            stateEpoch = forkyState.data.get_current_epoch
            blckEpoch = blck.bid.slot.epoch
            minEpoch = min(stateEpoch, blckEpoch)
            shufflingRef = dag.computeShufflingRef(forkyState, blck, epoch)
            mix = dag.computeRandaoMix(forkyState,
              dependentBsi.get.bid, epoch.lowSlotForAttesterShuffling)
          if compute_activation_exit_epoch(minEpoch) <= epoch or
              dag.ancestorSlot(
                forkyState, dependentBsi.get.bid,
                epoch.lowSlotForAttesterShuffling).isNone:
            check:
              shufflingRef.isNone
              mix.isNone
          else:
            check shufflingRef.isSome
            epochRef.checkShuffling shufflingRef
            check:
              mix.isSome
              memoryMix.isNone or mix == memoryMix
              databaseMix.isNone or mix == databaseMix
            epochRef.checkShuffling Opt.some ShufflingRef(
              epoch: epoch,
              attester_dependent_root: dependentBsi.get.bid.root,
              shuffled_active_validator_indices: forkyState.data
                .get_shuffled_active_validator_indices(epoch, mix.get))

  test "Accelerated shuffling computation (with epochRefState jump)":
    # Test cases where `epochRefState` is set to a very old block
    # that is advanced by several epochs to a recent slot.
    #
    # This is not dependent on the multilayer branching of the "Shufflings"
    # suite, but a function of getEpochRef extending epochRefState towards
    # a slot which it is essentially hallucinating a state, because it is
    # not accounting for the blocks with deposits. As it takes non-trivial
    # time to set up the "Shufflings" suite, we reuse its more complex DAG.
    #
    # The purely random fuzzing/tests have difficulty triggering this, because
    # this needs to happen across a wide portion of the sampled range so that:
    # (1) it checks a maximally early slot, both to create the gaps needed for
    #     (2) and (3), and to keep both blocks on the same forks, with maximal
    #     likelihood;
    # (2) calls getEpochRef with a late enough epoch to trigger the
    #     hallucination of relevance (>= epoch 4 typically works); and
    # (3) there then have to be enough slots between the last added block and
    #     the next state which will be sampled so that the validators can get
    #     active, after some spec 5 epoch delay. This pushes the lowest epoch
    #     possible to not much less than 8 which is already near the high end
    #     of the epoch sampling. Too early an epoch and it is within range of
    #     the headState check which gets it first, so the epochStateRef isn't
    #     exercised.

    let forkBlocks = dag.forkBlocks.toSeq()

    proc findKeyedBlck(m: Slot): int =
      # Avoid depending on implementation details of how `forkBlocks` is ordered
      for idx, fb in forkBlocks:
        if fb.data.slot == m:
          return idx
      raiseAssert "Unreachable"

    # The epoch for the first block can range from at least 4 to 10
    for (blockIdx, epoch) in [
        (findKeyedBlck(64.Slot), 10.Epoch),
        (findKeyedBlck(255.Slot), 8.Epoch)]:
      let
        blck = forkBlocks[blockIdx].data
        epochRef = dag.getEpochRef(blck, epoch, true)
      doAssert epochRef.isOk

      # If shuffling is computable from DAG, check its correctness
      epochRef.checkShuffling dag.computeShufflingRefFromMemory(blck, epoch)

      # If shuffling is computable from DB, check its correctness
      epochRef.checkShuffling dag.computeShufflingRefFromDatabase(blck, epoch)

suite "Shufflings":
  let cfg = defaultRuntimeConfig
  runShufflingTests(cfg, numRandomTests = 150)

suite "Shufflings (merged)":
  let cfg = block:
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
    cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    cfg
  runShufflingTests(cfg, numRandomTests = 50)

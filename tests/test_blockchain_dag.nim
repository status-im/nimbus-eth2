# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  taskpools,
  ../beacon_chain/el/merkle_minimal,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/[
    beaconstate, forks, helpers, signatures, state_transition],
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, block_quarantine, block_clearance,
    spec_cache],
  ../beacon_chain/fork_choice/fast_confirmation,
  ./[testblockutil, testdbutil, teststateutil, testutil]

from std/random import rand, randomize, sample
from std/sequtils import mapIt, toSeq
from ../beacon_chain/spec/datatypes/capella import
  SignedBLSToExecutionChangeList
from ./testbcutil import addHeadBlock

const
  nilPhase0Callback = OnBlockAdded[ConsensusFork.Phase0](nil)
  nilAltairCallback = OnBlockAdded[ConsensusFork.Altair](nil)
  nilBellatrixCallback = OnBlockAdded[ConsensusFork.Bellatrix](nil)
  nilGloasCallback = OnBlockAdded[ConsensusFork.Gloas](nil)

proc pruneAtFinalization(dag: ChainDAGRef) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()

type
  AddHeadRes = Result[BlockRef, VerifierError]
  AddBackRes = Result[void, VerifierError]

suite "Block pool processing" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = defaultRuntimeConfig
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
    var
      verifier {.used.} = BatchVerifier.init(rng, taskpool)
      quarantine {.used.} = Quarantine.init(dag.cfg)
    let state = newClone(dag.headState)
    var
      cache: StateCache
      info {.used.}: ForkedEpochInfo
    let
      att0 = makeFullAttestations(state[], dag.tail.root, 0.Slot, cache)
      b1 {.used.} = addTestBlock(state[], cache, attestations = att0).phase0Data
      b2 {.used.} = addTestBlock(state[], cache).phase0Data

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

  test "isAncestorOf":
    var tmpState = newClone(dag.headState)
    let
      genesisBid = dag.head.bid
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)
      b2Add = dag.addHeadBlock(verifier, b2, nilPhase0Callback)
      b1Fork = addTestBlock(tmpState[], cache).phase0Data
      b1ForkAdd = dag.addHeadBlock(verifier, b1Fork, nilPhase0Callback)
      unknown = BlockId(slot: 1.Slot, root: Eth2Digest.fromHex("0x01"))
    template do_checks(didPruneFork: bool): untyped =
      check:
        # Same block
        dag.isAncestorOf(genesisBid, genesisBid)
        dag.isAncestorOf(b1Add[].bid, b1Add[].bid)
        dag.isAncestorOf(b2Add[].bid, b2Add[].bid)

        # Linear chain
        dag.isAncestorOf(genesisBid, b1Add[].bid)
        dag.isAncestorOf(genesisBid, b2Add[].bid)
        dag.isAncestorOf(b1Add[].bid, b2Add[].bid)
        not dag.isAncestorOf(b2Add[].bid, genesisBid)
        not dag.isAncestorOf(b2Add[].bid, b1Add[].bid)
        not dag.isAncestorOf(b1Add[].bid, genesisBid)

        # Fork
        dag.isAncestorOf(genesisBid, b1ForkAdd[].bid) == not didPruneFork
        not dag.isAncestorOf(b1Add[].bid, b1ForkAdd[].bid)
        not dag.isAncestorOf(b1ForkAdd[].bid, b1Add[].bid)
        not dag.isAncestorOf(b1ForkAdd[].bid, b2Add[].bid)
        not dag.isAncestorOf(b2Add[].bid, b1ForkAdd[].bid)

        # Unknown root
        not dag.isAncestorOf(unknown, b2Add[].bid)
        not dag.isAncestorOf(b2Add[].bid, unknown)
        dag.isAncestorOf(unknown, unknown)
    do_checks(didPruneFork = false)

    # Build enough blocks to finalize, then test with pruned blocks
    let
      b1Bid = b1Add[].bid
      b1ForkBid = b1ForkAdd[].bid
    dag.updateHead(b2Add[], quarantine, [])
    tmpState = assignClone(dag.headState)
    for i in 0 ..< (SLOTS_PER_EPOCH * 4):
      let
        blck = addTestBlock(
          tmpState[], cache,
          attestations = makeFullAttestations(
            tmpState[], dag.head.root, tmpState[].slot, cache, {})).phase0Data
        added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()
    check:
      dag.finalizedHead.slot > b1Bid.slot
      dag.getBlockRef(b1Bid.root).isErr  # pruned

      # Pruned canonical block is ancestor of head
      dag.isAncestorOf(b1Bid, dag.head.bid)
      not dag.isAncestorOf(dag.head.bid, b1Bid)

      # Pruned orphaned fork is not ancestor of head
      not dag.isAncestorOf(b1ForkBid, dag.head.bid)
    do_checks(didPruneFork = true)

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
      validators = dag.headState.validators.lenu64()

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
    check cfg.process_slots(
      state[], state[].slot + 1, cache, info, {}).isOk()

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
      dag.getBlockRange(Slot(0), blocks.toOpenArray(0, 0)) == 0
      blocks[0..<1] == [dag.tail]

      dag.getBlockRange(Slot(0), blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [dag.tail, b1Add[].bid]

      # No blocks in sight
      dag.getBlockRange(Slot(5), blocks.toOpenArray(0, 1)) == 2

      # No blocks in sight
      dag.getBlockRange(Slot(uint64.high), blocks.toOpenArray(0, 1)) == 2

    # A fork forces the clearance state to a point where it cannot be advanced
    let
      nextEpoch = dag.head.slot.epoch + 1
      nextEpochSlot = nextEpoch.start_slot()
      parentBsi = dag.head.parent.atSlot(nextEpochSlot).toBlockSlotId().get()
      stateCheckpoint = dag.stateCheckpoint(parentBsi)
      shufflingRef = dag.getShufflingRef(dag.head, nextEpoch, false).valueOr:
        raiseAssert "false"
      nextEpochProposers = withState(dag.headState):
        when consensusFork == ConsensusFork.Gloas:
          default(seq[Opt[ValidatorIndex]])
        else:
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
      dag.epochRefState.slot == nextEpochSlot

    assign(state[], dag.epochRefState)

    let bnext = addTestBlock(state[], cache).phase0Data
    discard dag.addHeadBlock(verifier, bnext, nilPhase0Callback)

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
      dag.headState.slot == b1Add[].slot

  test "updateState sanity" & preset():
    let
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)
      b2Add = dag.addHeadBlock(verifier, b2, nilPhase0Callback)
      bs1 = BlockSlotId.init(b1Add[].bid, b1.message.slot)
      bs1_3 = BlockSlotId.init(b1Add[].bid, 3.Slot)
      bs2_3 = BlockSlotId.init(b2Add[].bid, 3.Slot)

    let tmpState = assignClone(dag.headState)

    # move to specific block
    var cache: StateCache
    check:
      dag.updateState(tmpState[], bs1, false, cache, dag.updateFlags)
      tmpState[].latest_block_root == b1Add[].root
      tmpState[].slot == bs1.slot

    # Skip slots
    check:
      dag.updateState(tmpState[], bs1_3, false, cache, dag.updateFlags)
      tmpState[].latest_block_root == b1Add[].root
      tmpState[].slot == bs1_3.slot

    # Move back slots, but not blocks
    check:
      dag.updateState(
        tmpState[], dag.parent(bs1_3.bid).expect("block").atSlot(), false,
        cache, dag.updateFlags)
      tmpState[].latest_block_root == b1Add[].parent.root
      tmpState[].slot == b1Add[].parent.slot

    # Move to different block and slot
    check:
      dag.updateState(tmpState[], bs2_3, false, cache, dag.updateFlags)
      tmpState[].latest_block_root == b2Add[].root
      tmpState[].slot == bs2_3.slot

    # Move back slot and block
    check:
      dag.updateState(tmpState[], bs1, false, cache, dag.updateFlags)
      tmpState[].latest_block_root == b1Add[].root
      tmpState[].slot == bs1.slot

    # Move back to genesis
    check:
      dag.updateState(
        tmpState[], dag.parent(bs1.bid).expect("block").atSlot(), false, cache,
        dag.updateFlags)
      tmpState[].latest_block_root == b1Add[].parent.root
      tmpState[].slot == b1Add[].parent.slot

suite "Block pool altair processing" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = Epoch(1)
        res
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
    var verifier = BatchVerifier.init(rng, taskpool)
    let state = newClone(dag.headState)
    var
      cache: StateCache
      info: ForkedEpochInfo

    # Advance to altair
    check:
      cfg.process_slots(
        state[], cfg.ALTAIR_FORK_EPOCH.start_slot(), cache, info, {}).isOk()

      state[].kind == ConsensusFork.Altair

    let
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
    let
      rng = HmacDrbgContext.new()
      cfg = defaultRuntimeConfig
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
    var
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init(dag.cfg)
      cache: StateCache
      info {.used.} = ForkedEpochInfo()

  test "prune heads on finalization" & preset():
    # Create a fork that will not be taken
    var blck = makeTestBlock(dag.headState, cache).phase0Data
    let tmpState = assignClone(dag.headState)
    check cfg.process_slots(
      tmpState[], tmpState[].slot + (5 * SLOTS_PER_EPOCH),
      cache, info, {}).isOk()

    let lateBlock = addTestBlock(tmpState[], cache).phase0Data
    block:
      let status = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: status.isOk()

    assign(tmpState[], dag.headState)

    # skip slots so we can test gappy getBlockIdAtSlot
    check cfg.process_slots(
      tmpState[], tmpState[].slot + 2.uint64,
      cache, info, {}).isOk()

    for i in 0 ..< (SLOTS_PER_EPOCH * 6):
      if i == 1:
        # There are 2 heads now because of the fork at slot 1
        check:
          dag.heads.len == 2

      blck = addTestBlock(
        tmpState[], cache,
        attestations = makeFullAttestations(
          tmpState[], dag.head.root, tmpState[].slot, cache, {})).phase0Data
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    check:
      dag.heads.len() == 1
      dag.forkBlocksMatchHeads()
      db.getHeadBlocks() == dag.heads.mapIt(it.root)
      dag.getBlockIdAtSlot(0.Slot).get().bid.slot == 0.Slot
      dag.getBlockIdAtSlot(2.Slot).get() ==
        BlockSlotId.init(dag.getBlockIdAtSlot(1.Slot).get().bid, 2.Slot)

      dag.getBlockIdAtSlot(dag.head.slot).get() == BlockSlotId.init(
        dag.head.bid, dag.head.slot)
      dag.getBlockIdAtSlot(dag.head.slot + 1).get() == BlockSlotId.init(
        dag.head.bid, dag.head.slot + 1)

      not dag.containsForkBlock(dag.getBlockIdAtSlot(5.Slot).get().bid.root)
      dag.containsForkBlock(dag.finalizedHead.blck.root)

      # Finalized - no BlockRef
      dag.getBlockRef(dag.getBlockIdAtSlot(0.Slot).get().bid.root).isNone()

      dag.getBlockRef(dag.finalizedHead.blck.root).isSome()

      isNil dag.finalizedHead.blck.parent

    check:
      dag.db.immutableValidators.len() == dag.headState.validators.len()

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
        false, cache, dag.updateFlags)

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
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})

    # check that the state reloaded from database resembles what we had before
    check:
      dag2.tail.root == dag.tail.root
      dag2.head.root == dag.head.root
      dag2.head.root == parentRoot
      dag2.finalizedHead.blck.root == dag.finalizedHead.blck.root
      dag2.finalizedHead.slot == dag.finalizedHead.slot
      dag2.headState.root == dag.headState.root
      dag2.forkBlocksMatchHeads()

    # No canonical block data should be pruned by the removal of the fork
    for i in Slot(0)..dag2.head.slot:
      let bids = dag.getBlockIdAtSlot(i).expect("found it")
      if bids.isProposed:
        check: dag2.getForkedBlock(bids.bid).isSome

    # The unviable block should have been pruned however
    check: dag2.getForkedBlock(lateBlock.root).isNone

  test "discard unloadable and duplicate heads on init" & preset():
    let blck = makeTestBlock(dag.headState, cache).phase0Data
    block:
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])

    # Add separate head to database, but don't store block data
    let
      headRoot = dag.head.root
      staleState = assignClone(dag.headState)
      staleRoot = makeTestBlock(staleState[], cache).phase0Data.root
    db.putHeadBlocks(@[headRoot, staleRoot, headRoot])  # Also add duplicate

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})
    check:
      dag2.heads.mapIt(it.bid.root) == @[headRoot]
      db.getHeadBlocks() == @[headRoot]
      dag2.forkBlocksMatchHeads()

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

    doAssert cfg.process_slots(
      prestate[], prestate[].slot + 1,
      cache, info, {}).isOk()

    # create another block, orphaning the head
    let blck = makeTestBlock(prestate[], cache).phase0Data

    # Add block, but don't update head
    let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
    check: added.isOk()

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})

    # check that we can apply the block after the orphaning
    check:
      dag2.getBlockRef(blck.root).isSome
      dag2.addHeadBlock(verifier, blck, nilPhase0Callback) ==
        AddHeadRes.err VerifierError.Duplicate

  test "init with gaps" & preset():
    for blck in makeTestBlocks(
        dag.headState, cache, int(SLOTS_PER_EPOCH * 6 - 2), attested = true):
      let added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    # Advance past epoch so that the epoch transition is gapped
    check cfg.process_slots(
      dag.headState, Slot(SLOTS_PER_EPOCH * 6 + 2),
      cache, info, {}).isOk()

    let blck = makeTestBlock(
      dag.headState, cache,
      attestations = makeFullAttestations(
        dag.headState, dag.head.root, dag.headState.slot,
        cache, {})).phase0Data

    let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
    check: added.isOk()
    dag.updateHead(added[], quarantine, [])
    dag.pruneAtFinalization()

    block:
      # Check that we can rewind to every block from head to finalized
      var cur = dag.head
      let tmpStateData = assignClone(dag.headState)
      while cur != nil: # Go all the way to dag.finalizedHead
        assign(tmpStateData[], dag.headState)
        check:
          dag.updateState(tmpStateData[], cur.bid.atSlot(), false, cache,
                          dag.updateFlags)
          dag.getForkedBlock(cur.bid).get().phase0Data.message.state_root ==
            tmpStateData[].root
          tmpStateData[].root == hash_tree_root(
            tmpStateData[].phase0Data.data)
        cur = cur.parent

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})

    # check that the state reloaded from database resembles what we had before
    check:
      dag2.tail.root == dag.tail.root
      dag2.head.root == dag.head.root
      dag2.finalizedHead.blck.root == dag.finalizedHead.blck.root
      dag2.finalizedHead.slot == dag.finalizedHead.slot
      dag2.headState.root == dag.headState.root

  test "shutdown during finalization" & preset():
    var
      testPassed: bool
      forkRoot: Eth2Digest
      firstCanonicalRoot: Eth2Digest

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
            dag.headState.finalized_checkpoint.epoch.start_slot
          dbFinalizedSlot =
            dag.db.finalizedBlocks.high.expect("Valid DB")
        doAssert stateFinalizedSlot > dbFinalizedSlot, "Finalized not written"

        # If the beacon node were to exit _now_, this is what the DB looks like.
        # Validate that we can initialize a new DAG from this database.
        let
          validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
          dag2 = ChainDAGRef.init(cfg, db, validatorMonitor2, {})
        if dag2.finalizedHead.slot > GENESIS_SLOT:
          # Orphans and pre-finalized should lose their BlockRef
          doAssert dag2.heads.len == 1
          doAssert dag2.getBlockRef(forkRoot).isNone
          doAssert dag2.getForkedBlock(forkRoot).isNone
          doAssert dag2.getBlockRef(firstCanonicalRoot).isNone
          doAssert dag2.forkBlocksMatchHeads()
        testPassed = true
    dag.setHeadCb(onHeadChanged)

    # Add an extra block that will be orphaned and purged on finality
    block:
      var cache: StateCache
      let
        tmpState = assignClone(dag.headState)
        forkBlock = addTestBlock(
          tmpState[], cache, graffiti = "fork".graffiti).phase0Data
        added = dag.addHeadBlock(verifier, forkBlock, nilPhase0Callback)
      check: added.isOk()
      forkRoot = forkBlock.root

    for blck in makeTestBlocks(
        dag.headState, cache, int(SLOTS_PER_EPOCH * 4), attested = true):
      let added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
      check: added.isOk
      if firstCanonicalRoot.isZero:
        firstCanonicalRoot = added[].root
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    check testPassed

suite "Old database versions" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = defaultRuntimeConfig
      genState = newClone(initGenesisState(cfg, SLOTS_PER_EPOCH).phase0Data)
      genBlock = get_initial_beacon_block(genState[])
    let taskpool = Taskpool.new()
    var verifier = BatchVerifier.init(rng, taskpool)

  test "pre-1.1.0":
    # only kvstore, no immutable validator keys
    let
      sq = SqStoreRef.init("", "test", inMemory = true).expect(
        "working database (out of memory?)")
      v0 = BeaconChainDBV0.new(sq, readOnly = false)
      db = BeaconChainDB.new(sq, cfg)

    # preInit a database to a v1.0.12 state
    v0.putStateV0(genState[].root, genState[].data)
    v0.putBlockV0(genBlock)

    db.putStateRoot(
      genState[].latest_block_root, genState[].data.slot, genState[].root)
    db.putTailBlock(genBlock.root)
    db.putHeadBlock(genBlock.root)
    db.putGenesisBlock(genBlock.root)

    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db,validatorMonitor, {})
      state = newClone(dag.headState)
    var cache: StateCache
    let
      att0 = makeFullAttestations(state[], dag.tail.root, 0.Slot, cache)
      b1 = addTestBlock(state[], cache, attestations = att0).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check:
      b1Add.isOk()

suite "Diverging hardforks":
  setup:
    let
      rng = HmacDrbgContext.new()
      phase0RuntimeConfig = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = FAR_FUTURE_EPOCH
        res
      altairRuntimeConfig = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = 2.Epoch
        res
      db = phase0RuntimeConfig.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(
        ValidatorMonitor.init(phase0RuntimeConfig))
      dag = init(ChainDAGRef, phase0RuntimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
    var verifier = BatchVerifier.init(rng, taskpool)
    let quarantine = newClone(Quarantine.init(dag.cfg))
    var
      cache: StateCache
      info = ForkedEpochInfo()
    let tmpState = assignClone(dag.headState)

  test "Tail block only in common":
    check:
      process_slots(
        phase0RuntimeConfig, tmpState[],
        tmpState[].slot + (3 * SLOTS_PER_EPOCH).uint64,
        cache, info, {}).isOk()

    # Because the first block is after the Altair transition, the only block in
    # common is the tail block
    let
      b1 = addTestBlock(tmpState[], cache).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check b1Add.isOk()
    dag.updateHead(b1Add[], quarantine[], [])

    let validatorMonitorAltair = newClone(
      ValidatorMonitor.init(altairRuntimeConfig))

    let dagAltair = init(
      ChainDAGRef, altairRuntimeConfig, db, validatorMonitorAltair, {})
    discard AttestationPool.init(dagAltair, quarantine)

  test "Non-tail block in common":
    check:
      process_slots(
        phase0RuntimeConfig, tmpState[],
        tmpState[].slot + SLOTS_PER_EPOCH.uint64,
        cache, info, {}).isOk()

    # There's a block in the shared-correct phase0 hardfork, before epoch 2
    let
      b1 = addTestBlock(tmpState[], cache).phase0Data
      b1Add = dag.addHeadBlock(verifier, b1, nilPhase0Callback)

    check:
      b1Add.isOk()
      process_slots(
        phase0RuntimeConfig, tmpState[],
        tmpState[].slot + (3 * SLOTS_PER_EPOCH).uint64,
        cache, info, {}).isOk()

    let
      b2 = addTestBlock(tmpState[], cache).phase0Data
      b2Add = dag.addHeadBlock(verifier, b2, nilPhase0Callback)

    check b2Add.isOk()
    dag.updateHead(b2Add[], quarantine[], [])

    let validatorMonitor = newClone(
      ValidatorMonitor.init(altairRuntimeConfig))

    let dagAltair = init(
      ChainDAGRef, altairRuntimeConfig, db, validatorMonitor, {})
    discard AttestationPool.init(dagAltair, quarantine)

suite "Backfill":
  setup:
    let
      cfg = defaultRuntimeConfig
      genState = initGenesisState(cfg, SLOTS_PER_EPOCH)
      tailState = assignClone(genState[])

      blocks = block:
        var blocks: seq[ForkedSignedBeaconBlock]
        var cache: StateCache
        for i in 0..<SLOTS_PER_EPOCH * 2:
          blocks.add addTestBlock(tailState[], cache)
        blocks

    let
      db = BeaconChainDB.new("", cfg, inMemory = true)

  test "Backfill to genesis":
    let
      tailBlock = blocks[^1]
      genBlock = get_initial_beacon_block(genState[])

    ChainDAGRef.preInit(db, genState[])
    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

    var cache = StateCache()

    check:
      dag.getBlockRef(tailBlock.root).get().bid == dag.tail
      dag.getBlockRef(blocks[^2].root).isNone()

      dag.getBlockId(tailBlock.root).get() == dag.tail
      dag.getBlockId(blocks[^2].root).isNone()

      dag.getBlockIdAtSlot(dag.tail.slot).get().bid == dag.tail
      dag.getBlockIdAtSlot(dag.tail.slot - 1).get().bid ==
        blocks[^2].toBlockId()  # recovered from tailState

      dag.getBlockIdAtSlot(Slot(0)).isSome()  # genesis stored in db
      dag.getBlockIdAtSlot(Slot(1)).isSome()  # recovered from tailState

      # No EpochRef for pre-tail epochs
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch - 1, true).isErr()

      # Should get EpochRef for the tail however
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch, true).isOk()
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      # Should not get EpochRef for random block
      dag.getEpochRef(
        BlockId(root: blocks[^2].root, slot: dag.tail.slot),  # incorrect slot
        dag.tail.slot.epoch, true).isErr()

      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      dag.getFinalizedEpochRef() != nil

      # Checkpoint block is unavailable, and should be backfileld first
      not dag.containsBlock(dag.tail)
      dag.backfill == BeaconBlockSummary(
        slot: dag.tail.slot + 1,
        parent_root: dag.tail.root)

      # Check that we can propose right from the checkpoint state
      dag.getProposalState(dag.head, dag.head.slot + 1, cache).isOk()

    var badBlock = blocks[^1].phase0Data
    badBlock.signature = blocks[^2].phase0Data.signature
    check:
      dag.addBackfillBlock(badBlock) == AddBackRes.err VerifierError.Invalid

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data) ==
        AddBackRes.err VerifierError.MissingParent
      dag.addBackfillBlock(genBlock.phase0Data.asSigned()) ==
        AddBackRes.err VerifierError.MissingParent

      dag.addBackfillBlock(blocks[^2].phase0Data) ==
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
      dag.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()  # recovered from tailState

      dag.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data).isOk()

      dag.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()
      dag.getBlockIdAtSlot(dag.tail.slot - 3).get() ==
        blocks[^4].toBlockId().atSlot()  # recovered from tailState

    for i in 3..<blocks.len:
      check: dag.addBackfillBlock(blocks[blocks.len - i - 1].phase0Data).isOk()

    check:
      dag.addBackfillBlock(genBlock.phase0Data.asSigned) ==
        AddBackRes.err VerifierError.Duplicate

      dag.backfill.slot == GENESIS_SLOT

    dag.rebuildIndex(proc(): bool = false)

    check:
      dag.getFinalizedEpochRef() != nil

    for i in 0..<blocks.len:
      check dag.containsBlock(blocks[i].toBlockId())

  test "Reload backfill position":
    let
      tailBlock = blocks[^1]

    ChainDAGRef.preInit(db, genState[])
    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

    check:
      dag.addBackfillBlock(blocks[^1].phase0Data).isOk()
      dag.backfill == blocks[^1].phase0Data.message.toBeaconBlockSummary()

      dag.addBackfillBlock(blocks[^2].phase0Data).isOk()
      dag.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))

      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})

    check:
      dag2.getFinalizedEpochRef() != nil

      dag2.getBlockRef(tailBlock.root).get().root == dag.tail.root
      dag2.getBlockRef(blocks[^2].root).isNone()

      dag2.getBlockIdAtSlot(dag.tail.slot).get().bid.root == dag.tail.root

      dag2.getBlockIdAtSlot(dag.tail.slot - 1).get() ==
        blocks[^2].toBlockId().atSlot()
      dag2.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()  # recovered from tailState
      dag2.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

  test "Init without genesis / block":
    let genBlock = get_initial_beacon_block(genState[])

    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

    check:
      dag.getFinalizedEpochRef() != nil

    # Try importing blocks too early
    for i in 0..<blocks.len - 1:
      check dag.addBackfillBlock(blocks[i].phase0Data) ==
        AddBackRes.err VerifierError.MissingParent

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

    let
      quarantine = newClone(Quarantine.init(dag.cfg))
      next = addTestBlock(tailState[], cache).phase0Data
      nextAdd = dag.addHeadBlock(verifier, next, nilPhase0Callback).get()
    dag.updateHead(nextAdd, quarantine[], [])

    let
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))

      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})
    check:
      dag2.head.root == next.root

  test "Restart after each block":
    ChainDAGRef.preInit(db, tailState[])

    for i in 1..blocks.len:
      let
        validatorMonitor = newClone(ValidatorMonitor.init(cfg))
        dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

      check dag.backfill == (
        if i > 1:
          blocks[^(i - 1)].phase0Data.message.toBeaconBlockSummary()
        else:
          BeaconBlockSummary(
            slot: blocks[^1].phase0Data.message.slot + 1,
            parent_root: blocks[^1].phase0Data.root))

      for j in 1..blocks.len:
        if j < i:
          check dag.addBackfillBlock(blocks[^j].phase0Data) ==
            AddBackRes.err VerifierError.Duplicate
        elif j > i:
          check dag.addBackfillBlock(blocks[^j].phase0Data) ==
            AddBackRes.err VerifierError.MissingParent
        else:
          discard

      check:
        dag.addBackfillBlock(blocks[^i].phase0Data).isOk()
        dag.backfill == blocks[^i].phase0Data.message.toBeaconBlockSummary()

    block:
      let
        validatorMonitor = newClone(ValidatorMonitor.init(cfg))
        dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
        genBlock = get_initial_beacon_block(genState[])
      check:
        dag.addBackfillBlock(genBlock.phase0Data.asSigned()).isOk()
        dag.backfill == default(BeaconBlockSummary)

    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
    check dag.backfill == default(BeaconBlockSummary)

suite "Starting states":
  setup:
    let
      cfg = defaultRuntimeConfig
      genState = initGenesisState(cfg, SLOTS_PER_EPOCH)
      tailState = assignClone(genState[])
      db = BeaconChainDB.new("", cfg, inMemory = true)
      quarantine = newClone(Quarantine.init(cfg))

  test "Starting state without block":
    var
      cache: StateCache
      info: ForkedEpochInfo
    let
      genBlock = get_initial_beacon_block(genState[])
      blocks = block:
        var blocks: seq[ForkedSignedBeaconBlock]
        while tailState[].slot.uint64 + 1 < SLOTS_PER_EPOCH:
          blocks.add addTestBlock(tailState[], cache)
        blocks
      tailBlock = blocks[^1]

    check cfg.process_slots(
      tailState[], Slot(SLOTS_PER_EPOCH), cache, info, {}).isOk()

    ChainDAGRef.preInit(db, tailState[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

    # check that we can update head to itself
    dag.updateHead(dag.head, quarantine[], [])

    check:
      dag.finalizedHead.toBlockSlotId()[] == BlockSlotId(
        bid: dag.tail, slot: (dag.tail.slot.epoch+1).start_slot)
      dag.getBlockRef(tailBlock.root).get().bid == dag.tail
      dag.getBlockRef(blocks[^2].root).isNone()

      dag.getBlockId(tailBlock.root).get() == dag.tail
      dag.getBlockId(blocks[^2].root).isNone()

      dag.getBlockIdAtSlot(Slot(0)).isSome()  # recovered from tailState
      dag.getBlockIdAtSlot(Slot(1)).isSome()  # recovered from tailState

      # Should get EpochRef for the tail however
      # dag.getEpochRef(dag.tail, dag.tail.slot.epoch, true).isOk()
      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      # Should not get EpochRef for random block
      dag.getEpochRef(
        BlockId(root: blocks[^2].root, slot: dag.tail.slot),  # incorrect slot
        dag.tail.slot.epoch, true).isErr()

      dag.getEpochRef(dag.tail, dag.tail.slot.epoch + 1, true).isOk()

      dag.getFinalizedEpochRef() != nil

      # Checkpoint block is unavailable, and should be backfileld first
      not dag.containsBlock(dag.tail)
      dag.backfill == BeaconBlockSummary(
        slot: dag.tail.slot + 1,
        parent_root: dag.tail.root)

      # Check that we can propose right from the checkpoint state
      dag.getProposalState(dag.head, dag.head.slot + 1, cache).isOk()

    var badBlock = blocks[^1].phase0Data
    badBlock.signature = blocks[^2].phase0Data.signature
    check:
      dag.addBackfillBlock(badBlock) == AddBackRes.err VerifierError.Invalid

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data) ==
        AddBackRes.err VerifierError.MissingParent
      dag.addBackfillBlock(genBlock.phase0Data.asSigned()) ==
        AddBackRes.err VerifierError.MissingParent

      dag.addBackfillBlock(blocks[^2].phase0Data) ==
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
      dag.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()  # recovered from tailState

      dag.backfill == blocks[^2].phase0Data.message.toBeaconBlockSummary()

    check:
      dag.addBackfillBlock(blocks[^3].phase0Data).isOk()

      dag.getBlockIdAtSlot(dag.tail.slot - 2).get() ==
        blocks[^3].toBlockId().atSlot()
      dag.getBlockIdAtSlot(dag.tail.slot - 3).get() ==
        blocks[^4].toBlockId().atSlot()  # recovered from tailState

    for i in 3..<blocks.len:
      check: dag.addBackfillBlock(blocks[blocks.len - i - 1].phase0Data).isOk()

    check:
      dag.addBackfillBlock(genBlock.phase0Data.asSigned).isOk()

      dag.backfill.slot == GENESIS_SLOT

    check:
      dag.getFinalizedEpochRef() != nil

  test "Checkpoint with missed epoch start slot":
    var
      cache: StateCache
      info: ForkedEpochInfo
    while tailState[].slot.uint64 + 1 < SLOTS_PER_EPOCH:
      discard addTestBlock(tailState[], cache)

    # The epoch start slot is missed, state checkpoint not stored at block slot
    check cfg.process_slots(
      tailState[], Slot(SLOTS_PER_EPOCH), cache, info, {}).isOk()

    ChainDAGRef.preInit(db, tailState[])

    let
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
    var verifier = BatchVerifier.init(rng, taskpool)

    # Create two heads on top of the checkpoint
    let
      forkState = assignClone(tailState[])
      b1 = addTestBlock(tailState[], cache).phase0Data
    block:
      let added = dag.addHeadBlock(verifier, b1, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine[], [])
    var cache2: StateCache
    let bFork = addTestBlock(
      forkState[], cache2, graffiti = "fork".graffiti).phase0Data
    block:
      let added = dag.addHeadBlock(verifier, bFork, nilPhase0Callback)
      check: added.isOk()
    check dag.heads.len == 2

    # Reload: `bFork` builds on the tail, whose state is not stored at its own
    # slot - the head must be reconstructed, not dropped
    let
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})
    check:
      dag2.head.root == b1.root
      dag2.heads.mapIt(it.bid).toHashSet == dag.heads.mapIt(it.bid).toHashSet
      dag2.forkBlocksMatchHeads()

suite "Latest valid hash" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = 1.Epoch
        res.BELLATRIX_FORK_EPOCH = 2.Epoch
        res
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
    var verifier = BatchVerifier.init(rng, taskpool)
    let quarantine = newClone(Quarantine.init(dag.cfg))
    var
      cache: StateCache
      info: ForkedEpochInfo
    let state = newClone(dag.headState)

  test "LVH searching":
    # Reach Bellatrix, where execution payloads exist
    check cfg.process_slots(
      state[], state[].slot + (3 * SLOTS_PER_EPOCH),
      cache, info, {}).isOk()

    let
      b1 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      b1Add = dag.addHeadBlock(verifier, b1, nilBellatrixCallback)
      b2 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      b2Add = dag.addHeadBlock(verifier, b2, nilBellatrixCallback)
      b3 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
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
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      tmpState = assignClone(dag.headState)

    let taskpool = Taskpool.new()
    var
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init(dag.cfg)
      cache: StateCache
      blocks = @[dag.head]

    for i in 0 ..< (SLOTS_PER_EPOCH * (EPOCHS_PER_STATE_SNAPSHOT + cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS)):
      let blck = addTestBlock(
        tmpState[], cache,
        attestations = makeFullAttestations(
          tmpState[], dag.head.root, tmpState[].slot, cache, {})).phase0Data
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
          tmpState[], dag.head.root, tmpState[].slot, cache, {})).phase0Data
      let added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check: added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

    dag.pruneHistory()

    check:
      dag.tail.slot == Epoch(EPOCHS_PER_STATE_SNAPSHOT).start_slot - 1
      not db.containsBlock(blocks[1].root)

suite "State history":
  test "getBlockIdAtSlot":
    const numValidators = SLOTS_PER_EPOCH
    let
      cfg = defaultRuntimeConfig
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = ChainDAGRef.init(
        cfg, cfg.makeTestDB(numValidators),
        validatorMonitor, {})
      quarantine = newClone(Quarantine.init(dag.cfg))
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()
    var verifier = BatchVerifier.init(rng, taskpool)

    var
      cache: StateCache
      info: ForkedEpochInfo
      res: Result[void, cstring]
    template state: untyped = dag.headState.phase0Data

    let gen = get_initial_beacon_block(dag.headState).toBlockId()
    check:
      state.getBlockIdAtSlot(0.Slot) ==
        Opt.some BlockSlotId.init(gen, 0.Slot)
      state.getBlockIdAtSlot(1.Slot).isNone

    # Miss 5 slots
    res = process_slots(cfg, dag.headState, 5.Slot, cache, info, flags = {})
    check res.isOk
    for i in 0.Slot .. 5.Slot:
      check state.getBlockIdAtSlot(i) == Opt.some BlockSlotId.init(gen, i)
    check state.getBlockIdAtSlot(6.Slot).isNone

    # Fill 5 slots
    var bids: seq[BlockId]
    for i in 0 ..< 5:
      let blck = dag.headState.addTestBlock(cache, cfg = cfg)
      bids.add blck.toBlockId()
      let added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
      check added.isOk()
      dag.updateHead(added[], quarantine[], [])
    for i in 0.Slot .. 5.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(gen, i)
    for i in 6.Slot .. 10.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(bids[(i - 6).int], i)
    check state.getBlockIdAtSlot(11.Slot).isNone

    # Jump to SLOTS_PER_HISTORICAL_ROOT
    let periodSlot = SLOTS_PER_HISTORICAL_ROOT.Slot
    res = process_slots(cfg, dag.headState, periodSlot, cache, info, flags = {})
    for i in 0.Slot .. 5.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(gen, i)
    for i in 6.Slot .. 10.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(bids[(i - 6).int], i)
    check:
      state.getBlockIdAtSlot(11.Slot) ==
        Opt.some BlockSlotId.init(bids[^1], 11.Slot)
      state.getBlockIdAtSlot(periodSlot) ==
        Opt.some BlockSlotId.init(bids[^1], periodSlot)
      state.getBlockIdAtSlot(periodSlot + 1).isNone

    # Create a block at periodSlot + 1
    let
      blck = dag.headState.addTestBlock(cache, cfg = cfg)
      added = dag.addHeadBlock(verifier, blck.phase0Data, nilPhase0Callback)
    check added.isOk()
    dag.updateHead(added[], quarantine[], [])
    for i in 0.Slot .. 5.Slot:
      check state.getBlockIdAtSlot(i).isNone
    for i in 6.Slot .. 10.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(bids[(i - 6).int], i)
    check:
      state.getBlockIdAtSlot(11.Slot) ==
        Opt.some BlockSlotId.init(bids[^1], 11.Slot)
      state.getBlockIdAtSlot(periodSlot) ==
        Opt.some BlockSlotId.init(bids[^1], periodSlot)
      state.getBlockIdAtSlot(periodSlot + 1) ==
        Opt.some BlockSlotId.init(blck.toBlockId(), periodSlot + 1)
      state.getBlockIdAtSlot(periodSlot + 2).isNone

    # Go to periodSlot + 5
    let plusFive = periodSlot + 5
    res = process_slots(cfg, dag.headState, plusFive, cache, info, flags = {})
    for i in 0.Slot .. 5.Slot:
      check state.getBlockIdAtSlot(i).isNone
    for i in 6.Slot .. 10.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(bids[(i - 6).int], i)
    check:
      state.getBlockIdAtSlot(11.Slot) ==
        Opt.some BlockSlotId.init(bids[^1], 11.Slot)
      state.getBlockIdAtSlot(periodSlot) ==
        Opt.some BlockSlotId.init(bids[^1], periodSlot)
    for i in periodSlot + 1 .. plusFive:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(blck.toBlockId(), i)
    check state.getBlockIdAtSlot(plusFive + 1).isNone

    # Go to periodSlot + 6
    let plusSix = periodSlot + 6
    res = process_slots(cfg, dag.headState, plusSix, cache, info, flags = {})
    for i in 0.Slot .. 6.Slot:
      check state.getBlockIdAtSlot(i).isNone
    for i in 7.Slot .. 10.Slot:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(bids[(i - 6).int], i)
    check:
      state.getBlockIdAtSlot(11.Slot) ==
        Opt.some BlockSlotId.init(bids[^1], 11.Slot)
      state.getBlockIdAtSlot(periodSlot) ==
        Opt.some BlockSlotId.init(bids[^1], periodSlot)
    for i in periodSlot + 1 .. plusSix:
      check state.getBlockIdAtSlot(i) ==
        Opt.some BlockSlotId.init(blck.toBlockId(), i)
    check state.getBlockIdAtSlot(plusSix + 1).isNone

suite "Ancestry":
  test "ancestorSlot":
    const numValidators = SLOTS_PER_EPOCH
    let
      cfg = defaultRuntimeConfig
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = ChainDAGRef.init(
        cfg, cfg.makeTestDB(numValidators),
        validatorMonitor, {})
      quarantine = newClone(Quarantine.init(dag.cfg))
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
    deposits.add Deposit(
      data: makeDepositData(depositIndex.int, version = cfg.GENESIS_FORK_VERSION)
    )
  let
    eth1Data = Eth1Data(
      deposit_root: deposits.attachMerkleProofs(),
      deposit_count: deposits.lenu64)
    validatorMonitor = newClone(ValidatorMonitor.init(cfg))
    dag = ChainDAGRef.init(
      cfg, cfg.makeTestDB(
        numValidators, eth1Data = Opt.some(eth1Data)),
      validatorMonitor, {})
    quarantine = newClone(Quarantine.init(dag.cfg))
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
        const nilCallback = OnBlockAdded[consensusFork](nil)
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
        dag.headState.slot + delaySlots,
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
        (findKeyedBlck(2.Epoch.start_slot), 10.Epoch),
        (findKeyedBlck(8.Epoch.start_slot - 1), 8.Epoch)]:
      let
        blck = forkBlocks[blockIdx].data
        epochRef = dag.getEpochRef(blck, epoch, true)
      doAssert epochRef.isOk

      # If shuffling is computable from DAG, check its correctness
      epochRef.checkShuffling dag.computeShufflingRefFromMemory(blck, epoch)

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

suite "Fast confirmation" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = defaultRuntimeConfig
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      tmpState = newClone(dag.headState)
    var
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init(dag.cfg)
      cache: StateCache

    for i in 0 ..< (SLOTS_PER_EPOCH * 4):
      let
        blck = addTestBlock(tmpState[], cache).phase0Data
        added = dag.addHeadBlock(verifier, blck, nilPhase0Callback)
      check added.isOk()
      dag.updateHead(added[], quarantine, [])
      dag.pruneAtFinalization()

  test "Update shufflings for current and previous epoch" & preset():
    let
      epoch = dag.head.slot.epoch
      epochRef = dag.getEpochRef(dag.head, epoch, false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source
    check:
      balance_source.update_latest_shufflings(dag, dag.head.slot).isOk
      balance_source.shuffling_epochs[(epoch - 0).shuffling_index] == epoch - 0
      balance_source.shuffling_epochs[(epoch - 1).shuffling_index] == epoch - 1
      balance_source.shuffling_epochs[(epoch - 2).shuffling_index] == epoch - 2

  test "Shuffling dependent roots" & preset():
    let epochRef = dag.getEpochRef(dag.head, dag.head.slot.epoch, false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source
    check balance_source.update_latest_shufflings(dag, dag.head.slot).isOk
    for i in 0 ..< NumAttesterDuties:
      let shufflingRef = dag.getShufflingRef(
        dag.head, balance_source.shuffling_epochs[i], false).get
      check balance_source.shuffling_roots[i] ==
        shufflingRef.attester_dependent_root

  test "Assigned slots cross-check" & preset():
    let epochRef = dag.getEpochRef(dag.head, dag.head.slot.epoch, false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source
    check balance_source.update_latest_shufflings(dag, dag.head.slot).isOk

    let
      epoch = dag.head.slot.epoch
      prevPrevShuffling = dag.getShufflingRef(dag.head, epoch - 2, false).get
      prevShuffling = dag.getShufflingRef(dag.head, epoch - 1, false).get
      curShuffling = dag.getShufflingRef(dag.head, epoch, false).get

    for valIdx in 0 ..< balance_source.balances.len:
      let slots = toSeq(balance_source.assigned_slots(valIdx.ValidatorIndex))
      check:
        slots.len == 3
        slots[0].epoch != slots[1].epoch
        slots[0].epoch != slots[2].epoch
        slots[1].epoch != slots[2].epoch
      for slot in slots:
        let shuffling =
          if slot.epoch == prevPrevShuffling.epoch:
            prevPrevShuffling
          elif slot.epoch == prevShuffling.epoch:
            prevShuffling
          else:
            curShuffling
        var found = false
        for committee_index in get_committee_indices(shuffling):
          for _, val in shuffling.get_beacon_committee(slot, committee_index):
            if val == valIdx.ValidatorIndex:
              found = true
        check found

  test "Shuffling update idempotency" & preset():
    let epochRef = dag.getEpochRef(dag.head, dag.head.slot.epoch, false).get
    var
      balance_source1 = epochRef.to_balance_checkpoint(dag.head).balance_source
      balance_source2 = epochRef.to_balance_checkpoint(dag.head).balance_source
    check:
      balance_source1.update_latest_shufflings(dag, dag.head.slot).isOk
      balance_source2.update_latest_shufflings(dag, dag.head.slot).isOk
      balance_source1.update_latest_shufflings(dag, dag.head.slot).isOk
    let num_validators = balance_source1.balances.len
    check num_validators == balance_source2.balances.len
    for valIdx in 0 ..< num_validators:
      check:
        toSeq(balance_source1.assigned_slots(valIdx.ValidatorIndex)) ==
        toSeq(balance_source2.assigned_slots(valIdx.ValidatorIndex))

  test "Shuffling epoch transition" & preset():
    let epochRef = dag.getEpochRef(dag.head, dag.head.slot.epoch, false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source

    # First update to epoch 3 (populates epochs 1, 2 and 3)
    let epoch3Slot = (SLOTS_PER_EPOCH * 3).Slot
    check:
      balance_source.update_latest_shufflings(dag, epoch3Slot).isOk
      balance_source.shuffling_epochs[Epoch(1).shuffling_index] == Epoch(1)
      balance_source.shuffling_epochs[Epoch(2).shuffling_index] == Epoch(2)
      balance_source.shuffling_epochs[Epoch(3).shuffling_index] == Epoch(3)

    # Now update to latest (epoch 4), populates epochs 2, 3 and 4
    check:
      balance_source.update_latest_shufflings(dag, dag.head.slot).isOk
      balance_source.shuffling_epochs[Epoch(2).shuffling_index] == Epoch(2)
      balance_source.shuffling_epochs[Epoch(3).shuffling_index] == Epoch(3)
      balance_source.shuffling_epochs[Epoch(4).shuffling_index] == Epoch(4)

    # Verify assigned_slots yields slots for epochs 2, 3 and 4
    for valIdx in 0 ..< balance_source.balances.len:
      let slots = toSeq(balance_source.assigned_slots(valIdx.ValidatorIndex))
      check slots.len == 3
      for slot in slots:
        check slot.epoch in [Epoch(2), Epoch(3), Epoch(4)]

  test "Assign shufflings" & preset():
    let epochRef = dag.getEpochRef(dag.head, dag.head.slot.epoch, false).get
    var
      src = epochRef.to_balance_checkpoint(dag.head).balance_source
      dst: BalanceSource
    check src.update_latest_shufflings(dag, dag.head.slot).isOk
    dst.assign_shufflings(src)
    for valIdx in 0 ..< src.balances.len:
      check:
        toSeq(src.assigned_slots(valIdx.ValidatorIndex)) ==
        toSeq(dst.assigned_slots(valIdx.ValidatorIndex))

  test "Shuffling preserves effective balance" & preset():
    let epochRef = dag.getEpochRef(dag.head, dag.head.slot.epoch, false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source
    let knownBalance = balance_source.balances[0].effective_balance
    check:
      balance_source.update_latest_shufflings(dag, dag.head.slot).isOk
      balance_source.balances[0].effective_balance == knownBalance

  test "Older epochRef with current shufflings" & preset():
    let
      epoch = dag.head.slot.epoch
      epochRef = dag.getEpochRef(dag.head, epoch, false).get
      oldEpochRef = dag.getEpochRef(
        dag.finalizedHead.blck, dag.finalizedHead.slot.epoch, false).get
    var
      balance_source =
        epochRef.to_balance_checkpoint(dag.head).balance_source
      old_balance_source =
        oldEpochRef.to_balance_checkpoint(dag.finalizedHead.blck).balance_source
    check:
      balance_source.update_latest_shufflings(dag, dag.head.slot).isOk
      old_balance_source.update_latest_shufflings(dag, dag.head.slot).isOk
      balance_source.shuffling_epochs[(epoch - 0).shuffling_index] == epoch - 0
      balance_source.shuffling_epochs[(epoch - 1).shuffling_index] == epoch - 1
      balance_source.shuffling_epochs[(epoch - 2).shuffling_index] == epoch - 2
      balance_source.shuffling_epochs == old_balance_source.shuffling_epochs
      balance_source.shuffling_roots == old_balance_source.shuffling_roots

    let num_validators = min(
      balance_source.balances.len, old_balance_source.balances.len)
    for valIdx in 0 ..< num_validators:
      check:
        toSeq(balance_source.assigned_slots(valIdx.ValidatorIndex)) ==
        toSeq(old_balance_source.assigned_slots(valIdx.ValidatorIndex))

  test "Genesis epoch" & preset():
    let epochRef = dag.getEpochRef(dag.head, GENESIS_EPOCH, false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source
    check:
      balance_source.update_latest_shufflings(dag, GENESIS_SLOT).isOk
      balance_source.shuffling_epochs[0] == GENESIS_EPOCH
      balance_source.shuffling_epochs[1] == FAR_FUTURE_EPOCH
      balance_source.shuffling_epochs[2] == FAR_FUTURE_EPOCH
    for valIdx in 0 ..< balance_source.balances.len:
      let slots = toSeq(balance_source.assigned_slots(valIdx.ValidatorIndex))
      check:
        slots.len == 1
        slots[0].epoch == GENESIS_EPOCH

  test "Epoch 1 shares dependent root for both epochs" & preset():
    let epochRef = dag.getEpochRef(dag.head, Epoch(1), false).get
    var balance_source = epochRef.to_balance_checkpoint(dag.head).balance_source
    check:
      balance_source.update_latest_shufflings(dag, SLOTS_PER_EPOCH.Slot).isOk
      balance_source.shuffling_epochs[0] == GENESIS_EPOCH
      balance_source.shuffling_epochs[1] == Epoch(1)
      balance_source.shuffling_epochs[2] == FAR_FUTURE_EPOCH
      balance_source.shuffling_roots[0] == balance_source.shuffling_roots[1]
    for valIdx in 0 ..< balance_source.balances.len:
      let slots = toSeq(balance_source.assigned_slots(valIdx.ValidatorIndex))
      check slots.len == 2

suite "Gloas block validity":
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var cfg = defaultRuntimeConfig
        cfg.ALTAIR_FORK_EPOCH = Epoch(0)
        cfg.BELLATRIX_FORK_EPOCH = Epoch(0)
        cfg.CAPELLA_FORK_EPOCH = Epoch(0)
        cfg.DENEB_FORK_EPOCH = Epoch(0)
        cfg.ELECTRA_FORK_EPOCH = Epoch(0)
        cfg.FULU_FORK_EPOCH = Epoch(0)
        cfg.GLOAS_FORK_EPOCH = Epoch(1)
        cfg
    var
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = Quarantine.init(dag.cfg)
      cache: StateCache
      info = ForkedEpochInfo()

  test "Execution valid":
    let state = assignClone(dag.clearanceState)
    const
      slotCount = 8
      currentFork = ConsensusFork.Gloas

    process_slots(
      cfg, state[], cfg.GLOAS_FORK_EPOCH.start_slot,
      cache, info, {}).expect("gloas fork")

    # Slot 0 - 7, build on FULL Payload
    for i in 0 ..< slotCount:
      process_slots(
        cfg, state[], state[].slot + 1,
        cache, info, {}).expect("next slot")

      let
        b = addTestEngineBlock(
          cfg, currentFork, state[].gloasData, cache)
        bRef = block:
          let res = dag.addHeadBlockWithParent(
            verifier, b.blck, dag.head,
            OptimisticStatus.notValidated, nilGloasCallback)
          check res.isOk()
          dag.updateHead(res.get(), quarantine, @[])
          res.get()
      # Mock that it is execution valid
      bRef.markExecutionValid(true)

      check:
        Opt.some(bRef.parent) == bRef.executionParent
        Opt.some(bRef.parent) == dag.executionParent(
          bRef.parent,
          b.envelope.message.payload.parent_hash)
        bRef.executionValid
      if i == 0:
        check bRef.parent.slot == GENESIS_SLOT

    # Slot 8 - 15, build on EMPTY Payload
    let payloadParent = dag.head.parent
    for i in 0 ..< slotCount:
      assign(state[], dag.headState)
      process_slots(
        cfg, state[], state[].slot + 1,
        cache, info, {}).expect("next slot")

      let
        b = addTestEngineBlock(
          cfg, currentFork, state[].gloasData, cache,
          should_extend_payload = false)
        bRef = block:
          let res = dag.addHeadBlockWithParent(
            verifier, b.blck, dag.head,
            OptimisticStatus.notValidated, nilGloasCallback)
          check res.isOk()
          dag.updateHead(res.get(), quarantine, @[])
          res.get()

      check:
        Opt.some(payloadParent) == bRef.executionParent
        Opt.some(payloadParent) == dag.executionParent(
          bRef.parent,
          b.envelope.message.payload.parent_hash)
        bRef.executionValid

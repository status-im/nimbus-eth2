# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}
{.used.}

import
  # Status libraries
  eth/keys, taskpools,
  # Beacon chain internals
  ../beacon_chain/consensus_object_pools/
    [block_clearance_light_client, block_clearance,
    block_quarantine, blockchain_dag],
  ../beacon_chain/spec/state_transition,
  # Test utilities
  ./testutil, ./testdbutil

suite "Block clearance (light client)" & preset():
  let
    cfg = block:
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH + 1
      res
    taskpool = Taskpool.new()

  proc newTestDag(): ChainDAGRef =
    const num_validators = SLOTS_PER_EPOCH
    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = ChainDAGRef.init(
        cfg, makeTestDB(num_validators), validatorMonitor, {})
    dag

  proc addBlocks(
      dag: ChainDAGRef,
      numBlocks: int,
      finalizedCheckpoints: var seq[Checkpoint],
      syncCommitteeRatio = 0.0,
      numSkippedSlots = 0.uint64) =
    let quarantine = newClone(Quarantine.init())
    var
      cache: StateCache
      verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)
    if numSkippedSlots > 0:
      var info: ForkedEpochInfo
      let slot = getStateField(dag.headState, slot) + numSkippedSlots
      process_slots(
        cfg, dag.headState, slot, cache, info, flags = {}).expect("no failure")
    for blck in makeTestBlocks(dag.headState, cache, numBlocks,
                               attested = true, syncCommitteeRatio, cfg):
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
      withState(dag.headState):
        if finalizedCheckpoints.len == 0 or
            state.data.finalized_checkpoint != finalizedCheckpoints[^1]:
          finalizedCheckpoints.add(state.data.finalized_checkpoint)

  proc checkBlocks(lcBlocks: LCBlocks, dag: ChainDAGRef, slots: Slice[Slot]) =
    for slot in slots.a .. slots.b:
      let
        latestLcBlck = lcBlocks.getLatestBlockThroughSlot(slot)
        lcBlck = lcBlocks.getBlockAtSlot(slot)
        bsi = dag.getBlockIdAtSlot(slot)
        dagBlck =
          if bsi.isOk:
            dag.getForkedBlock(bsi.get.bid)
          else:
            Opt[ForkedTrustedSignedBeaconBlock].err()
      check:
        lcBlck.isOk == dagBlck.isOk
        lcBlck.isOk == latestLcBlck.isOk
      if lcBlck.isOk:
        check:
          lcBlck.get.root == dagBlck.get.root
          lcBlck.get.root == latestLcBlck.get.root

  setup:
    let dag = newTestDag()
    var finalizedCheckpoints: seq[Checkpoint] = @[]
    dag.addBlocks(200, finalizedCheckpoints)

  test "Initial sync":
    const maxSlots = 160
    var lcBlocks = initLCBlocks(maxSlots)
    let minSlot = dag.head.slot + 1 - maxSlots
    check:
      lcBlocks.getHeadSlot() == FAR_FUTURE_SLOT
      lcBlocks.getFinalizedSlot() == GENESIS_SLOT
      lcBlocks.getFrontfillSlot() == GENESIS_SLOT
      lcBlocks.getBackfillSlot() == GENESIS_SLOT
    lcBlocks.setHeadBid(dag.head.bid)
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == GENESIS_SLOT
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    var bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check:
        res.isOk
        lcBlocks.getHeadSlot() == dag.head.slot
        lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
        lcBlocks.getFrontfillSlot() == minSlot
        lcBlocks.getBackfillSlot() == max(bdata.slot, minSlot)
      bid = dag.parent(bid).valueOr:
        break
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == minSlot
    lcBlocks.checkBlocks(dag, minSlot .. dag.head.slot)

  test "Delayed finality update":
    const maxSlots = 160
    var lcBlocks = initLCBlocks(maxSlots)
    let minSlot = dag.head.slot + 1 - maxSlots
    lcBlocks.setHeadBid(dag.head.bid)
    var bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break

    for finalizedCheckpoint in finalizedCheckpoints:
      let bsi = dag.getBlockIdAtSlot(finalizedCheckpoint.epoch.start_slot)
      check bsi.isOk
      lcBlocks.setFinalizedBid(bsi.get.bid)

    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == minSlot
    lcBlocks.checkBlocks(dag, minSlot .. dag.head.slot)

  test "Incremental sync":
    const maxSlots = 160
    var lcBlocks = initLCBlocks(maxSlots)
    let
      oldHeadSlot = dag.head.slot
      oldMinSlot = dag.head.slot + 1 - maxSlots
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    var bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break

    dag.addBlocks(20, finalizedCheckpoints)
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    let newMinSlot = dag.head.slot + 1 - maxSlots
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == newMinSlot
      lcBlocks.getBackfillSlot() == dag.head.slot + 1

    bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break

    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == newMinSlot
      lcBlocks.getBackfillSlot() == newMinSlot
    lcBlocks.checkBlocks(dag, newMinSlot .. dag.head.slot)

    dag.addBlocks(200, finalizedCheckpoints)
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    let minSlot = dag.head.slot + 1 - maxSlots
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == dag.head.slot + 1

    bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break

    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == minSlot
    lcBlocks.checkBlocks(dag, minSlot .. dag.head.slot)

  test "Reverse incremental sync":
    const maxSlots = 160
    var lcBlocks = initLCBlocks(maxSlots)
    let
      newHeadBid = dag.head.bid
      newFinalizedBid = dag.finalizedHead.blck.bid

    dag.addBlocks(20, finalizedCheckpoints)
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    let oldMinSlot = dag.head.slot + 1 - maxSlots

    var bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break

    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == oldMinSlot
      lcBlocks.getBackfillSlot() == oldMinSlot
    lcBlocks.checkBlocks(dag, oldMinSlot .. dag.head.slot)

    lcBlocks.setHeadBid(newHeadBid)
    lcBlocks.setFinalizedBid(newFinalizedBid)
    let newMinSlot = newHeadBid.slot + 1 - maxSlots
    check:
      lcBlocks.getHeadSlot() == newHeadBid.slot
      lcBlocks.getFinalizedSlot() == newFinalizedBid.slot
      lcBlocks.getFrontfillSlot() == newMinSlot
      lcBlocks.getBackfillSlot() == oldMinSlot

    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break

    check:
      lcBlocks.getHeadSlot() == newHeadBid.slot
      lcBlocks.getFinalizedSlot() == newFinalizedBid.slot
      lcBlocks.getFrontfillSlot() == newMinSlot
      lcBlocks.getBackfillSlot() == newMinSlot
    lcBlocks.checkBlocks(dag, newMinSlot .. newHeadBid.slot)

  test "Reorg":
    const maxSlots = 160
    var lcBlocks = initLCBlocks(maxSlots)
    let minSlot = dag.head.slot + 1 - maxSlots
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    var bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == minSlot
    lcBlocks.checkBlocks(dag, minSlot .. dag.head.slot)

    let dag2 = newTestDag()
    var finalizedCheckpoints2: seq[Checkpoint] = @[]
    dag2.addBlocks(200, finalizedCheckpoints2, syncCommitteeRatio = 0.1)
    lcBlocks.setHeadBid(dag2.head.bid)
    lcBlocks.setFinalizedBid(dag2.finalizedHead.blck.bid)
    check:
      lcBlocks.getHeadSlot() == dag2.head.slot
      lcBlocks.getFinalizedSlot() == dag2.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == dag2.head.slot + 1
    bid = dag2.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag2.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag2.parent(bid).valueOr:
        break
    check:
      lcBlocks.getHeadSlot() == dag2.head.slot
      lcBlocks.getFinalizedSlot() == dag2.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == minSlot
    lcBlocks.checkBlocks(dag2, minSlot .. dag2.head.slot)

    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    check:
      lcBlocks.getHeadSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() ==
        max(dag.finalizedHead.slot, maxSlots.Slot) + 1 - maxSlots
      lcBlocks.getBackfillSlot() == dag.finalizedHead.blck.slot + 1
    bid = dag.finalizedHead.blck.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break
    lcBlocks.setHeadBid(dag.head.bid)
    bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == minSlot
      lcBlocks.getBackfillSlot() == minSlot
    lcBlocks.checkBlocks(dag, minSlot .. dag.head.slot)

  test "Low slot numbers":
    const maxSlots = 320 # DAG slot numbers are smaller than `maxSlots`
    var lcBlocks = initLCBlocks(maxSlots)
    let
      oldHeadBid = dag.head.bid
      oldFinalizedBid = dag.finalizedHead.blck.bid
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    var bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == GENESIS_SLOT
      lcBlocks.getBackfillSlot() == GENESIS_SLOT
    lcBlocks.checkBlocks(dag, GENESIS_SLOT .. dag.head.slot)

    dag.addBlocks(20, finalizedCheckpoints)
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    bid = dag.head.bid
    while lcBlocks.getBackfillSlot() > lcBlocks.getFrontfillSlot():
      let
        bdata = dag.getForkedBlock(bid).valueOr:
          break
        res = lcBlocks.addBlock(bdata.asSigned())
      check res.isOk
      bid = dag.parent(bid).valueOr:
        break
    check:
      lcBlocks.getHeadSlot() == dag.head.slot
      lcBlocks.getFinalizedSlot() == dag.finalizedHead.blck.slot
      lcBlocks.getFrontfillSlot() == GENESIS_SLOT
      lcBlocks.getBackfillSlot() == GENESIS_SLOT

    lcBlocks.setHeadBid(oldHeadBid)
    lcBlocks.setFinalizedBid(oldFinalizedBid)
    check:
      lcBlocks.getHeadSlot() == oldHeadBid.slot
      lcBlocks.getFinalizedSlot() == oldFinalizedBid.slot
      lcBlocks.getFrontfillSlot() == GENESIS_SLOT
      lcBlocks.getBackfillSlot() == GENESIS_SLOT

  test "Error conditions":
    let dag2 = newTestDag()
    var finalizedCheckpoints2: seq[Checkpoint] = @[]
    dag2.addBlocks(200, finalizedCheckpoints2, syncCommitteeRatio = 0.1)

    const maxSlots = 2
    var lcBlocks = initLCBlocks(maxSlots)
    check:
      lcBlocks.getBlockAtSlot(GENESIS_SLOT).isErr
      lcBlocks.getBlockAtSlot(FAR_FUTURE_SLOT).isErr
      lcBlocks.getLatestBlockThroughSlot(GENESIS_SLOT).isErr
      lcBlocks.getLatestBlockThroughSlot(FAR_FUTURE_SLOT).isErr
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    check:
      lcBlocks.getBlockAtSlot(GENESIS_SLOT).isErr
      lcBlocks.getBlockAtSlot(FAR_FUTURE_SLOT).isErr
      lcBlocks.getBlockAtSlot(dag.head.slot).isErr
      lcBlocks.getBlockAtSlot(dag.finalizedHead.blck.slot).isErr
      lcBlocks.getLatestBlockThroughSlot(GENESIS_SLOT).isErr
      lcBlocks.getLatestBlockThroughSlot(FAR_FUTURE_SLOT).isErr
      lcBlocks.getLatestBlockThroughSlot(dag.head.slot).isErr
      lcBlocks.getLatestBlockThroughSlot(dag.finalizedHead.blck.slot).isErr
    let
      parentBid = dag.parent(dag.head.bid).expect("Parent exists")
      parentBdata = dag.getForkedBlock(parentBid).expect("Parent block exists")
    var res = lcBlocks.addBlock(parentBdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.MissingParent
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    let bdata2 = dag2.getForkedBlock(dag2.head.bid).expect("DAG 2 block exists")
    res = lcBlocks.addBlock(bdata2.asSigned())
    check:
      res.isErr
      res.error == BlockError.UnviableFork
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    let bdata = dag.getForkedBlock(dag.head.bid).expect("DAG block exists")
    res = lcBlocks.addBlock(bdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag.head.slot
    res = lcBlocks.addBlock(bdata2.asSigned())
    check:
      res.isErr
      res.error == BlockError.UnviableFork
      lcBlocks.getBackfillSlot() == dag.head.slot
    res = lcBlocks.addBlock(bdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.Duplicate
      lcBlocks.getBackfillSlot() == dag.head.slot
    let
      onePastBid = dag.parent(parentBid).expect("Parent of parent exists")
      onePastBdata = dag.getForkedBlock(onePastBid).expect("Block exists")
    res = lcBlocks.addBlock(onePastBdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.MissingParent
      lcBlocks.getBackfillSlot() == dag.head.slot
    res = lcBlocks.addBlock(parentBdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == parentBdata.slot
      lcBlocks.getBlockAtSlot(parentBdata.slot).isOk
      lcBlocks.getLatestBlockThroughSlot(parentBdata.slot).isOk
    res = lcBlocks.addBlock(onePastBdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag.head.slot + 1 - maxSlots
      lcBlocks.getBlockAtSlot(onePastBdata.slot).isErr
      lcBlocks.getLatestBlockThroughSlot(onePastBdata.slot).isErr
    res = lcBlocks.addBlock(onePastBdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.Duplicate
      lcBlocks.getBackfillSlot() == dag.head.slot + 1 - maxSlots

    let oldHeadBid = dag.head.bid
    dag.addBlocks(1, finalizedCheckpoints, numSkippedSlots = 3)   # ---X
    dag2.addBlocks(2, finalizedCheckpoints2, numSkippedSlots = 2) # --XX
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)

    let newBdata = dag.getForkedBlock(dag.head.bid).expect("New block ok")
    res = lcBlocks.addBlock(newBdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag.head.slot
    res = lcBlocks.addBlock(bdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag.head.slot + 1 - maxSlots
      lcBlocks.getBlockAtSlot(dag.head.slot).isOk
      lcBlocks.getBlockAtSlot(dag.head.slot - 1).isErr
      lcBlocks.getBlockAtSlot(dag.head.slot - 2).isErr
    let
      newParentBid2 = dag2.parent(dag2.head.bid).expect("New parent 2 exists")
      newParentBdata2 = dag2.getForkedBlock(newParentBid2).expect("Parent 2 ok")
    res = lcBlocks.addBlock(newParentBdata2.asSigned())
    check:
      res.isErr
      res.error == BlockError.UnviableFork
      lcBlocks.getBackfillSlot() == dag.head.slot + 1 - maxSlots

    lcBlocks.setHeadBid(dag2.head.bid)
    lcBlocks.setFinalizedBid(newParentBid2)
    let newBdata2 = dag2.getForkedBlock(dag2.head.bid).expect("New block 2 ok")
    res = lcBlocks.addBlock(newBdata2.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag2.head.slot
    res = lcBlocks.addBlock(newParentBdata2.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag2.head.slot + 1 - maxSlots

    lcBlocks.setHeadBid(dag.head.bid)
    res = lcBlocks.addBlock(newBdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag.head.slot
    res = lcBlocks.addBlock(bdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.UnviableFork
      lcBlocks.getHeadSlot() == newParentBid2.slot
      lcBlocks.getFinalizedSlot() == newParentBid2.slot
      lcBlocks.getFrontfillSlot() == newParentBid2.slot + 1 - maxSlots
      lcBlocks.getBackfillSlot() == newParentBid2.slot + 1
    res = lcBlocks.addBlock(newParentBdata2.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == newParentBid2.slot
    res = lcBlocks.addBlock(bdata2.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == newParentBid2.slot + 1 - maxSlots

    lcBlocks.setHeadBid(dag2.head.bid)
    lcBlocks.setFinalizedBid(oldHeadBid)
    res = lcBlocks.addBlock(newBdata2.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag2.head.slot
    res = lcBlocks.addBlock(newParentBdata2.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == newParentBid2.slot
    res = lcBlocks.addBlock(bdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.MissingParent
      lcBlocks.getBackfillSlot() == newParentBid2.slot

    lcBlocks = initLCBlocks(maxSlots = 0)
    lcBlocks.setHeadBid(dag.head.bid)
    lcBlocks.setFinalizedBid(dag.finalizedHead.blck.bid)
    res = lcBlocks.addBlock(newBdata2.asSigned())
    check:
      res.isErr
      res.error == BlockError.UnviableFork
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    res = lcBlocks.addBlock(newBdata.asSigned())
    check:
      res.isOk
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    res = lcBlocks.addBlock(newBdata2.asSigned())
    check:
      res.isErr
      res.error == BlockError.UnviableFork
      lcBlocks.getBackfillSlot() == dag.head.slot + 1
    res = lcBlocks.addBlock(newBdata.asSigned())
    check:
      res.isErr
      res.error == BlockError.Duplicate
      lcBlocks.getBackfillSlot() == dag.head.slot + 1

# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, sequtils, unittest,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[datatypes, digest, helpers, state_transition, presets],
  ../beacon_chain/[beacon_node_types, ssz],
  ../beacon_chain/block_pools/[chain_dag, quarantine, clearance]

when isMainModule:
  import chronicles # or some random compile error happens...

suiteReport "BlockRef and helpers" & preset():
  timedTest "isAncestorOf sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s1 = BlockRef(slot: Slot(1), parent: s0)
      s2 = BlockRef(slot: Slot(2), parent: s1)

    check:
      s0.isAncestorOf(s0)
      s0.isAncestorOf(s1)
      s0.isAncestorOf(s2)
      s1.isAncestorOf(s1)
      s1.isAncestorOf(s2)

      not s2.isAncestorOf(s0)
      not s2.isAncestorOf(s1)
      not s1.isAncestorOf(s0)

  timedTest "get_ancestor sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s1 = BlockRef(slot: Slot(1), parent: s0)
      s2 = BlockRef(slot: Slot(2), parent: s1)
      s4 = BlockRef(slot: Slot(4), parent: s2)

    check:
      s0.get_ancestor(Slot(0)) == s0
      s0.get_ancestor(Slot(1)) == s0

      s1.get_ancestor(Slot(0)) == s0
      s1.get_ancestor(Slot(1)) == s1

      s4.get_ancestor(Slot(0)) == s0
      s4.get_ancestor(Slot(1)) == s1
      s4.get_ancestor(Slot(2)) == s2
      s4.get_ancestor(Slot(3)) == s2
      s4.get_ancestor(Slot(4)) == s4

  timedTest "epochAncestor sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
    var cur = s0
    for i in 1..SLOTS_PER_EPOCH * 2:
      cur = BlockRef(slot: Slot(i), parent: cur)

    let ancestor = cur.epochAncestor(cur.slot.epoch)

    check:
      ancestor.slot.epoch == cur.slot.epoch
      ancestor.blck != cur # should have selected a parent

      ancestor.blck.epochAncestor(cur.slot.epoch) == ancestor
      ancestor.blck.epochAncestor(ancestor.blck.slot.epoch) != ancestor

suiteReport "BlockSlot and helpers" & preset():
  timedTest "atSlot sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s1 = BlockRef(slot: Slot(1), parent: s0)
      s2 = BlockRef(slot: Slot(2), parent: s1)
      s4 = BlockRef(slot: Slot(4), parent: s2)

    check:
      s0.atSlot(Slot(0)).blck == s0
      s0.atSlot(Slot(0)) == s1.atSlot(Slot(0))
      s1.atSlot(Slot(1)).blck == s1

      s4.atSlot(Slot(0)).blck == s0

  timedTest "parent sanity" & preset():
    let
      s0 = BlockRef(slot: Slot(0))
      s00 = BlockSlot(blck: s0, slot: Slot(0))
      s01 = BlockSlot(blck: s0, slot: Slot(1))
      s2 = BlockRef(slot: Slot(2), parent: s0)
      s22 = BlockSlot(blck: s2, slot: Slot(2))
      s24 = BlockSlot(blck: s2, slot: Slot(4))

    check:
      s00.parent == BlockSlot(blck: nil, slot: Slot(0))
      s01.parent == s00
      s22.parent == s01
      s24.parent == BlockSlot(blck: s2, slot: Slot(3))
      s24.parent.parent == s22

suiteReport "Block pool processing" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      dag = init(ChainDAGRef, defaultRuntimePreset, db)
      quarantine = QuarantineRef()
      stateData = newClone(dag.loadTailState())
      cache = StateCache()
      b1 = addTestBlock(stateData.data, dag.tail.root, cache)
      b1Root = hash_tree_root(b1.message)
      b2 = addTestBlock(stateData.data, b1Root, cache)
      b2Root {.used.} = hash_tree_root(b2.message)
  timedTest "getRef returns nil for missing blocks":
    check:
      dag.getRef(default Eth2Digest) == nil

  timedTest "loadTailState gets genesis block on first load" & preset():
    let
      b0 = dag.get(dag.tail.root)

    check:
      b0.isSome()

  timedTest "Simple block add&get" & preset():
    let
      b1Add = dag.addRawBlock(quarantine, b1, nil)
      b1Get = dag.get(b1.root)

    check:
      b1Get.isSome()
      b1Get.get().refs.root == b1Root
      b1Add[].root == b1Get.get().refs.root
      dag.heads.len == 1
      dag.heads[0] == b1Add[]

    let
      b2Add = dag.addRawBlock(quarantine, b2, nil)
      b2Get = dag.get(b2.root)

    check:
      b2Get.isSome()
      b2Get.get().refs.root == b2.root
      b2Add[].root == b2Get.get().refs.root
      dag.heads.len == 1
      dag.heads[0] == b2Add[]
      not b1Add[].findEpochRef(b1Add[].slot.epoch).isNil
      b1Add[].findEpochRef(b1Add[].slot.epoch) ==
        b2Add[].findEpochRef(b2Add[].slot.epoch)
      b1Add[].findEpochRef(b1Add[].slot.epoch + 1).isNil

    # Skip one slot to get a gap
    check:
      process_slots(stateData.data, stateData.data.data.slot + 1)

    let
      b4 = addTestBlock(stateData.data, b2.root, cache)
      b4Add = dag.addRawBlock(quarantine, b4, nil)

    check:
      b4Add[].parent == b2Add[]

    dag.updateHead(b4Add[])

    var blocks: array[3, BlockRef]

    check:
      dag.getBlockRange(Slot(0), 1, blocks.toOpenArray(0, 0)) == 0
      blocks[0..<1] == [dag.tail]

      dag.getBlockRange(Slot(0), 1, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [dag.tail, b1Add[]]

      dag.getBlockRange(Slot(0), 2, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [dag.tail, b2Add[]]

      dag.getBlockRange(Slot(0), 3, blocks.toOpenArray(0, 1)) == 1
      blocks[1..<2] == [dag.tail] # block 3 is missing!

      dag.getBlockRange(Slot(2), 2, blocks.toOpenArray(0, 1)) == 0
      blocks[0..<2] == [b2Add[], b4Add[]] # block 3 is missing!

      # empty length
      dag.getBlockRange(Slot(2), 2, blocks.toOpenArray(0, -1)) == 0

      # No blocks in sight
      dag.getBlockRange(Slot(5), 1, blocks.toOpenArray(0, 1)) == 2

      # No blocks in sight either due to gaps
      dag.getBlockRange(Slot(3), 2, blocks.toOpenArray(0, 1)) == 2
      blocks[2..<2].len == 0

  timedTest "Reverse order block add & get" & preset():
    let missing = dag.addRawBlock(quarantine, b2, nil)
    check: missing.error == MissingParent

    check:
      dag.get(b2.root).isNone() # Unresolved, shouldn't show up
      FetchRecord(root: b1.root) in quarantine.checkMissing()

    let status = dag.addRawBlock(quarantine, b1, nil)

    check: status.isOk

    let
      b1Get = dag.get(b1.root)
      b2Get = dag.get(b2.root)

    check:
      b1Get.isSome()
      b2Get.isSome()

      b2Get.get().refs.parent == b1Get.get().refs

    dag.updateHead(b2Get.get().refs)

    # The heads structure should have been updated to contain only the new
    # b2 head
    check:
      dag.heads.mapIt(it) == @[b2Get.get().refs]

    # check that init also reloads block graph
    var
      dag2 = init(ChainDAGRef, defaultRuntimePreset, db)

    check:
      # ensure we loaded the correct head state
      dag2.head.root == b2Root
      hash_tree_root(dag2.headState.data.data) == b2.message.state_root
      dag2.get(b1Root).isSome()
      dag2.get(b2Root).isSome()
      dag2.heads.len == 1
      dag2.heads[0].root == b2Root

  timedTest "Adding the same block twice returns a Duplicate error" & preset():
    let
      b10 = dag.addRawBlock(quarantine, b1, nil)
      b11 = dag.addRawBlock(quarantine, b1, nil)

    check:
      b11.error == Duplicate
      not b10[].isNil

  timedTest "updateHead updates head and headState" & preset():
    let
      b1Add = dag.addRawBlock(quarantine, b1, nil)

    dag.updateHead(b1Add[])

    check:
      dag.head == b1Add[]
      dag.headState.data.data.slot == b1Add[].slot

  timedTest "updateStateData sanity" & preset():
    let
      b1Add = dag.addRawBlock(quarantine, b1, nil)
      b2Add = dag.addRawBlock(quarantine, b2, nil)
      bs1 = BlockSlot(blck: b1Add[], slot: b1.message.slot)
      bs1_3 = b1Add[].atSlot(3.Slot)
      bs2_3 = b2Add[].atSlot(3.Slot)

    var tmpState = assignClone(dag.headState)

    # move to specific block
    var cache = StateCache()
    dag.updateStateData(tmpState[], bs1, cache)

    check:
      tmpState.blck == b1Add[]
      tmpState.data.data.slot == bs1.slot

    # Skip slots
    dag.updateStateData(tmpState[], bs1_3, cache) # skip slots

    check:
      tmpState.blck == b1Add[]
      tmpState.data.data.slot == bs1_3.slot

    # Move back slots, but not blocks
    dag.updateStateData(tmpState[], bs1_3.parent(), cache)
    check:
      tmpState.blck == b1Add[]
      tmpState.data.data.slot == bs1_3.parent().slot

    # Move to different block and slot
    dag.updateStateData(tmpState[], bs2_3, cache)
    check:
      tmpState.blck == b2Add[]
      tmpState.data.data.slot == bs2_3.slot

    # Move back slot and block
    dag.updateStateData(tmpState[], bs1, cache)
    check:
      tmpState.blck == b1Add[]
      tmpState.data.data.slot == bs1.slot

    # Move back to genesis
    dag.updateStateData(tmpState[], bs1.parent(), cache)
    check:
      tmpState.blck == b1Add[].parent
      tmpState.data.data.slot == bs1.parent.slot

suiteReport "chain DAG finalization tests" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      dag = init(ChainDAGRef, defaultRuntimePreset, db)
      quarantine = QuarantineRef()
      cache = StateCache()

  timedTest "prune heads on finalization" & preset():
    # Create a fork that will not be taken
    var
      blck = makeTestBlock(dag.headState.data, dag.head.root, cache)
      tmpState = assignClone(dag.headState.data)
    check:
      process_slots(
        tmpState[], tmpState.data.slot + (5 * SLOTS_PER_EPOCH).uint64)

    let lateBlock = makeTestBlock(tmpState[], dag.head.root, cache)
    block:
      let status = dag.addRawBlock(quarantine, blck, nil)
      check: status.isOk()

    for i in 0 ..< (SLOTS_PER_EPOCH * 6):
      if i == 1:
        # There are 2 heads now because of the fork at slot 1
        check:
          dag.heads.len == 2

      blck = makeTestBlock(
        dag.headState.data, dag.head.root, cache,
        attestations = makeFullAttestations(
          dag.headState.data.data, dag.head.root,
          dag.headState.data.data.slot, cache, {}))
      let added = dag.addRawBlock(quarantine, blck, nil)
      check: added.isOk()
      dag.updateHead(added[])

    check:
      dag.heads.len() == 1

      # Epochrefs should share validator key set when the validator set is
      # stable
      not dag.heads[0].findEpochRef(dag.heads[0].slot.epoch).isNil
      not dag.heads[0].findEpochRef(dag.heads[0].slot.epoch - 1).isNil
      dag.heads[0].findEpochRef(dag.heads[0].slot.epoch) !=
        dag.heads[0].findEpochRef(dag.heads[0].slot.epoch - 1)
      dag.heads[0].findEpochRef(dag.heads[0].slot.epoch).validator_key_store[1] ==
        dag.heads[0].findEpochRef(dag.heads[0].slot.epoch - 1).validator_key_store[1]

    block:
      # The late block is a block whose parent was finalized long ago and thus
      # is no longer a viable head candidate
      let status = dag.addRawBlock(quarantine, lateBlock, nil)
      check: status.error == Unviable

    let
      dag2 = init(ChainDAGRef, defaultRuntimePreset, db)

    # check that the state reloaded from database resembles what we had before
    check:
      dag2.tail.root == dag.tail.root
      dag2.head.root == dag.head.root
      dag2.finalizedHead.blck.root == dag.finalizedHead.blck.root
      dag2.finalizedHead.slot == dag.finalizedHead.slot
      hash_tree_root(dag2.headState.data.data) ==
        hash_tree_root(dag.headState.data.data)

  timedTest "orphaned epoch block" & preset():
    var prestate = (ref HashedBeaconState)()
    for i in 0 ..< SLOTS_PER_EPOCH:
      if i == SLOTS_PER_EPOCH - 1:
        assign(prestate[], dag.headState.data)

      let blck = makeTestBlock(
        dag.headState.data, dag.head.root, cache)
      let added = dag.addRawBlock(quarantine, blck, nil)
      check: added.isOk()
      dag.updateHead(added[])

    check:
      dag.heads.len() == 1

    advance_slot(prestate[], {}, cache)

    # create another block, orphaning the head
    let blck = makeTestBlock(
      prestate[], dag.head.parent.root, cache)

    # Add block, but don't update head
    let added = dag.addRawBlock(quarantine, blck, nil)
    check: added.isOk()

    var
      dag2 = init(ChainDAGRef, defaultRuntimePreset, db)

    # check that we can apply the block after the orphaning
    let added2 = dag2.addRawBlock(quarantine, blck, nil)
    check: added2.isOk()

suiteReport "chain DAG finalization tests" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      dag = init(ChainDAGRef, defaultRuntimePreset, db)
      quarantine = QuarantineRef()
      cache = StateCache()

  timedTest "init with gaps" & preset():
    for i in 0 ..< (SLOTS_PER_EPOCH * 6 - 2):
      var
        blck = makeTestBlock(
          dag.headState.data, dag.head.root, cache,
          attestations = makeFullAttestations(
            dag.headState.data.data, dag.head.root,
            dag.headState.data.data.slot, cache, {}))

      let added = dag.addRawBlock(quarantine, blck, nil)
      check: added.isOk()
      dag.updateHead(added[])

    # Advance past epoch so that the epoch transition is gapped
    check:
      process_slots(
        dag.headState.data, Slot(SLOTS_PER_EPOCH * 6 + 2) )

    var blck = makeTestBlock(
      dag.headState.data, dag.head.root, cache,
      attestations = makeFullAttestations(
        dag.headState.data.data, dag.head.root,
        dag.headState.data.data.slot, cache, {}))

    let added = dag.addRawBlock(quarantine, blck, nil)
    check: added.isOk()
    dag.updateHead(added[])

    let
      dag2 = init(ChainDAGRef, defaultRuntimePreset, db)

    # check that the state reloaded from database resembles what we had before
    check:
      dag2.tail.root == dag.tail.root
      dag2.head.root == dag.head.root
      dag2.finalizedHead.blck.root == dag.finalizedHead.blck.root
      dag2.finalizedHead.slot == dag.finalizedHead.slot
      hash_tree_root(dag2.headState.data.data) ==
        hash_tree_root(dag.headState.data.data)

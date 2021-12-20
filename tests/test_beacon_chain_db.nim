# Nimbus
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[algorithm, options, sequtils],
  unittest2,
  ../beacon_chain/[beacon_chain_db, interop],
  ../beacon_chain/spec/[beaconstate, forks, state_transition],
  ../beacon_chain/spec/datatypes/[phase0, altair, merge],
  ../beacon_chain/consensus_object_pools/blockchain_dag,
  eth/db/kvstore,
  # test utilies
  ./testutil, ./testdbutil, ./testblockutil, ./teststateutil

when isMainModule:
  import chronicles # or some random compile error happens...

proc getPhase0StateRef(db: BeaconChainDB, root: Eth2Digest):
    phase0.NilableBeaconStateRef =
  # load beaconstate the way the block pool does it - into an existing instance
  let res = (phase0.BeaconStateRef)()
  if db.getState(root, res[], noRollback):
    return res

proc getAltairStateRef(db: BeaconChainDB, root: Eth2Digest):
    altair.NilableBeaconStateRef =
  # load beaconstate the way the block pool does it - into an existing instance
  let res = (altair.BeaconStateRef)()
  if db.getState(root, res[], noRollback):
    return res

proc getMergeStateRef(db: BeaconChainDB, root: Eth2Digest):
    merge.NilableBeaconStateRef =
  # load beaconstate the way the block pool does it - into an existing instance
  let res = (merge.BeaconStateRef)()
  if db.getState(root, res[], noRollback):
    return res

func withDigest(blck: phase0.TrustedBeaconBlock):
    phase0.TrustedSignedBeaconBlock =
  phase0.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck)
  )

func withDigest(blck: altair.TrustedBeaconBlock):
    altair.TrustedSignedBeaconBlock =
  altair.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck)
  )

func withDigest(blck: merge.TrustedBeaconBlock):
    merge.TrustedSignedBeaconBlock =
  merge.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck)
  )

proc getTestStates(stateFork: BeaconStateFork): auto =
  let
    db = makeTestDB(SLOTS_PER_EPOCH)
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
  var testStates = getTestStates(dag.headState.data, stateFork)

  # Ensure transitions beyond just adding validators and increasing slots
  sort(testStates) do (x, y: ref ForkedHashedBeaconState) -> int:
    cmp($getStateRoot(x[]), $getStateRoot(y[]))

  testStates

# Each of phase 0/altair/merge states gets used twice, so make them global to
# module
let
  testStatesPhase0 = getTestStates(BeaconStateFork.Phase0)
  testStatesAltair = getTestStates(BeaconStateFork.Altair)
  testStatesMerge  = getTestStates(BeaconStateFork.Merge)

suite "Beacon chain DB" & preset():
  test "empty database" & preset():
    var
      db = BeaconChainDB.new("", inMemory = true)
    check:
      db.getPhase0StateRef(Eth2Digest()).isNil
      db.getPhase0Block(Eth2Digest()).isNone

  test "sanity check phase 0 blocks" & preset():
    var db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((phase0.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    check:
      db.containsBlock(root)
      db.containsBlockPhase0(root)
      not db.containsBlockAltair(root)
      not db.containsBlockMerge(root)
      db.getPhase0Block(root).get() == signedBlock

    db.delBlock(root)
    check:
      not db.containsBlock(root)
      not db.containsBlockPhase0(root)
      not db.containsBlockAltair(root)
      not db.containsBlockMerge(root)
      db.getPhase0Block(root).isErr()

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check Altair blocks" & preset():
    var db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((altair.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    check:
      db.containsBlock(root)
      not db.containsBlockPhase0(root)
      db.containsBlockAltair(root)
      not db.containsBlockMerge(root)
      db.getAltairBlock(root).get() == signedBlock

    db.delBlock(root)
    check:
      not db.containsBlock(root)
      not db.containsBlockPhase0(root)
      not db.containsBlockAltair(root)
      not db.containsBlockMerge(root)
      db.getAltairBlock(root).isErr()

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check Merge blocks" & preset():
    var db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((merge.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    check:
      db.containsBlock(root)
      not db.containsBlockPhase0(root)
      not db.containsBlockAltair(root)
      db.containsBlockMerge(root)
      db.getMergeBlock(root).get() == signedBlock

    db.delBlock(root)
    check:
      not db.containsBlock(root)
      not db.containsBlockPhase0(root)
      not db.containsBlockAltair(root)
      not db.containsBlockMerge(root)
      db.getMergeBlock(root).isErr()

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check phase 0 states" & preset():
    var db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesPhase0:
      let root = state[].phase0Data.root
      db.putState(root, state[].phase0Data.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getPhase0StateRef(root)[]) == root

      db.delState(root)
      check:
        not db.containsState(root)
        db.getPhase0StateRef(root).isNil

    db.close()

  test "sanity check Altair states" & preset():
    var db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesAltair:
      let root = state[].altairData.root
      db.putState(root, state[].altairData.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getAltairStateRef(root)[]) == root

      db.delState(root)
      check:
        not db.containsState(root)
        db.getAltairStateRef(root).isNil

    db.close()

  test "sanity check Merge states" & preset():
    var db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesMerge:
      let root = state[].mergeData.root
      db.putState(root, state[].mergeData.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getMergeStateRef(root)[]) == root

      db.delState(root)
      check:
        not db.containsState(root)
        db.getMergeStateRef(root).isNil

    db.close()

  test "sanity check phase 0 states, reusing buffers" & preset():
    var db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (phase0.BeaconStateRef)()

    for state in testStatesPhase0:
      let root = state[].phase0Data.root
      db.putState(root, state[].phase0Data.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check Altair states, reusing buffers" & preset():
    var db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (altair.BeaconStateRef)()

    for state in testStatesAltair:
      let root = state[].altairData.root
      db.putState(root, state[].altairData.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check Merge states, reusing buffers" & preset():
    var db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (merge.BeaconStateRef)()

    for state in testStatesMerge:
      let root = state[].mergeData.root
      db.putState(root, state[].mergeData.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check phase 0 getState rollback" & preset():
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      state = (ref ForkedHashedBeaconState)(
        kind: BeaconStateFork.Phase0,
        phase0Data: phase0.HashedBeaconState(data: phase0.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptPhase0State(root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[].data)

    check:
      state[].phase0Data.data.slot == 10.Slot
      not db.getState(root, state[].phase0Data.data, restore)
      state[].phase0Data.data.slot != 10.Slot

  test "sanity check Altair and cross-fork getState rollback" & preset():
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      state = (ref ForkedHashedBeaconState)(
        kind: BeaconStateFork.Altair,
        altairData: altair.HashedBeaconState(data: altair.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptAltairState(root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[].data)

    check:
      state[].altairData.data.slot == 10.Slot
      not db.getState(root, state[].altairData.data, restore)

      # assign() has switched the case object fork
      state[].kind == BeaconStateFork.Phase0
      state[].phase0Data.data.slot != 10.Slot

  test "sanity check Merge and cross-fork getState rollback" & preset():
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      state = (ref ForkedHashedBeaconState)(
        kind: BeaconStateFork.Merge,
        mergeData: merge.HashedBeaconState(data: merge.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptMergeState(root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[].data)

    check:
      state[].mergeData.data.slot == 10.Slot
      not db.getState(root, state[].mergeData.data, restore)

      # assign() has switched the case object fork
      state[].kind == BeaconStateFork.Phase0
      state[].phase0Data.data.slot != 10.Slot

  test "find ancestors" & preset():
    var
      db = BeaconChainDB.new("", inMemory = true)

    let
      a0 = withDigest(
        (phase0.TrustedBeaconBlock)(slot: GENESIS_SLOT + 0))
      a1 = withDigest(
        (phase0.TrustedBeaconBlock)(slot: GENESIS_SLOT + 1, parent_root: a0.root))
      a2 = withDigest(
        (phase0.TrustedBeaconBlock)(slot: GENESIS_SLOT + 2, parent_root: a1.root))

    doAssert toSeq(db.getAncestors(a0.root)) == []
    doAssert toSeq(db.getAncestors(a2.root)) == []

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 0
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 0

    db.putBlock(a2)

    doAssert toSeq(db.getAncestors(a0.root)) == []
    doAssert toSeq(db.getAncestors(a2.root)) == [a2]

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 0
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 1

    db.putBlock(a1)

    doAssert toSeq(db.getAncestors(a0.root)) == []
    doAssert toSeq(db.getAncestors(a2.root)) == [a2, a1]

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 0
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 2

    db.putBlock(a0)

    doAssert toSeq(db.getAncestors(a0.root)) == [a0]
    doAssert toSeq(db.getAncestors(a2.root)) == [a2, a1, a0]

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 1
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 3

  test "sanity check genesis roundtrip" & preset():
    # This is a really dumb way of checking that we can roundtrip a genesis
    # state. We've been bit by this because we've had a bug in the BLS
    # serialization where an all-zero default-initialized bls signature could
    # not be deserialized because the deserialization was too strict.
    var
      db = BeaconChainDB.new("", inMemory = true)

    let
      state = newClone(initialize_hashed_beacon_state_from_eth1(
        defaultRuntimeConfig, eth1BlockHash, 0,
        makeInitialDeposits(SLOTS_PER_EPOCH), {skipBlsValidation}))

    db.putState(state[].root, state[].data)

    check db.containsState(state[].root)
    let state2 = db.getPhase0StateRef(state[].root)
    db.delState(state[].root)
    check not db.containsState(state[].root)
    db.close()

    check:
      hash_tree_root(state2[]) == state[].root

  test "sanity check state diff roundtrip" & preset():
    var
      db = BeaconChainDB.new("", inMemory = true)

    # TODO htr(diff) probably not interesting/useful, but stand-in
    let
      stateDiff = BeaconStateDiff()
      root = hash_tree_root(stateDiff)

    db.putStateDiff(root, stateDiff)

    let state2 = db.getStateDiff(root)
    db.delStateDiff(root)
    check db.getStateDiff(root).isNone()
    db.close()

    check:
      hash_tree_root(state2[]) == root

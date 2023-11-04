# Nimbus
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/spec/[beaconstate, forks, state_transition],
  ../beacon_chain/consensus_object_pools/blockchain_dag,
  eth/db/kvstore,
  # test utilies
  ./mocking/mock_genesis,
  ./testutil, ./testdbutil, ./testblockutil, ./teststateutil

from std/algorithm import sort
from std/sequtils import toSeq
from snappy import encodeFramed, uncompressedLenFramed

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

proc getBellatrixStateRef(db: BeaconChainDB, root: Eth2Digest):
    bellatrix.NilableBeaconStateRef =
  # load beaconstate the way the block pool does it - into an existing instance
  let res = (bellatrix.BeaconStateRef)()
  if db.getState(root, res[], noRollback):
    return res

from ../beacon_chain/spec/datatypes/capella import
  BeaconStateRef, NilableBeaconStateRef

proc getCapellaStateRef(db: BeaconChainDB, root: Eth2Digest):
    capella.NilableBeaconStateRef =
  # load beaconstate the way the block pool does it - into an existing instance
  let res = (capella.BeaconStateRef)()
  if db.getState(root, res[], noRollback):
    return res

from ../beacon_chain/spec/datatypes/deneb import TrustedSignedBeaconBlock

proc getDenebStateRef(db: BeaconChainDB, root: Eth2Digest):
    deneb.NilableBeaconStateRef =
  # load beaconstate the way the block pool does it - into an existing instance
  let res = (deneb.BeaconStateRef)()
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

func withDigest(blck: bellatrix.TrustedBeaconBlock):
    bellatrix.TrustedSignedBeaconBlock =
  bellatrix.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck)
  )

func withDigest(blck: capella.TrustedBeaconBlock):
    capella.TrustedSignedBeaconBlock =
  capella.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck)
  )

func withDigest(blck: deneb.TrustedBeaconBlock):
    deneb.TrustedSignedBeaconBlock =
  deneb.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck)
  )

proc getTestStates(consensusFork: ConsensusFork): auto =
  let
    db = makeTestDB(SLOTS_PER_EPOCH)
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
  var testStates = getTestStates(dag.headState, consensusFork)

  # Ensure transitions beyond just adding validators and increasing slots
  sort(testStates) do (x, y: ref ForkedHashedBeaconState) -> int:
    cmp($getStateRoot(x[]), $getStateRoot(y[]))

  testStates

# Each set of states gets used twice, so scope them to module
let
  testStatesPhase0    = getTestStates(ConsensusFork.Phase0)
  testStatesAltair    = getTestStates(ConsensusFork.Altair)
  testStatesBellatrix = getTestStates(ConsensusFork.Bellatrix)
  testStatesCapella   = getTestStates(ConsensusFork.Capella)
  testStatesDeneb     = getTestStates(ConsensusFork.Deneb)
doAssert len(testStatesPhase0) > 8
doAssert len(testStatesAltair) > 8
doAssert len(testStatesBellatrix) > 8
doAssert len(testStatesCapella) > 8
doAssert len(testStatesDeneb) > 8

suite "Beacon chain DB" & preset():
  test "empty database" & preset():
    var
      db = BeaconChainDB.new("", inMemory = true)
    check:
      db.getPhase0StateRef(ZERO_HASH).isNil
      db.getBlock(ZERO_HASH, phase0.TrustedSignedBeaconBlock).isNone

  test "sanity check phase 0 blocks" & preset():
    let db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((phase0.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    var tmp, tmp2: seq[byte]
    check:
      db.containsBlock(root)
      db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, phase0.TrustedSignedBeaconBlock).get() == signedBlock
      db.getBlockSSZ(root, tmp, phase0.TrustedSignedBeaconBlock)
      db.getBlockSZ(root, tmp2, phase0.TrustedSignedBeaconBlock)
      tmp == SSZ.encode(signedBlock)
      tmp2 == encodeFramed(tmp)
      uncompressedLenFramed(tmp2).isSome

    check:
      db.delBlock(ConsensusFork.Phase0, root)
      not db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, phase0.TrustedSignedBeaconBlock).isErr()
      not db.getBlockSSZ(root, tmp, phase0.TrustedSignedBeaconBlock)
      not db.getBlockSZ(root, tmp2, phase0.TrustedSignedBeaconBlock)

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check Altair blocks" & preset():
    let db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((altair.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    var tmp, tmp2: seq[byte]
    check:
      db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, altair.TrustedSignedBeaconBlock).get() == signedBlock
      db.getBlockSSZ(root, tmp, altair.TrustedSignedBeaconBlock)
      db.getBlockSZ(root, tmp2, altair.TrustedSignedBeaconBlock)
      tmp == SSZ.encode(signedBlock)
      tmp2 == encodeFramed(tmp)
      uncompressedLenFramed(tmp2).isSome

    check:
      db.delBlock(ConsensusFork.Altair, root)
      not db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, altair.TrustedSignedBeaconBlock).isErr()
      not db.getBlockSSZ(root, tmp, altair.TrustedSignedBeaconBlock)
      not db.getBlockSZ(root, tmp2, altair.TrustedSignedBeaconBlock)

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check Bellatrix blocks" & preset():
    let db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((bellatrix.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    var tmp, tmp2: seq[byte]
    check:
      db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, bellatrix.TrustedSignedBeaconBlock).get() == signedBlock
      db.getBlockSSZ(root, tmp, bellatrix.TrustedSignedBeaconBlock)
      db.getBlockSZ(root, tmp2, bellatrix.TrustedSignedBeaconBlock)
      tmp == SSZ.encode(signedBlock)
      tmp2 == encodeFramed(tmp)
      uncompressedLenFramed(tmp2).isSome

    check:
      db.delBlock(ConsensusFork.Bellatrix, root)
      not db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, bellatrix.TrustedSignedBeaconBlock).isErr()
      not db.getBlockSSZ(root, tmp, bellatrix.TrustedSignedBeaconBlock)
      not db.getBlockSZ(root, tmp2, bellatrix.TrustedSignedBeaconBlock)

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check Capella blocks" & preset():
    let db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((capella.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    var tmp, tmp2: seq[byte]
    check:
      db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      db.getBlock(root, capella.TrustedSignedBeaconBlock).get() == signedBlock
      db.getBlockSSZ(root, tmp, capella.TrustedSignedBeaconBlock)
      db.getBlockSZ(root, tmp2, capella.TrustedSignedBeaconBlock)
      tmp == SSZ.encode(signedBlock)
      tmp2 == encodeFramed(tmp)
      uncompressedLenFramed(tmp2).isSome

    check:
      db.delBlock(ConsensusFork.Capella, root)
      not db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, capella.TrustedSignedBeaconBlock).isErr()
      not db.getBlockSSZ(root, tmp, capella.TrustedSignedBeaconBlock)
      not db.getBlockSZ(root, tmp2, capella.TrustedSignedBeaconBlock)

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check Deneb blocks" & preset():
    let db = BeaconChainDB.new("", inMemory = true)

    let
      signedBlock = withDigest((deneb.TrustedBeaconBlock)())
      root = hash_tree_root(signedBlock.message)

    db.putBlock(signedBlock)

    var tmp, tmp2: seq[byte]
    check:
      db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, deneb.TrustedSignedBeaconBlock).get() == signedBlock
      db.getBlockSSZ(root, tmp, deneb.TrustedSignedBeaconBlock)
      db.getBlockSZ(root, tmp2, deneb.TrustedSignedBeaconBlock)
      tmp == SSZ.encode(signedBlock)
      tmp2 == encodeFramed(tmp)
      uncompressedLenFramed(tmp2).isSome

    check:
      db.delBlock(ConsensusFork.Deneb, root)
      not db.containsBlock(root)
      not db.containsBlock(root, phase0.TrustedSignedBeaconBlock)
      not db.containsBlock(root, altair.TrustedSignedBeaconBlock)
      not db.containsBlock(root, bellatrix.TrustedSignedBeaconBlock)
      not db.containsBlock(root, capella.TrustedSignedBeaconBlock)
      not db.containsBlock(root, deneb.TrustedSignedBeaconBlock)
      db.getBlock(root, deneb.TrustedSignedBeaconBlock).isErr()
      not db.getBlockSSZ(root, tmp, deneb.TrustedSignedBeaconBlock)
      not db.getBlockSZ(root, tmp2, deneb.TrustedSignedBeaconBlock)

    db.putStateRoot(root, signedBlock.message.slot, root)
    var root2 = root
    root2.data[0] = root.data[0] + 1
    db.putStateRoot(root, signedBlock.message.slot + 1, root2)

    check:
      db.getStateRoot(root, signedBlock.message.slot).get() == root
      db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

    db.close()

  test "sanity check phase 0 states" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesPhase0:
      let root = state[].phase0Data.root
      db.putState(root, state[].phase0Data.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getPhase0StateRef(root)[]) == root

      db.delState(ConsensusFork.Phase0, root)
      check:
        not db.containsState(root)
        db.getPhase0StateRef(root).isNil

    db.close()

  test "sanity check Altair states" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesAltair:
      let root = state[].altairData.root
      db.putState(root, state[].altairData.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getAltairStateRef(root)[]) == root

      db.delState(ConsensusFork.Altair, root)
      check:
        not db.containsState(root)
        db.getAltairStateRef(root).isNil

    db.close()

  test "sanity check Bellatrix states" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesBellatrix:
      let root = state[].bellatrixData.root
      db.putState(root, state[].bellatrixData.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getBellatrixStateRef(root)[]) == root

      db.delState(ConsensusFork.Bellatrix, root)
      check:
        not db.containsState(root)
        db.getBellatrixStateRef(root).isNil

    db.close()

  test "sanity check Capella states" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesCapella:
      let root = state[].capellaData.root
      db.putState(root, state[].capellaData.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getCapellaStateRef(root)[]) == root

      db.delState(ConsensusFork.Capella, root)
      check:
        not db.containsState(root)
        db.getCapellaStateRef(root).isNil

    db.close()

  test "sanity check Deneb states" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)

    for state in testStatesDeneb:
      let root = state[].denebData.root
      db.putState(root, state[].denebData.data)

      check:
        db.containsState(root)
        hash_tree_root(db.getDenebStateRef(root)[]) == root

      db.delState(ConsensusFork.Deneb, root)
      check:
        not db.containsState(root)
        db.getDenebStateRef(root).isNil

    db.close()

  test "sanity check phase 0 states, reusing buffers" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (phase0.BeaconStateRef)()

    for state in testStatesPhase0:
      let root = state[].phase0Data.root
      db.putState(root, state[].phase0Data.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(ConsensusFork.Phase0, root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check Altair states, reusing buffers" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (altair.BeaconStateRef)()

    for state in testStatesAltair:
      let root = state[].altairData.root
      db.putState(root, state[].altairData.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(ConsensusFork.Altair, root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check Bellatrix states, reusing buffers" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (bellatrix.BeaconStateRef)()

    for state in testStatesBellatrix:
      let root = state[].bellatrixData.root
      db.putState(root, state[].bellatrixData.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(ConsensusFork.Bellatrix, root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check Capella states, reusing buffers" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (capella.BeaconStateRef)()

    for state in testStatesCapella:
      let root = state[].capellaData.root
      db.putState(root, state[].capellaData.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(ConsensusFork.Capella, root)
      check:
        not db.containsState(root)
        not db.getState(root, stateBuffer[], noRollback)

    db.close()

  test "sanity check Deneb states, reusing buffers" & preset():
    let db = makeTestDB(SLOTS_PER_EPOCH)
    let stateBuffer = (deneb.BeaconStateRef)()

    for state in testStatesDeneb:
      let root = state[].denebData.root
      db.putState(root, state[].denebData.data)

      check:
        db.getState(root, stateBuffer[], noRollback)
        db.containsState(root)
        hash_tree_root(stateBuffer[]) == root

      db.delState(ConsensusFork.Deneb, root)
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
        kind: ConsensusFork.Phase0,
        phase0Data: phase0.HashedBeaconState(data: phase0.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptState(ConsensusFork.Phase0, root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[])

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
        kind: ConsensusFork.Altair,
        altairData: altair.HashedBeaconState(data: altair.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptState(ConsensusFork.Altair, root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[])

    check:
      state[].altairData.data.slot == 10.Slot
      not db.getState(root, state[].altairData.data, restore)

      # assign() has switched the case object fork
      state[].kind == ConsensusFork.Phase0
      state[].phase0Data.data.slot != 10.Slot

  test "sanity check Bellatrix and cross-fork getState rollback" & preset():
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Bellatrix,
        bellatrixData: bellatrix.HashedBeaconState(data: bellatrix.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptState(ConsensusFork.Bellatrix, root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[])

    check:
      state[].bellatrixData.data.slot == 10.Slot
      not db.getState(root, state[].bellatrixData.data, restore)

      # assign() has switched the case object fork
      state[].kind == ConsensusFork.Phase0
      state[].phase0Data.data.slot != 10.Slot

  test "sanity check Capella and cross-fork getState rollback" & preset():
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Capella,
        capellaData: capella.HashedBeaconState(data: capella.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptState(ConsensusFork.Capella, root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[])

    check:
      state[].capellaData.data.slot == 10.Slot
      not db.getState(root, state[].capellaData.data, restore)

      # assign() has switched the case object fork
      state[].kind == ConsensusFork.Phase0
      state[].phase0Data.data.slot != 10.Slot

  test "sanity check Deneb and cross-fork getState rollback" & preset():
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      state = (ref ForkedHashedBeaconState)(
        kind: ConsensusFork.Deneb,
        denebData: deneb.HashedBeaconState(data: deneb.BeaconState(
          slot: 10.Slot)))
      root = Eth2Digest()

    db.putCorruptState(ConsensusFork.Deneb, root)

    let restoreAddr = addr dag.headState

    func restore() =
      assign(state[], restoreAddr[])

    check:
      state[].denebData.data.slot == 10.Slot
      not db.getState(root, state[].denebData.data, restore)

      # assign() has switched the case object fork
      state[].kind == ConsensusFork.Phase0
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

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 0
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 0
    doAssert db.getBeaconBlockSummary(a2.root).isNone()

    db.putBlock(a2)

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 0
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 1
    doAssert db.getBeaconBlockSummary(a2.root).get().slot == a2.message.slot

    db.putBlock(a1)

    doAssert toSeq(db.getAncestorSummaries(a0.root)).len == 0
    doAssert toSeq(db.getAncestorSummaries(a2.root)).len == 2

    db.putBlock(a0)

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
        defaultRuntimeConfig, mockEth1BlockHash, 0,
        makeInitialDeposits(SLOTS_PER_EPOCH), {skipBlsValidation}))

    db.putState(state[].root, state[].data)

    check db.containsState(state[].root)
    let state2 = db.getPhase0StateRef(state[].root)
    db.delState(ConsensusFork.Phase0, state[].root)
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

  test "sanity check blobs" & preset():
    const
      blockHeader0 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(0)))
      blockHeader1 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(1)))

    let
      blockRoot0 = hash_tree_root(blockHeader0.message)
      blockRoot1 = hash_tree_root(blockHeader1.message)

      # Ensure minimal-difference pairs on both block root and blob index to
      # verify that blobkey uses both
      blobSidecar0 = BlobSidecar(signed_block_header: blockHeader0, index: 3)
      blobSidecar1 = BlobSidecar(signed_block_header: blockHeader0, index: 2)
      blobSidecar2 = BlobSidecar(signed_block_header: blockHeader1, index: 2)

      db = makeTestDB(SLOTS_PER_EPOCH)

    var
      buf: seq[byte]
      blobSidecar: BlobSidecar

    check:
      not db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      not db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      not db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      not db.getBlobSidecarSZ(blockRoot0, 3, buf)
      not db.getBlobSidecarSZ(blockRoot0, 2, buf)
      not db.getBlobSidecarSZ(blockRoot1, 2, buf)

    db.putBlobSidecar(blobSidecar0)

    check:
      db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      blobSidecar == blobSidecar0
      not db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      not db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      db.getBlobSidecarSZ(blockRoot0, 3, buf)
      not db.getBlobSidecarSZ(blockRoot0, 2, buf)
      not db.getBlobSidecarSZ(blockRoot1, 2, buf)

    db.putBlobSidecar(blobSidecar1)

    check:
      db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      blobSidecar == blobSidecar0
      db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      blobSidecar == blobSidecar1
      not db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      db.getBlobSidecarSZ(blockRoot0, 3, buf)
      db.getBlobSidecarSZ(blockRoot0, 2, buf)
      not db.getBlobSidecarSZ(blockRoot1, 2, buf)

    check db.delBlobSidecar(blockRoot0, 3)

    check:
      not db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      blobSidecar == blobSidecar1
      not db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      not db.getBlobSidecarSZ(blockRoot0, 3, buf)
      db.getBlobSidecarSZ(blockRoot0, 2, buf)
      not db.getBlobSidecarSZ(blockRoot1, 2, buf)

    db.putBlobSidecar(blobSidecar2)

    check:
      not db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      blobSidecar == blobSidecar1
      db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      blobSidecar == blobSidecar2
      not db.getBlobSidecarSZ(blockRoot0, 3, buf)
      db.getBlobSidecarSZ(blockRoot0, 2, buf)
      db.getBlobSidecarSZ(blockRoot1, 2, buf)

    check db.delBlobSidecar(blockRoot0, 2)

    check:
      not db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      not db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      blobSidecar == blobSidecar2
      not db.getBlobSidecarSZ(blockRoot0, 3, buf)
      not db.getBlobSidecarSZ(blockRoot0, 2, buf)
      db.getBlobSidecarSZ(blockRoot1, 2, buf)

    check db.delBlobSidecar(blockRoot1, 2)

    check:
      not db.getBlobSidecar(blockRoot0, 3, blobSidecar)
      not db.getBlobSidecar(blockRoot0, 2, blobSidecar)
      not db.getBlobSidecar(blockRoot1, 2, blobSidecar)
      not db.getBlobSidecarSZ(blockRoot0, 3, buf)
      not db.getBlobSidecarSZ(blockRoot0, 2, buf)
      not db.getBlobSidecarSZ(blockRoot1, 2, buf)

    db.close()

suite "FinalizedBlocks" & preset():
  test "Basic ops" & preset():
    var
      db = SqStoreRef.init("", "test", inMemory = true).expect(
        "working database (out of memory?)")

    var s = FinalizedBlocks.init(db, "finalized_blocks").get()

    check:
      s.low.isNone
      s.high.isNone

    s.insert(Slot 0, ZERO_HASH)
    check:
      s.low.get() == Slot 0
      s.high.get() == Slot 0

    s.insert(Slot 5, ZERO_HASH)
    check:
      s.low.get() == Slot 0
      s.high.get() == Slot 5

    var items = 0
    for k, v in s:
      check: k in [Slot 0, Slot 5]
      items += 1

    check: items == 2

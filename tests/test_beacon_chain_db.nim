# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/[beacon_chain_db, beacon_chain_db_quarantine],
  ../beacon_chain/consensus_object_pools/block_dag,
  ../beacon_chain/spec/forks,
  ./[testutil, teststateutil]

from std/algorithm import sort
from std/sequtils import allIt, toSeq
from snappy import encodeFramed, uncompressedLenFramed
from ../beacon_chain/consensus_object_pools/block_pools_types import
  ChainDAGRef
from ../beacon_chain/consensus_object_pools/blockchain_dag import init
from ../beacon_chain/spec/beaconstate import
  initialize_hashed_beacon_state_from_eth1
from ../beacon_chain/spec/state_transition import noRollback
from ../beacon_chain/validators/validator_monitor import ValidatorMonitor
from ./consensus_spec/fixtures_utils import genesisTestruntimeConfig
from ./testblockutil import makeInitialDeposits
from ./testdbutil import makeTestDB

when isMainModule:
  import chronicles # or some random compile error happens...

template BeaconStateRef(kind: static ConsensusFork): typedesc =
  when kind == ConsensusFork.Gloas:
    gloas.BeaconStateRef
  elif kind == ConsensusFork.Fulu:
    fulu.BeaconStateRef
  elif kind == ConsensusFork.Electra:
    electra.BeaconStateRef
  elif kind == ConsensusFork.Deneb:
    deneb.BeaconStateRef
  elif kind == ConsensusFork.Capella:
    capella.BeaconStateRef
  elif kind == ConsensusFork.Bellatrix:
    bellatrix.BeaconStateRef
  elif kind == ConsensusFork.Altair:
    altair.BeaconStateRef
  elif kind == ConsensusFork.Phase0:
    phase0.BeaconStateRef
  else:
    {.error: "BeaconStateRef unsupported in " & $kind.}

template NilableBeaconStateRef(kind: static ConsensusFork): typedesc =
  when kind == ConsensusFork.Gloas:
    gloas.NilableBeaconStateRef
  elif kind == ConsensusFork.Fulu:
    fulu.NilableBeaconStateRef
  elif kind == ConsensusFork.Electra:
    electra.NilableBeaconStateRef
  elif kind == ConsensusFork.Deneb:
    deneb.NilableBeaconStateRef
  elif kind == ConsensusFork.Capella:
    capella.NilableBeaconStateRef
  elif kind == ConsensusFork.Bellatrix:
    bellatrix.NilableBeaconStateRef
  elif kind == ConsensusFork.Altair:
    altair.NilableBeaconStateRef
  elif kind == ConsensusFork.Phase0:
    phase0.NilableBeaconStateRef
  else:
    {.error: "NilableBeaconStateRef unsupported in " & $kind.}

template TrustedBeaconBlock(kind: static ConsensusFork): typedesc =
  when kind == ConsensusFork.Gloas:
    gloas.TrustedBeaconBlock
  elif kind == ConsensusFork.Fulu:
    fulu.TrustedBeaconBlock
  elif kind == ConsensusFork.Electra:
    electra.TrustedBeaconBlock
  elif kind == ConsensusFork.Deneb:
    deneb.TrustedBeaconBlock
  elif kind == ConsensusFork.Capella:
    capella.TrustedBeaconBlock
  elif kind == ConsensusFork.Bellatrix:
    bellatrix.TrustedBeaconBlock
  elif kind == ConsensusFork.Altair:
    altair.TrustedBeaconBlock
  elif kind == ConsensusFork.Phase0:
    phase0.TrustedBeaconBlock
  else:
    {.error: "TrustedBeaconBlock unsupported in " & $kind.}

proc getStateRef(
    db: BeaconChainDB,
    consensusFork: static ConsensusFork,
    root: Eth2Digest): auto =
  # load beaconstate the way the block pool does it - into an existing instance
  var res: consensusFork.NilableBeaconStateRef =
    (consensusFork.BeaconStateRef)()
  if not db.getState(root, res[], noRollback):
    res = nil
  res

func withDigest(blck: ForkyTrustedBeaconBlock): auto =
  typeof(blck).kind.TrustedSignedBeaconBlock(
    message: blck,
    root: hash_tree_root(blck))

proc getTestStates(
    cfg: RuntimeConfig,
    consensusFork: ConsensusFork): seq[ref ForkedHashedBeaconState] =
  let
    db = cfg.makeTestDB(SLOTS_PER_EPOCH)
    validatorMonitor = newClone(ValidatorMonitor.init(cfg))
    dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
  var testStates = getTestStates(dag.headState, consensusFork)

  # Ensure transitions beyond just adding validators and increasing slots
  sort(testStates) do (x, y: ref ForkedHashedBeaconState) -> int:
    cmp($x[].root, $y[].root)

  testStates

# Each set of states gets used twice, so scope them to module
let
  cfg = defaultRuntimeConfig
  testStates = block:
    var res: array[ConsensusFork, seq[ref ForkedHashedBeaconState]]
    for consensusFork in ConsensusFork:
      res[consensusFork] = cfg.getTestStates(consensusFork)
    res
debugHezeComment "..."
doAssert testStates.toOpenArray(0, testStates.len - 2).allIt(it.len > 8)

suite "Beacon chain DB" & preset():
  test "empty database" & preset():
    var db = BeaconChainDB.new("", cfg, inMemory = true)
    check:
      db.getStateRef(ConsensusFork.Phase0, ZERO_HASH).isNil
      db.getBlock(ZERO_HASH, phase0.TrustedSignedBeaconBlock).isNone

  template doBlockTest(consensusFork: static ConsensusFork): untyped =
    block:
      let db = BeaconChainDB.new(
        "", consensusFork.genesisTestRuntimeConfig, inMemory = true)

      let
        signedBlock = withDigest((consensusFork.TrustedBeaconBlock)())
        root = hash_tree_root(signedBlock.message)

      db.putBlock(signedBlock)

      var tmp, tmp2: seq[byte]
      check db.containsBlock(root)
      const fork = consensusFork
      withAll(ConsensusFork):
        let ok = db.containsBlock(root, consensusFork.TrustedSignedBeaconBlock)
        check ok == (consensusFork == fork)
      check:
        db.getBlock(
          root, consensusFork.TrustedSignedBeaconBlock).get() == signedBlock
        db.getBlockSSZ(root, tmp, consensusFork.TrustedSignedBeaconBlock)
        db.getBlockSZ(root, tmp2, consensusFork.TrustedSignedBeaconBlock)
        tmp == SSZ.encode(signedBlock)
        tmp2 == encodeFramed(tmp)
        uncompressedLenFramed(tmp2).isSome

        db.delBlock(consensusFork, root)
        not db.containsBlock(root)
      withAll(ConsensusFork):
        check not db.containsBlock(root, consensusFork.TrustedSignedBeaconBlock)
      check:
        db.getBlock(root, consensusFork.TrustedSignedBeaconBlock).isErr()
        not db.getBlockSSZ(root, tmp, consensusFork.TrustedSignedBeaconBlock)
        not db.getBlockSZ(root, tmp2, consensusFork.TrustedSignedBeaconBlock)

      db.putStateRoot(root, signedBlock.message.slot, root)
      var root2 = root
      root2.data[0] = root.data[0] + 1
      db.putStateRoot(root, signedBlock.message.slot + 1, root2)

      check:
        db.getStateRoot(root, signedBlock.message.slot).get() == root
        db.getStateRoot(root, signedBlock.message.slot + 1).get() == root2

      db.close()

  withAll(ConsensusFork):
    let name = "sanity check " & $consensusFork & " blocks"
    test name & preset():
      when consensusFork >= ConsensusFork.Gloas:
        skip()
      else:
        consensusFork.doBlockTest()

  template doStateTest(consensusFork: static ConsensusFork): untyped =
    block:
      let db = cfg.makeTestDB(SLOTS_PER_EPOCH)

      for state in testStates[consensusFork]:
        let root = state[].forky(consensusFork).root
        db.putState(root, state[].forky(consensusFork).data)

        check:
          db.containsState(root)
          hash_tree_root(db.getStateRef(consensusFork, root)[]) == root

        db.delState(consensusFork, root)
        check:
          not db.containsState(root)
          db.getStateRef(consensusFork, root).isNil

      db.close()

  withAll(ConsensusFork):
    let name = "sanity check " & $consensusFork & " states"
    test name & preset():
      when consensusFork >= ConsensusFork.Gloas:
        skip()
      else:
        consensusFork.doStateTest()

  template doStateTestReusingBuffers(
      consensusFork: static ConsensusFork): untyped =
    block:
      let
        db = cfg.makeTestDB(SLOTS_PER_EPOCH)
        stateBuffer = (consensusFork.BeaconStateRef)()

      for state in testStates[consensusFork]:
        let root = state[].forky(consensusFork).root
        db.putState(root, state[].forky(consensusFork).data)

        check:
          db.getState(root, stateBuffer[], noRollback)
          db.containsState(root)
          hash_tree_root(stateBuffer[]) == root

        db.delState(consensusFork, root)
        check:
          not db.containsState(root)
          not db.getState(root, stateBuffer[], noRollback)

      db.close()

  withAll(ConsensusFork):
    let name = "sanity check " & $consensusFork & " states, reusing buffers"
    test name & preset():
      when consensusFork >= ConsensusFork.Gloas:
        skip()
      else:
        consensusFork.doStateTestReusingBuffers()

  template doRollbackTest(consensusFork: static ConsensusFork): untyped =
    block:
      var
        db = cfg.makeTestDB(SLOTS_PER_EPOCH)
        validatorMonitor = newClone(ValidatorMonitor.init(cfg))
        dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
        state = ForkedHashedBeaconState.new(
          (ref consensusFork.BeaconState)(slot: 10.Slot)[])
        root = Eth2Digest()

      db.putCorruptState(consensusFork, root)

      let restoreAddr = addr dag.headState

      func restore() =
        assign(state[], restoreAddr[])

      withState(state[]):
        check:
          forkyState.data.slot == 10.Slot
          not db.getState(root, forkyState.data, restore)

      # assign() has switched the case object fork
      check:
        state[].kind == ConsensusFork.Phase0
        state[].phase0Data.data.slot != 10.Slot

  withAll(ConsensusFork):
    let name = "sanity check " & $consensusFork &
      (if consensusFork > ConsensusFork.Phase0: " and cross-fork" else: "") &
      " getState rollback"
    test name & preset():
      when consensusFork >= ConsensusFork.Gloas:
        skip()
      else:
        consensusFork.doRollbackTest()

  test "find ancestors" & preset():
    var db = BeaconChainDB.new("", cfg, inMemory = true)

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
    var db = BeaconChainDB.new("", cfg, inMemory = true)

    let
      state = newClone(initialize_hashed_beacon_state_from_eth1(
        cfg, mockEth1BlockHash, 0,
        makeInitialDeposits(cfg, SLOTS_PER_EPOCH), {skipBlsValidation}))

    db.putState(state[].root, state[].data)

    check db.containsState(state[].root)
    let state2 = db.getStateRef(ConsensusFork.Phase0, state[].root)
    db.delState(ConsensusFork.Phase0, state[].root)
    check not db.containsState(state[].root)
    db.close()

    check:
      hash_tree_root(state2[]) == state[].root

  test "sanity check state diff roundtrip" & preset():
    var db = BeaconChainDB.new("", cfg, inMemory = true)

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

      db = cfg.makeTestDB(SLOTS_PER_EPOCH)

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

  test "sanity check fulu data columns" & preset():
    const
      blockHeader0 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(0)))
      blockHeader1 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(1)))

    let
      blockRoot0 = hash_tree_root(blockHeader0.message)
      blockRoot1 = hash_tree_root(blockHeader1.message)

      # Ensure minimal-difference pairs on both block root and
      # data column index to verify that the columnkey uses both
      dataColumnSidecar0 = fulu.DataColumnSidecar(signed_block_header: blockHeader0, index: 3)
      dataColumnSidecar1 = fulu.DataColumnSidecar(signed_block_header: blockHeader0, index: 2)
      dataColumnSidecar2 = fulu.DataColumnSidecar(signed_block_header: blockHeader1, index: 2)

      db = cfg.makeTestDB(SLOTS_PER_EPOCH)

    var
      buf: seq[byte]
      dataColumnSidecar: fulu.DataColumnSidecar

    check:
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    db.putDataColumnSidecar(dataColumnSidecar0)

    check:
      db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar0
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    db.putDataColumnSidecar(dataColumnSidecar1)

    check:
      db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar0
      db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar1
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    check db.delDataColumnSidecar(ConsensusFork.Fulu, blockRoot0, 3)

    check:
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar1
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    db.putDataColumnSidecar(dataColumnSidecar2)

    check:
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar1
      db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar2
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 2, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    check db.delDataColumnSidecar(ConsensusFork.Fulu, blockRoot0, 2)

    check:
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar2
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 2, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    check db.delDataColumnSidecar(ConsensusFork.Fulu, blockRoot1, 2)

    check:
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Fulu, blockRoot1, 2, buf)

    db.close()

  test "sanity check gloas data columns" & preset():
    const
      blockHeader0 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(0)))
      blockHeader1 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(1)))

    let
      blockRoot0 = hash_tree_root(blockHeader0.message)
      blockRoot1 = hash_tree_root(blockHeader1.message)

      dataColumnSidecar0 = gloas.DataColumnSidecar(index: 3, beacon_block_root: blockRoot0)
      dataColumnSidecar1 = gloas.DataColumnSidecar(index: 2, beacon_block_root: blockRoot0)
      dataColumnSidecar2 = gloas.DataColumnSidecar(index: 2, beacon_block_root: blockRoot1)

      db = cfg.makeTestDB(SLOTS_PER_EPOCH)

    var
      buf: seq[byte]
      dataColumnSidecar: gloas.DataColumnSidecar

    check:
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    db.putDataColumnSidecar(dataColumnSidecar0)

    check:
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar0
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    db.putDataColumnSidecar(dataColumnSidecar1)

    check:
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar0
      db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar1
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    check db.delDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)

    check:
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar1
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    db.putDataColumnSidecar(dataColumnSidecar2)

    check:
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar1
      db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar2
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    check db.delDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)

    check:
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      dataColumnSidecar == dataColumnSidecar2
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    check db.delDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)

    check:
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 3)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot0, 2)
      not db.containsDataColumnSidecar(ConsensusFork.Gloas, blockRoot1, 2)
      not db.getDataColumnSidecar(blockRoot0, 3, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot0, 2, dataColumnSidecar)
      not db.getDataColumnSidecar(blockRoot1, 2, dataColumnSidecar)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 3, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot0, 2, buf)
      not db.getDataColumnSidecarSZ(ConsensusFork.Gloas, blockRoot1, 2, buf)

    db.close()

  test "sanity check execution payload envelopes" & preset():
    const
      blockHeader0 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(0)))
      blockHeader1 = SignedBeaconBlockHeader(
        message: BeaconBlockHeader(slot: Slot(1)))

    let
      blockRoot0 = hash_tree_root(blockHeader0.message)
      blockRoot1 = hash_tree_root(blockHeader1.message)

      envelope0 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(beacon_block_root: blockRoot0))
      envelope1 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(beacon_block_root: blockRoot1))

      db = cfg.makeTestDB(SLOTS_PER_EPOCH)

    var data: seq[byte]

    check:
      not db.containsExecutionPayloadEnvelope(blockRoot0)
      not db.containsExecutionPayloadEnvelope(blockRoot1)
      not db.getExecutionPayloadEnvelope(blockRoot0).isSome()
      not db.getExecutionPayloadEnvelope(blockRoot1).isSome()
      not db.getExecutionPayloadEnvelopeSZ(blockRoot0, data)
      not db.getExecutionPayloadEnvelopeSZ(blockRoot1, data)

    db.putExecutionPayloadEnvelope(envelope0)

    check:
      db.containsExecutionPayloadEnvelope(blockRoot0)
      not db.containsExecutionPayloadEnvelope(blockRoot1)
      db.getExecutionPayloadEnvelope(blockRoot0).get()
        .message.beacon_block_root == blockRoot0
      not db.getExecutionPayloadEnvelope(blockRoot1).isSome()
      db.getExecutionPayloadEnvelopeSZ(blockRoot0, data)
      not db.getExecutionPayloadEnvelopeSZ(blockRoot1, data)

    db.putExecutionPayloadEnvelope(envelope1)

    check:
      db.containsExecutionPayloadEnvelope(blockRoot0)
      db.containsExecutionPayloadEnvelope(blockRoot1)
      db.getExecutionPayloadEnvelope(blockRoot0).isSome()
      db.getExecutionPayloadEnvelope(blockRoot1).isSome()
      db.getExecutionPayloadEnvelopeSZ(blockRoot0, data)
      db.getExecutionPayloadEnvelopeSZ(blockRoot1, data)

    check db.delExecutionPayloadEnvelope(blockRoot0)

    check:
      not db.containsExecutionPayloadEnvelope(blockRoot0)
      db.containsExecutionPayloadEnvelope(blockRoot1)
      not db.getExecutionPayloadEnvelope(blockRoot0).isSome()
      db.getExecutionPayloadEnvelope(blockRoot1).isSome()
      not db.getExecutionPayloadEnvelopeSZ(blockRoot0, data)
      db.getExecutionPayloadEnvelopeSZ(blockRoot1, data)

    check db.delExecutionPayloadEnvelope(blockRoot1)

    check:
      not db.containsExecutionPayloadEnvelope(blockRoot0)
      not db.containsExecutionPayloadEnvelope(blockRoot1)
      not db.getExecutionPayloadEnvelope(blockRoot0).isSome()
      not db.getExecutionPayloadEnvelope(blockRoot1).isSome()
      not db.getExecutionPayloadEnvelopeSZ(blockRoot0, data)
      not db.getExecutionPayloadEnvelopeSZ(blockRoot1, data)

    db.close()

suite "Quarantine" & preset():
  setup:
    let
      db = BeaconChainDB.new("", cfg, inMemory = true)
      quarantine = db.getQuarantineDB()

  teardown:
    db.close()

  func genBlockRoot(index: int): Eth2Digest =
    var res: Eth2Digest
    let tmp = uint64(index).toBytesLE()
    copyMem(addr res.data[0], unsafeAddr tmp[0], sizeof(uint64))
    res

  func genKzgCommitment(index: int): KzgCommitment =
    var res: KzgCommitment
    let tmp = uint64(index).toBytesLE()
    copyMem(addr res.bytes[0], unsafeAddr tmp[0], sizeof(uint64))
    res

  func genBlobSidecar(
      index: int,
      slot: int,
      kzg_commitment: int,
      proposer_index: int
  ): BlobSidecar =
    BlobSidecar(
      index: BlobIndex(index),
      kzg_commitment: genKzgCommitment(kzg_commitment),
      signed_block_header: SignedBeaconBlockHeader(
        message: BeaconBlockHeader(
          slot: Slot(slot),
          proposer_index: uint64(proposer_index))))

  func genDataColumnSidecar(
      index: int,
      slot: int,
      proposer_index: int
  ): fulu.DataColumnSidecar =
    fulu.DataColumnSidecar(
      index: ColumnIndex(index),
      signed_block_header: SignedBeaconBlockHeader(
        message: BeaconBlockHeader(
          slot: Slot(slot),
          proposer_index: uint64(proposer_index))))

  proc cmp(
      a: openArray[ref BlobSidecar|ref fulu.DataColumnSidecar],
      b: openArray[ref BlobSidecar|ref fulu.DataColumnSidecar]
  ): bool =
    if len(a) != len(b):
      return false
    for index in 0 ..< len(a):
      if a[index][] != b[index][]:
        return false
    true

  proc generateBlobSidecars(): seq[ref BlobSidecar] =
    @[
      newClone(genBlobSidecar(0, 100, 10, 24)),
      newClone(genBlobSidecar(1, 100, 11, 24)),
      newClone(genBlobSidecar(2, 100, 12, 24)),
      newClone(genBlobSidecar(3, 100, 13, 24)),
      newClone(genBlobSidecar(4, 100, 14, 24)),
      newClone(genBlobSidecar(5, 100, 15, 24)),
      newClone(genBlobSidecar(6, 100, 16, 24)),
      newClone(genBlobSidecar(7, 100, 17, 24)),
      newClone(genBlobSidecar(8, 100, 18, 24))
    ]

  proc generateDataColumnSidecars(): seq[ref fulu.DataColumnSidecar] =
    @[
      newClone(genDataColumnSidecar(0, 200, 100234)),
      newClone(genDataColumnSidecar(7, 200, 100234)),
      newClone(genDataColumnSidecar(14, 200, 100234)),
      newClone(genDataColumnSidecar(21, 200, 100234)),
      newClone(genDataColumnSidecar(28, 200, 100234)),
      newClone(genDataColumnSidecar(35, 200, 100234)),
      newClone(genDataColumnSidecar(42, 200, 100234)),
      newClone(genDataColumnSidecar(49, 200, 100234)),
      newClone(genDataColumnSidecar(56, 200, 100234)),
      newClone(genDataColumnSidecar(63, 200, 100234)),
      newClone(genDataColumnSidecar(70, 200, 100234)),
      newClone(genDataColumnSidecar(77, 200, 100234)),
      newClone(genDataColumnSidecar(84, 200, 100234)),
      newClone(genDataColumnSidecar(91, 200, 100234)),
      newClone(genDataColumnSidecar(98, 200, 100234)),
      newClone(genDataColumnSidecar(127, 200, 100234)),
    ]

  proc getSidecars(
      quarantine: QuarantineDB,
      T: typedesc[BlobSidecar|fulu.DataColumnSidecar],
      blockRoot: Eth2Digest
  ): seq[ref T] =
    var res: seq[ref T]
    for item in quarantine.sidecars(T, blockRoot):
      res.add(newClone(item))
    res

  proc runDataSidecarTest(
      quarantine: QuarantineDB,
      T: typedesc[ForkyDataSidecar]
  ) =
    let
      broots = @[
        genBlockRoot(100), genBlockRoot(200), genBlockRoot(300)
      ]
      sidecars =
        when T is deneb.BlobSidecar:
          generateBlobSidecars()
        else:
          generateDataColumnSidecars()
      offsets =
        when T is deneb.BlobSidecar:
          @[(0, 8), (0, 3), (0, 5)]
        else:
          @[(0, 15), (4, 11), (0, 7)]

    check:
      len(quarantine.getSidecars(T, broots[0])) == 0
      len(quarantine.getSidecars(T, broots[1])) == 0
      len(quarantine.getSidecars(T, broots[2])) == 0
      quarantine.sidecarsCount(T) == 0

    quarantine.removeDataSidecars(T, broots[0])
    quarantine.removeDataSidecars(T, broots[1])
    quarantine.removeDataSidecars(T, broots[2])

    quarantine.putDataSidecars(broots[0],
      sidecars.toOpenArray(offsets[0][0], offsets[0][1]))

    block:
      let
        res1 = quarantine.getSidecars(T, broots[0])
      check:
        quarantine.sidecarsCount(T) == len(res1)
        len(res1) == (offsets[0][1] - offsets[0][0] + 1)
        cmp(res1, sidecars.toOpenArray(offsets[0][0], offsets[0][1])) == true
        len(quarantine.getSidecars(T, broots[1])) == 0
        len(quarantine.getSidecars(T, broots[2])) == 0

    quarantine.putDataSidecars(broots[1],
      sidecars.toOpenArray(offsets[1][0], offsets[1][1]))

    block:
      let
        res1 = quarantine.getSidecars(T, broots[0])
        res2 = quarantine.getSidecars(T, broots[1])
      check:
        quarantine.sidecarsCount(T) == len(res1) + len(res2)
        len(res1) == (offsets[0][1] - offsets[0][0] + 1)
        len(res2) == (offsets[1][1] - offsets[1][0] + 1)
        cmp(res1, sidecars.toOpenArray(offsets[0][0], offsets[0][1])) == true
        cmp(res2, sidecars.toOpenArray(offsets[1][0], offsets[1][1])) == true
        len(quarantine.getSidecars(T, broots[2])) == 0

    quarantine.putDataSidecars(broots[2],
      sidecars.toOpenArray(offsets[2][0], offsets[2][1]))

    block:
      let
        res1 = quarantine.getSidecars(T, broots[0])
        res2 = quarantine.getSidecars(T, broots[1])
        res3 = quarantine.getSidecars(T, broots[2])
      check:
        len(res1) == (offsets[0][1] - offsets[0][0] + 1)
        len(res2) == (offsets[1][1] - offsets[1][0] + 1)
        len(res3) == (offsets[2][1] - offsets[2][0] + 1)
        quarantine.sidecarsCount(T) == len(res1) + len(res2) + len(res3)
        cmp(res1, sidecars.toOpenArray(offsets[0][0], offsets[0][1])) == true
        cmp(res2, sidecars.toOpenArray(offsets[1][0], offsets[1][1])) == true
        cmp(res3, sidecars.toOpenArray(offsets[2][0], offsets[2][1])) == true

    quarantine.removeDataSidecars(T, broots[1])

    block:
      let
        res1 = quarantine.getSidecars(T, broots[0])
        res3 = quarantine.getSidecars(T, broots[2])
      check:
        len(res1) == (offsets[0][1] - offsets[0][0] + 1)
        cmp(res1, sidecars.toOpenArray(offsets[0][0], offsets[0][1])) == true
        len(quarantine.getSidecars(T, broots[1])) == 0
        len(res3) == (offsets[2][1] - offsets[2][0] + 1)
        cmp(res3, sidecars.toOpenArray(offsets[2][0], offsets[2][1])) == true
        quarantine.sidecarsCount(T) == len(res1) + len(res3)

    quarantine.removeDataSidecars(T, broots[0])

    block:
      let
        res3 = quarantine.getSidecars(T, broots[2])
      check:
        len(quarantine.getSidecars(T, broots[0])) == 0
        len(quarantine.getSidecars(T, broots[1])) == 0
        len(res3) == (offsets[2][1] - offsets[2][0] + 1)
        cmp(res3, sidecars.toOpenArray(offsets[2][0], offsets[2][1])) == true
        quarantine.sidecarsCount(T) == len(res3)

    quarantine.removeDataSidecars(T, broots[2])

    check:
      len(quarantine.getSidecars(T, broots[0])) == 0
      len(quarantine.getSidecars(T, broots[1])) == 0
      len(quarantine.getSidecars(T, broots[2])) == 0
      quarantine.sidecarsCount(T) == 0

  test "put/iterate/remove test [BlobSidecars]":
    quarantine.runDataSidecarTest(deneb.BlobSidecar)

  test "put/iterate/remove test [DataColumnSidecar]":
    quarantine.runDataSidecarTest(fulu.DataColumnSidecar)

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

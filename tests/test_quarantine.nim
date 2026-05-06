# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import stew/endians2,
       unittest2,
       ./testutil,
       ../beacon_chain/[beacon_chain_db, beacon_chain_db_quarantine],
       ../beacon_chain/spec/[helpers, column_map],
       ../beacon_chain/consensus_object_pools/column_quarantine

from std/sequtils import mapIt, toSeq

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

func genFuluDataColumnSidecar(
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

func genGloasDataColumnSidecar(
    index: int,
    slot: int,
): gloas.DataColumnSidecar =
  gloas.DataColumnSidecar(
    index: ColumnIndex(index),
    slot: Slot(slot))

func genFuluSignedBeaconBlock(
    blockRoot: Eth2Digest,
    commitments: openArray[KzgCommitment]
): fulu.SignedBeaconBlock =
  var res = @commitments
  fulu.SignedBeaconBlock(
    message: fulu.BeaconBlock(
      body: fulu.BeaconBlockBody(blob_kzg_commitments: KzgCommitments(res))),
    root: blockRoot)

func genGloasSignedExecutionPayloadEnvelope(
    blockRoot: Eth2Digest,
    _: openArray[KzgCommitment]
): gloas.SignedExecutionPayloadEnvelope =
  # GloasColumnQuarantine shouldn't care about kzg commitments so functions and
  # tests should be refactored.
  debugGloasComment("remove kzg commitments")
  gloas.SignedExecutionPayloadEnvelope(
    message: gloas.ExecutionPayloadEnvelope(
      beacon_block_root: blockRoot))

func compareSidecars(
    a, b: openArray[ref fulu.DataColumnSidecar | ref gloas.DataColumnSidecar]
): bool =
  if len(a) != len(b):
    return false
  if len(a) == 0:
    return true
  for i in 0 ..< len(a):
    if cast[uint64](a[i]) != cast[uint64](b[i]):
      return false
  true

func compareSidecarsByValue(
    a, b: openArray[ref fulu.DataColumnSidecar | ref gloas.DataColumnSidecar]
): bool =
  if len(a) != len(b):
    debugEcho "Length not equal"
    return false
  if len(a) == 0:
    return true
  for i in 0 ..< len(a):
    if a[i][] != b[i][]:
      debugEcho "data not equal"
      return false
  true

func compareSidecars(
    blockRoot: Eth2Digest,
    a: openArray[ref fulu.DataColumnSidecar | ref gloas.DataColumnSidecar],
    b: DataColumnsByRootIdentifier
): bool =
  if len(a) != len(b.indices):
    return false
  if len(a) == 0:
    return true
  if b.block_root != blockRoot:
    return false
  for i in 0 ..< len(a):
    if (a[i][].index != b.indices[i]):
      return false
  true

func compareIdentifiers(
  a, b: DataColumnsByRootIdentifier): bool =
  if len(a.indices) != len(b.indices):
    return false
  if a.block_root != b.block_root:
    return false
  if len(a.indices) == 0:
    return true
  for i in 0 ..< len(a.indices):
    if (a.indices[i] != b.indices[i]):
      return false
  true

func supernodeColumns(): seq[ColumnIndex] =
  var res: seq[ColumnIndex]
  for i in 0 ..< 128:
    res.add(ColumnIndex(i))
  res

suite "ColumnQuarantine data structure test suite " & preset():
  setup:
    let
      cfg {.used.} = defaultRuntimeConfig
      db {.used.} = BeaconChainDB.new("", cfg, inMemory = true)
      quarantine {.used.} = db.getQuarantineDB()

  teardown:
    db.close()

  test "put()/hasSidecar(index, slot, proposer_index)/remove() test":
    let custodyColumns =
      [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
    var bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      broot3 = genBlockRoot(3)
      broot4 = genBlockRoot(4)
      broot5 = genBlockRoot(5)
      sidecar1 =
        newClone(genFuluDataColumnSidecar(
          index = 0, slot = 1, proposer_index = 5))
      sidecar2 =
        newClone(genFuluDataColumnSidecar(
          index = 31, slot = 1, proposer_index = 5))
      sidecar3 =
        newClone(genFuluDataColumnSidecar(
          index = 32, slot = 1, proposer_index = 5))
      sidecar4 =
        newClone(genFuluDataColumnSidecar(
          index = 127, slot = 2, proposer_index = 6))
      sidecar5 =
        newClone(genFuluDataColumnSidecar(
          index = 0, slot = 3, proposer_index = 7))
      sidecar6 =
        newClone(genFuluDataColumnSidecar(
          index = 31, slot = 3, proposer_index = 8))

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == false
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(broot2, Slot(2), uint64(5), ColumnIndex(127)) == false
      bq.hasSidecar(broot3, Slot(3), uint64(5), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot1, sidecar1)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot1, sidecar2)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot1, sidecar3)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot2, sidecar4)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot3, sidecar5)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == true
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot4, sidecar6)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == true
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == true
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(broot4)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == true
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(broot3)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(broot2)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(broot1)

    check:
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(0)) == false
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(broot1, Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(broot2, Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(broot3, Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(broot4, Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(broot5, Slot(10), uint64(100), ColumnIndex(3)) == false
      len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [node] test":
    let custodyColumns =
      [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
    var bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 6)))
          res
      commitments1 = [
        genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
      ]
      commitments2 = [
        genKzgCommitment(4), genKzgCommitment(5), genKzgCommitment(6)
      ]
      fuluBlock1 = genFuluSignedBeaconBlock(broot1, commitments1)
      fuluBlock2 = genFuluSignedBeaconBlock(broot2, commitments2)

    check:
      bq.hasSidecars(fuluBlock1) == false
      bq.popSidecars(fuluBlock1.root).isNone() == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true

    bq.put(broot1, sidecars1)
    check:
      len(bq) == len(sidecars1)

    var counter = 0
    for index in 0 ..< len(sidecars2):
      if index notin [1, 3, 5, 7]:
        bq.put(broot2, sidecars2[index])
        inc(counter)
        check len(bq) == len(sidecars1) + counter

    check:
      bq.hasSidecars(fuluBlock1) == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true
    let dres = bq.popSidecars(fuluBlock1.root)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true
      len(bq) == counter

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true
      len(bq) == counter + 1

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true
      len(bq) == counter + 2

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true
      len(bq) == counter + 3

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(fuluBlock2) == true
      len(bq) == len(sidecars2)

    let eres = bq.popSidecars(fuluBlock2.root)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true
      len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [supernode] test":
    let custodyColumns = supernodeColumns()
    var bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 6)))
          res
      commitments1 = [
        genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
      ]
      commitments2 = [
        genKzgCommitment(4), genKzgCommitment(5), genKzgCommitment(6)
      ]
      fuluBlock1 = genFuluSignedBeaconBlock(broot1, commitments1)
      fuluBlock2 = genFuluSignedBeaconBlock(broot2, commitments2)

    check:
      bq.hasSidecars(fuluBlock1) == false
      bq.popSidecars(fuluBlock1.root).isNone() == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true

    bq.put(broot1, sidecars1)

    for index in 0 ..< len(sidecars2):
      if index notin [1, 3, 5, 7]:
        bq.put(broot2, sidecars2[index])

    check:
      bq.hasSidecars(fuluBlock1) == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true
    let dres = bq.popSidecars(fuluBlock1.root)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2.root).isNone() == true

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(fuluBlock2) == true

    let eres = bq.popSidecars(fuluBlock2.root)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true

    bq.remove(broot1)
    bq.remove(broot2)
    check len(bq) == 0

  test "put()/fetchMissingSidecars/remove test [node]":
    let
      custodyColumns =
        [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
      peerCustodyColumns1 =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      peerCustodyColumns2 =
        [1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))

    var bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      expected1 = [
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(64), 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(95), 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(96)]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[])
      ]
      sidecars1 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 2, proposer_index = 50)))
          res

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1)
        missing2 = bq.fetchMissingSidecars(broot2)
        missing3 =
          bq.fetchMissingSidecars(broot1, peerCustodyColumns1)
        missing4 =
          bq.fetchMissingSidecars(broot2, peerCustodyColumns2)

      check:
        compareSidecars(
          broot1,
          sidecars1.toOpenArray(i, len(sidecars1) - 1), missing1) == true
        compareSidecars(
          broot2,
          sidecars2.toOpenArray(i, len(sidecars2) - 1), missing2) == true

      check:
        compareIdentifiers(expected1[i], missing3)
        len(missing4.indices) == 0

      if i >= len(sidecars1):
        break

      bq.put(broot1, sidecars1[i])
      bq.put(broot2, sidecars2[i])

    bq.remove(broot1)
    bq.remove(broot2)
    check len(bq) == 0

  test "put()/fetchMissingSidecars/remove test [supernode]":
    let
      custodyColumns = supernodeColumns()
      peerCustodyColumns1 =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genFuluDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 2, proposer_index = 50)))
          res

    func checkSupernodeExpected(
      root: Eth2Digest,
      index: int,
      missing: DataColumnsByRootIdentifier
    ): bool =
      const ExpectedVectors = [
        (@[63, 64, 65, 66, 95, 96, 97, 98], 0 .. 57),
        (@[63, 64, 65, 66, 95, 96, 97], 58 .. 58),
        (@[63, 64, 65, 66, 95, 96], 59 .. 59),
        (@[63, 64, 65, 66, 95], 60 .. 60),
        (@[63, 64, 65, 66], 61 .. 61),
        (@[63, 64, 65], 62 .. 62),
        (@[63, 64], 63 .. 63),
        (@[64], 64 .. 64),
        (@[], 65 .. 65)
      ]

      doAssert(index in 0 .. 65)
      for expect in ExpectedVectors:
        if index in expect[1]:
          if len(expect[0]) != len(missing.indices):
            return false
          for i in 0 ..< len(missing.indices):
            if missing.block_root != root:
              return false
            if (int(missing.indices[i]) != expect[0][i]):
              return false
          return true
      false

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1)
        missing2 = bq.fetchMissingSidecars(broot2)
        missing3 =
          bq.fetchMissingSidecars(broot1, peerCustodyColumns1)
      check:
        compareSidecars(
          broot1,
          sidecars1.toOpenArray(i, len(sidecars1) - 1), missing1) == true
        compareSidecars(
          broot2,
          sidecars2.toOpenArray(i, len(sidecars2) - 1), missing2) == true
        checkSupernodeExpected(
          broot1,
          i, missing3) == true

      if i >= len(sidecars1):
        break

      bq.put(broot1, sidecars1[i])
      bq.put(broot2, sidecars2[i])

    bq.remove(broot1)
    bq.remove(broot2)
    check len(bq) == 0

  test "overfill protection test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var
      bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
      sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                          blockRoot: Eth2Digest]]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot = i div len(custodyColumns) + 100
        blockRoot = genBlockRoot(slot)
        sidecar = newClone(
          genFuluDataColumnSidecar(index = int(custodyColumns[index]),
                                   slot, proposer_index = i))
      sidecars.add((sidecar, blockRoot))

    for item in sidecars:
      bq.put(item.blockRoot, item.sidecar)

    check len(bq) == maxSidecars

    # put(sidecar) test

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(
        genFuluDataColumnSidecar(index = int(custodyColumns[0]),
                                 slot = 10000, proposer_index = 1000000))
      blockRoot = genBlockRoot(10000)
    check:
      bq.hasSidecar(blockRoot = blockRoot, slot = Slot(10000),
                    proposer_index = 1000000'u64,
                    index = custodyColumns[0]) == false
    bq.put(blockRoot, sidecar)
    check:
      len(bq) == (len(sidecars) - len(custodyColumns) + 1)
      bq.hasSidecar(blockRoot = blockRoot, slot = Slot(10000),
                    proposer_index = 1000000'u64,
                    index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[i].sidecar[].index
        ) == false

    # put(openArray[sidecar]) test

    let
      msidecars =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            let sidecar =
              newClone(genFuluDataColumnSidecar(index = int(custodyColumns[i]),
                                                slot = 100_000,
                                                proposer_index = 2000000))
            res.add(sidecar)
          res
      mblockRoot = genBlockRoot(20000)

    check:
      len(bq) == (len(sidecars) - len(custodyColumns) + 1)

    let beforeLength = len(bq)

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == false

    bq.put(mblockRoot, msidecars)
    check len(bq) == beforeLength

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == true

    for i in 0 ..< len(custodyColumns):
      let j = len(custodyColumns) + i
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[j].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars[j].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[j].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[j].sidecar[].index
        ) == false

  test "put() duplicate items should not affect counters [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
    var
      bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
      sidecars1: seq[ref fulu.DataColumnSidecar]
      sidecars1d: seq[ref fulu.DataColumnSidecar]
      sidecars2: seq[ref fulu.DataColumnSidecar]
      sidecars2d: seq[ref fulu.DataColumnSidecar]

    for index in custodyColumns:
      let
        sidecar1 = newClone(genFuluDataColumnSidecar(int(index), 1, 64))
        sidecar1d = newClone(genFuluDataColumnSidecar(int(index), 1, 64))
        sidecar2 = newClone(genFuluDataColumnSidecar(int(index), 2, 65))
        sidecar2d = newClone(genFuluDataColumnSidecar(int(index), 2, 65))
      sidecars1.add(sidecar1)
      sidecars1d.add(sidecar1d)
      sidecars2.add(sidecar2)
      sidecars2d.add(sidecar2d)

    let
      broot1 = genBlockRoot(100)
      broot2 = genBlockRoot(200)

    check:
      len(bq) == 0
      len(bq.fetchMissingSidecars(
        broot1, custodyColumns).indices) == len(custodyColumns)
      len(bq.fetchMissingSidecars(
        broot2, custodyColumns).indices) == len(custodyColumns)

    for index in 0 ..< len(custodyColumns):
      bq.put(broot1, sidecars1[index])
      check:
        len(bq) == (index + 1)
        len(bq.fetchMissingSidecars(
          broot1, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)
      bq.put(broot1, sidecars1d[index])
      check:
        len(bq) == (index + 1)
        len(bq.fetchMissingSidecars(
          broot1, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)

    for index in 0 ..< len(custodyColumns):
      bq.put(broot2, sidecars2[index])
      check:
        len(bq) == len(custodyColumns) + (index + 1)
        len(bq.fetchMissingSidecars(
          broot2, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)
      bq.put(broot2, sidecars2d[index])
      check:
        len(bq) == len(custodyColumns) + (index + 1)
        len(bq.fetchMissingSidecars(
          broot2, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)

    bq.remove(broot2)
    check len(bq) == len(custodyColumns)
    bq.remove(broot1)
    check len(bq) == 0

  test "pruneAfterFinalization() test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    const TestVectors = [
      (root: 1, slot: 1, index: 63, proposer_index: 20),
      (root: 1, slot: 1, index: 64, proposer_index: 20),
      (root: 1, slot: 1, index: 65, proposer_index: 20),
      (root: 1, slot: 1, index: 66, proposer_index: 20),
      (root: 1, slot: 1, index: 96, proposer_index: 20),
      (root: 2, slot: 32, index: 63, proposer_index: 21),
      (root: 2, slot: 32, index: 64, proposer_index: 21),
      (root: 2, slot: 32, index: 65, proposer_index: 21),
      (root: 3, slot: 33, index: 63, proposer_index: 22),
      (root: 3, slot: 33, index: 64, proposer_index: 22),
      (root: 4, slot: 63, index: 63, proposer_index: 23),
      (root: 5, slot: 64, index: 63, proposer_index: 24),
      (root: 5, slot: 64, index: 64, proposer_index: 24),
      (root: 5, slot: 64, index: 65, proposer_index: 24),
      (root: 6, slot: 65, index: 63, proposer_index: 25),
      (root: 6, slot: 65, index: 64, proposer_index: 25),
      (root: 7, slot: 67, index: 63, proposer_index: 26),
      (root: 7, slot: 67, index: 64, proposer_index: 26),
      (root: 8, slot: 95, index: 63, proposer_index: 27),
      (root: 8, slot: 95, index: 64, proposer_index: 27),
      (root: 8, slot: 95, index: 65, proposer_index: 27),
      (root: 8, slot: 95, index: 66, proposer_index: 27),
      (root: 8, slot: 95, index: 98, proposer_index: 27),
      (root: 9, slot: 96, index: 63, proposer_index: 28),
      (root: 9, slot: 96, index: 64, proposer_index: 28),
      (root: 9, slot: 96, index: 65, proposer_index: 28),
      (root: 9, slot: 96, index: 66, proposer_index: 28),
      (root: 9, slot: 96, index: 95, proposer_index: 28),
      (root: 9, slot: 96, index: 96, proposer_index: 28),
      (root: 9, slot: 96, index: 97, proposer_index: 28),
      (root: 9, slot: 96, index: 98, proposer_index: 28),
      (root: 10, slot: 127, index: 96, proposer_index: 29),
      (root: 10, slot: 127, index: 97, proposer_index: 29),
      (root: 10, slot: 127, index: 98, proposer_index: 29)
    ]

    var bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    for item in TestVectors:
      let sidecar =
        newClone(
          genFuluDataColumnSidecar(index = item.index, slot = item.slot,
                                   proposer_index = item.proposer_index))
      bq.put(genBlockRoot(item.root), sidecar)

    check:
      len(bq) == len(TestVectors)

    for item in TestVectors:
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          uint64(item.proposer_index), ColumnIndex(item.index)) == true

    bq.pruneAfterFinalization(Epoch(0), false)
    check:
      len(bq) == len(TestVectors) - 5

    for item in TestVectors:
      let res =
        if item.root == 1:
          false
        else:
          true
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          uint64(item.proposer_index), ColumnIndex(item.index)) == res

    bq.pruneAfterFinalization(Epoch(1), false)
    check:
      len(bq) == len(TestVectors) - 5 - 6

    for item in TestVectors:
      let res =
        if item.root in [1, 2, 3, 4]:
          false
        else:
          true
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          uint64(item.proposer_index), ColumnIndex(item.index)) == res

    bq.pruneAfterFinalization(Epoch(2), false)
    check:
      len(bq) == len(TestVectors) - 5 - 6 - 12

    for item in TestVectors:
      let res =
        if item.root in [1, 2, 3, 4, 5, 6, 7, 8]:
          false
        else:
          true
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          uint64(item.proposer_index), ColumnIndex(item.index)) == res

    bq.pruneAfterFinalization(Epoch(3), false)
    check:
      len(bq) == 0

    for item in TestVectors:
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          uint64(item.proposer_index), ColumnIndex(item.index)) == false

  test "database unload/load test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var
      bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
      sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                          blockRoot: Eth2Digest]]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot = i div len(custodyColumns) + 100
        blockRoot = genBlockRoot(slot)
        sidecar = newClone(
          genFuluDataColumnSidecar(index = int(custodyColumns[index]),
                                   slot, proposer_index = i))
      sidecars.add((sidecar, blockRoot))

    for item in sidecars:
      bq.put(item.blockRoot, item.sidecar)

    # put(sidecar) test

    check:
      len(bq) == maxSidecars
      lenMemory(bq) == maxSidecars
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(
        genFuluDataColumnSidecar(index = int(custodyColumns[0]), slot = 10000,
                                 proposer_index = 1000000))
      blockRoot1 = genBlockRoot(10000)
    check:
      bq.hasSidecar(
        blockRoot = blockRoot1, slot = Slot(10000),
        proposer_index = 1000000'u64, index = custodyColumns[0]) == false

    bq.put(blockRoot1, sidecar)

    check:
      len(bq) == len(sidecars) + 1
      lenDisk(bq) == len(custodyColumns)
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) ==
        len(custodyColumns)
      lenMemory(bq) == len(sidecars) - len(custodyColumns) + 1
      bq.hasSidecar(
        blockRoot = blockRoot1, slot = Slot(10000),
        proposer_index = 1000000'u64, index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      blockRoot2 =
        genBlockRoot(
          int(sidecars[0].sidecar[].signed_block_header.message.slot))
      sidecars2 =
        sidecars.toOpenArray(0, len(custodyColumns) - 1).mapIt(it.sidecar)
      dres = bq.popSidecars(blockRoot2)

    check:
      dres.isOk()
      compareSidecarsByValue(dres.get(), sidecars2) == true
      len(bq) == len(sidecars) - len(custodyColumns) + 1
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0

    # put(openArray[sidecar]) test

    let
      msidecars =
        block:
          var res: seq[ref fulu.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            let sidecar =
              newClone(
                genFuluDataColumnSidecar(
                  index = int(custodyColumns[i]), slot = 100_000,
                  proposer_index = 2000000))
            res.add(sidecar)
          res
      mblockRoot = genBlockRoot(20000)

    check:
      len(bq) == len(sidecars) - len(custodyColumns) + 1

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == false

    bq.put(mblockRoot, msidecars)

    check:
      lenDisk(bq) == len(custodyColumns)
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) ==
        len(custodyColumns)
      len(bq) == len(sidecars) + 1

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == true

    for i in 0 ..< len(custodyColumns):
      let j = len(custodyColumns) + i
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[j].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars[j].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[j].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[j].sidecar[].index
        ) == true

    let
      i3 = len(custodyColumns)
      blockRoot3 =
        genBlockRoot(
          int(sidecars[i3].sidecar[].signed_block_header.message.slot))
      sidecars3 =
        sidecars.toOpenArray(i3, i3 + len(custodyColumns) - 1).
          mapIt(it.sidecar)
      dres3 = bq.popSidecars(blockRoot3)

    check:
      dres3.isOk()
      compareSidecarsByValue(dres3.get(), sidecars3) == true
      len(bq) == len(sidecars) - len(custodyColumns) + 1
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0

  test "database and memory overfill protection and pruning test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
    var
      bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 1, nil)
      sidecars1: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                           blockRoot: Eth2Digest]]
      sidecars2: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                           blockRoot: Eth2Digest]]
      epochs1: seq[Epoch]
      epochs2: seq[Epoch]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot1 = i div len(custodyColumns) + 100
        slot2 = i div len(custodyColumns) + 100000
        epoch1 = Slot(slot1).epoch()
        epoch2 = Slot(slot2).epoch()
        blockRoot1 = genBlockRoot(slot1)
        blockRoot2 = genBlockRoot(slot2)
        sidecar1 = newClone(
          genFuluDataColumnSidecar(int(custodyColumns[index]), slot1,
            proposer_index = i))
        sidecar2 = newClone(
          genFuluDataColumnSidecar(int(custodyColumns[index]), slot2,
            proposer_index = 100 + i))

      sidecars1.add((sidecar1, blockRoot1))
      sidecars2.add((sidecar2, blockRoot2))
      if len(epochs1) == 0 or epochs1[^1] != epoch1:
        epochs1.add(epoch1)
      if len(epochs2) == 0 or epochs2[^1] != epoch2:
        epochs2.add(epoch2)

    for item in sidecars1:
      bq.put(item.blockRoot, item.sidecar)

    check:
      len(bq) == len(sidecars1)
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0

    for i in 0 ..< (maxSidecars div len(custodyColumns)):
      let
        start = len(custodyColumns) * int(i)
        finish = start + len(custodyColumns) - 1
        blockRoot = sidecars2[start].blockRoot
        sidecars = sidecars2.toOpenArray(start, finish).mapIt(it.sidecar)
      bq.put(blockRoot, sidecars)

    check:
      len(bq) == len(sidecars1) + len(sidecars2)
      lenDisk(bq) == len(sidecars1)
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) ==
        len(sidecars1)
      lenMemory(bq) == len(sidecars2)

    for i in 0 ..< len(sidecars1):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars1[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars1[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars1[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars1[i].sidecar[].index
        ) == true

    for i in 0 ..< len(sidecars2):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars2[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars2[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars2[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars2[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(genFuluDataColumnSidecar(
        index = int(custodyColumns[0]), slot = 1000000,
        proposer_index = 2000000))
      blockRoot = genBlockRoot(1000000)

    check:
      bq.hasSidecar(blockRoot = blockRoot, slot = Slot(1000000),
                    proposer_index = 2000000'u64,
                    index = custodyColumns[0]) == false

    bq.put(blockRoot, sidecar)

    check:
      len(bq) == len(sidecars1) + len(sidecars2) - len(custodyColumns) + 1
      lenDisk(bq) == len(sidecars1)
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == len(sidecars1)
      lenMemory(bq) == len(sidecars2) - len(custodyColumns) + 1
      bq.hasSidecar(
        blockRoot = blockRoot, slot = Slot(1000000),
        proposer_index = 2000000'u64, index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars1[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars1[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars1[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars1[i].sidecar[].index
        ) == false

    for i in len(custodyColumns) ..< len(sidecars1):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars1[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars1[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars1[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars1[i].sidecar[].index
        ) == true

    for i in 0 ..< len(sidecars2):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars2[i].sidecar[].signed_block_header.message.slot)),
          slot =
            sidecars2[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars2[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars2[i].sidecar[].index
        ) == true

    # Pruning memory and database
    for epoch in epochs1:
      bq.pruneAfterFinalization(epoch, false)
    for epoch in epochs2:
      bq.pruneAfterFinalization(epoch, false)

    check:
      len(bq) == 1

    bq.pruneAfterFinalization(Slot(1000000).epoch(), false)

    check:
      len(bq) == 0
      quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0

  const ColumnsVectors = [
    ("node", [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))),
    ("supernode", supernodeColumns())
  ]

  for cvec in ColumnsVectors:
    test "overfill test [" & cvec[0] & "]":
      let custodyColumns = cvec[1]
      var
        bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      let maximumSidecars = bq.size * 2

      for i in 0 ..< maximumSidecars:
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genFuluDataColumnSidecar(int(custodyColumns[index]),
            slot, proposer_index = i))
        sidecars.add((sidecar, blockRoot))

      for item in sidecars:
        bq.put(item.blockRoot, item.sidecar)

      # At this stage only last sidecars in range
      # [maxSidecars - quarantine.size, maxSidecars] should be present in
      # quarantine.
      let
        startPosition = maximumSidecars - bq.size()

      for i in startPosition ..< maximumSidecars:
        let
          item =
            sidecars[i]
          slot =
            item.sidecar[].signed_block_header.message.slot
          proposerIndex =
            item.sidecar[].signed_block_header.message.proposer_index
          index =
            item.sidecar[].index

        check:
          bq.hasSidecar(
            blockRoot = item.blockRoot, slot = slot,
            proposer_index = proposerIndex, index = index) == true

      for i in 0 ..< startPosition:
        let
          item =
            sidecars[i]
          slot =
            item.sidecar[].signed_block_header.message.slot
          proposerIndex =
            item.sidecar[].signed_block_header.message.proposer_index
          index =
            item.sidecar[].index

        check:
          bq.hasSidecar(
            blockRoot = item.blockRoot, slot = slot,
            proposer_index = proposerIndex, index = index) == false

    test "Empty in-memory scenario test [" & cvec[0] & "]":
      let custodyColumns = cvec[1]
      var
        bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      let size = bq.sizeMemory * 2
        # full size of quarantine is bq.sizeMemory + bq.sizeMemory * 2
      for i in 0 ..< size:
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genFuluDataColumnSidecar(int(custodyColumns[index]),
            slot, proposer_index = i))
        sidecars.add((sidecar, blockRoot))

      for item in sidecars:
        bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()
        bq.lenDisk() == bq.sizeMemory()

      # At this stage we have full in memory store and partially filled disk store

      for i in bq.sizeMemory ..< size:
        let blockRoot = sidecars[i].blockRoot
        bq.remove(blockRoot)

      # At this stage we removed all the in-memory roots.
      check:
        bq.lenMemory() == 0
        bq.lenDisk() == bq.sizeMemory()

      var
        sidecars2: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                             blockRoot: Eth2Digest]]

      for i in 0 ..< len(custodyColumns):
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 1000000
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genFuluDataColumnSidecar(int(custodyColumns[index]),
            slot, proposer_index = i))
        sidecars2.add((sidecar, blockRoot))

      # Now we should be able to add new columns to in-memory storage.
      for item in sidecars2:
        bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == len(custodyColumns)
        bq.lenDisk() == bq.sizeMemory()

    test "Mixed entries scenario test [" & cvec[0] & "]":
      let custodyColumns = cvec[1]
      var
        bq = ColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      let maximumSidecars = bq.size * 2

      for i in 0 ..< maximumSidecars:
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genFuluDataColumnSidecar(int(custodyColumns[index]),
            slot, proposer_index = i))
        sidecars.add((sidecar, blockRoot))

      case cvec[0]
      of "node":
        # Add only first 3 sidecars for first block
        for i in 0 ..< 3:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add only first 5 sidecars for second block
        for i in 8 ..< 13:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add all other sidecars
        for item in sidecars.toOpenArray(16, bq.sizeMemory - 1):
          bq.put(item.blockRoot, item.sidecar)
      of "supernode":
        # Add only 64 sidecars for first block.
        for i in 0 ..< 64:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add only 64 sidecars for second block.
        for i in 128 ..< 192:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add all other sidecars
        for item in sidecars.toOpenArray(256, bq.sizeMemory - 1):
          bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory() - len(custodyColumns)

      # Adding last block which could fit in memory
      block:
        let offset = bq.sizeMemory()
        for i in 0 ..< len(custodyColumns):
          let item = sidecars[offset + i]
          bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()

      # Adding block which should overfill memory storage and our two non-100%
      # filled blocks should be offloaded to disk.
      block:
        let offset = bq.sizeMemory() + len(custodyColumns)
        for i in 0 ..< len(custodyColumns):
          let item = sidecars[offset + i]
          bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()
        bq.lenDisk() == len(custodyColumns)

      # Checking columns are in place.
      case cvec[0]
      of "node":
        for i in [0, 1, 2, 8, 9, 10, 11, 12]:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].signed_block_header.message.slot,
              sidecars[i].sidecar[].signed_block_header.message.proposer_index,
              sidecars[i].sidecar[].index
            ) == true
        for i in [3, 4, 5, 6, 7, 13, 14, 15]:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].signed_block_header.message.slot,
              sidecars[i].sidecar[].signed_block_header.message.proposer_index,
              sidecars[i].sidecar[].index
            ) == false
      of "supernode":
        for i in 0 ..< 64:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].signed_block_header.message.slot,
              sidecars[i].sidecar[].signed_block_header.message.proposer_index,
              sidecars[i].sidecar[].index
            ) == true

        for i in 128 ..< 192:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].signed_block_header.message.slot,
              sidecars[i].sidecar[].signed_block_header.message.proposer_index,
              sidecars[i].sidecar[].index
            ) == true

        for i in 64 ..< 128:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].signed_block_header.message.slot,
              sidecars[i].sidecar[].signed_block_header.message.proposer_index,
              sidecars[i].sidecar[].index
            ) == false

        for i in 192 ..< 256:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].signed_block_header.message.slot,
              sidecars[i].sidecar[].signed_block_header.message.proposer_index,
              sidecars[i].sidecar[].index
            ) == false

      let
        commitments = [
          genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
        ]
        block1 = genFuluSignedBeaconBlock(
          sidecars[0].blockRoot, commitments)
        block2 = genFuluSignedBeaconBlock(
          sidecars[0 + len(custodyColumns)].blockRoot, commitments)

      # Both blocks should be incomplete.
      check:
        bq.hasSidecars(block1) == false
        bq.hasSidecars(block2) == false

      case cvec[0]
      of "node":
        # Add last 5 sidecars for first block
        for i in 3 ..< 8:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add last 3 sidecars for second block
        for i in 13 ..< 16:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
      of "supernode":
        # Add last 64 sidecars for first block.
        for i in 64 ..< 128:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add last 64 sidecars for second block.
        for i in 192 ..< 256:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()
        bq.lenDisk() == len(custodyColumns) * 2
        bq.hasSidecars(block1) == true
        bq.hasSidecars(block2) == true

      let sidecars1 = bq.popSidecars(sidecars[0].blockRoot)
      check:
        sidecars1.isSome() == true
      case cvec[0]
      of "node":
        check:
          bq.lenMemory() == bq.sizeMemory() - 5
          bq.lenDisk() == len(custodyColumns) * 2 - 3
      of "supernode":
        check:
          bq.lenMemory() == bq.sizeMemory() - 64
          bq.lenDisk() == len(custodyColumns) * 2 - 64

      let sidecars2 = bq.popSidecars(sidecars[len(custodyColumns)].blockRoot)

      check:
        sidecars2.isSome() == true
        bq.lenMemory() == bq.sizeMemory() - len(custodyColumns)
        bq.lenDisk() == len(custodyColumns) * 2 - len(custodyColumns)

      let
        expect1 =
          case cvec[0]
          of "node":
            let
              start = 0
              finish = len(custodyColumns)
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          of "supernode":
            # In case of super node quarantine returns
            # NUMBER_OF_COLUMNS div 2 + 1 columns which is enough for
            # rebuild.
            let
              start = 0
              finish = len(custodyColumns) div 2 + 1
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          else:
            raiseAssert "inaccessible"
        expect2 =
          case cvec[0]
          of "node":
            let
              start = len(custodyColumns)
              finish = start + len(custodyColumns)
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          of "supernode":
            # In case of super node quarantine returns
            # NUMBER_OF_COLUMNS div 2 + 1 columns which is enough for
            # rebuild.
            let
              start = len(custodyColumns)
              finish = start + len(custodyColumns) div 2 + 1
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          else:
            raiseAssert "inaccessible"

      check:
        compareSidecarsByValue(sidecars1.get(), expect1) == true
        compareSidecarsByValue(sidecars2.get(), expect2) == true

  const
    EmptyTests = [
      (
        "empty:grow", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))
      ),
      (
        "empty:grow", "node->supernode",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        supernodeColumns()
      ),
      (
        "empty:shrink", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      ),
      (
        "empty:shrink", "supernode->node",
        supernodeColumns(),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      )
    ]

  for vtest in EmptyTests:
    test "ColumnQuarantine: update(" & vtest[0] & ") [" & vtest[1] & "] test":
      var bq = ColumnQuarantine.init(cfg, vtest[2], quarantine, 2, nil)

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      bq.update(cfg, vtest[3])

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[3])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())

  const
    MemoryTests = [
      (
        "memory:grow", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))
      ),
      (
        "memory:grow", "node->supernode",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        supernodeColumns()
      ),
      (
        "memory:shrink", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      ),
      (
        "memory:shrink", "supernode->node",
        supernodeColumns(),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      )
    ]


  for vtest in MemoryTests:
    test "ColumnQuarantine: update(" & vtest[0] & ") [" & vtest[1] & "] test":
      var
        bq = ColumnQuarantine.init(cfg, vtest[2], quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      for i in 0 ..< bq.sizeMemory():
        let
          index = i mod len(bq.custodyColumns)
          slot = i div len(bq.custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genFuluDataColumnSidecar(
            int(bq.custodyColumns[index]), slot, proposer_index = i))
        sidecars.add((sidecar, blockRoot))
        bq.put(blockRoot, sidecar)

      let rootsCount = bq.sizeMemory() div len(bq.custodyColumns)

      check:
        len(bq) == bq.sizeMemory()
        lenDisk(bq) == 0
        lenMemory(bq) == bq.sizeMemory()
        quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      bq.update(cfg, vtest[3])

      if vtest[0] == "memory:grow":
        check:
          len(bq) == bq.sizeMemory()
          lenDisk(bq) == 0
          lenMemory(bq) == bq.sizeMemory()
          quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())
      else:
        check:
          len(bq) == rootsCount * len(bq.custodyMap)
          lenDisk(bq) == 0
          lenMemory(bq) == rootsCount * len(bq.custodyMap)
          quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())

      for item in sidecars:
        if item.sidecar[].index in bq.custodyMap:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].signed_block_header.message.slot,
              item.sidecar[].signed_block_header.message.proposer_index,
              item.sidecar[].index) == true
        else:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].signed_block_header.message.slot,
              item.sidecar[].signed_block_header.message.proposer_index,
              item.sidecar[].index) == false

  const
    MemoryDiskTests = [
      (
        "memory+disk:grow", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))
      ),
      (
        "memory+disk:grow", "node->supernode",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        supernodeColumns()
      ),
      (
        "memory+disk:shrink", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      ),
      (
        "memory+disk:shrink", "supernode->node",
        supernodeColumns(),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      )
    ]

  for vtest in MemoryDiskTests:
    test "ColumnQuarantine: update(" & vtest[0] & ") [" & vtest[1] & "] test":
      var
        bq = ColumnQuarantine.init(cfg, vtest[2], quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref fulu.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      for i in 0 ..< bq.sizeMemory() * 2:
        let
          index = i mod len(bq.custodyColumns)
          slot = i div len(bq.custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genFuluDataColumnSidecar(
            int(bq.custodyColumns[index]), slot, proposer_index = i))
        sidecars.add((sidecar, blockRoot))
        bq.put(blockRoot, sidecar)

      let rootsCount = (bq.sizeMemory() * 2) div len(bq.custodyColumns)

      check:
        len(bq) == bq.sizeMemory() * 2
        lenDisk(bq) == bq.sizeMemory()
        lenMemory(bq) == bq.sizeMemory()
        quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) ==
          lenDisk(bq)
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      bq.update(cfg, vtest[3])

      if vtest[0] == "memory+disk:grow":
        check:
          len(bq) == bq.sizeMemory() * 2
          lenDisk(bq) == bq.sizeMemory()
          lenMemory(bq) == bq.sizeMemory()
          quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) ==
            bq.sizeMemory()
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())
      else:
        check:
          len(bq) == rootsCount * len(bq.custodyMap)
          lenDisk(bq) == (rootsCount div 2) * len(bq.custodyMap)
          lenMemory(bq) == (rootsCount div 2) * len(bq.custodyMap)
        # Because we do not do database cleanup immediately database actually
        # holds all the values which was present before update.
        check:
          quarantine.sidecarsCount(typedesc[fulu.DataColumnSidecar]) ==
            bq.sizeMemory()
        check:
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())

      for item in sidecars:
        if item.sidecar[].index in bq.custodyMap:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].signed_block_header.message.slot,
              item.sidecar[].signed_block_header.message.proposer_index,
              item.sidecar[].index) == true
        else:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].signed_block_header.message.slot,
              item.sidecar[].signed_block_header.message.proposer_index,
              item.sidecar[].index) == false

suite "GloasColumnQuarantine data structure test suite " & preset():
  setup:
    let
      cfg {.used.} = defaultRuntimeConfig
      db {.used.} = BeaconChainDB.new("", cfg, inMemory = true)
      quarantine {.used.} = db.getQuarantineDB()

  teardown:
    db.close()

  test "put()/hasSidecar(index, slot, proposer_index)/remove() test":
    let custodyColumns =
      [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
    var bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      broot3 = genBlockRoot(3)
      broot4 = genBlockRoot(4)
      broot5 = genBlockRoot(5)
      sidecar1 =
        newClone(genGloasDataColumnSidecar(index = 0, slot = 1))
      sidecar2 =
        newClone(genGloasDataColumnSidecar(index = 31, slot = 1))
      sidecar3 =
        newClone(genGloasDataColumnSidecar(index = 32, slot = 1))
      sidecar4 =
        newClone(genGloasDataColumnSidecar(index = 127, slot = 2))
      sidecar5 =
        newClone(genGloasDataColumnSidecar(index = 0, slot = 3))
      sidecar6 =
        newClone(genGloasDataColumnSidecar(index = 31, slot = 3))

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == false
      bq.hasSidecar(broot1, ColumnIndex(31)) == false
      bq.hasSidecar(broot1, ColumnIndex(32)) == false
      bq.hasSidecar(broot2, ColumnIndex(127)) == false
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.put(broot1, sidecar1)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == false
      bq.hasSidecar(broot1, ColumnIndex(32)) == false
      bq.hasSidecar(broot2, ColumnIndex(127)) == false
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.put(broot1, sidecar2)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == false
      bq.hasSidecar(broot2, ColumnIndex(127)) == false
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.put(broot1, sidecar3)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == false
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.put(broot2, sidecar4)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == true
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.put(broot3, sidecar5)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == true
      bq.hasSidecar(broot3, ColumnIndex(0)) == true
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.put(broot4, sidecar6)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == true
      bq.hasSidecar(broot3, ColumnIndex(0)) == true
      bq.hasSidecar(broot4, ColumnIndex(31)) == true
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.remove(broot4)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == true
      bq.hasSidecar(broot3, ColumnIndex(0)) == true
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.remove(broot3)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == true
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.remove(broot2)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == true
      bq.hasSidecar(broot1, ColumnIndex(31)) == true
      bq.hasSidecar(broot1, ColumnIndex(32)) == true
      bq.hasSidecar(broot2, ColumnIndex(127)) == false
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false

    bq.remove(broot1)

    check:
      bq.hasSidecar(broot1, ColumnIndex(0)) == false
      bq.hasSidecar(broot1, ColumnIndex(31)) == false
      bq.hasSidecar(broot1, ColumnIndex(32)) == false
      bq.hasSidecar(broot2, ColumnIndex(127)) == false
      bq.hasSidecar(broot3, ColumnIndex(0)) == false
      bq.hasSidecar(broot4, ColumnIndex(31)) == false
      bq.hasSidecar(broot5, ColumnIndex(3)) == false
      len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [node] test":
    let custodyColumns =
      [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
    var bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1)))
          res
      sidecars2 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1)))
          res
      commitments1 = [
        genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
      ]
      commitments2 = [
        genKzgCommitment(4), genKzgCommitment(5), genKzgCommitment(6)
      ]
      envl1 = genGloasSignedExecutionPayloadEnvelope(broot1, commitments1)
      envl2 = genGloasSignedExecutionPayloadEnvelope(broot2, commitments2)

    check:
      bq.hasSidecars(envl1) == false
      bq.popSidecars(broot1).isNone() == true
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true

    bq.put(broot1, sidecars1)
    check:
      len(bq) == len(sidecars1)

    var counter = 0
    for index in 0 ..< len(sidecars2):
      if index notin [1, 3, 5, 7]:
        bq.put(broot2, sidecars2[index])
        inc(counter)
        check len(bq) == len(sidecars1) + counter

    check:
      bq.hasSidecars(envl1) == true
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true
    let dres = bq.popSidecars(broot1)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true
      len(bq) == counter

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true
      len(bq) == counter + 1

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true
      len(bq) == counter + 2

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true
      len(bq) == counter + 3

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(envl2) == true
      len(bq) == len(sidecars2)

    let eres = bq.popSidecars(broot2)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true
      len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [supernode] test":
    let custodyColumns = supernodeColumns()
    var bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1)))
          res
      sidecars2 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1)))
          res
      commitments1 = [
        genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
      ]
      commitments2 = [
        genKzgCommitment(4), genKzgCommitment(5), genKzgCommitment(6)
      ]
      envl1 = genGloasSignedExecutionPayloadEnvelope(broot1, commitments1)
      envl2 = genGloasSignedExecutionPayloadEnvelope(broot2, commitments2)

    check:
      bq.hasSidecars(envl1) == false
      bq.popSidecars(broot1).isNone() == true
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true

    bq.put(broot1, sidecars1)

    for index in 0 ..< len(sidecars2):
      if index notin [1, 3, 5, 7]:
        bq.put(broot2, sidecars2[index])

    check:
      bq.hasSidecars(envl1) == true
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true
    let dres = bq.popSidecars(broot1)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(envl2) == false
      bq.popSidecars(broot2).isNone() == true

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(envl2) == true

    let eres = bq.popSidecars(broot2)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true

    bq.remove(broot1)
    bq.remove(broot2)
    check len(bq) == 0

  test "put()/fetchMissingSidecars/remove test [node]":
    let
      custodyColumns =
        [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
      peerCustodyColumns1 =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      peerCustodyColumns2 =
        [1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))

    var bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      expected1 = [
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(63), 64, 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(64), 95, 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(95), 96]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[ColumnIndex(96)]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[]),
        DataColumnsByRootIdentifier(
          block_root: broot1,
          indices: DataColumnIndices @[])
      ]
      sidecars1 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1)))
          res
      sidecars2 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 2)))
          res

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1)
        missing2 = bq.fetchMissingSidecars(broot2)
        missing3 =
          bq.fetchMissingSidecars(broot1, peerCustodyColumns1)
        missing4 =
          bq.fetchMissingSidecars(broot2, peerCustodyColumns2)

      check:
        compareSidecars(
          broot1,
          sidecars1.toOpenArray(i, len(sidecars1) - 1), missing1) == true
        compareSidecars(
          broot2,
          sidecars2.toOpenArray(i, len(sidecars2) - 1), missing2) == true

      check:
        compareIdentifiers(expected1[i], missing3)
        len(missing4.indices) == 0

      if i >= len(sidecars1):
        break

      bq.put(broot1, sidecars1[i])
      bq.put(broot2, sidecars2[i])

    bq.remove(broot1)
    bq.remove(broot2)
    check len(bq) == 0

  test "put()/fetchMissingSidecars/remove test [supernode]":
    let
      custodyColumns = supernodeColumns()
      peerCustodyColumns1 =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1)))
          res
      sidecars2 =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genGloasDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 2)))
          res

    func checkSupernodeExpected(
      root: Eth2Digest,
      index: int,
      missing: DataColumnsByRootIdentifier
    ): bool =
      const ExpectedVectors = [
        (@[63, 64, 65, 66, 95, 96, 97, 98], 0 .. 57),
        (@[63, 64, 65, 66, 95, 96, 97], 58 .. 58),
        (@[63, 64, 65, 66, 95, 96], 59 .. 59),
        (@[63, 64, 65, 66, 95], 60 .. 60),
        (@[63, 64, 65, 66], 61 .. 61),
        (@[63, 64, 65], 62 .. 62),
        (@[63, 64], 63 .. 63),
        (@[64], 64 .. 64),
        (@[], 65 .. 65)
      ]

      doAssert(index in 0 .. 65)
      for expect in ExpectedVectors:
        if index in expect[1]:
          if len(expect[0]) != len(missing.indices):
            return false
          for i in 0 ..< len(missing.indices):
            if missing.block_root != root:
              return false
            if (int(missing.indices[i]) != expect[0][i]):
              return false
          return true
      false

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1)
        missing2 = bq.fetchMissingSidecars(broot2)
        missing3 =
          bq.fetchMissingSidecars(broot1, peerCustodyColumns1)
      check:
        compareSidecars(
          broot1,
          sidecars1.toOpenArray(i, len(sidecars1) - 1), missing1) == true
        compareSidecars(
          broot2,
          sidecars2.toOpenArray(i, len(sidecars2) - 1), missing2) == true
        checkSupernodeExpected(
          broot1,
          i, missing3) == true

      if i >= len(sidecars1):
        break

      bq.put(broot1, sidecars1[i])
      bq.put(broot2, sidecars2[i])

    bq.remove(broot1)
    bq.remove(broot2)
    check len(bq) == 0

  test "overfill protection test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var
      bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
      sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                          blockRoot: Eth2Digest]]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot = i div len(custodyColumns) + 100
        blockRoot = genBlockRoot(slot)
        sidecar = newClone(
          genGloasDataColumnSidecar(
            index = int(custodyColumns[index]), slot))
      sidecars.add((sidecar, blockRoot))

    for item in sidecars:
      bq.put(item.blockRoot, item.sidecar)

    check len(bq) == maxSidecars

    # put(sidecar) test

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].slot)),
          slot =
            sidecars[i].sidecar[].slot,
          proposer_index = 0'u64,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(
        genGloasDataColumnSidecar(
          index = int(custodyColumns[0]),
          slot = 10000))
      blockRoot = genBlockRoot(10000)
    check:
      bq.hasSidecar(blockRoot = blockRoot, slot = Slot(10000),
                    proposer_index = 0'u64,
                    index = custodyColumns[0]) == false
    bq.put(blockRoot, sidecar)
    check:
      len(bq) == (len(sidecars) - len(custodyColumns) + 1)
      bq.hasSidecar(blockRoot = blockRoot, slot = Slot(10000),
                    index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].slot)),
          slot =
            sidecars[i].sidecar[].slot,
          proposer_index = 0'u64,
          index = sidecars[i].sidecar[].index
        ) == false

    # put(openArray[sidecar]) test

    let
      msidecars =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            let sidecar =
              newClone(genGloasDataColumnSidecar(
                index = int(custodyColumns[i]), slot = 100_000))
            res.add(sidecar)
          res
      mblockRoot = genBlockRoot(20000)

    check:
      len(bq) == (len(sidecars) - len(custodyColumns) + 1)

    let beforeLength = len(bq)

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.slot,
                      0'u64,
                      s.index) == false

    bq.put(mblockRoot, msidecars)
    check len(bq) == beforeLength

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.slot,
                      0'u64,
                      s.index) == true

    for i in 0 ..< len(custodyColumns):
      let j = len(custodyColumns) + i
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[j].sidecar[].slot)),
          slot =
            sidecars[j].sidecar[].slot,
          proposer_index = 0'u64,
          index = sidecars[j].sidecar[].index
        ) == false

  test "put() duplicate items should not affect counters [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
    var
      bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
      sidecars1: seq[ref gloas.DataColumnSidecar]
      sidecars1d: seq[ref gloas.DataColumnSidecar]
      sidecars2: seq[ref gloas.DataColumnSidecar]
      sidecars2d: seq[ref gloas.DataColumnSidecar]

    for index in custodyColumns:
      let
        sidecar1 = newClone(genGloasDataColumnSidecar(int(index), 1))
        sidecar1d = newClone(genGloasDataColumnSidecar(int(index), 1))
        sidecar2 = newClone(genGloasDataColumnSidecar(int(index), 2))
        sidecar2d = newClone(genGloasDataColumnSidecar(int(index), 2))
      sidecars1.add(sidecar1)
      sidecars1d.add(sidecar1d)
      sidecars2.add(sidecar2)
      sidecars2d.add(sidecar2d)

    let
      broot1 = genBlockRoot(100)
      broot2 = genBlockRoot(200)

    check:
      len(bq) == 0
      len(bq.fetchMissingSidecars(
        broot1, custodyColumns).indices) == len(custodyColumns)
      len(bq.fetchMissingSidecars(
        broot2, custodyColumns).indices) == len(custodyColumns)

    for index in 0 ..< len(custodyColumns):
      bq.put(broot1, sidecars1[index])
      check:
        len(bq) == (index + 1)
        len(bq.fetchMissingSidecars(
          broot1, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)
      bq.put(broot1, sidecars1d[index])
      check:
        len(bq) == (index + 1)
        len(bq.fetchMissingSidecars(
          broot1, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)

    for index in 0 ..< len(custodyColumns):
      bq.put(broot2, sidecars2[index])
      check:
        len(bq) == len(custodyColumns) + (index + 1)
        len(bq.fetchMissingSidecars(
          broot2, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)
      bq.put(broot2, sidecars2d[index])
      check:
        len(bq) == len(custodyColumns) + (index + 1)
        len(bq.fetchMissingSidecars(
          broot2, custodyColumns).indices) ==
            len(custodyColumns) - (index + 1)

    bq.remove(broot2)
    check len(bq) == len(custodyColumns)
    bq.remove(broot1)
    check len(bq) == 0

  test "pruneAfterFinalization() test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    const TestVectors = [
      (root: 1, slot: 1, index: 63),
      (root: 1, slot: 1, index: 64),
      (root: 1, slot: 1, index: 65),
      (root: 1, slot: 1, index: 66),
      (root: 1, slot: 1, index: 96),
      (root: 2, slot: 32, index: 63),
      (root: 2, slot: 32, index: 64),
      (root: 2, slot: 32, index: 65),
      (root: 3, slot: 33, index: 63),
      (root: 3, slot: 33, index: 64),
      (root: 4, slot: 63, index: 63),
      (root: 5, slot: 64, index: 63),
      (root: 5, slot: 64, index: 64),
      (root: 5, slot: 64, index: 65),
      (root: 6, slot: 65, index: 63),
      (root: 6, slot: 65, index: 64),
      (root: 7, slot: 67, index: 63),
      (root: 7, slot: 67, index: 64),
      (root: 8, slot: 95, index: 63),
      (root: 8, slot: 95, index: 64),
      (root: 8, slot: 95, index: 65),
      (root: 8, slot: 95, index: 66),
      (root: 8, slot: 95, index: 98),
      (root: 9, slot: 96, index: 63),
      (root: 9, slot: 96, index: 64),
      (root: 9, slot: 96, index: 65),
      (root: 9, slot: 96, index: 66),
      (root: 9, slot: 96, index: 95),
      (root: 9, slot: 96, index: 96),
      (root: 9, slot: 96, index: 97),
      (root: 9, slot: 96, index: 98),
      (root: 10, slot: 127, index: 96),
      (root: 10, slot: 127, index: 97),
      (root: 10, slot: 127, index: 98)
    ]

    var bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 0, nil)
    for item in TestVectors:
      let sidecar =
        newClone(
          genGloasDataColumnSidecar(
            index = item.index, slot = item.slot))
      bq.put(genBlockRoot(item.root), sidecar)

    check:
      len(bq) == len(TestVectors)

    for item in TestVectors:
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          ColumnIndex(item.index)) == true

    bq.pruneAfterFinalization(Epoch(0), false)
    check:
      len(bq) == len(TestVectors) - 5

    for item in TestVectors:
      let res =
        if item.root == 1:
          false
        else:
          true
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          ColumnIndex(item.index)) == res

    bq.pruneAfterFinalization(Epoch(1), false)
    check:
      len(bq) == len(TestVectors) - 5 - 6

    for item in TestVectors:
      let res =
        if item.root in [1, 2, 3, 4]:
          false
        else:
          true
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          ColumnIndex(item.index)) == res

    bq.pruneAfterFinalization(Epoch(2), false)
    check:
      len(bq) == len(TestVectors) - 5 - 6 - 12

    for item in TestVectors:
      let res =
        if item.root in [1, 2, 3, 4, 5, 6, 7, 8]:
          false
        else:
          true
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          ColumnIndex(item.index)) == res

    bq.pruneAfterFinalization(Epoch(3), false)
    check:
      len(bq) == 0

    for item in TestVectors:
      check:
        bq.hasSidecar(
          genBlockRoot(item.root), Slot(item.slot),
          ColumnIndex(item.index)) == false

  test "database unload/load test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var
      bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
      sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                          blockRoot: Eth2Digest]]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot = i div len(custodyColumns) + 100
        blockRoot = genBlockRoot(slot)
        sidecar = newClone(
          genGloasDataColumnSidecar(index = int(custodyColumns[index]), slot))
      sidecars.add((sidecar, blockRoot))

    for item in sidecars:
      bq.put(item.blockRoot, item.sidecar)

    # put(sidecar) test

    check:
      len(bq) == maxSidecars
      lenMemory(bq) == maxSidecars
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].slot)),
          slot =
            sidecars[i].sidecar[].slot,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(
        genGloasDataColumnSidecar(index = int(custodyColumns[0]), slot = 10000))
      blockRoot1 = genBlockRoot(10000)
    check:
      bq.hasSidecar(
        blockRoot = blockRoot1, slot = Slot(10000),
        index = custodyColumns[0]) == false

    bq.put(blockRoot1, sidecar)

    check:
      len(bq) == len(sidecars) + 1
      lenDisk(bq) == len(custodyColumns)
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) ==
        len(custodyColumns)
      lenMemory(bq) == len(sidecars) - len(custodyColumns) + 1
      bq.hasSidecar(
        blockRoot = blockRoot1, slot = Slot(10000),
        index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[i].sidecar[].slot)),
          slot =
            sidecars[i].sidecar[].slot,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      blockRoot2 =
        genBlockRoot(
          int(sidecars[0].sidecar[].slot))
      sidecars2 =
        sidecars.toOpenArray(0, len(custodyColumns) - 1).mapIt(it.sidecar)
      dres = bq.popSidecars(blockRoot2)

    check:
      dres.isOk()
      compareSidecarsByValue(dres.get(), sidecars2) == true
      len(bq) == len(sidecars) - len(custodyColumns) + 1
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0

    # put(openArray[sidecar]) test

    let
      msidecars =
        block:
          var res: seq[ref gloas.DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            let sidecar =
              newClone(
                genGloasDataColumnSidecar(
                  index = int(custodyColumns[i]), slot = 100_000))
            res.add(sidecar)
          res
      mblockRoot = genBlockRoot(20000)

    check:
      len(bq) == len(sidecars) - len(custodyColumns) + 1

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.slot,
                      s.index) == false

    bq.put(mblockRoot, msidecars)

    check:
      lenDisk(bq) == len(custodyColumns)
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) ==
        len(custodyColumns)
      len(bq) == len(sidecars) + 1

    for s in msidecars:
      check:
        bq.hasSidecar(mblockRoot,
                      s.slot,
                      s.index) == true

    for i in 0 ..< len(custodyColumns):
      let j = len(custodyColumns) + i
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars[j].sidecar[].slot)),
          slot =
            sidecars[j].sidecar[].slot,
          index = sidecars[j].sidecar[].index
        ) == true

    let
      i3 = len(custodyColumns)
      blockRoot3 =
        genBlockRoot(
          int(sidecars[i3].sidecar[].slot))
      sidecars3 =
        sidecars.toOpenArray(i3, i3 + len(custodyColumns) - 1).
          mapIt(it.sidecar)
      dres3 = bq.popSidecars(blockRoot3)

    check:
      dres3.isOk()
      compareSidecarsByValue(dres3.get(), sidecars3) == true
      len(bq) == len(sidecars) - len(custodyColumns) + 1
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0

  test "database and memory overfill protection and pruning test [node]":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
    var
      bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 1, nil)
      sidecars1: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                          blockRoot: Eth2Digest]]
      sidecars2: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                          blockRoot: Eth2Digest]]
      epochs1: seq[Epoch]
      epochs2: seq[Epoch]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot1 = i div len(custodyColumns) + 100
        slot2 = i div len(custodyColumns) + 100000
        epoch1 = Slot(slot1).epoch()
        epoch2 = Slot(slot2).epoch()
        blockRoot1 = genBlockRoot(slot1)
        blockRoot2 = genBlockRoot(slot2)
        sidecar1 = newClone(
          genGloasDataColumnSidecar(int(custodyColumns[index]), slot1))
        sidecar2 = newClone(
          genGloasDataColumnSidecar(int(custodyColumns[index]), slot2))

      sidecars1.add((sidecar1, blockRoot1))
      sidecars2.add((sidecar2, blockRoot2))
      if len(epochs1) == 0 or epochs1[^1] != epoch1:
        epochs1.add(epoch1)
      if len(epochs2) == 0 or epochs2[^1] != epoch2:
        epochs2.add(epoch2)

    for item in sidecars1:
      bq.put(item.blockRoot, item.sidecar)

    check:
      len(bq) == len(sidecars1)
      lenDisk(bq) == 0
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0

    for i in 0 ..< (maxSidecars div len(custodyColumns)):
      let
        start = len(custodyColumns) * int(i)
        finish = start + len(custodyColumns) - 1
        blockRoot = sidecars2[start].blockRoot
        sidecars = sidecars2.toOpenArray(start, finish).mapIt(it.sidecar)
      bq.put(blockRoot, sidecars)

    check:
      len(bq) == len(sidecars1) + len(sidecars2)
      lenDisk(bq) == len(sidecars1)
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) ==
        len(sidecars1)
      lenMemory(bq) == len(sidecars2)

    for i in 0 ..< len(sidecars1):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars1[i].sidecar[].slot)),
          slot =
            sidecars1[i].sidecar[].slot,
          index = sidecars1[i].sidecar[].index
        ) == true

    for i in 0 ..< len(sidecars2):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars2[i].sidecar[].slot)),
          slot =
            sidecars2[i].sidecar[].slot,
          index = sidecars2[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(genGloasDataColumnSidecar(
        index = int(custodyColumns[0]), slot = 1000000))
      blockRoot = genBlockRoot(1000000)

    check:
      bq.hasSidecar(blockRoot = blockRoot, slot = Slot(1000000),
                    index = custodyColumns[0]) == false

    bq.put(blockRoot, sidecar)

    check:
      len(bq) == len(sidecars1) + len(sidecars2) - len(custodyColumns) + 1
      lenDisk(bq) == len(sidecars1)
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == len(sidecars1)
      lenMemory(bq) == len(sidecars2) - len(custodyColumns) + 1
      bq.hasSidecar(
        blockRoot = blockRoot, slot = Slot(1000000),
        index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars1[i].sidecar[].slot)),
          slot =
            sidecars1[i].sidecar[].slot,
          index = sidecars1[i].sidecar[].index
        ) == false

    for i in len(custodyColumns) ..< len(sidecars1):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars1[i].sidecar[].slot)),
          slot =
            sidecars1[i].sidecar[].slot,
          index = sidecars1[i].sidecar[].index
        ) == true

    for i in 0 ..< len(sidecars2):
      check:
        bq.hasSidecar(
          blockRoot =
            genBlockRoot(
              int(sidecars2[i].sidecar[].slot)),
          slot =
            sidecars2[i].sidecar[].slot,
          index = sidecars2[i].sidecar[].index
        ) == true

    # Pruning memory and database
    for epoch in epochs1:
      bq.pruneAfterFinalization(epoch, false)
    for epoch in epochs2:
      bq.pruneAfterFinalization(epoch, false)

    check:
      len(bq) == 1

    bq.pruneAfterFinalization(Slot(1000000).epoch(), false)

    check:
      len(bq) == 0
      quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0

  const ColumnsVectors = [
    ("node", [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))),
    ("supernode", supernodeColumns())
  ]

  for cvec in ColumnsVectors:
    test "overfill test [" & cvec[0] & "]":
      let custodyColumns = cvec[1]
      var
        bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      let maximumSidecars = bq.size * 2

      for i in 0 ..< maximumSidecars:
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genGloasDataColumnSidecar(
            int(custodyColumns[index]), slot))
        sidecars.add((sidecar, blockRoot))

      for item in sidecars:
        bq.put(item.blockRoot, item.sidecar)

      # At this stage only last sidecars in range
      # [maxSidecars - quarantine.size, maxSidecars] should be present in
      # quarantine.
      let
        startPosition = maximumSidecars - bq.size()

      for i in startPosition ..< maximumSidecars:
        let
          item =
            sidecars[i]
          slot =
            item.sidecar[].slot
          index =
            item.sidecar[].index

        check:
          bq.hasSidecar(
            blockRoot = item.blockRoot, slot = slot,
            index = index) == true

      for i in 0 ..< startPosition:
        let
          item =
            sidecars[i]
          slot =
            item.sidecar[].slot
          index =
            item.sidecar[].index

        check:
          bq.hasSidecar(
            blockRoot = item.blockRoot, slot = slot,
            index = index) == false

    test "Empty in-memory scenario test [" & cvec[0] & "]":
      let custodyColumns = cvec[1]
      var
        bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      let size = bq.sizeMemory * 2
        # full size of quarantine is bq.sizeMemory + bq.sizeMemory * 2
      for i in 0 ..< size:
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genGloasDataColumnSidecar(
            int(custodyColumns[index]), slot))
        sidecars.add((sidecar, blockRoot))

      for item in sidecars:
        bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()
        bq.lenDisk() == bq.sizeMemory()

      # At this stage we have full in memory store and partially filled disk store

      for i in bq.sizeMemory ..< size:
        let blockRoot = sidecars[i].blockRoot
        bq.remove(blockRoot)

      # At this stage we removed all the in-memory roots.
      check:
        bq.lenMemory() == 0
        bq.lenDisk() == bq.sizeMemory()

      var
        sidecars2: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      for i in 0 ..< len(custodyColumns):
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 1000000
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genGloasDataColumnSidecar(
            int(custodyColumns[index]), slot))
        sidecars2.add((sidecar, blockRoot))

      # Now we should be able to add new columns to in-memory storage.
      for item in sidecars2:
        bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == len(custodyColumns)
        bq.lenDisk() == bq.sizeMemory()

    test "Mixed entries scenario test [" & cvec[0] & "]":
      let custodyColumns = cvec[1]
      var
        bq = GloasColumnQuarantine.init(cfg, custodyColumns, quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      let maximumSidecars = bq.size * 2

      for i in 0 ..< maximumSidecars:
        let
          index = i mod len(custodyColumns)
          slot = i div len(custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genGloasDataColumnSidecar(
            int(custodyColumns[index]), slot))
        sidecars.add((sidecar, blockRoot))

      case cvec[0]
      of "node":
        # Add only first 3 sidecars for first block
        for i in 0 ..< 3:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add only first 5 sidecars for second block
        for i in 8 ..< 13:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add all other sidecars
        for item in sidecars.toOpenArray(16, bq.sizeMemory - 1):
          bq.put(item.blockRoot, item.sidecar)
      of "supernode":
        # Add only 64 sidecars for first block.
        for i in 0 ..< 64:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add only 64 sidecars for second block.
        for i in 128 ..< 192:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add all other sidecars
        for item in sidecars.toOpenArray(256, bq.sizeMemory - 1):
          bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory() - len(custodyColumns)

      # Adding last block which could fit in memory
      block:
        let offset = bq.sizeMemory()
        for i in 0 ..< len(custodyColumns):
          let item = sidecars[offset + i]
          bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()

      # Adding block which should overfill memory storage and our two non-100%
      # filled blocks should be offloaded to disk.
      block:
        let offset = bq.sizeMemory() + len(custodyColumns)
        for i in 0 ..< len(custodyColumns):
          let item = sidecars[offset + i]
          bq.put(item.blockRoot, item.sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()
        bq.lenDisk() == len(custodyColumns)

      # Checking columns are in place.
      case cvec[0]
      of "node":
        for i in [0, 1, 2, 8, 9, 10, 11, 12]:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].slot,
              sidecars[i].sidecar[].index
            ) == true
        for i in [3, 4, 5, 6, 7, 13, 14, 15]:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].slot,
              sidecars[i].sidecar[].index
            ) == false
      of "supernode":
        for i in 0 ..< 64:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].slot,
              sidecars[i].sidecar[].index
            ) == true

        for i in 128 ..< 192:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].slot,
              sidecars[i].sidecar[].index
            ) == true

        for i in 64 ..< 128:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].slot,
              sidecars[i].sidecar[].index
            ) == false

        for i in 192 ..< 256:
          check:
            bq.hasSidecar(
              sidecars[i].blockRoot,
              sidecars[i].sidecar[].slot,
              sidecars[i].sidecar[].index
            ) == false

      let
        commitments = [
          genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
        ]
        envl1 = genGloasSignedExecutionPayloadEnvelope(
          sidecars[0].blockRoot, commitments)
        envl2 = genGloasSignedExecutionPayloadEnvelope(
          sidecars[0 + len(custodyColumns)].blockRoot, commitments)

      # Both blocks should be incomplete.
      check:
        bq.hasSidecars(envl1) == false
        bq.hasSidecars(envl2) == false

      case cvec[0]
      of "node":
        # Add last 5 sidecars for first block
        for i in 3 ..< 8:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add last 3 sidecars for second block
        for i in 13 ..< 16:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
      of "supernode":
        # Add last 64 sidecars for first block.
        for i in 64 ..< 128:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)
        # Add last 64 sidecars for second block.
        for i in 192 ..< 256:
          bq.put(sidecars[i].blockRoot, sidecars[i].sidecar)

      check:
        bq.lenMemory() == bq.sizeMemory()
        bq.lenDisk() == len(custodyColumns) * 2
        bq.hasSidecars(envl1) == true
        bq.hasSidecars(envl2) == true

      let sidecars1 = bq.popSidecars(sidecars[0].blockRoot)
      check:
        sidecars1.isSome() == true
      case cvec[0]
      of "node":
        check:
          bq.lenMemory() == bq.sizeMemory() - 5
          bq.lenDisk() == len(custodyColumns) * 2 - 3
      of "supernode":
        check:
          bq.lenMemory() == bq.sizeMemory() - 64
          bq.lenDisk() == len(custodyColumns) * 2 - 64

      let sidecars2 = bq.popSidecars(sidecars[len(custodyColumns)].blockRoot)

      check:
        sidecars2.isSome() == true
        bq.lenMemory() == bq.sizeMemory() - len(custodyColumns)
        bq.lenDisk() == len(custodyColumns) * 2 - len(custodyColumns)

      let
        expect1 =
          case cvec[0]
          of "node":
            let
              start = 0
              finish = len(custodyColumns)
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          of "supernode":
            # In case of super node quarantine returns
            # NUMBER_OF_COLUMNS div 2 + 1 columns which is enough for
            # rebuild.
            let
              start = 0
              finish = len(custodyColumns) div 2 + 1
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          else:
            raiseAssert "inaccessible"
        expect2 =
          case cvec[0]
          of "node":
            let
              start = len(custodyColumns)
              finish = start + len(custodyColumns)
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          of "supernode":
            # In case of super node quarantine returns
            # NUMBER_OF_COLUMNS div 2 + 1 columns which is enough for
            # rebuild.
            let
              start = len(custodyColumns)
              finish = start + len(custodyColumns) div 2 + 1
            sidecars.toOpenArray(start, finish - 1).mapIt(it.sidecar)
          else:
            raiseAssert "inaccessible"

      check:
        compareSidecarsByValue(sidecars1.get(), expect1) == true
        compareSidecarsByValue(sidecars2.get(), expect2) == true

  const
    EmptyTests = [
      (
        "empty:grow", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))
      ),
      (
        "empty:grow", "node->supernode",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        supernodeColumns()
      ),
      (
        "empty:shrink", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      ),
      (
        "empty:shrink", "supernode->node",
        supernodeColumns(),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      )
    ]

  for vtest in EmptyTests:
    test "GloasColumnQuarantine: update(" & vtest[0] & ") [" & vtest[1] & "] test":
      var bq = GloasColumnQuarantine.init(cfg, vtest[2], quarantine, 2, nil)

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      bq.update(cfg, vtest[3])

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[3])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())

  const
    MemoryTests = [
      (
        "memory:grow", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))
      ),
      (
        "memory:grow", "node->supernode",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        supernodeColumns()
      ),
      (
        "memory:shrink", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      ),
      (
        "memory:shrink", "supernode->node",
        supernodeColumns(),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      )
    ]


  for vtest in MemoryTests:
    test "GloasColumnQuarantine: update(" & vtest[0] & ") [" & vtest[1] & "] test":
      var
        bq = GloasColumnQuarantine.init(cfg, vtest[2], quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      for i in 0 ..< bq.sizeMemory():
        let
          index = i mod len(bq.custodyColumns)
          slot = i div len(bq.custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genGloasDataColumnSidecar(
            int(bq.custodyColumns[index]), slot))
        sidecars.add((sidecar, blockRoot))
        bq.put(blockRoot, sidecar)

      let rootsCount = bq.sizeMemory() div len(bq.custodyColumns)

      check:
        len(bq) == bq.sizeMemory()
        lenDisk(bq) == 0
        lenMemory(bq) == bq.sizeMemory()
        quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      bq.update(cfg, vtest[3])

      if vtest[0] == "memory:grow":
        check:
          len(bq) == bq.sizeMemory()
          lenDisk(bq) == 0
          lenMemory(bq) == bq.sizeMemory()
          quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())
      else:
        check:
          len(bq) == rootsCount * len(bq.custodyMap)
          lenDisk(bq) == 0
          lenMemory(bq) == rootsCount * len(bq.custodyMap)
          quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())

      for item in sidecars:
        if item.sidecar[].index in bq.custodyMap:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].slot,
              item.sidecar[].index) == true
        else:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].slot,
              item.sidecar[].index) == false

  const
    MemoryDiskTests = [
      (
        "memory+disk:grow", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))
      ),
      (
        "memory+disk:grow", "node->supernode",
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it)),
        supernodeColumns()
      ),
      (
        "memory+disk:shrink", "node->node",
        [63, 64, 65, 66, 95, 96, 97, 98, 1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it)),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      ),
      (
        "memory+disk:shrink", "supernode->node",
        supernodeColumns(),
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      )
    ]

  for vtest in MemoryDiskTests:
    test "GloasColumnQuarantine: update(" & vtest[0] & ") [" & vtest[1] & "] test":
      var
        bq = GloasColumnQuarantine.init(cfg, vtest[2], quarantine, 2, nil)
        sidecars: seq[tuple[sidecar: ref gloas.DataColumnSidecar,
                            blockRoot: Eth2Digest]]

      check:
        len(bq) == 0
        lenDisk(bq) == 0
        lenMemory(bq) == 0
        quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) == 0
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      for i in 0 ..< bq.sizeMemory() * 2:
        let
          index = i mod len(bq.custodyColumns)
          slot = i div len(bq.custodyColumns) + 100
          blockRoot = genBlockRoot(slot)
          sidecar = newClone(genGloasDataColumnSidecar(
            int(bq.custodyColumns[index]), slot))
        sidecars.add((sidecar, blockRoot))
        bq.put(blockRoot, sidecar)

      let rootsCount = (bq.sizeMemory() * 2) div len(bq.custodyColumns)

      check:
        len(bq) == bq.sizeMemory() * 2
        lenDisk(bq) == bq.sizeMemory()
        lenMemory(bq) == bq.sizeMemory()
        quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) ==
          lenDisk(bq)
        bq.custodyMap == ColumnMap.init(vtest[2])
        bq.custodyColumns == toSeq(ColumnMap.init(vtest[2]).items())

      bq.update(cfg, vtest[3])

      if vtest[0] == "memory+disk:grow":
        check:
          len(bq) == bq.sizeMemory() * 2
          lenDisk(bq) == bq.sizeMemory()
          lenMemory(bq) == bq.sizeMemory()
          quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) ==
            bq.sizeMemory()
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())
      else:
        check:
          len(bq) == rootsCount * len(bq.custodyMap)
          lenDisk(bq) == (rootsCount div 2) * len(bq.custodyMap)
          lenMemory(bq) == (rootsCount div 2) * len(bq.custodyMap)
        # Because we do not do database cleanup immediately database actually
        # holds all the values which was present before update.
        check:
          quarantine.sidecarsCount(typedesc[gloas.DataColumnSidecar]) ==
            bq.sizeMemory()
        check:
          bq.custodyMap == ColumnMap.init(vtest[3])
          bq.custodyColumns == toSeq(ColumnMap.init(vtest[3]).items())

      for item in sidecars:
        if item.sidecar[].index in bq.custodyMap:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].slot,
              item.sidecar[].index) == true
        else:
          check:
            bq.hasSidecar(
              item.blockRoot,
              item.sidecar[].slot,
              item.sidecar[].index) == false

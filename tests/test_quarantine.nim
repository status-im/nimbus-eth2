# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/[strutils, sequtils], stew/endians2,
       kzg4844/kzg,
       unittest2,
       ./testutil,
       ../beacon_chain/spec/datatypes/[deneb, electra, fulu],
       ../beacon_chain/spec/[presets, helpers],
       ../beacon_chain/consensus_object_pools/blob_quarantine

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
): DataColumnSidecar =
  DataColumnSidecar(
    index: ColumnIndex(index),
    signed_block_header: SignedBeaconBlockHeader(
      message: BeaconBlockHeader(
        slot: Slot(slot),
        proposer_index: uint64(proposer_index))))

func genDenebSignedBeaconBlock(
    blockRoot: Eth2Digest,
    sidecars: openArray[ref BlobSidecar]
): deneb.SignedBeaconBlock =
  var res: seq[KzgCommitment]
  for sidecar in sidecars:
    res.add(sidecar[].kzg_commitment)
  deneb.SignedBeaconBlock(
    message: deneb.BeaconBlock(
      body: deneb.BeaconBlockBody(blob_kzg_commitments: KzgCommitments(res))),
    root: blockRoot)

func genElectraSignedBeaconBlock(
    blockRoot: Eth2Digest,
    sidecars: openArray[ref BlobSidecar]
): electra.SignedBeaconBlock =
  var res: seq[KzgCommitment]
  for sidecar in sidecars:
    res.add(sidecar[].kzg_commitment)
  electra.SignedBeaconBlock(
    message: electra.BeaconBlock(
      body: electra.BeaconBlockBody(blob_kzg_commitments: KzgCommitments(res))),
    root: blockRoot)

func genFuluSignedBeaconBlock(
    blockRoot: Eth2Digest,
    commitments: openArray[KzgCommitment]
): fulu.SignedBeaconBlock =
  var res = @commitments
  fulu.SignedBeaconBlock(
    message: fulu.BeaconBlock(
      body: fulu.BeaconBlockBody(blob_kzg_commitments: KzgCommitments(res))),
    root: blockRoot)

func compareSidecars(
    a, b: openArray[ref BlobSidecar|ref DataColumnSidecar]
): bool =
  if len(a) != len(b):
    return false
  if len(a) == 0:
    return true
  for i in 0 ..< len(a):
    if cast[uint64](a[i]) != cast[uint64](b[i]):
      return false
  true

func compareSidecars(
    blockRoot: Eth2Digest,
    a: openArray[ref BlobSidecar|ref DataColumnSidecar],
    b: openArray[BlobIdentifier|DataColumnIdentifier]
): bool =
  if len(a) != len(b):
    return false
  if len(a) == 0:
    return true
  for i in 0 ..< len(a):
    if (a[i][].index != b[i].index) or (b[i].block_root != blockRoot):
      return false
  true

func compareIdentifiers(
  a, b: openArray[DataColumnIdentifier]): bool =
  if len(a) != len(b):
    return false
  if len(a) == 0:
    return true
  for i in 0 ..< len(a):
    if (a[i].block_root != b[i].block_root) or (a[i].index != b[i].index):
      return false
  true

func supernodeColumns(): seq[ColumnIndex] =
  var res: seq[ColumnIndex]
  for i in 0 ..< 128:
    res.add(ColumnIndex(i))
  res

suite "BlobQuarantine data structure test suite " & preset():
  setup:
    let cfg = defaultRuntimeConfig

  test "put()/hasSidecar(index, slot, proposer_index)/remove() test":
    var bq = BlobQuarantine.init(cfg, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      broot3 = genBlockRoot(3)
      broot4 = genBlockRoot(4)
      sidecar1 =
        newClone(genBlobSidecar(index = 0, slot = 1, 1, proposer_index = 5))
      sidecar2 =
        newClone(genBlobSidecar(index = 1, slot = 1, 2, proposer_index = 5))
      sidecar3 =
        newClone(genBlobSidecar(index = 2, slot = 1, 3, proposer_index = 5))
      sidecar4 =
        newClone(genBlobSidecar(index = 4, slot = 2, 4, proposer_index = 6))
      sidecar5 =
        newClone(genBlobSidecar(index = 5, slot = 3, 5, proposer_index = 7))
      sidecar6 =
        newClone(genBlobSidecar(index = 6, slot = 3, 6, proposer_index = 8))

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == false
      bq.hasSidecar(Slot(2), uint64(5), BlobIndex(4)) == false
      bq.hasSidecar(Slot(3), uint64(5), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(5), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.put(broot1, sidecar1)

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == false
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == false
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.put(broot1, sidecar2)

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == false
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == false
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.put(broot1, sidecar3)

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == true
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == false
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.put(broot2, sidecar4)

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == true
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == true
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.put(broot3, sidecar5)

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == true
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == true
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == true
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.put(broot4, sidecar6)

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == true
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == true
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == true
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == true
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.remove(Slot(3))

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == true
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == true
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.remove(Slot(2))

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == true
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == true
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == false
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false

    bq.remove(Slot(1))

    check:
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(0)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(1)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(2)) == false
      bq.hasSidecar(Slot(2), uint64(6), BlobIndex(4)) == false
      bq.hasSidecar(Slot(3), uint64(7), BlobIndex(5)) == false
      bq.hasSidecar(Slot(3), uint64(8), BlobIndex(6)) == false
      bq.hasSidecar(Slot(10), uint64(100), BlobIndex(3)) == false
      len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() test":
    var bq = BlobQuarantine.init(cfg, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref BlobSidecar]
          for i in 0 ..< cfg.MAX_BLOBS_PER_BLOCK_ELECTRA:
            res.add(newClone(genBlobSidecar(index = int(i), slot = 1,
                                            1 + int(i), proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref BlobSidecar]
          for i in 0 ..< cfg.MAX_BLOBS_PER_BLOCK_ELECTRA:
            res.add(newClone(genBlobSidecar(index = int(i), slot = 1,
                                            1 + int(i), proposer_index = 50)))
          res
      denebBlock = genDenebSignedBeaconBlock(broot1, sidecars1)
      electraBlock = genElectraSignedBeaconBlock(broot2, sidecars2)

    check:
      bq.hasSidecars(denebBlock) == false
      bq.popSidecars(denebBlock).isNone() == true
      bq.hasSidecars(electraBlock) == false
      bq.popSidecars(electraBlock).isNone() == true

    bq.put(broot1, sidecars1)

    for index in 0 ..< len(sidecars2):
      if index mod 2 != 1:
        bq.put(broot2, sidecars2[index])

    check:
      bq.hasSidecars(denebBlock) == true
      bq.hasSidecars(electraBlock) == false
      bq.popSidecars(electraBlock).isNone() == true
    let dres = bq.popSidecars(denebBlock)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(electraBlock) == false
      bq.popSidecars(electraBlock).isNone() == true

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(electraBlock) == false
      bq.popSidecars(electraBlock).isNone() == true

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(electraBlock) == false
      bq.popSidecars(electraBlock).isNone() == true

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(electraBlock) == true
    let eres = bq.popSidecars(electraBlock)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true

    bq.remove(Slot(1))
    check:
      len(bq) == 0

  test "put()/fetchMissingSidecars/remove test":
    var bq = BlobQuarantine.init(cfg, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref BlobSidecar]
          for i in 0 ..< cfg.MAX_BLOBS_PER_BLOCK_ELECTRA:
            res.add(newClone(genBlobSidecar(index = int(i), slot = 1,
                                            1 + int(i), proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref BlobSidecar]
          for i in 0 ..< cfg.MAX_BLOBS_PER_BLOCK_ELECTRA:
            res.add(newClone(genBlobSidecar(index = int(i), slot = 1,
                                            1 + int(i), proposer_index = 50)))
          res
      denebBlock = genDenebSignedBeaconBlock(broot1, sidecars1)
      electraBlock = genElectraSignedBeaconBlock(broot2, sidecars2)

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1, denebBlock)
        missing2 = bq.fetchMissingSidecars(broot2, electraBlock)

      check:
        compareSidecars(
          broot1,
          sidecars1.toOpenArray(i, len(sidecars1) - 1), missing1) == true
        compareSidecars(
          broot2,
          sidecars2.toOpenArray(i, len(sidecars2) - 1), missing2) == true

      if i >= len(sidecars1):
        break

      bq.put(broot1, sidecars1[i])
      bq.put(broot2, sidecars2[i])

    bq.remove(Slot(1))
    check len(bq) == 0

  test "popSidecars()/hasSidecars() return []/true on block without blobs":
    var
      bq = BlobQuarantine.init(cfg, nil)
    let
      blockRoot1 = genBlockRoot(100)
      blockRoot2 = genBlockRoot(5337)
      blockRoot3 = genBlockRoot(191925)
      blockRoot4 = genBlockRoot(1294967295)
      denebBlock1 = genDenebSignedBeaconBlock(blockRoot1, [])
      denebBlock2 = genDenebSignedBeaconBlock(blockRoot2, [])
      electraBlock1 = genElectraSignedBeaconBlock(blockRoot3, [])
      electraBlock2 = genElectraSignedBeaconBlock(blockRoot4, [])
    check:
      bq.hasSidecars(denebBlock1.root, denebBlock1) == true
      bq.hasSidecars(denebBlock2.root, denebBlock2) == true
      bq.hasSidecars(electraBlock1.root, electraBlock1) == true
      bq.hasSidecars(electraBlock2.root, electraBlock2) == true

    let
      res1 = bq.popSidecars(denebBlock1.root, denebBlock1)
      res2 = bq.popSidecars(denebBlock2.root, denebBlock2)
      res3 = bq.popSidecars(electraBlock1.root, electraBlock1)
      res4 = bq.popSidecars(electraBlock2.root, electraBlock2)

    check:
      res1.isOk()
      len(res1.get()) == 0
      res2.isOk()
      len(res2.get()) == 0
      res3.isOk()
      len(res3.get()) == 0
      res4.isOk()
      len(res4.get()) == 0

  test "overfill protection test":
    var bq = BlobQuarantine.init(cfg, nil)
    var sidecars: seq[tuple[sidecar: ref BlobSidecar, blockRoot: Eth2Digest]]

    let maxSidecars = int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA)
        slot = i div int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA) + 100
        blockRoot = genBlockRoot(slot)
        sidecar = newClone(genBlobSidecar(index, slot, i, proposer_index = i))
      sidecars.add((sidecar, blockRoot))

    for item in sidecars:
      bq.put(item.blockRoot, item.sidecar)

    # put(sidecar) test

    check len(bq) == maxSidecars

    for i in 0 ..< int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA):
      check:
        bq.hasSidecar(
          slot =
            sidecars[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(genBlobSidecar(index = 0, slot = 10000, 100000,
                                        proposer_index = 1000000))
      blockRoot = genBlockRoot(10000)
    check:
      bq.hasSidecar(slot = Slot(10000), proposer_index = 1000000'u64,
                    index = BlobIndex(0)) == false
    bq.put(blockRoot, sidecar)
    check:
      len(bq) == (len(sidecars) - int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA) + 1)
      bq.hasSidecar(slot = Slot(10000), proposer_index = 1000000'u64,
                    index = BlobIndex(0)) == true

    for i in 0 ..< int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA):
      check:
        bq.hasSidecar(
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
          var res: seq[ref BlobSidecar]
          for i in 0 ..< int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA):
            let sidecar =
              newClone(genBlobSidecar(index = i, slot = 100_000, 200000,
                                      proposer_index = 2000000))
            res.add(sidecar)
          res
      mblockRoot = genBlockRoot(20000)

    check:
      len(bq) == (len(sidecars) - int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA) + 1)

    let beforeLength = len(bq)

    for s in msidecars:
      check:
        bq.hasSidecar(s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == false

    bq.put(mblockRoot, msidecars)
    check len(bq) == beforeLength

    for s in msidecars:
      check:
        bq.hasSidecar(s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == true

    for i in 0 ..< int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA):
      let j = int(cfg.MAX_BLOBS_PER_BLOCK_ELECTRA) + i
      check:
        bq.hasSidecar(
          slot =
            sidecars[j].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[j].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[j].sidecar[].index
        ) == false

suite "ColumnQuarantine data structure test suite " & preset():
  setup:
    let cfg {.used.} = defaultRuntimeConfig

  test "ColumnMap test":
    # Filling columns of different sizes with all bits [8, 128)
    for columnSize in 8 .. 128:
      let
        columnsCount = 128 div columnSize
        lastColumnSize = 128 mod columnSize

      for i in 0 ..< columnsCount:
        let
          start = i * columnSize
          finish = start + columnSize
        var
          columns: seq[ColumnIndex]
          numbers: seq[int]
        for k in start ..< finish:
          columns.add(ColumnIndex(k))
          numbers.add(k)

        check:
          $ColumnMap.init(columns) ==
            "[" & $ numbers.mapIt($it).join(", ") & "]"

      if lastColumnSize > 0:
        let
          start = columnsCount * columnSize
          finish = start + lastColumnSize
        var
          columns: seq[ColumnIndex]
          numbers: seq[int]
        for k in start ..< finish:
          columns.add(ColumnIndex(k))
          numbers.add(k)

        check:
          $ColumnMap.init(columns) ==
            "[" & $ numbers.mapIt($it).join(", ") & "]"

    # Verify `and` operation is correct
    const TestVectors = [
      (
        [1, 2, 3, 4, 5, 6, 7, 8],
        [5, 6, 7, 8, 9, 10, 11, 12],
        "[5, 6, 7, 8]"
      ),
      (
        [56, 57, 58, 59, 60, 61, 62, 63],
        [60, 61, 62, 63, 64, 65, 66, 67],
        "[60, 61, 62, 63]"
      ),
      (
        [1, 5, 10, 15, 20, 25, 64, 65],
        [1, 5, 6, 7, 8, 9, 64, 65],
        "[1, 5, 64, 65]"
      ),
      (
        [60, 61, 62, 63, 124, 125, 126, 127],
        [60, 61, 62, 63, 124, 125, 126, 127],
        "[60, 61, 62, 63, 124, 125, 126, 127]"
      ),
      (
        [0, 1, 63, 64, 65, 93, 126, 127],
        [0, 2, 63, 64, 67, 94, 126, 127],
        "[0, 63, 64, 126, 127]"
      )
    ]

    for vector in TestVectors:
      let
        map1 = ColumnMap.init(vector[0].mapIt(ColumnIndex(it)))
        map2 = ColumnMap.init(vector[1].mapIt(ColumnIndex(it)))
      check:
        $(map1 and map2) == vector[2]


  test "put()/hasSidecar(index, slot, proposer_index)/remove() test":
    let custodyColumns =
      [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
    var bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      broot3 = genBlockRoot(3)
      broot4 = genBlockRoot(4)
      sidecar1 =
        newClone(genDataColumnSidecar(
          index = 0, slot = 1, proposer_index = 5))
      sidecar2 =
        newClone(genDataColumnSidecar(
          index = 31, slot = 1, proposer_index = 5))
      sidecar3 =
        newClone(genDataColumnSidecar(
          index = 32, slot = 1, proposer_index = 5))
      sidecar4 =
        newClone(genDataColumnSidecar(
          index = 127, slot = 2, proposer_index = 6))
      sidecar5 =
        newClone(genDataColumnSidecar(
          index = 0, slot = 3, proposer_index = 7))
      sidecar6 =
        newClone(genDataColumnSidecar(
          index = 31, slot = 3, proposer_index = 8))

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(Slot(2), uint64(5), ColumnIndex(127)) == false
      bq.hasSidecar(Slot(3), uint64(5), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot1, sidecar1)

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot1, sidecar2)

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot1, sidecar3)

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot2, sidecar4)

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot3, sidecar5)

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.put(broot4, sidecar6)

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(Slot(3))

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == true
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(Slot(2))

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == true
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == true
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false

    bq.remove(Slot(1))

    check:
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(1), uint64(5), ColumnIndex(32)) == false
      bq.hasSidecar(Slot(2), uint64(6), ColumnIndex(127)) == false
      bq.hasSidecar(Slot(3), uint64(7), ColumnIndex(0)) == false
      bq.hasSidecar(Slot(3), uint64(8), ColumnIndex(31)) == false
      bq.hasSidecar(Slot(10), uint64(100), ColumnIndex(3)) == false
      len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [node] test":
    let custodyColumns =
      [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
    var bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genDataColumnSidecar(
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
      bq.popSidecars(fuluBlock1).isNone() == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot1, sidecars1)

    for index in 0 ..< len(sidecars2):
      if index notin [1, 3, 5, 7]:
        bq.put(broot2, sidecars2[index])

    check:
      bq.hasSidecars(fuluBlock1) == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true
    let dres = bq.popSidecars(fuluBlock1)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(fuluBlock2) == true

    let eres = bq.popSidecars(fuluBlock2)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true

    bq.remove(Slot(1))
    check len(bq) == 0

  test "put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [supernode] test":
    let custodyColumns = supernodeColumns()
    var bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genDataColumnSidecar(
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
      bq.popSidecars(fuluBlock1).isNone() == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot1, sidecars1)

    for index in 0 ..< len(sidecars2):
      if index notin [1, 3, 5, 7]:
        bq.put(broot2, sidecars2[index])

    check:
      bq.hasSidecars(fuluBlock1) == true
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true
    let dres = bq.popSidecars(fuluBlock1)
    check:
      dres.isOk()
      compareSidecars(dres.get(), sidecars1) == true

    bq.put(broot2, sidecars2[1])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot2, sidecars2[3])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot2, sidecars2[5])
    check:
      bq.hasSidecars(fuluBlock2) == false
      bq.popSidecars(fuluBlock2).isNone() == true

    bq.put(broot2, sidecars2[7])
    check:
      bq.hasSidecars(fuluBlock2) == true

    let eres = bq.popSidecars(fuluBlock2)
    check:
      eres.isOk()
      compareSidecars(eres.get(), sidecars2) == true

    bq.remove(Slot(1))
    check len(bq) == 0

  test "put()/fetchMissingSidecars/remove test [node]":
    let
      custodyColumns =
        [0, 31, 32, 63, 64, 95, 96, 127].mapIt(ColumnIndex(it))
      peerCustodyColumns1 =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
      peerCustodyColumns2 =
        [1, 2, 3, 4, 5, 6, 7, 8].mapIt(ColumnIndex(it))

    var bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      expected1 = [
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(63)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(64)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(95)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(63)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(64)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(95)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(63)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(64)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(95)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(63)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(64)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(95)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(64)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(95)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(95)),
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[
          DataColumnIdentifier(block_root: broot1, index: ColumnIndex(96))],
        @[],
        @[]
      ]
      sidecars1 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            res.add(newClone(genDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 2, proposer_index = 50)))
          res
      commitments1 = [
        genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
      ]
      commitments2 = [
        genKzgCommitment(4), genKzgCommitment(5), genKzgCommitment(6)
      ]
      fuluBlock1 = genFuluSignedBeaconBlock(broot1, commitments1)
      fuluBlock2 = genFuluSignedBeaconBlock(broot2, commitments2)

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1, fuluBlock1)
        missing2 = bq.fetchMissingSidecars(broot2, fuluBlock2)
        missing3 = bq.fetchMissingSidecars(broot1, fuluBlock1,
                                           peerCustodyColumns1)
        missing4 = bq.fetchMissingSidecars(broot2, fuluBlock2,
                                           peerCustodyColumns2)

      check:
        compareSidecars(
          broot1,
          sidecars1.toOpenArray(i, len(sidecars1) - 1), missing1) == true
        compareSidecars(
          broot2,
          sidecars2.toOpenArray(i, len(sidecars2) - 1), missing2) == true

      check:
        compareIdentifiers(expected1[i], missing3)
        len(missing4) == 0

      if i >= len(sidecars1):
        break

      bq.put(broot1, sidecars1[i])
      bq.put(broot2, sidecars2[i])

    bq.remove(Slot(1))
    bq.remove(Slot(2))
    check len(bq) == 0

  test "put()/fetchMissingSidecars/remove test [supernode]":
    let
      custodyColumns = supernodeColumns()
      peerCustodyColumns1 =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
    let
      broot1 = genBlockRoot(1)
      broot2 = genBlockRoot(2)
      sidecars1 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 1, proposer_index = 5)))
          res
      sidecars2 =
        block:
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< (len(custodyColumns) div 2 + 1):
            res.add(newClone(genDataColumnSidecar(
              index = int(custodyColumns[i]), slot = 2, proposer_index = 50)))
          res
      commitments1 = [
        genKzgCommitment(1), genKzgCommitment(2), genKzgCommitment(3)
      ]
      commitments2 = [
        genKzgCommitment(4), genKzgCommitment(5), genKzgCommitment(6)
      ]
      fuluBlock1 = genFuluSignedBeaconBlock(broot1, commitments1)
      fuluBlock2 = genFuluSignedBeaconBlock(broot2, commitments2)

    func checkSupernodeExpected(
      root: Eth2Digest,
      index: int,
      missing: openArray[DataColumnIdentifier]
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
          if len(expect[0]) != len(missing):
            return false
          for i in 0 ..< len(missing):
            if (missing[i].block_root != root) or
               (int(missing[i].index) != expect[0][i]):
              return false
          return true
      false

    for i in 0 ..< len(sidecars1) + 1:
      let
        missing1 = bq.fetchMissingSidecars(broot1, fuluBlock1)
        missing2 = bq.fetchMissingSidecars(broot2, fuluBlock2)
        missing3 = bq.fetchMissingSidecars(broot1, fuluBlock1,
                                           peerCustodyColumns1)
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

    bq.remove(Slot(1))
    bq.remove(Slot(2))
    check len(bq) == 0

  test "popSidecars()/hasSidecars() return []/true on block without columns":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))
    var
      bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
    let
      blockRoot1 = genBlockRoot(100)
      blockRoot2 = genBlockRoot(5337)
      blockRoot3 = genBlockRoot(1294967295)
      fuluBlock1 = genFuluSignedBeaconBlock(blockRoot1, [])
      fuluBlock2 = genFuluSignedBeaconBlock(blockRoot2, [])
      fuluBlock3 = genFuluSignedBeaconBlock(blockRoot3, [])

    check:
      bq.hasSidecars(fuluBlock1.root, fuluBlock1) == true
      bq.hasSidecars(fuluBlock2.root, fuluBlock2) == true
      bq.hasSidecars(fuluBlock3.root, fuluBlock3) == true

    let
      res1 = bq.popSidecars(fuluBlock1.root, fuluBlock1)
      res2 = bq.popSidecars(fuluBlock2.root, fuluBlock2)
      res3 = bq.popSidecars(fuluBlock3.root, fuluBlock3)

    check:
      res1.isOk()
      len(res1.get()) == 0
      res2.isOk()
      len(res2.get()) == 0
      res3.isOk()
      len(res3.get()) == 0

  test "overfill protection test":
    let
      custodyColumns =
        [63, 64, 65, 66, 95, 96, 97, 98].mapIt(ColumnIndex(it))

    var
      bq = ColumnQuarantine.init(cfg, custodyColumns, nil)
      sidecars: seq[tuple[sidecar: ref DataColumnSidecar,
                          blockRoot: Eth2Digest]]

    let maxSidecars = int(NUMBER_OF_COLUMNS * SLOTS_PER_EPOCH) * 3
    for i in 0 ..< maxSidecars:
      let
        index = i mod len(custodyColumns)
        slot = i div len(custodyColumns) + 100
        blockRoot = genBlockRoot(slot)
        sidecar = newClone(
          genDataColumnSidecar(index = int(custodyColumns[index]),
                               slot, proposer_index = i))
      sidecars.add((sidecar, blockRoot))

    for item in sidecars:
      bq.put(item.blockRoot, item.sidecar)

    check len(bq) == maxSidecars

    # put(sidecar) test

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
          slot =
            sidecars[i].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[i].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[i].sidecar[].index
        ) == true

    let
      sidecar = newClone(
        genDataColumnSidecar(index = int(custodyColumns[0]),
                             slot = 10000, proposer_index = 1000000))
      blockRoot = genBlockRoot(10000)
    check:
      bq.hasSidecar(slot = Slot(10000), proposer_index = 1000000'u64,
                    index = custodyColumns[0]) == false
    bq.put(blockRoot, sidecar)
    check:
      len(bq) == (len(sidecars) - len(custodyColumns) + 1)
      bq.hasSidecar(slot = Slot(10000), proposer_index = 1000000'u64,
                    index = custodyColumns[0]) == true

    for i in 0 ..< len(custodyColumns):
      check:
        bq.hasSidecar(
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
          var res: seq[ref DataColumnSidecar]
          for i in 0 ..< len(custodyColumns):
            let sidecar =
              newClone(genDataColumnSidecar(index = int(custodyColumns[i]),
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
        bq.hasSidecar(s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == false

    bq.put(mblockRoot, msidecars)
    check len(bq) == beforeLength

    for s in msidecars:
      check:
        bq.hasSidecar(s.signed_block_header.message.slot,
                      s.signed_block_header.message.proposer_index,
                      s.index) == true

    for i in 0 ..< len(custodyColumns):
      let j = len(custodyColumns) + i
      check:
        bq.hasSidecar(
          slot =
            sidecars[j].sidecar[].signed_block_header.message.slot,
          proposer_index =
            sidecars[j].sidecar[].signed_block_header.message.proposer_index,
          index = sidecars[j].sidecar[].index
        ) == false

# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import stew/endians2,
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

# func genFuluSignedBeaconBlock[T, U](
#     blobs: HSlice[T, U]
# ): fulu.SignedBeaconBlock =
#   var res: seq[KzgCommitment]
#   for blobIdx in blobs:
#     res.add(genKzgCommitment(blobIdx))
#   fulu.SignedBeaconBlock(
#     message: fulu.BeaconBlock(
#       body: fulu.BeaconBlockBody(blob_kzg_commitments: KzgCommitments(res))))

func compareSidecars(a, b: openArray[ref BlobSidecar]): bool =
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
    a: openArray[ref BlobSidecar],
    b: openArray[BlobIdentifier]
): bool =
  if len(a) != len(b):
    return false
  if len(a) == 0:
    return true
  for i in 0 ..< len(a):
    if (a[i][].index != b[i].index) or (b[i].block_root != blockRoot):
      return false
  true

suite "BlobQuarantine datastructure test suite " & preset():
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
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(4)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(5)) == false
      bq.hasSidecar(Slot(1), uint64(5), BlobIndex(6)) == false
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

  test "put()/hasSidecars/popSidecars/remove() test":
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

    for sidecar in sidecars1:
      bq.put(broot1, sidecar)

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

suite "ColumnQuarantine datastructure test suite " & preset():
  setup:
    let cfg = defaultRuntimeConfig

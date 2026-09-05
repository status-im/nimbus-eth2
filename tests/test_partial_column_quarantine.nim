# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

# Spec references:
# - Fulu: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md
# - Gloas: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/partial-columns/p2p-interface.md

import
  stew/endians2,
  unittest2,
  kzg4844/kzg_abi,
  ssz_serialization/[types as sszTypes, bitseqs],
  ../beacon_chain/spec/datatypes/[deneb, gloas],
  ../beacon_chain/spec/presets,
  ../beacon_chain/consensus_object_pools/partial_column_quarantine

from ../beacon_chain/spec/datatypes/fulu import ColumnIndex

func genDigest(index: int): Eth2Digest =
  let tmp = uint64(index).toBytesLE()
  copyMem(addr result.data[0], addr tmp[0], sizeof(uint64))

func gen[T](index: int): T =
  let tmp = uint64(index).toBytesLE()
  copyMem(addr result.bytes[0], addr tmp[0], sizeof(uint64))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/partial-columns/p2p-interface.md#new-partialdatacolumngroupid
func genPartialDataColumnGroupID(
    slot: int, beaconBlockRootSeed: int
): ref gloas.PartialDataColumnGroupID =
  (ref gloas.PartialDataColumnGroupID)(
    slot: Slot(slot),
    beacon_block_root: genDigest(beaconBlockRootSeed))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/partial-columns/p2p-interface.md#modified-partialdatacolumnsidecar
func genGloasPartialDataColumnSidecar(
    blobIndices: openArray[int], startCellId: int = 0
): ref gloas.PartialDataColumnSidecar =
  ## Build a Gloas PartialDataColumnSidecar (singular `partial_column`,
  ## no `header` field).
  var
    bitmap = gloas.CellsPresentBits.init(
      if blobIndices.len == 0: 0 else: max(blobIndices) + 1)
    cells = newSeqOfCap[KzgCell](blobIndices.len)
    proofs = newSeqOfCap[KzgProof](blobIndices.len)
  for i, blobIdx in blobIndices:
    bitmap[Natural(blobIdx)] = true
    cells.add(gen[KzgCell](startCellId + i))
    proofs.add(gen[KzgProof](startCellId + i))
  (ref gloas.PartialDataColumnSidecar)(
    cells_present_bitmap: bitmap,
    partial_column: cells,
    kzg_proofs: proofs)

suite "Partial Column Quarantine":
  func gid(slot: int, rootSeed: int): gloas.PartialDataColumnGroupID =
    gloas.PartialDataColumnGroupID(
      slot: Slot(slot), beacon_block_root: genDigest(rootSeed))

  test "Init creates empty quarantine":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)
    check:
      not quarantine.hasPartialGroupID(id)
      not quarantine.hasEntry(id, ColumnIndex(0))

  test "putPartialGroupID stores group id under itself":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 11, beaconBlockRootSeed = 7)
    quarantine.putPartialGroupID(groupId)
    check:
      quarantine.hasPartialGroupID(groupId[])

  test "Group IDs with same root but different slots are distinct keys":
    var quarantine = PartialColumnQuarantine.init()
    let
      a = genPartialDataColumnGroupID(slot = 10, beaconBlockRootSeed = 1)
      b = genPartialDataColumnGroupID(slot = 11, beaconBlockRootSeed = 1)
    quarantine.putPartialGroupID(a)
    check:
      quarantine.hasPartialGroupID(a[])
      not quarantine.hasPartialGroupID(b[])

  test "Header LRU eviction (gloas, keyed by GroupID)":
    var quarantine = PartialColumnQuarantine.init()
    for i in 0 ..< MaxPartialHeaders + 3:
      quarantine.putPartialGroupID(
        genPartialDataColumnGroupID(slot = i, beaconBlockRootSeed = i))
    check:
      quarantine.hasPartialGroupID(gid(MaxPartialHeaders + 2,
                                      MaxPartialHeaders + 2))
      not quarantine.hasPartialGroupID(gid(0, 0))

  test "getOrCreateEntry reflects gloas group-id validation":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 3, beaconBlockRootSeed = 1)

    let entry1 = quarantine.getOrCreateEntry(groupId[], ColumnIndex(0),
                                             numBlobs = 2)
    check entry1.headerValidated == false

    quarantine.putPartialGroupID(groupId)
    let entry2 = quarantine.getOrCreateEntry(groupId[], ColumnIndex(1),
                                             numBlobs = 2)
    check entry2.headerValidated == true

  test "addCells ingests cells from a gloas PartialDataColumnSidecar":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(2, 1)
      colIdx = ColumnIndex(2)
      numBlobs = 4

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs)
    check entry == quarantine.getEntry(groupId, colIdx).get()

    let sidecar = genGloasPartialDataColumnSidecar([1, 3], startCellId = 200)
    quarantine.addCells(groupId, colIdx, sidecar)

    check:
      not quarantine.hasCellReceived(groupId, colIdx, 0)
      quarantine.hasCellReceived(groupId, colIdx, 1)
      not quarantine.hasCellReceived(groupId, colIdx, 2)
      quarantine.hasCellReceived(groupId, colIdx, 3)

    let updated = quarantine.getEntry(groupId, colIdx).get()
    check:
      updated.cells[1].get() == gen[KzgCell](200)
      updated.proofs[1].get() == gen[KzgProof](200)
      updated.cells[3].get() == gen[KzgCell](201)
      updated.proofs[3].get() == gen[KzgProof](201)

  test "isComplete and assembleDataColumnSidecar (gloas)":
    var quarantine = PartialColumnQuarantine.init()
    let
      colIdx = ColumnIndex(4)
      numBlobs = 2
      groupId = genPartialDataColumnGroupID(slot = 99, beaconBlockRootSeed = 7)

    quarantine.putPartialGroupID(groupId)
    let entry = quarantine.getOrCreateEntry(groupId[], colIdx, numBlobs)
    check entry == quarantine.getEntry(groupId[], colIdx).get()

    quarantine.addCells(groupId[], colIdx,
      genGloasPartialDataColumnSidecar([0], startCellId = 70))
    check not quarantine.isComplete(groupId[], colIdx)
    check quarantine.assembleDataColumnSidecar(groupId[], colIdx).isNone()

    quarantine.addCells(groupId[], colIdx,
      genGloasPartialDataColumnSidecar([1], startCellId = 71))
    check quarantine.isComplete(groupId[], colIdx)

    let assembled = quarantine.assembleDataColumnSidecar(groupId[], colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    # gloas.DataColumnSidecar carries slot + beacon_block_root instead of
    # signed_block_header / kzg_commitments / inclusion proof:
    # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#modified-datacolumnsidecar
    check:
      dcs.index == colIdx
      dcs.column.len == numBlobs
      dcs.kzg_proofs.len == numBlobs
      dcs.slot == Slot(99)
      dcs.beacon_block_root == genDigest(7)
      dcs.column[0] == gen[KzgCell](70)
      dcs.column[1] == gen[KzgCell](71)
      dcs.kzg_proofs[0] == gen[KzgProof](70)
      dcs.kzg_proofs[1] == gen[KzgProof](71)

  test "assembleDataColumnSidecar returns none when group-id missing (gloas)":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    var allReceived = BitSeq.init(1)
    allReceived.setBit(0)
    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: allReceived,
      cells: @[Opt.some(gen[KzgCell](1))],
      proofs: @[Opt.some(gen[KzgProof](1))]))

    check quarantine.assembleDataColumnSidecar(groupId, colIdx).isNone()

  test "Remove header (group id) does not remove entries (gloas)":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 1, beaconBlockRootSeed = 1)

    quarantine.putPartialGroupID(groupId)
    quarantine.putEntry(groupId[], ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeHeader(groupId[])
    check:
      not quarantine.hasPartialGroupID(groupId[])
      quarantine.hasEntry(groupId[], ColumnIndex(0))

  test "GroupID hash and equality":
    let
      a = gid(10, 1)
      b = gid(10, 1)
      c = gid(11, 1)
      d = gid(10, 2)
    check:
      a == b
      hash(a) == hash(b)
      a != c
      a != d
      hash(a) != hash(c)
      hash(a) != hash(d)

  # --- Header management ---

  test "Remove header":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 10, beaconBlockRootSeed = 1)

    quarantine.putPartialGroupID(groupId)
    check quarantine.hasPartialGroupID(groupId[])

    quarantine.removeHeader(groupId[])
    check:
      not quarantine.hasPartialGroupID(groupId[])

  test "Remove non-existent header is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(99, 99)
    quarantine.removeHeader(groupId) # should not crash

  # --- Entry (cell tracking) management ---

  test "Put and get entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(5)
      entry = PartialColumnEntry(
        headerValidated: true,
        cellsReceived: BitSeq.init(4))

    quarantine.putEntry(groupId, colIdx, entry)
    check:
      quarantine.hasEntry(groupId, colIdx)
      quarantine.getEntry(groupId, colIdx).isSome()
      quarantine.getEntry(groupId, colIdx).get().headerValidated == true
      quarantine.getEntry(groupId, colIdx).get().cellsReceived.len == 4

  test "Get entry for unknown key returns none":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(1, 1)
    check:
      not quarantine.hasEntry(groupId, ColumnIndex(0))
      quarantine.getEntry(groupId, ColumnIndex(0)).isNone()

  test "Different column indices are independent":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(1, 1)

    quarantine.putEntry(groupId, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))
    quarantine.putEntry(groupId, ColumnIndex(1), PartialColumnEntry(
      headerValidated: false, cellsReceived: BitSeq.init(5)))

    check:
      quarantine.hasEntry(groupId, ColumnIndex(0))
      quarantine.hasEntry(groupId, ColumnIndex(1))
      not quarantine.hasEntry(groupId, ColumnIndex(2))
      quarantine.getEntry(groupId, ColumnIndex(0)).get().cellsReceived.len == 3
      quarantine.getEntry(groupId, ColumnIndex(1)).get().cellsReceived.len == 5

  test "Different block roots with same column index are independent":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId1 = gid(1, 1)
      groupId2 = gid(2, 2)
      colIdx = ColumnIndex(7)

    quarantine.putEntry(groupId1, colIdx, PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    quarantine.putEntry(groupId2, colIdx, PartialColumnEntry(
      headerValidated: false, cellsReceived: BitSeq.init(4)))

    check:
      quarantine.getEntry(groupId1, colIdx).get().headerValidated == true
      quarantine.getEntry(groupId2, colIdx).get().headerValidated == false

  test "Remove entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(3)

    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    check quarantine.hasEntry(groupId, colIdx)

    quarantine.removeEntry(groupId, colIdx)
    check:
      not quarantine.hasEntry(groupId, colIdx)
      quarantine.getEntry(groupId, colIdx).isNone()

  test "Remove entry does not affect other entries":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(1, 1)

    quarantine.putEntry(groupId, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    quarantine.putEntry(groupId, ColumnIndex(1), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeEntry(groupId, ColumnIndex(0))
    check:
      not quarantine.hasEntry(groupId, ColumnIndex(0))
      quarantine.hasEntry(groupId, ColumnIndex(1))

  test "Remove non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.removeEntry(gid(99, 99), ColumnIndex(0))

  # --- getOrCreateEntry ---

  test "getOrCreateEntry creates new entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(2)

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs = 6)
    check:
      entry.cellsReceived.len == 6
      entry.headerValidated == false
      quarantine.hasEntry(groupId, colIdx)

  test "getOrCreateEntry returns existing entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(2)

    var cellBits = BitSeq.init(3)
    cellBits.setBit(0)
    cellBits.setBit(2)
    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: cellBits))

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs = 10)
    check:
      # Should return the existing entry, not create a new one with 10 blobs
      entry.cellsReceived.len == 3
      entry.headerValidated == true
      entry.cellsReceived[0] == true
      entry.cellsReceived[1] == false
      entry.cellsReceived[2] == true

  # --- Cell tracking ---

  test "Mark and check cell received":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(4)))

    check:
      not quarantine.hasCellReceived(groupId, colIdx, 0)
      not quarantine.hasCellReceived(groupId, colIdx, 1)
      not quarantine.hasCellReceived(groupId, colIdx, 2)
      not quarantine.hasCellReceived(groupId, colIdx, 3)

    quarantine.markCellReceived(groupId, colIdx, 1)
    quarantine.markCellReceived(groupId, colIdx, 3)

    check:
      not quarantine.hasCellReceived(groupId, colIdx, 0)
      quarantine.hasCellReceived(groupId, colIdx, 1)
      not quarantine.hasCellReceived(groupId, colIdx, 2)
      quarantine.hasCellReceived(groupId, colIdx, 3)

  test "Mark cell received for non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(99, 99)
    quarantine.markCellReceived(groupId, ColumnIndex(0), 0)
    check not quarantine.hasCellReceived(groupId, ColumnIndex(0), 0)

  test "Mark cell received with out-of-bounds blob index is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(3)))

    quarantine.markCellReceived(groupId, colIdx, 10) # out of bounds
    check not quarantine.hasCellReceived(groupId, colIdx, 10)

  test "hasCellReceived for non-existent entry returns false":
    var quarantine = PartialColumnQuarantine.init()
    check not quarantine.hasCellReceived(gid(1, 1), ColumnIndex(0), 0)

  test "hasCellReceived for out-of-bounds index returns false":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(2)))

    check not quarantine.hasCellReceived(groupId, colIdx, 5)

  test "Mark all cells received":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)
      numBlobs = 6

    quarantine.putEntry(groupId, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(numBlobs)))

    for i in 0 ..< numBlobs:
      quarantine.markCellReceived(groupId, colIdx, i)

    for i in 0 ..< numBlobs:
      check quarantine.hasCellReceived(groupId, colIdx, i)

  test "Cell tracking is per-column":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(1, 1)

    quarantine.putEntry(groupId, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))
    quarantine.putEntry(groupId, ColumnIndex(1), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.markCellReceived(groupId, ColumnIndex(0), 1)

    check:
      quarantine.hasCellReceived(groupId, ColumnIndex(0), 1)
      not quarantine.hasCellReceived(groupId, ColumnIndex(1), 1)

  # --- PartialColumnKey equality and hashing ---

  test "PartialColumnKey equality":
    let
      groupId1 = gid(1, 1)
      groupId2 = gid(2, 2)
    check:
      PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(0)) ==
        PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(0))
      PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(0)) !=
        PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(1))
      PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(0)) !=
        PartialColumnKey(blockId: groupId2, columnIndex: ColumnIndex(0))

  test "PartialColumnKey hash differs for different keys":
    let
      groupId1 = gid(1, 1)
      groupId2 = gid(2, 2)
      k1 = PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(0))
      k2 = PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(1))
      k3 = PartialColumnKey(blockId: groupId2, columnIndex: ColumnIndex(0))
    check hash(k1) == hash(
      PartialColumnKey(blockId: groupId1, columnIndex: ColumnIndex(0)))
    check hash(k1) != hash(k2)
    check hash(k1) != hash(k3)
    check hash(k2) != hash(k3)

  # --- Header and entry independence ---

  test "Removing entry does not remove header":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 1, beaconBlockRootSeed = 1)

    quarantine.putPartialGroupID(groupId)
    quarantine.putEntry(groupId[], ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeEntry(groupId[], ColumnIndex(0))
    check:
      quarantine.hasPartialGroupID(groupId[])
      not quarantine.hasEntry(groupId[], ColumnIndex(0))

  # --- markCellReceived with cell data and proof ---

  test "markCellReceived with data stores cell and proof":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)
      numBlobs = 3

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs)
    check entry == quarantine.getEntry(groupId, colIdx).get()

    let
      cell = gen[KzgCell](42)
      proof = gen[KzgProof](42)
    quarantine.markCellReceived(groupId, colIdx, 1, cell, proof)

    check quarantine.hasCellReceived(groupId, colIdx, 1)

    let updated = quarantine.getEntry(groupId, colIdx).get()
    check:
      updated.cells[1].isSome()
      updated.cells[1].get() == cell
      updated.proofs[1].isSome()
      updated.proofs[1].get() == proof
      updated.cells[0].isNone()
      updated.cells[2].isNone()
      updated.proofs[0].isNone()
      updated.proofs[2].isNone()

  test "markCellReceived with data on non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.markCellReceived(
      gid(99, 99), ColumnIndex(0), 0, gen[KzgCell](1), gen[KzgProof](1))
    check not quarantine.hasCellReceived(gid(99, 99), ColumnIndex(0), 0)

  test "markCellReceived with data out-of-bounds is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(1, 1)
    let entry = quarantine.getOrCreateEntry(groupId, ColumnIndex(0), numBlobs = 2)
    check entry == quarantine.getEntry(groupId, ColumnIndex(0)).get()
    quarantine.markCellReceived(
      groupId, ColumnIndex(0), 10, gen[KzgCell](1), gen[KzgProof](1))
    check not quarantine.hasCellReceived(groupId, ColumnIndex(0), 10)

  # --- getOrCreateEntry initializes cells/proofs seqs ---

  test "getOrCreateEntry new entry has properly sized cells and proofs":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)
      numBlobs = 4

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs)
    check:
      entry.cells.len == numBlobs
      entry.proofs.len == numBlobs
      entry.cellsReceived.len == numBlobs
    for i in 0 ..< numBlobs:
      check:
        entry.cells[i].isNone()
        entry.proofs[i].isNone()
        entry.cellsReceived[i] == false

  # --- addCells ---

  test "addCells accumulates across multiple sidecars":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)
      numBlobs = 3

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs)
    check entry == quarantine.getEntry(groupId, colIdx).get()

    quarantine.addCells(groupId, colIdx,
      genGloasPartialDataColumnSidecar([0], startCellId = 10))
    quarantine.addCells(groupId, colIdx,
      genGloasPartialDataColumnSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(groupId, colIdx, 0)
      not quarantine.hasCellReceived(groupId, colIdx, 1)
      quarantine.hasCellReceived(groupId, colIdx, 2)

    let updated = quarantine.getEntry(groupId, colIdx).get()
    check:
      updated.cells[0].get() == gen[KzgCell](10)
      updated.cells[2].get() == gen[KzgCell](20)

  test "addCells on non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let sidecar = genGloasPartialDataColumnSidecar([0], startCellId = 1)
    quarantine.addCells(gid(99, 99), ColumnIndex(0), sidecar)
    check not quarantine.hasEntry(gid(99, 99), ColumnIndex(0))

  test "addCells with overlapping bitmap overwrites existing cells":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(groupId, colIdx).get()

    quarantine.addCells(groupId, colIdx,
      genGloasPartialDataColumnSidecar([1], startCellId = 50))
    let entry1 = quarantine.getEntry(groupId, colIdx).get()
    check entry1.cells[1].get() == gen[KzgCell](50)

    quarantine.addCells(groupId, colIdx,
      genGloasPartialDataColumnSidecar([1], startCellId = 99))
    let entry2 = quarantine.getEntry(groupId, colIdx).get()
    check entry2.cells[1].get() == gen[KzgCell](99)

  test "addCells is independent across columns":
    var quarantine = PartialColumnQuarantine.init()
    let groupId = gid(1, 1)

    let entry0 = quarantine.getOrCreateEntry(groupId, ColumnIndex(0), numBlobs = 3)
    check entry0 == quarantine.getEntry(groupId, ColumnIndex(0)).get()
    let entry1 = quarantine.getOrCreateEntry(groupId, ColumnIndex(1), numBlobs = 3)
    check entry1 == quarantine.getEntry(groupId, ColumnIndex(1)).get()

    quarantine.addCells(groupId, ColumnIndex(0),
      genGloasPartialDataColumnSidecar([0], startCellId = 10))
    quarantine.addCells(groupId, ColumnIndex(1),
      genGloasPartialDataColumnSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(groupId, ColumnIndex(0), 0)
      not quarantine.hasCellReceived(groupId, ColumnIndex(0), 2)
      not quarantine.hasCellReceived(groupId, ColumnIndex(1), 0)
      quarantine.hasCellReceived(groupId, ColumnIndex(1), 2)

  # --- isComplete ---

  test "isComplete returns false for non-existent entry":
    var quarantine = PartialColumnQuarantine.init()
    check not quarantine.isComplete(gid(99, 99), ColumnIndex(0))

  test "isComplete returns false when header not validated":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs = 2)
    check entry.headerValidated == false
    quarantine.addCells(groupId, colIdx,
      genGloasPartialDataColumnSidecar([0, 1], startCellId = 1))

    check not quarantine.isComplete(groupId, colIdx)

  test "isComplete with single blob":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = genPartialDataColumnGroupID(slot = 1, beaconBlockRootSeed = 1)
      colIdx = ColumnIndex(0)

    quarantine.putPartialGroupID(groupId)
    let entry = quarantine.getOrCreateEntry(groupId[], colIdx, numBlobs = 1)
    check entry == quarantine.getEntry(groupId[], colIdx).get()
    quarantine.addCells(groupId[], colIdx,
      genGloasPartialDataColumnSidecar([0], startCellId = 1))

    check quarantine.isComplete(groupId[], colIdx)

  # --- assembleDataColumnSidecar ---

  test "assembleDataColumnSidecar returns none for non-existent entry":
    var quarantine = PartialColumnQuarantine.init()
    check quarantine.assembleDataColumnSidecar(
      gid(99, 99), ColumnIndex(0)).isNone()

  test "assembleDataColumnSidecar returns none when header not validated":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(groupId, colIdx, numBlobs = 2)
    check entry.headerValidated == false
    quarantine.addCells(groupId, colIdx,
      genGloasPartialDataColumnSidecar([0, 1], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(groupId, colIdx).isNone()

  test "assembleDataColumnSidecar with markCellReceived (data overload)":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = genPartialDataColumnGroupID(slot = 1, beaconBlockRootSeed = 1)
      colIdx = ColumnIndex(0)
      numBlobs = 2

    quarantine.putPartialGroupID(groupId)
    let entry = quarantine.getOrCreateEntry(groupId[], colIdx, numBlobs)
    check entry == quarantine.getEntry(groupId[], colIdx).get()

    quarantine.markCellReceived(groupId[], colIdx, 0, gen[KzgCell](0), gen[KzgProof](0))
    quarantine.markCellReceived(groupId[], colIdx, 1, gen[KzgCell](1), gen[KzgProof](1))

    let assembled = quarantine.assembleDataColumnSidecar(groupId[], colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.column.len == numBlobs
      dcs.column[0] == gen[KzgCell](0)
      dcs.column[1] == gen[KzgCell](1)

  # --- End-to-end: multiple columns for same block ---

  test "Assemble multiple columns for the same block independently":
    var quarantine = PartialColumnQuarantine.init()
    let
      groupId = genPartialDataColumnGroupID(slot = 1, beaconBlockRootSeed = 1)
      numBlobs = 2

    quarantine.putPartialGroupID(groupId)

    let entry0 = quarantine.getOrCreateEntry(groupId[], ColumnIndex(0), numBlobs)
    check entry0 == quarantine.getEntry(groupId[], ColumnIndex(0)).get()
    let entry1 = quarantine.getOrCreateEntry(groupId[], ColumnIndex(1), numBlobs)
    check entry1 == quarantine.getEntry(groupId[], ColumnIndex(1)).get()

    quarantine.addCells(groupId[], ColumnIndex(0),
      genGloasPartialDataColumnSidecar([0, 1], startCellId = 10))
    quarantine.addCells(groupId[], ColumnIndex(1),
      genGloasPartialDataColumnSidecar([0], startCellId = 20))

    check:
      quarantine.isComplete(groupId[], ColumnIndex(0))
      not quarantine.isComplete(groupId[], ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(groupId[], ColumnIndex(0)).isSome()
      quarantine.assembleDataColumnSidecar(groupId[], ColumnIndex(1)).isNone()

    quarantine.addCells(groupId[], ColumnIndex(1),
      genGloasPartialDataColumnSidecar([1], startCellId = 21))

    check:
      quarantine.isComplete(groupId[], ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(groupId[], ColumnIndex(1)).isSome()

    let
      dcs0 = quarantine.assembleDataColumnSidecar(groupId[], ColumnIndex(0)).get()
      dcs1 = quarantine.assembleDataColumnSidecar(groupId[], ColumnIndex(1)).get()
    check:
      dcs0.index == ColumnIndex(0)
      dcs1.index == ColumnIndex(1)
      dcs0.column[0] == gen[KzgCell](10)
      dcs0.column[1] == gen[KzgCell](11)
      dcs1.column[0] == gen[KzgCell](20)
      dcs1.column[1] == gen[KzgCell](21)

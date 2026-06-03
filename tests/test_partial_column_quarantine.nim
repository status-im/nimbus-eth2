# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

# Spec references:
# - Fulu: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md
# - Gloas: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/partial-columns/p2p-interface.md

import
  stew/endians2,
  unittest2,
  kzg4844/kzg_abi,
  ssz_serialization/[types as sszTypes, bitseqs],
  ../beacon_chain/spec/datatypes/[fulu, gloas, deneb],
  ../beacon_chain/spec/presets,
  ../beacon_chain/consensus_object_pools/partial_column_quarantine

func genDigest(index: int): Eth2Digest =
  let tmp = uint64(index).toBytesLE()
  copyMem(addr result.data[0], unsafeAddr tmp[0], sizeof(uint64))

func gen[T](index: int): T =
  let tmp = uint64(index).toBytesLE()
  copyMem(addr result.bytes[0], unsafeAddr tmp[0], sizeof(uint64))

# --- Fulu helpers ---
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md#partialdatacolumnheader

proc genPartialDataColumnHeader(
    slot: int, proposerIndex: int, numCommitments: int
): ref fulu.PartialDataColumnHeader =
  var commitments: KzgCommitments
  for i in 0 ..< numCommitments:
    check commitments.add(gen[KzgCommitment](i))
  result = new fulu.PartialDataColumnHeader
  result[] = fulu.PartialDataColumnHeader(
    kzg_commitments: commitments,
    signed_block_header: SignedBeaconBlockHeader(
      message: BeaconBlockHeader(
        slot: Slot(slot),
        proposer_index: uint64(proposerIndex))))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md#partialdatacolumnsidecar
func genPartialDataColumnSidecar(
    blobIndices: openArray[int], startCellId: int = 0
): ref fulu.PartialDataColumnSidecar =
  ## Build a Fulu PartialDataColumnSidecar with cells at the given blob
  ## indices. Cell/proof payloads are deterministic from startCellId.
  var
    bitmap = fulu.CellsPresentBits.init(
      if blobIndices.len == 0: 0 else: max(blobIndices) + 1)
    cells = newSeqOfCap[KzgCell](blobIndices.len)
    proofs = newSeqOfCap[KzgProof](blobIndices.len)
  for i, blobIdx in blobIndices:
    bitmap[Natural(blobIdx)] = true
    cells.add(gen[KzgCell](startCellId + i))
    proofs.add(gen[KzgProof](startCellId + i))
  result = new fulu.PartialDataColumnSidecar
  result[] = fulu.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap,
    partial_column: DataColumn.init(cells),
    kzg_proofs: deneb.KzgProofs.init(proofs))

# --- Gloas helpers ---
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/partial-columns/p2p-interface.md#new-partialdatacolumngroupid

proc genPartialDataColumnGroupID(
    slot: int, beaconBlockRootSeed: int
): ref gloas.PartialDataColumnGroupID =
  result = new gloas.PartialDataColumnGroupID
  result[] = gloas.PartialDataColumnGroupID(
    slot: Slot(slot),
    beacon_block_root: genDigest(beaconBlockRootSeed))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/partial-columns/p2p-interface.md#modified-partialdatacolumnsidecar
func genGloasPartialDataColumnSidecar(
    blobIndices: openArray[int], startCellId: int = 0
): ref gloas.PartialDataColumnSidecar =
  ## Build a Gloas PartialDataColumnSidecar (singular `partial_column`,
  ## no `header` field).
  var
    bitmap = fulu.CellsPresentBits.init(
      if blobIndices.len == 0: 0 else: max(blobIndices) + 1)
    cells = newSeqOfCap[KzgCell](blobIndices.len)
    proofs = newSeqOfCap[KzgProof](blobIndices.len)
  for i, blobIdx in blobIndices:
    bitmap[Natural(blobIdx)] = true
    cells.add(gen[KzgCell](startCellId + i))
    proofs.add(gen[KzgProof](startCellId + i))
  result = new gloas.PartialDataColumnSidecar
  result[] = gloas.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap,
    partial_column: DataColumn.init(cells),
    kzg_proofs: deneb.KzgProofs.init(proofs))

suite "Partial Column Quarantine (Fulu)":
  test "Init creates empty quarantine":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)
    check:
      not quarantine.hasPartialHeader(root)
      quarantine.getPartialHeader(root).isNone()
      not quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.getEntry(root, ColumnIndex(0)).isNone()

  # --- Header management ---

  test "Put and get partial header":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      header = genPartialDataColumnHeader(slot = 10, proposerIndex = 5,
                                          numCommitments = 3)
    quarantine.putPartialHeader(root, header)
    check:
      quarantine.hasPartialHeader(root)
      quarantine.getPartialHeader(root).isSome()
      quarantine.getPartialHeader(root).get().signed_block_header.message.slot ==
        Slot(10)
      quarantine.getPartialHeader(root).get().kzg_commitments.len == 3

  test "Get header for unknown root returns none":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root1 = genDigest(1)
      root2 = genDigest(2)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 1)
    quarantine.putPartialHeader(root1, header)
    check:
      quarantine.hasPartialHeader(root1)
      not quarantine.hasPartialHeader(root2)
      quarantine.getPartialHeader(root2).isNone()

  test "Overwrite header with same root":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      header1 = genPartialDataColumnHeader(slot = 10, proposerIndex = 1,
                                           numCommitments = 2)
      header2 = genPartialDataColumnHeader(slot = 10, proposerIndex = 1,
                                           numCommitments = 5)
    quarantine.putPartialHeader(root, header1)
    check quarantine.getPartialHeader(root).get().kzg_commitments.len == 2

    quarantine.putPartialHeader(root, header2)
    check quarantine.getPartialHeader(root).get().kzg_commitments.len == 5

  test "Multiple headers for different roots":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root1 = genDigest(1)
      root2 = genDigest(2)
      root3 = genDigest(3)
      h1 = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                      numCommitments = 1)
      h2 = genPartialDataColumnHeader(slot = 2, proposerIndex = 2,
                                      numCommitments = 2)
      h3 = genPartialDataColumnHeader(slot = 3, proposerIndex = 3,
                                      numCommitments = 3)

    quarantine.putPartialHeader(root1, h1)
    quarantine.putPartialHeader(root2, h2)
    quarantine.putPartialHeader(root3, h3)

    check:
      quarantine.getPartialHeader(root1).get().kzg_commitments.len == 1
      quarantine.getPartialHeader(root2).get().kzg_commitments.len == 2
      quarantine.getPartialHeader(root3).get().kzg_commitments.len == 3

  test "Remove header":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      header = genPartialDataColumnHeader(slot = 10, proposerIndex = 1,
                                          numCommitments = 2)

    quarantine.putPartialHeader(root, header)
    check quarantine.hasPartialHeader(root)

    quarantine.removeHeader(root)
    check:
      not quarantine.hasPartialHeader(root)
      quarantine.getPartialHeader(root).isNone()

  test "Remove non-existent header is no-op":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(99)
    quarantine.removeHeader(root) # should not crash

  # --- Entry (cell tracking) management ---

  test "Put and get entry":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(5)
      entry = PartialColumnEntry(
        headerValidated: true,
        cellsReceived: BitSeq.init(4))

    quarantine.putEntry(root, colIdx, entry)
    check:
      quarantine.hasEntry(root, colIdx)
      quarantine.getEntry(root, colIdx).isSome()
      quarantine.getEntry(root, colIdx).get().headerValidated == true
      quarantine.getEntry(root, colIdx).get().cellsReceived.len == 4

  test "Get entry for unknown key returns none":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)
    check:
      not quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.getEntry(root, ColumnIndex(0)).isNone()

  test "Different column indices are independent":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)

    quarantine.putEntry(root, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))
    quarantine.putEntry(root, ColumnIndex(1), PartialColumnEntry(
      headerValidated: false, cellsReceived: BitSeq.init(5)))

    check:
      quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.hasEntry(root, ColumnIndex(1))
      not quarantine.hasEntry(root, ColumnIndex(2))
      quarantine.getEntry(root, ColumnIndex(0)).get().cellsReceived.len == 3
      quarantine.getEntry(root, ColumnIndex(1)).get().cellsReceived.len == 5

  test "Different block roots with same column index are independent":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root1 = genDigest(1)
      root2 = genDigest(2)
      colIdx = ColumnIndex(7)

    quarantine.putEntry(root1, colIdx, PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    quarantine.putEntry(root2, colIdx, PartialColumnEntry(
      headerValidated: false, cellsReceived: BitSeq.init(4)))

    check:
      quarantine.getEntry(root1, colIdx).get().headerValidated == true
      quarantine.getEntry(root2, colIdx).get().headerValidated == false

  test "Remove entry":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(3)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    check quarantine.hasEntry(root, colIdx)

    quarantine.removeEntry(root, colIdx)
    check:
      not quarantine.hasEntry(root, colIdx)
      quarantine.getEntry(root, colIdx).isNone()

  test "Remove entry does not affect other entries":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)

    quarantine.putEntry(root, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    quarantine.putEntry(root, ColumnIndex(1), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeEntry(root, ColumnIndex(0))
    check:
      not quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.hasEntry(root, ColumnIndex(1))

  test "Remove non-existent entry is no-op":
    var quarantine = FuluPartialColumnQuarantine.init()
    quarantine.removeEntry(genDigest(99), ColumnIndex(0))

  # --- getOrCreateEntry ---

  test "getOrCreateEntry creates new entry":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(2)

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 6)
    check:
      entry.cellsReceived.len == 6
      entry.headerValidated == false
      quarantine.hasEntry(root, colIdx)

  test "getOrCreateEntry returns existing entry":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(2)

    var cellBits = BitSeq.init(3)
    cellBits.setBit(0)
    cellBits.setBit(2)
    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: cellBits))

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 10)
    check:
      # Should return the existing entry, not create a new one with 10 blobs
      entry.cellsReceived.len == 3
      entry.headerValidated == true
      entry.cellsReceived[0] == true
      entry.cellsReceived[1] == false
      entry.cellsReceived[2] == true

  test "getOrCreateEntry reflects header validation status":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 5, proposerIndex = 1,
                                          numCommitments = 3)

    # Without header stored
    let entry1 = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)
    check entry1.headerValidated == false

    # Store header, create a new entry on different column
    quarantine.putPartialHeader(root, header)
    let entry2 = quarantine.getOrCreateEntry(root, ColumnIndex(1), numBlobs = 3)
    check entry2.headerValidated == true

  # --- Cell tracking ---

  test "Mark and check cell received":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(4)))

    check:
      not quarantine.hasCellReceived(root, colIdx, 0)
      not quarantine.hasCellReceived(root, colIdx, 1)
      not quarantine.hasCellReceived(root, colIdx, 2)
      not quarantine.hasCellReceived(root, colIdx, 3)

    quarantine.markCellReceived(root, colIdx, 1)
    quarantine.markCellReceived(root, colIdx, 3)

    check:
      not quarantine.hasCellReceived(root, colIdx, 0)
      quarantine.hasCellReceived(root, colIdx, 1)
      not quarantine.hasCellReceived(root, colIdx, 2)
      quarantine.hasCellReceived(root, colIdx, 3)

  test "Mark cell received for non-existent entry is no-op":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(99)
    quarantine.markCellReceived(root, ColumnIndex(0), 0)
    check not quarantine.hasCellReceived(root, ColumnIndex(0), 0)

  test "Mark cell received with out-of-bounds blob index is no-op":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(3)))

    quarantine.markCellReceived(root, colIdx, 10) # out of bounds
    check not quarantine.hasCellReceived(root, colIdx, 10)

  test "hasCellReceived for non-existent entry returns false":
    var quarantine = FuluPartialColumnQuarantine.init()
    check not quarantine.hasCellReceived(genDigest(1), ColumnIndex(0), 0)

  test "hasCellReceived for out-of-bounds index returns false":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(2)))

    check not quarantine.hasCellReceived(root, colIdx, 5)

  test "Mark all cells received":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 6

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(numBlobs)))

    for i in 0 ..< numBlobs:
      quarantine.markCellReceived(root, colIdx, i)

    for i in 0 ..< numBlobs:
      check quarantine.hasCellReceived(root, colIdx, i)

  test "Cell tracking is per-column":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)

    quarantine.putEntry(root, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))
    quarantine.putEntry(root, ColumnIndex(1), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.markCellReceived(root, ColumnIndex(0), 1)

    check:
      quarantine.hasCellReceived(root, ColumnIndex(0), 1)
      not quarantine.hasCellReceived(root, ColumnIndex(1), 1)

  # --- PartialColumnKey equality and hashing ---

  test "PartialColumnKey equality":
    let
      root1 = genDigest(1)
      root2 = genDigest(2)
    check:
      PartialColumnKey[Eth2Digest](blockId: root1, columnIndex: ColumnIndex(0)) ==
        PartialColumnKey[Eth2Digest](blockId: root1, columnIndex: ColumnIndex(0))
      PartialColumnKey[Eth2Digest](blockId: root1, columnIndex: ColumnIndex(0)) !=
        PartialColumnKey[Eth2Digest](blockId: root1, columnIndex: ColumnIndex(1))
      PartialColumnKey[Eth2Digest](blockId: root1, columnIndex: ColumnIndex(0)) !=
        PartialColumnKey[Eth2Digest](blockId: root2, columnIndex: ColumnIndex(0))

  test "PartialColumnKey hash differs for different keys":
    let
      root1 = genDigest(1)
      root2 = genDigest(2)
      k1 = PartialColumnKey[Eth2Digest](
        blockId: root1, columnIndex: ColumnIndex(0))
      k2 = PartialColumnKey[Eth2Digest](
        blockId: root1, columnIndex: ColumnIndex(1))
      k3 = PartialColumnKey[Eth2Digest](
        blockId: root2, columnIndex: ColumnIndex(0))
    check hash(k1) == hash(
      PartialColumnKey[Eth2Digest](blockId: root1, columnIndex: ColumnIndex(0)))
    check hash(k1) != hash(k2)
    check hash(k1) != hash(k3)
    check hash(k2) != hash(k3)

  # --- LRU eviction ---

  test "Header LRU evicts oldest entry when full":
    var quarantine = FuluPartialColumnQuarantine.init()

    for i in 0 ..< MaxPartialHeaders + 5:
      let root = genDigest(i)
      let header = genPartialDataColumnHeader(
        slot = i, proposerIndex = 1, numCommitments = 1)
      quarantine.putPartialHeader(root, header)

    let lastRoot = genDigest(MaxPartialHeaders + 4)
    check quarantine.hasPartialHeader(lastRoot)

    let firstRoot = genDigest(0)
    check not quarantine.hasPartialHeader(firstRoot)

  # --- Header and entry independence ---

  test "Removing header does not remove entries":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 3)

    quarantine.putPartialHeader(root, header)
    quarantine.putEntry(root, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeHeader(root)
    check:
      not quarantine.hasPartialHeader(root)
      quarantine.hasEntry(root, ColumnIndex(0))

  test "Removing entry does not remove header":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 3)

    quarantine.putPartialHeader(root, header)
    quarantine.putEntry(root, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeEntry(root, ColumnIndex(0))
    check:
      quarantine.hasPartialHeader(root)
      not quarantine.hasEntry(root, ColumnIndex(0))

  # --- markCellReceived with cell data and proof ---

  test "markCellReceived with data stores cell and proof":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()

    let
      cell = gen[KzgCell](42)
      proof = gen[KzgProof](42)
    quarantine.markCellReceived(root, colIdx, 1, cell, proof)

    check quarantine.hasCellReceived(root, colIdx, 1)

    let updated = quarantine.getEntry(root, colIdx).get()
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
    var quarantine = FuluPartialColumnQuarantine.init()
    quarantine.markCellReceived(
      genDigest(99), ColumnIndex(0), 0, gen[KzgCell](1), gen[KzgProof](1))
    check not quarantine.hasCellReceived(genDigest(99), ColumnIndex(0), 0)

  test "markCellReceived with data out-of-bounds is no-op":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)
    let entry = quarantine.getOrCreateEntry(root, ColumnIndex(0), numBlobs = 2)
    check entry == quarantine.getEntry(root, ColumnIndex(0)).get()
    quarantine.markCellReceived(
      root, ColumnIndex(0), 10, gen[KzgCell](1), gen[KzgProof](1))
    check not quarantine.hasCellReceived(root, ColumnIndex(0), 10)

  # --- getOrCreateEntry initializes cells/proofs seqs ---

  test "getOrCreateEntry new entry has properly sized cells and proofs":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 4

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
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

  test "addCells ingests cells from a PartialDataColumnSidecar":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(5)
      numBlobs = 4

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()

    let sidecar = genPartialDataColumnSidecar([0, 2], startCellId = 100)
    quarantine.addCells(root, colIdx, sidecar)

    check:
      quarantine.hasCellReceived(root, colIdx, 0)
      not quarantine.hasCellReceived(root, colIdx, 1)
      quarantine.hasCellReceived(root, colIdx, 2)
      not quarantine.hasCellReceived(root, colIdx, 3)

    let updated = quarantine.getEntry(root, colIdx).get()
    check:
      updated.cells[0].isSome()
      updated.cells[0].get() == gen[KzgCell](100)
      updated.proofs[0].isSome()
      updated.proofs[0].get() == gen[KzgProof](100)
      updated.cells[2].isSome()
      updated.cells[2].get() == gen[KzgCell](101)
      updated.proofs[2].isSome()
      updated.proofs[2].get() == gen[KzgProof](101)
      updated.cells[1].isNone()
      updated.cells[3].isNone()

  test "addCells accumulates across multiple sidecars":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 10))
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(root, colIdx, 0)
      not quarantine.hasCellReceived(root, colIdx, 1)
      quarantine.hasCellReceived(root, colIdx, 2)

    let updated = quarantine.getEntry(root, colIdx).get()
    check:
      updated.cells[0].get() == gen[KzgCell](10)
      updated.cells[2].get() == gen[KzgCell](20)

  test "addCells on non-existent entry is no-op":
    var quarantine = FuluPartialColumnQuarantine.init()
    let sidecar = genPartialDataColumnSidecar([0], startCellId = 1)
    quarantine.addCells(genDigest(99), ColumnIndex(0), sidecar)
    check not quarantine.hasEntry(genDigest(99), ColumnIndex(0))

  test "addCells with overlapping bitmap overwrites existing cells":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(root, colIdx).get()

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([1], startCellId = 50))
    let entry1 = quarantine.getEntry(root, colIdx).get()
    check entry1.cells[1].get() == gen[KzgCell](50)

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([1], startCellId = 99))
    let entry2 = quarantine.getEntry(root, colIdx).get()
    check entry2.cells[1].get() == gen[KzgCell](99)

  test "addCells is independent across columns":
    var quarantine = FuluPartialColumnQuarantine.init()
    let root = genDigest(1)

    let entry0 = quarantine.getOrCreateEntry(root, ColumnIndex(0), numBlobs = 3)
    check entry0 == quarantine.getEntry(root, ColumnIndex(0)).get()
    let entry1 = quarantine.getOrCreateEntry(root, ColumnIndex(1), numBlobs = 3)
    check entry1 == quarantine.getEntry(root, ColumnIndex(1)).get()

    quarantine.addCells(root, ColumnIndex(0),
      genPartialDataColumnSidecar([0], startCellId = 10))
    quarantine.addCells(root, ColumnIndex(1),
      genPartialDataColumnSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(root, ColumnIndex(0), 0)
      not quarantine.hasCellReceived(root, ColumnIndex(0), 2)
      not quarantine.hasCellReceived(root, ColumnIndex(1), 0)
      quarantine.hasCellReceived(root, ColumnIndex(1), 2)

  # --- isComplete ---

  test "isComplete returns false for non-existent entry":
    var quarantine = FuluPartialColumnQuarantine.init()
    check not quarantine.isComplete(genDigest(99), ColumnIndex(0))

  test "isComplete returns false when header not validated":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 2)
    check entry.headerValidated == false
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1], startCellId = 1))

    check not quarantine.isComplete(root, colIdx)

  test "isComplete returns false when cells are missing":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 3)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)
    check entry.headerValidated == true
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 2], startCellId = 1))

    check not quarantine.isComplete(root, colIdx)

  test "isComplete returns true when header validated and all cells received":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1, 2], startCellId = 1))

    check quarantine.isComplete(root, colIdx)

  test "isComplete with single blob":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 1)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 1)
    check entry == quarantine.getEntry(root, colIdx).get()
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 1))

    check quarantine.isComplete(root, colIdx)

  test "isComplete becomes true after incremental addCells":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 1))
    check not quarantine.isComplete(root, colIdx)

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([1], startCellId = 2))
    check not quarantine.isComplete(root, colIdx)

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([2], startCellId = 3))
    check quarantine.isComplete(root, colIdx)

  # --- assembleDataColumnSidecar ---

  test "assembleDataColumnSidecar returns none for non-existent entry":
    var quarantine = FuluPartialColumnQuarantine.init()
    check quarantine.assembleDataColumnSidecar(
      genDigest(99), ColumnIndex(0)).isNone()

  test "assembleDataColumnSidecar returns none when header not validated":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 2)
    check entry.headerValidated == false
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

  test "assembleDataColumnSidecar returns none when cells incomplete":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 3)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)
    check entry.headerValidated == true
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 2], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

  test "assembleDataColumnSidecar returns none when header missing from cache":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    var allReceived = BitSeq.init(1)
    allReceived.setBit(0)
    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: allReceived,
      cells: @[Opt.some(gen[KzgCell](1))],
      proofs: @[Opt.some(gen[KzgProof](1))]))

    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

  test "assembleDataColumnSidecar produces correct DataColumnSidecar":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(7)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 10, proposerIndex = 5,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1, 2], startCellId = 50))

    let assembled = quarantine.assembleDataColumnSidecar(root, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.index == colIdx
      dcs.column.len == numBlobs
      dcs.kzg_commitments.len == numBlobs
      dcs.kzg_proofs.len == numBlobs
      dcs.signed_block_header.message.slot == Slot(10)
      dcs.signed_block_header.message.proposer_index == 5'u64

    check:
      dcs.column[0] == gen[KzgCell](50)
      dcs.column[1] == gen[KzgCell](51)
      dcs.column[2] == gen[KzgCell](52)

    check:
      dcs.kzg_proofs[0] == gen[KzgProof](50)
      dcs.kzg_proofs[1] == gen[KzgProof](51)
      dcs.kzg_proofs[2] == gen[KzgProof](52)

    for i in 0 ..< numBlobs:
      check dcs.kzg_commitments[i] == gen[KzgCommitment](i)

  test "assembleDataColumnSidecar with cells added incrementally":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(3)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 5, proposerIndex = 2,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([2], startCellId = 30))
    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 10))
    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([1], startCellId = 20))

    let assembled = quarantine.assembleDataColumnSidecar(root, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.index == colIdx
      dcs.column[0] == gen[KzgCell](10)
      dcs.column[1] == gen[KzgCell](20)
      dcs.column[2] == gen[KzgCell](30)
      dcs.kzg_proofs[0] == gen[KzgProof](10)
      dcs.kzg_proofs[1] == gen[KzgProof](20)
      dcs.kzg_proofs[2] == gen[KzgProof](30)

  test "assembleDataColumnSidecar with markCellReceived (data overload)":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)
      numBlobs = 2
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    check entry == quarantine.getEntry(root, colIdx).get()

    quarantine.markCellReceived(root, colIdx, 0, gen[KzgCell](0), gen[KzgProof](0))
    quarantine.markCellReceived(root, colIdx, 1, gen[KzgCell](1), gen[KzgProof](1))

    let assembled = quarantine.assembleDataColumnSidecar(root, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.column.len == numBlobs
      dcs.column[0] == gen[KzgCell](0)
      dcs.column[1] == gen[KzgCell](1)

  test "assembleDataColumnSidecar preserves inclusion proof from header":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      colIdx = ColumnIndex(0)

    let header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                            numCommitments = 1)
    for i in 0 ..< KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH:
      header[].kzg_commitments_inclusion_proof[i] = genDigest(100 + int(i))

    quarantine.putPartialHeader(root, header)
    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 1)
    check entry == quarantine.getEntry(root, colIdx).get()
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 1))

    let assembled = quarantine.assembleDataColumnSidecar(root, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    for i in 0 ..< KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH:
      check dcs.kzg_commitments_inclusion_proof[i] == genDigest(100 + int(i))

  # --- End-to-end: multiple columns for same block ---

  test "Assemble multiple columns for the same block independently":
    var quarantine = FuluPartialColumnQuarantine.init()
    let
      root = genDigest(1)
      numBlobs = 2
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)

    let entry0 = quarantine.getOrCreateEntry(root, ColumnIndex(0), numBlobs)
    check entry0 == quarantine.getEntry(root, ColumnIndex(0)).get()
    let entry1 = quarantine.getOrCreateEntry(root, ColumnIndex(1), numBlobs)
    check entry1 == quarantine.getEntry(root, ColumnIndex(1)).get()

    quarantine.addCells(root, ColumnIndex(0),
      genPartialDataColumnSidecar([0, 1], startCellId = 10))
    quarantine.addCells(root, ColumnIndex(1),
      genPartialDataColumnSidecar([0], startCellId = 20))

    check:
      quarantine.isComplete(root, ColumnIndex(0))
      not quarantine.isComplete(root, ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(root, ColumnIndex(0)).isSome()
      quarantine.assembleDataColumnSidecar(root, ColumnIndex(1)).isNone()

    quarantine.addCells(root, ColumnIndex(1),
      genPartialDataColumnSidecar([1], startCellId = 21))

    check:
      quarantine.isComplete(root, ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(root, ColumnIndex(1)).isSome()

    let
      dcs0 = quarantine.assembleDataColumnSidecar(root, ColumnIndex(0)).get()
      dcs1 = quarantine.assembleDataColumnSidecar(root, ColumnIndex(1)).get()
    check:
      dcs0.index == ColumnIndex(0)
      dcs1.index == ColumnIndex(1)
      dcs0.column[0] == gen[KzgCell](10)
      dcs0.column[1] == gen[KzgCell](11)
      dcs1.column[0] == gen[KzgCell](20)
      dcs1.column[1] == gen[KzgCell](21)

# Gloas suite — exercises the spec differences:
# - Keyed by `PartialDataColumnGroupID` (slot + beacon_block_root), not
#   by block root, per
#   https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/partial-columns/p2p-interface.md
# - The wire sidecar carries no `header` field; metadata flows through
#   the GroupID instead.
# - The assembled `gloas.DataColumnSidecar` carries `slot` +
#   `beacon_block_root` rather than `signed_block_header` /
#   `kzg_commitments` / `kzg_commitments_inclusion_proof`.
suite "Partial Column Quarantine (Gloas)":
  func gid(slot: int, rootSeed: int): gloas.PartialDataColumnGroupID =
    gloas.PartialDataColumnGroupID(
      slot: Slot(slot), beacon_block_root: genDigest(rootSeed))

  test "Init creates empty quarantine":
    var quarantine = GloasPartialColumnQuarantine.init()
    let id = gid(1, 1)
    check:
      not quarantine.hasPartialHeader(id)
      quarantine.getPartialHeader(id).isNone()
      not quarantine.hasEntry(id, ColumnIndex(0))

  test "putPartialGroupID stores group id under itself":
    var quarantine = GloasPartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 11, beaconBlockRootSeed = 7)
    quarantine.putPartialGroupID(groupId)
    check:
      quarantine.hasPartialHeader(groupId[])
      quarantine.getPartialHeader(groupId[]).isSome()
      quarantine.getPartialHeader(groupId[]).get().slot == Slot(11)
      quarantine.getPartialHeader(groupId[]).get().beacon_block_root ==
        genDigest(7)

  test "Group IDs with same root but different slots are distinct keys":
    var quarantine = GloasPartialColumnQuarantine.init()
    let
      a = genPartialDataColumnGroupID(slot = 10, beaconBlockRootSeed = 1)
      b = genPartialDataColumnGroupID(slot = 11, beaconBlockRootSeed = 1)
    quarantine.putPartialGroupID(a)
    check:
      quarantine.hasPartialHeader(a[])
      not quarantine.hasPartialHeader(b[])

  test "Header LRU eviction (gloas, keyed by GroupID)":
    var quarantine = GloasPartialColumnQuarantine.init()
    for i in 0 ..< MaxPartialHeaders + 3:
      quarantine.putPartialGroupID(
        genPartialDataColumnGroupID(slot = i, beaconBlockRootSeed = i))
    check:
      quarantine.hasPartialHeader(gid(MaxPartialHeaders + 2,
                                      MaxPartialHeaders + 2))
      not quarantine.hasPartialHeader(gid(0, 0))

  test "getOrCreateEntry reflects gloas group-id validation":
    var quarantine = GloasPartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 3, beaconBlockRootSeed = 1)

    let entry1 = quarantine.getOrCreateEntry(groupId[], ColumnIndex(0),
                                             numBlobs = 2)
    check entry1.headerValidated == false

    quarantine.putPartialGroupID(groupId)
    let entry2 = quarantine.getOrCreateEntry(groupId[], ColumnIndex(1),
                                             numBlobs = 2)
    check entry2.headerValidated == true

  test "addCells ingests cells from a gloas PartialDataColumnSidecar":
    var quarantine = GloasPartialColumnQuarantine.init()
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
    var quarantine = GloasPartialColumnQuarantine.init()
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
    # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/p2p-interface.md#modified-datacolumnsidecar
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
    var quarantine = GloasPartialColumnQuarantine.init()
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
    var quarantine = GloasPartialColumnQuarantine.init()
    let groupId = genPartialDataColumnGroupID(slot = 1, beaconBlockRootSeed = 1)

    quarantine.putPartialGroupID(groupId)
    quarantine.putEntry(groupId[], ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeHeader(groupId[])
    check:
      not quarantine.hasPartialHeader(groupId[])
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

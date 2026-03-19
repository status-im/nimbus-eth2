# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  stew/endians2,
  unittest2,
  kzg4844/kzg_abi,
  ssz_serialization/[types as sszTypes, bitseqs],
  ../beacon_chain/spec/datatypes/[fulu, deneb],
  ../beacon_chain/spec/presets,
  ../beacon_chain/consensus_object_pools/partial_column_quarantine

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

func genKzgCell(index: int): KzgCell =
  var res: KzgCell
  let tmp = uint64(index).toBytesLE()
  copyMem(addr res.bytes[0], unsafeAddr tmp[0], sizeof(uint64))
  res

func genKzgProof(index: int): KzgProof =
  var res: KzgProof
  let tmp = uint64(index).toBytesLE()
  copyMem(addr res.bytes[0], unsafeAddr tmp[0], sizeof(uint64))
  res

func genPartialDataColumnHeader(
    slot: int, proposerIndex: int, numCommitments: int
): PartialDataColumnHeader =
  var commitments: KzgCommitments
  for i in 0 ..< numCommitments:
    discard commitments.add(genKzgCommitment(i))
  PartialDataColumnHeader(
    kzg_commitments: commitments,
    signed_block_header: SignedBeaconBlockHeader(
      message: BeaconBlockHeader(
        slot: Slot(slot),
        proposer_index: uint64(proposerIndex))))

func genPartialDataColumnSidecar(
    blobIndices: openArray[int], startCellId: int = 0
): fulu.PartialDataColumnSidecar =
  ## Build a PartialDataColumnSidecar with cells at the given blob indices.
  ## Cell/proof payloads are deterministic based on startCellId + position.
  var
    bitmap: BitArray[int(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
    cells = newSeqOfCap[KzgCell](blobIndices.len)
    proofs = newSeqOfCap[KzgProof](blobIndices.len)
  for i, blobIdx in blobIndices:
    bitmap[Natural(blobIdx)] = true
    cells.add(genKzgCell(startCellId + i))
    proofs.add(genKzgProof(startCellId + i))
  fulu.PartialDataColumnSidecar(
    cells_present_bitmap: bitmap,
    partial_columns: DataColumn.init(cells),
    kzg_proofs: deneb.KzgProofs.init(proofs))

suite "Partial Column Quarantine":
  test "Init creates empty quarantine":
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)
    check:
      not quarantine.hasPartialHeader(root)
      quarantine.getPartialHeader(root).isNone()
      not quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.getEntry(root, ColumnIndex(0)).isNone()

  # --- Header management ---

  test "Put and get partial header":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root1 = genBlockRoot(1)
      root2 = genBlockRoot(2)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 1)
    quarantine.putPartialHeader(root1, header)
    check:
      quarantine.hasPartialHeader(root1)
      not quarantine.hasPartialHeader(root2)
      quarantine.getPartialHeader(root2).isNone()

  test "Overwrite header with same root":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      header1 = genPartialDataColumnHeader(slot = 10, proposerIndex = 1,
                                           numCommitments = 2)
      header2 = genPartialDataColumnHeader(slot = 10, proposerIndex = 1,
                                           numCommitments = 5)
    quarantine.putPartialHeader(root, header1)
    check quarantine.getPartialHeader(root).get().kzg_commitments.len == 2

    quarantine.putPartialHeader(root, header2)
    check quarantine.getPartialHeader(root).get().kzg_commitments.len == 5

  test "Multiple headers for different roots":
    var quarantine = PartialColumnQuarantine.init()
    let
      root1 = genBlockRoot(1)
      root2 = genBlockRoot(2)
      root3 = genBlockRoot(3)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      header = genPartialDataColumnHeader(slot = 10, proposerIndex = 1,
                                          numCommitments = 2)

    quarantine.putPartialHeader(root, header)
    check quarantine.hasPartialHeader(root)

    quarantine.removeHeader(root)
    check:
      not quarantine.hasPartialHeader(root)
      quarantine.getPartialHeader(root).isNone()

  test "Remove non-existent header is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(99)
    quarantine.removeHeader(root) # should not crash

  # --- Entry (cell tracking) management ---

  test "Put and get entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)
    check:
      not quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.getEntry(root, ColumnIndex(0)).isNone()

  test "Different column indices are independent":
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)

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
    var quarantine = PartialColumnQuarantine.init()
    let
      root1 = genBlockRoot(1)
      root2 = genBlockRoot(2)
      colIdx = ColumnIndex(7)

    quarantine.putEntry(root1, colIdx, PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    quarantine.putEntry(root2, colIdx, PartialColumnEntry(
      headerValidated: false, cellsReceived: BitSeq.init(4)))

    check:
      quarantine.getEntry(root1, colIdx).get().headerValidated == true
      quarantine.getEntry(root2, colIdx).get().headerValidated == false

  test "Remove entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(3)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    check quarantine.hasEntry(root, colIdx)

    quarantine.removeEntry(root, colIdx)
    check:
      not quarantine.hasEntry(root, colIdx)
      quarantine.getEntry(root, colIdx).isNone()

  test "Remove entry does not affect other entries":
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)

    quarantine.putEntry(root, ColumnIndex(0), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(2)))
    quarantine.putEntry(root, ColumnIndex(1), PartialColumnEntry(
      headerValidated: true, cellsReceived: BitSeq.init(3)))

    quarantine.removeEntry(root, ColumnIndex(0))
    check:
      not quarantine.hasEntry(root, ColumnIndex(0))
      quarantine.hasEntry(root, ColumnIndex(1))

  test "Remove non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.removeEntry(genBlockRoot(99), ColumnIndex(0))

  # --- getOrCreateEntry ---

  test "getOrCreateEntry creates new entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(2)

    let entry = quarantine.getOrCreateEntry(root, colIdx, numBlobs = 6)
    check:
      entry.cellsReceived.len == 6
      entry.headerValidated == false
      quarantine.hasEntry(root, colIdx)

  test "getOrCreateEntry returns existing entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(99)
    quarantine.markCellReceived(root, ColumnIndex(0), 0)
    check not quarantine.hasCellReceived(root, ColumnIndex(0), 0)

  test "Mark cell received with out-of-bounds blob index is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(3)))

    quarantine.markCellReceived(root, colIdx, 10) # out of bounds
    check not quarantine.hasCellReceived(root, colIdx, 10)

  test "hasCellReceived for non-existent entry returns false":
    var quarantine = PartialColumnQuarantine.init()
    check not quarantine.hasCellReceived(genBlockRoot(1), ColumnIndex(0), 0)

  test "hasCellReceived for out-of-bounds index returns false":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: BitSeq.init(2)))

    check not quarantine.hasCellReceived(root, colIdx, 5)

  test "Mark all cells received":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)

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
      root1 = genBlockRoot(1)
      root2 = genBlockRoot(2)
    check:
      PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(0)) ==
        PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(0))
      PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(0)) !=
        PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(1))
      PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(0)) !=
        PartialColumnKey(blockRoot: root2, columnIndex: ColumnIndex(0))

  test "PartialColumnKey hash differs for different keys":
    let
      root1 = genBlockRoot(1)
      root2 = genBlockRoot(2)
      k1 = PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(0))
      k2 = PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(1))
      k3 = PartialColumnKey(blockRoot: root2, columnIndex: ColumnIndex(0))
    # Same key hashes the same
    check hash(k1) == hash(
      PartialColumnKey(blockRoot: root1, columnIndex: ColumnIndex(0)))
    # Different keys should (overwhelmingly likely) hash differently
    check hash(k1) != hash(k2)
    check hash(k1) != hash(k3)
    check hash(k2) != hash(k3)

  # --- LRU eviction ---

  test "Header LRU evicts oldest entry when full":
    var quarantine = PartialColumnQuarantine.init()

    # Fill beyond MaxPartialHeaders
    for i in 0 ..< MaxPartialHeaders + 5:
      let root = genBlockRoot(i)
      let header = genPartialDataColumnHeader(
        slot = i, proposerIndex = 1, numCommitments = 1)
      quarantine.putPartialHeader(root, header)

    # The most recently added headers should still be present
    let lastRoot = genBlockRoot(MaxPartialHeaders + 4)
    check quarantine.hasPartialHeader(lastRoot)

    # The very first ones should have been evicted
    # (LRU with capacity MaxPartialHeaders means the first entries get pushed out)
    let firstRoot = genBlockRoot(0)
    check not quarantine.hasPartialHeader(firstRoot)

  # --- Header and entry independence ---

  test "Removing header does not remove entries":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3

    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)

    let
      cell = genKzgCell(42)
      proof = genKzgProof(42)
    quarantine.markCellReceived(root, colIdx, 1, cell, proof)

    check quarantine.hasCellReceived(root, colIdx, 1)

    let entry = quarantine.getEntry(root, colIdx).get()
    check:
      entry.cells[1].isSome()
      entry.cells[1].get() == cell
      entry.proofs[1].isSome()
      entry.proofs[1].get() == proof
      # Other slots remain empty
      entry.cells[0].isNone()
      entry.cells[2].isNone()
      entry.proofs[0].isNone()
      entry.proofs[2].isNone()

  test "markCellReceived with data on non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.markCellReceived(
      genBlockRoot(99), ColumnIndex(0), 0, genKzgCell(1), genKzgProof(1))
    check not quarantine.hasCellReceived(genBlockRoot(99), ColumnIndex(0), 0)

  test "markCellReceived with data out-of-bounds is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)
    discard quarantine.getOrCreateEntry(root, ColumnIndex(0), numBlobs = 2)
    quarantine.markCellReceived(
      root, ColumnIndex(0), 10, genKzgCell(1), genKzgProof(1))
    check not quarantine.hasCellReceived(root, ColumnIndex(0), 10)

  # --- getOrCreateEntry initializes cells/proofs seqs ---

  test "getOrCreateEntry new entry has properly sized cells and proofs":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(5)
      numBlobs = 4

    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)

    # Sidecar with cells at blob indices 0 and 2
    let sidecar = genPartialDataColumnSidecar([0, 2], startCellId = 100)
    quarantine.addCells(root, colIdx, sidecar)

    check:
      quarantine.hasCellReceived(root, colIdx, 0)
      not quarantine.hasCellReceived(root, colIdx, 1)
      quarantine.hasCellReceived(root, colIdx, 2)
      not quarantine.hasCellReceived(root, colIdx, 3)

    let entry = quarantine.getEntry(root, colIdx).get()
    check:
      entry.cells[0].isSome()
      entry.cells[0].get() == genKzgCell(100)
      entry.proofs[0].isSome()
      entry.proofs[0].get() == genKzgProof(100)
      entry.cells[2].isSome()
      entry.cells[2].get() == genKzgCell(101)
      entry.proofs[2].isSome()
      entry.proofs[2].get() == genKzgProof(101)
      entry.cells[1].isNone()
      entry.cells[3].isNone()

  test "addCells accumulates across multiple sidecars":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3

    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)

    # First sidecar: blob 0
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 10))
    # Second sidecar: blob 2
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(root, colIdx, 0)
      not quarantine.hasCellReceived(root, colIdx, 1)
      quarantine.hasCellReceived(root, colIdx, 2)

    let entry = quarantine.getEntry(root, colIdx).get()
    check:
      entry.cells[0].get() == genKzgCell(10)
      entry.cells[2].get() == genKzgCell(20)

  test "addCells on non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let sidecar = genPartialDataColumnSidecar([0], startCellId = 1)
    quarantine.addCells(genBlockRoot(99), ColumnIndex(0), sidecar)
    check not quarantine.hasEntry(genBlockRoot(99), ColumnIndex(0))

  test "addCells with overlapping bitmap overwrites existing cells":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)

    # First ingest: blob 1
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([1], startCellId = 50))
    let entry1 = quarantine.getEntry(root, colIdx).get()
    check entry1.cells[1].get() == genKzgCell(50)

    # Second ingest: blob 1 again with different data
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([1], startCellId = 99))
    let entry2 = quarantine.getEntry(root, colIdx).get()
    check entry2.cells[1].get() == genKzgCell(99)

  test "addCells is independent across columns":
    var quarantine = PartialColumnQuarantine.init()
    let root = genBlockRoot(1)

    discard quarantine.getOrCreateEntry(root, ColumnIndex(0), numBlobs = 3)
    discard quarantine.getOrCreateEntry(root, ColumnIndex(1), numBlobs = 3)

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
    var quarantine = PartialColumnQuarantine.init()
    check not quarantine.isComplete(genBlockRoot(99), ColumnIndex(0))

  test "isComplete returns false when header not validated":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    # Create entry without header (headerValidated = false)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 2)
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1], startCellId = 1))

    check not quarantine.isComplete(root, colIdx)

  test "isComplete returns false when cells are missing":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 3)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)
    # Only add 2 of 3 cells
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 2], startCellId = 1))

    check not quarantine.isComplete(root, colIdx)

  test "isComplete returns true when header validated and all cells received":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1, 2], startCellId = 1))

    check quarantine.isComplete(root, colIdx)

  test "isComplete with single blob":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 1)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 1)
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 1))

    check quarantine.isComplete(root, colIdx)

  test "isComplete becomes true after incremental addCells":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)

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
    var quarantine = PartialColumnQuarantine.init()
    check quarantine.assembleDataColumnSidecar(
      genBlockRoot(99), ColumnIndex(0)).isNone()

  test "assembleDataColumnSidecar returns none when header not validated":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 2)
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 1], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

  test "assembleDataColumnSidecar returns none when cells incomplete":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = 3)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 3)
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0, 2], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

  test "assembleDataColumnSidecar returns none when header missing from cache":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    # Manually create entry with headerValidated = true but no header in cache
    var allReceived = BitSeq.init(1)
    allReceived.setBit(0)
    quarantine.putEntry(root, colIdx, PartialColumnEntry(
      headerValidated: true,
      cellsReceived: allReceived,
      cells: @[Opt.some(genKzgCell(1))],
      proofs: @[Opt.some(genKzgProof(1))]))

    check quarantine.assembleDataColumnSidecar(root, colIdx).isNone()

  test "assembleDataColumnSidecar produces correct DataColumnSidecar":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(7)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 10, proposerIndex = 5,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)
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

    # Verify cells are in blob-index order
    check:
      dcs.column[0] == genKzgCell(50)
      dcs.column[1] == genKzgCell(51)
      dcs.column[2] == genKzgCell(52)

    # Verify proofs are in blob-index order
    check:
      dcs.kzg_proofs[0] == genKzgProof(50)
      dcs.kzg_proofs[1] == genKzgProof(51)
      dcs.kzg_proofs[2] == genKzgProof(52)

    # Verify commitments come from the header
    for i in 0 ..< numBlobs:
      check dcs.kzg_commitments[i] == genKzgCommitment(i)

  test "assembleDataColumnSidecar with cells added incrementally":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(3)
      numBlobs = 3
      header = genPartialDataColumnHeader(slot = 5, proposerIndex = 2,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)

    # Add cells one by one in non-sequential order
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
      dcs.column[0] == genKzgCell(10)
      dcs.column[1] == genKzgCell(20)
      dcs.column[2] == genKzgCell(30)
      dcs.kzg_proofs[0] == genKzgProof(10)
      dcs.kzg_proofs[1] == genKzgProof(20)
      dcs.kzg_proofs[2] == genKzgProof(30)

  test "assembleDataColumnSidecar with markCellReceived (data overload)":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)
      numBlobs = 2
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs)

    quarantine.markCellReceived(root, colIdx, 0, genKzgCell(0), genKzgProof(0))
    quarantine.markCellReceived(root, colIdx, 1, genKzgCell(1), genKzgProof(1))

    let assembled = quarantine.assembleDataColumnSidecar(root, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.column.len == numBlobs
      dcs.column[0] == genKzgCell(0)
      dcs.column[1] == genKzgCell(1)

  test "assembleDataColumnSidecar preserves inclusion proof from header":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      colIdx = ColumnIndex(0)

    # Create header with a custom inclusion proof
    var header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                            numCommitments = 1)
    for i in 0 ..< KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH:
      header.kzg_commitments_inclusion_proof[i] = genBlockRoot(100 + int(i))

    quarantine.putPartialHeader(root, header)
    discard quarantine.getOrCreateEntry(root, colIdx, numBlobs = 1)
    quarantine.addCells(root, colIdx,
      genPartialDataColumnSidecar([0], startCellId = 1))

    let assembled = quarantine.assembleDataColumnSidecar(root, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    for i in 0 ..< KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH:
      check dcs.kzg_commitments_inclusion_proof[i] == genBlockRoot(100 + int(i))

  # --- End-to-end: multiple columns for same block ---

  test "Assemble multiple columns for the same block independently":
    var quarantine = PartialColumnQuarantine.init()
    let
      root = genBlockRoot(1)
      numBlobs = 2
      header = genPartialDataColumnHeader(slot = 1, proposerIndex = 1,
                                          numCommitments = numBlobs)

    quarantine.putPartialHeader(root, header)

    # Set up two columns
    discard quarantine.getOrCreateEntry(root, ColumnIndex(0), numBlobs)
    discard quarantine.getOrCreateEntry(root, ColumnIndex(1), numBlobs)

    # Complete column 0
    quarantine.addCells(root, ColumnIndex(0),
      genPartialDataColumnSidecar([0, 1], startCellId = 10))
    # Partially fill column 1
    quarantine.addCells(root, ColumnIndex(1),
      genPartialDataColumnSidecar([0], startCellId = 20))

    check:
      quarantine.isComplete(root, ColumnIndex(0))
      not quarantine.isComplete(root, ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(root, ColumnIndex(0)).isSome()
      quarantine.assembleDataColumnSidecar(root, ColumnIndex(1)).isNone()

    # Now complete column 1
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
      dcs0.column[0] == genKzgCell(10)
      dcs0.column[1] == genKzgCell(11)
      dcs1.column[0] == genKzgCell(20)
      dcs1.column[1] == genKzgCell(21)

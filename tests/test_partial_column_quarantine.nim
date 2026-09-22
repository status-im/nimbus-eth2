# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md

import
  stew/endians2,
  unittest2,
  kzg4844/kzg_abi,
  ssz_serialization/[types as sszTypes, bitseqs],
  ../beacon_chain/spec/datatypes/gloas,
  ../beacon_chain/spec/presets,
  ../beacon_chain/consensus_object_pools/partial_column_quarantine

from ../beacon_chain/spec/datatypes/fulu import ColumnIndex

func genDigest(index: int): Eth2Digest =
  let tmp = uint64(index).toBytesLE()
  var digest: Eth2Digest
  copyMem(addr digest.data[0], addr tmp[0], sizeof(uint64))
  digest

func gen[T](index: int): T =
  let tmp = uint64(index).toBytesLE()
  var value: T
  copyMem(addr value.bytes[0], addr tmp[0], sizeof(uint64))
  value

func gid(slot: int, rootSeed: int): gloas.PartialDataColumnGroupID =
  gloas.PartialDataColumnGroupID(
    slot: Slot(slot), beacon_block_root: genDigest(rootSeed))

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md#modified-partialdatacolumnsidecar
func genSidecar(
    blobIndices: openArray[int], startCellId: int = 0
): ref gloas.PartialDataColumnSidecar =
  ## Cells at the given blob indices, with payloads deterministic in
  ## startCellId.
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
  test "Init creates empty quarantine":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)
    check:
      not quarantine.hasGroupId(id)
      not quarantine.hasEntry(id, ColumnIndex(0))
      quarantine.getEntry(id, ColumnIndex(0)).isNone()

  # --- Group ID management ---

  test "Put and check group id":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(11, 7)
    quarantine.putGroupId(id)
    check quarantine.hasGroupId(id)

  test "Unknown group id is not present":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.putGroupId(gid(1, 1))
    check:
      quarantine.hasGroupId(gid(1, 1))
      not quarantine.hasGroupId(gid(1, 2))

  test "Group IDs with same root but different slots are distinct keys":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.putGroupId(gid(10, 1))
    check:
      quarantine.hasGroupId(gid(10, 1))
      not quarantine.hasGroupId(gid(11, 1))

  test "Multiple group ids coexist":
    var quarantine = PartialColumnQuarantine.init()
    for i in 1 .. 3:
      quarantine.putGroupId(gid(i, i))
    check:
      quarantine.hasGroupId(gid(1, 1))
      quarantine.hasGroupId(gid(2, 2))
      quarantine.hasGroupId(gid(3, 3))

  test "Remove group id":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(10, 1)
    quarantine.putGroupId(id)
    check quarantine.hasGroupId(id)

    quarantine.removeGroupId(id)
    check not quarantine.hasGroupId(id)

  test "Remove non-existent group id is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.removeGroupId(gid(99, 99))

  test "Group ID LRU evicts oldest entry when full":
    var quarantine = PartialColumnQuarantine.init()
    for i in 0 ..< MaxPartialGroupIds + 5:
      quarantine.putGroupId(gid(i, i))
    check:
      quarantine.hasGroupId(gid(MaxPartialGroupIds + 4, MaxPartialGroupIds + 4))
      not quarantine.hasGroupId(gid(0, 0))

  # --- Entry (cell tracking) management ---

  test "Put and get entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(5)

    quarantine.putEntry(id, colIdx, PartialColumnEntryRef.init(4))
    check:
      quarantine.hasEntry(id, colIdx)
      quarantine.getEntry(id, colIdx).isSome()
      quarantine.getEntry(id, colIdx).get().cellsReceived.len == 4

  test "Entry LRU evicts oldest entry when full":
    var quarantine = PartialColumnQuarantine.init()
    for i in 0 ..< MaxPartialEntries + 5:
      quarantine.putEntry(
        gid(i, i), ColumnIndex(0), PartialColumnEntryRef.init(1))
    check:
      quarantine.hasEntry(
        gid(MaxPartialEntries + 4, MaxPartialEntries + 4), ColumnIndex(0))
      not quarantine.hasEntry(gid(0, 0), ColumnIndex(0))

  test "Get entry for unknown key returns none":
    var quarantine = PartialColumnQuarantine.init()
    check:
      not quarantine.hasEntry(gid(1, 1), ColumnIndex(0))
      quarantine.getEntry(gid(1, 1), ColumnIndex(0)).isNone()

  test "Different column indices are independent":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    quarantine.putEntry(id, ColumnIndex(0), PartialColumnEntryRef.init(3))
    quarantine.putEntry(id, ColumnIndex(1), PartialColumnEntryRef.init(5))

    check:
      quarantine.hasEntry(id, ColumnIndex(0))
      quarantine.hasEntry(id, ColumnIndex(1))
      not quarantine.hasEntry(id, ColumnIndex(2))
      quarantine.getEntry(id, ColumnIndex(0)).get().cellsReceived.len == 3
      quarantine.getEntry(id, ColumnIndex(1)).get().cellsReceived.len == 5

  test "Different group ids with same column index are independent":
    var quarantine = PartialColumnQuarantine.init()
    let colIdx = ColumnIndex(7)

    quarantine.putEntry(gid(1, 1), colIdx, PartialColumnEntryRef.init(2))
    quarantine.putEntry(gid(2, 2), colIdx, PartialColumnEntryRef.init(4))

    check:
      quarantine.getEntry(gid(1, 1), colIdx).get().cellsReceived.len == 2
      quarantine.getEntry(gid(2, 2), colIdx).get().cellsReceived.len == 4

  test "Remove entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(3)

    quarantine.putEntry(id, colIdx, PartialColumnEntryRef.init(2))
    check quarantine.hasEntry(id, colIdx)

    quarantine.removeEntry(id, colIdx)
    check:
      not quarantine.hasEntry(id, colIdx)
      quarantine.getEntry(id, colIdx).isNone()

  test "Remove entry does not affect other entries":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    quarantine.putEntry(id, ColumnIndex(0), PartialColumnEntryRef.init(2))
    quarantine.putEntry(id, ColumnIndex(1), PartialColumnEntryRef.init(3))

    quarantine.removeEntry(id, ColumnIndex(0))
    check:
      not quarantine.hasEntry(id, ColumnIndex(0))
      quarantine.hasEntry(id, ColumnIndex(1))

  test "Remove non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.removeEntry(gid(99, 99), ColumnIndex(0))

  # --- getOrCreateEntry ---

  test "getOrCreateEntry creates new entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(2)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 6)
    check:
      entry.cellsReceived.len == 6
      quarantine.hasEntry(id, colIdx)

  test "getOrCreateEntry returns existing entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(2)

    let existing = PartialColumnEntryRef.init(3)
    existing.cellsReceived.setBit(0)
    existing.cellsReceived.setBit(2)
    quarantine.putEntry(id, colIdx, existing)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 10)
    check:
      # The entry that was already there, handed back as the same object
      # rather than a copy - and not a fresh one sized for 10 blobs
      entry == existing
      entry.cellsReceived.len == 3
      entry.cellsReceived[0] == true
      entry.cellsReceived[1] == false
      entry.cellsReceived[2] == true

  test "Group id arriving after the cells still completes the entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(3, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 2)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 1], startCellId = 1))

    # Every cell is in, but the group id has not been validated yet.
    check:
      not quarantine.isComplete(id, colIdx)
      quarantine.assembleDataColumnSidecar(id, colIdx).isNone()

    quarantine.putGroupId(id)

    check:
      quarantine.isComplete(id, colIdx)
      quarantine.assembleDataColumnSidecar(id, colIdx).isSome()

  test "getOrCreateEntry new entry has properly sized cells and proofs":
    var quarantine = PartialColumnQuarantine.init()
    let numBlobs = 4

    let entry = quarantine.getOrCreateEntry(gid(1, 1), ColumnIndex(0), numBlobs)
    check:
      entry.cells.len == numBlobs
      entry.proofs.len == numBlobs
      entry.cellsReceived.len == numBlobs
    for i in 0 ..< numBlobs:
      check:
        entry.cellsReceived[i] == false
        entry.cellsReceived[i] == false

  # --- Reference semantics ---

  test "getEntry hands back the cached entry":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 2)
    check entry == quarantine.getEntry(id, colIdx).get()

    entry.cellsReceived.setBit(1)
    entry.cells[1] = gen[KzgCell](7)
    entry.proofs[1] = gen[KzgProof](7)

    let fetched = quarantine.getEntry(id, colIdx).get()
    check:
      fetched == entry
      quarantine.hasCellReceived(id, colIdx, 1)
      fetched.cells[1] == gen[KzgCell](7)
      fetched.proofs[1] == gen[KzgProof](7)

  test "putEntry stores the caller's entry without copying it":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)
      entry = PartialColumnEntryRef.init(2)

    quarantine.putEntry(id, colIdx, entry)

    # Mutated after the put - the quarantine holds this very object.
    entry.cellsReceived.setBit(0)
    entry.cells[0] = gen[KzgCell](3)

    check:
      quarantine.getEntry(id, colIdx).get() == entry
      quarantine.hasCellReceived(id, colIdx, 0)
      quarantine.getEntry(id, colIdx).get().cells[0] == gen[KzgCell](3)

  test "getOrCreateEntry hands back the same object on every call":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)
      first = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
      second = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check first == second

  test "Entries under different keys are distinct objects":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      col0 = quarantine.getOrCreateEntry(id, ColumnIndex(0), numBlobs = 2)
      col1 = quarantine.getOrCreateEntry(id, ColumnIndex(1), numBlobs = 2)
      other = quarantine.getOrCreateEntry(
        gid(2, 2), ColumnIndex(0), numBlobs = 2)
    check:
      col0 != col1
      col0 != other

  test "Removing an entry leaves a ref the caller already holds usable":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)
      entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 2)

    quarantine.removeEntry(id, colIdx)
    entry.cellsReceived.setBit(0)

    check:
      not quarantine.hasEntry(id, colIdx)
      not quarantine.hasCellReceived(id, colIdx, 0)
      entry.cellsReceived[0] == true

  # --- receivedCells ---

  test "receivedCells borrows the entry bitmap":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 2], startCellId = 5))

    check:
      # The entry's own bitmap, not a copy of it
      quarantine.receivedCells(id, colIdx) == entry.cellsReceived
      quarantine.receivedCells(id, colIdx).len == 3
      quarantine.receivedCells(id, colIdx)[0] == true
      quarantine.receivedCells(id, colIdx)[1] == false
      quarantine.receivedCells(id, colIdx)[2] == true

    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 6))
    check quarantine.receivedCells(id, colIdx)[1] == true

  test "receivedCells is empty for an unknown entry":
    var quarantine = PartialColumnQuarantine.init()
    check quarantine.receivedCells(gid(99, 99), ColumnIndex(0)).len == 0

  # --- Cell tracking ---

  test "Mark and check cell received":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(id, colIdx, PartialColumnEntryRef.init(4))

    quarantine.markCellReceived(id, colIdx, 1)
    quarantine.markCellReceived(id, colIdx, 3)

    check:
      not quarantine.hasCellReceived(id, colIdx, 0)
      quarantine.hasCellReceived(id, colIdx, 1)
      not quarantine.hasCellReceived(id, colIdx, 2)
      quarantine.hasCellReceived(id, colIdx, 3)

  test "Mark cell received for non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.markCellReceived(gid(99, 99), ColumnIndex(0), 0)
    check not quarantine.hasCellReceived(gid(99, 99), ColumnIndex(0), 0)

  test "Mark cell received with out-of-bounds blob index is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(id, colIdx, PartialColumnEntryRef.init(3))

    quarantine.markCellReceived(id, colIdx, 10)
    check not quarantine.hasCellReceived(id, colIdx, 10)

  test "hasCellReceived for non-existent entry returns false":
    var quarantine = PartialColumnQuarantine.init()
    check not quarantine.hasCellReceived(gid(1, 1), ColumnIndex(0), 0)

  test "hasCellReceived for out-of-bounds index returns false":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putEntry(id, colIdx, PartialColumnEntryRef.init(2))

    check not quarantine.hasCellReceived(id, colIdx, 5)

  test "Mark all cells received":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)
      numBlobs = 6

    quarantine.putEntry(id, colIdx, PartialColumnEntryRef.init(numBlobs))

    for i in 0 ..< numBlobs:
      quarantine.markCellReceived(id, colIdx, i)
    for i in 0 ..< numBlobs:
      check quarantine.hasCellReceived(id, colIdx, i)

  test "Cell tracking is per-column":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    quarantine.putEntry(id, ColumnIndex(0), PartialColumnEntryRef.init(3))
    quarantine.putEntry(id, ColumnIndex(1), PartialColumnEntryRef.init(3))

    quarantine.markCellReceived(id, ColumnIndex(0), 1)

    check:
      quarantine.hasCellReceived(id, ColumnIndex(0), 1)
      not quarantine.hasCellReceived(id, ColumnIndex(1), 1)

  test "markCellReceived with data stores cell and proof":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)

    let
      cell = gen[KzgCell](42)
      proof = gen[KzgProof](42)
    quarantine.markCellReceived(id, colIdx, 1, cell, proof)

    check quarantine.hasCellReceived(id, colIdx, 1)

    let updated = quarantine.getEntry(id, colIdx).get()
    check:
      # Written in place, so the ref taken before the update sees it too
      updated == entry
      entry.cells[1] == cell
      entry.proofs[1] == proof
      updated.cells[1] == cell
      updated.proofs[1] == proof
      not quarantine.hasCellReceived(id, colIdx, 0)
      not quarantine.hasCellReceived(id, colIdx, 2)

  test "markCellReceived with data on non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.markCellReceived(
      gid(99, 99), ColumnIndex(0), 0, gen[KzgCell](1), gen[KzgProof](1))
    check not quarantine.hasCellReceived(gid(99, 99), ColumnIndex(0), 0)

  test "markCellReceived with data out-of-bounds is no-op":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)
    let entry = quarantine.getOrCreateEntry(id, ColumnIndex(0), numBlobs = 2)
    check entry == quarantine.getEntry(id, ColumnIndex(0)).get()
    quarantine.markCellReceived(
      id, ColumnIndex(0), 10, gen[KzgCell](1), gen[KzgProof](1))
    check not quarantine.hasCellReceived(id, ColumnIndex(0), 10)

  # --- Keys and hashing ---

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

  test "PartialColumnKey equality":
    check:
      PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(0)) ==
        PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(0))
      PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(0)) !=
        PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(1))
      PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(0)) !=
        PartialColumnKey(groupId: gid(1, 2), columnIndex: ColumnIndex(0))

  test "PartialColumnKey hash differs for different keys":
    let
      k1 = PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(0))
      k2 = PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(1))
      k3 = PartialColumnKey(groupId: gid(1, 2), columnIndex: ColumnIndex(0))
    check:
      hash(k1) == hash(
        PartialColumnKey(groupId: gid(1, 1), columnIndex: ColumnIndex(0)))
      hash(k1) != hash(k2)
      hash(k1) != hash(k3)
      hash(k2) != hash(k3)

  # --- Group id and entry independence ---

  test "Removing group id does not remove entries":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    quarantine.putGroupId(id)
    quarantine.putEntry(id, ColumnIndex(0), PartialColumnEntryRef.init(3))

    quarantine.removeGroupId(id)
    check:
      not quarantine.hasGroupId(id)
      quarantine.hasEntry(id, ColumnIndex(0))

  test "Removing entry does not remove group id":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    quarantine.putGroupId(id)
    quarantine.putEntry(id, ColumnIndex(0), PartialColumnEntryRef.init(3))

    quarantine.removeEntry(id, ColumnIndex(0))
    check:
      quarantine.hasGroupId(id)
      not quarantine.hasEntry(id, ColumnIndex(0))

  # --- addCells ---

  test "addCells ingests cells from a PartialDataColumnSidecar":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(2, 1)
      colIdx = ColumnIndex(5)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 4)

    quarantine.addCells(id, colIdx, genSidecar([0, 2], startCellId = 100))

    check:
      quarantine.hasCellReceived(id, colIdx, 0)
      not quarantine.hasCellReceived(id, colIdx, 1)
      quarantine.hasCellReceived(id, colIdx, 2)
      not quarantine.hasCellReceived(id, colIdx, 3)

    let updated = quarantine.getEntry(id, colIdx).get()
    check:
      updated == entry
      entry.cells[0] == gen[KzgCell](100)
      entry.proofs[0] == gen[KzgProof](100)
      updated.cells[0] == gen[KzgCell](100)
      updated.proofs[0] == gen[KzgProof](100)
      updated.cells[2] == gen[KzgCell](101)
      updated.proofs[2] == gen[KzgProof](101)
      not quarantine.hasCellReceived(id, colIdx, 1)
      not quarantine.hasCellReceived(id, colIdx, 3)

  test "addCells accumulates across multiple sidecars":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()

    quarantine.addCells(id, colIdx, genSidecar([0], startCellId = 10))
    quarantine.addCells(id, colIdx, genSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(id, colIdx, 0)
      not quarantine.hasCellReceived(id, colIdx, 1)
      quarantine.hasCellReceived(id, colIdx, 2)

    let updated = quarantine.getEntry(id, colIdx).get()
    check:
      updated.cells[0] == gen[KzgCell](10)
      updated.cells[2] == gen[KzgCell](20)

  test "addCells on non-existent entry is no-op":
    var quarantine = PartialColumnQuarantine.init()
    quarantine.addCells(
      gid(99, 99), ColumnIndex(0), genSidecar([0], startCellId = 1))
    check not quarantine.hasEntry(gid(99, 99), ColumnIndex(0))

  test "addCells with overlapping bitmap overwrites existing cells":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()

    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 50))
    check quarantine.getEntry(id, colIdx).get().cells[1] ==
      gen[KzgCell](50)

    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 99))
    check quarantine.getEntry(id, colIdx).get().cells[1] ==
      gen[KzgCell](99)

  test "addCells is independent across columns":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    let entry0 = quarantine.getOrCreateEntry(id, ColumnIndex(0), numBlobs = 3)
    check entry0 == quarantine.getEntry(id, ColumnIndex(0)).get()
    let entry1 = quarantine.getOrCreateEntry(id, ColumnIndex(1), numBlobs = 3)
    check entry1 == quarantine.getEntry(id, ColumnIndex(1)).get()

    quarantine.addCells(id, ColumnIndex(0), genSidecar([0], startCellId = 10))
    quarantine.addCells(id, ColumnIndex(1), genSidecar([2], startCellId = 20))

    check:
      quarantine.hasCellReceived(id, ColumnIndex(0), 0)
      not quarantine.hasCellReceived(id, ColumnIndex(0), 2)
      not quarantine.hasCellReceived(id, ColumnIndex(1), 0)
      quarantine.hasCellReceived(id, ColumnIndex(1), 2)

  # --- cellsConsistent ---

  test "cellsConsistent is true when no entry exists":
    var quarantine = PartialColumnQuarantine.init()
    check quarantine.cellsConsistent(
      gid(99, 99), ColumnIndex(0), genSidecar([0], startCellId = 1))

  test "cellsConsistent is true when cells do not overlap":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0], startCellId = 10))

    check quarantine.cellsConsistent(
      id, colIdx, genSidecar([2], startCellId = 20))

  test "cellsConsistent is true when overlapping cells match":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 10))

    check quarantine.cellsConsistent(
      id, colIdx, genSidecar([1], startCellId = 10))

  test "cellsConsistent is false when an overlapping cell differs":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 10))

    check not quarantine.cellsConsistent(
      id, colIdx, genSidecar([1], startCellId = 99))

  test "cellsConsistent is false when an overlapping proof differs":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 10))

    # Same cell payload, different proof.
    let conflicting = genSidecar([1], startCellId = 10)
    conflicting[].kzg_proofs = @[gen[KzgProof](77)]

    check not quarantine.cellsConsistent(id, colIdx, conflicting)

  # --- isComplete ---

  test "isComplete returns false for non-existent entry":
    var quarantine = PartialColumnQuarantine.init()
    check not quarantine.isComplete(gid(99, 99), ColumnIndex(0))

  test "isComplete returns false when group id not validated":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 2)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 1], startCellId = 1))

    check not quarantine.isComplete(id, colIdx)

  test "isComplete returns false when cells are missing":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 2], startCellId = 1))

    check not quarantine.isComplete(id, colIdx)

  test "isComplete returns true when group id validated and all cells received":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 1, 2], startCellId = 1))

    check quarantine.isComplete(id, colIdx)

  test "isComplete with single blob":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 1)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0], startCellId = 1))

    check quarantine.isComplete(id, colIdx)

  test "isComplete becomes true after incremental addCells":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()

    quarantine.addCells(id, colIdx, genSidecar([0], startCellId = 1))
    check not quarantine.isComplete(id, colIdx)

    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 2))
    check not quarantine.isComplete(id, colIdx)

    quarantine.addCells(id, colIdx, genSidecar([2], startCellId = 3))
    check quarantine.isComplete(id, colIdx)

  # --- assembleDataColumnSidecar ---

  test "assembleDataColumnSidecar returns none for non-existent entry":
    var quarantine = PartialColumnQuarantine.init()
    check quarantine.assembleDataColumnSidecar(
      gid(99, 99), ColumnIndex(0)).isNone()

  test "assembleDataColumnSidecar returns none when group id not validated":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 2)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 1], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(id, colIdx).isNone()

  test "assembleDataColumnSidecar returns none when cells incomplete":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 2], startCellId = 1))

    check quarantine.assembleDataColumnSidecar(id, colIdx).isNone()

  test "assembleDataColumnSidecar returns none when group id missing from cache":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    let entry = PartialColumnEntryRef.init(1)
    entry.cellsReceived.setBit(0)
    entry.cells[0] = gen[KzgCell](1)
    entry.proofs[0] = gen[KzgProof](1)
    quarantine.putEntry(id, colIdx, entry)

    check quarantine.assembleDataColumnSidecar(id, colIdx).isNone()

  # gloas.DataColumnSidecar carries slot + beacon_block_root instead of
  # signed_block_header / kzg_commitments / inclusion proof:
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/p2p-interface.md#modified-datacolumnsidecar
  test "assembleDataColumnSidecar produces correct DataColumnSidecar":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(99, 7)
      colIdx = ColumnIndex(4)
      numBlobs = 3

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs)
    check entry == quarantine.getEntry(id, colIdx).get()
    quarantine.addCells(id, colIdx, genSidecar([0, 1, 2], startCellId = 50))

    let assembled = quarantine.assembleDataColumnSidecar(id, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.index == colIdx
      dcs.column.len == numBlobs
      dcs.kzg_proofs.len == numBlobs
      dcs.slot == Slot(99)
      dcs.beacon_block_root == genDigest(7)
      dcs.column[0] == gen[KzgCell](50)
      dcs.column[1] == gen[KzgCell](51)
      dcs.column[2] == gen[KzgCell](52)
      dcs.kzg_proofs[0] == gen[KzgProof](50)
      dcs.kzg_proofs[1] == gen[KzgProof](51)
      dcs.kzg_proofs[2] == gen[KzgProof](52)

  test "assembleDataColumnSidecar hands out its own copy of the cells":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 2)
    quarantine.addCells(id, colIdx, genSidecar([0, 1], startCellId = 10))

    let dcs = quarantine.assembleDataColumnSidecar(id, colIdx).valueOr:
      raiseAssert "entry is complete"

    # The entry stays in quarantine and keeps evolving; the assembled sidecar
    # owns its cells and must not alias them.
    entry.cells[0] = gen[KzgCell](99)

    check:
      dcs.column[0] == gen[KzgCell](10)
      dcs.column[1] == gen[KzgCell](11)
      quarantine.getEntry(id, colIdx).get().cells[0] == gen[KzgCell](99)

  test "assembleDataColumnSidecar with cells added incrementally":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(5, 2)
      colIdx = ColumnIndex(3)

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs = 3)
    check entry == quarantine.getEntry(id, colIdx).get()

    quarantine.addCells(id, colIdx, genSidecar([2], startCellId = 30))
    check quarantine.assembleDataColumnSidecar(id, colIdx).isNone()

    quarantine.addCells(id, colIdx, genSidecar([0], startCellId = 10))
    check quarantine.assembleDataColumnSidecar(id, colIdx).isNone()

    quarantine.addCells(id, colIdx, genSidecar([1], startCellId = 20))

    let assembled = quarantine.assembleDataColumnSidecar(id, colIdx)
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
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      colIdx = ColumnIndex(0)
      numBlobs = 2

    quarantine.putGroupId(id)
    let entry = quarantine.getOrCreateEntry(id, colIdx, numBlobs)
    check entry == quarantine.getEntry(id, colIdx).get()

    quarantine.markCellReceived(id, colIdx, 0, gen[KzgCell](0), gen[KzgProof](0))
    quarantine.markCellReceived(id, colIdx, 1, gen[KzgCell](1), gen[KzgProof](1))

    let assembled = quarantine.assembleDataColumnSidecar(id, colIdx)
    check assembled.isSome()

    let dcs = assembled.get()
    check:
      dcs.column.len == numBlobs
      dcs.column[0] == gen[KzgCell](0)
      dcs.column[1] == gen[KzgCell](1)

  test "Assemble multiple columns for the same block independently":
    var quarantine = PartialColumnQuarantine.init()
    let
      id = gid(1, 1)
      numBlobs = 2

    quarantine.putGroupId(id)

    let entry0 = quarantine.getOrCreateEntry(id, ColumnIndex(0), numBlobs)
    check entry0 == quarantine.getEntry(id, ColumnIndex(0)).get()
    let entry1 = quarantine.getOrCreateEntry(id, ColumnIndex(1), numBlobs)
    check entry1 == quarantine.getEntry(id, ColumnIndex(1)).get()

    quarantine.addCells(id, ColumnIndex(0), genSidecar([0, 1], startCellId = 10))
    quarantine.addCells(id, ColumnIndex(1), genSidecar([0], startCellId = 20))

    check:
      quarantine.isComplete(id, ColumnIndex(0))
      not quarantine.isComplete(id, ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(id, ColumnIndex(0)).isSome()
      quarantine.assembleDataColumnSidecar(id, ColumnIndex(1)).isNone()

    quarantine.addCells(id, ColumnIndex(1), genSidecar([1], startCellId = 21))

    check:
      quarantine.isComplete(id, ColumnIndex(1))
      quarantine.assembleDataColumnSidecar(id, ColumnIndex(1)).isSome()

    let
      dcs0 = quarantine.assembleDataColumnSidecar(id, ColumnIndex(0)).get()
      dcs1 = quarantine.assembleDataColumnSidecar(id, ColumnIndex(1)).get()
    check:
      dcs0.index == ColumnIndex(0)
      dcs1.index == ColumnIndex(1)
      dcs0.column[0] == gen[KzgCell](10)
      dcs0.column[1] == gen[KzgCell](11)
      dcs1.column[0] == gen[KzgCell](20)
      dcs1.column[1] == gen[KzgCell](21)

  # --- pruneForBlock ---

  test "pruneForBlock drops the group id and its entries":
    var quarantine = PartialColumnQuarantine.init()
    let id = gid(1, 1)

    quarantine.putGroupId(id)
    for columnIndex in 0 ..< 3:
      discard quarantine.getOrCreateEntry(
        id, ColumnIndex(columnIndex), numBlobs = 2)

    quarantine.pruneForBlock(id)

    check not quarantine.hasGroupId(id)
    for columnIndex in 0 ..< 3:
      check not quarantine.hasEntry(id, ColumnIndex(columnIndex))

  test "pruneForBlock leaves other group ids alone":
    var quarantine = PartialColumnQuarantine.init()
    let
      a = gid(1, 1)
      b = gid(2, 2)

    quarantine.putGroupId(a)
    quarantine.putGroupId(b)
    discard quarantine.getOrCreateEntry(a, ColumnIndex(0), numBlobs = 2)
    discard quarantine.getOrCreateEntry(b, ColumnIndex(0), numBlobs = 2)

    quarantine.pruneForBlock(a)

    check:
      not quarantine.hasGroupId(a)
      not quarantine.hasEntry(a, ColumnIndex(0))
      quarantine.hasGroupId(b)
      quarantine.hasEntry(b, ColumnIndex(0))

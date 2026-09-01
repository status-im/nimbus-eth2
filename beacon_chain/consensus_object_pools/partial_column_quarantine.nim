# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/hashes,
  minilru, results,
  kzg4844/[kzg, kzg_abi],
  ssz_serialization/bitseqs,
  ../spec/[datatypes/base, digest, presets]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/gloas/partial-columns/p2p-interface.md

from ../spec/datatypes/deneb import KzgProofs
from ../spec/datatypes/fulu import ColumnIndex
from ../spec/datatypes/gloas import
  DataColumnSidecar, PartialDataColumnGroupID, PartialDataColumnSidecar

export results

const
  MaxPartialGroupIds* = 3 * int(SLOTS_PER_EPOCH)
    ## Maximum number of validated group IDs to cache.
  MaxPartialEntries = 3 * int(SLOTS_PER_EPOCH) * NUMBER_OF_COLUMNS
    ## Maximum number of (group_id, column_index) entries to cache.

type
  PartialColumnEntry* = object
    ## Tracks accumulated cells for a single (group_id, column_index) pair.
    cellsReceived*: BitSeq
      ## Per-blob cell presence tracking, indexed by blob index. A slot in
      ## `cells`/`proofs` is only meaningful once its bit here is set.
    cells*: seq[KzgCell]
      ## Accumulated cell data, indexed by blob index.
    proofs*: seq[KzgProof]
      ## Accumulated KZG proofs, indexed by blob index.

  PartialColumnKey* = object
    groupId*: PartialDataColumnGroupID
    columnIndex*: ColumnIndex

  PartialColumnQuarantine* = object
    ## Stores validated group IDs and tracks which cells have been received
    ## for each (group_id, column_index) pair. Validating a group ID on any
    ## subnet makes it available to all of them.
    groupIds*: LruCache[PartialDataColumnGroupID, PartialDataColumnGroupID]
    entries*: LruCache[PartialColumnKey, PartialColumnEntry]

func hash*(gid: PartialDataColumnGroupID): Hash =
  var h: Hash = 0
  h = h !& hash(uint64(gid.slot))
  h = h !& hash(gid.beacon_block_root)
  !$h

func `==`*(a, b: PartialDataColumnGroupID): bool =
  a.slot == b.slot and a.beacon_block_root == b.beacon_block_root

func hash*(key: PartialColumnKey): Hash =
  var h: Hash = 0
  h = h !& hash(key.groupId)
  h = h !& hash(uint64(key.columnIndex))
  !$h

func `==`*(a, b: PartialColumnKey): bool =
  a.groupId == b.groupId and a.columnIndex == b.columnIndex

func init*(T: typedesc[PartialColumnQuarantine]): T =
  T(
    groupIds: LruCache[PartialDataColumnGroupID, PartialDataColumnGroupID].init(
      MaxPartialGroupIds),
    entries: LruCache[PartialColumnKey, PartialColumnEntry].init(
      MaxPartialEntries))

# --- Group ID management ---

func hasGroupId*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID): bool =
  groupId in quarantine.groupIds

func getGroupId*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID): Opt[PartialDataColumnGroupID] =
  quarantine.groupIds.get(groupId)

func putGroupId*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID) =
  ## The group ID is both the key and the stored metadata, since it carries
  ## everything needed to assemble a sidecar.
  quarantine.groupIds.put(groupId, groupId)

# --- Entry (cell tracking) management ---

func hasEntry*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex): bool =
  PartialColumnKey(groupId: groupId, columnIndex: columnIndex) in
    quarantine.entries

func getEntry*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex): Opt[PartialColumnEntry] =
  quarantine.entries.get(
    PartialColumnKey(groupId: groupId, columnIndex: columnIndex))

func putEntry*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    entry: PartialColumnEntry) =
  quarantine.entries.put(
    PartialColumnKey(groupId: groupId, columnIndex: columnIndex), entry)

func getOrCreateEntry*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    numBlobs: int): PartialColumnEntry =
  let key = PartialColumnKey(groupId: groupId, columnIndex: columnIndex)
  quarantine.entries.get(key).isErrOr:
    return value

  let entry = PartialColumnEntry(
    cellsReceived: BitSeq.init(numBlobs),
    cells: newSeq[KzgCell](numBlobs),
    proofs: newSeq[KzgProof](numBlobs))
  quarantine.entries.put(key, entry)
  entry

func markCellReceived*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    blobIndex: int) =
  let key = PartialColumnKey(groupId: groupId, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return
  if blobIndex < entry.cellsReceived.len:
    entry.cellsReceived.setBit(blobIndex)
    quarantine.entries.put(key, entry)

func markCellReceived*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    blobIndex: int,
    cell: KzgCell,
    proof: KzgProof) =
  ## Mark a cell as received, storing the cell data and proof.
  let key = PartialColumnKey(groupId: groupId, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return
  if blobIndex < entry.cellsReceived.len:
    entry.cellsReceived.setBit(blobIndex)
    entry.cells[blobIndex] = cell
    entry.proofs[blobIndex] = proof
    quarantine.entries.put(key, entry)

func hasCellReceived*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    blobIndex: int): bool =
  let entry = quarantine.entries.get(
      PartialColumnKey(groupId: groupId, columnIndex: columnIndex)).valueOr:
    return false
  if blobIndex < entry.cellsReceived.len:
    return entry.cellsReceived[blobIndex]
  false

# --- Cell ingestion and assembly ---

func receivedCells*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex): BitSeq =
  ## Blob indices whose cells are already stored, and so already KZG-verified.
  let entry = quarantine.entries.get(
      PartialColumnKey(groupId: groupId, columnIndex: columnIndex)).valueOr:
    return BitSeq.init(0)
  entry.cellsReceived

func cellsConsistent*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    sidecar: PartialDataColumnSidecar): bool =
  ## Every cell in `sidecar` that is already populated locally must match
  ## the stored copy. True when no entry exists yet or all overlaps agree.
  let entry = quarantine.entries.get(
      PartialColumnKey(groupId: groupId, columnIndex: columnIndex)).valueOr:
    return true

  var cellIdx = 0
  for blobIdx in 0 ..< sidecar.cells_present_bitmap.len:
    if sidecar.cells_present_bitmap[Natural(blobIdx)]:
      if cellIdx < sidecar.partial_column.len and
         cellIdx < sidecar.kzg_proofs.len and
         blobIdx < entry.cellsReceived.len and
         entry.cellsReceived[blobIdx]:
        if entry.cells[blobIdx] != sidecar.partial_column[cellIdx]:
          return false
        if entry.proofs[blobIdx] != sidecar.kzg_proofs[cellIdx]:
          return false
      cellIdx.inc
  true

func addCells*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex,
    sidecar: ref PartialDataColumnSidecar) =
  ## Ingest cells and proofs from a validated partial data column sidecar.
  let key = PartialColumnKey(groupId: groupId, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return

  template s: untyped = sidecar[]
  var cellIdx = 0
  for blobIdx in 0 ..< s.cells_present_bitmap.len:
    if s.cells_present_bitmap[Natural(blobIdx)]:
      if cellIdx < s.partial_column.len and
         cellIdx < s.kzg_proofs.len and
         blobIdx < entry.cellsReceived.len:
        entry.cellsReceived.setBit(blobIdx)
        entry.cells[blobIdx] = s.partial_column[cellIdx]
        entry.proofs[blobIdx] = s.kzg_proofs[cellIdx]
      cellIdx.inc

  quarantine.entries.put(key, entry)

func isComplete*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex): bool =
  ## True once the group ID is validated and every cell has been received.
  if not quarantine.hasGroupId(groupId):
    return false
  let entry = quarantine.entries.get(
      PartialColumnKey(groupId: groupId, columnIndex: columnIndex)).valueOr:
    return false
  for received in entry.cellsReceived:
    if not received:
      return false
  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/gloas/p2p-interface.md#modified-datacolumnsidecar
func assembleDataColumnSidecar*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex): Opt[DataColumnSidecar] =
  ## Assemble a full DataColumnSidecar from accumulated partial cells.
  ## None if the entry is incomplete or the group ID is not cached.
  let stored = quarantine.groupIds.get(groupId).valueOr:
    return Opt.none(DataColumnSidecar)

  let entry = quarantine.entries.get(
      PartialColumnKey(groupId: groupId, columnIndex: columnIndex)).valueOr:
    return Opt.none(DataColumnSidecar)

  for received in entry.cellsReceived:
    if not received:
      return Opt.none(DataColumnSidecar)

  Opt.some(DataColumnSidecar(
    index: columnIndex,
    column: entry.cells,
    kzg_proofs: entry.proofs,
    slot: stored.slot,
    beacon_block_root: stored.beacon_block_root))

# --- Cleanup ---

func removeGroupId*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID) =
  quarantine.groupIds.del(groupId)

func removeEntry*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID,
    columnIndex: ColumnIndex) =
  quarantine.entries.del(
    PartialColumnKey(groupId: groupId, columnIndex: columnIndex))

func pruneForBlock*(
    quarantine: var PartialColumnQuarantine,
    groupId: PartialDataColumnGroupID) =
  ## Drop the group ID and every per-column entry for it. Called once full
  ## DataColumnSidecars for the block have been promoted into the normal
  ## column quarantine, so the accumulated cells are redundant.
  quarantine.groupIds.del(groupId)
  for columnIndex in 0'u64 ..< NUMBER_OF_COLUMNS:
    quarantine.entries.del(
      PartialColumnKey(groupId: groupId, columnIndex: ColumnIndex(columnIndex)))

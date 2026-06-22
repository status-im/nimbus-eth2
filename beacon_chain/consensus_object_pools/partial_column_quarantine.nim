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
  ../spec/[digest, forks, helpers, presets]

# Spec references:
# - Fulu: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/fulu/partial-columns/p2p-interface.md
# - Gloas: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/partial-columns/p2p-interface.md

from ../spec/datatypes/fulu import
  ColumnIndex, DataColumn

from ../spec/datatypes/deneb import KzgCommitments, KzgProofs

export results

const
  MaxPartialHeaders* = 3 * int(SLOTS_PER_EPOCH)
    ## Maximum number of validated headers (Fulu) or group IDs (Gloas) to
    ## cache.
  MaxPartialEntries* = 3 * int(SLOTS_PER_EPOCH) * NUMBER_OF_COLUMNS
    ## Maximum number of (block_id, column_index) entries to cache.

type
  PartialColumnEntry* = object
    ## Tracks accumulated cells for a single (block_id, column_index) pair.
    ## Fork-agnostic: the same shape is used by every fork that exposes
    ## partial data column sidecars.
    headerValidated*: bool
      ## For Fulu: the PartialDataColumnHeader has been validated on some
      ## subnet. For Gloas: the PartialDataColumnGroupID has been
      ## acknowledged for a block we know about.
    cellsReceived*: BitSeq
      ## Per-blob cell presence tracking, indexed by blob index.
    cells*: seq[Opt[KzgCell]]
      ## Accumulated cell data, indexed by blob index.
    proofs*: seq[Opt[KzgProof]]
      ## Accumulated KZG proofs, indexed by blob index.

  PartialColumnKey*[K] = object
    ## Composite key: per-fork block identifier plus column index.
    ## - Fulu:  K = Eth2Digest (block root)
    ## - Gloas: K = gloas.PartialDataColumnGroupID (slot + beacon_block_root)
    blockId*: K
    columnIndex*: ColumnIndex

  PartialColumnQuarantine*[K, H] = object
    ## Quarantine for partial data column messages, generic over the
    ## per-fork block-identifier type `K` and "header" type `H`.
    ## For Fulu, `K = Eth2Digest` and `H` is the rich
    ## `PartialDataColumnHeader`. For Gloas — the sidecar carries no
    ## header on the wire; the binding is `PartialDataColumnGroupID`,
    ## which we use as both `K` and `H`.
    ##
    ## Stores validated headers / group-ids and tracks which cells have
    ## been received for each (block_id, column_index) pair. Validation
    ## of a header / group-id on any subnet is shared across subnets.
    headers*: LruCache[K, H]
      ## Validated headers (Fulu) or group IDs (Gloas).
    entries*: LruCache[PartialColumnKey[K], PartialColumnEntry]
      ## Per-(block_id, column_index) tracking of received cells.

  # Convenience aliases — one quarantine flavor per fork that exposes
  # partial data column sidecars.
  FuluPartialColumnQuarantine* =
    PartialColumnQuarantine[Eth2Digest, fulu.PartialDataColumnHeader]
  GloasPartialColumnQuarantine* =
    PartialColumnQuarantine[
      gloas.PartialDataColumnGroupID, gloas.PartialDataColumnGroupID]

  # Type class matching any fork's partial sidecar. Both variants share
  # the same cell-bearing fields (cells_present_bitmap, partial_column,
  # kzg_proofs) per spec.
  AnyPartialDataColumnSidecar =
    fulu.PartialDataColumnSidecar | gloas.PartialDataColumnSidecar

func hash*(gid: gloas.PartialDataColumnGroupID): Hash =
  ## https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/partial-columns/p2p-interface.md#new-partialdatacolumngroupid
  var h: Hash = 0
  h = h !& hash(uint64(gid.slot))
  h = h !& hash(gid.beacon_block_root)
  !$h

func `==`*(a, b: gloas.PartialDataColumnGroupID): bool =
  a.slot == b.slot and a.beacon_block_root == b.beacon_block_root

func hash*[K](key: PartialColumnKey[K]): Hash =
  var h: Hash = 0
  h = h !& hash(key.blockId)
  h = h !& hash(uint64(key.columnIndex))
  !$h

func `==`*[K](a, b: PartialColumnKey[K]): bool =
  a.blockId == b.blockId and a.columnIndex == b.columnIndex

func init*[K, H](T: typedesc[PartialColumnQuarantine[K, H]]): T =
  T(
    headers: LruCache[K, H].init(MaxPartialHeaders),
    entries: LruCache[PartialColumnKey[K], PartialColumnEntry].init(
      MaxPartialEntries))

# --- Header / group-id management ---

func hasPartialHeader*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K): bool =
  ## Returns true if a validated header / group-id exists for `blockId`.
  blockId in quarantine.headers

func getPartialHeader*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K): Opt[H] =
  ## Returns the validated header / group-id for `blockId`, if any.
  quarantine.headers.get(blockId)

func putPartialHeader*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    header: ref H) =
  ## Store a validated header / group-id. Passed by reference to match the
  ## `seq[ref ...]` style used for these types elsewhere; the cache itself
  ## stores by value.
  quarantine.headers.put(blockId, header[])

func putPartialGroupID*(
    quarantine: var GloasPartialColumnQuarantine,
    groupId: ref gloas.PartialDataColumnGroupID) =
  ## Gloas convenience: the group-id is both the key and the stored
  ## metadata, so callers do not need to pass it twice.
  quarantine.headers.put(groupId[], groupId[])

# --- Entry (cell tracking) management ---

func hasEntry*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex): bool =
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  key in quarantine.entries

func getEntry*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex): Opt[PartialColumnEntry] =
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  quarantine.entries.get(key)

func putEntry*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex,
    entry: PartialColumnEntry) =
  ## Store or update a PartialColumnEntry for (block_id, column_index).
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  quarantine.entries.put(key, entry)

func getOrCreateEntry*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex,
    numBlobs: int): PartialColumnEntry =
  ## Get or create a PartialColumnEntry for (block_id, column_index).
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  quarantine.entries.get(key).isErrOr:
    return value

  var cellOpts = newSeq[Opt[KzgCell]](numBlobs)
  var proofOpts = newSeq[Opt[KzgProof]](numBlobs)
  let entry = PartialColumnEntry(
    headerValidated: quarantine.hasPartialHeader(blockId),
    cellsReceived: BitSeq.init(numBlobs),
    cells: cellOpts,
    proofs: proofOpts)
  quarantine.entries.put(key, entry)
  entry

func markCellReceived*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex,
    blobIndex: int) =
  ## Mark a specific cell (identified by blob index) as received for the
  ## given (block_id, column_index) pair.
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return
  if blobIndex < entry.cellsReceived.len:
    entry.cellsReceived.setBit(blobIndex)
    quarantine.entries.put(key, entry)

func markCellReceived*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex,
    blobIndex: int,
    cell: KzgCell,
    proof: KzgProof) =
  ## Mark a specific cell as received, storing the cell data and proof.
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return
  if blobIndex < entry.cellsReceived.len:
    entry.cellsReceived.setBit(blobIndex)
    entry.cells[blobIndex] = Opt.some(cell)
    entry.proofs[blobIndex] = Opt.some(proof)
    quarantine.entries.put(key, entry)

func hasCellReceived*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex,
    blobIndex: int): bool =
  ## Check if a specific cell has already been received.
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return false
  if blobIndex < entry.cellsReceived.len:
    return entry.cellsReceived[blobIndex]
  false

# --- Cell ingestion and assembly ---

func addCells*[K, H; S: AnyPartialDataColumnSidecar](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex,
    sidecar: ref S) =
  ## Ingest cells and proofs from a validated partial data column sidecar
  ## into the quarantine entry for the given (block_id, column_index)
  ## pair.
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
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
        entry.cells[blobIdx] = Opt.some(s.partial_column[cellIdx])
        entry.proofs[blobIdx] = Opt.some(s.kzg_proofs[cellIdx])
      cellIdx.inc

  quarantine.entries.put(key, entry)

func isComplete*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex): bool =
  ## Returns true if all cells have been received for the given
  ## (block_id, column_index) pair and the header / group-id has been
  ## validated.
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return false
  if not entry.headerValidated:
    return false
  for received in entry.cellsReceived:
    if not received:
      return false
  true

template assembleColumnAndProofs(entry: PartialColumnEntry): (DataColumn, deneb.KzgProofs) =
  ## Build the column / proofs lists in blob-index order from the entry's
  ## per-blob slots. Caller must have already verified completeness.
  let numBlobs = entry.cellsReceived.len
  var
    column = newSeqOfCap[KzgCell](numBlobs)
    proofs = newSeqOfCap[KzgProof](numBlobs)
  for i in 0 ..< numBlobs:
    column.add(entry.cells[i].get())
    proofs.add(entry.proofs[i].get())
  (DataColumn.init(column), deneb.KzgProofs.init(proofs))

func assembleDataColumnSidecar*(
    quarantine: var FuluPartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex): Opt[fulu.DataColumnSidecar] =
  ## Assemble a full Fulu DataColumnSidecar from accumulated partial cells
  ## and the validated header. Returns Opt.none if the entry is not
  ## complete or the header is missing.
  let key =
    PartialColumnKey[Eth2Digest](blockId: blockRoot, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return Opt.none(fulu.DataColumnSidecar)

  if not entry.headerValidated:
    return Opt.none(fulu.DataColumnSidecar)
  for received in entry.cellsReceived:
    if not received:
      return Opt.none(fulu.DataColumnSidecar)

  let header = quarantine.headers.get(blockRoot).valueOr:
    return Opt.none(fulu.DataColumnSidecar)

  let (column, proofs) = assembleColumnAndProofs(entry)

  Opt.some(fulu.DataColumnSidecar(
    index: columnIndex,
    column: column,
    kzg_commitments: header.kzg_commitments,
    kzg_proofs: proofs,
    signed_block_header: header.signed_block_header,
    kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof))

func assembleDataColumnSidecar*(
    quarantine: var GloasPartialColumnQuarantine,
    groupId: gloas.PartialDataColumnGroupID,
    columnIndex: ColumnIndex): Opt[gloas.DataColumnSidecar] =
  ## Assemble a full Gloas DataColumnSidecar from accumulated partial cells
  ## and the validated group-id. Returns Opt.none if the entry is not
  ## complete or the group-id is not in the cache.
  let key = PartialColumnKey[gloas.PartialDataColumnGroupID](
    blockId: groupId, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return Opt.none(gloas.DataColumnSidecar)

  if not entry.headerValidated:
    return Opt.none(gloas.DataColumnSidecar)
  for received in entry.cellsReceived:
    if not received:
      return Opt.none(gloas.DataColumnSidecar)

  let stored = quarantine.headers.get(groupId).valueOr:
    return Opt.none(gloas.DataColumnSidecar)

  let (column, proofs) = assembleColumnAndProofs(entry)

  Opt.some(gloas.DataColumnSidecar(
    index: columnIndex,
    column: column,
    kzg_proofs: proofs,
    slot: stored.slot,
    beacon_block_root: stored.beacon_block_root))

# --- Cleanup ---

func removeHeader*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K) =
  ## Remove the header / group-id associated with `blockId`.
  quarantine.headers.del(blockId)

func removeEntry*[K, H](
    quarantine: var PartialColumnQuarantine[K, H],
    blockId: K,
    columnIndex: ColumnIndex) =
  ## Remove a specific (block_id, column_index) entry.
  let key = PartialColumnKey[K](blockId: blockId, columnIndex: columnIndex)
  quarantine.entries.del(key)

func pruneForBlock*(
    quarantine: var FuluPartialColumnQuarantine,
    blockRoot: Eth2Digest) =
  ## Drop the validated header and every per-column entry for `blockRoot`.
  ## Called once full DataColumnSidecars for the block have been promoted
  ## into the normal column quarantine — the accumulated partial cells are
  ## now redundant and would otherwise sit in the LRUs until eviction.
  ##
  ## Fulu-only: the Fulu quarantine is keyed by block root. Gloas keys on
  ## `PartialDataColumnGroupID`, so it cannot be pruned by root alone.
  quarantine.headers.del(blockRoot)
  for columnIndex in 0'u64 ..< NUMBER_OF_COLUMNS:
    let key = PartialColumnKey[Eth2Digest](
      blockId: blockRoot, columnIndex: ColumnIndex(columnIndex))
    quarantine.entries.del(key)

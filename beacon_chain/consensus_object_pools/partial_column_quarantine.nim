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

from ../spec/datatypes/fulu import
  PartialDataColumnHeader, PartialDataColumnSidecar, ColumnIndex,
  DataColumn, DataColumnSidecar,
  MAX_BLOB_COMMITMENTS_PER_BLOCK

from ../spec/datatypes/deneb import KzgCommitments, KzgProofs

export results

const
  MaxPartialHeaders* = 3 * int(SLOTS_PER_EPOCH)
    ## Maximum number of validated headers to cache.
  MaxPartialEntries* = 3 * int(SLOTS_PER_EPOCH) * NUMBER_OF_COLUMNS
    ## Maximum number of (block_root, column_index) entries to cache.

type
  PartialColumnEntry* = object
    ## Tracks accumulated cells for a single (block_root, column_index) pair.
    headerValidated*: bool
    cellsReceived*: BitSeq
      ## Per-blob cell presence tracking, indexed by blob index.
    cells*: seq[Opt[KzgCell]]
      ## Accumulated cell data, indexed by blob index.
    proofs*: seq[Opt[KzgProof]]
      ## Accumulated KZG proofs, indexed by blob index.

  PartialColumnKey* = object
    blockRoot*: Eth2Digest
    columnIndex*: ColumnIndex

  HeaderLru = LruCache[Eth2Digest, PartialDataColumnHeader]
  EntryLru = LruCache[PartialColumnKey, PartialColumnEntry]

  PartialColumnQuarantine* = object
    ## Quarantine for partial data column messages.
    ##
    ## Stores validated PartialDataColumnHeaders and tracks which cells
    ## have been received for each (block_root, column_index) pair.
    ## A validated header on any subnet can be reused across all subnets.
    headers*: HeaderLru
      ## Validated headers keyed by block root. Once validated on any subnet,
      ## a header is valid for all subnets.
    entries*: EntryLru
      ## Per-(block_root, column_index) tracking of received cells.

func hash*(key: PartialColumnKey): Hash =
  var h: Hash = 0
  h = h !& hash(key.blockRoot)
  h = h !& hash(uint64(key.columnIndex))
  !$h

func `==`*(a, b: PartialColumnKey): bool =
  a.blockRoot == b.blockRoot and a.columnIndex == b.columnIndex

func init*(T: typedesc[PartialColumnQuarantine]): T =
  T(
    headers: HeaderLru.init(MaxPartialHeaders),
    entries: EntryLru.init(MaxPartialEntries))

# --- Header management ---

func hasPartialHeader*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest): bool =
  ## Returns true if a validated PartialDataColumnHeader exists for this
  ## block root.
  blockRoot in quarantine.headers

func getPartialHeader*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest): Opt[PartialDataColumnHeader] =
  ## Returns the validated PartialDataColumnHeader for a block root, if one
  ## exists.
  quarantine.headers.get(blockRoot)

func putPartialHeader*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    header: PartialDataColumnHeader) =
  ## Store a validated PartialDataColumnHeader. Once validated on any subnet,
  ## the header is valid for all subnets.
  quarantine.headers.put(blockRoot, header)

# --- Entry (cell tracking) management ---

func hasEntry*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex): bool =
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  key in quarantine.entries

func getEntry*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex): Opt[PartialColumnEntry] =
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  quarantine.entries.get(key)

func putEntry*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    entry: PartialColumnEntry) =
  ## Store or update a PartialColumnEntry for (block_root, column_index).
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  quarantine.entries.put(key, entry)

func getOrCreateEntry*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    numBlobs: int): PartialColumnEntry =
  ## Get or create a PartialColumnEntry for the given (block_root, column_index).
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  quarantine.entries.get(key).isErrOr:
    return value

  var cellOpts = newSeq[Opt[KzgCell]](numBlobs)
  var proofOpts = newSeq[Opt[KzgProof]](numBlobs)
  let entry = PartialColumnEntry(
    headerValidated: quarantine.hasPartialHeader(blockRoot),
    cellsReceived: BitSeq.init(numBlobs),
    cells: cellOpts,
    proofs: proofOpts)
  quarantine.entries.put(key, entry)
  entry

func markCellReceived*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    blobIndex: int) =
  ## Mark a specific cell (identified by blob index) as received for the
  ## given (block_root, column_index) pair.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return
  if blobIndex < entry.cellsReceived.len:
    entry.cellsReceived.setBit(blobIndex)
    quarantine.entries.put(key, entry)

func markCellReceived*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    blobIndex: int,
    cell: KzgCell,
    proof: KzgProof) =
  ## Mark a specific cell as received, storing the cell data and proof.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return
  if blobIndex < entry.cellsReceived.len:
    entry.cellsReceived.setBit(blobIndex)
    entry.cells[blobIndex] = Opt.some(cell)
    entry.proofs[blobIndex] = Opt.some(proof)
    quarantine.entries.put(key, entry)

func hasCellReceived*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    blobIndex: int): bool =
  ## Check if a specific cell has already been received.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return false
  if blobIndex < entry.cellsReceived.len:
    return entry.cellsReceived[blobIndex]
  false

# --- Cell ingestion and assembly ---

func addCells*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex,
    sidecar: fulu.PartialDataColumnSidecar) =
  ## Ingest cells and proofs from a validated PartialDataColumnSidecar into
  ## the quarantine entry for the given (block_root, column_index) pair.
  ## Assumes the sidecar has already passed validatePartialDataColumnSidecar.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  var entry = quarantine.entries.get(key).valueOr:
    return

  var cellIdx = 0
  for blobIdx in 0 ..< int(MAX_BLOB_COMMITMENTS_PER_BLOCK):
    if sidecar.cells_present_bitmap[Natural(blobIdx)]:
      if cellIdx < sidecar.partial_columns.len and
         cellIdx < sidecar.kzg_proofs.len and
         blobIdx < entry.cellsReceived.len:
        entry.cellsReceived.setBit(blobIdx)
        entry.cells[blobIdx] = Opt.some(sidecar.partial_columns[cellIdx])
        entry.proofs[blobIdx] = Opt.some(sidecar.kzg_proofs[cellIdx])
      cellIdx.inc

  quarantine.entries.put(key, entry)

func isComplete*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex): bool =
  ## Returns true if all cells have been received for the given
  ## (block_root, column_index) pair and the header has been validated.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return false
  if not entry.headerValidated:
    return false
  for received in entry.cellsReceived:
    if not received:
      return false
  true

func assembleDataColumnSidecar*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex): Opt[fulu.DataColumnSidecar] =
  ## Assemble a full DataColumnSidecar from accumulated partial cells and
  ## the validated header. Returns Opt.none if the entry is not complete
  ## or the header is missing.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  let entry = quarantine.entries.get(key).valueOr:
    return Opt.none(fulu.DataColumnSidecar)

  # Must have header validated and all cells received
  if not entry.headerValidated:
    return Opt.none(fulu.DataColumnSidecar)
  for received in entry.cellsReceived:
    if not received:
      return Opt.none(fulu.DataColumnSidecar)

  let header = quarantine.headers.get(blockRoot).valueOr:
    return Opt.none(fulu.DataColumnSidecar)

  # Assemble the column and proofs in blob-index order
  let numBlobs = entry.cellsReceived.len
  var
    column = newSeqOfCap[KzgCell](numBlobs)
    proofs = newSeqOfCap[KzgProof](numBlobs)

  for i in 0 ..< numBlobs:
    column.add(entry.cells[i].get())
    proofs.add(entry.proofs[i].get())

  Opt.some(fulu.DataColumnSidecar(
    index: columnIndex,
    column: DataColumn.init(column),
    kzg_commitments: header.kzg_commitments,
    kzg_proofs: deneb.KzgProofs.init(proofs),
    signed_block_header: header.signed_block_header,
    kzg_commitments_inclusion_proof: header.kzg_commitments_inclusion_proof))

# --- Cleanup ---

func removeHeader*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest) =
  ## Remove the header associated with a block root.
  quarantine.headers.del(blockRoot)

func removeEntry*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest,
    columnIndex: ColumnIndex) =
  ## Remove a specific (block_root, column_index) entry.
  let key = PartialColumnKey(blockRoot: blockRoot, columnIndex: columnIndex)
  quarantine.entries.del(key)

func pruneForBlock*(
    quarantine: var PartialColumnQuarantine,
    blockRoot: Eth2Digest) =
  ## Drop the validated header and every per-column entry for `blockRoot`.
  ## Called once full DataColumnSidecars for the block have been promoted
  ## into the normal column quarantine — the accumulated partial cells are
  ## now redundant and would otherwise sit in the LRUs until eviction.
  quarantine.headers.del(blockRoot)
  for columnIndex in 0'u64 ..< NUMBER_OF_COLUMNS:
    let key = PartialColumnKey(
      blockRoot: blockRoot, columnIndex: ColumnIndex(columnIndex))
    quarantine.entries.del(key)

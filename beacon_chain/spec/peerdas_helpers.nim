# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Uncategorized helper functions from the spec
import
  chronos, chronicles, results, taskpools,
  eth/p2p/discoveryv5/node,
  kzg4844/kzg,
  ssz_serialization/[
    proofs,
    types],
  stew/assign2,
  ./crypto,
  ./[helpers, digest, column_map],
  ./datatypes/[fulu, deneb]

from std/algorithm import sort
from std/sequtils import repeat, toSeq
from stew/staticfor import staticFor

type
  CellBytes = array[fulu.CELLS_PER_EXT_BLOB, Cell]
  ProofBytes = array[fulu.CELLS_PER_EXT_BLOB, KzgProof]

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.4/specs/fulu/das-core.md#compute_columns_for_custody_group
iterator compute_columns_for_custody_group*(cfg: RuntimeConfig,
                                            custody_group: CustodyIndex):
                                            ColumnIndex =
  let columns_per_group = NUMBER_OF_COLUMNS div cfg.NUMBER_OF_CUSTODY_GROUPS
  for i in 0'u64 ..< columns_per_group:
    yield ColumnIndex(cfg.NUMBER_OF_CUSTODY_GROUPS * i + custody_group)

func handle_custody_groups(cfg: RuntimeConfig, node_id: NodeId,
                           custody_group_count: CustodyIndex):
                           HashSet[CustodyIndex] =
  # Decouples the custody group computation from
  # `get_custody_groups`, in order to later use this custody
  # group list across various types of output types

  var
    custody_groups: HashSet[CustodyIndex]
    current_id = node_id

  let safe_count = min(custody_group_count, cfg.NUMBER_OF_CUSTODY_GROUPS)
  while custody_groups.lenu64 < safe_count:
    var hashed_bytes: array[8, byte]

    let
      current_id_bytes = current_id.toBytesLE()
      hashed_current_id = eth2digest(current_id_bytes)

    hashed_bytes[0..7] = hashed_current_id.data.toOpenArray(0,7)
    let custody_group = bytes_to_uint64(hashed_bytes) mod
      cfg.NUMBER_OF_CUSTODY_GROUPS

    custody_groups.incl custody_group

    inc current_id

  custody_groups

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#get_custody_groups
func get_custody_groups*(cfg: RuntimeConfig, node_id: NodeId,
                         custody_group_count: CustodyIndex):
                         seq[CustodyIndex] =
  let custody_groups =
    cfg.handle_custody_groups(node_id, custody_group_count)

  var groups = custody_groups.toSeq()
  groups.sort()
  groups

func resolve_columns_from_custody_groups*(cfg: RuntimeConfig, node_id: NodeId,
                                          custody_group_count: CustodyIndex):
                                          HashSet[ColumnIndex] =
  ## Returns a set of unique columns for the custody groups of a node.
  let custody_groups = cfg.handle_custody_groups(node_id, custody_group_count)
  var columns: HashSet[ColumnIndex]
  for group in custody_groups:
    for index in compute_columns_for_custody_group(cfg, group):
      columns.incl index
  columns

func resolve_column_map_from_custody_groups*(
    cfg: RuntimeConfig,
    node_id: NodeId,
    custody_group_count: CustodyIndex
): ColumnMap =
  let custody_groups = cfg.handle_custody_groups(node_id, custody_group_count)
  var columns: ColumnMap
  for group in custody_groups:
    for index in compute_columns_for_custody_group(cfg, group):
      columns.incl(index)
  columns

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/fulu/das-core.md#compute_matrix
proc compute_matrix*(blobs: seq[KzgBlob]): Result[seq[MatrixEntry], cstring] =
  ## `compute_matrix` helper demonstrates the relationship
  ## between blobs and the `MatrixEntries`
  var extended_matrix: seq[MatrixEntry]

  for blbIdx, blob in blobs.pairs:
    let cellsAndProofs = computeCellsAndKzgProofs(blob)
    if cellsAndProofs.isErr:
      return err("Computing Extended Matrix: Issue computing cells and proofs")

    for i in 0..<fulu.CELLS_PER_EXT_BLOB:
      extended_matrix.add(MatrixEntry(
        cell: cellsAndProofs.get.cells[i],
        kzg_proof: cellsAndProofs.get.proofs[i],
        row_index: blbIdx.uint64,
        column_index: i.uint64
      ))

  ok(extended_matrix)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/fulu/das-core.md#recover_matrix
proc recover_matrix*(partial_matrix: seq[MatrixEntry],
                     blobCount: int):
                     Result[seq[MatrixEntry], cstring] =
  ## This helper demonstrates how to apply recover_cells_and_kzg_proofs
  ## The data structure for storing cells is implementation-dependent
  var extended_matrix: seq[MatrixEntry]
  for blob_index in 0..<blobCount:
    var
      cell_indices: seq[CellIndex]
      cells: seq[Cell]

    for e in partial_matrix:
      if e.row_index == uint64(blob_index):
        cell_indices.add(e.column_index)
        cells.add(e.cell)

    let recoveredCellsAndKzgProofs =
      recoverCellsAndKzgProofs(cell_indices, cells)
    if recoveredCellsAndKzgProofs.isErr:
      return err("Issue in recovering cells and proofs")

    for i in 0..<recoveredCellsAndKzgProofs.get.cells.len:
      let
        cell = recoveredCellsAndKzgProofs.get.cells[i]
        proof = recoveredCellsAndKzgProofs.get.proofs[i]
      extended_matrix.add(MatrixEntry(
        cell: cell,
        kzg_proof: proof,
        row_index: blob_index.uint64,
        column_index: i.uint64
      ))

  ok(extended_matrix)

proc recoverCellsAndKzgProofsTask(cellIndices: openArray[CellIndex],
                                  cells: openArray[Cell]): Result[CellsAndProofs, void] =
  recoverCellsAndKzgProofs(cellIndices, cells).mapErr(
    proc (x: string) =
      discard)

proc recover_cells_and_proofs_parallel*(
    tp: Taskpool,
    dataColumns: seq[ref fulu.DataColumnSidecar]):
    Result[seq[CellsAndProofs], cstring] =
  ## Recover blobs from data column sidecars in parallel.
  ## - Uses Nim sequences with pointer passing for worker inputs
  ## - Bounds in-flight tasks to limit peak memory/alloc pressure.
  ## - Checks timeout before every spawn operation.
  ## - Ensures all spawned tasks are awaited (drained) before returning.

  if dataColumns.len == 0:
    return err("DataColumnSidecar: Length should not be 0")
  if dataColumns.len > NUMBER_OF_COLUMNS:
    return err("DataColumnSidecar: Length exceeds NUMBER_OF_COLUMNS")

  let
    columnCount = dataColumns.len
    blobCount = dataColumns[0].column.len

  for column in dataColumns:
    if blobCount != column.column.len:
      return err("DataColumns do not have the same length")

  proc workerRecover(idxPtr: ptr CellIndex, cellsPtr: ptr Cell,
                    columnCount: int): Result[CellsAndProofs, void] =
    let
      idxArr = cast[ptr UncheckedArray[CellIndex]](idxPtr)
      cellsArr = cast[ptr UncheckedArray[Cell]](cellsPtr)
    # Use toOpenArray to create views without copying
    recoverCellsAndKzgProofsTask(
      idxArr.toOpenArray(0, columnCount - 1),
      cellsArr.toOpenArray(0, columnCount - 1))

  var
    pendingFuts = newSeq[Flowvar[Result[CellsAndProofs, void]]] (blobCount)
    pendingIndices = newSeq[seq[CellIndex]](blobCount)
    pendingCells = newSeq[seq[Cell]](blobCount)
    res = newSeq[CellsAndProofs](blobCount)

  # track how many we've actually spawned
  var spawned = 0

  # Choose a sane limit for concurrent tasks to reduce peak memory pressure.
  let maxInFlight = min(blobCount, 9)

  let startTime = Moment.now()
  const reconstructionTimeout = 2.seconds

  var
    completed = 0
    hadError = false

  # ---- Spawn + bounded-await loop ----
  for blobIdx in 0 ..< blobCount:
    # Check timeout BEFORE spawning
    if (Moment.now() - startTime) > reconstructionTimeout:
      trace "PeerDAS reconstruction timed out before spawning task",
        spawned = spawned, completed = completed, total = blobCount
      hadError = true
      break  # Stop spawning new tasks

    # Allocate sequences and assign directly to avoid temporary copies
    pendingIndices[spawned] = newSeq[CellIndex](columnCount)
    pendingCells[spawned] = newSeq[Cell](columnCount)

    # Cache addresses to avoid repeated lookups and bounds checks
    let
      indicesPtr = addr pendingIndices[spawned]
      cellsPtr = addr pendingCells[spawned]

    for i in 0 ..< columnCount:
      indicesPtr[][i] = dataColumns[i][].index
      cellsPtr[][i] = dataColumns[i][].column[blobIdx]

    # Store sequences and spawn worker with pointers to their data
    pendingFuts[spawned] = tp.spawn workerRecover(
      addr pendingIndices[spawned][0],
      addr pendingCells[spawned][0],
      columnCount)
    inc spawned

    # If too many in-flight tasks, await the oldest one
    while spawned - completed >= maxInFlight:
      # Check timeout BEFORE syncing
      if (Moment.now() - startTime) > reconstructionTimeout:
        trace "PeerDAS reconstruction timed out before syncing task",
          completed = completed, totalSpawned = spawned
        hadError = true
        break

      let futRes = sync pendingFuts[completed]

      if futRes.isErr:
        hadError = true
      else:
        res[completed] = futRes.get

      inc completed

    if hadError:
      break

  # ---- CRITICAL: Drain all spawned tasks before returning ----
  # This ensures no task references memory that will be destroyed
  for i in completed ..< spawned:
    let futRes = sync pendingFuts[i]
    # Store results only if we haven't had an error and the result is ok
    if not hadError and futRes.isOk:
      res[i] = futRes.get
    elif futRes.isErr:
      hadError = true

  if hadError:
    if (Moment.now() - startTime) > reconstructionTimeout:
      return err("Data column reconstruction timed out")
    # Segregate errors from timeouts
    else:
      return err("Data column reconstruction failed")

  ok(res)

proc assemble_data_column_sidecars*(
    signed_beacon_block: fulu.SignedBeaconBlock,
    blobs: seq[KzgBlob], cell_proofs: seq[KzgProof]): seq[fulu.DataColumnSidecar] =
  template blck(): auto = signed_beacon_block.message
  var sidecars = newSeqOfCap[fulu.DataColumnSidecar](CELLS_PER_EXT_BLOB)

  template kzg_commitments: untyped =
    signed_beacon_block.message.body.blob_kzg_commitments
  if kzg_commitments.len == 0:
    return sidecars
  let
    beacon_block_header =
      BeaconBlockHeader(
        slot: blck.slot,
        proposer_index: blck.proposer_index,
        parent_root: blck.parent_root,
        state_root: blck.state_root,
        body_root: hash_tree_root(blck.body))

    signed_beacon_block_header =
      SignedBeaconBlockHeader(
        message: beacon_block_header,
        signature: signed_beacon_block.signature)

  var
    cells = newSeq[CellBytes](blobs.len)
    proofs = newSeq[ProofBytes](blobs.len)

  for i in 0 ..< blobs.len:
    cells[i] = computeCells(blobs[i]).get
    let proofElem = addr proofs[i]
    staticFor j, 0 ..< CELLS_PER_EXT_BLOB:
      assign(proofElem[][j], cell_proofs[i * CELLS_PER_EXT_BLOB + j])

  for columnIndex in 0..<CELLS_PER_EXT_BLOB:
    var
      column = newSeqOfCap[KzgCell](blobs.len)
      kzgProofOfColumn = newSeqOfCap[KzgProof](blobs.len)
    for rowIndex in 0..<blobs.len:
      column.add(cells[rowIndex][columnIndex])
      kzgProofOfColumn.add(proofs[rowIndex][columnIndex])

    var sidecar = fulu.DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(column),
      kzg_commitments: blck.body.blob_kzg_commitments,
      kzg_proofs: deneb.KzgProofs.init(kzgProofOfColumn),
      signed_block_header: signed_beacon_block_header)
    blck.body.build_proof(
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex,
      sidecar.kzg_commitments_inclusion_proof).expect("Valid gindex")
    sidecars.add(sidecar)

  sidecars

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/builder.md#modified-get_data_column_sidecars
proc assemble_data_column_sidecars*(
    signed_beacon_block: gloas.SignedBeaconBlock,
    blobs: seq[KzgBlob], cell_proofs: seq[KzgProof]): seq[gloas.DataColumnSidecar] =
  template kzg_commitments(): auto =
    signed_beacon_block.message.body.signed_execution_payload_bid.message.blob_kzg_commitments

  if kzg_commitments.len == 0 or blobs.len == 0:
    return static(default(seq[gloas.DataColumnSidecar]))

  var sidecars = newSeqOfCap[gloas.DataColumnSidecar](CELLS_PER_EXT_BLOB)

  if blobs.len != kzg_commitments.len:
    return sidecars

  if cell_proofs.len != blobs.len * CELLS_PER_EXT_BLOB:
    return sidecars

  var
    cells = newSeq[CellBytes](blobs.len)
    proofs = newSeq[ProofBytes](blobs.len)

  for i in 0 ..< blobs.len:
    cells[i] = computeCells(blobs[i]).get
    let proofElem = addr proofs[i]
    staticFor j, 0 ..< CELLS_PER_EXT_BLOB:
      assign(proofElem[][j], cell_proofs[i * CELLS_PER_EXT_BLOB + j])

  template beacon_block_root: untyped = signed_beacon_block.root

  for columnIndex in 0 ..< CELLS_PER_EXT_BLOB:
    var
      column = newSeqOfCap[KzgCell](blobs.len)
      kzgProofOfColumn = newSeqOfCap[KzgProof](blobs.len)

    for rowIndex in 0..<blobs.len:
      column.add(cells[rowIndex][columnIndex])
      kzgProofOfColumn.add(proofs[rowIndex][columnIndex])

    let sidecar = gloas.DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(column),
      kzg_proofs: deneb.KzgProofs.init(kzgProofOfColumn),
      slot: signed_beacon_block.message.slot,
      beacon_block_root: beacon_block_root
    )
    sidecars.add(sidecar)

  sidecars

proc assemble_partial_data_column_sidecars*(
    signed_beacon_block: fulu.SignedBeaconBlock,
    blobs: seq[KzgBlob], cell_proofs: seq[Opt[KzgProof]]): seq[fulu.PartialDataColumnSidecar] =
  ## Returns a seq where element i corresponds to column index i.
  var sidecars = newSeqOfCap[fulu.PartialDataColumnSidecar](CELLS_PER_EXT_BLOB)

  when signed_beacon_block is gloas.SignedBeaconBlock:
    debugGloasComment "kzg_commitments removed from beaconblock in gloas"
    return sidecars
  else:
    if blobs.len == 0 or blobs.len > int(MAX_BLOB_COMMITMENTS_PER_BLOCK):
      return sidecars
    if cell_proofs.len != blobs.len * CELLS_PER_EXT_BLOB:
      return sidecars

    var cells = newSeq[CellBytes](blobs.len)
    for i in 0 ..< blobs.len:
      cells[i] = computeCells(blobs[i]).get

    for columnIndex in 0..<CELLS_PER_EXT_BLOB:
      var
        bitmap: BitArray[int(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
        partialColumn = newSeqOfCap[KzgCell](blobs.len)
        partialProofs = newSeqOfCap[KzgProof](blobs.len)

      for rowIndex in 0..<blobs.len:
        let proofOpt = cell_proofs[rowIndex * CELLS_PER_EXT_BLOB + columnIndex]
        if proofOpt.isSome:
          bitmap[Natural(rowIndex)] = true
          partialColumn.add(cells[rowIndex][columnIndex])
          partialProofs.add(proofOpt.get)

      sidecars.add fulu.PartialDataColumnSidecar(
        cells_present_bitmap: bitmap,
        partial_columns: DataColumn.init(partialColumn),
        kzg_proofs: deneb.KzgProofs.init(partialProofs))

    sidecars

proc verify_partial_data_column_sidecar_kzg_proofs*(
    sidecar: fulu.PartialDataColumnSidecar,
    all_commitments: deneb.KzgCommitments): Result[void, cstring] =
  ## Verify if the KZG proofs are correct.
  var
    cellIndices = newSeqOfCap[CellIndex](sidecar.partial_columns.len)
    commitments = newSeqOfCap[KzgCommitment](sidecar.partial_columns.len)

  let maxI = min(all_commitments.len, int(MAX_BLOB_COMMITMENTS_PER_BLOCK))
  for i in 0 ..< maxI:
    let idx = Natural(i)
    if sidecar.cells_present_bitmap[idx]:
      cellIndices.add(CellIndex(i))
      commitments.add(all_commitments[i])

  if commitments.len != sidecar.partial_columns.len or
      commitments.len != sidecar.kzg_proofs.len:
    return err("PartialDataColumnSidecar: length mismatch")

  let res = verifyCellKzgProofBatch(
      commitments, cellIndices, sidecar.partial_columns.asSeq,
      sidecar.kzg_proofs.asSeq).valueOr:
    return err("PartialDataColumnSidecar: validation error")

  if not res:
    return err("PartialDataColumnSidecar: validation failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.1/specs/fulu/p2p-interface.md#verify_data_column_sidecar
func verify_data_column_sidecar*(cfg: RuntimeConfig, sidecar: fulu.DataColumnSidecar):
                                 Result[void, cstring] =
  ## Verify if the data column sidecar is valid.

  # The sidecar index must be within the valid range
  if sidecar.index >= NUMBER_OF_COLUMNS:
    return err("Data column sidecar index exceeds the NUMBER_OF_COLUMNS")

  # A sidecar for zero blobs is invalid
  if sidecar.kzg_commitments.len == 0:
    return err("Data column contains zero blobs")

  # Check that the sidecar respects the blob limit
  template epoch: untyped = sidecar.signed_block_header.message.slot.epoch()
  if sidecar.kzg_commitments.lenu64 >
      cfg.get_blob_parameters(epoch).MAX_BLOBS_PER_BLOCK:
    return err("Data column contains too many blobs")

  # The column length must be equal to the number of commitments/proofs
  if sidecar.column.len != sidecar.kzg_commitments.len or
      sidecar.column.len != sidecar.kzg_proofs.len:
    return err("Data column length must be equal to the number of commitments/proofs")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/p2p-interface.md#modified-verify_data_column_sidecar
func verify_data_column_sidecar*(cfg: RuntimeConfig, sidecar: gloas.DataColumnSidecar,
                                 kzg_commitments: KzgCommitments):
                                 Result[void, cstring] =
  ## Verify if the data column sidecar is valid.

  # The sidecar index must be within the valid range
  if sidecar.index >= NUMBER_OF_COLUMNS:
    return err("Data column sidecar index exceeds the NUMBER_OF_COLUMNS")

  # [Modified in Gloas:EIP7732]
  # A sidecar for zero blobs is invalid
  if sidecar.column.len() == 0:
    return err("Data column contains zero blobs")

  # [Modified in Gloas:EIP7732]
  # The column length must be equal to the number of commitments/proofs
  if sidecar.column.len() != kzg_commitments.len() or
      sidecar.column.len() != sidecar.kzg_proofs.len():
    return err("Data column length must be equal to the number of commitments/proofs")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#verify_data_column_sidecar_inclusion_proof
func verify_data_column_sidecar_inclusion_proof*(sidecar: fulu.DataColumnSidecar):
                                                 Result[void, cstring] =
  ## Verify if the given KZG commitments included in the given beacon block.
  let gindex =
    KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex
  if not is_valid_merkle_branch(
      hash_tree_root(sidecar.kzg_commitments),
      sidecar.kzg_commitments_inclusion_proof,
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH.int,
      get_subtree_index(gindex),
      sidecar.signed_block_header.message.body_root):

    return err("DataColumnSidecar: Inclusion proof is invalid")

  ok()

# https://github.com/MarcoPolo/consensus-specs/blob/ffee0018e44ba83da90ff41523a3ab88262e5a57/specs/fulu/p2p-interface.md#verify_partial_data_column_header_inclusion_proof
func verify_partial_data_column_header_inclusion_proof*(
    header: fulu.PartialDataColumnHeader): Result[void, cstring] =
  ## Verify if the given KZG commitments are included in the given beacon block.
  let gindex =
    KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex
  if not is_valid_merkle_branch(
      hash_tree_root(header.kzg_commitments),
      header.kzg_commitments_inclusion_proof,
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH.int,
      get_subtree_index(gindex),
      header.signed_block_header.message.body_root):

    return err("PartialDataColumnHeader: Inclusion proof is invalid")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*(sidecar: fulu.DataColumnSidecar):
                                            Result[void, cstring] =
  ## Verify if the KZG proofs are correct.

  # Iterate through the cell indices
  var cellIndices = newSeqOfCap[CellIndex](sidecar.column.len)
  for _ in 0..<sidecar.column.len:
    cellIndices.add(CellIndex(sidecar.index))

  let res = verifyCellKzgProofBatch(
      sidecar.kzg_commitments.asSeq, cellIndices, sidecar.column.asSeq,
      sidecar.kzg_proofs.asSeq).valueOr:
    return err("DataColumnSidecar: validation error")

  if not res:
    return err("DataColumnSidecar: validation failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/p2p-interface.md#modified-verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*(sidecar: gloas.DataColumnSidecar,
                                            kzg_commitments: KzgCommitments):
                                            Result[void, cstring] =
  ## Verify if the KZG proofs are correct.

  # The column index also represents the cell index
  let cellIndices = repeat(CellIndex(sidecar.index), sidecar.column.len)

  # Batch verify that the cells match the corresponding commitments and proofs
  let res = verifyCellKzgProofBatch(
      # [Modified in Gloas:EIP7732]
      kzg_commitments.asSeq,
      cellIndices,
      sidecar.column.asSeq,
      sidecar.kzg_proofs.asSeq).valueOr:
    return err("DataColumnSidecar: validation error")

  if not res:
    return err("DataColumnSidecar: validation failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.4/specs/fulu/validator.md#validator-custody
func get_validators_custody_requirement*(cfg: RuntimeConfig,
                                         total_node_balance: Gwei):
                                         uint64 =
  let count = total_node_balance div cfg.BALANCE_PER_ADDITIONAL_CUSTODY_GROUP
  min(max(count.uint64, cfg.VALIDATOR_CUSTODY_REQUIREMENT),
      cfg.NUMBER_OF_CUSTODY_GROUPS.uint64)

proc recover_blobs_from_data_columns*(
  dataColumns: seq[fulu.DataColumnSidecar]
): Blobs =
  const numCols = CELLS_PER_EXT_BLOB div 2
  var blobs: Blobs

  if dataColumns.len < numCols:
    return blobs
  for i in 0 ..< numCols:
    if dataColumns[i].index != i.uint64:
      return blobs
  let numBlobs = dataColumns[0].column.len

  for blobIndex in 0 ..< numBlobs:
    var blobBytes: Blob
    for colIdx in 0 ..< numCols:
      let
        cellBytes = dataColumns[colIdx].column[blobIndex].bytes
        offset = colIdx * fulu.BYTES_PER_CELL
      assign(
        blobBytes.toOpenArray(offset, offset + fulu.BYTES_PER_CELL - 1),
        cellBytes.toOpenArray(0, fulu.BYTES_PER_CELL - 1)
      )
    discard blobs.add(blobBytes)

  blobs

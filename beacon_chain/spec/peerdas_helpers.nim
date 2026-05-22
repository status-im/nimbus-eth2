# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Uncategorized helper functions from the spec
import
  chronos, chronos/threadsync, chronicles, results, taskpools,
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
from std/sequtils import anyIt, mapIt, repeat, toSeq
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
  recoverCellsAndKzgProofs(cellIndices, cells).mapConvertErr(void)

proc recover_cells_and_proofs_parallel*(
    tp: Taskpool,
    dataColumns: seq[ref fulu.DataColumnSidecar]):
    Future[Result[seq[CellsAndProofs], cstring]] {.async: (raises: []).} =
  ## Recover blobs from data column sidecars in parallel.
  ## - Uses Nim sequences with pointer passing for worker inputs
  ## - Bounds in-flight tasks to limit peak memory/alloc pressure.
  ## - Checks timeout before every spawn operation.
  ## - Ensures all spawned tasks are awaited (drained) before returning.
  if dataColumns.len == 0:
    return err("DataColumnSidecar: Length should not be 0")
  if dataColumns.len > NUMBER_OF_COLUMNS:
    return err("DataColumnSidecar: Length exceeds NUMBER_OF_COLUMNS")
  if tp.numThreads < 2:
    # Without 2 threads, tasks might require blocking the "main" thread which
    # won't work with the logic below
    return err("Need at least 2 threads")

  let
    columnCount = dataColumns.len
    blobCount = dataColumns[0].column.len

  for column in dataColumns:
    if blobCount != column.column.len:
      return err("DataColumns do not have the same length")

  let tsp = ThreadSignalPtr.new().valueOr:
    return err("Could not allocate signal")

  var wait = tsp.wait() # `wait` before task-ended check to avoid race

  defer:
    await wait.cancelAndWait()
    # If there's an error closing the TSP, there's nothing we can do about it
    # here..
    discard tsp.close()

  type Task = object
    pendingIndices: seq[CellIndex]
    pendingCells: seq[Cell]
    ok: Flowvar[bool]

  proc workerRecover(idxPtr: ptr CellIndex, cellsPtr: ptr Cell,
                     columnCount: int, res: ptr CellsAndProofs, tsp: ThreadSignalPtr): bool =
    let
      idxArr = cast[ptr UncheckedArray[CellIndex]](idxPtr)
      cellsArr = cast[ptr UncheckedArray[Cell]](cellsPtr)
    # Use toOpenArray to create views without copying
    defer:
      discard tsp.fireSync()

    res[] = recoverCellsAndKzgProofsTask(
      idxArr.toOpenArray(0, columnCount - 1),
      cellsArr.toOpenArray(0, columnCount - 1)).valueOr:
        return false
    true

  var
    res = newSeq[CellsAndProofs](blobCount)
    spawned = 0 # how many we've actually spawned

  # Run no more tasks than we have threads so that we don't swamp the tp with
  # reconstruction tasks and thus sig verification
  var tasks = newSeq[Task](min(min(blobCount, tp.numThreads), 8))
  for t in tasks.mitems():
    t.pendingIndices = newSeq[CellIndex](columnCount)
    t.pendingCells = newSeq[Cell](columnCount)

  let startTime = Moment.now()
  const reconstructionTimeout = 2.seconds

  var
    hadError = false
    hadTimeout = false

  # Spawn tasks incrementally as they get completed to avoid monopolising the
  # thread pool task queue.
  block spawning:
    # ---- Spawn + bounded-await loop ----
    for blobIdx in 0 ..< blobCount:
      # Check timeout BEFORE spawning
      if (Moment.now() - startTime) > reconstructionTimeout:
        trace "PeerDAS reconstruction timed out before spawning task",
          spawned = spawned, total = blobCount
        hadTimeout = true
        break spawning  # Stop spawning new tasks

      # Find a free task, waiting for some unfinished tasks if none are available
      let taskPtr = block:
        var found = -1
        while true:
          for i, t in tasks.mpairs():
            if not t.ok.isSpawned:
              found = i
              break
            if t.ok.isReady:
              if not t.ok.sync():
                hadError = true
              t.ok.reset()
              if hadError:
                break spawning
              found = i
              break

          if found != -1:
            break

          try:
            await wait
          except AsyncError:
            hadError = true
            break spawning
          except CancelledError:
            hadTimeout = true
            break spawning
          wait = tsp.wait()
        addr tasks[found]

      # Set up pointers to actual data
      for i in 0 ..< columnCount:
        taskPtr[].pendingIndices[i] = dataColumns[i][].index
        taskPtr[].pendingCells[i] = dataColumns[i][].column[blobIdx]

      # Store sequences and spawn worker with pointers to their data
      taskPtr[].ok = tp.spawn workerRecover(
        addr taskPtr[].pendingIndices[0],
        addr taskPtr[].pendingCells[0],
        columnCount,
        addr res[spawned],
        tsp,
      )
      inc spawned

  # ---- CRITICAL: Complete all spawned tasks before returning ----
  while true:
    for t in tasks.mitems():
      if t.ok.isSpawned() and t.ok.isReady():
        # Always consume ok
        hadError = not t.ok.sync() or hadError
        t.ok.reset()

    if tasks.anyIt(it.ok.isSpawned):
      try:
        await wait
      except CatchableError:
        # Waiting for a signal should never fail, but if it does anyway we have
        # to make sure that the tasks are all finished to retain memory safety
        for t in tasks.mitems():
          if t.ok.isSpawned():
            if not t.ok.sync():
              hadError = true
      wait = tsp.wait()
    else:
      break

  if hadError:
    return err("Data column reconstruction failed")
  elif hadTimeout:
    return err("Data column reconstruction timed out")

  ok(res)

proc assemble_data_column_sidecars*(
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments: KzgCommitments,
    kzg_commitments_inclusion_proof:
      array[KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, Eth2Digest],
    blobs: seq[KzgBlob],
    cell_proofs: seq[KzgProof]): fulu.DataColumnSidecars =
  ## Variant used by the column-first sidecar retrieval path: assembles
  ## column sidecars from the per-block constants carried by an existing
  ## column sidecar (header, commitments, inclusion proof) plus blobs and
  ## cell proofs recovered from the EL. The block itself is not required.
  var sidecars = newSeqOfCap[ref fulu.DataColumnSidecar](CELLS_PER_EXT_BLOB)

  if kzg_commitments.len == 0 or blobs.len == 0:
    return sidecars
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

  for columnIndex in 0 ..< CELLS_PER_EXT_BLOB:
    var
      column = newSeqOfCap[KzgCell](blobs.len)
      kzgProofOfColumn = newSeqOfCap[KzgProof](blobs.len)
    for rowIndex in 0 ..< blobs.len:
      column.add(cells[rowIndex][columnIndex])
      kzgProofOfColumn.add(proofs[rowIndex][columnIndex])

    sidecars.add (ref fulu.DataColumnSidecar)(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(column),
      kzg_commitments: kzg_commitments,
      kzg_proofs: deneb.KzgProofs.init(kzgProofOfColumn),
      signed_block_header: signed_block_header,
      kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof)

  sidecars

proc assemble_data_column_sidecars*(
    signed_beacon_block: fulu.SignedBeaconBlock,
    blobs: seq[KzgBlob], cell_proofs: seq[KzgProof]): fulu.DataColumnSidecars =
  template blck(): auto = signed_beacon_block.message
  var sidecars = newSeqOfCap[ref fulu.DataColumnSidecar](CELLS_PER_EXT_BLOB)

  template kzg_commitments: untyped =
    signed_beacon_block.message.body.blob_kzg_commitments
  if kzg_commitments.len == 0:
    return sidecars
  if blobs.len != kzg_commitments.len:
    return sidecars
  if cell_proofs.len != blobs.len * CELLS_PER_EXT_BLOB:
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

  let inclusion_proof =
    blck.body.build_proof(KZG_COMMITMENTS_GINDEX).expect("Valid gindex")
  for columnIndex in 0..<CELLS_PER_EXT_BLOB:
    var
      column = newSeqOfCap[KzgCell](blobs.len)
      kzgProofOfColumn = newSeqOfCap[KzgProof](blobs.len)
    for rowIndex in 0..<blobs.len:
      column.add(cells[rowIndex][columnIndex])
      kzgProofOfColumn.add(proofs[rowIndex][columnIndex])

    sidecars.add (ref fulu.DataColumnSidecar)(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(column),
      kzg_commitments: blck.body.blob_kzg_commitments,
      kzg_proofs: deneb.KzgProofs.init(kzgProofOfColumn),
      signed_block_header: signed_beacon_block_header,
      kzg_commitments_inclusion_proof: inclusion_proof)

  sidecars

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/builder.md#modified-get_data_column_sidecars
proc assemble_data_column_sidecars*(
    signed_beacon_block: gloas.SignedBeaconBlock,
    blobs: seq[KzgBlob], cell_proofs: seq[KzgProof]): gloas.DataColumnSidecars =
  template kzg_commitments(): auto =
    signed_beacon_block.message.body.signed_execution_payload_bid.message.blob_kzg_commitments

  if kzg_commitments.len == 0 or blobs.len == 0:
    return static(default(gloas.DataColumnSidecars))

  var sidecars = newSeqOfCap[ref gloas.DataColumnSidecar](CELLS_PER_EXT_BLOB)

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

    sidecars.add (ref gloas.DataColumnSidecar)(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(column),
      kzg_proofs: deneb.KzgProofs.init(kzgProofOfColumn),
      slot: signed_beacon_block.message.slot,
      beacon_block_root: beacon_block_root)

  sidecars

proc assemble_partial_data_column_sidecars*(
    blobs: seq[KzgBlob], cell_proofs: seq[Opt[KzgProof]]): seq[fulu.PartialDataColumnSidecar] =
  ## Returns a seq where element i corresponds to column index i.
  var sidecars = newSeqOfCap[fulu.PartialDataColumnSidecar](CELLS_PER_EXT_BLOB)

  if blobs.len == 0 or blobs.len > int(MAX_BLOB_COMMITMENTS_PER_BLOCK):
    return sidecars
  if cell_proofs.len != blobs.len * CELLS_PER_EXT_BLOB:
    return sidecars

  let cells = blobs.mapIt(computeCells(it).get)

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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.7/specs/fulu/p2p-interface.md#verify_partial_data_column_sidecar_kzg_proofs
proc verify_partial_data_column_sidecar_kzg_proofs*(
    sidecar: fulu.PartialDataColumnSidecar,
    all_commitments: deneb.KzgCommitments,
    column_index: ColumnIndex): Result[void, cstring] =
  ## Verify the KZG proofs for partial data column sidecars.

  # Get the blob indices from the bitmap
  var blobIndices = newSeqOfCap[int](sidecar.partial_columns.len)
  for i in 0 ..< int(MAX_BLOB_COMMITMENTS_PER_BLOCK):
    # BitArray's [] / []= accessors require a Natural (non-negative integer)
    if sidecar.cells_present_bitmap[Natural(i)]:
      blobIndices.add(i)

  # The cell index is the column index for all cells in this column
  let cellIndices = repeat(CellIndex(column_index), blobIndices.len)

  # Batch verify that the cells match the corresponding commitments and proofs
  let commitments = blobIndices.mapIt(all_commitments[it])

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
func verify_data_column_sidecar_inclusion_proof*(
    sidecar: fulu.DataColumnSidecar): Result[void, cstring] =
  ## Verify if the given KZG commitments included in the given beacon block.
  const gindex = KZG_COMMITMENTS_GINDEX
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
  const gindex = KZG_COMMITMENTS_GINDEX
  if not is_valid_merkle_branch(
      hash_tree_root(header.kzg_commitments),
      header.kzg_commitments_inclusion_proof,
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH.int,
      get_subtree_index(gindex),
      header.signed_block_header.message.body_root):
    return err("PartialDataColumnHeader: Inclusion proof is invalid")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#verify_data_column_sidecar_kzg_proofs
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/p2p-interface.md#modified-verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*[
    T: fulu.DataColumnSidecar | gloas.DataColumnSidecar](
    sidecar: T, kzg_commitments: KzgCommitments): Result[void, cstring] =
  ## Verify if the KZG proofs are correct.

  # The column index also represents the cell index
  let cellIndices = repeat(CellIndex(sidecar.index), sidecar.column.len)

  let res = verifyCellKzgProofBatch(
      kzg_commitments.asSeq,
      cellIndices,
      sidecar.column.asSeq,
      sidecar.kzg_proofs.asSeq).valueOr:
    return err("DataColumnSidecar: validation error")

  if not res:
    return err("DataColumnSidecar: validation failed")

  ok()

proc verify_data_column_sidecar_kzg_proofs*(sidecar: fulu.DataColumnSidecar):
                                            Result[void, cstring] =
  ## Verify if the KZG proofs are correct.
  verify_data_column_sidecar_kzg_proofs(sidecar, sidecar.kzg_commitments)

template verifyKzgBatchBody(
    sidecarsArg, expectedLen, commitmentAt: untyped) =
  if sidecarsArg.len == 0:
    return ok()

  var totalCells = 0
  for sidecar {.inject.} in sidecarsArg:
    if sidecar.column.len != expectedLen or
        sidecar.column.len != sidecar.kzg_proofs.len:
      return err("DataColumnSidecar: length mismatch")
    totalCells += sidecar.column.len

  var
    commitments = newSeqOfCap[KzgCommitment](totalCells)
    cellIndices = newSeqOfCap[CellIndex](totalCells)
    cells = newSeqOfCap[KzgCell](totalCells)
    proofs = newSeqOfCap[KzgProof](totalCells)

  for sidecar {.inject.} in sidecarsArg:
    let idx = CellIndex(sidecar.index)
    for blobIdx {.inject.} in 0 ..< sidecar.column.len:
      commitments.add(commitmentAt)
      cellIndices.add(idx)
      cells.add(sidecar.column[blobIdx])
      proofs.add(sidecar.kzg_proofs[blobIdx])

  let res = verifyCellKzgProofBatch(
      commitments, cellIndices, cells, proofs).valueOr:
    return err("DataColumnSidecar: validation error")

  if not res:
    return err("DataColumnSidecar: validation failed")

  ok()

proc verify_data_column_sidecar_kzg_proofs*[
    T: fulu.DataColumnSidecar | gloas.DataColumnSidecar |
       ref fulu.DataColumnSidecar | ref gloas.DataColumnSidecar](
    sidecars: openArray[T],
    kzg_commitments: KzgCommitments): Result[void, cstring] =
  ## Batch verify KZG proofs across multiple DataColumnSidecars against a
  ## single shared `kzg_commitments` array (e.g. gloas, where commitments
  ## come from the bid). Accepts either values or refs.
  verifyKzgBatchBody(sidecars, kzg_commitments.len, kzg_commitments[blobIdx])

proc verify_data_column_sidecar_kzg_proofs*[
    T: fulu.DataColumnSidecar | ref fulu.DataColumnSidecar](
    sidecars: openArray[T]): Result[void, cstring] =
  ## Batch verify KZG proofs across multiple fulu DataColumnSidecars using
  ## each sidecar's own `kzg_commitments`. Equivalent to verifying each
  ## sidecar individually: a sidecar carrying commitments that don't match
  ## its cells/proofs is rejected regardless of its position in the batch.
  verifyKzgBatchBody(
    sidecars, sidecar.kzg_commitments.len, sidecar.kzg_commitments[blobIdx])

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.4/specs/fulu/validator.md#validator-custody
func get_validators_custody_requirement*(cfg: RuntimeConfig,
                                         total_node_balance: Gwei):
                                         uint64 =
  let count = total_node_balance div cfg.BALANCE_PER_ADDITIONAL_CUSTODY_GROUP
  min(max(count.uint64, cfg.VALIDATOR_CUSTODY_REQUIREMENT),
      cfg.NUMBER_OF_CUSTODY_GROUPS.uint64)

proc recover_blobs_from_data_columns*(
  dataColumns: openArray[ref fulu.DataColumnSidecar]
): Blobs =
  const numCols = CELLS_PER_EXT_BLOB div 2
  var blobs: Blobs

  if dataColumns.len < numCols:
    return blobs
  for i in 0 ..< numCols:
    if dataColumns[i][].index != i.uint64:
      return blobs
  let numBlobs = dataColumns[0][].column.len

  for blobIndex in 0 ..< numBlobs:
    var blobBytes: Blob
    for colIdx in 0 ..< numCols:
      let
        cellBytes = dataColumns[colIdx][].column[blobIndex].bytes
        offset = colIdx * fulu.BYTES_PER_CELL
      assign(
        blobBytes.toOpenArray(offset, offset + fulu.BYTES_PER_CELL - 1),
        cellBytes.toOpenArray(0, fulu.BYTES_PER_CELL - 1)
      )
    discard blobs.add(blobBytes)

  blobs

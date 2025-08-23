# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Uncategorized helper functions from the spec
import
  chronicles, results,
  eth/p2p/discoveryv5/[node],
  kzg4844/[kzg],
  ssz_serialization/[
    proofs,
    types],
  stew/assign2,
  ./crypto,
  ./[helpers, digest],
  ./datatypes/fulu

from std/algorithm import sort
from std/sequtils import toSeq
from stew/staticfor import staticfor

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

  while custody_groups.lenu64 < custody_group_count:
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
  let custody_groups = cfg.get_custody_groups(node_id, custody_group_count)
  var columns: HashSet[ColumnIndex]
  for group in custody_groups:
    for index in compute_columns_for_custody_group(cfg, group):
      columns.incl index
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

proc recover_cells_and_proofs*(
    data_columns: seq[ref DataColumnSidecar]):
    Result[seq[CellsAndProofs], cstring] =
  ## This helper recovers blobs from the data column sidecars
  if data_columns.len == 0:
    return err("DataColumnSidecar: Length should not be 0")

  let start = Moment.now()

  let
    columnCount = data_columns.len
    blobCount = data_columns[0].column.len

  for data_column in data_columns:
    if not (blobCount == data_column.column.len):
      return err ("DataColumns do not have the same length")

  var
    recovered_cps =
      newSeq[CellsAndProofs](blobCount)

  for blobIdx in 0..<blobCount:
    var
      bIdx = blobIdx
      cell_ids = newSeqOfCap[CellIndex](columnCount)
      ckzgCells = newSeqOfCap[KzgCell](columnCount)

    for col in data_columns:
      cell_ids.add col[].index

      let
        column = col[].column
        cell = column[bIdx]

      ckzgCells.add cell

    # Recovering the cells and proofs
    let recovered_cells_and_proofs =
      recoverCellsAndKzgProofs(cell_ids, ckzgCells)
    if not recovered_cells_and_proofs.isOk:
      return err("Failed to compute cells and proofs")

    recovered_cps[bIdx] =
      recovered_cells_and_proofs.get
  let finish = Moment.now()
  debug "Time taken to reconstruct sequentially", time = finish-start
  ok(recovered_cps)

# Additional overload to perform reconstruction at the time of gossip
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.4/specs/fulu/validator.md#get_data_column_sidecars
func get_data_column_sidecars*(signed_beacon_block: fulu.SignedBeaconBlock,
                               cellsAndProofs: seq[CellsAndProofs]):
                               seq[DataColumnSidecar] =
  ## Given a signed beacon block and the blobs corresponding to the block,
  ## this function assembles the sidecars which can be distributed to
  ## the peers post data column reconstruction at every slot start.
  ##
  ## Note: this function only accepts `SignedBeaconBlock` as
  ## during practice we would be extracting data columns
  ## before publishing them, all of this happens during block
  ## production, hence the blocks are yet untrusted and have not
  ## yet been verified.
  template blck(): auto = signed_beacon_block.message
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
    sidecars =
      newSeqOfCap[DataColumnSidecar](CELLS_PER_EXT_BLOB)

  for column_index in 0..<NUMBER_OF_COLUMNS:
    var
      column_cells = newSeqOfCap[KzgCell](cellsAndProofs.len)
      column_proofs = newSeqOfCap[KzgProof](cellsAndProofs.len)
    for i in 0..<cellsAndProofs.len:
      column_cells.add(cellsAndProofs[i].cells)
      column_proofs.add(cellsAndProofs[i].proofs)

    var sidecar = DataColumnSidecar(
      index: ColumnIndex(column_index),
      column: DataColumn.init(column_cells),
      kzg_commitments: blck.body.blob_kzg_commitments,
      kzg_proofs: KzgProofs.init(column_proofs),
      signed_block_header: signed_beacon_block_header)
    blck.body.build_proof(
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex,
      sidecar.kzg_commitments_inclusion_proof).expect("Valid gindex")
    sidecars.add(sidecar)

  sidecars

proc assemble_data_column_sidecars*(signed_beacon_block: fulu.SignedBeaconBlock,
                                    blobs: seq[KzgBlob],
                                    cell_proofs: seq[KzgProof]):
                                    seq[DataColumnSidecar] =
  template blck(): auto = signed_beacon_block.message
  var
    sidecars =
      newSeqOfCap[DataColumnSidecar](CELLS_PER_EXT_BLOB)
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

    var sidecar = DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(column),
      kzg_commitments: blck.body.blob_kzg_commitments,
      kzg_proofs: KzgProofs.init(kzgProofOfColumn),
      signed_block_header: signed_beacon_block_header)
    blck.body.build_proof(
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex,
      sidecar.kzg_commitments_inclusion_proof).expect("Valid gindex")
    sidecars.add(sidecar)

  sidecars

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/fulu/peer-sampling.md#get_extended_sample_count
func get_extended_sample_count*(samples_per_slot: int,
                                allowed_failures: int):
                                int =
  ## `get_extended_sample_count` computes the number of samples we
  ## should query from peers, given the SAMPLES_PER_SLOT and
  ## the number of allowed failures

  # If 50% of the columns are missing, we are able to reconstruct the data
  # If 50% + 1 columns are missing, we cannot reconstruct the data
  const worstCaseConditionCount = (NUMBER_OF_COLUMNS div 2) + 1

  # Compute the false positive threshold
  let falsePositiveThreshold =
    hypergeom_cdf(0, NUMBER_OF_COLUMNS, worstCaseConditionCount, samples_per_slot)

  # Finally, compute the extended sample count
  for i in samples_per_slot .. NUMBER_OF_COLUMNS:
    if hypergeom_cdf(
        allowed_failures,
        NUMBER_OF_COLUMNS,
        worstCaseConditionCount, i) <= falsePositiveThreshold:
      return i

  NUMBER_OF_COLUMNS

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#verify_data_column_sidecar
func verify_data_column_sidecar*(sidecar: DataColumnSidecar):
                                 Result[void, cstring] =
  ## Verify if the data column sidecar is valid.

  if sidecar.index >= NUMBER_OF_COLUMNS:
    return err("Data column sidecar index exceeds the NUMBER_OF_COLUMNS")

  if sidecar.kzg_commitments.len == 0:
    return err("Data column contains zero blob")

  if sidecar.column.len != sidecar.kzg_commitments.len or
      sidecar.column.len != sidecar.kzg_proofs.len:
    return err("Data column length must be equal to the number of commitments/proofs")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#verify_data_column_sidecar_inclusion_proof
func verify_data_column_sidecar_inclusion_proof*(sidecar: DataColumnSidecar):
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*(sidecar: DataColumnSidecar):
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

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.4/specs/fulu/validator.md#validator-custody
func get_validators_custody_requirement*(cfg: RuntimeConfig,
                                         total_node_balance: Gwei):
                                         uint64 =
  let count = total_node_balance div cfg.BALANCE_PER_ADDITIONAL_CUSTODY_GROUP
  min(max(count.uint64, cfg.VALIDATOR_CUSTODY_REQUIREMENT),
      cfg.NUMBER_OF_CUSTODY_GROUPS.uint64)

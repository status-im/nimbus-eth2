# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec
import
  std/[algorithm, sequtils],
  results,
  eth/p2p/discoveryv5/[node],
  kzg4844/[kzg],
  ssz_serialization/[
    proofs,
    types],
  ./crypto,
  ./[helpers, digest],
  ./datatypes/[fulu]

type
  CellBytes = array[fulu.CELLS_PER_EXT_BLOB, Cell]
  ProofBytes = array[fulu.CELLS_PER_EXT_BLOB, KzgProof]

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#compute_columns_for_custody_group
iterator compute_columns_for_custody_group(custody_group: CustodyIndex):
                                           ColumnIndex =
  for i in 0'u64 ..< COLUMNS_PER_GROUP:
    yield ColumnIndex(NUMBER_OF_CUSTODY_GROUPS * i + custody_group)

func handle_custody_groups(node_id: NodeId,
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
      NUMBER_OF_CUSTODY_GROUPS

    custody_groups.incl custody_group

    inc current_id

  custody_groups

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#get_custody_groups
func get_custody_groups*(node_id: NodeId,
                        custody_group_count: CustodyIndex):
                        seq[CustodyIndex] =
  let custody_groups =
    node_id.handle_custody_groups(custody_group_count)

  var groups = custody_groups.toSeq()
  groups.sort()
  groups

func resolve_columns_from_custody_groups*(node_id: NodeId,
                                          custody_group_count: CustodyIndex):
                                          seq[ColumnIndex] =

  let
    custody_groups = node_id.get_custody_groups(custody_group_count)

  var flattened =
    newSeqOfCap[ColumnIndex](COLUMNS_PER_GROUP * custody_groups.len)
  for group in custody_groups:
    for index in compute_columns_for_custody_group(group):
       flattened.add index
  flattened

func resolve_column_sets_from_custody_groups*(node_id: NodeId,
                                    custody_group_count: CustodyIndex):
                                    HashSet[ColumnIndex] =

  node_id.resolve_columns_from_custody_groups(custody_group_count).toHashSet()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#compute_matrix
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#recover_matrix
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/das-core.md#get_data_column_sidecars
proc get_data_column_sidecars*(signed_beacon_block: electra.TrustedSignedBeaconBlock,
                               cellsAndProofs: seq[CellsAndProofs]):
                               seq[DataColumnSidecar] =
  ## Given a trusted signed beacon block and the cells/proofs associated
  ## with each data column (thereby blob as well) corresponding to the block,
  ## this function assembles the sidecars which can be distributed to
  ## the peers post data column reconstruction at every slot start.
  ##
  ## Note: this function only accepts `TrustedSignedBeaconBlock` as
  ## during practice we would be computing cells and proofs from
  ## data columns only after retrieving them from the database, where
  ## they we were already verified and persisted.
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
        signature: signed_beacon_block.signature.toValidatorSig)

  var
    sidecars =
      newSeqOfCap[DataColumnSidecar](CELLS_PER_EXT_BLOB)

  for column_index in 0..<NUMBER_OF_COLUMNS:
    var
      column_cells: seq[KzgCell]
      column_proofs: seq[KzgProof]
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

# Alternative approach to `get_data_column_sidecars` by directly computing
# blobs from blob bundles
proc get_data_column_sidecars*(signed_beacon_block: electra.SignedBeaconBlock,
                               blobs: seq[KzgBlob]):
                               Result[seq[DataColumnSidecar], cstring] =
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
    cells = newSeq[CellBytes](blobs.len)
    proofs = newSeq[ProofBytes](blobs.len)

  for i in 0..<blobs.len:
    let
      cell_and_proof = computeCellsAndKzgProofs(blobs[i])
    if cell_and_proof.isErr():
      return err("EIP7549: Could not compute cells")

    cells[i] = cell_and_proof.get.cells
    proofs[i] = cell_and_proof.get.proofs

  for columnIndex in 0..<CELLS_PER_EXT_BLOB:
    var
      column: seq[KzgCell]
      kzgProofOfColumn: seq[KzgProof]
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

  ok(sidecars)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/peer-sampling.md#get_extended_sample_count
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#verify_data_column_sidecar_inclusion_proof
proc verify_data_column_sidecar_inclusion_proof*(sidecar: DataColumnSidecar):
                                                 Result[void, cstring] =
  ## Verify if the given KZG Commitments are in included
  ## in the beacon block or not
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*(sidecar: DataColumnSidecar):
                                            Result[void, cstring] =
  ## Verify if the KZG Proofs consisting in the `DataColumnSidecar`
  ## is valid or not.

  # Check if the data column sidecar index < NUMBER_OF_COLUMNS
  if not (sidecar.index < NUMBER_OF_COLUMNS):
    return err("Data column sidecar index exceeds the NUMBER_OF_COLUMNS")

  # Check is the sidecar column length = sidecar.kzg_commitments length
  # and sidecar.kzg_commitments length = sidecar.kzg_proofs length
  if not (sidecar.column.len == sidecar.kzg_commitments.len):
    return err("Data column sidecar length is not equal to the kzg_commitments length")

  if not (sidecar.kzg_commitments.len == sidecar.kzg_proofs.len):
    return err("Sidecar kzg_commitments length is not equal to the kzg_proofs length")

  # Iterate through the cell indices
  var cellIndices =
    newSeq[CellIndex](MAX_BLOB_COMMITMENTS_PER_BLOCK)
  for _ in 0..<sidecar.column.len:
    cellIndices.add(sidecar.index * sidecar.column.lenu64)

  let res =
    verifyCellKzgProofBatch(sidecar.kzg_commitments.asSeq,
                            cellIndices,
                            sidecar.column.asSeq,
                            sidecar.kzg_proofs.asSeq)

  if res.isErr():
    return err("DataColumnSidecar: validation failed")

  ok()

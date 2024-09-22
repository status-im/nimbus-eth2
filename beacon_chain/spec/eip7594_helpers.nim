# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec
import
  std/algorithm,
  results,
  eth/p2p/discoveryv5/[node],
  kzg4844/[kzg],
  ssz_serialization/[
    proofs,
    types],
  ./crypto,
  ./[helpers, digest],
  ./datatypes/[eip7594]

type
  CellBytes = array[eip7594.CELLS_PER_EXT_BLOB, Cell]
  ProofBytes = array[eip7594.CELLS_PER_EXT_BLOB, KzgProof]

func sortedColumnIndices*(columnsPerSubnet: ColumnIndex,
                          subnetIds: HashSet[uint64]):
                          seq[ColumnIndex] =
  var res: seq[ColumnIndex] = @[]
  for i in 0'u64 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort
  res

func sortedColumnIndexList*(columnsPerSubnet: ColumnIndex,
                            subnetIds: HashSet[uint64]):
                            List[ColumnIndex, NUMBER_OF_COLUMNS] =
  var
    res: seq[ColumnIndex]
  for i in 0'u64 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort()
  List[ColumnIndex, NUMBER_OF_COLUMNS].init(res)

func get_custody_column_subnets*(node_id: NodeId,
                                 custody_subnet_count: uint64):
                                 HashSet[uint64] =

  # Decouples the custody subnet computation part from
  # `get_custody_columns`, in order to later use this subnet list
  # in order to maintain subscription to specific column subnets.

  var
    subnet_ids: HashSet[uint64]
    current_id = node_id

  while subnet_ids.lenu64 < custody_subnet_count:
    var
      hashed_bytes: array[8, byte]

    let
      current_id_bytes = current_id.toBytesLE()
      hashed_current_id = eth2digest(current_id_bytes)

    hashed_bytes[0..7] = hashed_current_id.data.toOpenArray(0,7)
    let subnet_id = bytes_to_uint64(hashed_bytes) mod
      DATA_COLUMN_SIDECAR_SUBNET_COUNT

    subnet_ids.incl(subnet_id)

    if current_id == UInt256.high.NodeId:
      # Overflow prevention
      current_id = NodeId(StUint[256].zero)
    current_id += NodeId(StUint[256].one)

  subnet_ids

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#get_custody_columns
func get_custody_columns*(node_id: NodeId,
                          custody_subnet_count: uint64):
                          seq[ColumnIndex] =
  let
    subnet_ids =
      get_custody_column_subnets(node_id, custody_subnet_count)
  const
    columns_per_subnet =
      NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT

  sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids)

func get_custody_column_list*(node_id: NodeId,
                              custody_subnet_count: uint64):
                              List[ColumnIndex, NUMBER_OF_COLUMNS] =

  # Not in spec in the exact format, but it is useful in sorting custody columns
  # before sending, data_column_sidecars_by_range requests
  let
    subnet_ids =
      get_custody_column_subnets(node_id, custody_subnet_count)
  const
    columns_per_subnet =
      NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT

  sortedColumnIndexList(ColumnIndex(columns_per_subnet), subnet_ids)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#compute_matrix
proc compute_matrix*(blobs: seq[KzgBlob]): Result[seq[MatrixEntry], cstring] =
  ## `compute_matrix` helper demonstrates the relationship
  ## between blobs and the `MatrixEntries`
  var extended_matrix: seq[MatrixEntry]

  for blbIdx, blob in blobs.pairs:
    let cellsAndProofs = computeCellsAndKzgProofs(blob)
    if cellsAndProofs.isErr:
      return err("Computing Extended Matrix: Issue computing cells and proofs")

    for i in 0..<eip7594.CELLS_PER_EXT_BLOB:
      extended_matrix.add(MatrixEntry(
        cell: cellsAndProofs.get.cells[i],
        kzg_proof: cellsAndProofs.get.proofs[i],
        row_index: blbIdx.uint64,
        column_index: i.uint64
      ))

  ok(extended_matrix)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#recover_matrix
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/_features/eip7594/peer-sampling.md#get_extended_sample_count
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
  let
    blck = signed_beacon_block.message
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
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: KzgProofs.init(column_proofs),
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
                               Result[seq[DataColumnSidecar], string] =
  ## Given a signed beacon block and the blobs corresponding to the block,
  ## this function assembles the sidecars which can be distributed to 
  ## the peers post data column reconstruction at every slot start.
  ## 
  ## Note: this function only accepts `SignedBeaconBlock` as
  ## during practice we would be extracting data columns
  ## before publishing them, all of this happens during block 
  ## production, hence the blocks are yet untrusted and have not 
  ## yet been verified.
  let
    blck = signed_beacon_block.message
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

  var
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
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: KzgProofs.init(kzgProofOfColumn),
      signed_block_header: signed_beacon_block_header)
    blck.body.build_proof(
      KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GINDEX.GeneralizedIndex,
      sidecar.kzg_commitments_inclusion_proof).expect("Valid gindex")
    sidecars.add(sidecar)

  ok(sidecars)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/_features/eip7594/peer-sampling.md#get_extended_sample_count
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
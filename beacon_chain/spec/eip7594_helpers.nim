# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec
import
  std/[algorithm, macros, tables],
  stew/results,
  ssz_serialization/[
    proofs,
    types],
  chronicles,
  ./[beacon_time, crypto],
  kzg4844/kzg_ex,
  eth/p2p/discoveryv5/[node],
  ./helpers,
  
  ./datatypes/[eip7594, deneb]

type
  CellBytes = array[eip7594.CELLS_PER_EXT_BLOB, Cell]
  ProofBytes = array[eip7594.CELLS_PER_EXT_BLOB, KzgProof]

proc sortedColumnIndices*(columnsPerSubnet: ColumnIndex,
                          subnetIds: HashSet[uint64]):
                          seq[ColumnIndex] =
  var res: seq[ColumnIndex] = @[]
  for i in 0'u64 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort
  res

proc sortedColumnIndexList*(columnsPerSubnet: ColumnIndex, 
                            subnetIds: HashSet[uint64]): 
                            List[ColumnIndex, NUMBER_OF_COLUMNS] =
  var
    res: seq[ColumnIndex]
  for i in 0'u64 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort()
  let list = List[ColumnIndex, NUMBER_OF_COLUMNS].init(res)
  list

proc get_custody_column_subnets*(node_id: NodeId, 
                                 custody_subnet_count: uint64): 
                                 Result[HashSet[uint64], cstring] =

  # Decouples the custody subnet computation part from
  # `get_custody_columns`, in order to later use this subnet list
  # in order to maintain subscription to specific column subnets.

  if not (custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT):
    return err("Eip7594: Custody subnet count exceeds the DATA_COLUMN_SIDECAR_SUBNET_COUNT")

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

  ok(subnet_ids)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#get_custody_columns
proc get_custody_columns*(node_id: NodeId, 
                          custody_subnet_count: uint64): 
                          seq[ColumnIndex] =
  let
    subnet_ids = 
      get_custody_column_subnets(node_id, custody_subnet_count).get
  const
    columns_per_subnet = 
      NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT

  sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids)


proc get_custody_column_list*(node_id: NodeId, 
                          custody_subnet_count: uint64): 
                          List[ColumnIndex, NUMBER_OF_COLUMNS] =

  # Not in spec in the exact format, but it is useful in sorting custody columns 
  # before sending, data_column_sidecars_by_range requests
  let
    subnet_ids = 
      get_custody_column_subnets(node_id, custody_subnet_count).get
  const
    columns_per_subnet = 
      NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  sortedColumnIndexList(ColumnIndex(columns_per_subnet), subnet_ids)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/_features/eip7594/das-core.md#compute_extended_matrix
proc compute_extended_matrix* (blobs: seq[KzgBlob]): Result[seq[MatrixEntry], cstring] =
  # This helper demonstrates the relationship between blobs and the `MatrixEntries`
  var extended_matrix: seq[MatrixEntry]

  for blbIdx, blob in blobs.pairs:
    let cellsAndProofs = computeCellsAndKzgProofs(blob)
    if not cellsAndProofs.isOk:
      return err("Computing Extended Matrix: Issue computing cells and proofs")

    for i in 0..<eip7594.CELLS_PER_EXT_BLOB:
      extended_matrix.add(MatrixEntry(
        cell: cellsAndProofs.get.cells[i],
        kzg_proof: cellsAndProofs.get.proofs[i],
        row_index: blbIdx.uint64,
        column_index: i.uint64
      ))

  ok(extended_matrix)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/_features/eip7594/das-core.md#recover_matrix
proc recover_matrix*(partial_matrix: seq[MatrixEntry],
                     blobCount: int): 
                     Result[seq[MatrixEntry], cstring] =
  # This helper demonstrates how to apply recover_cells_and_kzg_proofs
  # The data structure for storing cells is implementation-dependent
  var extended_matrix: seq[MatrixEntry]
  for blob_index in 0..<blobCount:
    var
      cell_indices: seq[CellID]
      cells: seq[Cell]
  
    for e in partial_matrix:
      if e.row_index == uint64(blob_index):
        cell_indices.add(e.column_index)
        cells.add(e.cell)

    let recoveredCellsAndKzgProofs = 
      recoverCellsAndKzgProofs(cell_indices, cells)
    if not recoveredCellsAndKzgProofs.isOk:
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

# THIS METHOD IS DEPRECATED, WILL BE REMOVED ONCE ALPHA 4 IS RELEASED
proc recover_cells_and_proofs*(
    data_columns: seq[DataColumnSidecar],
    blck: deneb.SignedBeaconBlock |
    electra.SignedBeaconBlock |
    deneb.TrustedSignedBeaconBlock | 
    electra.TrustedSignedBeaconBlock |
    ForkedTrustedSignedBeaconBlock):
    Result[seq[CellsAndProofs], cstring] =

  # This helper recovers blobs from the data column sidecars
  if not (data_columns.len != 0):
    return err("DataColumnSidecar: Length should not be 0")

  var columnCount = data_columns.len
  var blobCount = data_columns[0].column.len
  for data_column in data_columns:
    if not (blobCount == data_column.column.len):
      return err ("DataColumns do not have the same length")

  var
    recovered_cps = newSeq[CellsAndProofs](blobCount)

  for blobIdx in 0..<blobCount:
    var
      bIdx = blobIdx
      cell_ids = newSeqOfCap[CellID](columnCount)
      ckzgCells = newSeqOfCap[KzgCell](columnCount)

    cell_ids.setLen(0)
    ckzgCells.setLen(0)

    for col in data_columns:
      cell_ids.add col.index

      let 
        column = col.column
        cell = column[bIdx]
      
      ckzgCells.add cell

    # Recovering the cells and proofs
    let recovered_cells_and_proofs = recoverCellsAndKzgProofs(cell_ids, ckzgCells)
    if not recovered_cells_and_proofs.isOk:
      return err("Issue with computing cells and proofs!")

    recovered_cps[bIdx] = recovered_cells_and_proofs.get

  ok(recovered_cps)

proc compute_signed_block_header(signed_block: deneb.TrustedSignedBeaconBlock |
                                 electra.TrustedSignedBeaconBlock): 
                                 SignedBeaconBlockHeader =
  let blck = signed_block.message
  let block_header = BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    state_root: blck.state_root,
    body_root: hash_tree_root(blck.body)
  )
  result = SignedBeaconBlockHeader(
    message: block_header,
    signature: signed_block.signature.toValidatorSig
  )

proc compute_signed_block_header(signed_block: deneb.SignedBeaconBlock | 
                                 electra.SignedBeaconBlock): 
                                 SignedBeaconBlockHeader =
  let blck = signed_block.message
  let block_header = BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    state_root: blck.state_root,
    body_root: hash_tree_root(blck.body)
  )
  result = SignedBeaconBlockHeader(
    message: block_header,
    signature: signed_block.signature
  )

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/_features/eip7594/das-core.md#get_data_column_sidecars
proc get_data_column_sidecars*(signed_beacon_block: deneb.TrustedSignedBeaconBlock |
                               electra.TrustedSignedBeaconBlock,
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
      newSeqOfCap[DataColumnSidecar](kzg_abi.CELLS_PER_EXT_BLOB)
    # Flattened the cells and proofs from the `CellsAndProofs` type to 
    # make it simpler to handle overall
    flattened_cells = 
      newSeq[CellBytes](cellsAndProofs.len)
    flattened_proofs =
      newSeq[ProofBytes](cellsAndProofs.len)


  for i in 0..<cellsAndProofs.len:
    flattened_cells[i] = cellsAndProofs[i].cells
    flattened_proofs[i] = cellsAndProofs[i].proofs

  for column_index in 0..<NUMBER_OF_COLUMNS:
    var
      column_cells: seq[KzgCell]
      column_proofs: seq[KzgProof]
    for row_index in 0..<cellsAndProofs.len:
      column_cells.add(flattened_cells[row_index][column_index])
      column_proofs.add(flattened_proofs[row_index][column_index])

    column_proofs.setLen(blck.body.blob_kzg_commitments.len)
    column_cells.setLen(blck.body.blob_kzg_commitments.len)

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

proc get_data_column_sidecars*(signed_beacon_block: deneb.SignedBeaconBlock |
                               electra.SignedBeaconBlock,
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
        signature: signed_beacon_block.signature)
  
  var
    sidecars =
      newSeqOfCap[DataColumnSidecar](kzg_abi.CELLS_PER_EXT_BLOB)
    # Flattened the cells and proofs from the `CellsAndProofs` type to 
    # make it simpler to handle overall
    flattened_cells = 
      newSeq[CellBytes](cellsAndProofs.len)
    flattened_proofs =
      newSeq[ProofBytes](cellsAndProofs.len)


  for i in 0..<cellsAndProofs.len:
    flattened_cells[i] = cellsAndProofs[i].cells
    flattened_proofs[i] = cellsAndProofs[i].proofs

  for column_index in 0..<NUMBER_OF_COLUMNS:
    var
      column_cells: seq[KzgCell]
      column_proofs: seq[KzgProof]
    for row_index in 0..<cellsAndProofs.len:
      column_cells.add(flattened_cells[row_index][column_index])
      column_proofs.add(flattened_proofs[row_index][column_index])

    column_proofs.setLen(blck.body.blob_kzg_commitments.len)
    column_cells.setLen(blck.body.blob_kzg_commitments.len)

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
proc get_data_column_sidecars*(signed_beacon_block: deneb.SignedBeaconBlock |
                               electra.SignedBeaconBlock,
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
      newSeqOfCap[DataColumnSidecar](eip7594.CELLS_PER_EXT_BLOB)
    cells = newSeq[CellBytes](blobs.len)
    proofs = newSeq[ProofBytes](blobs.len)

  for i in 0..<blobs.len:
    let
      cell_and_proof = computeCellsAndKzgProofs(blobs[i])
    if cell_and_proof.isErr():
      return err("EIP7549: Could not compute cells")

    cells[i] = cell_and_proof.get.cells
    proofs[i] = cell_and_proof.get.proofs

  for columnIndex in 0..<eip7594.CELLS_PER_EXT_BLOB:
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

# Helper function to `verifyCellKzgProofBatch` at https://github.com/ethereum/c-kzg-4844/blob/das/bindings/nim/kzg_ex.nim#L170
proc validate_data_column_sidecar*(
    expected_commitments: seq[KzgCommitment], 
    cellIndex: seq[CellIndex], 
    column: seq[Cell],
    proofs: seq[KzgProof]): Result[void, string] =
  let res = verifyCellKzgProofBatch(expected_commitments, cellIndex, column, proofs).valueOr:
    return err("DataColumnSidecar: Proof verification error: " & error())

  if not res:
    return err("DataColumnSidecar: Proof verification failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/p2p-interface.md#verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*(sidecar: DataColumnSidecar):
                                            Result[void, cstring] =
  ## Verify if the KZG Proofs consisting in the `DataColumnSidecar`
  ## is valid or not.
  
  if (sidecar.kzg_commitments.len == 0):
    return err("Kzg commitments length cannot be 0")

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
  var cellIndices = newSeqOfCap[CellIndex](sidecar.column.len)
  for _ in 0..<sidecar.column.len:
    cellIndices.add(CellIndex(sidecar.index))

  let res = 
    verifyCellKzgProofBatch(sidecar.kzg_commitments.asSeq,
                            cellIndices,
                            sidecar.column.asSeq,
                            sidecar.kzg_proofs.asSeq)

  if res.isErr():
    return err("DataColumnSidecar: validation failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/p2p-interface.md#verify_data_column_sidecar_inclusion_proof
func verify_data_column_sidecar_inclusion_proof*(sidecar: DataColumnSidecar): Result[void, string] =

  # Verify if the given KZG commitments are included in the beacon block
  let gindex = 27.GeneralizedIndex
  if not is_valid_merkle_branch(
    hash_tree_root(sidecar.kzg_commitments),
    sidecar.kzg_commitments_inclusion_proof,
    4.int,
    get_subtree_index(gindex),
    sidecar.signed_block_header.message.body_root):
    
    return err("DataColumnSidecar: inclusion proof not valid")

  ok()

proc selfReconstructDataColumns*(numCol: uint64):
                                 bool =
  # This function tells whether data columns can be 
  # reconstructed or not
  const totalColumns = NUMBER_OF_COLUMNS.uint64
  let 
    columnsNeeded = totalColumns div 2 + totalColumns mod 2
  if numCol >= columnsNeeded:
    return true
  false

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/_features/eip7594/das-core.md#compute_extended_matrix
proc get_extended_sample_count*(samples_per_slot: int,
                                allowed_failures: int):
                                int =
  # `get_extended_sample_count` computes the number of samples we
  # should query from peers, given the SAMPLES_PER_SLOT and 
  # the number of allowed failures

  # Retrieving the column count
  let columnsCount = NUMBER_OF_COLUMNS.int

  # If 50% of the columns are missing, we are able to reconstruct the data
  # If 50% + 1 columns are missing, we are NO MORE able to reconstruct the data
  let worstCaseConditionCount = (columnsCount div 2) + 1

  # Compute the false positive threshold
  let falsePositiveThreshold = hypergeom_cdf(0, columnsCount, worstCaseConditionCount, samples_per_slot)

  var sampleCount: int

  # Finally, compute the extended sample count
  for i in samples_per_slot .. columnsCount + 1:
    if hypergeom_cdf(allowed_failures, columnsCount, worstCaseConditionCount, i) <= falsePositiveThreshold:
      sampleCount = i
      break
    sampleCount = i
  
  return sampleCount

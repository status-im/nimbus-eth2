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


proc sortedColumnIndices*(columnsPerSubnet: ColumnIndex, subnetIds: HashSet[uint64]): seq[ColumnIndex] =
  var res: seq[ColumnIndex] = @[]
  for i in 0 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      result.add(ColumnIndex(index))
  res.sort()
  res

proc get_custody_column_subnet*(node_id: NodeId, custody_subnet_count: uint64): Result[HashSet[uint64], cstring] =
  # fetches the subnets for custody column for the current node
  # assert custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT
  if not (custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT):
    return err("Eip7594: Custody subnet count exceeds the DATA_COLUMN_SIDECAR_SUBNET_COUNT")

  var 
    subnet_ids: HashSet[uint64]
    current_id = node_id

  while subnet_ids.len < int(custody_subnet_count):

    var subnet_id_bytes: array[8, byte]
    subnet_id_bytes[0..7] = current_id.toBytesLE().toOpenArray(0,7)

    var subnet_id = bytes_to_uint64(subnet_id_bytes) mod 
        DATA_COLUMN_SIDECAR_SUBNET_COUNT
    
    if subnet_id notin subnet_ids:
        subnet_ids.incl(subnet_id)

    if current_id == UInt256.high.NodeId:
        # Overflow prevention
        current_id = NodeId(StUint[256].zero)
    current_id += NodeId(StUint[256].one)

  # assert len(subnet_ids) == len(set(subnet_ids))
  if not (subnet_ids.len == subnet_ids.len):
    return err("Eip7594: Subnet ids are not unique")

  ok(subnet_ids)

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#get_custody_columns
proc get_custody_columns*(node_id: NodeId, custody_subnet_count: uint64): Result[seq[ColumnIndex], cstring] =
    
  let subnet_ids = get_custody_column_subnet(node_id, custody_subnet_count).get

  # columns_per_subnet = NUMBER_OF_COLUMNS // DATA_COLUMN_SIDECAR_SUBNET_COUNT
  let columns_per_subnet = NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  ok(sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids))

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#compute_extended_matrix
proc compute_extended_matrix* (blobs: seq[KzgBlob]): Result[ExtendedMatrix, cstring] =
  # This helper demonstrates the relationship between blobs and `ExtendedMatrix`
  var extended_matrix: ExtendedMatrix
  for i in 0..<blobs.len:
    debugEcho "Checkpoint 1"
    let res = computeCells(blobs[i])
    debugEcho "Checkpoint 2"
    if res.isErr:
        return err("Error computing kzg cells and kzg proofs")
    debugEcho "Checkpoint 3"
    discard extended_matrix.add(res.get())
    debugEcho "Checkpoint 4"
  ok(extended_matrix)

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#recover_matrix    
proc recover_matrix*(cells_dict: Table[(BlobIndex, CellID), Cell], blobCount: uint64): Result[ExtendedMatrix, cstring] =
  # This helper demonstrates how to apply recover_all_cells
  # The data structure for storing cells is implementation-dependent

  var extended_matrix: ExtendedMatrix

  for blobIndex in 0'u64..<blobCount:
    var 
      cellIds: seq[CellID] = @[]
      blIdx: BlobIndex
      cellId: CellID
    let key = (blIdx, cellId)

    for key, cell in pairs(cells_dict):
      if blIdx == blobIndex:
        cellIds.add(cellId)

    var cells: seq[Cell]
    for cellId in cellIds:
      var interim_key = (BlobIndex(blobIndex), cellId)
      
      if cells_dict.hasKey(interim_key):
        try:
          let cell = cells_dict[interim_key]
          cells.add(cell)
        except:
          debug "DataColumn: Key not found in Cell Dictionary", interim_key

    let allCellsForRow = recoverAllCells(cellIds, cells)
    let check = extended_matrix.add(allCellsForRow.get())
    doAssert check == true, "DataColumn: Could not add cells to the extended matrix"

  ok(extended_matrix)

proc recover_matrix*(partial_matrix: seq[MatrixEntry], blobCount: int): Result[seq[MatrixEntry], cstring] =
  # This helper demonstrates how to apply recover_cells_and_kzg_proofs
  # The data structure for storing cells is implementation-dependent

  var extended_matrix: seq[MatrixEntry]
  for blob_index in 0..<blobCount:
    var
      cell_indices: seq[CellID]
      cells: seq[Cell]
      proofs: seq[KzgProof]
  
    for e in partial_matrix:
      if e.row_index == uint64(blob_index):
        cell_indices.add(e.column_index)
        cells.add(e.cell)
        proofs.add(e.kzg_proof)

proc recover_blobs*(
    data_columns: seq[DataColumnSidecar],
    columnCount: int,
    blck: deneb.SignedBeaconBlock | 
    electra.SignedBeaconBlock |
    ForkySignedBeaconBlock):
    Result[seq[KzgBlob], cstring] =

  # This helper recovers blobs from the data column sidecars
  if not (data_columns.len != 0):
    return err("DataColumnSidecar: Length should not be 0")

  var blobCount = data_columns[0].column.len
  for data_column in data_columns:
    if not (blobCount == data_column.column.len):
      return err ("DataColumns do not have the same length")

  var recovered_blobs = newSeqOfCap[KzgBlob](blobCount)

  for blobIdx in 0 ..< blobCount:
    var
      cell_ids = newSeqOfCap[CellID](columnCount)
      ckzgCells = newSeqOfCap[KzgCell](columnCount)

    for data_column in data_columns:
      cell_ids.add(data_column.index)

      let 
        column = data_column.column
        cell = column[blobIdx]

      # Transform the cell as a ckzg cell
      var ckzgCell: Cell
      for i in 0 ..< int(FIELD_ELEMENTS_PER_CELL):
        var start = 32 * i
        for j in 0 ..< 32:
          ckzgCell[start + j] = cell[start+j]

      ckzgCells.add(ckzgCell)

    # Recovering the blob
    let recovered_cells = recoverAllCells(cell_ids, ckzgCells)
    if not recovered_cells.isOk:
      return err ("Recovering all cells for blob failed")

    let recovered_blob_res = cellsToBlob(recovered_cells.get)
    if not recovered_blob_res.isOk:
      return err ("Cells to blob for blob failed")

    recovered_blobs.add(recovered_blob_res.get)

  ok(recovered_blobs)

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

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#get_data_column_sidecars
proc get_data_column_sidecars*(signed_block: deneb.SignedBeaconBlock |
                               electra.SignedBeaconBlock, 
                               blobs: seq[KzgBlob]): 
                               Result[seq[DataColumnSidecar], cstring] =

  var 
    sidecar: DataColumnSidecar
    blck = signed_block.message
    signed_beacon_block_header = compute_signed_block_header(signed_block)
    cellsAndProofs: seq[KzgCellsAndKzgProofs]
    kzg_incl_proof: array[4, Eth2Digest]

  blck.body.build_proof(
    27.GeneralizedIndex,
    kzg_incl_proof).expect("Valid gindex")
  
  for blob in blobs:
    let
      computed_cell = computeCellsAndProofs(blob)

    if computed_cell.isErr():
      return err("EIP7549: Could not compute cells")

    cellsAndProofs.add(computed_cell.get())

  let blobCount = blobs.len
  var
    cells: seq[seq[Cell]]
    proofs: seq[seq[KzgProof]]

  for i in 0..<blobCount:
    for j in 0..<int(CELLS_PER_EXT_BLOB):
      cells[i].add(cellsAndProofs[i].cells[j])

  for i in 0..<blobCount:
    for j in 0..<int(MAX_BLOB_COMMITMENTS_PER_BLOCK):
      proofs[i].add(cellsAndProofs[i].proofs[j])

  var sidecars: seq[DataColumnSidecar]

  for columnIndex in 0..<NUMBER_OF_COLUMNS:
    var column: DataColumn
    for rowIndex in 0..<blobCount:
      column[rowIndex] = cells[rowIndex][columnIndex]

    var kzgProofOfColumn: KzgProofs
    for rowIndex in 0..<blobCount:
      kzgProofOfColumn[rowIndex] = proofs[rowIndex][columnIndex]

    sidecar = DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: column,
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: kzgProofOfColumn,
      signed_block_header: signed_beacon_block_header,
      kzg_commitments_inclusion_proof: kzg_incl_proof
    )
    sidecars.add(sidecar)

  ok(sidecars)

# Helper function to `verifyCellKzgProofBatch` at https://github.com/ethereum/c-kzg-4844/blob/das/bindings/nim/kzg_ex.nim#L170
proc validate_data_column_sidecar*(
    expected_commitments: seq[KzgCommitment], 
    rowIndex: seq[RowIndex], 
    columnIndex: seq[ColumnIndex], 
    column: seq[Cell],
    proofs: seq[KzgProof]): Result[void, string] =
  let res = verifyCellKzgProofBatch(expected_commitments, rowIndex, columnIndex, column, proofs).valueOr:
    return err("DataColumnSidecar: Proof verification error: " & error())

  if not res:
    return err("DataColumnSidecar: Proof verification failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/p2p-interface.md#verify_data_column_sidecar_kzg_proofs
proc verify_data_column_sidecar_kzg_proofs*(sidecar: DataColumnSidecar): Result[void, string] =
  # Verifying if the KZG proofs are correct

  # Check if the data column sidecar index < NUMBER_OF_COLUMNS
  if not (sidecar.index < NUMBER_OF_COLUMNS):
    return err("EIP7594: Data column sidecar index exceeds the NUMBER_OF_COLUMNS")

  # Check is the sidecar column length == sidecar.kzg_commitments length == sidecar.kzg_proofs mixInLength
  if not (sidecar.column.len == sidecar.kzg_commitments.len):
    return err("EIP7594: Data column sidecar length is not equal to the kzg_commitments length")

  if not (sidecar.kzg_commitments.len == sidecar.kzg_proofs.len):
    return err("EIP7594: Data column sidecar kzg_commitments length is not equal to the kzg_proofs length")

  # Iterate through the row indices
  var rowIndices: seq[RowIndex]
  for i in 0..<sidecar.column.len:
    rowIndices.add(RowIndex(i))

  # Iterate through the column indices
  var colIndices: seq[ColumnIndex]
  for _ in 0..<sidecar.column.len:
    colIndices.add(sidecar.index * sidecar.column.lenu64)

  let 
    kzgCommits = sidecar.kzg_commitments.asSeq
    sidecarCol = sidecar.column.asSeq
    kzgProofs = sidecar.kzg_proofs.asSeq

  let res = validate_data_column_sidecar(kzgCommits, rowIndices, colIndices, sidecarCol, kzgProofs)

  if res.isErr():
    return err("DataColumnSidecar: validation failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/p2p-interface.md#verify_data_column_sidecar_inclusion_proof
proc verify_data_column_sidecar_inclusion_proof*(sidecar: DataColumnSidecar): Result[void, string] =
  # Verify if the given KZG commitments are included in the beacon block
  let gindex = 27.GeneralizedIndex
  if not is_valid_merkle_branch(
    hash_tree_root(sidecar.kzg_commitments),
    sidecar.kzg_commitments_inclusion_proof,
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
    get_subtree_index(gindex),
    sidecar.signed_block_header.message.body_root):
    
    return err("DataColumnSidecar: inclusion proof not valid")

  ok()

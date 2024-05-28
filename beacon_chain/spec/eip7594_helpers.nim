# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec

import
  tables,
  algorithm,
  std/macros,
  results,
  stew/assign2,
  nim-ssz-serialization/ssz_serialization/proofs,
  chronicles,
  std/sequtils,
  ./[beacon_time, crypto],
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

proc get_custody_columns*(node_id: NodeId, custody_subnet_count: uint64): Result[seq[ColumnIndex], cstring] =
    
  # assert custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT
  if not (custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT):
    return err("Eip7594: Custody subnet count exceeds the DATA_COLUMN_SIDECAR_SUBNET_COUNT")

  var subnet_ids: HashSet[uint64]
  var current_id = node_id

  while subnet_ids.len < int(custody_subnet_count):
  
    # var subnet_id_bytes: seq[byte]
    let subnet_id_bytes = eth2digest(current_id.toBytesLE().toOpenArray(0,8))
    var subnet_id = bytes_to_uint64(subnet_id_bytes.data) mod DATA_COLUMN_SIDECAR_SUBNET_COUNT
    
    if subnet_id notin subnet_ids:
        subnet_ids.incl(subnet_id)

    if current_id == UInt256.high.NodeId:
        # Overflow prevention
        current_id = NodeId(StUint[256].zero)
    current_id += NodeId(StUint[256].one)

  # assert len(subnet_ids) == len(set(subnet_ids))
  if not (subnet_ids.len == subnet_ids.len):
    return err("Eip7594: Subnet ids are not unique")

  # columns_per_subnet = NUMBER_OF_COLUMNS // DATA_COLUMN_SIDECAR_SUBNET_COUNT
  let columns_per_subnet = NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  ok(sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids))


# #### `compute_extended_matrix`

proc compute_extended_matrix* (blobs: seq[KzgBlob]): Result[ExtendedMatrix, cstring] =
  # This helper demonstrates the relationship between blobs and `ExtendedMatrix`
  var extended_matrix: ExtendedMatrix
  for blob in blobs:
    let computed_cell = computeCellsAndKzgProofs(blob)
    discard extended_matrix.add(computed_cell)
  ok(extended_matrix)
    
proc recover_matrix*(cells_dict: Table[(BlobIndex, CellID), Cell], blobCount: uint64): Result[ExtendedMatrix, cstring] =
  # This helper demonstrates how to apply recover_all_cells
  # The data structure for storing cells is implementation-dependent

  var extended_matrix: ExtendedMatrix

  for blobIndex in 0'u64..<blobCount:
    var cellIds: seq[CellID] = @[]
    var blIdx: BlobIndex
    var cellId: CellID
    let key = (blIdx, cellId)

    for key, cell in pairs(cells_dict):
      if blIdx == blobIndex:
        cellIds.add(cellId)

    var cells: seq[Cell] = @[]
    for cellId in cellIds:
      var interim_key = (BlobIndex(blobIndex), cellId)
      
      if cells_dict.hasKey(interim_key):
        try:
          let cell = cells_dict[interim_key]
          cells.add(cell)
        except:
          debug "DataColumn: Key not found in Cell Dictionary", interim_key
    var allCellsForRow: Cells 
    allCellsForRow = recoverAllCells(cellIds, cells)
    discard extended_matrix.add(allCellsForRow) 

  ok(extended_matrix)

proc get_data_column_sidecars*(signed_block: deneb.SignedBeaconBlock, blobs: seq[KzgBlob]): Result[seq[DataColumnSidecar]] =

# #### `get_data_column_sidecars`

  var signed_block_header: deneb.SignedBeaconBlockHeader
  var blck = signed_block.message
  let 
    kzgCommitmentInclusionProof = build_proof(blck.body, 32'u64)

  if kzgCommitmentInclusionProof.isErr():
    fatal "EIP7549: Could not compute Merkle proof"

  var cellsAndProofs: seq[CellsAndProofs]

  for blob in blobs:
    let
      computed_cell = computeCellsAndKzgProofs(blob)

    if computed_cell.isErr():
      fatal "EIP7549: Could not compute cells"

    cellsAndProofs.add(computed_cell)

  let blobCount = blobs.len
  var cells: seq[seq[Cell]] = @[]
  var proofs: seq[seq[KzgProof]] = @[]

  for i in 0..<blobCount:
    cells.add(cellsAndProofs.cells)
    proofs.add(cellsAndProofs.proofs)

  var sidecars: seq[DataColumnSidecar] = @[]

  for columnIndex in 0..<NUMBER_OF_COLUMNS:
    var column: DataColumn
    var cellsForColumn: seq[Cell] = @[]
    for rowIndex in 0..<blobCount:
      cellsForColumn.add(cells[rowIndex][columnIndex])
    column = DataColumn(cellsForColumn)

    var kzgProofOfColumn: seq[KzgProof] = @[]
    for rowIndex in 0..<blobCount:
      kzgProofOfColumn.add(proofs[rowIndex][columnIndex])

    var sidecar = DataColumnSidecar(
      index: columnIndex,
      column: column,
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: kzgProofOfColumn,
      signed_block_header: signed_block_header,
      kzg_commitments_inclusion_proof: kzgCommitmentInclusionProof
    )
    sidecars.add(sidecar)

  ok(sidecars)


proc verify_data_column_sidecar_kzg_proofs* (sidecar: DataColumnSidecar): Result[bool, cstring] =
  # Verifying if the KZG proofs are correct

  # Check if the data column sidecar index < NUMBER_OF_COLUMNS
  if not (sidecar.index < NUMBER_OF_COLUMNS):
    return err("EIP7549: Data column sidecar index exceeds the NUMBER_OF_COLUMNS")

  # Check is the sidecar column length == sidecar.kzg_commitments length == sidecar.kzg_proofs mixInLength
  if not (sidecar.column.len == sidecar.kzg_commitments.len and sidecar.kzg_commitments.len == sidecar.kzg_proofs.len):
    return err("EIP7549: Data column sidecar column length does not match the kzg_commitments length or kzg_proofs length")

  # Iterate through the row indices
  var rowIndices: seq[RowIndex] = @[]
  for i in 0..<sidecar.column.len:
    rowIndices.add(RowIndex(i))

  # Iterate through the column indices
  var colIndices: seq[ColumnIndex] = @[]
  for i in 0..<sidecar.column.len:
    colIndices.add(ColumnIndex(i))

  # KZG batch verifies that the cells match the corresponding commitments and KZG proofs
  var res = verifyCellKzgProofBatch(
    sidecar.kzg_commitments,
    rowIndices,
    colIndices,
    sidecar.column,
    sidecar.kzg_proofs
  )
  
  ok(res)
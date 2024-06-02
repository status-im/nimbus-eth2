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
  ssz_serialization/proofs,
  chronicles,
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

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#get_custody_columns
proc get_custody_columns*(node_id: NodeId, custody_subnet_count: uint64): Result[seq[ColumnIndex], cstring] =
    
  # assert custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT
  if not (custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT):
    return err("Eip7594: Custody subnet count exceeds the DATA_COLUMN_SIDECAR_SUBNET_COUNT")

  var 
    subnet_ids: HashSet[uint64]
    current_id = node_id

  while subnet_ids.len < int(custody_subnet_count):
    let subnet_id_bytes = eth2digest(current_id.toBytesLE().toOpenArray(0,8))
    var subnet_id = bytes_to_uint64(subnet_id_bytes.data) mod 
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

  # columns_per_subnet = NUMBER_OF_COLUMNS // DATA_COLUMN_SIDECAR_SUBNET_COUNT
  let columns_per_subnet = NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  ok(sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids))

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#compute_extended_matrix
proc compute_extended_matrix* (blobs: seq[KzgBlob]): Result[ExtendedMatrix, cstring] =
  # This helper demonstrates the relationship between blobs and `ExtendedMatrix`
  var extended_matrix: ExtendedMatrix
  for blob in blobs:
    let res = computeCells(blob)

    if res.isErr:
        return err("Error computing kzg cells and kzg proofs")

    discard extended_matrix.add(res.get())

  ok(extended_matrix)

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#recover_matrix    
proc recover_matrix*(cells_dict: Table[(BlobIndex, CellID), KzgCell], blobCount: uint64): Result[ExtendedMatrix, cstring] =
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

    var cells: seq[KzgCell]
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

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#get_data_column_sidecars
proc get_data_column_sidecars*(signed_block: deneb.SignedBeaconBlock, blobs: seq[KzgBlob]): Result[seq[DataColumnSidecar], cstring] =
  var sidecar: DataColumnSidecar
  var signed_block_header: deneb.SignedBeaconBlockHeader
  var blck = signed_block.message

  var cellsAndProofs: seq[KzgCellsAndKzgProofs] = @[]

  for blob in blobs:
    let
      computed_cell = computeCellsAndKzgProofs(blob)

    if computed_cell.isErr():
      fatal "EIP7549: Could not compute cells"

    cellsAndProofs.add(computed_cell.get())

  let blobCount = blobs.len
  var
    cells: seq[seq[KzgCell]]
    proofs: seq[seq[KzgProof]]

  for i in 0..<blobCount:
    cells[i].add(cellsAndProofs[i].cells[0])
    proofs[i].add(cellsAndProofs[i].proofs[1])

  var sidecars: seq[DataColumnSidecar] = @[]

  for columnIndex in 0..<NUMBER_OF_COLUMNS:
    var column: DataColumn
    for rowIndex in 0..<blobCount:
      column[rowIndex] = cells[rowIndex][columnIndex]

    var kzgProofOfColumn: List[KzgProof, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
    for rowIndex in 0..<blobCount:
      kzgProofOfColumn[rowIndex] = proofs[rowIndex][columnIndex]

    sidecar = DataColumnSidecar(
      index: uint64(columnIndex),
      column: column,
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: kzgProofOfColumn,
      signed_block_header: signed_block_header
    )
    blck.body.build_proof(
      kzg_commitment_inclusion_proof_gindex(BlobIndex(columnIndex)),
      sidecar.kzg_commitments_inclusion_proof).expect("Valid gindex")
    sidecars.add(sidecar)

  ok(sidecars)

# Helper function to `verifyCellKzgProofBatch` at https://github.com/ethereum/c-kzg-4844/blob/das/bindings/nim/kzg_ex.nim#L170
proc validate_data_column_sidecar*(
    expected_commitments: seq[KzgCommitment], rowIndex: seq[RowIndex], columnIndex: seq[ColumnIndex], column: seq[KzgCell],
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

  # KZG batch verifies that the cells match the corresponding commitments and KZG proofs
  let res = validate_data_column_sidecar(
    kzgCommits,
    rowIndices,
    colIndices,
    sidecarCol,
    kzgProofs)

  if res.isErr():
    return err("DataColumnSidecar: validation failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/p2p-interface.md#verify_data_column_sidecar_inclusion_proof
proc verify_data_column_sidecar_inclusion_proof*(sidecar: DataColumnSidecar): Result[void, string] =
  # Verify if the given KZG commitments are included in the beacon block
  let gindex = kzg_commitment_inclusion_proof_gindex(sidecar.index)
  if not is_valid_merkle_branch(
    hash_tree_root(sidecar.kzg_commitments),
    sidecar.kzg_commitments_inclusion_proof,
    KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
    get_subtree_index(gindex),
    sidecar.signed_block_header.message.body_root):
    
    return err("DataColumnSidecar: inclusion proof not valid")

  ok()

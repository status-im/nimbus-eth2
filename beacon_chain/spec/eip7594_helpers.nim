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

proc sortedColumnIndices*(columnsPerSubnet: ColumnIndex, subnetIds: HashSet[uint64]): seq[ColumnIndex] =
  var res: seq[ColumnIndex] = @[]
  for i in 0 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort()
  res

proc sortedColumnIndexList*(columnsPerSubnet: ColumnIndex, 
                          subnetIds: HashSet[uint64]): 
                          List[ColumnIndex, NUMBER_OF_COLUMNS] =
  var
    res: seq[ColumnIndex]
    list: List[ColumnIndex, NUMBER_OF_COLUMNS]
  for i in 0 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      res.add(ColumnIndex(index))
  res.sort()
  for elem in res:
    discard list.add(ColumnIndex(elem))
  list

proc get_custody_column_subnet*(node_id: NodeId, 
                                custody_subnet_count: uint64): 
                                Result[HashSet[uint64], cstring] =
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
proc get_custody_columns*(node_id: NodeId, 
                          custody_subnet_count: uint64): 
                          Result[seq[ColumnIndex], cstring] =
    
  let subnet_ids = get_custody_column_subnet(node_id, custody_subnet_count).get

  # columns_per_subnet = NUMBER_OF_COLUMNS // DATA_COLUMN_SIDECAR_SUBNET_COUNT
  let columns_per_subnet = NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  ok(sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids))

proc get_custody_column_list*(node_id: NodeId, 
                          custody_subnet_count: uint64): 
                          Result[List[ColumnIndex, NUMBER_OF_COLUMNS], cstring] =
    
  let subnet_ids = get_custody_column_subnet(node_id, custody_subnet_count).get

  # columns_per_subnet = NUMBER_OF_COLUMNS // DATA_COLUMN_SIDECAR_SUBNET_COUNT
  let columns_per_subnet = NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
  
  ok(sortedColumnIndexList(ColumnIndex(columns_per_subnet), subnet_ids))

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
    columnCount: int,
    blck: deneb.TrustedSignedBeaconBlock | 
    electra.TrustedSignedBeaconBlock |
    ForkedTrustedSignedBeaconBlock):
    Result[seq[CellsAndProofs], cstring] =

  # This helper recovers blobs from the data column sidecars
  if not (data_columns.len != 0):
    return err("DataColumnSidecar: Length should not be 0")

  var blobCount = data_columns[0].column.len
  for data_column in data_columns:
    if not (blobCount == data_column.column.len):
      return err ("DataColumns do not have the same length")

  var
    recovered_cps = newSeq[CellsAndProofs](blobCount)

  for blobIdx in 0 ..< blobCount:
    var
      bIdx = blobIdx
      cell_ids = newSeq[CellID](columnCount)
      ckzgCells = newSeq[KzgCell](columnCount)

    for i  in 0..<data_columns.len:
      cell_ids[i] = data_columns[i].index

      let 
        column = data_columns[i].column
        cell = column[bIdx]
      
      ckzgCells[i] = cell

    # Recovering the cells and proofs
    let recovered_cells_and_proofs = recoverCellsAndKzgProofs(cell_ids, ckzgCells)
    if not recovered_cells_and_proofs.isOk:
      return err("Issue with computing cells and proofs!")

    recovered_cps[blobIdx] = recovered_cells_and_proofs.get

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

# https://github.com/ethereum/consensus-specs/blob/bb8f3caafc92590cdcf2d14974adb602db9b5ca3/specs/_features/eip7594/das-core.md#get_data_column_sidecars
proc get_data_column_sidecars*(signed_block: deneb.TrustedSignedBeaconBlock |
                               electra.TrustedSignedBeaconBlock,
                               cellsAndProofs: seq[CellsAndProofs]):
                               Result[seq[DataColumnSidecar], string] =
  # Given a signed block and the cells/proofs associated with each blob
  # in the block, assemble the sidecars which can be distributed to peers.
  var
    blck = signed_block.message
    signed_beacon_block_header = 
      compute_signed_block_header(signed_block)
    kzg_incl_proof: array[4, Eth2Digest]

  var sidecars = newSeq[DataColumnSidecar](CELLS_PER_EXT_BLOB)

  if cellsAndProofs.len == 0:
    return ok(sidecars)

  for column_index in 0..<NUMBER_OF_COLUMNS:
    var
      column_cells: DataColumn
      column_proofs: KzgProofs
    for i in 0..<cellsAndProofs.len:
      let check1 = column_cells.add(cellsAndProofs[i].cells)
      if not check1: debug "Issue fetching cell from CellsAndProofs"
      let check2 = column_proofs.add(cellsAndProofs[i].proofs)
      if not check2: debug "Issue fetching proof from CellsAndProofs"

    var sidecar = DataColumnSidecar(
      index: ColumnIndex(column_index),
      column: DataColumn(column_cells),
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: KzgProofs(column_proofs),
      signed_block_header: signed_beacon_block_header)
    blck.body.build_proof(
      27.GeneralizedIndex,
      sidecar.kzg_commitments_inclusion_proof).expect("Valid gindex")
    sidecars.add(sidecar)

  ok(sidecars)

# https://github.com/ethereum/consensus-specs/blob/5f48840f4d768bf0e0a8156a3ed06ec333589007/specs/_features/eip7594/das-core.md#get_data_column_sidecars
proc get_data_column_sidecars*(signed_block: deneb.SignedBeaconBlock |
                               electra.SignedBeaconBlock, 
                               blobs: seq[KzgBlob]): 
                               Result[seq[DataColumnSidecar], string] =
  var
    blck = signed_block.message
    signed_beacon_block_header = compute_signed_block_header(signed_block)
    kzg_incl_proof: array[4, Eth2Digest]
  
  var sidecars = newSeq[DataColumnSidecar](CELLS_PER_EXT_BLOB)

  if blobs.len == 0:
    return ok(sidecars)

  var
    cells = newSeq[CellBytes](blobs.len)
    proofs = newSeq[ProofBytes](blobs.len)

  for i in 0..<blobs.len:
    let
      cell_and_proof = computeCellsAndProofs(blobs[i])
    if cell_and_proof.isErr():
      return err("EIP7549: Could not compute cells")

    cells[i] = cell_and_proof.get.cells
    proofs[i] = cell_and_proof.get.proofs
  
  let blobCount = blobs.len

  for columnIndex in 0..<CELLS_PER_EXT_BLOB:
    var 
      column: DataColumn
      kzgProofOfColumn: KzgProofs
    for rowIndex in 0..<blobCount:
      discard column.add(cells[rowIndex][columnIndex])

    for rowIndex in 0..<blobCount:
      discard kzgProofOfColumn.add(proofs[rowIndex][columnIndex])

    var sidecar = DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: DataColumn(column),
      kzgCommitments: blck.body.blob_kzg_commitments,
      kzgProofs: KzgProofs(kzgProofOfColumn),
      signed_block_header: signed_beacon_block_header)
    blck.body.build_proof(
      27.GeneralizedIndex,
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

  # Iterate through the cell indices
  var cellIndices: seq[CellIndex]
  for _ in 0..<sidecar.column.len:
    cellIndices.add(sidecar.index * sidecar.column.lenu64)

  let 
    kzgCommits = sidecar.kzg_commitments.asSeq
    sidecarCol = sidecar.column.asSeq
    kzgProofs = sidecar.kzg_proofs.asSeq

  let res = validate_data_column_sidecar(kzgCommits, cellIndices, sidecarCol, kzgProofs)

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

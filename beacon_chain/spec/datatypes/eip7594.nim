# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import "."/[base, deneb], kzg4844

from std/sequtils import mapIt
from std/strutils import join

export base

const
  FIELD_ELEMENTS_PER_EXT_BLOB* = 2 * kzg_abi.FIELD_ELEMENTS_PER_BLOB
    # Number of field elements in a Reed-Solomon extended blob |
  FIELD_ELEMENTS_PER_CELL* = 64 # Number of field elements in a cell |
  BYTES_PER_CELL* = FIELD_ELEMENTS_PER_CELL * kzg_abi.BYTES_PER_FIELD_ELEMENT
    # The number of bytes in a cell |
  CELLS_PER_EXT_BLOB* = FIELD_ELEMENTS_PER_EXT_BLOB div FIELD_ELEMENTS_PER_CELL
    # The number of cells in an extended blob |
  # RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN = 'RCKZGCBATCH__V1_'
  KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = 4 # TODO dedupe vs network

type
  BLSFieldElement* = KzgBytes32
  G2Point* = array[96, byte]
  PolynomialCoeff* = List[BLSFieldElement, FIELD_ELEMENTS_PER_EXT_BLOB]
  Coset* = array[FIELD_ELEMENTS_PER_CELL, BLSFieldElement]
  CosetEvals* = array[FIELD_ELEMENTS_PER_CELL, BLSFieldElement]
  Cell* = KzgCell
  Cells* = KzgCells
  CellsAndProofs* = KzgCellsAndKzgProofs
  CellID* = uint64
  RowIndex* = uint64
  ColumnIndex* = uint64

const
  NUMBER_OF_COLUMNS* = 128
  MAX_CELLS_IN_EXTENDED_MATRIX* = MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS

  DATA_COLUMN_SIDECAR_SUBNET_COUNT* = 64
  SAMPLES_PER_SLOT* = 16
  CUSTODY_REQUIREMENT* = 4
  TARGET_NUMBER_OF_PEERS* = 70

type
  DataColumn* = List[KzgCell, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
  ExtendedMatrix* = List[KzgCell, Limit(MAX_CELLS_IN_EXTENDED_MATRIX)]

  DataColumnSidecar* = object
    index*: ColumnIndex # Index of column in extended matrix
    column*: DataColumn
    kzg_commitments*: KzgCommitments
    kzg_proofs*: KzgProofs
    signed_block_header*: SignedBeaconBlockHeader
    kzg_commitments_inclusion_proof*:
      array[KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, Eth2Digest]

  DataColumnSidecars* = seq[ref DataColumnSidecar]

  DataColumnIdentifier* = object 
    block_root*: Eth2Digest
    index*: ColumnIndex

  MatrixEntry* = object
    cell*: Cell
    kzg_proof*: KzgProof
    column_index*: ColumnIndex
    row_index*: RowIndex
    
func shortLog*(v: DataColumnSidecar): auto =
  (
    index: v.index,
    column: v.column,
    kzg_commitments: v.kzg_commitments.len,
    kzg_proofs: v.kzg_proofs.len,
    block_header: shortLog(v.signed_block_header.message),
  )

func shortLog*(v: seq[DataColumnSidecar]): auto =
  "[" & v.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[DataColumnIdentifier]): string =
  "[" & x.mapIt(shortLog(it.block_root) & "/" & $it.index).join(", ") & "]"
# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sequtils],
  "."/[altair, base, deneb], 
  kzg4844/[kzg, kzg_abi]

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

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/p2p-interface.md#preset
  KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH* = 4

type
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/polynomial-commitments-sampling.md#custom-types 
  BLSFieldElement* = KzgBytes32
  G2Point* = array[96, byte]
  PolynomialCoeff* = List[BLSFieldElement, FIELD_ELEMENTS_PER_EXT_BLOB]
  Coset* = array[FIELD_ELEMENTS_PER_CELL, BLSFieldElement]
  CosetEvals* = array[FIELD_ELEMENTS_PER_CELL, BLSFieldElement]
  Cell* = KzgCell
  Cells* = KzgCells
  CellsAndProofs* = KzgCellsAndKzgProofs

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#custom-types
  RowIndex* = uint64
  ColumnIndex* = uint64
  CellIndex* = uint64

const
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#data-size
  NUMBER_OF_COLUMNS* = 128

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#networking
  DATA_COLUMN_SIDECAR_SUBNET_COUNT* = 128

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#custody-setting
  SAMPLES_PER_SLOT* = 8
  CUSTODY_REQUIREMENT* = 4

type
  DataColumn* = List[KzgCell, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#datacolumnsidecar
  DataColumnSidecar* = object
    index*: ColumnIndex # Index of column in extended matrix
    column*: DataColumn
    kzg_commitments*: KzgCommitments
    kzg_proofs*: KzgProofs
    signed_block_header*: SignedBeaconBlockHeader
    kzg_commitments_inclusion_proof*:
      array[KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, Eth2Digest]

  DataColumnSidecars* = seq[ref DataColumnSidecar]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/p2p-interface.md#datacolumnidentifier
  DataColumnIdentifier* = object
    block_root*: Eth2Digest
    index*: ColumnIndex

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/das-core.md#matrixentry
  MatrixEntry* = object
    cell*: Cell
    kzg_proof*: KzgProof
    column_index*: ColumnIndex
    row_index*: RowIndex
  
  # Not in spec, defined in order to compute custody subnets
  CscBits* = BitArray[DATA_COLUMN_SIDECAR_SUBNET_COUNT]

  CscCount* = uint8

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7594/p2p-interface.md#metadata
  MetaData* = object
    seq_number*: uint64
    attnets*: AttnetBits
    syncnets*: SyncnetBits
    custody_subnet_count*: CscCount 

func shortLog*(v: DataColumnSidecar): auto =
  (
    index: v.index,
    kzg_commitments: v.kzg_commitments.len,
    kzg_proofs: v.kzg_proofs.len,
    block_header: shortLog(v.signed_block_header.message),
  )

func shortLog*(v: seq[DataColumnSidecar]): auto =
  "[" & v.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[DataColumnIdentifier]): string =
  "[" & x.mapIt(shortLog(it.block_root) & "/" & $it.index).join(", ") & "]"

import "."/[base, deneb], kzg4844

export base, kzg4844

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
  DataColumn* = List[Cell, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
  ExtendedMatrix* = List[Cell, Limit(MAX_CELLS_IN_EXTENDED_MATRIX)]

  DataColumnSidecar* = object
    index*: ColumnIndex # Index of column in extended matrix
    column*: DataColumn
    kzg_commitments*: List[KzgCommitment, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
    kzg_proofs*: List[KzgProof, Limit(MAX_BLOB_COMMITMENTS_PER_BLOCK)]
    signed_block_header*: SignedBeaconBlockHeader
    kzg_commitments_inclusion_proof*:
      array[KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH, KzgBytes32]

func shortLog*(v: DataColumnSidecar): auto =
  (
    index: v.index,
    column: v.column,
    kzg_commitments: v.kzg_commitments.len,
    kzg_proofs: v.kzg_proofs.len,
    block_header: shortLog(v.signed_block_header.message),
  )
# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ./eth2_ssz_serialization,
  ./datatypes/[bellatrix, capella, deneb, gloas]

from ./datatypes/fulu import BYTES_PER_CELL

export eth2_ssz_serialization

const
  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#max_-constants
  MAX_EXECUTION_REQUESTS_PER_PAYLOAD* = 1 shl 8
  MAX_BYTES_PER_EXECUTION_REQUEST* = 1 shl 30
  MAX_BLOBS_REQUEST* = 128
  MAX_ERROR_BYTES* = 1024

type
  EngineFork* {.pure.} = enum
    Paris = "paris"
    Shanghai = "shanghai"
    Cancun = "cancun"
    Prague = "prague"
    Osaka = "osaka"
    Amsterdam = "amsterdam"

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#engine-api-v2----ssz-container-sketches-amsterdam
  Optional*[T] = List[T, 1]

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#engine-api-v2----ssz-container-sketches-amsterdam
  EngineString* = List[byte, Limit MAX_ERROR_BYTES]

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#primitive-aliases
  ExecutionRequestsList* = List[
    ByteList[Limit MAX_BYTES_PER_EXECUTION_REQUEST],
    Limit MAX_EXECUTION_REQUESTS_PER_PAYLOAD]

  Withdrawals* = List[capella.Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]

  VersionedHashes* = List[Eth2Digest, Limit MAX_BLOBS_REQUEST]

  CellIndices* = BitArray[CELLS_PER_EXT_BLOB]

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#forkchoicestate
  ForkchoiceState* = object
    head_block_hash*: Eth2Digest
    safe_block_hash*: Eth2Digest
    finalized_block_hash*: Eth2Digest

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#payloadstatus
  PayloadStatusCode* {.pure.} = enum
    VALID = 0
    INVALID = 1
    SYNCING = 2
    ACCEPTED = 3

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#payloadstatus
  PayloadStatus* = object
    status*: uint8
    latest_valid_hash*: Optional[Eth2Digest]
    validation_error*: Optional[EngineString]

  ForkchoiceUpdateResponse* = object
    payload_status*: PayloadStatus
    payload_id*: Optional[array[8, byte]]

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#payloadattributes-per-fork
  PayloadAttributesPrague* = object
    timestamp*: uint64
    prev_randao*: Eth2Digest
    suggested_fee_recipient*: ExecutionAddress
    withdrawals*: Withdrawals
    parent_beacon_block_root*: Eth2Digest

  PayloadAttributesAmsterdam* = object
    timestamp*: uint64
    prev_randao*: Eth2Digest
    suggested_fee_recipient*: ExecutionAddress
    withdrawals*: Withdrawals
    parent_beacon_block_root*: Eth2Digest
    slot_number*: uint64
    target_gas_limit*: uint64

  ForkchoiceUpdatePrague* = object
    forkchoice_state*: ForkchoiceState
    payload_attributes*: Optional[PayloadAttributesPrague]

  ForkchoiceUpdateAmsterdam* = object
    forkchoice_state*: ForkchoiceState
    payload_attributes*: Optional[PayloadAttributesAmsterdam]
    custody_columns*: Optional[CellIndices]

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#executionpayloadenvelope-per-fork
  ExecutionPayloadEnvelopeParis* = object
    payload*: bellatrix.ExecutionPayload

  ExecutionPayloadEnvelopeShanghai* = object
    payload*: capella.ExecutionPayload

  ExecutionPayloadEnvelopeCancun* = object
    payload*: deneb.ExecutionPayload
    parent_beacon_block_root*: Eth2Digest

  ExecutionPayloadEnvelopePrague* = object
    payload*: deneb.ExecutionPayload
    parent_beacon_block_root*: Eth2Digest
    execution_requests*: ExecutionRequestsList

  ExecutionPayloadEnvelopeAmsterdam* = object
    payload*: gloas.ExecutionPayload
    parent_beacon_block_root*: Eth2Digest
    execution_requests*: ExecutionRequestsList

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#blobsbundle-per-revision
  BlobsBundleV1* = deneb.BlobsBundle

  BlobsBundleV2* = object
    commitments*: deneb.KzgCommitments
    proofs*: List[deneb.KzgProof,
      Limit (MAX_BLOB_COMMITMENTS_PER_BLOCK * CELLS_PER_EXT_BLOB.uint64)]
    blobs*: deneb.Blobs

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#builtpayload-per-fork
  BuiltPayloadPrague* = object
    payload*: deneb.ExecutionPayload
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV1
    execution_requests*: ExecutionRequestsList
    should_override_builder*: bool

  BuiltPayloadOsaka* = object
    payload*: deneb.ExecutionPayload
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV2
    execution_requests*: ExecutionRequestsList
    should_override_builder*: bool

  BuiltPayloadAmsterdam* = object
    payload*: gloas.ExecutionPayload
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV2
    execution_requests*: ExecutionRequestsList
    should_override_builder*: bool

  BlobsRequest* = object
    versioned_hashes*: VersionedHashes

  BlobsV4Request* = object
    versioned_hashes*: VersionedHashes
    indices_bitarray*: CellIndices

  # https://github.com/ethereum/execution-apis/blob/22e87b3c689f4fd1696baf40328d3c94c02275dd/src/engine/refactor-ssz.md#blobandproof-per-revision
  BlobAndProofV2* = object
    blob*: deneb.Blob
    proofs*: List[deneb.KzgProof, Limit CELLS_PER_EXT_BLOB]

  BlobV2Entry* = object
    available*: bool
    contents*: BlobAndProofV2

  BlobsV2Response* = object
    entries*: List[BlobV2Entry, Limit MAX_BLOBS_REQUEST]

  BlobCellsAndProofs* = object
    blob_cells*: List[Optional[array[BYTES_PER_CELL.int, byte]],
      Limit CELLS_PER_EXT_BLOB]
    proofs*: List[Optional[deneb.KzgProof], Limit CELLS_PER_EXT_BLOB]

  BlobV4Entry* = object
    available*: bool
    contents*: BlobCellsAndProofs

  BlobsV4Response* = object
    entries*: List[BlobV4Entry, Limit MAX_BLOBS_REQUEST]

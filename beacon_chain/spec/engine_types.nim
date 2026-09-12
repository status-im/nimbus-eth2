# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  eth/common/base as eth_common_base,
  ./eth2_ssz_serialization,
  ./datatypes/[bellatrix, capella, deneb, gloas],
  ./presets

from kzg4844/kzg_abi import
  FIELD_ELEMENTS_PER_CELL, BYTES_PER_FIELD_ELEMENT, BYTES_PER_CELL

export eth2_ssz_serialization except BitArray
export presets
export FIELD_ELEMENTS_PER_CELL, BYTES_PER_FIELD_ELEMENT, BYTES_PER_CELL
export kzg_abi.CELLS_PER_EXT_BLOB

type
  Bytes8 = eth_common_base.Bytes8

  ForkchoiceState* = object
    head_block_hash*: Eth2Digest
    safe_block_hash*: Eth2Digest
    finalized_block_hash*: Eth2Digest

func init*(T: type ForkchoiceState,
    headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest): T =
  T(
    head_block_hash: headBlockHash,
    safe_block_hash: safeBlockHash,
    finalized_block_hash: finalizedBlockHash)

type
  Optional*[T] = List[T, 1]

func optSome*[T](x: T): Optional[T] =
  Optional[T].init(@[x])

func optNone*(T: typedesc): Optional[T] =
  Optional[T].init(newSeq[T]())

func isSome*[T](o: Optional[T]): bool =
  asSeq(o).len > 0

func get*[T](o: Optional[T]): T =
  asSeq(o)[0]

func toOptional*[T](o: Opt[T]): Optional[T] =
  if o.isSome: optSome(o.get) else: optNone(T)

func toOpt*[T](o: Optional[T]): Opt[T] =
  if o.isSome: Opt.some(o.get) else: Opt.none(T)

const
  MAX_ERROR_BYTES* = 1024

# String == List[byte, MAX_ERROR_BYTES]
type
  StringSsz* = List[byte, MAX_ERROR_BYTES]

func toStringSsz*(s: string): StringSsz =
  var b = newSeq[byte](s.len)
  for i, c in s:
    b[i] = byte(c)
  StringSsz.init(b)

func toString*(s: StringSsz): string =
  let b = asSeq(s)
  result = newString(b.len)
  for i, x in b:
    result[i] = char(x)

const
  MAX_BYTES_PER_TX* = 1 shl 30
  MAX_TXS_PER_PAYLOAD* = 1 shl 20
  MAX_WITHDRAWALS_PER_PAYLOAD* = 1 shl 4
  MAX_EXECUTION_REQUESTS_PER_PAYLOAD* = 1 shl 8
  MAX_BYTES_PER_EXECUTION_REQUEST* = MAX_BYTES_PER_TX
  MAX_VERSIONED_HASHES_PER_REQUEST* = 128
  MAX_BLOBS_REQUEST* = MAX_VERSIONED_HASHES_PER_REQUEST
  MAX_BODIES_REQUEST* = 1 shl 5
  MAX_BAL_BYTES* = MAX_BYTES_PER_TX
  MAX_CLIENT_CODE_LENGTH* = 2
  MAX_CLIENT_NAME_LENGTH* = 64
  MAX_CLIENT_VERSION_LENGTH* = 64
  MAX_REQUEST_BODY_SIZE* = 64 * 1024 * 1024

type
  ExecutionRequests* = List[ByteList[Limit MAX_BYTES_PER_EXECUTION_REQUEST],
    Limit MAX_EXECUTION_REQUESTS_PER_PAYLOAD]

  EngineFork* {.pure.} = enum
    Paris
    Shanghai
    Cancun
    Prague
    Osaka
    Amsterdam

func parseEngineFork*(s: string): Opt[EngineFork] =
  case s
  of "paris": Opt.some(EngineFork.Paris)
  of "shanghai": Opt.some(EngineFork.Shanghai)
  of "cancun": Opt.some(EngineFork.Cancun)
  of "prague": Opt.some(EngineFork.Prague)
  of "osaka": Opt.some(EngineFork.Osaka)
  of "amsterdam": Opt.some(EngineFork.Amsterdam)
  else: Opt.none(EngineFork)

type
  Withdrawal* = capella.Withdrawal
  Blob* = deneb.Blob
  KzgProof* = deneb.KzgProof

  # reuse from beacon chain
  ExecutionPayloadParis* = bellatrix.ExecutionPayload
  ExecutionPayloadShanghai* = capella.ExecutionPayload
  ExecutionPayloadCancun* = deneb.ExecutionPayload
  ExecutionPayloadPrague* = deneb.ExecutionPayload
  ExecutionPayloadOsaka* = deneb.ExecutionPayload
  ExecutionPayloadAmsterdam* = gloas.ExecutionPayload

  PayloadStatusCode* {.pure.} = enum
    VALID = 0
    INVALID = 1
    SYNCING = 2
    ACCEPTED = 3
    # Deviation from execution-apis PR#793 only for compatibility with json rpc
    INVALID_BLOCK_HASH = 4

  PayloadStatus* = object
    status*: uint8 # PayloadStatusCode
    latest_valid_hash*: Optional[Digest]
    validation_error*: Optional[StringSsz]

  BlobsBundleV1* = object
    commitments*: List[deneb.KzgCommitment, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
    proofs*: List[deneb.KzgProof, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
    blobs*: List[deneb.Blob, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]

  BlobsBundleV2* = object
    commitments*: List[deneb.KzgCommitment, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
    proofs*: List[deneb.KzgProof, Limit (MAX_BLOB_COMMITMENTS_PER_BLOCK * kzg_abi.CELLS_PER_EXT_BLOB)]
    blobs*: List[deneb.Blob, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]

  PayloadAttributesParis* = object
    timestamp*: uint64
    prev_randao*: Digest
    suggested_fee_recipient*: ExecutionAddress

  PayloadAttributesShanghai* = object
    timestamp*: uint64
    prev_randao*: Digest
    suggested_fee_recipient*: ExecutionAddress
    withdrawals*: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]

  PayloadAttributesCancun* = object
    timestamp*: uint64
    prev_randao*: Digest
    suggested_fee_recipient*: ExecutionAddress
    withdrawals*: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]
    parent_beacon_block_root*: Digest

  PayloadAttributesPrague* = PayloadAttributesCancun
  PayloadAttributesOsaka* = PayloadAttributesCancun

  PayloadAttributesAmsterdam* = object
    timestamp*: uint64
    prev_randao*: Digest
    suggested_fee_recipient*: ExecutionAddress
    withdrawals*: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]
    parent_beacon_block_root*: Digest
    slot_number*: uint64
    target_gas_limit*: uint64

func init*(T: type PayloadAttributesParis, timestamp: uint64,
    prevRandao: Eth2Digest, suggestedFeeRecipient: Eth1Address): T =
  T(
    timestamp: timestamp,
    prev_randao: prevRandao,
    suggested_fee_recipient: suggestedFeeRecipient)

func init*(T: type PayloadAttributesShanghai, timestamp: uint64,
    prevRandao: Eth2Digest, suggestedFeeRecipient: Eth1Address,
    withdrawals: sink seq[capella.Withdrawal]): T =
  T(
    timestamp: timestamp,
    prev_randao: prevRandao,
    suggested_fee_recipient: suggestedFeeRecipient,
    withdrawals: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD].init(
      withdrawals))

func init*(T: type PayloadAttributesCancun, timestamp: uint64,
    prevRandao: Eth2Digest, suggestedFeeRecipient: Eth1Address,
    withdrawals: sink seq[capella.Withdrawal], consensusHead: Eth2Digest): T =
  T(
    timestamp: timestamp,
    prev_randao: prevRandao,
    suggested_fee_recipient: suggestedFeeRecipient,
    withdrawals: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD].init(
      withdrawals),
    parent_beacon_block_root: consensusHead)

func init*(T: type PayloadAttributesAmsterdam, timestamp: uint64,
    prevRandao: Eth2Digest, suggestedFeeRecipient: Eth1Address,
    withdrawals: sink seq[capella.Withdrawal], consensusHead: Eth2Digest,
    slot: Slot, targetGasLimit: uint64): T =
  T(
    timestamp: timestamp,
    prev_randao: prevRandao,
    suggested_fee_recipient: suggestedFeeRecipient,
    withdrawals: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD].init(
      withdrawals),
    parent_beacon_block_root: consensusHead,
    slot_number: uint64(slot),
    target_gas_limit: targetGasLimit)

type
  ForkedPayloadAttributes* = object
    case fork*: EngineFork
    of EngineFork.Paris:
      parisData*: PayloadAttributesParis
    of EngineFork.Shanghai:
      shanghaiData*: PayloadAttributesShanghai
    of EngineFork.Cancun, EngineFork.Prague, EngineFork.Osaka:
      cancunData*: PayloadAttributesCancun
    of EngineFork.Amsterdam:
      amsterdamData*: PayloadAttributesAmsterdam

template withForkedAttributes*(x: ForkedPayloadAttributes, body: untyped): untyped =
  case x.fork
  of EngineFork.Paris:
    const fork {.inject, used.} = EngineFork.Paris
    template attrs: untyped {.inject, used.} = x.parisData
    body
  of EngineFork.Shanghai:
    const fork {.inject, used.} = EngineFork.Shanghai
    template attrs: untyped {.inject, used.} = x.shanghaiData
    body
  of EngineFork.Cancun, EngineFork.Prague, EngineFork.Osaka:
    const fork {.inject, used.} = EngineFork.Cancun
    template attrs: untyped {.inject, used.} = x.cancunData
    body
  of EngineFork.Amsterdam:
    const fork {.inject, used.} = EngineFork.Amsterdam
    template attrs: untyped {.inject, used.} = x.amsterdamData
    body

func timestamp*(x: ForkedPayloadAttributes): uint64 =
  withForkedAttributes(x): attrs.timestamp

type
  ExecutionPayloadEnvelopeParis* = object
    payload*: ExecutionPayloadParis

  ExecutionPayloadEnvelopeShanghai* = object
    payload*: ExecutionPayloadShanghai

  ExecutionPayloadEnvelopeCancun* = object
    payload*: ExecutionPayloadCancun
    parent_beacon_block_root*: Digest

  ExecutionPayloadEnvelopePrague* = object
    payload*: ExecutionPayloadPrague
    parent_beacon_block_root*: Digest
    execution_requests*: ExecutionRequests

  ExecutionPayloadEnvelopeOsaka* = object
    payload*: ExecutionPayloadOsaka
    parent_beacon_block_root*: Digest
    execution_requests*: ExecutionRequests

  ExecutionPayloadEnvelopeAmsterdam* = object
    payload*: ExecutionPayloadAmsterdam
    parent_beacon_block_root*: Digest
    execution_requests*: ExecutionRequests

  ForkchoiceUpdateParis* = object
    forkchoice_state*: ForkchoiceState
    payload_attributes*: Optional[PayloadAttributesParis]

  ForkchoiceUpdateShanghai* = object
    forkchoice_state*: ForkchoiceState
    payload_attributes*: Optional[PayloadAttributesShanghai]

  ForkchoiceUpdateCancun* = object
    forkchoice_state*: ForkchoiceState
    payload_attributes*: Optional[PayloadAttributesCancun]

  ForkchoiceUpdatePrague* = ForkchoiceUpdateCancun
  ForkchoiceUpdateOsaka* = ForkchoiceUpdateCancun

  ForkchoiceUpdateAmsterdam* = object
    forkchoice_state*: ForkchoiceState
    payload_attributes*: Optional[PayloadAttributesAmsterdam]
    custody_columns*: Optional[BitArray[kzg_abi.CELLS_PER_EXT_BLOB]]

  ForkchoiceUpdateResponse* = object
    payload_status*: PayloadStatus
    payload_id*: Optional[ByteVector[8]]

  BuiltPayloadParis* = object
    payload*: ExecutionPayloadParis
    block_value*: UInt256

  BuiltPayloadShanghai* = object
    payload*: ExecutionPayloadShanghai
    block_value*: UInt256

  BuiltPayloadCancun* = object
    payload*: ExecutionPayloadCancun
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV1
    should_override_builder*: bool

  BuiltPayloadPrague* = object
    payload*: ExecutionPayloadPrague
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV1
    execution_requests*: ExecutionRequests
    should_override_builder*: bool

  BuiltPayloadOsaka* = object
    payload*: ExecutionPayloadOsaka
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV2
    execution_requests*: ExecutionRequests
    should_override_builder*: bool

  BuiltPayloadAmsterdam* = object
    payload*: ExecutionPayloadAmsterdam
    block_value*: UInt256
    blobs_bundle*: BlobsBundleV2
    execution_requests*: ExecutionRequests
    should_override_builder*: bool

  ExecutionPayloadBodyParis* = object
    transactions*: List[ByteList[Limit MAX_BYTES_PER_TX], Limit MAX_TXS_PER_PAYLOAD]

  ExecutionPayloadBodyShanghai* = object
    transactions*: List[ByteList[Limit MAX_BYTES_PER_TX], Limit MAX_TXS_PER_PAYLOAD]
    withdrawals*: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]

  ExecutionPayloadBodyCancun* = ExecutionPayloadBodyShanghai
  ExecutionPayloadBodyPrague* = ExecutionPayloadBodyShanghai
  ExecutionPayloadBodyOsaka* = ExecutionPayloadBodyShanghai

  ExecutionPayloadBodyAmsterdam* = object
    transactions*: List[ByteList[Limit MAX_BYTES_PER_TX], Limit MAX_TXS_PER_PAYLOAD]
    withdrawals*: List[Withdrawal, Limit MAX_WITHDRAWALS_PER_PAYLOAD]
    block_access_list*: ByteList[Limit MAX_BAL_BYTES]

  BodiesByHashRequest* = object
    block_hashes*: List[Digest, Limit MAX_BODIES_REQUEST]

  BodyEntryParis* = object
    available*: bool
    body*: ExecutionPayloadBodyParis

  BodyEntryShanghai* = object
    available*: bool
    body*: ExecutionPayloadBodyShanghai

  BodyEntryCancun* = BodyEntryShanghai
  BodyEntryPrague* = BodyEntryShanghai
  BodyEntryOsaka* = BodyEntryShanghai

  BodyEntryAmsterdam* = object
    available*: bool
    body*: ExecutionPayloadBodyAmsterdam

  BodiesResponseParis* = object
    entries*: List[BodyEntryParis, Limit MAX_BODIES_REQUEST]

  BodiesResponseShanghai* = object
    entries*: List[BodyEntryShanghai, Limit MAX_BODIES_REQUEST]

  BodiesResponseCancun* = BodiesResponseShanghai
  BodiesResponsePrague* = BodiesResponseShanghai
  BodiesResponseOsaka* = BodiesResponseShanghai

  BodiesResponseAmsterdam* = object
    entries*: List[BodyEntryAmsterdam, Limit MAX_BODIES_REQUEST]

  BlobsRequest* = object
    versioned_hashes*: List[Digest, Limit MAX_BLOBS_REQUEST]

  BlobsV4Request* = object
    versioned_hashes*: List[Digest, Limit MAX_BLOBS_REQUEST]
    indices_bitarray*: BitArray[kzg_abi.CELLS_PER_EXT_BLOB]

  BlobAndProofV1* = object
    blob*: deneb.Blob
    proof*: deneb.KzgProof

  BlobAndProofV2* = object
    blob*: deneb.Blob
    proofs*: List[deneb.KzgProof, Limit kzg_abi.CELLS_PER_EXT_BLOB]

  BlobCellsAndProofs* = object
    blob_cells*: List[Optional[array[BYTES_PER_CELL, byte]], Limit kzg_abi.CELLS_PER_EXT_BLOB]
    proofs*: List[Optional[deneb.KzgProof], Limit kzg_abi.CELLS_PER_EXT_BLOB]

  BlobV1Entry* = object
    available*: bool
    contents*: BlobAndProofV1

  BlobV2Entry* = object
    available*: bool
    contents*: BlobAndProofV2

  BlobV3Entry* = BlobV2Entry

  BlobV4Entry* = object
    available*: bool
    contents*: BlobCellsAndProofs

  BlobsV1Response* = object
    entries*: List[BlobV1Entry, Limit MAX_BLOBS_REQUEST]

  BlobsV2Response* = object
    entries*: List[BlobV2Entry, Limit MAX_BLOBS_REQUEST]

  BlobsV3Response* = object
    entries*: List[BlobV3Entry, Limit MAX_BLOBS_REQUEST]

  BlobsV4Response* = object
    entries*: List[BlobV4Entry, Limit MAX_BLOBS_REQUEST]

  # for beacon use only
  EnginePayloadStatus* = object
    status*: PayloadStatusCode
    latestValidHash*: Opt[Eth2Digest]
    validationError*: Opt[string]

  ForkchoiceUpdateResult* = object
    payloadStatus*: EnginePayloadStatus
    payloadId*: Opt[Bytes8]

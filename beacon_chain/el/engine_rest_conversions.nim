# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sequtils, typetraits],
  eth/common/base as eth_common_base,
  web3/engine_api, web3/primitives,
  ../spec/engine_types,
  ../spec/datatypes/[bellatrix, capella, deneb, electra, fulu, gloas],
  ../spec/engine_authentication,
  ./engine_api_conversions,
  ./engine_rest_client

type
  Web3KzgCommitment = eth_common_base.KzgCommitment
  Web3KzgProof = eth_common_base.KzgProof
  Web3Blob = primitives.Blob

export engine_rest_client

func asConsensusType(status: PayloadExecutionStatus): PayloadStatusCode =
  case status
  of PayloadExecutionStatus.syncing: PayloadStatusCode.SYNCING
  of PayloadExecutionStatus.valid: PayloadStatusCode.VALID
  of PayloadExecutionStatus.invalid: PayloadStatusCode.INVALID
  of PayloadExecutionStatus.accepted: PayloadStatusCode.ACCEPTED
  of PayloadExecutionStatus.invalid_block_hash: PayloadStatusCode.INVALID_BLOCK_HASH

func asConsensusType*(status: engine_types.PayloadStatus): EnginePayloadStatus =
  EnginePayloadStatus(
    status: PayloadStatusCode(status.status),
    latestValidHash:
      if status.latest_valid_hash.isSome: Opt.some(status.latest_valid_hash.get)
      else: Opt.none(Eth2Digest),
    validationError:
      if status.validation_error.isSome: Opt.some(status.validation_error.get.toString)
      else: Opt.none(string))

func asConsensusType*(status: PayloadStatusV1): EnginePayloadStatus =
  EnginePayloadStatus(
    status: asConsensusType(status.status),
    latestValidHash:
      if status.latestValidHash.isSome: Opt.some(status.latestValidHash.get.asEth2Digest)
      else: Opt.none(Eth2Digest),
    validationError: status.validationError)

func asConsensusType*(resp: engine_types.ForkchoiceUpdateResponse): ForkchoiceUpdateResult =
  ForkchoiceUpdateResult(
    payloadStatus: resp.payload_status.asConsensusType,
    payloadId:
      if resp.payload_id.isSome: Opt.some(Bytes8(distinctBase(resp.payload_id.get)))
      else: Opt.none(Bytes8))

func asConsensusType*(resp: ForkchoiceUpdatedResponseV1): ForkchoiceUpdateResult =
  ForkchoiceUpdateResult(
    payloadStatus: resp.payloadStatus.asConsensusType,
    payloadId: resp.payloadId)

func asWeb3*(state: engine_types.ForkchoiceState): ForkchoiceStateV1 =
  ForkchoiceStateV1(
    headBlockHash: state.head_block_hash.asBlockHash,
    safeBlockHash: state.safe_block_hash.asBlockHash,
    finalizedBlockHash: state.finalized_block_hash.asBlockHash)

func asWeb3Withdrawals(withdrawals: List[capella.Withdrawal, Limit 16]): seq[WithdrawalV1] =
  asSeq(withdrawals).mapIt(it.asEngineWithdrawal)

func asWeb3*(a: engine_types.PayloadAttributesParis): PayloadAttributesV1 =
  PayloadAttributesV1(
    timestamp: Quantity(a.timestamp),
    prevRandao: Bytes32(a.prev_randao.asBlockHash),
    suggestedFeeRecipient: a.suggested_fee_recipient)

func asWeb3*(a: engine_types.PayloadAttributesShanghai): PayloadAttributesV2 =
  PayloadAttributesV2(
    timestamp: Quantity(a.timestamp),
    prevRandao: Bytes32(a.prev_randao.asBlockHash),
    suggestedFeeRecipient: a.suggested_fee_recipient,
    withdrawals: asWeb3Withdrawals(a.withdrawals))

func asWeb3*(a: engine_types.PayloadAttributesCancun): PayloadAttributesV3 =
  PayloadAttributesV3(
    timestamp: Quantity(a.timestamp),
    prevRandao: Bytes32(a.prev_randao.asBlockHash),
    suggestedFeeRecipient: a.suggested_fee_recipient,
    withdrawals: asWeb3Withdrawals(a.withdrawals),
    parentBeaconBlockRoot: a.parent_beacon_block_root.asBlockHash)

func asWeb3*(a: engine_types.PayloadAttributesAmsterdam): PayloadAttributesV4 =
  PayloadAttributesV4(
    timestamp: Quantity(a.timestamp),
    prevRandao: Bytes32(a.prev_randao.asBlockHash),
    suggestedFeeRecipient: a.suggested_fee_recipient,
    withdrawals: asWeb3Withdrawals(a.withdrawals),
    parentBeaconBlockRoot: a.parent_beacon_block_root.asBlockHash,
    slotNumber: Quantity(a.slot_number),
    targetGasLimit: Quantity(a.target_gas_limit))

func asWeb3*(hashes: seq[Eth2Digest]): seq[engine_api.VersionedHash] =
  hashes.mapIt(it.asBlockHash)

func asSszType*(reqs: seq[seq[byte]]): engine_types.ExecutionRequests =
  engine_types.ExecutionRequests.init(
    reqs.mapIt(ByteList[Limit MAX_BYTES_PER_EXECUTION_REQUEST].init(it)))

func asConsensusType*(reqs: engine_types.ExecutionRequests): seq[seq[byte]] =
  asSeq(reqs).mapIt(asSeq(it))

func asSszType*(hashes: seq[Eth2Digest]): List[Digest, Limit MAX_BLOBS_REQUEST] =
  List[Digest, Limit MAX_BLOBS_REQUEST].init(hashes)

func asSszEnvelope*(payload: bellatrix.ExecutionPayload): ExecutionPayloadEnvelopeParis =
  ExecutionPayloadEnvelopeParis(payload: payload)

func asSszEnvelope*(payload: capella.ExecutionPayload): ExecutionPayloadEnvelopeShanghai =
  ExecutionPayloadEnvelopeShanghai(payload: payload)

func asSszEnvelope*(payload: deneb.ExecutionPayload, parentBeaconBlockRoot: Eth2Digest):
    ExecutionPayloadEnvelopeCancun =
  ExecutionPayloadEnvelopeCancun(
    payload: payload,
    parent_beacon_block_root: parentBeaconBlockRoot)

func asSszEnvelopePrague*(payload: deneb.ExecutionPayload,
    parentBeaconBlockRoot: Eth2Digest, executionRequests: seq[seq[byte]]):
    ExecutionPayloadEnvelopePrague =
  ExecutionPayloadEnvelopePrague(
    payload: payload,
    parent_beacon_block_root: parentBeaconBlockRoot,
    execution_requests: executionRequests.asSszType)

func asSszEnvelope*(payload: gloas.ExecutionPayload,
    parentBeaconBlockRoot: Eth2Digest, executionRequests: seq[seq[byte]]):
    ExecutionPayloadEnvelopeAmsterdam =
  ExecutionPayloadEnvelopeAmsterdam(
    payload: payload,
    parent_beacon_block_root: parentBeaconBlockRoot,
    execution_requests: executionRequests.asSszType)

func asConsensusType*(b: engine_types.BlobsBundleV1): deneb.BlobsBundle =
  deneb.BlobsBundle(
    commitments: b.commitments,
    proofs: b.proofs,
    blobs: b.blobs)

func asConsensusType*(b: engine_types.BlobsBundleV2): fulu.BlobsBundle =
  fulu.BlobsBundle(
    commitments: b.commitments,
    proofs: fulu.KzgProofs.init(asSeq(b.proofs)),
    blobs: b.blobs)

func asConsensusType*(b: BuiltPayloadPrague): electra.ExecutionPayloadForSigning =
  electra.ExecutionPayloadForSigning(
    executionPayload: b.payload,
    blockValue: b.block_value,
    blobsBundle: b.blobs_bundle.asConsensusType,
    executionRequests: b.execution_requests.asConsensusType)

func asConsensusType*(b: BuiltPayloadOsaka): fulu.ExecutionPayloadForSigning =
  fulu.ExecutionPayloadForSigning(
    executionPayload: b.payload,
    blockValue: b.block_value,
    blobsBundle: b.blobs_bundle.asConsensusType,
    executionRequests: b.execution_requests.asConsensusType)

func asConsensusType*(b: BuiltPayloadAmsterdam): gloas.ExecutionPayloadForSigning =
  gloas.ExecutionPayloadForSigning(
    executionPayload: b.payload,
    blockValue: b.block_value,
    blobsBundle: b.blobs_bundle.asConsensusType,
    executionRequests: b.execution_requests.asConsensusType)

func asConsensusType*(b: engine_api.BlobAndProofV2): engine_types.BlobAndProofV2 =
  engine_types.BlobAndProofV2(
    blob: deneb.Blob(b.blob),
    proofs: List[deneb.KzgProof, Limit engine_types.CELLS_PER_EXT_BLOB].init(
      b.proofs.mapIt(deneb.KzgProof(bytes: distinctBase(it)))))

func asConsensusType*(resp: engine_types.BlobsV2Response): seq[engine_types.BlobAndProofV2] =
  asSeq(resp.entries).mapIt(it.contents)

func asConsensusType*(resp: engine_types.BlobsV3Response): seq[Opt[engine_types.BlobAndProofV2]] =
  asSeq(resp.entries).mapIt(
    if it.available: Opt.some(it.contents) else: Opt.none(engine_types.BlobAndProofV2))

func asConsensusType*(resp: GetBlobsV2Response): seq[engine_types.BlobAndProofV2] =
  resp.mapIt(it.asConsensusType)

func asConsensusType*(resp: GetBlobsV3Response): seq[Opt[engine_types.BlobAndProofV2]] =
  resp.mapIt(
    if it.isSome: Opt.some(it.get.asConsensusType)
    else: Opt.none(engine_types.BlobAndProofV2))

proc decodeSszResponse*(T: type, resp: RestPlainResponse): T
    {.raises: [CatchableError].} =
  if resp.status != 200:
    raise newException(CatchableError,
      "Engine REST API request failed with status " & $resp.status &
        ": " & cast[string](resp.data))
  try:
    SSZ.decode(resp.data, T)
  except CatchableError as exc:
    raise newException(CatchableError,
      "Failed to decode Engine REST API response: " & exc.msg)

proc restAuthHeaders*(jwtSecret: Opt[JwtSharedKey]): seq[(string, string)] =
  if jwtSecret.isSome: engineJwtHeader(jwtSecret.get)
  else: @[]

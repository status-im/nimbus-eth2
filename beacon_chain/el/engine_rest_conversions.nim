# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/sequtils,
  results, stew/byteutils,
  web3/[engine_api_types, primitives],
  ../spec/engine_types,
  ../spec/datatypes/[capella, deneb, gloas],
  ./engine_api_conversions

from eth/common/base import Bytes8, Bytes48

func toSsz*(state: ForkchoiceStateV1): ForkchoiceState =
  ForkchoiceState(
    head_block_hash: state.headBlockHash.asEth2Digest,
    safe_block_hash: state.safeBlockHash.asEth2Digest,
    finalized_block_hash: state.finalizedBlockHash.asEth2Digest)

func toSsz(withdrawals: seq[WithdrawalV1]): engine_types.Withdrawals =
  engine_types.Withdrawals.init(withdrawals.mapIt(it.asConsensusWithdrawal))

func toSsz*(attributes: PayloadAttributesV3): PayloadAttributesPrague =
  PayloadAttributesPrague(
    timestamp: attributes.timestamp.uint64,
    prev_randao: attributes.prevRandao.asEth2Digest,
    suggested_fee_recipient: attributes.suggestedFeeRecipient,
    withdrawals: attributes.withdrawals.toSsz,
    parent_beacon_block_root: attributes.parentBeaconBlockRoot.asEth2Digest)

func toSsz*(attributes: PayloadAttributesV4): PayloadAttributesAmsterdam =
  PayloadAttributesAmsterdam(
    timestamp: attributes.timestamp.uint64,
    prev_randao: attributes.prevRandao.asEth2Digest,
    suggested_fee_recipient: attributes.suggestedFeeRecipient,
    withdrawals: attributes.withdrawals.toSsz,
    parent_beacon_block_root: attributes.parentBeaconBlockRoot.asEth2Digest,
    slot_number: attributes.slotNumber.uint64,
    target_gas_limit: attributes.targetGasLimit.uint64)

func toSszOptional*(
    attributes: Opt[PayloadAttributesV3]): Optional[PayloadAttributesPrague] =
  if attributes.isSome:
    Optional[PayloadAttributesPrague].init(@[attributes.get.toSsz])
  else:
    default(Optional[PayloadAttributesPrague])

func toSszOptional*(
    attributes: Opt[PayloadAttributesV4]): Optional[PayloadAttributesAmsterdam] =
  if attributes.isSome:
    Optional[PayloadAttributesAmsterdam].init(@[attributes.get.toSsz])
  else:
    default(Optional[PayloadAttributesAmsterdam])

func toSsz*(executionRequests: seq[seq[byte]]): ExecutionRequestsList =
  ExecutionRequestsList.init(executionRequests.mapIt(
    ByteList[Limit MAX_BYTES_PER_EXECUTION_REQUEST].init(it)))

func toSsz*(versionedHashes: seq[VersionedHash]): engine_types.VersionedHashes =
  engine_types.VersionedHashes.init(versionedHashes.mapIt(it.asEth2Digest))

func toSsz*(indices: FixedBytes[16]): CellIndices =
  CellIndices(bytes: distinctBase(indices))

func toSsz*(payload: ExecutionPayloadV1): ExecutionPayloadEnvelopeParis =
  ExecutionPayloadEnvelopeParis(payload: payload.asConsensusType)

func toSsz*(payload: ExecutionPayloadV2): ExecutionPayloadEnvelopeShanghai =
  ExecutionPayloadEnvelopeShanghai(payload: payload.asConsensusType)

func toSsz*(
    payload: ExecutionPayloadV3,
    parentBeaconBlockRoot: Hash32): ExecutionPayloadEnvelopeCancun =
  ExecutionPayloadEnvelopeCancun(
    payload: payload.asConsensusType,
    parent_beacon_block_root: parentBeaconBlockRoot.asEth2Digest)

func toSsz*(
    payload: ExecutionPayloadV3,
    parentBeaconBlockRoot: Hash32,
    executionRequests: seq[seq[byte]]): ExecutionPayloadEnvelopePrague =
  ExecutionPayloadEnvelopePrague(
    payload: payload.asConsensusType,
    parent_beacon_block_root: parentBeaconBlockRoot.asEth2Digest,
    execution_requests: executionRequests.toSsz)

func toSsz*(
    payload: ExecutionPayloadV4,
    parentBeaconBlockRoot: Hash32,
    executionRequests: seq[seq[byte]]): ExecutionPayloadEnvelopeAmsterdam =
  ExecutionPayloadEnvelopeAmsterdam(
    payload: payload.asConsensusType,
    parent_beacon_block_root: parentBeaconBlockRoot.asEth2Digest,
    execution_requests: executionRequests.toSsz)

func toWeb3*(
    status: engine_types.PayloadStatus): Result[PayloadStatusV1, string] =
  let code =
    case status.status
    of PayloadStatusCode.VALID.uint8: PayloadExecutionStatus.valid
    of PayloadStatusCode.INVALID.uint8: PayloadExecutionStatus.invalid
    of PayloadStatusCode.SYNCING.uint8: PayloadExecutionStatus.syncing
    of PayloadStatusCode.ACCEPTED.uint8: PayloadExecutionStatus.accepted
    else: return err("Unknown payload status: " & $status.status)

  ok PayloadStatusV1(
    status: code,
    latestValidHash:
      if status.latest_valid_hash.len > 0:
        Opt.some(status.latest_valid_hash[0].asBlockHash)
      else:
        Opt.none(Hash32),
    validationError:
      if status.validation_error.len > 0:
        Opt.some(string.fromBytes(status.validation_error[0].asSeq))
      else:
        Opt.none(string))

func toWeb3*(
    response: ForkchoiceUpdateResponse
): Result[ForkchoiceUpdatedResponseV1, string] =
  ok ForkchoiceUpdatedResponseV1(
    payloadStatus: ? response.payload_status.toWeb3,
    payloadId:
      if response.payload_id.len > 0:
        Opt.some(Bytes8(response.payload_id[0]))
      else:
        Opt.none(Bytes8))

func toWeb3(
    bundle: engine_types.BlobsBundleV1): engine_api_types.BlobsBundleV1 =
  engine_api_types.BlobsBundleV1(
    commitments: bundle.commitments.mapIt(Bytes48(it.bytes)),
    proofs: bundle.proofs.mapIt(Bytes48(it.bytes)),
    blobs: bundle.blobs.mapIt(primitives.Blob(it)))

func toWeb3(
    bundle: engine_types.BlobsBundleV2): engine_api_types.BlobsBundleV2 =
  engine_api_types.BlobsBundleV2(
    commitments: bundle.commitments.mapIt(Bytes48(it.bytes)),
    proofs: bundle.proofs.mapIt(Bytes48(it.bytes)),
    blobs: bundle.blobs.mapIt(primitives.Blob(it)))

func toWeb3*(payload: BuiltPayloadPrague): GetPayloadV4Response =
  GetPayloadV4Response(
    executionPayload: payload.payload.asEngineExecutionPayload,
    blockValue: payload.block_value,
    blobsBundle: payload.blobs_bundle.toWeb3,
    shouldOverrideBuilder: payload.should_override_builder,
    executionRequests: payload.execution_requests.mapIt(it.asSeq))

func toWeb3*(payload: BuiltPayloadOsaka): GetPayloadV5Response =
  GetPayloadV5Response(
    executionPayload: payload.payload.asEngineExecutionPayload,
    blockValue: payload.block_value,
    blobsBundle: payload.blobs_bundle.toWeb3,
    shouldOverrideBuilder: payload.should_override_builder,
    executionRequests: payload.execution_requests.mapIt(it.asSeq))

func toWeb3*(payload: BuiltPayloadAmsterdam): GetPayloadV6Response =
  GetPayloadV6Response(
    executionPayload: payload.payload.asEngineExecutionPayload,
    blockValue: payload.block_value,
    blobsBundle: payload.blobs_bundle.toWeb3,
    shouldOverrideBuilder: payload.should_override_builder,
    executionRequests: payload.execution_requests.mapIt(it.asSeq))

func toWeb3(
    blobAndProof: engine_types.BlobAndProofV2
): Result[engine_api_types.BlobAndProofV2, string] =
  var res = engine_api_types.BlobAndProofV2(
    blob: primitives.Blob(blobAndProof.blob))
  if blobAndProof.proofs.len != res.proofs.len:
    return err("Unexpected number of cell proofs: " & $blobAndProof.proofs.len)
  for i in 0 ..< blobAndProof.proofs.len:
    res.proofs[i] = Bytes48(blobAndProof.proofs[i].bytes)
  ok res

func toWeb3*(
    response: BlobsV2Response, T: type GetBlobsV2Response
): Result[T, string] =
  var res: T
  for entry in response.entries:
    if not entry.available:
      return err("Missing blob in all-or-nothing response")
    res.add(? entry.contents.toWeb3)
  ok res

func toWeb3(cellsAndProofs: BlobCellsAndProofs): BlobCellsAndProofsV1 =
  BlobCellsAndProofsV1(
    blob_cells: cellsAndProofs.blob_cells.mapIt(
      if it.len > 0: Opt.some(@(it[0])) else: Opt.none(seq[byte])),
    proofs: cellsAndProofs.proofs.mapIt(
      if it.len > 0: Opt.some(Bytes48(it[0].bytes)) else: Opt.none(Bytes48)))

func toWeb3*(response: BlobsV4Response): GetBlobsV4Response =
  response.entries.mapIt(
    if it.available: Opt.some(it.contents.toWeb3)
    else: Opt.none(BlobCellsAndProofsV1))

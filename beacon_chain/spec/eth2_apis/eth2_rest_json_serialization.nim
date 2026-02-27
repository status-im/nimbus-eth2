# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[macros, strformat, strutils],
  results,
  stew/[assign2, base10, byteutils],
  faststreams/textio,
  json_serialization,
  json_serialization/pkg/results,
  ../../validators/slashing_protection_common,
  ../../consensus_object_pools/block_pools_types,
  ../[forks, keystore],
  ./[rest_keymanager_types, rest_types]

export
  results, json_serialization, results, slashing_protection_common, block_pools_types,
  forks, keystore, rest_keymanager_types, rest_types

## The RestJson format implements JSON serialization in the way specified
## by the Beacon API:
##
## https://ethereum.github.io/beacon-APIs/
##
## In this format, we must always set `allowUnknownFields = true` in the
## decode calls in order to conform the following spec:
##
## All JSON responses return the requested data under a data key in the top
## level of their response.  Additional metadata may or may not be present
## in other keys at the top level of the response, dependent on the endpoint.
## The rules that require an increase in version number are as follows:
##
## - no field that is listed in an endpoint shall be removed without an increase
##   in the version number
##
## - no field that is listed in an endpoint shall be altered in terms of format
##   (e.g. from a string to an array) without an increase in the version number
##
## Note that it is possible for a field to be added to an endpoint's data or
## metadata without an increase in the version number.
##
## This also means that when new fields are introduced to the object definitions
## below, one must use the `Opt[T]` type so as not to trigger `requiresAllFields`.

createJsonFlavor RestJson,
  automaticObjectSerialization = false,
  requireAllFields = true,
  omitOptionalFields = true,
  allowUnknownFields = true

#!fmt: off
RestJson.useDefaultSerializationFor(
  AttestationData,
  BLSToExecutionChange,
  BeaconBlockHeader,
  BlobSidecar,
  BlobSidecarInfoObject,
  Builder,
  BuilderPendingPayment,
  BuilderPendingWithdrawal,
  Checkpoint,
  ConsolidationRequest,
  ContributionAndProof,
  DataColumnSidecarInfoObject,
  DataEnclosedObject,
  DataMetaEnclosedObject,
  DataOptimisticAndFinalizedObject,
  DataOptimisticObject,
  DataRootEnclosedObject,
  DataVersionEnclosedObject,
  DeleteKeystoresBody,
  DeleteKeystoresResponse,
  DeleteRemoteKeystoresResponse,
  DenebSignedBlockContents,
  Deposit,
  DepositData,
  DepositRequest,
  DistributedKeystoreInfo,
  ElectraSignedBlockContents,
  EmptyBody,
  Eth1Data,
  EventBeaconBlockObject,
  EventBeaconBlockGossipObject,
  EventBeaconBlockGossipPeerObject,
  ExecutionPayloadEnvelope,
  ExecutionPayloadInfoObject,
  ExecutionRequests,
  FinalizationInfoObject,
  Fork,
  FuluSignedBlockContents,
  GetBlockAttestationsResponse,
  GetBlockHeaderResponse,
  GetBlockHeadersResponse,
  GetDistributedKeystoresResponse,
  GetEpochCommitteesResponse,
  GetEpochSyncCommitteesResponse,
  GetForkChoiceResponse,
  GetForkScheduleResponse,
  GetGenesisResponse,
  GetHistoricalSummariesV1Response,
  GetHistoricalSummariesV1ResponseElectra,
  GetKeystoresResponse,
  GetNextWithdrawalsResponse,
  GetPoolAttesterSlashingsResponse,
  GetPoolProposerSlashingsResponse,
  GetPoolVoluntaryExitsResponse,
  GetRemoteKeystoresResponse,
  GetSpecVCResponse,
  GetStateFinalityCheckpointsResponse,
  GetStateForkResponse,
  GetStateRandaoResponse,
  GetStateRootResponse,
  GetStateValidatorBalancesResponse,
  GetStateValidatorResponse,
  GetStateValidatorsResponse,
  GetValidatorGasLimitResponse,
  GloasSignedBlockContents,
  HeadChangeInfoObject,
  HistoricalSummary,
  ImportDistributedKeystoresBody,
  ImportRemoteKeystoresBody,
  IndexedPayloadAttestation,
  KeymanagerGenericError,
  KeystoreInfo,
  ListFeeRecipientResponse,
  ListGasLimitResponse,
  GetGraffitiResponse,
  GraffitiResponse,
  PayloadAttestation,
  PayloadAttestationData,
  PayloadAttestationMessage,
  PendingAttestation,
  PendingConsolidation,
  PendingDeposit,
  PendingPartialWithdrawal,
  PostKeystoresResponse,
  PrepareBeaconProposer,
  ProposerSlashing,
  RemoteKeystoreInfo,
  RemoteSignerInfo,
  RequestItemStatus,
  RestActivityItem,
  RestAttesterDuty,
  RestBeaconCommitteeSelection,
  RestBeaconStatesCommittees,
  RestBeaconStatesFinalityCheckpoints,
  RestBlockHeader,
  RestBlockHeaderInfo,
  RestChainHeadV2,
  RestCommitteeSubscription,
  RestContributionAndProof,
  RestEpochRandao,
  RestEpochSyncCommittee,
  RestExtraData,
  RestGenesis,
  RestIndexedErrorMessage,
  RestIndexedErrorMessageItem,
  RestLivenessItem,
  RestMetadata,
  RestNetworkIdentity,
  RestNimbusTimestamp1,
  RestNimbusTimestamp2,
  RestNode,
  RestNodeExtraData,
  RestNodePeer,
  RestNodeVersion,
  RestPeerCount,
  RestProposerDuty,
  RestRoot,
  RestSignedBlockHeader,
  RestSignedContributionAndProof,
  RestSyncCommitteeContribution,
  RestSyncCommitteeDuty,
  RestSyncCommitteeMessage,
  RestSyncCommitteeReward,
  RestSyncCommitteeSelection,
  RestSyncCommitteeSubscription,
  RestSyncInfo,
  RestValidator,
  RestValidatorIdentity,
  RestValidatorBalance,
  ReorgInfoObject,
  SPDIR,
  SPDIR_Meta,
  SPDIR_SignedAttestation,
  SPDIR_SignedBlock,
  SPDIR_Validator,
  SetFeeRecipientRequest,
  SetGasLimitRequest,
  SetGraffitiRequest,
  SignedBLSToExecutionChange,
  SignedBeaconBlockHeader,
  SignedContributionAndProof,
  SignedExecutionPayloadBid,
  SignedExecutionPayloadEnvelope,
  SignedValidatorRegistrationV1,
  SignedVoluntaryExit,
  SyncAggregate,
  SyncAggregatorSelectionData,
  SyncCommittee,
  SyncCommitteeContribution,
  SyncCommitteeMessage,
  Validator,
  ValidatorRegistrationV1,
  VoluntaryExit,
  Web3SignerAggregationSlotData,
  Web3SignerDepositData,
  Web3SignerErrorResponse,
  Web3SignerForkInfo,
  Web3SignerMerkleProof,
  Web3SignerRandaoRevealData,
  Web3SignerSignatureResponse,
  Web3SignerStatusResponse,
  Web3SignerSyncCommitteeMessageData,
  Web3SignerValidatorRegistration,
  Withdrawal,
  WithdrawalRequest,
  altair.BeaconBlock,
  altair.BeaconBlockBody,
  altair.BeaconState,
  altair.LightClientBootstrap,
  altair.LightClientFinalityUpdate,
  altair.LightClientHeader,
  altair.LightClientOptimisticUpdate,
  altair.LightClientUpdate,
  bellatrix.BeaconBlock,
  bellatrix.BeaconBlockBody,
  bellatrix.BeaconState,
  bellatrix.ExecutionPayload,
  bellatrix.ExecutionPayloadHeader,
  bellatrix_mev.BlindedBeaconBlockBody,
  bellatrix_mev.BlindedBeaconBlock,
  bellatrix_mev.SignedBlindedBeaconBlock,
  capella.BeaconBlock,
  capella.BeaconBlockBody,
  capella.BeaconState,
  capella.ExecutionPayload,
  capella.ExecutionPayloadHeader,
  capella.LightClientBootstrap,
  capella.LightClientFinalityUpdate,
  capella.LightClientHeader,
  capella.LightClientOptimisticUpdate,
  capella.LightClientUpdate,
  capella_mev.BlindedBeaconBlock,
  capella_mev.BlindedBeaconBlockBody,
  capella_mev.SignedBlindedBeaconBlock,
  deneb.BeaconBlock,
  deneb.BeaconBlockBody,
  deneb.BeaconState,
  deneb.BlobsBundle,
  deneb.BlockContents,
  deneb.ExecutionPayload,
  deneb.ExecutionPayloadHeader,
  deneb.LightClientBootstrap,
  deneb.LightClientFinalityUpdate,
  deneb.LightClientHeader,
  deneb.LightClientOptimisticUpdate,
  deneb.LightClientUpdate,
  deneb_mev.BlindedBeaconBlock,
  deneb_mev.BlindedBeaconBlockBody,
  deneb_mev.SignedBlindedBeaconBlock,
  electra.AggregateAndProof,
  electra.Attestation,
  electra.AttesterSlashing,
  electra.BeaconBlock,
  electra.BeaconState,
  electra.BeaconBlockBody,
  electra.BlockContents,
  electra.IndexedAttestation,
  electra.LightClientBootstrap,
  electra.LightClientFinalityUpdate,
  electra.LightClientHeader,
  electra.LightClientOptimisticUpdate,
  electra.LightClientUpdate,
  electra.SignedAggregateAndProof,
  electra.SingleAttestation,
  electra.TrustedAttestation,
  electra_mev.BlindedBeaconBlock,
  electra_mev.BlindedBeaconBlockBody,
  electra_mev.BuilderBid,
  electra_mev.ExecutionPayloadAndBlobsBundle,
  electra_mev.SignedBlindedBeaconBlock,
  electra_mev.SignedBuilderBid,
  fulu.BeaconBlock,
  fulu.BeaconBlockBody,
  fulu.BeaconState,
  fulu.BlobsBundle,
  fulu.BlockContents,
  fulu.DataColumnSidecar,
  fulu_mev.BlindedBeaconBlock,
  fulu_mev.BlindedBeaconBlockBody,
  fulu_mev.BuilderBid,
  fulu_mev.SignedBlindedBeaconBlock,
  fulu_mev.SignedBuilderBid,
  gloas.BeaconBlock,
  gloas.BeaconBlockBody,
  gloas.BeaconState,
  gloas.BlockContents,
  gloas.DataColumnSidecar,
  gloas.ExecutionPayloadBid,
  phase0.AggregateAndProof,
  phase0.Attestation,
  phase0.AttesterSlashing,
  phase0.BeaconBlock,
  phase0.BeaconBlockBody,
  phase0.BeaconState,
  phase0.IndexedAttestation,
  phase0.SignedAggregateAndProof,
  phase0.TrustedAttestation
)
#!fmt: on

type
  RestJsonWriter = RestJson.Writer()
  RestJsonReader = RestJson.Reader()

{.pragma: reader, raises: [IOError, SerializationError].}
{.pragma: writer, raises: [IOError].}

## https://github.com/ethereum/beacon-APIs/blob/v3.1.0/types/primitive.yaml#L57
proc write0xHex*(w: var RestJsonWriter, value: openArray[byte]) {.writer.} =
  w.streamElement(s):
    s.write("\"0x")
    s.writeHex(value)
    s.write('"')

# TODO
# Tuples are widely used in the responses of the REST server
# If we switch to concrete types there, it would be possible
# to remove this overly generic definition.
template writeValue*(w: RestJsonWriter, value: tuple) =
  writeRecordValue(w, value)

## https://github.com/ethereum/beacon-APIs/blob/v3.1.0/types/primitive.yaml#L31
proc writeValue*(
    w: var RestJsonWriter, value: uint64 | uint32 | uint16 | uint8
) {.writer.} =
  w.streamElement(s):
    s.write('"')
    s.writeText(value)
    s.write('"')

proc readValue*[T: uint64 | uint32 | uint16 | uint8](
    r: var RestJsonReader, value: var T
) {.reader.} =
  let svalue = r.readValue(string)
  value = Base10.decode(T, svalue).valueOr:
    r.raiseUnexpectedValue($error & ": " & svalue)

proc writeValue*(w: var RestJsonWriter, value: ConsensusFork) {.writer.} =
  w.writeValue(value.toString())

proc readValue*(r: var RestJsonReader, value: var ConsensusFork) {.reader.} =
  let svalue = r.readValue(string)
  # toLowerAscii because Web3Signer uses uppercase (!)
  value = ConsensusFork.init(svalue.toLowerAscii).valueOr:
    r.raiseUnexpectedValue("Invalid or unknown consensus fork: " & $svalue)

proc writeValue*(w: var RestJsonWriter, value: RestReward) {.writer.} =
  w.streamElement(s):
    s.write('"')
    s.writeText(int64(value))
    s.write('"')

proc readValue*(r: var RestJsonReader, value: var RestReward) {.reader.} =
  let svalue = r.readValue(string)
  if svalue.startsWith("-"):
    let res = Base10.decode(uint64, svalue.toOpenArray(1, len(svalue) - 1)).valueOr:
      r.raiseUnexpectedValue($error & ": " & svalue)
    if res > uint64(high(int64)):
      r.raiseUnexpectedValue("Integer value overflow " & svalue)
    value = RestReward(-int64(res))
  else:
    let res = Base10.decode(uint64, svalue).valueOr:
      r.raiseUnexpectedValue($error & ": " & svalue)
    if res > uint64(high(int64)):
      r.raiseUnexpectedValue("Integer value overflow " & svalue)
    value = RestReward(int64(res))

proc writeValue*(w: var RestJsonWriter, value: RestNumeric) {.writer.} =
  w.streamElement(s):
    s.writeText(int(value))

proc readValue*(r: var RestJsonReader, value: var RestNumeric) {.reader.} =
  if r.tokKind == JsonValueKind.String:
    # Nimbus earlier than v23.11.0 erroneously used a string in some number
    # fields - provide backwards compatibilty..
    let svalue = r.readValue(string)
    try:
      value = RestNumeric(parseInt(svalue))
    except ValueError:
      r.raiseUnexpectedValue("Expected number/string")
  else:
    value = RestNumeric(r.parseInt(int))

proc writeValue*(w: var RestJsonWriter, value: JustificationBits) {.writer.} =
  w.write0xHex([uint8(value)])

proc readValue*(r: var RestJsonReader, value: var JustificationBits) {.reader.} =
  let hex = r.readValue(string)
  try:
    value = JustificationBits(hexToByteArray(hex, 1)[0])
  except ValueError:
    r.raiseUnexpectedValue("The `justification_bits` value must be a hex string")

proc writeValue*(w: var RestJsonWriter, value: UInt256) {.writer.} =
  w.writeValue(toString(value))

proc readValue*(r: var RestJsonReader, value: var UInt256) {.reader.} =
  let svalue = r.readValue(string)
  try:
    value = parse(svalue, UInt256, 10)
  except ValueError:
    r.raiseUnexpectedValue("UInt256 value should be a valid decimal string")

proc writeValue*(w: var RestJsonWriter, value: Gwei | Epoch | Slot) {.writer.} =
  w.writeValue(distinctBase(value))

proc readValue*(r: var RestJsonReader, value: var (Gwei | Epoch | Slot)) {.reader.} =
  r.readValue(distinctBase(value))

proc writeValue*(w: var RestJsonWriter, value: EpochParticipationFlags) {.writer.} =
  for e in w.stepwiseArrayCreation(value.asList):
    w.writeValue e

proc readValue*(
    r: var RestJsonReader, value: var EpochParticipationFlags
) {.raises: [SerializationError, IOError].} =
  for e in r.readArray(uint8):
    if not value.asList.add(e):
      r.raiseUnexpectedValue("The participation flags list size exceeds limit")

proc writeValue*(
    w: var RestJsonWriter,
    value: RestValidatorIndex | ValidatorIndex | IndexInSyncCommittee | CommitteeIndex,
) {.writer.} =
  w.writeValue(distinctBase(value))

proc readValue*[T: ValidatorIndex | IndexInSyncCommittee | CommitteeIndex](
    r: var RestJsonReader, value: var T
) {.reader.} =
  let v = r.readValue(uint64)
  value = T.init(v).valueOr:
    r.raiseUnexpectedValue($error)

proc readValue*(r: var RestJsonReader, value: var RestValidatorIndex) {.reader.} =
  r.readValue(uint64(value))

proc writeValue*(
    w: var RestJsonWriter, value: ValidatorSig | TrustedSig | ValidatorPubKey
) {.writer.} =
  w.write0xHex(toRaw(value))

proc readValue*[T: ValidatorSig | ValidatorPubKey](
    r: var RestJsonReader, value: var T
) {.reader.} =
  let hexValue = r.readValue(string)
  value = T.fromHex(hexValue).valueOr:
    r.raiseUnexpectedValue($error)

proc readValue*(r: var RestJsonReader, value: var TrustedSig) {.reader.} =
  let hexValue = r.readValue(string)
  let sig = ValidatorSig.fromHex(hexValue).valueOr:
    r.raiseUnexpectedValue($error)

  value = TrustedSig(blob: sig.blob)

proc readValue*(r: var RestJsonReader, value: var HashedValidatorPubKey) {.reader.} =
  let key = r.readValue(ValidatorPubKey)

  value = HashedValidatorPubKey.init(key)

proc writeValue*(w: var RestJsonWriter, value: HashedValidatorPubKey) {.writer.} =
  w.writeValue(value.pubkey)

proc readValue*[T: BitSeq | BitList](r: var RestJsonReader, value: var T) {.reader.} =
  try:
    value = T hexToSeqByte(r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue(&"{$type(value)} should be a valid hex string")

proc writeValue*(w: var RestJsonWriter, value: BitSeq | BitList | BitArray) {.writer.} =
  w.write0xHex(value.bytes)

proc readValue*(r: var RestJsonReader, value: var BitArray) {.reader.} =
  try:
    hexToByteArray(r.readValue(string), value.bytes)
  except ValueError:
    r.raiseUnexpectedValue("BitArray value should be a valid hex string")

proc readValue*(
    r: var RestJsonReader, value: var (Eth2Digest | BloomLogs | Eth1Address | Blob)
) {.reader.} =
  try:
    hexToByteArray(r.readValue(string), value.data)
  except ValueError:
    r.raiseUnexpectedValue(&"{$type(value)} should be a valid hex string")

proc writeValue*(
    w: var RestJsonWriter, value: Eth2Digest | BloomLogs | Eth1Address | Blob
) {.writer.} =
  w.write0xHex(value.data)

proc readValue*(r: var RestJsonReader, value: var Blob) {.reader.} =
  try:
    hexToByteArray(r.readValue(string), value)
  except ValueError:
    r.raiseUnexpectedValue(&"{$type(value)} should be a valid hex string")

proc writeValue*(w: var RestJsonWriter, value: Blob) {.writer.} =
  w.write0xHex(value)

proc readValue*(r: var RestJsonReader, value: var (HashArray | HashList)) {.reader.} =
  r.readValue(value.data)
  value.resetCache()

proc writeValue*(w: var RestJsonWriter, value: HashArray | HashList) {.writer.} =
  w.writeValue(value.data)

## https://github.com/ethereum/beacon-APIs/blob/v2.4.2/types/primitive.yaml#L135-L146
proc readValue*(
    r: var RestJsonReader, value: var (KzgCommitment | KzgProof | KzgCell)
) {.reader.} =
  try:
    hexToByteArray(r.readValue(string), distinctBase(value.bytes))
  except ValueError:
    r.raiseUnexpectedValue(&"{$typeof(value)} should be a valid hex string")

proc writeValue*(
    w: var RestJsonWriter, value: KzgCommitment | KzgProof | KzgCell
) {.writer.} =
  w.write0xHex(value.bytes)

proc writeValue*(w: var RestJsonWriter, value: Blobs) {.writer.} =
  w.writeArray:
    for blob in value.asSeq():
      w.writeValue(blob)

proc writeValue*(w: var RestJsonWriter, value: GraffitiBytes) {.writer.} =
  w.write0xHex(distinctBase(value))

proc readValue*(r: var RestJsonReader, value: var GraffitiBytes) {.reader.} =
  try:
    value = init(GraffitiBytes, r.readValue(string))
  except ValueError as err:
    r.raiseUnexpectedValue err.msg

proc readValue*(
    r: var RestJsonReader,
    value: var (Version | ForkDigest | DomainType | RestWithdrawalPrefix),
) {.reader.} =
  try:
    hexToByteArray(r.readValue(string), distinctBase(value))
  except ValueError:
    r.raiseUnexpectedValue(
      &"Expected a valid hex string with {distinctBase(value).len()} bytes"
    )

template unrecognizedFieldWarning(fieldNameParam, typeNameParam: string) =
  # TODO: There should be a different notification mechanism for informing the
  #       caller of a deserialization routine for unexpected fields.
  #       The chonicles import in this module should be removed.
  trace "JSON field not recognized by the current version of Nimbus. Consider upgrading",
    fieldName = fieldNameParam, typeName = typeNameParam

template unrecognizedFieldIgnore() =
  discard r.readValue(JsonString)

type
  VersionedData = object
    version: ConsensusFork
    data: JsonString

RestJson.useDefaultSerializationFor VersionedData

type Web3SignerVersionedBeaconBlock = object
  version: string # Uppercase!
  `block`: Opt[JsonString]
  block_header: Opt[JsonString]

RestJson.useDefaultSerializationFor Web3SignerVersionedBeaconBlock

proc readValue*(
    r: var RestJsonReader, value: var Web3SignerForkedBeaconBlock
) {.reader.} =
  var tmp: Web3SignerVersionedBeaconBlock
  r.readValue(tmp)
  let version = ConsensusFork.init(tmp.version.toLowerAscii).valueOr:
    r.raiseUnexpectedValue($error)

  if version <= ConsensusFork.Altair:
    r.raiseUnexpectedValue("Web3Signer implementation supports Bellatrix and newer")
  if tmp.block_header.isNone():
    r.raiseUnexpectedValue("Missing `block_header`")

  let res = RestJson.decode(string(tmp.block_header.get()), BeaconBlockHeader)
  value = Web3SignerForkedBeaconBlock(kind: version, data: res)

proc writeValue*(w: var RestJsonWriter, value: Web3SignerForkedBeaconBlock) {.writer.} =
  # https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing/operation/ETH2_SIGN
  # https://github.com/ConsenSys/web3signer/blob/d51337e96ba5ce410222943556bed7c4856b8e57/core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/signing/eth2/json/BlockRequestDeserializer.java#L42-L58
  w.writeObject:
    w.writeField("version", value.kind.toString.toUpperAscii)
    w.writeField("block_header", value.data)

type VersionedSignedBeaconBlock = VersionedData

proc readValue*(
    r: var RestJsonReader, value: var SomeForkySignedBeaconBlock
) {.reader.} =
  # Keep `root` up to date!
  r.readRecordValue(value)
  value.root = hash_tree_root(value.message)

proc writeValue*(w: var RestJsonWriter, value: SomeForkySignedBeaconBlock) {.writer.} =
  w.writeRecordValue(value)

proc readValue*(r: var RestJsonReader, value: var ForkedSignedBeaconBlock) {.reader.} =
  let v = r.readValue(VersionedSignedBeaconBlock)

  if value.kind != v.version:
    value = ForkedSignedBeaconBlock(kind: v.version)

  try:
    withBlck(value):
      forkyBlck = RestJson.decode(string(v.data), typeof(forkyBlck))
  except SerializationError as exc:
    r.raiseUnexpectedValue(
      &"""Incorrect {v.version} block format, [{exc.formatMsg("SignedBeaconBlock")}]"""
    )

proc writeValue*(w: var RestJsonWriter, value: ForkedSignedBeaconBlock) {.writer.} =
  w.writeObject:
    w.writeField("version", value.kind.toString)
    withBlck(value):
      w.writeField("data", forkyBlck)

type VersionedHashedBeaconState = VersionedData
proc readValue*(r: var RestJsonReader, value: var ForkedHashedBeaconState) {.reader.} =
  let v = r.readValue(VersionedHashedBeaconState)

  # Use a temporary to avoid stack instances and `value` mutation in case of
  # exception
  let tmp = (ref ForkedHashedBeaconState)(kind: v.version)

  template toValue(field: untyped) =
    tmp[].field.data = RestJson.decode(string(v.data), typeof(tmp[].field.data))
    if tmp[].kind == value.kind:
      assign(value.field, tmp[].field)
    else:
      value = tmp[] # slow, but rare (hopefully)
    value.field.root = hash_tree_root(value.field.data)

  try:
    case v.version
    of ConsensusFork.Phase0:
      toValue(phase0Data)
    of ConsensusFork.Altair:
      toValue(altairData)
    of ConsensusFork.Bellatrix:
      toValue(bellatrixData)
    of ConsensusFork.Capella:
      toValue(capellaData)
    of ConsensusFork.Deneb:
      toValue(denebData)
    of ConsensusFork.Electra:
      toValue(electraData)
    of ConsensusFork.Fulu:
      toValue(fuluData)
    of ConsensusFork.Gloas:
      toValue(gloasData)
  except SerializationError:
    r.raiseUnexpectedValue(&"Incorrect {v.version} beacon state format")

proc writeValue*(w: var RestJsonWriter, value: ForkedHashedBeaconState) {.writer.} =
  w.writeObject:
    w.writeField("version", value.kind.toString)
    withState(value):
      w.writeField("data", forkyState.data)

type VersionedLightClientObject = VersionedData

proc readValue*[T: SomeForkedLightClientObject](
    r: var RestJsonReader, value: var T
) {.reader.} =
  let v = r.readValue(VersionedLightClientObject)

  withLcDataFork(lcDataForkAtConsensusFork(v.version)):
    when lcDataFork > LightClientDataFork.None:
      try:
        value = T.init(RestJson.decode(string(v.data), T.Forky(lcDataFork)))
      except SerializationError:
        r.raiseUnexpectedValue("Incorrect format (" & $lcDataFork & ")")
    else:
      r.raiseUnexpectedValue("Unsupported fork " & $v.version)

type VersionedAggregateAndProof = VersionedData
proc readValue*(r: var RestJsonReader, value: var ForkedAggregateAndProof) {.reader.} =
  let v = r.readValue(VersionedAggregateAndProof)

  if value.kind != v.version:
    value = ForkedAggregateAndProof(kind: v.version)

  try:
    withAggregateAndProof(value):
      forkyProof = RestJson.decode(string(v.data), typeof(forkyProof))
  except SerializationError as exc:
    r.raiseUnexpectedValue(
      &"""Incorrect {v.version} aggregated attestation format, [{exc.formatMsg("ForkedAggregateAndProof")}]"""
    )

proc writeValue*(w: var RestJsonWriter, proof: ForkedAggregateAndProof) {.writer.} =
  w.writeObject:
    w.writeField("version", proof.kind.toString())
    withAggregateAndProof(proof):
      w.writeField("data", forkyProof)

proc writeValue*(w: var RestJsonWriter, value: Web3SignerRequest) {.writer.} =
  w.writeObject:
    w.writeField("type", value.kind)
    w.writeField("fork_info", value.forkInfo)
    w.writeField("signingRoot", value.signingRoot)

    case value.kind
    of Web3SignerRequestKind.AggregationSlot:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("aggregation_slot", value.aggregationSlot)
    of Web3SignerRequestKind.AggregateAndProof:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("aggregate_and_proof", value.aggregateAndProof)
    of Web3SignerRequestKind.AggregateAndProofV2:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("aggregate_and_proof", value.forkedAggregateAndProof)
    of Web3SignerRequestKind.Attestation:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("attestation", value.attestation)
    of Web3SignerRequestKind.BlockV2:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      # https://github.com/Consensys/web3signer/blob/2d956c019663ac70f60640d23196d1d321c1b1fa/core/src/main/resources/openapi-specs/eth2/signing/schemas.yaml#L483-L500
      w.writeField("beacon_block", value.beaconBlockHeader)

      w.writeField("proofs", value.proofs)
    of Web3SignerRequestKind.Deposit:
      w.writeField("deposit", value.deposit)
    of Web3SignerRequestKind.RandaoReveal:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("randao_reveal", value.randaoReveal)
    of Web3SignerRequestKind.VoluntaryExit:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("voluntary_exit", value.voluntaryExit)
    of Web3SignerRequestKind.SyncCommitteeMessage:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("sync_committee_message", value.syncCommitteeMessage)
    of Web3SignerRequestKind.SyncCommitteeSelectionProof:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("sync_aggregator_selection_data", value.syncAggregatorSelectionData)
    of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
      doAssert(value.forkInfo.isSome(), "forkInfo should be set for " & $value.kind)
      w.writeField("contribution_and_proof", value.syncCommitteeContributionAndProof)
    of Web3SignerRequestKind.ValidatorRegistration:
      # https://consensys.github.io/web3signer/web3signer-eth2.html#operation/ETH2_SIGN
      w.writeField("validator_registration", value.validatorRegistration)

type RawWeb3SignerRequest = object
  `type`: Web3SignerRequestKind
  fork_info: Opt[Web3SignerForkInfo]
  signingRoot: Opt[Eth2Digest] # Capitalized like so in spec!
  proofs: Opt[seq[Web3SignerMerkleProof]]

  # The following fields are present or not depending on the type
  aggregation_slot: Opt[Web3SignerAggregationSlotData]
  attestation: Opt[AttestationData]
  aggregate_and_proof: Opt[JsonString]
  beacon_block: Opt[Web3SignerForkedBeaconBlock]
  deposit: Opt[Web3SignerDepositData]
  randao_reveal: Opt[Web3SignerRandaoRevealData]
  voluntary_exit: Opt[VoluntaryExit]
  sync_committee_message: Opt[Web3SignerSyncCommitteeMessageData]
  sync_aggregator_selection_data: Opt[SyncAggregatorSelectionData]
  contribution_and_proof: Opt[ContributionAndProof]
  validator_registration: Opt[Web3SignerValidatorRegistration]

RestJson.useDefaultSerializationFor RawWeb3SignerRequest
proc readValue*(r: var RestJsonReader, value: var Web3SignerRequest) {.reader.} =
  let v = r.readValue(RawWeb3SignerRequest)

  template expectedForkInfo(): untyped =
    if v.fork_info.isNone():
      r.raiseUnexpectedValue("Field `fork_info` is missing")
    v.fork_info

  template expectedField(name: untyped): untyped =
    const fieldName = astToStr(name)

    v.name.valueOr:
      r.raiseUnexpectedValue("Field `" & fieldName & "` is missing")

  value =
    case v.`type`
    of Web3SignerRequestKind.AggregationSlot:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.AggregationSlot,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        aggregationSlot: expectedField(aggregation_slot),
      )
    of Web3SignerRequestKind.AggregateAndProof:
      let aggregate_and_proof = RestJson.decode(
        string expectedField(aggregate_and_proof), phase0.AggregateAndProof
      )

      Web3SignerRequest(
        kind: Web3SignerRequestKind.AggregateAndProof,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        aggregateAndProof: aggregate_and_proof,
      )
    of Web3SignerRequestKind.AggregateAndProofV2:
      let aggregate_and_proof = RestJson.decode(
        string expectedField(aggregate_and_proof), ForkedAggregateAndProof
      )
      Web3SignerRequest(
        kind: Web3SignerRequestKind.AggregateAndProofV2,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        forkedAggregateAndProof: aggregate_and_proof,
      )
    of Web3SignerRequestKind.Attestation:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.Attestation,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        attestation: expectedField(attestation),
      )
    of Web3SignerRequestKind.BlockV2:
      # https://github.com/ConsenSys/web3signer/blob/41834a927088f1bde7a097e17d19e954d0058e54/core/src/main/resources/openapi-specs/eth2/signing/schemas.yaml#L421-L425 (branch v22.7.0)
      # It's the "beacon_block" field even when it's not a block, but a header
      Web3SignerRequest(
        kind: Web3SignerRequestKind.BlockV2,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        beaconBlockHeader: expectedField(beacon_block),
        proofs: v.proofs,
      )
    of Web3SignerRequestKind.Deposit:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.Deposit,
        signingRoot: v.signingRoot,
        deposit: expectedField(deposit),
      )
    of Web3SignerRequestKind.RandaoReveal:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.RandaoReveal,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        randaoReveal: expectedField(randao_reveal),
      )
    of Web3SignerRequestKind.VoluntaryExit:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.VoluntaryExit,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        voluntaryExit: expectedField(voluntary_exit),
      )
    of Web3SignerRequestKind.SyncCommitteeMessage:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.SyncCommitteeMessage,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        syncCommitteeMessage: expectedField(sync_committee_message),
      )
    of Web3SignerRequestKind.SyncCommitteeSelectionProof:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.SyncCommitteeSelectionProof,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        syncAggregatorSelectionData: expectedField(sync_aggregator_selection_data),
      )
    of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.SyncCommitteeContributionAndProof,
        forkInfo: expectedForkInfo,
        signingRoot: v.signingRoot,
        syncCommitteeContributionAndProof: expectedField(contribution_and_proof),
      )
    of Web3SignerRequestKind.ValidatorRegistration:
      Web3SignerRequest(
        kind: Web3SignerRequestKind.ValidatorRegistration,
        signingRoot: v.signingRoot,
        validatorRegistration: expectedField(validator_registration),
      )

proc writeValue*(w: var RestJsonWriter, value: RemoteKeystoreStatus) {.writer.} =
  w.writeObject:
    w.writeField("status", $value.status)
    w.writeField("message", value.message)

proc readValue*(r: var RestJsonReader, value: var RemoteKeystoreStatus) {.reader.} =
  var message: Opt[string]
  var status: Opt[KeystoreStatus]

  for fieldName in readObjectFields(r):
    case fieldName
    of "message":
      if message.isSome():
        r.raiseUnexpectedField(
          "Multiple `message` fields found", "RemoteKeystoreStatus"
        )
      message = Opt.some(r.readValue(string))
    of "status":
      if status.isSome():
        r.raiseUnexpectedField("Multiple `status` fields found", "RemoteKeystoreStatus")
      let res = r.readValue(string)
      status = Opt.some(
        case res
        of "error":
          KeystoreStatus.error
        of "not_active":
          KeystoreStatus.notActive
        of "not_found":
          KeystoreStatus.notFound
        of "deleted":
          KeystoreStatus.deleted
        of "duplicate":
          KeystoreStatus.duplicate
        of "imported":
          KeystoreStatus.imported
        else:
          r.raiseUnexpectedValue("Invalid `status` value")
      )
    else:
      unrecognizedFieldWarning(fieldName, typeof(value).name)

  if status.isNone():
    r.raiseUnexpectedValue("Field `status` is missing")

  value = RemoteKeystoreStatus(status: status.get(), message: message)

proc readValue*(
    r: var RestJsonReader, value: var ScryptSalt
) {.raises: [SerializationError, IOError].} =
  let res =
    try:
      hexToSeqByte(r.readValue(string))
    except ValueError:
      r.raiseUnexpectedValue("Invalid scrypt salt value")

  if len(res) == 0:
    r.raiseUnexpectedValue("Invalid scrypt salt value")
  value = ScryptSalt(res)

proc writeValue*(w: var RestJsonWriter, value: Pbkdf2Params) {.writer.} =
  w.writeObject:
    w.writeField("dklen", JsonString(Base10.toString(value.dklen)))
    w.writeField("c", JsonString(Base10.toString(value.c)))
    w.writeField("prf", value.prf)
    w.writeField("salt", value.salt)

proc readValue*(
    r: var RestJsonReader, value: var Pbkdf2Params
) {.raises: [SerializationError, IOError].} =
  var
    dklen: Opt[uint64]
    c: Opt[uint64]
    prf: Opt[PrfKind]
    salt: Opt[Pbkdf2Salt]

  for fieldName in readObjectFields(r):
    case fieldName
    of "dklen":
      if dklen.isSome():
        r.raiseUnexpectedField("Multiple `dklen` fields found", "Pbkdf2Params")
      dklen = Opt.some(r.readValue(uint64))
    of "c":
      if c.isSome():
        r.raiseUnexpectedField("Multiple `c` fields found", "Pbkdf2Params")
      c = Opt.some(r.readValue(uint64))
    of "prf":
      if prf.isSome():
        r.raiseUnexpectedField("Multiple `prf` fields found", "Pbkdf2Params")
      prf = Opt.some(r.readValue(PrfKind))
    of "salt":
      if salt.isSome():
        r.raiseUnexpectedField("Multiple `salt` fields found", "Pbkdf2Params")
      salt = Opt.some(r.readValue(Pbkdf2Salt))
    else:
      unrecognizedFieldWarning(fieldName, typeof(value).name)

  if dklen.isNone():
    r.raiseUnexpectedValue("Field `dklen` is missing")
  if c.isNone():
    r.raiseUnexpectedValue("Field `c` is missing")
  if prf.isNone():
    r.raiseUnexpectedValue("Field `prf` is missing")
  if salt.isNone():
    r.raiseUnexpectedValue("Field `salt` is missing")

  value = Pbkdf2Params(dklen: dklen.get(), c: c.get(), prf: prf.get(), salt: salt.get())

proc writeValue*(w: var RestJsonWriter, value: ScryptParams) {.writer.} =
  w.writeObject:
    w.writeField("dklen", JsonString(Base10.toString(value.dklen)))
    w.writeField("n", JsonString(Base10.toString(uint64(value.n))))
    w.writeField("p", JsonString(Base10.toString(uint64(value.p))))
    w.writeField("r", JsonString(Base10.toString(uint64(value.r))))
    w.writeField("salt", value.salt)

proc readValue*(
    r: var RestJsonReader, value: var ScryptParams
) {.raises: [SerializationError, IOError].} =
  var
    dklen: Opt[uint64]
    n, p, rv: Opt[int]
    salt: Opt[ScryptSalt]

  for fieldName in readObjectFields(r):
    case fieldName
    of "dklen":
      if dklen.isSome():
        r.raiseUnexpectedField("Multiple `dklen` fields found", "ScryptParams")
      dklen = Opt.some(r.readValue(uint64))
    of "n":
      if n.isSome():
        r.raiseUnexpectedField("Multiple `n` fields found", "ScryptParams")
      let res = r.readValue(int)
      if res < 0:
        r.raiseUnexpectedValue("Unexpected negative `n` value")
      n = Opt.some(res)
    of "p":
      if p.isSome():
        r.raiseUnexpectedField("Multiple `p` fields found", "ScryptParams")
      let res = r.readValue(int)
      if res < 0:
        r.raiseUnexpectedValue("Unexpected negative `p` value")
      p = Opt.some(res)
    of "r":
      if rv.isSome():
        r.raiseUnexpectedField("Multiple `r` fields found", "ScryptParams")
      let res = r.readValue(int)
      if res < 0:
        r.raiseUnexpectedValue("Unexpected negative `r` value")
      rv = Opt.some(res)
    of "salt":
      if salt.isSome():
        r.raiseUnexpectedField("Multiple `salt` fields found", "ScryptParams")
      salt = Opt.some(r.readValue(ScryptSalt))
    else:
      unrecognizedFieldWarning(fieldName, typeof(value).name)

  if dklen.isNone():
    r.raiseUnexpectedValue("Field `dklen` is missing")
  if n.isNone():
    r.raiseUnexpectedValue("Field `n` is missing")
  if p.isNone():
    r.raiseUnexpectedValue("Field `p` is missing")
  if rv.isNone():
    r.raiseUnexpectedValue("Field `r` is missing")
  if salt.isNone():
    r.raiseUnexpectedValue("Field `salt` is missing")

  value = ScryptParams(
    dklen: dklen.get(), n: n.get(), p: p.get(), r: rv.get(), salt: salt.get()
  )

proc writeValue*(
  w: var RestJsonWriter, value: Keystore
) {.
  error:
    "keystores must be converted to json with Json.encode(keystore). " &
    "There is no REST-specific encoding"
.}

proc readValue*(
  r: var RestJsonReader, value: var Keystore
) {.
  error:
    "Keystores must be loaded with `parseKeystore`. " &
    "There is no REST-specific encoding"
.}

proc writeValue*(
    w: var RestJsonWriter, value: KeystoresAndSlashingProtection
) {.writer.} =
  let keystores = block:
    var res: seq[string]
    for keystore in value.keystores:
      let encoded = Json.encode(keystore)
      res.add(encoded)
    res

  w.writeObject:
    w.writeField("keystores", keystores)
    w.writeField("passwords", value.passwords)
    if value.slashing_protection.isSome():
      let slashingProtection = RestJson.encode(value.slashing_protection.get)
      w.writeField("slashing_protection", slashingProtection)

proc readValue*(
    r: var RestJsonReader, value: var KeystoresAndSlashingProtection
) {.raises: [SerializationError, IOError].} =
  var
    strKeystores: seq[string]
    passwords: seq[string]
    strSlashing: Opt[string]

  for fieldName in readObjectFields(r):
    case fieldName
    of "keystores":
      strKeystores = r.readValue(seq[string])
    of "passwords":
      passwords = r.readValue(seq[string])
    of "slashing_protection":
      if strSlashing.isSome():
        r.raiseUnexpectedField(
          "Multiple `slashing_protection` fields found",
          "KeystoresAndSlashingProtection",
        )
      strSlashing = Opt.some(r.readValue(string))
    else:
      unrecognizedFieldWarning(fieldName, typeof(value).name)

  if len(strKeystores) == 0:
    r.raiseUnexpectedValue("Missing or empty `keystores` value")
  if len(passwords) == 0:
    r.raiseUnexpectedValue("Missing or empty `passwords` value")

  let keystores = block:
    var res: seq[Keystore]
    for item in strKeystores:
      let key =
        try:
          parseKeystore(item)
        except SerializationError:
          # TODO re-raise the exception by adjusting the column index, so the user
          # will get an accurate syntax error within the larger message
          r.raiseUnexpectedValue("Invalid keystore format")
      res.add(key)
    res

  let slashing =
    if strSlashing.isSome():
      let db =
        try:
          RestJson.decode(strSlashing.get(), SPDIR)
        except SerializationError:
          r.raiseUnexpectedValue("Invalid slashing protection format")
      Opt.some(db)
    else:
      Opt.none(SPDIR)

  value = KeystoresAndSlashingProtection(
    keystores: keystores, passwords: passwords, slashing_protection: slashing
  )

proc writeValue*(w: var RestJsonWriter, value: RestNodeValidity) {.writer.} =
  w.writeValue($value)

proc readValue*(
    r: var RestJsonReader, value: var RestErrorMessage
) {.raises: [SerializationError, IOError].} =
  var
    code: Opt[int]
    message: Opt[string]
    stacktraces: Opt[seq[string]]

  for fieldName in readObjectFields(r):
    case fieldName
    of "code":
      if code.isSome():
        r.raiseUnexpectedField("Multiple `code` fields found", "RestErrorMessage")
      let ires =
        try:
          let res = r.readValue(int)
          if res < 0:
            r.raiseUnexpectedValue("Invalid `code` field value")
          Opt.some(res)
        except SerializationError:
          Opt.none(int)
      if ires.isNone():
        let sres =
          try:
            parseInt(r.readValue(string))
          except ValueError:
            r.raiseUnexpectedValue("Invalid `code` field format")
        if sres < 0:
          r.raiseUnexpectedValue("Invalid `code` field value")
        code = Opt.some(sres)
      else:
        code = ires
    of "message":
      if message.isSome():
        r.raiseUnexpectedField("Multiple `message` fields found", "RestErrorMessage")
      message = Opt.some(r.readValue(string))
    of "stacktraces":
      if stacktraces.isSome():
        r.raiseUnexpectedField(
          "Multiple `stacktraces` fields found", "RestErrorMessage"
        )
      stacktraces = Opt.some(r.readValue(seq[string]))
    else:
      unrecognizedFieldIgnore()

  if code.isNone():
    r.raiseUnexpectedValue("Missing or invalid `code` value")
  if message.isNone():
    r.raiseUnexpectedValue("Missing or invalid `message` value")

  value =
    RestErrorMessage(code: code.get(), message: message.get(), stacktraces: stacktraces)

proc writeValue*(w: var RestJsonWriter, value: RestErrorMessage) {.writer.} =
  w.writeObject:
    w.writeField("code", value.code)
    w.writeField("message", value.message)
    w.writeField("stacktraces", value.stacktraces)

proc readValue*(
    r: var RestJsonReader, value: var VCRuntimeConfig
) {.raises: [SerializationError, IOError].} =
  for fieldName in readObjectFields(r):
    let fieldValue =
      case toLowerAscii(fieldName)
      of "blob_schedule":
        string(r.readValue(JsonString))
      else:
        r.readValue(string)

    if value.hasKeyOrPut(toUpperAscii(fieldName), fieldValue):
      let msg = "Multiple `" & fieldName & "` fields found"
      r.raiseUnexpectedField(msg, "VCRuntimeConfig")

type VersionedMaybeBlindedBeaconBlock = object
  version: ConsensusFork
  execution_payload_blinded: bool
  execution_payload_value: UInt256
  consensus_block_value: Opt[UInt256]
  data: JsonString

RestJson.useDefaultSerializationFor VersionedMaybeBlindedBeaconBlock

proc readValue*(
    r: var RestJsonReader, value: var ProduceBlockResponseV3
) {.raises: [SerializationError, IOError].} =
  let v = r.readValue(VersionedMaybeBlindedBeaconBlock)

  # TODO (cheatfate): At some point we should add check for missing
  # `consensus_block_value`

  withConsensusFork(v.version):
    debugGloasComment "re-add gloas mev"
    value =
      when consensusFork >= ConsensusFork.Gloas:
        if v.execution_payload_blinded:
          r.raiseUnexpectedValue(
            &"`execution_payload_blinded` unsupported for {v.version}"
          )
        ForkedMaybeBlindedBeaconBlock.init(
          RestJson.decode(string(v.data), consensusFork.BlockContents)
        )
      elif consensusFork >= ConsensusFork.Electra:
        if v.execution_payload_blinded:
          ForkedMaybeBlindedBeaconBlock.init(
            RestJson.decode(string(v.data), consensusFork.BlindedBlockContents),
            Opt.some v.execution_payload_value,
            v.consensus_block_value,
          )
        else:
          ForkedMaybeBlindedBeaconBlock.init(
            RestJson.decode(string(v.data), consensusFork.BlockContents),
            Opt.some v.execution_payload_value,
            v.consensus_block_value,
          )
      elif consensusFork >= ConsensusFork.Bellatrix:
        if v.execution_payload_blinded:
          r.raiseUnexpectedValue(
            &"`execution_payload_blinded` unsupported for {v.version}"
          )
        ForkedMaybeBlindedBeaconBlock.init(
          RestJson.decode(string(v.data), consensusFork.BlockContents),
          Opt.some v.execution_payload_value,
          v.consensus_block_value,
        )
      else:
        if v.execution_payload_blinded:
          r.raiseUnexpectedValue(
            &"`execution_payload_blinded` unsupported for {v.version}"
          )
        ForkedMaybeBlindedBeaconBlock.init(
          RestJson.decode(string(v.data), consensusFork.BlockContents)
        )

proc writeValue*(w: var RestJsonWriter, value: ProduceBlockResponseV3) {.writer.} =
  w.writeObject:
    withForkyMaybeBlindedBlck(value):
      w.writeField("version", consensusFork.toString())
      w.writeField("execution_payload_blinded", isBlinded)
      if value.executionValue.isSome():
        w.writeField("execution_payload_value", $(value.executionValue.get()))
      if value.consensusValue.isSome():
        w.writeField("consensus_block_value", $(value.consensusValue.get()))
      w.writeField("data", forkyMaybeBlindedBlck)

proc writeValue*(w: var RestJsonWriter, value: GraffitiString) {.writer.} =
  w.writeValue($value)

proc readValue*(r: var RestJsonReader, T: type GraffitiString): T {.reader.} =
  let res = init(GraffitiString, r.readValue(string))
  if res.isErr():
    r.raiseUnexpectedValue res.error
  res.get

proc writeValue*(w: var RestJsonWriter, value: ValidatorIdent) {.writer.} =
  case value.kind
  of ValidatorQueryKind.Index:
    w.writeValue(value.index)
  of ValidatorQueryKind.Key:
    w.writeValue(value.key)

proc readValue*(r: var RestJsonReader, value: var ValidatorIdent) {.reader.} =
  value = ValidatorIdent.parse(r.readValue(string)).valueOr:
    r.raiseUnexpectedValue($error)

type RawRestValidatorRequest = object
  ids: Opt[seq[ValidatorIdent]]
  statuses: Opt[seq[string]]

RestJson.useDefaultSerializationFor RawRestValidatorRequest
proc readValue*(r: var RestJsonReader, value: var RestValidatorRequest) {.reader.} =
  let
    v = r.readValue(RawRestValidatorRequest)
    filter = block:
      if v.statuses.isSome():
        var res: ValidatorFilter
        for item in v.statuses.get():
          let value = ValidatorFilter.parse(item).valueOr:
            r.raiseUnexpectedValue($error)
          # Test for uniqueness of value.
          if value * res != {}:
            r.raiseUnexpectedValue(
              "The `statuses` array should consist of only unique values"
            )
          res.incl(value)
        Opt.some(res)
      else:
        Opt.none(ValidatorFilter)

  # Test for uniqueness of value will be happened on higher layer.
  value = RestValidatorRequest(ids: v.ids, status: filter)

proc writeValue*(w: var RestJsonWriter, value: RestValidatorRequest) {.writer.} =
  w.writeObject:
    w.writeField("ids", value.ids)
    if value.status.isSome():
      let res = value.status.get().toList()
      if len(res) > 0:
        w.writeField("statuses", res)

type VersionedAttestation = VersionedData

proc readValue*(r: var RestJsonReader, value: var ForkedAttestation) {.reader.} =
  let v = r.readValue(VersionedAttestation)
  if value.kind != v.version:
    value = ForkedAttestation(kind: v.version)

  try:
    withAttestation(value):
      forkyAttestation = RestJson.decode(string(v.data), typeof(forkyAttestation))
  except SerializationError as exc:
    r.raiseUnexpectedValue(
      &"""Incorrect {v.version} attestation format, [{exc.formatMsg("ForkedAttestation")}]"""
    )

proc writeValue*(w: var RestJsonWriter, value: ForkedAttestation) {.writer.} =
  w.writeObject:
    w.writeField("version", value.kind.toString())
    withAttestation(value):
      w.writeField("data", forkyAttestation)

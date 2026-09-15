# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronos, presto/client, stew/byteutils,
  web3/engine_api_types,
  ../spec/eth2_apis/rest_common,
  ../spec/[engine_authentication, engine_types],
  ./engine_rest_conversions

from std/times import getTime, toUnix
from eth/common/base import Bytes8, FixedBytes, to0xHex

export EngineFork

const
  EngineApiVersionHeader = "Eth-Execution-Version"

type
  EngineRestError* = object of CatchableError
    status*: int

  EngineRestClient* = ref object
    url: string
    jwtSecret: Opt[JwtSharedKey]
    client: Opt[RestClientRef]

func new*(T: type EngineRestClient,
          url: string, jwtSecret: Opt[JwtSharedKey]): T =
  T(url: url, jwtSecret: jwtSecret)

proc close*(c: EngineRestClient) {.async: (raises: []).} =
  if c.client.isSome:
    let client = c.client.get
    c.client = Opt.none(RestClientRef)
    await client.closeWait()

proc raiseEngineRestError(msg: string, status = 0) {.noreturn, raises: [EngineRestError].} =
  raise (ref EngineRestError)(msg: msg, status: status)

proc connected(c: EngineRestClient): RestClientRef
              {.raises: [EngineRestError].} =
  if c.client.isNone:
    let client = RestClientRef.new(c.url).valueOr:
      raiseEngineRestError("Invalid Engine REST API URL: " & $error)
    c.client = Opt.some(client)
  c.client.get

proc authHeaders(c: EngineRestClient): seq[(string, string)] =
  var res: seq[(string, string)]
  if c.jwtSecret.isSome:
    res.add ("Authorization",
      "Bearer " & getSignedIatToken(c.jwtSecret.get, getTime().toUnix()))
  return res

proc headers(c: EngineRestClient, fork: EngineFork): seq[(string, string)] =
  var res = @[(EngineApiVersionHeader, $fork)]
  res.add c.authHeaders
  return res

proc encodeBytes*[T: ForkchoiceUpdatePrague | ForkchoiceUpdateAmsterdam |
    ExecutionPayloadEnvelopeParis | ExecutionPayloadEnvelopeShanghai |
    ExecutionPayloadEnvelopeCancun | ExecutionPayloadEnvelopePrague |
    ExecutionPayloadEnvelopeAmsterdam | BlobsRequest | BlobsV4Request](
    value: T, contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/octet-stream":
    ok(SSZ.encode(value))
  else:
    err("Content-Type not supported")

proc postForkchoice(body: ForkchoiceUpdatePrague): RestPlainResponse {.
  rest, endpoint: "/engine/v1/forkchoice", meth: MethodPost.}
proc postForkchoice(body: ForkchoiceUpdateAmsterdam): RestPlainResponse {.
  rest, endpoint: "/engine/v1/forkchoice", meth: MethodPost.}

proc postPayload(body: ExecutionPayloadEnvelopeParis): RestPlainResponse {.
  rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayload(body: ExecutionPayloadEnvelopeShanghai): RestPlainResponse {.
  rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayload(body: ExecutionPayloadEnvelopeCancun): RestPlainResponse {.
  rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayload(body: ExecutionPayloadEnvelopePrague): RestPlainResponse {.
  rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayload(body: ExecutionPayloadEnvelopeAmsterdam): RestPlainResponse {.
  rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}

proc getPayloadById(payloadId: string): RestPlainResponse {.
  rest, endpoint: "/engine/v1/payloads/{payloadId}", meth: MethodGet.}

proc postBlobsV2(body: BlobsRequest): RestPlainResponse {.
  rest, endpoint: "/engine/v1/blobs/v2", meth: MethodPost.}
proc postBlobsV3(body: BlobsRequest): RestPlainResponse {.
  rest, endpoint: "/engine/v1/blobs/v3", meth: MethodPost.}
proc postBlobsV4(body: BlobsV4Request): RestPlainResponse {.
  rest, endpoint: "/engine/v1/blobs/v4", meth: MethodPost.}

proc decodeSsz(
    T: type, response: RestPlainResponse): T {.raises: [EngineRestError].} =
  if response.status != 200:
    raiseEngineRestError(
      "Engine REST API request failed: " & $response.status & " " &
        string.fromBytes(response.data.toOpenArray(
          0, min(response.data.len, 256) - 1)),
      response.status)
  if response.contentType.isNone() or
      response.contentType.get().mediaType != OctetStreamMediaType:
    raiseEngineRestError(
      "Engine REST API response is not SSZ: " &
        (if response.contentType.isSome(): $response.contentType.get().mediaType
         else: "missing Content-Type"),
      response.status)
  try:
    SSZ.decode(response.data, T)
  except SerializationError as exc:
    raiseEngineRestError(
      "Failed to decode Engine REST API response: " & exc.msg)

template engineFork*(T: type GetPayloadV4Response): EngineFork =
  EngineFork.Prague
template engineFork*(T: type GetPayloadV5Response): EngineFork =
  EngineFork.Osaka
template engineFork*(T: type GetPayloadV6Response): EngineFork =
  EngineFork.Amsterdam

proc forkchoiceUpdated*(
    c: EngineRestClient,
    state: ForkchoiceStateV1,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3] |
                       Opt[PayloadAttributesV4],
): Future[ForkchoiceUpdatedResponseV1] {.async: (raises: [CatchableError]).} =
  let response =
    when payloadAttributes is Opt[PayloadAttributesV4]:
      await c.connected.postForkchoice(
        ForkchoiceUpdateAmsterdam(
          forkchoice_state: state.toSsz,
          payload_attributes: payloadAttributes.toSszOptional),
        restContentType = $OctetStreamMediaType,
        restAcceptType = $OctetStreamMediaType,
        extraHeaders = c.headers(EngineFork.Amsterdam))
    else:
      await c.connected.postForkchoice(
        ForkchoiceUpdatePrague(
          forkchoice_state: state.toSsz,
          payload_attributes: payloadAttributes.toSszOptional),
        restContentType = $OctetStreamMediaType,
        restAcceptType = $OctetStreamMediaType,
        extraHeaders = c.headers(EngineFork.Osaka))

  decodeSsz(ForkchoiceUpdateResponse, response).toWeb3.valueOr:
    raiseEngineRestError(error)

proc newPayload*(
    c: EngineRestClient,
    fork: static EngineFork,
    payload: ExecutionPayloadV1 | ExecutionPayloadV2 |
             ExecutionPayloadV3 | ExecutionPayloadV4,
    parentBeaconBlockRoot = default(Hash32),
    executionRequests: seq[seq[byte]] = @[],
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  static:
    when fork == EngineFork.Paris:
      doAssert payload is ExecutionPayloadV1
    elif fork == EngineFork.Shanghai:
      doAssert payload is ExecutionPayloadV2
    elif fork == EngineFork.Amsterdam:
      doAssert payload is ExecutionPayloadV4
    else:
      doAssert payload is ExecutionPayloadV3

  let envelope =
    when fork == EngineFork.Paris or fork == EngineFork.Shanghai:
      payload.toSsz
    elif fork == EngineFork.Cancun:
      payload.toSsz(parentBeaconBlockRoot)
    else:
      payload.toSsz(parentBeaconBlockRoot, executionRequests)

  let response = await c.connected.postPayload(
    envelope,
    restContentType = $OctetStreamMediaType,
    restAcceptType = $OctetStreamMediaType,
    extraHeaders = c.headers(fork))

  decodeSsz(engine_types.PayloadStatus, response).toWeb3.valueOr:
    raiseEngineRestError(error)

proc getPayload*(
    c: EngineRestClient,
    T: type,
    payloadId: Bytes8,
): Future[T] {.async: (raises: [CatchableError]).} =
  let response = await c.connected.getPayloadById(
    payloadId.to0xHex(),
    restAcceptType = $OctetStreamMediaType,
    extraHeaders = c.headers(engineFork(T)))

  when T is GetPayloadV4Response:
    decodeSsz(BuiltPayloadPrague, response).toWeb3
  elif T is GetPayloadV5Response:
    decodeSsz(BuiltPayloadOsaka, response).toWeb3
  else:
    decodeSsz(BuiltPayloadAmsterdam, response).toWeb3

proc engine_getBlobsV2*(
    c: EngineRestClient,
    versionedHashes: seq[VersionedHash],
): Future[GetBlobsV2Response] {.async: (raises: [CatchableError]).} =
  let response = await c.connected.postBlobsV2(
    BlobsRequest(versioned_hashes: versionedHashes.toSsz),
    restContentType = $OctetStreamMediaType,
    restAcceptType = $OctetStreamMediaType,
    extraHeaders = c.authHeaders)

  decodeSsz(BlobsV2Response, response).toWeb3(GetBlobsV2Response).valueOr:
    raiseEngineRestError(error)

proc engine_getBlobsV3*(
    c: EngineRestClient,
    versionedHashes: seq[VersionedHash],
): Future[GetBlobsV3Response] {.async: (raises: [CatchableError]).} =
  let response = await c.connected.postBlobsV3(
    BlobsRequest(versioned_hashes: versionedHashes.toSsz),
    restContentType = $OctetStreamMediaType,
    restAcceptType = $OctetStreamMediaType,
    extraHeaders = c.authHeaders)

  decodeSsz(BlobsV2Response, response).toWeb3(GetBlobsV3Response).valueOr:
    raiseEngineRestError(error)

proc engine_getBlobsV4*(
    c: EngineRestClient,
    versionedHashes: seq[VersionedHash],
    indicesBitarray: FixedBytes[16],
): Future[GetBlobsV4Response] {.async: (raises: [CatchableError]).} =
  let response = await c.connected.postBlobsV4(
    BlobsV4Request(
      versioned_hashes: versionedHashes.toSsz,
      indices_bitarray: indicesBitarray.toSsz),
    restContentType = $OctetStreamMediaType,
    restAcceptType = $OctetStreamMediaType,
    extraHeaders = c.authHeaders)

  decodeSsz(BlobsV4Response, response).toWeb3

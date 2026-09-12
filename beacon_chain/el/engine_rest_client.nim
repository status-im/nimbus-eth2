# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/times,
  chronos, chronos/apps/http/httpclient, presto/client,
  ../spec/eth2_apis/[rest_common, eth2_rest_serialization],
  ../spec/engine_authentication,
  ../spec/engine_types

export chronos, client, engine_types

const
  EngineApiVersionHeader* = "Eth-Execution-Version"
  EngineApiClientVersionHeader* = "X-Engine-Client-Version"

proc encodeBytes[T](value: T, contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/octet-stream":
    ok(SSZ.encode(value))
  else:
    err("Content-Type not supported")

func toEngineApiForkString*(fork: EngineFork): string =
  case fork
  of EngineFork.Paris: "paris"
  of EngineFork.Shanghai: "shanghai"
  of EngineFork.Cancun: "cancun"
  of EngineFork.Prague: "prague"
  of EngineFork.Osaka: "osaka"
  of EngineFork.Amsterdam: "amsterdam"

proc engineJwtHeader*(jwtSecret: JwtSharedKey): seq[(string, string)] =
  @[("Authorization", "Bearer " & getSignedIatToken(jwtSecret, getTime().toUnix()))]

proc postForkchoiceRaw(body: ForkchoiceUpdateParis): RestPlainResponse
    {.rest, endpoint: "/engine/v1/forkchoice", meth: MethodPost.}
proc postForkchoiceRaw(body: ForkchoiceUpdateShanghai): RestPlainResponse
    {.rest, endpoint: "/engine/v1/forkchoice", meth: MethodPost.}
proc postForkchoiceRaw(body: ForkchoiceUpdateCancun): RestPlainResponse
    {.rest, endpoint: "/engine/v1/forkchoice", meth: MethodPost.}
proc postForkchoiceRaw(body: ForkchoiceUpdateAmsterdam): RestPlainResponse
    {.rest, endpoint: "/engine/v1/forkchoice", meth: MethodPost.}

proc postForkchoice*(client: RestClientRef, fork: EngineFork,
    body: ForkchoiceUpdateParis | ForkchoiceUpdateShanghai |
          ForkchoiceUpdateCancun | ForkchoiceUpdateAmsterdam,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.postForkchoiceRaw(body,
    restContentType = $OctetStreamMediaType,
    extraHeaders = @[(EngineApiVersionHeader, fork.toEngineApiForkString())] & extraHeaders)

proc postPayloadRaw(body: ExecutionPayloadEnvelopeParis): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayloadRaw(body: ExecutionPayloadEnvelopeShanghai): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayloadRaw(body: ExecutionPayloadEnvelopeCancun): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayloadRaw(body: ExecutionPayloadEnvelopePrague): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayloadRaw(body: ExecutionPayloadEnvelopeOsaka): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}
proc postPayloadRaw(body: ExecutionPayloadEnvelopeAmsterdam): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads", meth: MethodPost.}

proc postPayload*(client: RestClientRef, fork: EngineFork,
    body: ExecutionPayloadEnvelopeParis | ExecutionPayloadEnvelopeShanghai |
          ExecutionPayloadEnvelopeCancun | ExecutionPayloadEnvelopePrague |
          ExecutionPayloadEnvelopeOsaka | ExecutionPayloadEnvelopeAmsterdam,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.postPayloadRaw(body,
    restContentType = $OctetStreamMediaType,
    extraHeaders = @[(EngineApiVersionHeader, fork.toEngineApiForkString())] & extraHeaders)

proc getPayloadRaw(payloadId: string): RestPlainResponse
    {.rest, endpoint: "/engine/v1/payloads/{payloadId}", meth: MethodGet.}

proc getPayload*(client: RestClientRef, fork: EngineFork, payloadId: string,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.getPayloadRaw(payloadId,
    extraHeaders = @[(EngineApiVersionHeader, fork.toEngineApiForkString())] & extraHeaders)

proc postBodiesByHashRaw(body: BodiesByHashRequest): RestPlainResponse
    {.rest, endpoint: "/engine/v1/bodies/hash", meth: MethodPost.}

proc postBodiesByHash*(client: RestClientRef, fork: EngineFork,
    body: BodiesByHashRequest, extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.postBodiesByHashRaw(body,
    restContentType = $OctetStreamMediaType,
    extraHeaders = @[(EngineApiVersionHeader, fork.toEngineApiForkString())] & extraHeaders)

# GET /bodies?from=N&count=M can't go through the {.rest.} macro becausse of "from"
proc getBodiesByRange*(client: RestClientRef, fork: EngineFork,
    startBlock: uint64, blockCount: uint64,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, HttpError]).} =
  var address = client.address
  address.path = "/engine/v1/bodies"
  address.query = "from=" & $startBlock & "&count=" & $blockCount

  let headers = @[
    ("accept", $OctetStreamMediaType),
    ("user-agent", "nimbus-eth2"),
    (EngineApiVersionHeader, fork.toEngineApiForkString())] & extraHeaders

  let request = HttpClientRequestRef.new(
    client.session, address, MethodGet, headers = headers)
  let response = await request.send()
  let status = response.status
  let contentType = response.contentType
  let data = await response.getBodyBytes()
  await response.closeWait()
  RestPlainResponse(status: status, contentType: contentType,
    headers: response.headers, data: data)

proc postBlobsV1Raw(body: BlobsRequest): RestPlainResponse
    {.rest, endpoint: "/engine/v1/blobs/v1", meth: MethodPost.}
proc postBlobsV2Raw(body: BlobsRequest): RestPlainResponse
    {.rest, endpoint: "/engine/v1/blobs/v2", meth: MethodPost.}
proc postBlobsV3Raw(body: BlobsRequest): RestPlainResponse
    {.rest, endpoint: "/engine/v1/blobs/v3", meth: MethodPost.}

proc postBlobsV1*(client: RestClientRef, body: BlobsRequest,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.postBlobsV1Raw(body,
    restContentType = $OctetStreamMediaType, extraHeaders = extraHeaders)

proc postBlobsV2*(client: RestClientRef, body: BlobsRequest,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.postBlobsV2Raw(body,
    restContentType = $OctetStreamMediaType, extraHeaders = extraHeaders)

proc postBlobsV3*(client: RestClientRef, body: BlobsRequest,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.postBlobsV3Raw(body,
    restContentType = $OctetStreamMediaType, extraHeaders = extraHeaders)

proc getEngineIdentityRaw(): RestPlainResponse
    {.rest, endpoint: "/engine/v1/identity", meth: MethodGet.}
proc getEngineCapabilitiesRaw(): RestPlainResponse
    {.rest, endpoint: "/engine/v1/capabilities", meth: MethodGet.}

proc getEngineIdentity*(client: RestClientRef,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.getEngineIdentityRaw(extraHeaders = extraHeaders)

proc getEngineCapabilities*(client: RestClientRef,
    extraHeaders: seq[(string, string)] = @[]
    ): Future[RestPlainResponse] {.async: (raises: [CancelledError, RestEncodingError,
      RestDnsResolveError, RestCommunicationError]).} =
  await client.getEngineCapabilitiesRaw(extraHeaders = extraHeaders)

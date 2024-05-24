# beacon_chain
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos,
  results,
  stew/endians2,
  presto/client,
  ../helpers,
  "."/[rest_common, eth2_rest_serialization]

func checkForkConsistency(
    obj: SomeForkedLightClientObject,
    cfg: RuntimeConfig,
    consensusFork = err(Opt[ConsensusFork])) {.raises: [RestError].} =
  let objectFork = withForkyObject(obj):
    when lcDataFork > LightClientDataFork.None:
      cfg.consensusForkAtEpoch(forkyObject.contextEpoch)
    else:
      raiseRestDecodingBytesError("Invalid data")

  if lcDataForkAtConsensusFork(objectFork) != obj.kind:
    raiseRestDecodingBytesError(cstring("Inconsistent forks" &
      " (kind: " & $(obj.kind) & ", data: " & $objectFork & ")"))

  if consensusFork.isSome:
    if objectFork != consensusFork.get:
      raiseRestDecodingBytesError(cstring("Inconsistent forks" &
        " (header: " & $(consensusFork.get) & ", data: " & $objectFork & ")"))

func checkForkConsistency(
    obj: SomeForkedLightClientObject,
    cfg: RuntimeConfig,
    consensusFork: ConsensusFork) {.raises: [RestError].} =
  obj.checkForkConsistency(cfg, Opt[ConsensusFork].ok(consensusFork))

func decodeSszLightClientObject[T: SomeForkedLightClientObject](
    x: typedesc[T],
    data: openArray[byte],
    consensusFork: ConsensusFork,
    cfg: RuntimeConfig): T {.raises: [RestError].} =
  try:
    withLcDataFork(lcDataForkAtConsensusFork(consensusFork)):
      when lcDataFork > LightClientDataFork.None:
        var obj = T.init(SSZ.decode(data, T.Forky(lcDataFork)))
        obj.checkForkConsistency(cfg, consensusFork)
        obj
      else:
        raiseRestDecodingBytesError(
          cstring("Unsupported fork: " & $consensusFork))
  except SerializationError as exc:
    raiseRestDecodingBytesError(cstring("Malformed data: " & $exc.msg))

proc decodeJsonLightClientObject*[T: SomeForkedLightClientObject](
    x: typedesc[T],
    data: openArray[byte],
    consensusFork: Opt[ConsensusFork],
    cfg: RuntimeConfig): T {.raises: [RestError].} =
  let objRes = decodeBytes(T, data, Opt.none(ContentTypeData))
  if objRes.isErr:
    raiseRestDecodingBytesError(objRes.error)
  template obj: auto = objRes.get
  obj.checkForkConsistency(cfg, consensusFork)
  obj

proc decodeHttpLightClientObject*[T: SomeForkedLightClientObject](
    x: typedesc[T],
    data: openArray[byte],
    mediaType: MediaType,
    consensusFork: ConsensusFork,
    cfg: RuntimeConfig): T {.raises: [RestError].} =
  if mediaType == OctetStreamMediaType:
    x.decodeSszLightClientObject(data, consensusFork, cfg)
  elif mediaType == ApplicationJsonMediaType:
    x.decodeJsonLightClientObject(data, Opt.some(consensusFork), cfg)
  else:
    raise newException(RestError, "Unsupported content-type")

proc decodeHttpLightClientObject[T: SomeForkedLightClientObject](
    x: typedesc[T],
    data: openArray[byte],
    contentType: Opt[ContentTypeData],
    consensusFork: ConsensusFork,
    cfg: RuntimeConfig): T {.raises: [RestError].} =
  let mediaTypeRes = decodeMediaType(contentType)
  if mediaTypeRes.isErr:
    raise newException(RestError, mediaTypeRes.error)
  x.decodeHttpLightClientObject(data, mediaTypeRes.get, consensusFork, cfg)

proc decodeSszLightClientObjects[S: seq[SomeForkedLightClientObject]](
    x: typedesc[S],
    data: openArray[byte],
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests): S {.raises: [RestError].} =
  let l = data.len
  var
    res: S
    o = 0
  while l - o != 0:
    # response_chunk_len
    type chunkLenType = uint64
    const chunkLenLen = sizeof chunkLenType  # 8
    if l - o < chunkLenLen:
      raiseRestDecodingBytesError("Malformed data: Incomplete length")
    let responseChunkLen = chunkLenType.fromBytesLE(
      data.toOpenArray(o, o + chunkLenLen - 1))
    o = o + chunkLenLen

    # response_chunk
    if responseChunkLen > int.high.chunkLenType:
      raiseRestDecodingBytesError("Malformed data: Unsupported length")
    if l - o < responseChunkLen.int:
      raiseRestDecodingBytesError("Malformed data: Incomplete chunk")
    let
      begin = o
      after = o + responseChunkLen.int
    o += responseChunkLen.int

    # context
    const contextLen = sizeof ForkDigest  # 4
    if responseChunkLen < contextLen.chunkLenType:
      raiseRestDecodingBytesError("Malformed data: Incomplete context")
    let
      context = ForkDigest [
        data[begin + 0], data[begin + 1], data[begin + 2], data[begin + 3]]
      consensusFork = forkDigests[].consensusForkForDigest(context).valueOr:
        raiseRestDecodingBytesError("Malformed data: Invalid context")

    # payload
    try:
      withLcDataFork(lcDataForkAtConsensusFork(consensusFork)):
        when lcDataFork > LightClientDataFork.None:
          type T = typeof(res[0])
          var obj = T.init(SSZ.decode(
            data.toOpenArray(begin + contextLen, after - 1),
            T.Forky(lcDataFork)))
          obj.checkForkConsistency(cfg, consensusFork)
          res.add obj
        else:
          raiseRestDecodingBytesError(
            cstring("Unsupported fork: " & $consensusFork))
    except SerializationError as exc:
      raiseRestDecodingBytesError(cstring("Malformed data: " & $exc.msg))
  res

proc decodeJsonLightClientObjects[S: seq[SomeForkedLightClientObject]](
    x: typedesc[S],
    data: openArray[byte],
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests): S {.raises: [RestError].} =
  let objsRes = decodeBytes(S, data, Opt.none(ContentTypeData))
  if objsRes.isErr:
    raiseRestDecodingBytesError(objsRes.error)
  template objs: auto = objsRes.get
  for obj in objs:
    obj.checkForkConsistency(cfg)
  objs

proc decodeHttpLightClientObjects*[S: seq[SomeForkedLightClientObject]](
    x: typedesc[S],
    data: openArray[byte],
    mediaType: MediaType,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests): S {.raises: [RestError].} =
  if mediaType == OctetStreamMediaType:
    x.decodeSszLightClientObjects(data, cfg, forkDigests)
  elif mediaType == ApplicationJsonMediaType:
    x.decodeJsonLightClientObjects(data, cfg, forkDigests)
  else:
    raise newException(RestError, "Unsupported content-type")

proc decodeHttpLightClientObjects[S: seq[SomeForkedLightClientObject]](
    x: typedesc[S],
    data: openArray[byte],
    contentType: Opt[ContentTypeData],
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests): S {.raises: [RestError].} =
  let mediaTypeRes = decodeMediaType(contentType)
  if mediaTypeRes.isErr:
    raise newException(RestError, mediaTypeRes.error)
  x.decodeHttpLightClientObjects(data, mediaTypeRes.get, cfg, forkDigests)

proc getLightClientBootstrapPlain(
    block_root: Eth2Digest): RestHttpResponseRef {.
    rest, endpoint: "/eth/v1/beacon/light_client/bootstrap/{block_root}",
    accept: preferSSZ,
    meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getLightClientBootstrap

proc getLightClientBootstrap*(
    client: RestClientRef, block_root: Eth2Digest,
    cfg: RuntimeConfig, forkDigests: ref ForkDigests,
    restAccept = ""): Future[ForkedLightClientBootstrap] {.async.} =
  let resp =
    if len(restAccept) > 0:
      await client.getLightClientBootstrapPlain(
        block_root, restAcceptType = restAccept)
    else:
      await client.getLightClientBootstrapPlain(block_root)
  const maxBodyBytes = 128 * 1024
  let data = (await resp.getBodyBytesWithCap(maxBodyBytes)).valueOr:
    raiseRestDecodingBytesError("Response too long")
  return
    case resp.status
    of 200:
      let consensusForkRes = ConsensusFork.decodeString(
        resp.headers.getString("eth-consensus-version"))
      if consensusForkRes.isErr:
        raiseRestDecodingBytesError(consensusForkRes.error)
      ForkedLightClientBootstrap.decodeHttpLightClientObject(
        data, resp.contentType, consensusForkRes.get, cfg)
    of 404:
      default(ForkedLightClientBootstrap)
    of 400, 406, 500:
      let error =
        decodeBytes(RestErrorMessage, data, resp.contentType).valueOr:
          raiseRestDecodingBytesError(error)
      raise newException(RestError,
        "Error response (" & $resp.status & ") [" & error.message & "]")
    else:
      raiseRestResponseError(RestPlainResponse(
        status: resp.status,
        contentType: resp.contentType,
        data: data))

from ../../spec/network import MAX_REQUEST_LIGHT_CLIENT_UPDATES
export MAX_REQUEST_LIGHT_CLIENT_UPDATES

proc getLightClientUpdatesByRangePlain(
    start_period: SyncCommitteePeriod, count: uint64): RestHttpResponseRef {.
    rest, endpoint: "/eth/v1/beacon/light_client/updates",
    accept: preferSSZ,
    meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getLightClientUpdatesByRange

proc getLightClientUpdatesByRange*(
    client: RestClientRef, start_period: SyncCommitteePeriod, count: uint64,
    cfg: RuntimeConfig, forkDigests: ref ForkDigests,
    restAccept = ""): Future[seq[ForkedLightClientUpdate]] {.async.} =
  let resp =
    if len(restAccept) > 0:
      await client.getLightClientUpdatesByRangePlain(
        start_period, count, restAcceptType = restAccept)
    else:
      await client.getLightClientUpdatesByRangePlain(start_period, count)
  const maxBodyBytes = MAX_REQUEST_LIGHT_CLIENT_UPDATES * 128 * 1024
  let data = (await resp.getBodyBytesWithCap(maxBodyBytes)).valueOr:
    raiseRestDecodingBytesError("Response too long")
  return
    case resp.status
    of 200:
      seq[ForkedLightClientUpdate].decodeHttpLightClientObjects(
        data, resp.contentType, cfg, forkDigests)
    of 400, 406, 500:
      let error =
        decodeBytes(RestErrorMessage, data, resp.contentType).valueOr:
          raiseRestDecodingBytesError(error)
      raise newException(RestError,
        "Error response (" & $resp.status & ") [" & error.message & "]")
    else:
      raiseRestResponseError(RestPlainResponse(
        status: resp.status,
        contentType: resp.contentType,
        data: data))

proc getLightClientFinalityUpdatePlain(): RestHttpResponseRef {.
    rest, endpoint: "/eth/v1/beacon/light_client/finality_update",
    accept: preferSSZ,
    meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getLightClientFinalityUpdate

proc getLightClientFinalityUpdate*(
    client: RestClientRef,
    cfg: RuntimeConfig, forkDigests: ref ForkDigests,
    restAccept = ""): Future[ForkedLightClientFinalityUpdate] {.async.} =
  let resp =
    if len(restAccept) > 0:
      await client.getLightClientFinalityUpdatePlain(
        restAcceptType = restAccept)
    else:
      await client.getLightClientFinalityUpdatePlain()
  const maxBodyBytes = 128 * 1024
  let data = (await resp.getBodyBytesWithCap(maxBodyBytes)).valueOr:
    raiseRestDecodingBytesError("Response too long")
  return
    case resp.status
    of 200:
      let consensusForkRes = ConsensusFork.decodeString(
        resp.headers.getString("eth-consensus-version"))
      if consensusForkRes.isErr:
        raiseRestDecodingBytesError(consensusForkRes.error)
      ForkedLightClientFinalityUpdate.decodeHttpLightClientObject(
        data, resp.contentType, consensusForkRes.get, cfg)
    of 404:
      default(ForkedLightClientFinalityUpdate)
    of 406, 500:
      let error =
        decodeBytes(RestErrorMessage, data, resp.contentType).valueOr:
          raiseRestDecodingBytesError(error)
      raise newException(RestError,
        "Error response (" & $resp.status & ") [" & error.message & "]")
    else:
      raiseRestResponseError(RestPlainResponse(
        status: resp.status,
        contentType: resp.contentType,
        data: data))

proc getLightClientOptimisticUpdatePlain(): RestHttpResponseRef {.
    rest, endpoint: "/eth/v1/beacon/light_client/optimistic_update",
    accept: preferSSZ,
    meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getLightClientOptimisticUpdate

proc getLightClientOptimisticUpdate*(
    client: RestClientRef,
    cfg: RuntimeConfig, forkDigests: ref ForkDigests,
    restAccept = ""): Future[ForkedLightClientOptimisticUpdate] {.async.} =
  let resp =
    if len(restAccept) > 0:
      await client.getLightClientOptimisticUpdatePlain(
        restAcceptType = restAccept)
    else:
      await client.getLightClientOptimisticUpdatePlain()
  const maxBodyBytes = 128 * 1024
  let data = (await resp.getBodyBytesWithCap(maxBodyBytes)).valueOr:
    raiseRestDecodingBytesError("Response too long")
  return
    case resp.status
    of 200:
      let consensusForkRes = ConsensusFork.decodeString(
        resp.headers.getString("eth-consensus-version"))
      if consensusForkRes.isErr:
        raiseRestDecodingBytesError(consensusForkRes.error)
      ForkedLightClientOptimisticUpdate.decodeHttpLightClientObject(
        data, resp.contentType, consensusForkRes.get, cfg)
    of 404:
      default(ForkedLightClientOptimisticUpdate)
    of 406, 500:
      let error =
        decodeBytes(RestErrorMessage, data, resp.contentType).valueOr:
          raiseRestDecodingBytesError(error)
      raise newException(RestError,
        "Error response (" & $resp.status & ") [" & error.message & "]")
    else:
      raiseRestResponseError(RestPlainResponse(
        status: resp.status,
        contentType: resp.contentType,
        data: data))

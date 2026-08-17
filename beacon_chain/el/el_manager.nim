# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[json, macros],
  # Nimble packages:
  chronos, metrics, chronicles/timings,
  json_rpc/[client, errors],
  web3, web3/[engine_api, primitives, conversions],
  eth/common/eth_types,
  results,
  kzg4844/[kzg_abi, kzg],
  stew/objects,
  # Local modules:
  ../spec/[engine_authentication, forks, helpers_el],
  ../networking/network_metadata,
  "."/[el_conf, engine_api_conversions]

import ../spec/engine_types except
  PayloadStatus, BlobAndProofV2, Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD,
  BYTES_PER_CELL, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL, Blob,
  ExecutionRequests, KzgProof
import "."/engine_rest_client except connection, PayloadStatus, BlobAndProofV2
import "."/engine_rest_conversions except connection, PayloadStatus, BlobAndProofV2

from std/sequtils import anyIt, filterIt, mapIt
from std/times import getTime, toUnix
from std/typetraits import distinctBase
from ../spec/state_transition_block import kzg_commitment_to_versioned_hash

export
  el_conf, engine_api, base
export engine_types except
  PayloadStatus, BlobAndProofV2, Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD,
  BYTES_PER_CELL, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL, Blob,
  ExecutionRequests, KzgProof

logScope:
  topics = "elman"

const
  minBackoff = 10.millis
  maxBackoff = 160.millis

  # Engine API timeouts
  engineApiConnectionTimeout = 5.seconds  # How long we wait before giving up connecting to the Engine API
  web3RequestsTimeout = 8.seconds # How long we wait for eth_* requests

  multiTimeout = 1.seconds
    ## When multiple beacon nodes are connected, this is the amount of time we
    ## give them to respond, when looking for disagreements about valid and
    ## invalid blocks - we have to balance getting a response at all with the
    ## slowing down of all requests since the total request time will be based
    ## on the slowest response.

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/paris.md#request-2
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/shanghai.md#request-2
  GETPAYLOAD_TIMEOUT = 1.seconds

  # https://github.com/ethereum/execution-apis/blob/74feb592ce7b3a33fd8f6866d9464f8028c8a5e3/src/engine/osaka.md#request-1
  # https://github.com/ethereum/execution-apis/blob/74feb592ce7b3a33fd8f6866d9464f8028c8a5e3/src/engine/osaka.md#request-2
  GETBLOBS_TIMEOUT = 1.seconds

  connectionStateChangeHysteresisThreshold* = 15
    ## How many unsuccessful/successful requests we must see
    ## before declaring the connection as degraded/restored

type
  DeadlineFuture* = Future[void].Raising([CancelledError])

  SomeEnginePayloadWithValue =
    electra.ExecutionPayloadForSigning |
    fulu.ExecutionPayloadForSigning |
    gloas.ExecutionPayloadForSigning

  PayloadParams = object
    ## Parameters given to the latest payload-preparing forkChoiceParameters
    ## call - if all parameters match, we can use the payload id given in
    ## response, else we have to make a new call
    state: engine_types.ForkchoiceState
    attributes: engine_types.PayloadAttributesAmsterdam
      # Amsterdam is a superset of the earlier versions so we can use it for
      # cache equivalence purposes

  PayloadReq = tuple[params: PayloadParams, resp: Future[ForkchoiceUpdateResult]]

  ELManager* = ref object
    eth1Network: Opt[Eth1Network]
      ## If this value is supplied the EL manager will check whether
      ## all configured EL nodes are connected to the same network.

    elConnections: seq[ELConnection]
      ## All active EL connections

    checkChainIdLoopFut: Future[void]

  ChainIdStatus {.pure.} = enum
    notExchangedYet
    mismatch
    match

  ELConnectionState {.pure.} = enum
    NeverTested
    Working
    Degraded

  ELTransportKind {.pure.} = enum
    JsonRpc
    Rest

  ELConnection = ref object
    engineUrl: EngineApiUrl
    transport: ELTransportKind

    web3: Opt[Web3]
      ## This will be `none` before connecting and while we are
      ## reconnecting after a lost connection. You can wait on
      ## the future below for the moment the connection is active.
      ## Unused when `transport == Rest`.

    restClient: Opt[RestClientRef]

    connectingFut: Future[Result[Web3, string]].Raising([CancelledError])
      ## This future will be replaced when the connection is lost.
      ## Unused when `transport == Rest`.

    chainIdStatus: ChainIdStatus
      ## The latest status of the `checkChainId` exchange.

    state: ELConnectionState
    hysteresisCounter: int

    lastPayloadReq: PayloadReq
      ## Cache of the latest in-flight payload request with its parameters -
      ## when requesting payloads from the execution client, we expect that the
      ## block we receive in response will match the parameters we send as
      ## agreed based on the payload id.

declareCounter engine_api_responses,
  "Number of successful requests to the newPayload Engine API end-point",
  labels = ["url", "request", "status"]

declareHistogram engine_api_request_duration_seconds,
  "Time(s) used to generate signature using remote signer",
   buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
   labels = ["url", "request"]

declareCounter engine_api_timeouts,
  "Number of timed-out requests to Engine API end-point",
  labels = ["url", "request"]

declareCounter engine_api_last_minute_forkchoice_updates_sent,
  "Number of last minute requests to the forkchoiceUpdated Engine API end-point just before block proposals",
  labels = ["url"]

proc close(connection: ELConnection): Future[void] {.async: (raises: []).} =
  if connection.web3.isSome:
    try:
      let web3 = connection.web3.get
      await noCancel web3.close().wait(30.seconds)
    except AsyncTimeoutError:
      debug "Failed to close execution layer data provider in time",
            timeout = 30.seconds
    except CatchableError as exc:
      # TODO (cheatfate): This handler should be removed when `nim-web3` will
      # adopt `asyncraises`.
      debug "Failed to close execution layer", error = $exc.name,
            reason = $exc.msg

func increaseCounterTowardsStateChange(connection: ELConnection): bool =
  result = connection.hysteresisCounter >= connectionStateChangeHysteresisThreshold
  if result:
    connection.hysteresisCounter = 0
  else:
    inc connection.hysteresisCounter

func decreaseCounterTowardsStateChange(connection: ELConnection) =
  if connection.hysteresisCounter > 0:
    # While we increase the counter by 1, we decrease it by 20% in order
    # to require a steady and affirmative change instead of allowing
    # the counter to drift very slowly in one direction when the ratio
    # between success and failure is roughly 50:50%
    connection.hysteresisCounter = connection.hysteresisCounter div 5

proc setDegradedState(
    connection: ELConnection,
    requestName: string,
    statusCode: int,
    errMsg: string
): Future[void] {.async: (raises: []).} =
  debug "Failed EL Request", requestName, statusCode, err = errMsg
  case connection.state
  of ELConnectionState.NeverTested, ELConnectionState.Working:
    if connection.increaseCounterTowardsStateChange():
      warn "Connection to EL node degraded",
        url = url(connection.engineUrl),
        failedRequest = requestName,
        statusCode, err = errMsg

      connection.state = Degraded

      await connection.close()
      connection.web3 = Opt.none(Web3)
  of ELConnectionState.Degraded:
    connection.decreaseCounterTowardsStateChange()

proc setWorkingState(connection: ELConnection) =
  case connection.state
  of ELConnectionState.NeverTested:
    connection.hysteresisCounter = 0
    connection.state = Working
  of ELConnectionState.Degraded:
    if connection.increaseCounterTowardsStateChange():
      info "Connection to EL node restored",
        url = url(connection.engineUrl)
      connection.state = Working
  of ELConnectionState.Working:
    connection.decreaseCounterTowardsStateChange()

proc engineApiRequest[T](
    connection: ELConnection, request: Future[T], requestName: string, startTime: Moment
): Future[T] {.async: (raises: [CatchableError]).} =
  try:
    let res = await request
    engine_api_request_duration_seconds.observe(
      float(milliseconds(Moment.now - startTime)) / 1000.0,
      [connection.engineUrl.url, requestName],
    )
    engine_api_responses.inc(1, [connection.engineUrl.url, requestName, "200"])
    connection.setWorkingState()
    res
  except CancelledError as exc:
    # Cancellation is usually due to timeout
    engine_api_timeouts.inc(1, [connection.engineUrl.url, requestName])
    await connection.setDegradedState(requestName, 0, "Request timed out")
    raise exc
  except CatchableError as exc:
    let statusCode =
      if request.error of ErrorResponse:
        ((ref ErrorResponse) request.error).status
      else:
        0
    engine_api_responses.inc(1, [connection.engineUrl.url, requestName, $statusCode])
    await connection.setDegradedState(requestName, statusCode, request.error.msg)
    raise exc

func isConnected(connection: ELConnection): bool =
  connection.web3.isSome or connection.restClient.isSome

func getJsonRpcRequestHeaders(jwtSecret: Opt[JwtSharedKey]): auto =
  if jwtSecret.isSome:
    let secret = jwtSecret.get
    proc(): seq[(string, string)] =
      # https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1
      @[("Authorization", "Bearer " & getSignedIatToken(secret, getTime().toUnix()))]
  else:
    proc(): seq[(string, string)] =
      @[]

proc newWeb3*(engineUrl: EngineApiUrl): Future[Web3] =
  newWeb3(engineUrl.url,
          getJsonRpcRequestHeaders(engineUrl.jwtSecret), httpFlags = {})

proc establishEngineApiConnection(url: EngineApiUrl):
                                  Future[Result[Web3, string]] {.
                                  async: (raises: [CancelledError]).} =
  try:
    ok(await newWeb3(url).wait(engineApiConnectionTimeout))
  except AsyncTimeoutError:
    err "Engine API connection timed out"
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    err exc.msg

proc tryConnecting(connection: ELConnection): Future[bool] {.
     async: (raises: [CancelledError]).} =
  if connection.isConnected:
    return true

  if connection.transport == ELTransportKind.Rest:
    let clientRes = RestClientRef.new(connection.engineUrl.url)
    if clientRes.isErr:
      warn "Engine REST API connection failed", err = clientRes.error
      return false
    connection.restClient = Opt.some(clientRes.get)
    return true

  if connection.connectingFut == nil or
     connection.connectingFut.finished: # The previous attempt was not successful
    connection.connectingFut =
      establishEngineApiConnection(connection.engineUrl)

  let web3Res = await connection.connectingFut
  if web3Res.isErr:
    warn "Engine API connection failed", err = web3Res.error
    false
  else:
    let web3 = web3Res.get
    web3.onDisconnect = proc() =
      connection.web3.isErrOr:
        if value == web3:
          debug "Connection to EL node lost", url = url(connection.engineUrl)
          connection.web3 = Opt.none(Web3)
    connection.web3 = Opt.some(web3)
    true

proc connectedRpcClient(connection: ELConnection): Future[RpcClient] {.
     async: (raises: [CancelledError]).} =
  while not connection.isConnected:
    if not(await connection.tryConnecting()):
      await sleepAsync(chronos.seconds(10))

  connection.web3.get.provider

proc connectedRestClient(connection: ELConnection): Future[RestClientRef] {.
     async: (raises: [CancelledError]).} =
  while connection.restClient.isNone:
    if not(await connection.tryConnecting()):
      await sleepAsync(chronos.seconds(10))

  connection.restClient.get

template restHeaders(connection: ELConnection): seq[(string, string)] =
  restAuthHeaders(connection.engineUrl.jwtSecret)

# Transport-specific "send forkchoiceUpdated, decode the reply" helpers.
# Deliberately not `await`ed by their callers -- the returned future is
# meant to be stashed in `connection.lastPayloadReq` so a subsequent
# `getPayload` call for the same params can latch onto it instead of
# firing a redundant request, for either transport.
proc sendForkchoiceUpdatedRpc(
    rpcClient: RpcClient,
    state: ForkchoiceStateV1,
    payloadAttributes: Opt[PayloadAttributesV1] | Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3] | Opt[PayloadAttributesV4],
): Future[ForkchoiceUpdateResult] {.async: (raises: [CatchableError]).} =
  (await rpcClient.forkchoiceUpdated(state, payloadAttributes)).asConsensusType

proc sendForkchoiceUpdatedRest(
    client: RestClientRef,
    state: engine_types.ForkchoiceState,
    payloadAttributes: Opt[engine_types.PayloadAttributesParis] |
                       Opt[engine_types.PayloadAttributesShanghai] |
                       Opt[engine_types.PayloadAttributesCancun] |
                       Opt[engine_types.PayloadAttributesAmsterdam],
    headers: seq[(string, string)],
): Future[ForkchoiceUpdateResult] {.async: (raises: [CatchableError]).} =
  let resp =
    when payloadAttributes is Opt[engine_types.PayloadAttributesParis]:
      await client.postForkchoice(EngineFork.Paris, ForkchoiceUpdateParis(
        forkchoice_state: state,
        payload_attributes:
          if payloadAttributes.isSome: optSome(payloadAttributes.get)
          else: optNone(PayloadAttributesParis)),
        headers)
    elif payloadAttributes is Opt[engine_types.PayloadAttributesShanghai]:
      await client.postForkchoice(EngineFork.Shanghai, ForkchoiceUpdateShanghai(
        forkchoice_state: state,
        payload_attributes:
          if payloadAttributes.isSome: optSome(payloadAttributes.get)
          else: optNone(PayloadAttributesShanghai)),
        headers)
    elif payloadAttributes is Opt[engine_types.PayloadAttributesCancun]:
      await client.postForkchoice(EngineFork.Cancun, ForkchoiceUpdateCancun(
        forkchoice_state: state,
        payload_attributes:
          if payloadAttributes.isSome: optSome(payloadAttributes.get)
          else: optNone(PayloadAttributesCancun)),
        headers)
    else:
      await client.postForkchoice(EngineFork.Amsterdam, ForkchoiceUpdateAmsterdam(
        forkchoice_state: state,
        payload_attributes:
          if payloadAttributes.isSome: optSome(payloadAttributes.get)
          else: optNone(PayloadAttributesAmsterdam),
        custody_columns: optNone(BitArray[engine_types.CELLS_PER_EXT_BLOB])),
        headers)
  decodeSszResponse(ForkchoiceUpdateResponse, resp).asConsensusType

template retryUntilCancelled(body: untyped) =
  ## Perform the same request in a loop until it is explicitly cancelled,
  ## usually due to a timeout.
  ##
  ## When we make the request, the connection might have died for unrelated
  ## reasons and we only get to know this when we try to use the connection -
  ## instead of waiting for the next round of communication, retry the same
  ## request if there is time.

  # Don't retry on already-degraded connections to prevent a single broken
  # connection from slowing down all requests indefinately
  let retry = retry and connection.state != ELConnectionState.Degraded
  var
    lastError: ref CatchableError
    backoff = minBackoff
  while true:
    try:
      body
    except CancelledError as exc:
      if lastError != nil:
        raise lastError
      raise exc
    except CatchableError as exc:
      if not retry:
        raise exc

      lastError = exc

    await sleepAsync(backoff)

    if backoff < maxBackoff: # Exponential backoff
      backoff = backoff * 2

template EngineApiResponseType(T: type electra.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV4Response

template EngineApiResponseType(T: type fulu.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV5Response

template EngineApiResponseType(T: type gloas.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV6Response

proc getPayload(
    connection: ELConnection,
    PayloadType: type,
    params: PayloadParams,
    payloadAttributes: engine_types.PayloadAttributesCancun |
                       engine_types.PayloadAttributesAmsterdam,
    retry: bool,
): Future[PayloadType] {.async: (raises: [CatchableError]).} =
  template payloadReq(): auto =
    connection.lastPayloadReq

  var
    payload: PayloadType
    payloadId: Bytes8

  let webPayloadAttributes = payloadAttributes.asWeb3
  retryUntilCancelled:
    let
      # Use prepared payload if it was given or still pending; otherwise make a
      # new request. `safeBlockHash` and `finalizedBlockHash` are intentionally
      # excluded, because the payload depends on neither and the FCR safe block
      # typically change between when the payload preparation was requested and
      # getPayload is sent. This applies to both transports: `lastPayloadReq`
      # holds a transport-agnostic `Future[ForkchoiceUpdateResult]`.
      useLastPayload =
        payloadReq.resp != nil and
        payloadReq.params.state.head_block_hash == params.state.head_block_hash and
        payloadReq.params.attributes == params.attributes and
        (not payloadReq.resp.finished or (payloadReq.resp.completed and
           payloadReq.resp.value().payloadId.isSome()))

      fcu = await(
        if useLastPayload:
          payloadReq.resp
        else:
          engine_api_last_minute_forkchoice_updates_sent.inc(
            1, [connection.engineUrl.url]
          )
          notice "Payload not prepared, sending last-minute payload request",
            url = connection.engineUrl.url

          if connection.transport == ELTransportKind.Rest:
            let client = await connection.connectedRestClient()
            client.sendForkchoiceUpdatedRest(
              params.state, Opt.some(payloadAttributes), connection.restHeaders)
          else:
            let rpcClient = await connection.connectedRpcClient()
            rpcClient.sendForkchoiceUpdatedRpc(
              params.state.asWeb3, Opt.some webPayloadAttributes)
      )

    payloadId = fcu.payloadId.valueOr:
      warn "Execution client did not return payload id",
        url = connection.engineUrl.url, status = fcu.payloadStatus.status
      raise newException(
        CatchableError,
        "No payload id given: " & $fcu.payloadStatus.status,
      )

    if not useLastPayload:
      # Give the EL some time to build the block
      await sleepAsync(500.milliseconds)

    if connection.transport == ELTransportKind.Rest:
      let
        client = await connection.connectedRestClient()
        fork =
          when PayloadType is electra.ExecutionPayloadForSigning: EngineFork.Prague
          elif PayloadType is fulu.ExecutionPayloadForSigning: EngineFork.Osaka
          else: EngineFork.Amsterdam
        payloadResp = await client.getPayload(
          fork, payloadId.to0xHex(), connection.restHeaders)

      payload =
        when PayloadType is electra.ExecutionPayloadForSigning:
          decodeSszResponse(BuiltPayloadPrague, payloadResp).asConsensusType
        elif PayloadType is fulu.ExecutionPayloadForSigning:
          decodeSszResponse(BuiltPayloadOsaka, payloadResp).asConsensusType
        else:
          decodeSszResponse(BuiltPayloadAmsterdam, payloadResp).asConsensusType
    else:
      let rpcClient = await connection.connectedRpcClient()
      payload = (await rpcClient.getPayload(
        EngineApiResponseType(PayloadType), payloadId)).asConsensusType

    break # retryUntilCancelled

  # Check that the execution payload matches the attributes we asked for, as
  # aggreed per payload id - this is done outside of the retry loop to avoid
  # re-requesting from a faulty client
  if payload.executionPayload.extra_data.len > MAX_EXTRA_DATA_BYTES:
    warn "Execution client payload with extraData exceeding limit",
      url = connection.engineUrl.url,
      payloadId,
      size = payload.executionPayload.extra_data.len,
      limit = MAX_EXTRA_DATA_BYTES
    raise newException(CatchableError, "Execution payload extraData exceeds max size")

  let elWithdrawals =
    when PayloadType is gloas.ExecutionPayloadForSigning:
      payload.executionPayload.withdrawals
    else:
      payload.executionPayload.withdrawals.asSeq

  if params.attributes.withdrawals.asSeq != elWithdrawals:
    warn "Execution client returned unexpected payload withdrawals",
      url = connection.engineUrl.url,
      payloadId,
      withdrawals_from_cl_len = params.attributes.withdrawals.len,
      withdrawals_from_el_len = elWithdrawals.len,
      withdrawals_from_cl = params.attributes.withdrawals.asSeq,
      withdrawals_from_el = elWithdrawals
    raise newException(
      CatchableError, "Execution client returned mismatching withdrawals"
    )

  payload

func init(
    T: type PayloadParams, state: engine_types.ForkchoiceState,
    attributes: engine_types.PayloadAttributesParis
): T =
  PayloadParams(
    state: state,
    attributes: engine_types.PayloadAttributesAmsterdam(
      timestamp: attributes.timestamp,
      prev_randao: attributes.prev_randao,
      suggested_fee_recipient: attributes.suggested_fee_recipient,
      withdrawals: default(List[capella.Withdrawal, Limit 16]),
      parent_beacon_block_root: default(Eth2Digest),
      slot_number: FAR_FUTURE_SLOT.uint64
    ),
  )

func init(
    T: type PayloadParams, state: engine_types.ForkchoiceState,
    attributes: engine_types.PayloadAttributesShanghai
): T =
  PayloadParams(
    state: state,
    attributes: engine_types.PayloadAttributesAmsterdam(
      timestamp: attributes.timestamp,
      prev_randao: attributes.prev_randao,
      suggested_fee_recipient: attributes.suggested_fee_recipient,
      withdrawals: attributes.withdrawals,
      parent_beacon_block_root: default(Eth2Digest),
      slot_number: FAR_FUTURE_SLOT.uint64
    ),
  )

func init(
    T: type PayloadParams, state: engine_types.ForkchoiceState,
    attributes: engine_types.PayloadAttributesCancun
): T =
  PayloadParams(
    state: state,
    attributes: engine_types.PayloadAttributesAmsterdam(
      timestamp: attributes.timestamp,
      prev_randao: attributes.prev_randao,
      suggested_fee_recipient: attributes.suggested_fee_recipient,
      withdrawals: attributes.withdrawals,
      parent_beacon_block_root: attributes.parent_beacon_block_root,
      slot_number: FAR_FUTURE_SLOT.uint64
    ),
  )

func init(
    T: type PayloadParams, state: engine_types.ForkchoiceState,
    attributes: engine_types.PayloadAttributesAmsterdam
): T =
  PayloadParams(state: state, attributes: attributes)

proc getPayload*(
    m: ELManager,
    PayloadType: type ForkyExecutionPayloadForSigning,
    state: engine_types.ForkchoiceState,
    payloadAttributes: engine_types.PayloadAttributesCancun |
                       engine_types.PayloadAttributesAmsterdam,
): Future[Opt[PayloadType]] {.async: (raises: [CancelledError]).} =
  if m.elConnections.len == 0:
    notice "No engine configured, using empty payload"
    return Opt.none(PayloadType)

  let params = PayloadParams.init(state, payloadAttributes)

  # `getPayloadFromSingleEL` may introduce additional latency
  const extraProcessingOverhead = 500.milliseconds
  let deadline = sleepAsync(GETPAYLOAD_TIMEOUT + extraProcessingOverhead)

  let requests = m.elConnections.mapIt(
    it.getPayload(PayloadType, params, payloadAttributes, true)
  )
  defer:
    # In case any request didn't complete on time
    await cancelAndWait(requests)

  discard await race(allFutures(requests), deadline)

  # Of the payloads that arrived on time, select the one with the highest
  # block value
  func betterThan(a, b: SomeEnginePayloadWithValue): bool =
    a.blockValue > b.blockValue

  var bestPayloadIdx = Opt.none(int)
  for idx, req in requests:
    if req.completed():
      if bestPayloadIdx.isNone() or
          req.value().betterThan(requests[bestPayloadIdx.get].value()):
        bestPayloadIdx = Opt.some(idx)
    elif req.failed():
      warn "Failed to get execution payload from EL",
        url = m.elConnections[idx].engineUrl.url, reason = req.error.msg
    else:
      warn "Timeout while getting execution payload",
        url = m.elConnections[idx].engineUrl.url

  if bestPayloadIdx.isSome():
    ok(requests[bestPayloadIdx.get()].value())
  else:
    Opt.none(PayloadType)

proc newPayload(
    connection: ELConnection, payload: bellatrix.ExecutionPayload, retry: bool
): Future[EnginePayloadStatus] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    if connection.transport == ELTransportKind.Rest:
      let
        client = await connection.connectedRestClient()
        resp = await client.postPayload(
          EngineFork.Paris, payload.asSszEnvelope(), connection.restHeaders)
      return decodeSszResponse(engine_types.PayloadStatus, resp).asConsensusType
    let rpcClient = await connection.connectedRpcClient()
    return (await rpcClient.engine_newPayloadV1(
      payload.asEngineExecutionPayload())).asConsensusType

proc newPayload(
    connection: ELConnection, payload: capella.ExecutionPayload, retry: bool
): Future[EnginePayloadStatus] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    if connection.transport == ELTransportKind.Rest:
      let
        client = await connection.connectedRestClient()
        resp = await client.postPayload(
          EngineFork.Shanghai, payload.asSszEnvelope(), connection.restHeaders)
      return decodeSszResponse(engine_types.PayloadStatus, resp).asConsensusType
    let rpcClient = await connection.connectedRpcClient()
    return (await rpcClient.engine_newPayloadV2(
      payload.asEngineExecutionPayload())).asConsensusType

proc newPayload(
    connection: ELConnection,
    payload: deneb.ExecutionPayload,
    versioned_hashes: seq[Eth2Digest],
    parent_beacon_block_root: Eth2Digest,
    retry: bool,
): Future[EnginePayloadStatus] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    if connection.transport == ELTransportKind.Rest:
      let
        client = await connection.connectedRestClient()
        resp = await client.postPayload(EngineFork.Cancun,
          payload.asSszEnvelope(parent_beacon_block_root), connection.restHeaders)
      return decodeSszResponse(engine_types.PayloadStatus, resp).asConsensusType
    let rpcClient = await connection.connectedRpcClient()
    return (await rpcClient.engine_newPayloadV3(
      payload.asEngineExecutionPayload(), versioned_hashes.asWeb3,
      parent_beacon_block_root.asBlockHash)).asConsensusType

proc newPayload(
    connection: ELConnection,
    payload: deneb.ExecutionPayload,
    versioned_hashes: seq[Eth2Digest],
    parent_beacon_block_root: Eth2Digest,
    executionRequests: seq[seq[byte]],
    retry: bool,
): Future[EnginePayloadStatus] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    if connection.transport == ELTransportKind.Rest:
      let
        client = await connection.connectedRestClient()
        resp = await client.postPayload(EngineFork.Prague,
          payload.asSszEnvelopePrague(parent_beacon_block_root, executionRequests),
          connection.restHeaders)
      return decodeSszResponse(engine_types.PayloadStatus, resp).asConsensusType
    let rpcClient = await connection.connectedRpcClient()
    return (await rpcClient.engine_newPayloadV4(
      payload.asEngineExecutionPayload(), versioned_hashes.asWeb3,
      parent_beacon_block_root.asBlockHash, executionRequests)).asConsensusType

proc newPayload(
    connection: ELConnection,
    payload: gloas.ExecutionPayload,
    versioned_hashes: seq[Eth2Digest],
    parent_beacon_block_root: Eth2Digest,
    executionRequests: seq[seq[byte]],
    retry: bool,
): Future[EnginePayloadStatus] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    if connection.transport == ELTransportKind.Rest:
      let
        client = await connection.connectedRestClient()
        resp = await client.postPayload(EngineFork.Amsterdam,
          payload.asSszEnvelope(parent_beacon_block_root, executionRequests),
          connection.restHeaders)
      return decodeSszResponse(engine_types.PayloadStatus, resp).asConsensusType
    let rpcClient = await connection.connectedRpcClient()
    return (await rpcClient.engine_newPayloadV5(
      payload.asEngineExecutionPayload(), versioned_hashes.asWeb3,
      parent_beacon_block_root.asBlockHash, executionRequests)).asConsensusType

proc getBlobsV2(
    connection: ELConnection,
    versioned_hashes: seq[Eth2Digest]
): Future[seq[engine_types.BlobAndProofV2]] {.async: (raises: [CatchableError]).} =
  if connection.transport == ELTransportKind.Rest:
    let
      client = await connection.connectedRestClient()
      body = BlobsRequest(versioned_hashes: versioned_hashes.asSszType)
      resp = await client.postBlobsV2(body, connection.restHeaders)
    return decodeSszResponse(BlobsV2Response, resp).asConsensusType

  let rpcClient = await connection.connectedRpcClient()
  (await rpcClient.engine_getBlobsV2(versioned_hashes.asWeb3)).asConsensusType

proc getBlobsV3(
    connection: ELConnection,
    versioned_hashes: seq[Eth2Digest]
): Future[seq[Opt[engine_types.BlobAndProofV2]]] {.async: (raises: [CatchableError]).} =
  if connection.transport == ELTransportKind.Rest:
    let
      client = await connection.connectedRestClient()
      body = BlobsRequest(versioned_hashes: versioned_hashes.asSszType)
      resp = await client.postBlobsV3(body, connection.restHeaders)
    return decodeSszResponse(BlobsV3Response, resp).asConsensusType

  let rpcClient = await connection.connectedRpcClient()
  (await rpcClient.engine_getBlobsV3(versioned_hashes.asWeb3)).asConsensusType

type
  StatusRelation = enum
    newStatusIsPreferable
    oldStatusIsOk
    disagreement

func compareStatuses(
    newStatus, prevStatus: PayloadStatusCode
): StatusRelation =
  case prevStatus
  of PayloadStatusCode.SYNCING:
    if newStatus == PayloadStatusCode.SYNCING:
      oldStatusIsOk
    else:
      newStatusIsPreferable

  of PayloadStatusCode.VALID:
    case newStatus
    of PayloadStatusCode.SYNCING,
       PayloadStatusCode.ACCEPTED,
       PayloadStatusCode.VALID:
      oldStatusIsOk
    of PayloadStatusCode.INVALID_BLOCK_HASH,
       PayloadStatusCode.INVALID:
      disagreement

  of PayloadStatusCode.INVALID:
    case newStatus
    of PayloadStatusCode.SYNCING,
       PayloadStatusCode.INVALID:
      oldStatusIsOk
    of PayloadStatusCode.VALID,
       PayloadStatusCode.ACCEPTED,
       PayloadStatusCode.INVALID_BLOCK_HASH:
      disagreement

  of PayloadStatusCode.ACCEPTED:
    case newStatus
    of PayloadStatusCode.ACCEPTED,
       PayloadStatusCode.SYNCING:
      oldStatusIsOk
    of PayloadStatusCode.VALID:
      newStatusIsPreferable
    of PayloadStatusCode.INVALID_BLOCK_HASH,
       PayloadStatusCode.INVALID:
      disagreement

  of PayloadStatusCode.INVALID_BLOCK_HASH:
    if newStatus == PayloadStatusCode.INVALID_BLOCK_HASH:
      oldStatusIsOk
    else:
      disagreement

type
  ELConsensusViolationDetector = object
    selectedResponse: Opt[int]
    selectedStatus: Opt[PayloadStatusCode]
    disagreementAlreadyDetected: bool

func init(T: type ELConsensusViolationDetector): T =
  ELConsensusViolationDetector(
    selectedResponse: Opt.none(int),
    selectedStatus: Opt.none(PayloadStatusCode),
    disagreementAlreadyDetected: false
  )

proc hasDisagreement(
    d: var ELConsensusViolationDetector,
    elResponseType: typedesc,
    connections: openArray[ELConnection],
    requests: auto,
    req: auto,
): bool =
  if not req.completed:
    return false

  let idx = requests.find(req)
  doAssert idx != -1, "must find request in list"

  let status = requests[idx].value().status
  if d.selectedResponse.isNone:
    d.selectedResponse = Opt.some(idx)
    d.selectedStatus = Opt.some(status)
  elif not d.disagreementAlreadyDetected:
    let prevStatus = requests[d.selectedResponse.get].value().status
    case compareStatuses(status, prevStatus)
    of newStatusIsPreferable:
      d.selectedResponse = Opt.some(idx)
      d.selectedStatus = Opt.some(status)
    of oldStatusIsOk:
      discard
    of disagreement:
      d.disagreementAlreadyDetected = true
      error "Execution layer consensus violation detected",
            responseType = name(elResponseType),
            url1 = connections[d.selectedResponse.get].engineUrl.url,
            status1 = prevStatus,
            url2 = connections[idx].engineUrl.url,
            status2 = status
  d.disagreementAlreadyDetected

proc lazyWait[T: FutureBase](futures: seq[T], deadline: DeadlineFuture) {.async: (raises: []).} =
  try:
    discard await race(allFutures(futures), deadline)
  except CancelledError:
    discard

  await cancelAndWait(futures)

proc firstOrCancel[T; U: Future[T]](
    requests: sink seq[U], deadline: DeadlineFuture
): Future[Opt[T]] {.async: (raises: [CancelledError]).} =
  defer:
    await cancelAndWait(requests)

  while requests.len > 0:
    # Wait for at least one requests or deadline to finish
    discard await race(race(requests), deadline)

    requests = requests.filterIt:
      if it.completed: # First successful response wins
        return ok it.value()
      if it.failed:
        debug "Execution client request failed", error = it.error().msg

      not it.finished

    if deadline.finished:
      break

  Opt.none(T)

proc getBlobsV2*(
    m: ELManager, blck: fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
): Future[Opt[seq[engine_types.BlobAndProofV2]]]
    {.async: (raises: [CancelledError], raw: true).} =
  mixin getBlobsV2

  template kzg_commitments(): auto =
    when typeof(blck).kind >= ConsensusFork.Gloas:
      blck.message.body.signed_execution_payload_bid.message.blob_kzg_commitments
    else:
      blck.message.body.blob_kzg_commitments

  let deadline = sleepAsync(GETBLOBS_TIMEOUT)

  m.elConnections
    .mapIt(
      it.getBlobsV2(
        kzg_commitments.mapIt(kzg_commitment_to_versioned_hash(it).asEth2Digest)
      )
    )
    .firstOrCancel(deadline)

proc getBlobsV2*(
    m: ELManager, kzg_commitments: deneb.KzgCommitments
): Future[Opt[seq[engine_types.BlobAndProofV2]]]
    {.async: (raises: [CancelledError], raw: true).} =
  ## Variant used by the column-first sidecar retrieval path: derives
  ## versioned hashes from `kzg_commitments` directly, without requiring the
  ## block (which has not yet been seen via gossip).
  mixin getBlobsV2

  let deadline = sleepAsync(GETBLOBS_TIMEOUT)

  m.elConnections
    .mapIt(
      it.getBlobsV2(
        kzg_commitments.mapIt(kzg_commitment_to_versioned_hash(it).asEth2Digest)
      )
    )
    .firstOrCancel(deadline)

proc getBlobsV3*(
    m: ELManager, blck: fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
): Future[Opt[seq[Opt[engine_types.BlobAndProofV2]]]] {.
    async: (raises: [CancelledError], raw: true)
.} =
  mixin getBlobsV3

  template kzg_commitments(): auto =
    when typeof(blck).kind >= ConsensusFork.Gloas:
      blck.message.body.signed_execution_payload_bid.message.blob_kzg_commitments
    else:
      blck.message.body.blob_kzg_commitments

  let deadline = sleepAsync(GETBLOBS_TIMEOUT)
  m.elConnections
    .mapIt(
      it.getBlobsV3(
        kzg_commitments.mapIt(kzg_commitment_to_versioned_hash(it).asEth2Digest)
      )
    )
    .firstOrCancel(deadline)

template sendNewPayload(payload: untyped; args: varargs[untyped]): untyped =
  if m.elConnections.len == 0:
    info "No execution client configured; cannot process block payloads"
    Opt.none(PayloadStatusCode)
  else:
    let startTime = Moment.now()
    var
      res = Opt.none PayloadStatusCode
      responseProcessor = ELConsensusViolationDetector.init()
    let requests = m.elConnections.mapIt:
      let req = unpackVarargs(it.newPayload, payload, args)
      it.engineApiRequest(req, "newPayload", startTime)
    var pending = requests
    let earlyDeadline = sleepAsync(multiTimeout)

    defer:
      await cancelAndWait(pending)

    while pending.len > 0:
      try:
        if responseProcessor.selectedResponse.isSome():
          discard await race(race(pending), earlyDeadline)
        else:
          discard await race(race(pending), deadline)
      except ValueError:
        raiseAssert "race error cannot happen"

      if pending.anyIt responseProcessor.hasDisagreement(
          EnginePayloadStatus, m.elConnections, requests, it):
        res.ok PayloadStatusCode.INVALID
        break

      pending = pending.filterIt(not it.finished)

      if earlyDeadline.finished and responseProcessor.selectedResponse.isSome():
        # At the early deadline, select the best response we've received so far
        if pending.len > 0:
          # Let the other requests run their course so they receive the update
          asyncSpawn lazyWait(pending, deadline)
          reset pending
        break

      if deadline.finished:
        break

    if res.isNone and responseProcessor.selectedResponse.isSome():
      res.ok requests[responseProcessor.selectedResponse.get].value().status
    res

proc newPayload(
    m: ELManager,
    payload: bellatrix.ExecutionPayload | capella.ExecutionPayload,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadStatusCode]] {.async: (raises: [CancelledError]).} =
  sendNewPayload(payload, retry)

proc newPayload(
    m: ELManager,
    payload: deneb.ExecutionPayload,
    blob_versioned_hashes: seq[Eth2Digest],
    parent_root: Eth2Digest,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadStatusCode]] {.async: (raises: [CancelledError]).} =
  sendNewPayload(payload, blob_versioned_hashes, parent_root, retry)

proc newPayload(
    m: ELManager,
    payload: deneb.ExecutionPayload | gloas.ExecutionPayload,
    blob_versioned_hashes: seq[Eth2Digest],
    parent_root: Eth2Digest,
    execution_requests: seq[seq[byte]],
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadStatusCode]] {.async: (raises: [CancelledError]).} =
  sendNewPayload(
    payload, blob_versioned_hashes, parent_root, execution_requests, retry)

proc newPayload*(
    m: ELManager,
    blck: SomeForkyBeaconBlock,
    envelope: NoEnvelope | gloas.ExecutionPayloadEnvelope,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadStatusCode]] {.async: (raises: [CancelledError]).} =
  const consensusFork = typeof(blck).kind

  template executionPayload(): auto =
    when consensusFork >= ConsensusFork.Gloas:
      envelope.payload
    else:
      blck.body.execution_payload

  let payload = executionPayload

  when consensusFork >= ConsensusFork.Gloas:
    await m.newPayload(
      payload,
      blck.body.signed_execution_payload_bid
        .message.blob_kzg_commitments.mapIt(
          kzg_commitment_to_versioned_hash(it).asEth2Digest),
      blck.parent_root,
      envelope.execution_requests.asEngineExecutionRequests(),
      deadline, retry)
  elif consensusFork >= ConsensusFork.Electra:
    await m.newPayload(
      payload,
      blck.body.blob_kzg_commitments.mapIt(
        kzg_commitment_to_versioned_hash(it).asEth2Digest),
      blck.parent_root,
      blck.body.execution_requests.asEngineExecutionRequests(),
      deadline, retry)
  elif consensusFork >= ConsensusFork.Deneb:
    await m.newPayload(
      payload,
      blck.body.blob_kzg_commitments.mapIt(
        kzg_commitment_to_versioned_hash(it).asEth2Digest),
      blck.parent_root,
      deadline, retry)
  elif consensusFork >= ConsensusFork.Bellatrix:
    await m.newPayload(payload, deadline, retry)
  else:
    {.error: "newPayload unsupported in " & $consensusFork.}

proc newPayload*(
    m: ELManager,
    envelope: gloas.ExecutionPayloadEnvelope,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadStatusCode]] {.async: (raises: [CancelledError]).} =
  let blob_versioned_hashes =
    envelope.payload.transactions.all_blob_versioned_hashes().valueOr:
      debug "Envelope has invalid blob transaction", err = error
      return Opt.none(PayloadStatusCode)
  await m.newPayload(
    envelope.payload,
    blob_versioned_hashes.mapIt(it.asEth2Digest),
    envelope.parent_beacon_block_root,
    envelope.execution_requests.asEngineExecutionRequests(),
    deadline, retry)

proc forkchoiceUpdated(
    connection: ELConnection,
    state: engine_types.ForkchoiceState,
    payloadAttributes: Opt[engine_types.PayloadAttributesParis] |
                       Opt[engine_types.PayloadAttributesShanghai] |
                       Opt[engine_types.PayloadAttributesCancun] |
                       Opt[engine_types.PayloadAttributesAmsterdam],
    retry: bool,
): Future[EnginePayloadStatus] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let responseFut =
      if connection.transport == ELTransportKind.Rest:
        let client = await connection.connectedRestClient()
        client.sendForkchoiceUpdatedRest(state, payloadAttributes, connection.restHeaders)
      else:
        let
          rpcClient = await connection.connectedRpcClient()
          webState = state.asWeb3
          webPayloadAttributes =
            when payloadAttributes is Opt[engine_types.PayloadAttributesParis]:
              if payloadAttributes.isSome: Opt.some(payloadAttributes.get.asWeb3)
              else: Opt.none(PayloadAttributesV1)
            elif payloadAttributes is Opt[engine_types.PayloadAttributesShanghai]:
              if payloadAttributes.isSome: Opt.some(payloadAttributes.get.asWeb3)
              else: Opt.none(PayloadAttributesV2)
            elif payloadAttributes is Opt[engine_types.PayloadAttributesCancun]:
              if payloadAttributes.isSome: Opt.some(payloadAttributes.get.asWeb3)
              else: Opt.none(PayloadAttributesV3)
            else:
              if payloadAttributes.isSome: Opt.some(payloadAttributes.get.asWeb3)
              else: Opt.none(PayloadAttributesV4)
        rpcClient.sendForkchoiceUpdatedRpc(webState, webPayloadAttributes)

    if payloadAttributes.isSome:
      # Saving the future here allows the getPayload request to latch on to
      # an in-flight request and thus avoid concurrent payload requests with the
      # same attributes -- for either transport, since `lastPayloadReq` now
      # holds a transport-agnostic `Future[ForkchoiceUpdateResult]`.
      connection.lastPayloadReq =
        (PayloadParams.init(state, payloadAttributes[]), responseFut)

    return (await responseFut).payloadStatus

proc forkchoiceUpdated*(
    m: ELManager,
    state: engine_types.ForkchoiceState,
    payloadAttributes: Opt[engine_types.PayloadAttributesParis] |
                       Opt[engine_types.PayloadAttributesShanghai] |
                       Opt[engine_types.PayloadAttributesCancun] |
                       Opt[engine_types.PayloadAttributesAmsterdam],
    deadline: DeadlineFuture,
    retry: bool,
): Future[(PayloadStatusCode, Opt[Eth2Digest])] {.
   async: (raises: [CancelledError]).} =
  # Allow finalizedBlockHash to be 0 to avoid sync deadlocks.
  #
  # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md#pos-events
  # has "Before the first finalized block occurs in the system the finalized
  # block hash provided by this event is stubbed with
  # `0x0000000000000000000000000000000000000000000000000000000000000000`."
  # and
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/bellatrix/validator.md#executionpayload
  # notes "`finalized_block_hash` is the hash of the latest finalized execution
  # payload (`Hash32()` if none yet finalized)"

  if m.elConnections.len == 0:
    return (PayloadStatusCode.SYNCING, Opt.none Eth2Digest)

  let startTime = Moment.now

  var responseProcessor = ELConsensusViolationDetector.init()
  let requests = m.elConnections.mapIt:
      let req = it.forkchoiceUpdated(state, payloadAttributes, retry)
      engineApiRequest(it, req, "forkchoiceUpdated", startTime)
  var pending = requests
  let earlyDeadline = sleepAsync(multiTimeout)

  defer:
    await cancelAndWait(pending)

  while pending.len > 0:
    try:
      if responseProcessor.selectedResponse.isSome():
        discard await race(race(pending), earlyDeadline)
      else:
        discard await race(race(pending), deadline)
    except ValueError:
      raiseAssert "race error cannot happen"

    if pending.anyIt(
      responseProcessor.hasDisagreement(EnginePayloadStatus, m.elConnections, requests, it)
    ):
      return (PayloadStatusCode.INVALID, Opt.none Eth2Digest)

    pending = pending.filterIt(not it.finished)

    if earlyDeadline.finished and responseProcessor.selectedResponse.isSome():
      # At the early deadline, we select the best response we've received so far
      if pending.len > 0:
        # Let the other requests run their course so they receive the update
        asyncSpawn lazyWait(pending, deadline)
        reset pending
      break

    if deadline.finished:
      break

  if responseProcessor.selectedResponse.isSome():
    let data = requests[responseProcessor.selectedResponse.get].value()
    (data.status, data.latestValidHash)
  else:
    (PayloadStatusCode.SYNCING, Opt.none Eth2Digest)

proc forkchoiceUpdated*(
    m: ELManager,
    state: engine_types.ForkchoiceState,
    payloadAttributes: Opt[engine_types.PayloadAttributesParis] |
                       Opt[engine_types.PayloadAttributesShanghai] |
                       Opt[engine_types.PayloadAttributesCancun] |
                       Opt[engine_types.PayloadAttributesAmsterdam]
): Future[(PayloadStatusCode, Opt[Eth2Digest])] {.
    async: (raises: [CancelledError], raw: true).} =
  forkchoiceUpdated(
    m, state, payloadAttributes, sleepAsync(FORKCHOICEUPDATED_TIMEOUT), true
  )

proc checkChainId(
    m: ELManager,
    connection: ELConnection
) {.async: (raises: [CancelledError]).} =
  let rpcClient = await connection.connectedRpcClient()

  if m.eth1Network.isSome and
     connection.chainIdStatus == ChainIdStatus.notExchangedYet:
    try:
      let
        providerChain = await connection.engineApiRequest(
          rpcClient.eth_chainId(), "chainId", Moment.now()
        )

        # https://chainid.network/
        expectedChain = case m.eth1Network.get
          of mainnet: 1.u256
          of sepolia: 11155111.u256
          of hoodi: 560048.u256
      if expectedChain != providerChain:
        warn "The specified EL client is connected to a different chain",
              url = connection.engineUrl,
              expectedChain = distinctBase(expectedChain),
              actualChain = distinctBase(providerChain)
        connection.chainIdStatus = ChainIdStatus.mismatch
        return
    except CancelledError as exc:
      debug "Configuration exchange was interrupted"
      raise exc
    except CatchableError as exc:
      # Typically because it's not synced through EIP-155, assuming this Web3
      # endpoint has been otherwise working.
      debug "Failed to obtain eth_chainId", reason = exc.msg

  connection.chainIdStatus = ChainIdStatus.match

proc checkChainId(
    m: ELManager
) {.async: (raises: [CancelledError]).} =
  if m.elConnections.len == 0:
    return

  let requests = m.elConnections.mapIt(m.checkChainId(it))
  try:
    await allFutures(requests).wait(3.seconds)
  except AsyncTimeoutError:
    discard
  except CancelledError as exc:
    await cancelAndWait(requests)
    raise exc

  let (pending, failed, finished) =
    block:
      var
        failed = 0
        done = 0
        pending: seq[Future[void]]
      for req in requests:
        if not req.finished():
          pending.add(req.cancelAndWait())
        else:
          if req.completed():
            inc(done)
          else:
            inc(failed)
      (pending, failed, done)

  await cancelAndWait(pending)

  if (len(pending) > 0) or (failed != 0):
    warn "Failed to exchange configuration with the configured EL end-points",
         completed = finished, failed = failed, timed_out = len(pending)

func new*(T: type ELConnection, engineUrl: EngineApiUrl): T =
  ELConnection(
    engineUrl: engineUrl,
    transport:
      if engineUrl.restEnabled: ELTransportKind.Rest
      else: ELTransportKind.JsonRpc)

func new*(T: type ELManager,
          engineApiUrls: seq[EngineApiUrl],
          eth1Network: Opt[Eth1Network]): T =
  T(elConnections: mapIt(engineApiUrls, ELConnection.new(it)),
    eth1Network: eth1Network)

func hasConnection*(m: ELManager): bool =
  m.elConnections.len > 0

func hasAnyWorkingConnection*(m: ELManager): bool =
  m.elConnections.anyIt(it.state == Working or it.state == NeverTested)

proc startCheckChainIdLoop(
    m: ELManager
) {.async: (raises: [CancelledError]).} =
  debug "Starting chain ID checking loop"

  while true:
    await m.checkChainId()
    await sleepAsync(60.seconds)

proc start*(m: ELManager) =
  if m.elConnections.len == 0:
    return

  if m.checkChainIdLoopFut.isNil:
    m.checkChainIdLoopFut = m.startCheckChainIdLoop()

proc testWeb3Provider*(
    web3Url: Uri, jwtSecret: Opt[JwtSharedKey]
) {.async: (raises: [CatchableError]).} =
  stdout.write "Establishing web3 connection..."
  let web3 =
    try:
      await newWeb3($web3Url,
                    getJsonRpcRequestHeaders(jwtSecret)).wait(5.seconds)
    except CatchableError as exc:
      stdout.write "\rEstablishing web3 connection: Failure(" & exc.msg & ")\n"
      quit 1

  stdout.write "\rEstablishing web3 connection: Connected\n"

  template request(actionDesc: static string, action: untyped): untyped =
    stdout.write actionDesc & "..."
    stdout.flushFile()
    var res: typeof(read action)
    try:
      let fut = action
      res = await fut.wait(web3RequestsTimeout)
      stdout.write "\r" & actionDesc & ": " & $res
    except CatchableError as err:
      stdout.write "\r" & actionDesc & ": Error(" & err.msg & ")"
    stdout.write "\n"
    res

  discard request "Chain ID":
    web3.provider.eth_chainId()

  discard request "Sync status":
    web3.provider.eth_syncing()

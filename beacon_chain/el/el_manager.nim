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

from std/sequtils import anyIt, filterIt, mapIt
from std/times import getTime, toUnix
from std/typetraits import distinctBase
from ../spec/state_transition_block import kzg_commitment_to_versioned_hash

export
  el_conf, engine_api, base

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
    GetPayloadV4Response |
    GetPayloadV5Response |
    GetPayloadV6Response

  PayloadParams = object
    ## Parameters given to the latest payload-preparing forkChoiceParameters
    ## call - if all parameters match, we can use the payload id given in
    ## response, else we have to make a new call
    state: ForkchoiceStateV1
    attributes: PayloadAttributesV4
      # V4 is a superset of the earlier versions so we can use it for cache
      # equivalence purposes

  PayloadReq = tuple[params: PayloadParams, resp: Future[ForkchoiceUpdatedResponse]]

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

  ELConnection = ref object
    engineUrl: EngineApiUrl

    web3: Opt[Web3]
      ## This will be `none` before connecting and while we are
      ## reconnecting after a lost connection. You can wait on
      ## the future below for the moment the connection is active.

    connectingFut: Future[Result[Web3, string]].Raising([CancelledError])
      ## This future will be replaced when the connection is lost.

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
  connection.web3.isSome

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

proc getPayload(
    connection: ELConnection,
    GetPayloadResponseType: type,
    params: PayloadParams,
    payloadAttributes: PayloadAttributesV3 | PayloadAttributesV4,
    retry: bool,
): Future[GetPayloadResponseType] {.async: (raises: [CatchableError]).} =
  template payloadReq(): auto =
    connection.lastPayloadReq

  var
    payload: GetPayloadResponseType
    payloadId: Bytes8

  retryUntilCancelled:
    let
      rpcClient = await connection.connectedRpcClient()
      # Use prepared payload if it was given or still pending; otherwise make a
      # new request. `safeBlockHash` and `finalizedBlockHash` are intentionally
      # excluded, because the payload depends on neither and the FCR safe block
      # typically change between when the payload preparation was requested and
      # getPayload is sent.
      useLastPayload =
        payloadReq.resp != nil and
        payloadReq.params.state.headBlockHash == params.state.headBlockHash and
        payloadReq.params.attributes == params.attributes and
        (not payloadReq.resp.completed or payloadReq.resp.value().payloadId.isSome())

      forkchoiceUpdated = await(
        if useLastPayload:
          payloadReq.resp
        else:
          engine_api_last_minute_forkchoice_updates_sent.inc(
            1, [connection.engineUrl.url]
          )
          notice "Payload not prepared, sending last-minute payload request",
            url = connection.engineUrl.url

          rpcClient.forkchoiceUpdated(params.state, Opt.some payloadAttributes)
      )

    payloadId = forkchoiceUpdated.payloadId.valueOr:
      warn "Execution client did not return payload id",
        url = connection.engineUrl.url, status = forkchoiceUpdated.payloadStatus.status
      raise newException(
        CatchableError,
        "No payload id given: " & $forkchoiceUpdated.payloadStatus.status,
      )

    if not useLastPayload:
      # Give the EL some time to build the block
      await sleepAsync(500.milliseconds)

    payload = await rpcClient.getPayload(GetPayloadResponseType, payloadId)

    break # retryUntilCancelled

  # Check that the execution payload matches the attributes we asked for, as
  # aggreed per payload id - this is done outside of the retry loop to avoid
  # re-requesting from a faulty client
  if payload.executionPayload.extraData.len > MAX_EXTRA_DATA_BYTES:
    warn "Execution client payload with extraData exceeding limit",
      url = connection.engineUrl.url,
      payloadId,
      size = payload.executionPayload.extraData.len,
      limit = MAX_EXTRA_DATA_BYTES
    raise newException(CatchableError, "Execution payload extraData exceeds max size")

  if params.attributes.withdrawals != payload.executionPayload.withdrawals:
    warn "Execution client returned unexpected payload withdrawals",
      url = connection.engineUrl.url,
      payloadId,
      withdrawals_from_cl_len = params.attributes.withdrawals.len,
      withdrawals_from_el_len = payload.executionPayload.withdrawals.len,
      withdrawals_from_cl =
        mapIt(params.attributes.withdrawals, it.asConsensusWithdrawal),
      withdrawals_from_el = mapIt(
        payload.executionPayload.withdrawals, it.asConsensusWithdrawal
      )
    raise newException(
      CatchableError, "Execution client returned mismatching withdrawals"
    )

  payload

template EngineApiResponseType(T: type electra.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV4Response

template EngineApiResponseType(T: type fulu.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV5Response

template EngineApiResponseType(T: type gloas.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV6Response

template toEngineWithdrawals*(withdrawals: seq[capella.Withdrawal]): seq[WithdrawalV1] =
  mapIt(withdrawals, toEngineWithdrawal(it))

func init*(
    T: type ForkchoiceStateV1, headBlock, safeBlock, finalizedBlock: Eth2Digest
): T =
  T(
    headBlockHash: headBlock.asBlockHash,
    safeBlockHash: safeBlock.asBlockHash,
    finalizedBlockHash: finalizedBlock.asBlockHash,
  )

func init*(
    T: type PayloadAttributesV3,
    timestamp: uint64,
    prevRandao: Eth2Digest,
    suggestedFeeRecipient: Eth1Address,
    withdrawals: sink seq[capella.Withdrawal],
    consensusHead: Eth2Digest,
): T =
  T(
    timestamp: Quantity timestamp,
    prevRandao: Bytes32 prevRandao.to(Hash32),
    suggestedFeeRecipient: suggestedFeeRecipient,
    withdrawals: withdrawals.toEngineWithdrawals(),
    parentBeaconBlockRoot: consensusHead.to(Hash32),
  )

func init*(
    T: type PayloadAttributesV4,
    timestamp: uint64,
    prevRandao: Eth2Digest,
    suggestedFeeRecipient: Eth1Address,
    withdrawals: sink seq[capella.Withdrawal],
    consensusHead: Eth2Digest,
    slot: Slot,
    targetGasLimit: uint64,
): T =
  T(
    timestamp: Quantity timestamp,
    prevRandao: Bytes32 prevRandao.to(Hash32),
    suggestedFeeRecipient: suggestedFeeRecipient,
    withdrawals: withdrawals.toEngineWithdrawals(),
    parentBeaconBlockRoot: consensusHead.to(Hash32),
    slotNumber: Quantity(slot),
    targetGasLimit: Quantity(targetGasLimit),
  )

func init(
    T: type PayloadParams, state: ForkchoiceStateV1, attributes: PayloadAttributesV1
): T =
  PayloadParams(
    state: state,
    attributes: PayloadAttributesV4(
      timestamp: attributes.timestamp,
      prevRandao: attributes.prevRandao,
      suggestedFeeRecipient: attributes.suggestedFeeRecipient,
      withdrawals: @[],
      parentBeaconBlockRoot: static(default(Hash32)),
      slotNumber: FAR_FUTURE_SLOT.Quantity
    ),
  )

func init(
    T: type PayloadParams, state: ForkchoiceStateV1, attributes: PayloadAttributesV2
): T =
  PayloadParams(
    state: state,
    attributes: PayloadAttributesV4(
      timestamp: attributes.timestamp,
      prevRandao: attributes.prevRandao,
      suggestedFeeRecipient: attributes.suggestedFeeRecipient,
      withdrawals: attributes.withdrawals,
      parentBeaconBlockRoot: static(default(Hash32)),
      slotNumber: FAR_FUTURE_SLOT.Quantity
    ),
  )

func init(
    T: type PayloadParams, state: ForkchoiceStateV1, attributes: PayloadAttributesV3
): T =
  PayloadParams(
    state: state,
    attributes: PayloadAttributesV4(
      timestamp: attributes.timestamp,
      prevRandao: attributes.prevRandao,
      suggestedFeeRecipient: attributes.suggestedFeeRecipient,
      withdrawals: attributes.withdrawals,
      parentBeaconBlockRoot: attributes.parentBeaconBlockRoot,
      slotNumber: FAR_FUTURE_SLOT.Quantity
    ),
  )

func init(
    T: type PayloadParams, state: ForkchoiceStateV1, attributes: PayloadAttributesV4
): T =
  PayloadParams(state: state, attributes: attributes)

proc getPayload*(
    m: ELManager,
    PayloadType: type ForkyExecutionPayloadForSigning,
    state: ForkchoiceStateV1,
    payloadAttributes: PayloadAttributesV3 | PayloadAttributesV4,
): Future[Opt[PayloadType]] {.async: (raises: [CancelledError]).} =
  if m.elConnections.len == 0:
    notice "No engine configured, using empty payload"
    return Opt.none(PayloadType)

  let params = PayloadParams.init(state, payloadAttributes)

  # `getPayloadFromSingleEL` may introduce additional latency
  const extraProcessingOverhead = 500.milliseconds
  let deadline = sleepAsync(GETPAYLOAD_TIMEOUT + extraProcessingOverhead)

  let requests = m.elConnections.mapIt(
    it.getPayload(EngineApiResponseType(PayloadType), params, payloadAttributes, true)
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
    debugHezeComment("")
    ok(requests[bestPayloadIdx.get()].value().asConsensusType)
  else:
    Opt.none(PayloadType)

proc newPayload(
    connection: ELConnection, payload: engine_api.ExecutionPayloadV1, retry: bool
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let rpcClient = await connection.connectedRpcClient()
    return await rpcClient.engine_newPayloadV1(payload)

proc newPayload(
    connection: ELConnection, payload: engine_api.ExecutionPayloadV2, retry: bool
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let rpcClient = await connection.connectedRpcClient()
    return await rpcClient.engine_newPayloadV2(payload)

proc newPayload(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV3,
    versioned_hashes: seq[engine_api.VersionedHash],
    parent_beacon_block_root: Hash32,
    retry: bool,
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let rpcClient = await connection.connectedRpcClient()
    return await rpcClient.engine_newPayloadV3(
      payload, versioned_hashes, parent_beacon_block_root
    )

proc newPayload(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV3,
    versioned_hashes: seq[engine_api.VersionedHash],
    parent_beacon_block_root: Hash32,
    executionRequests: seq[seq[byte]],
    retry: bool,
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let rpcClient = await connection.connectedRpcClient()
    return await rpcClient.engine_newPayloadV4(
      payload, versioned_hashes, parent_beacon_block_root, executionRequests
    )

proc newPayload(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV4,
    versioned_hashes: seq[engine_api.VersionedHash],
    parent_beacon_block_root: Hash32,
    executionRequests: seq[seq[byte]],
    retry: bool,
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let rpcClient = await connection.connectedRpcClient()
    return await rpcClient.engine_newPayloadV5(
      payload, versioned_hashes, parent_beacon_block_root, executionRequests
    )

proc getBlobsV2(
    connection: ELConnection,
    versioned_hashes: seq[engine_api.VersionedHash]
): Future[GetBlobsV2Response] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_getBlobsV2(versioned_hashes)

proc getBlobsV3(
    connection: ELConnection,
    versioned_hashes: seq[engine_api.VersionedHash]
): Future[GetBlobsV3Response] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_getBlobsV3(versioned_hashes)

type
  StatusRelation = enum
    newStatusIsPreferable
    oldStatusIsOk
    disagreement

func compareStatuses(
    newStatus, prevStatus: PayloadExecutionStatus
): StatusRelation =
  case prevStatus
  of PayloadExecutionStatus.syncing:
    if newStatus == PayloadExecutionStatus.syncing:
      oldStatusIsOk
    else:
      newStatusIsPreferable

  of PayloadExecutionStatus.valid:
    case newStatus
    of PayloadExecutionStatus.syncing,
       PayloadExecutionStatus.accepted,
       PayloadExecutionStatus.valid:
      oldStatusIsOk
    of PayloadExecutionStatus.invalid_block_hash,
       PayloadExecutionStatus.invalid:
      disagreement

  of PayloadExecutionStatus.invalid:
    case newStatus
    of PayloadExecutionStatus.syncing,
       PayloadExecutionStatus.invalid:
      oldStatusIsOk
    of PayloadExecutionStatus.valid,
       PayloadExecutionStatus.accepted,
       PayloadExecutionStatus.invalid_block_hash:
      disagreement

  of PayloadExecutionStatus.accepted:
    case newStatus
    of PayloadExecutionStatus.accepted,
       PayloadExecutionStatus.syncing:
      oldStatusIsOk
    of PayloadExecutionStatus.valid:
      newStatusIsPreferable
    of PayloadExecutionStatus.invalid_block_hash,
       PayloadExecutionStatus.invalid:
      disagreement

  of PayloadExecutionStatus.invalid_block_hash:
    if newStatus == PayloadExecutionStatus.invalid_block_hash:
      oldStatusIsOk
    else:
      disagreement

type
  ELConsensusViolationDetector = object
    selectedResponse: Opt[int]
    selectedStatus: Opt[PayloadExecutionStatus]
    disagreementAlreadyDetected: bool

func init(T: type ELConsensusViolationDetector): T =
  ELConsensusViolationDetector(
    selectedResponse: Opt.none(int),
    selectedStatus: Opt.none(PayloadExecutionStatus),
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
): Future[Opt[seq[BlobAndProofV2]]] {.async: (raises: [CancelledError], raw: true).} =
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
        kzg_commitments.mapIt(kzg_commitment_to_versioned_hash(it))
      )
    )
    .firstOrCancel(deadline)

proc getBlobsV2*(
    m: ELManager, kzg_commitments: KzgCommitments
): Future[Opt[seq[BlobAndProofV2]]] {.async: (raises: [CancelledError], raw: true).} =
  ## Variant used by the column-first sidecar retrieval path: derives
  ## versioned hashes from `kzg_commitments` directly, without requiring the
  ## block (which has not yet been seen via gossip).
  mixin getBlobsV2

  let deadline = sleepAsync(GETBLOBS_TIMEOUT)

  m.elConnections
    .mapIt(
      it.getBlobsV2(
        kzg_commitments.mapIt(kzg_commitment_to_versioned_hash(it))
      )
    )
    .firstOrCancel(deadline)

proc getBlobsV3*(
    m: ELManager, blck: fulu.SignedBeaconBlock | gloas.SignedBeaconBlock
): Future[Opt[seq[Opt[BlobAndProofV2]]]] {.
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
        kzg_commitments.mapIt(kzg_commitment_to_versioned_hash(it))
      )
    )
    .firstOrCancel(deadline)

template sendNewPayload(payload: untyped; args: varargs[untyped]): untyped =
  if m.elConnections.len == 0:
    info "No execution client configured; cannot process block payloads"
    Opt.none(PayloadExecutionStatus)
  else:
    let startTime = Moment.now()
    var
      res = Opt.none PayloadExecutionStatus
      responseProcessor = ELConsensusViolationDetector.init()
      requests = m.elConnections.mapIt:
        let req = unpackVarargs(it.newPayload, payload, args)
        it.engineApiRequest(req, "newPayload", startTime)
      pending = requests
      earlyDeadline = sleepAsync(multiTimeout)

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
          PayloadStatusV1, m.elConnections, requests, it):
        res.ok PayloadExecutionStatus.invalid
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
    payload: engine_api.ExecutionPayloadV1 | engine_api.ExecutionPayloadV2,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  sendNewPayload(payload, retry)

proc newPayload(
    m: ELManager,
    payload: engine_api.ExecutionPayloadV3,
    blob_versioned_hashes: seq[engine_api.VersionedHash],
    parent_root: Hash32,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  sendNewPayload(payload, blob_versioned_hashes, parent_root, retry)

proc newPayload(
    m: ELManager,
    payload: engine_api.ExecutionPayloadV3 | engine_api.ExecutionPayloadV4,
    blob_versioned_hashes: seq[engine_api.VersionedHash],
    parent_root: Hash32,
    execution_requests: seq[seq[byte]],
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  sendNewPayload(
    payload, blob_versioned_hashes, parent_root, execution_requests, retry)

proc newPayload*(
    m: ELManager,
    blck: SomeForkyBeaconBlock,
    envelope: NoEnvelope | gloas.ExecutionPayloadEnvelope,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  const consensusFork = typeof(blck).kind

  template executionPayload(): auto =
    when consensusFork >= ConsensusFork.Gloas:
      envelope.payload
    else:
      blck.body.execution_payload

  let payload = executionPayload.asEngineExecutionPayload()

  when consensusFork >= ConsensusFork.Gloas:
    await m.newPayload(
      payload,
      blck.body.signed_execution_payload_bid
        .message.blob_kzg_commitments.asEngineVersionedHashes(),
      blck.parent_root.to(Hash32),
      envelope.execution_requests.asEngineExecutionRequests(),
      deadline, retry)
  elif consensusFork >= ConsensusFork.Electra:
    await m.newPayload(
      payload,
      blck.body.blob_kzg_commitments.asEngineVersionedHashes(),
      blck.parent_root.to(Hash32),
      blck.body.execution_requests.asEngineExecutionRequests(),
      deadline, retry)
  elif consensusFork >= ConsensusFork.Deneb:
    await m.newPayload(
      payload,
      blck.body.blob_kzg_commitments.asEngineVersionedHashes(),
      blck.parent_root.to(Hash32),
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
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  let blob_versioned_hashes =
    envelope.payload.transactions.asSeq.all_blob_versioned_hashes().valueOr:
      debug "Envelope has invalid blob transaction", err = error
      return Opt.none(PayloadExecutionStatus)
  await m.newPayload(
    envelope.payload.asEngineExecutionPayload(),
    blob_versioned_hashes,
    envelope.parent_beacon_block_root.to(Hash32),
    envelope.execution_requests.asEngineExecutionRequests(),
    deadline, retry)

proc forkchoiceUpdated(
    connection: ELConnection,
    state: ForkchoiceStateV1,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3] |
                       Opt[PayloadAttributesV4],
    retry: bool,
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  retryUntilCancelled:
    let
      rpcClient = await connection.connectedRpcClient()
      responseFut = rpcClient.forkchoiceUpdated(state, payloadAttributes)

    if payloadAttributes.isSome:
      # Saving the future here allows the getPayload request to latch on to
      # an in-flight request and thus avoid concurrent payload requests with the
      # same attributes
      connection.lastPayloadReq =
        (PayloadParams.init(state, payloadAttributes[]), responseFut)

    return (await responseFut).payloadStatus

proc forkchoiceUpdated*(
    m: ELManager,
    state: ForkchoiceStateV1,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3] |
                       Opt[PayloadAttributesV4],
    deadline: DeadlineFuture,
    retry: bool,
): Future[(PayloadExecutionStatus, Opt[Hash32])] {.
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
    return (PayloadExecutionStatus.syncing, Opt.none Hash32)

  let startTime = Moment.now

  var
    responseProcessor = ELConsensusViolationDetector.init()
    requests = m.elConnections.mapIt:
      let req = it.forkchoiceUpdated(state, payloadAttributes, retry)
      engineApiRequest(it, req, "forkchoiceUpdated", startTime)
    pending = requests
    earlyDeadline = sleepAsync(multiTimeout)

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
      responseProcessor.hasDisagreement(PayloadStatusV1, m.elConnections, requests, it)
    ):
      return (PayloadExecutionStatus.invalid, Opt.none Hash32)

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
    (PayloadExecutionStatus.syncing, Opt.none Hash32)

proc forkchoiceUpdated*(
    m: ELManager,
    state: ForkchoiceStateV1,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3] |
                       Opt[PayloadAttributesV4]
): Future[(PayloadExecutionStatus, Opt[Hash32])] {.
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
  ELConnection(engineUrl: engineUrl)

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

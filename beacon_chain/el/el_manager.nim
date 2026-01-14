# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/json,
  # Nimble packages:
  chronos, metrics, chronicles/timings,
  json_rpc/[client, errors],
  web3, web3/[engine_api, primitives, conversions],
  eth/common/eth_types,
  results,
  kzg4844/[kzg_abi, kzg],
  stew/objects,
  # Local modules:
  ../spec/[engine_authentication, forks],
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
  SleepDurations =
    [100.milliseconds, 200.milliseconds, 500.milliseconds, 1.seconds]

type
  WithoutTimeout = distinct int

  DeadlineFuture* = Future[void].Raising([CancelledError])

  SomeEnginePayloadWithValue =
    BellatrixExecutionPayloadWithValue |
    GetPayloadV2Response |
    GetPayloadV3Response |
    GetPayloadV4Response |
    GetPayloadV5Response

const
  noTimeout = WithoutTimeout(0)

  # Engine API timeouts
  engineApiConnectionTimeout = 5.seconds  # How long we wait before giving up connecting to the Engine API
  web3RequestsTimeout = 8.seconds # How long we wait for eth_* requests

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/paris.md#request-2
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/shanghai.md#request-2
  GETPAYLOAD_TIMEOUT = 1.seconds

  GETBLOBS_TIMEOUT = 250.milliseconds

  connectionStateChangeHysteresisThreshold = 15
    ## How many unsuccesful/successful requests we must see
    ## before declaring the connection as degraded/restored

type
  NextExpectedPayloadParams = object
    headBlockHash: Eth2Digest
    safeBlockHash: Eth2Digest
    finalizedBlockHash: Eth2Digest
    payloadAttributes: PayloadAttributesV3

  ELManager* = ref object
    eth1Network: Opt[Eth1Network]
      ## If this value is supplied the EL manager will check whether
      ## all configured EL nodes are connected to the same network.

    elConnections: seq[ELConnection]
      ## All active EL connections

    checkChainIdLoopFut: Future[void]
    nextExpectedPayloadParams: Opt[NextExpectedPayloadParams]

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
      ## reconnecting after a lost connetion. You can wait on
      ## the future below for the moment the connection is active.

    connectingFut: Future[Result[Web3, string]].Raising([CancelledError])
      ## This future will be replaced when the connection is lost.

    chainIdStatus: ChainIdStatus
      ## The latest status of the `checkChainId` exchange.

    state: ELConnectionState
    hysteresisCounter: int
    lastPayloadId: Opt[Bytes8]

  DataProviderTimeout* = object of CatchableError

declareCounter engine_api_responses,
  "Number of successful requests to the newPayload Engine API end-point",
  labels = ["url", "request", "status"]

declareHistogram engine_api_request_duration_seconds,
  "Time(s) used to generate signature usign remote signer",
   buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
   labels = ["url", "request"]

declareCounter engine_api_timeouts,
  "Number of timed-out requests to Engine API end-point",
  labels = ["url", "request"]

declareCounter engine_api_last_minute_forkchoice_updates_sent,
  "Number of last minute requests to the forkchoiceUpdated Engine API end-point just before block proposals",
  labels = ["url"]

proc variedSleep(
    counter: var int,
    durations: openArray[Duration]
): Future[void] {.async: (raises: [CancelledError], raw: true).} =
  doAssert(len(durations) > 0, "Empty durations array!")
  let index =
    if (counter < 0) or (counter > high(durations)):
      high(durations)
    else:
      counter
  inc(counter)
  sleepAsync(durations[index])

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
    # While we increase the counter by 1, we decreate it by 20% in order
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
    connection: ELConnection,
    request: Future[T],
    requestName: string,
    startTime: Moment,
    deadline: Future[void] | Duration | WithoutTimeout,
    failureAllowed = false
): Future[T] {.async: (raises: [CatchableError]).} =
  ## This procedure raises `CancelledError` and `DataProviderTimeout`
  ## exceptions, and everything which `request` could raise.
  try:
    let res =
      when deadline is WithoutTimeout:
        await request
      else:
        await request.wait(deadline)
    engine_api_request_duration_seconds.observe(
      float(milliseconds(Moment.now - startTime)) / 1000.0,
        [connection.engineUrl.url, requestName])
    engine_api_responses.inc(
      1, [connection.engineUrl.url, requestName, "200"])
    connection.setWorkingState()
    res
  except AsyncTimeoutError:
    engine_api_timeouts.inc(1, [connection.engineUrl.url, requestName])
    if not(failureAllowed):
      await connection.setDegradedState(requestName, 0, "Request timed out")
    raise newException(DataProviderTimeout, "Request timed out")
  except CancelledError as exc:
    when deadline is WithoutTimeout:
      # When `deadline` is set to `noTimeout`, we usually get cancelled on
      # timeout which was handled by caller.
      engine_api_timeouts.inc(1, [connection.engineUrl.url, requestName])
      if not(failureAllowed):
        await connection.setDegradedState(requestName, 0, "Request timed out")
    else:
      if not(failureAllowed):
        await connection.setDegradedState(requestName, 0, "Request interrupted")
    raise exc
  except CatchableError as exc:
    let statusCode =
      if request.error of ErrorResponse:
        ((ref ErrorResponse) request.error).status
      else:
        0
    engine_api_responses.inc(
      1, [connection.engineUrl.url, requestName, $statusCode])
    if not(failureAllowed):
      await connection.setDegradedState(
        requestName, statusCode, request.error.msg)
    raise exc

func raiseIfNil(web3block: BlockObject): BlockObject {.raises: [ValueError].} =
  if web3block == nil:
    raise newException(ValueError, "EL returned 'null' result for block")
  web3block

func hasJwtSecret(m: ELManager): bool =
  for c in m.elConnections:
    if c.engineUrl.jwtSecret.isSome:
      return true
  false

# TODO: Add cfg validation
# MIN_GENESIS_ACTIVE_VALIDATOR_COUNT should be larger than SLOTS_PER_EPOCH

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
    connection.web3 = Opt.some(web3Res.get)
    true

proc connectedRpcClient(connection: ELConnection): Future[RpcClient] {.
     async: (raises: [CancelledError]).} =
  while not connection.isConnected:
    if not(await connection.tryConnecting()):
      await sleepAsync(chronos.seconds(10))

  connection.web3.get.provider

func areSameAs(expectedParams: Opt[NextExpectedPayloadParams],
               latestHead, latestSafe, latestFinalized: Eth2Digest,
               timestamp: uint64,
               randomData: Eth2Digest,
               feeRecipient: Eth1Address,
               withdrawals: seq[WithdrawalV1]): bool =
  expectedParams.isSome and
    expectedParams.get.headBlockHash == latestHead and
    expectedParams.get.safeBlockHash == latestSafe and
    expectedParams.get.finalizedBlockHash == latestFinalized and
    expectedParams.get.payloadAttributes.timestamp.uint64 == timestamp and
    expectedParams.get.payloadAttributes.prevRandao.data == randomData.data and
    expectedParams.get.payloadAttributes.suggestedFeeRecipient == feeRecipient and
    expectedParams.get.payloadAttributes.withdrawals == withdrawals

proc forkchoiceUpdated(rpcClient: RpcClient,
                       state: ForkchoiceStateV1,
                       payloadAttributes: Opt[PayloadAttributesV1] |
                                          Opt[PayloadAttributesV2] |
                                          Opt[PayloadAttributesV3]):
                       Future[ForkchoiceUpdatedResponse] =
  when payloadAttributes is Opt[PayloadAttributesV1]:
    rpcClient.engine_forkchoiceUpdatedV1(state, payloadAttributes)
  elif payloadAttributes is Opt[PayloadAttributesV2]:
    rpcClient.engine_forkchoiceUpdatedV2(state, payloadAttributes)
  elif payloadAttributes is Opt[PayloadAttributesV3]:
    rpcClient.engine_forkchoiceUpdatedV3(state, payloadAttributes)
  else:
    static: doAssert false

proc getPayloadFromSingleEL(
    connection: ELConnection,
    GetPayloadResponseType: type,
    isForkChoiceUpToDate: bool,
    consensusHead: Eth2Digest,
    headBlock, safeBlock, finalizedBlock: Eth2Digest,
    timestamp: uint64,
    prevRandao: Eth2Digest,
    suggestedFeeRecipient: Eth1Address,
    withdrawals: seq[WithdrawalV1]
): Future[GetPayloadResponseType] {.async: (raises: [CatchableError]).} =

  let
    rpcClient = await connection.connectedRpcClient()
    payloadId = if isForkChoiceUpToDate and connection.lastPayloadId.isSome:
      connection.lastPayloadId.get
    elif not headBlock.isZero:
      engine_api_last_minute_forkchoice_updates_sent.inc(1, [connection.engineUrl.url])

      when GetPayloadResponseType is BellatrixExecutionPayloadWithValue:
        let response = await rpcClient.forkchoiceUpdated(
          ForkchoiceStateV1(
            headBlockHash: headBlock.asBlockHash,
            safeBlockHash: safeBlock.asBlockHash,
            finalizedBlockHash: finalizedBlock.asBlockHash),
          Opt.some PayloadAttributesV1(
            timestamp: Quantity timestamp,
            prevRandao: Bytes32 prevRandao.to(Hash32),
            suggestedFeeRecipient: suggestedFeeRecipient))
      elif GetPayloadResponseType is engine_api.GetPayloadV2Response:
        let response = await rpcClient.forkchoiceUpdated(
          ForkchoiceStateV1(
            headBlockHash: headBlock.asBlockHash,
            safeBlockHash: safeBlock.asBlockHash,
            finalizedBlockHash: finalizedBlock.asBlockHash),
          Opt.some PayloadAttributesV2(
            timestamp: Quantity timestamp,
            prevRandao: Bytes32 prevRandao.to(Hash32),
            suggestedFeeRecipient: suggestedFeeRecipient,
            withdrawals: withdrawals))
      elif  GetPayloadResponseType is engine_api.GetPayloadV3Response or
            GetPayloadResponseType is engine_api.GetPayloadV4Response or
            GetPayloadResponseType is engine_api.GetPayloadV5Response:
        # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/prague.md
        # does not define any new forkchoiceUpdated, so reuse V3 from Dencun
        # https://github.com/ethereum/execution-apis/blob/5d634063ccfd897a6974ea589c00e2c1d889abc9/src/engine/osaka.md
        let response = await rpcClient.forkchoiceUpdated(
          ForkchoiceStateV1(
            headBlockHash: headBlock.asBlockHash,
            safeBlockHash: safeBlock.asBlockHash,
            finalizedBlockHash: finalizedBlock.asBlockHash),
          Opt.some PayloadAttributesV3(
            timestamp: Quantity timestamp,
            prevRandao: Bytes32 prevRandao.to(Hash32),
            suggestedFeeRecipient: suggestedFeeRecipient,
            withdrawals: withdrawals,
            parentBeaconBlockRoot: consensusHead.to(Hash32)))
      else:
        static: doAssert false

      if response.payloadStatus.status != PayloadExecutionStatus.valid or
         response.payloadId.isNone:
        raise newException(CatchableError, "Head block is not a valid payload; " & $response)

      # Give the EL some time to assemble the block
      await sleepAsync(chronos.milliseconds 500)

      response.payloadId.get
    else:
      raise newException(CatchableError, "No confirmed execution head yet")

  when GetPayloadResponseType is BellatrixExecutionPayloadWithValue:
    let payload =
      await engine_api.getPayload(rpcClient, ExecutionPayloadV1, payloadId)
    return BellatrixExecutionPayloadWithValue(
      executionPayload: payload, blockValue: Wei.zero)
  else:
    return await engine_api.getPayload(
      rpcClient, GetPayloadResponseType, payloadId)

func cmpGetPayloadResponses(lhs, rhs: SomeEnginePayloadWithValue): int =
  cmp(distinctBase lhs.blockValue, distinctBase rhs.blockValue)

template EngineApiResponseType*(T: type bellatrix.ExecutionPayloadForSigning): type =
  BellatrixExecutionPayloadWithValue

template EngineApiResponseType*(T: type capella.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV2Response

template EngineApiResponseType*(T: type deneb.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV3Response

template EngineApiResponseType*(T: type electra.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV4Response

template EngineApiResponseType*(T: type fulu.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV5Response

template toEngineWithdrawals*(withdrawals: seq[capella.Withdrawal]): seq[WithdrawalV1] =
  mapIt(withdrawals, toEngineWithdrawal(it))

template kind(T: type ExecutionPayloadV1): ConsensusFork =
  ConsensusFork.Bellatrix

template kind(T: typedesc[ExecutionPayloadV1OrV2|ExecutionPayloadV2]): ConsensusFork =
  ConsensusFork.Capella

template kind(T: type ExecutionPayloadV3): ConsensusFork =
  ConsensusFork.Deneb

proc getPayload*(
    m: ELManager,
    PayloadType: type ForkyExecutionPayloadForSigning,
    consensusHead: Eth2Digest,
    headBlock, safeBlock, finalizedBlock: Eth2Digest,
    timestamp: uint64,
    prevRandao: Eth2Digest,
    suggestedFeeRecipient: Eth1Address,
    withdrawals: seq[capella.Withdrawal]
): Future[Opt[PayloadType]] {.async: (raises: [CancelledError]).} =
  if m.elConnections.len == 0:
    notice "No engine configured, using empty payload"
    return Opt.none(PayloadType)

  let
    engineApiWithdrawals = toEngineWithdrawals withdrawals
    isFcUpToDate = m.nextExpectedPayloadParams.areSameAs(
      headBlock, safeBlock, finalizedBlock, timestamp,
      prevRandao, suggestedFeeRecipient, engineApiWithdrawals)

  # `getPayloadFromSingleEL` may introduce additional latency
  const extraProcessingOverhead = 500.milliseconds
  let
    timeout = GETPAYLOAD_TIMEOUT + extraProcessingOverhead
    deadline = sleepAsync(timeout)

  var bestPayloadIdx = Opt.none(int)

  while true:
    let requests =
      m.elConnections.mapIt(
        it.getPayloadFromSingleEL(EngineApiResponseType(PayloadType),
          isFcUpToDate, consensusHead, headBlock, safeBlock, finalizedBlock,
          timestamp, prevRandao, suggestedFeeRecipient, engineApiWithdrawals))

    let timeoutExceeded =
      try:
        await allFutures(requests).wait(deadline)
        false
      except AsyncTimeoutError:
        true
      except CancelledError as exc:
        let pending =
          requests.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
        await noCancel allFutures(pending)
        raise exc

    for idx, req in requests:
      if not(req.finished()):
        warn "Timeout while getting execution payload",
             url = m.elConnections[idx].engineUrl.url
      elif req.failed():
        warn "Failed to get execution payload from EL",
             url = m.elConnections[idx].engineUrl.url,
             reason = req.error.msg
      else:
        const payloadFork = PayloadType.kind
        when payloadFork >= ConsensusFork.Capella:
          when payloadFork == ConsensusFork.Capella:
            # TODO: The engine_api module may offer an alternative API where
            # it is guaranteed to return the correct response type (i.e. the
            # rule below will be enforced during deserialization).
            if req.value().executionPayload.withdrawals.isNone:
              warn "Execution client returned a block without a " &
                   "'withdrawals' field for a post-Shanghai block",
                    url = m.elConnections[idx].engineUrl.url
              continue

          if engineApiWithdrawals !=
             req.value().executionPayload.withdrawals.maybeDeref:
            # otherwise it formats as "@[(index: ..., validatorIndex: ...,
            # address: ..., amount: ...), (index: ..., validatorIndex: ...,
            # address: ..., amount: ...)]"
            # TODO (cheatfate): should we have `continue` statement at the
            # end of this branch. If no such payload could be choosen as
            # best one.
            warn "Execution client did not return correct withdrawals",
              withdrawals_from_cl_len = engineApiWithdrawals.len,
              withdrawals_from_el_len =
                req.value().executionPayload.withdrawals.maybeDeref.len,
              withdrawals_from_cl =
                mapIt(engineApiWithdrawals, it.asConsensusWithdrawal),
              withdrawals_from_el =
                mapIt(
                  req.value().executionPayload.withdrawals.maybeDeref,
                  it.asConsensusWithdrawal),
              url = m.elConnections[idx].engineUrl.url
            # If we have more than one EL connection we consider this as
            # a failure.
            if len(requests) > 1:
              continue

        if req.value().executionPayload.extraData.len > MAX_EXTRA_DATA_BYTES:
          warn "Execution client provided a block with invalid extraData " &
               "(size exceeds limit)",
               url = m.elConnections[idx].engineUrl.url,
               size = req.value().executionPayload.extraData.len,
               limit = MAX_EXTRA_DATA_BYTES
          continue

        if bestPayloadIdx.isNone:
          bestPayloadIdx = Opt.some(idx)
        else:
          if cmpGetPayloadResponses(
               req.value(), requests[bestPayloadIdx.get].value()) > 0:
            bestPayloadIdx = Opt.some(idx)

    let pending =
      requests.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)

    if bestPayloadIdx.isSome():
      return ok(requests[bestPayloadIdx.get()].value().asConsensusType)

    if timeoutExceeded:
      break

  err()

proc sendNewPayloadToSingleEL(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV1
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_newPayloadV1(payload)

proc sendNewPayloadToSingleEL(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV2
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_newPayloadV2(payload)

proc sendNewPayloadToSingleEL(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV3,
    versioned_hashes: seq[engine_api.VersionedHash],
    parent_beacon_block_root: Hash32
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_newPayloadV3(
    payload, versioned_hashes, parent_beacon_block_root)

proc sendNewPayloadToSingleEL(
    connection: ELConnection,
    payload: engine_api.ExecutionPayloadV3,
    versioned_hashes: seq[engine_api.VersionedHash],
    parent_beacon_block_root: Hash32,
    executionRequests: seq[seq[byte]]
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_newPayloadV4(
    payload, versioned_hashes, parent_beacon_block_root,
    executionRequests)

proc sendGetBlobsV2toSingleEl(
    connection: ELConnection,
    versioned_hashes: seq[engine_api.VersionedHash]
): Future[GetBlobsV2Response] {.async: (raises: [CatchableError]).} =
  let rpcClient = await connection.connectedRpcClient()
  await rpcClient.engine_getBlobsV2(versioned_hashes)

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

proc processResponse(
    d: var ELConsensusViolationDetector,
    elResponseType: typedesc,
    connections: openArray[ELConnection],
    requests: auto,
    idx: int) =

  if not requests[idx].completed:
    return

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

func couldBeBetter(d: ELConsensusViolationDetector): bool =
  const
    SyncingOrAccepted = {
      PayloadExecutionStatus.syncing,
      PayloadExecutionStatus.accepted
    }
  if d.disagreementAlreadyDetected:
    return false
  if d.selectedStatus.isNone():
    return true
  d.selectedStatus.get() in SyncingOrAccepted

proc lazyWait(futures: seq[FutureBase]) {.async: (raises: []).} =
  block:
    let pending = futures.filterIt(not(it.finished()))
    if len(pending) > 0:
      try:
        await allFutures(pending).wait(30.seconds)
      except CancelledError:
        discard
      except AsyncTimeoutError:
        discard

  block:
    let pending = futures.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
    if len(pending) > 0:
      await noCancel allFutures(pending)

proc sendGetBlobsV2*(
    m: ELManager,
    blck: fulu.SignedBeaconBlock | gloas.SignedBeaconBlock,
): Future[Opt[seq[BlobAndProofV2]]] {.async: (raises: [CancelledError]).} =
  if m.elConnections.len == 0:
    return err()

  when blck is gloas.SignedBeaconBlock:
    debugGloasComment "handle correctly for Gloas?"
    return err()
  else:
    let deadline = sleepAsync(GETBLOBS_TIMEOUT)

    var bestIdx: Opt[int]

    while true:
      let requests = m.elConnections.mapIt(
        sendGetBlobsV2toSingleEl(it,
          mapIt(blck.message.body.blob_kzg_commitments,
                kzg_commitment_to_versioned_hash(it))
        )
      )

      let timeoutExceeded =
        try:
          await allFutures(requests).wait(deadline)
          false
        except AsyncTimeoutError:
          true
        except CancelledError as exc:
          # cancel anything still running, then re-raise
          await noCancel allFutures(
            requests.filterIt(not it.finished()).mapIt(it.cancelAndWait())
          )
          raise exc

      for idx, req in requests:
        if req.finished():
          # choose the first successful (not failed) response
          if req.error.isNil and bestIdx.isNone:
            bestIdx = Opt.some(idx)
        else:
          # finished == false
          let errmsg =
            if req.error.isNil: "request still pending"
            else: req.error.msg
          warn "Timeout while getting blobs & proofs",
              url = m.elConnections[idx].engineUrl.url,
              reason = errmsg

      await noCancel allFutures(
        requests.filterIt(not it.finished()).mapIt(it.cancelAndWait())
      )

      if bestIdx.isSome():
        let chosen = requests[bestIdx.get()]
        # chosen is finished; but could still be an error, so guard again
        if chosen.error.isNil:
          return ok(chosen.value())
        else:
          warn "Chosen EL failed unexpectedly", reason = chosen.error.msg
      if timeoutExceeded:
        break

    err()

proc sendNewPayload*(
    m: ELManager,
    blck: SomeForkyBeaconBlock,
    deadline: DeadlineFuture,
    retry: bool,
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  if m.elConnections.len == 0:
    info "No execution client configured; cannot process block payloads",
      executionPayload = shortLog(blck.body.execution_payload)
    return Opt.none(PayloadExecutionStatus)

  const consensusFork = typeof(blck).kind

  let
    startTime = Moment.now()
    payload = blck.body.execution_payload.asEngineExecutionPayload

  when consensusFork >= ConsensusFork.Deneb:
    let
      versioned_hashes = blck.body.blob_kzg_commitments.asEngineVersionedHashes()
      parent_root = blck.parent_root.to(Hash32)

  when consensusFork >= ConsensusFork.Electra:
    let execution_requests = blck.body.execution_requests.asEngineExecutionRequests()

  var
    responseProcessor = ELConsensusViolationDetector.init()
    sleepCounter = 0

  while true:
    block mainLoop:
      let requests = m.elConnections.mapIt:
        let req =
          when consensusFork >= ConsensusFork.Electra:
            sendNewPayloadToSingleEL(
              it, payload, versioned_hashes, parent_root, execution_requests
            )
          elif consensusFork >= ConsensusFork.Deneb:
            sendNewPayloadToSingleEL(it, payload, versioned_hashes, parent_root)
          elif consensusFork >= ConsensusFork.Bellatrix:
            sendNewPayloadToSingleEL(it, payload)
          else:
            {.error: "Unsupported fork " & $consensusFork.}

        engineApiRequest(it, req, "newPayload", startTime, noTimeout)

      var pendingRequests = requests

      while true:
        let timeoutExceeded =
          try:
            discard await race(pendingRequests).wait(deadline)
            false
          except AsyncTimeoutError:
            true
          except ValueError:
            raiseAssert "pendingRequests should not be empty!"
          except CancelledError as exc:
            let pending =
              requests.filterIt(not(it.finished())).mapIt(it.cancelAndWait())
            await noCancel allFutures(pending)
            raise exc

        var stillPending: type(pendingRequests)
        for request in pendingRequests:
          if not(request.finished()):
            stillPending.add(request)
          elif request.completed():
            let index = requests.find(request)
            doAssert(index >= 0)
            responseProcessor.processResponse(type(payload),
                                              m.elConnections, requests, index)
        pendingRequests = stillPending

        if responseProcessor.disagreementAlreadyDetected:
          let pending =
            pendingRequests.filterIt(not(it.finished())).
              mapIt(it.cancelAndWait())
          await noCancel allFutures(pending)
          return Opt.some PayloadExecutionStatus.invalid

        if responseProcessor.selectedResponse.isSome():
          if (len(pendingRequests) == 0) or
             not(responseProcessor.couldBeBetter()):
            # We spawn task which will wait for all other responses which are
            # still pending, after 30.seconds all pending requests will be
            # cancelled.
            asyncSpawn lazyWait(pendingRequests.mapIt(FutureBase(it)))
            return
              Opt.some requests[responseProcessor.selectedResponse.get].value().status

        if timeoutExceeded:
          # Timeout exceeded, cancelling all pending requests.
          let pending =
            pendingRequests.filterIt(not(it.finished())).
              mapIt(it.cancelAndWait())
          await noCancel allFutures(pending)
          return Opt.none(PayloadExecutionStatus)

        if len(pendingRequests) == 0:
          # All requests failed.
          if not retry:
            return Opt.none(PayloadExecutionStatus)

          # To avoid continous spam of requests when EL node is offline we
          # going to sleep until next attempt.
          await variedSleep(sleepCounter, SleepDurations)
          break mainLoop

proc forkchoiceUpdatedForSingleEL(
    connection: ELConnection,
    state: ref ForkchoiceStateV1,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3]
): Future[PayloadStatusV1] {.async: (raises: [CatchableError]).} =
  let
    rpcClient = await connection.connectedRpcClient()
    response = await rpcClient.forkchoiceUpdated(state[], payloadAttributes)

  if response.payloadStatus.status notin {syncing, valid, invalid}:
    debug "Invalid fork-choice updated response from the EL",
          payloadStatus = response.payloadStatus
    return

  if response.payloadStatus.status == PayloadExecutionStatus.valid and
     response.payloadId.isSome:
    connection.lastPayloadId = response.payloadId

  return response.payloadStatus

proc forkchoiceUpdated*(
    m: ELManager,
    headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3],
    deadline: DeadlineFuture,
    retry: bool,
): Future[(PayloadExecutionStatus, Opt[Hash32])] {.
   async: (raises: [CancelledError]).} =
  doAssert not headBlockHash.isZero

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

  when payloadAttributes is Opt[PayloadAttributesV3]:
    template payloadAttributesV3(): auto =
      if payloadAttributes.isSome:
        payloadAttributes.get
      else:
        # As timestamp and prevRandao are both 0, won't false-positive match
        (static(default(PayloadAttributesV3)))
  elif payloadAttributes is Opt[PayloadAttributesV2]:
    template payloadAttributesV3(): auto =
      if payloadAttributes.isSome:
        PayloadAttributesV3(
          timestamp: payloadAttributes.get.timestamp,
          prevRandao: payloadAttributes.get.prevRandao,
          suggestedFeeRecipient: payloadAttributes.get.suggestedFeeRecipient,
          withdrawals: payloadAttributes.get.withdrawals,
          parentBeaconBlockRoot: default(Hash32))
      else:
        # As timestamp and prevRandao are both 0, won't false-positive match
        (static(default(PayloadAttributesV3)))
  elif payloadAttributes is Opt[PayloadAttributesV1]:
    template payloadAttributesV3(): auto =
      if payloadAttributes.isSome:
        PayloadAttributesV3(
          timestamp: payloadAttributes.get.timestamp,
          prevRandao: payloadAttributes.get.prevRandao,
          suggestedFeeRecipient: payloadAttributes.get.suggestedFeeRecipient,
          withdrawals: @[],
          parentBeaconBlockRoot: default(Hash32))
      else:
        # As timestamp and prevRandao are both 0, won't false-positive match
        (static(default(PayloadAttributesV3)))
  else:
    static: doAssert false

  let
    state = newClone ForkchoiceStateV1(
      headBlockHash: headBlockHash.asBlockHash,
      safeBlockHash: safeBlockHash.asBlockHash,
      finalizedBlockHash: finalizedBlockHash.asBlockHash)
    startTime = Moment.now

  var
    responseProcessor = ELConsensusViolationDetector.init()
    sleepCounter = 0
    retriesCount = 0

  while true:
    block mainLoop:
      let requests =
        m.elConnections.mapIt:
          let req = it.forkchoiceUpdatedForSingleEL(state, payloadAttributes)
          engineApiRequest(it, req, "forkchoiceUpdated", startTime, noTimeout)

      var pendingRequests = requests

      while true:
        let timeoutExceeded =
          try:
            discard await race(pendingRequests).wait(deadline)
            false
          except ValueError:
            raiseAssert "pendingRequests should not be empty!"
          except AsyncTimeoutError:
            true
          except CancelledError as exc:
            let pending =
              pendingRequests.filterIt(not(it.finished())).
                mapIt(it.cancelAndWait())
            await noCancel allFutures(pending)
            raise exc

        var stillPending: type(pendingRequests)
        for request in pendingRequests:
          if not(request.finished()):
            stillPending.add(request)
          elif request.completed():
            let index = requests.find(request)
            doAssert(index >= 0)
            responseProcessor.processResponse(
              PayloadStatusV1, m.elConnections, requests, index)
        pendingRequests = stillPending

        template assignNextExpectedPayloadParams() =
          # Ensure that there's no race condition window where getPayload's
          # check for whether it needs to trigger a new fcU payload, due to
          # cache invalidation, falsely suggests that the expected payload
          # matches, and similarly that if the fcU fails or times out for other
          # reasons, the expected payload params remain synchronized with
          # EL state.
          m.nextExpectedPayloadParams = Opt.some NextExpectedPayloadParams(
            headBlockHash: headBlockHash,
            safeBlockHash: safeBlockHash,
            finalizedBlockHash: finalizedBlockHash,
            payloadAttributes: payloadAttributesV3)

        template getSelected: untyped =
          let data = requests[responseProcessor.selectedResponse.get].value()
          (data.status, data.latestValidHash)

        if responseProcessor.disagreementAlreadyDetected:
          let pending =
            pendingRequests.filterIt(not(it.finished())).
              mapIt(it.cancelAndWait())
          await noCancel allFutures(pending)
          return (PayloadExecutionStatus.invalid, Opt.none Hash32)
        elif responseProcessor.selectedResponse.isSome:
          # We spawn task which will wait for all other responses which are
          # still pending, after 30.seconds all pending requests will be
          # cancelled.
          asyncSpawn lazyWait(pendingRequests.mapIt(FutureBase(it)))
          assignNextExpectedPayloadParams()
          return getSelected()

        if timeoutExceeded:
          # Timeout exceeded, cancelling all pending requests.
          let pending =
            pendingRequests.filterIt(not(it.finished())).
              mapIt(it.cancelAndWait())
          await noCancel allFutures(pending)
          return (PayloadExecutionStatus.syncing, Opt.none Hash32)

        if len(pendingRequests) == 0:
          # All requests failed, we will continue our attempts until deadline
          # is not finished.
          inc(retriesCount)
          if not retry:
            return (PayloadExecutionStatus.syncing, Opt.none Hash32)

          # To avoid continous spam of requests when EL node is offline we
          # going to sleep until next attempt.
          await variedSleep(sleepCounter, SleepDurations)
          break mainLoop

proc forkchoiceUpdated*(
    m: ELManager,
    headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
    payloadAttributes: Opt[PayloadAttributesV1] |
                       Opt[PayloadAttributesV2] |
                       Opt[PayloadAttributesV3]
): Future[(PayloadExecutionStatus, Opt[Hash32])] {.
    async: (raises: [CancelledError], raw: true).} =
  forkchoiceUpdated(
    m, headBlockHash, safeBlockHash, finalizedBlockHash,
    payloadAttributes, sleepAsync(FORKCHOICEUPDATED_TIMEOUT), true)

proc checkChainIdWithSingleEL(
    m: ELManager,
    connection: ELConnection
) {.async: (raises: [CancelledError]).} =
  let rpcClient = await connection.connectedRpcClient()

  if m.eth1Network.isSome and
     connection.chainIdStatus == ChainIdStatus.notExchangedYet:
    try:
      let
        providerChain = await connection.engineApiRequest(
          rpcClient.eth_chainId(), "chainId", Moment.now(),
          web3RequestsTimeout)

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

  let requests = m.elConnections.mapIt(m.checkChainIdWithSingleEL(it))
  try:
    await allFutures(requests).wait(3.seconds)
  except AsyncTimeoutError:
    discard
  except CancelledError as exc:
    let pending = requests.filterIt(not(it.finished())).
                    mapIt(it.cancelAndWait())
    await noCancel allFutures(pending)
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

  await noCancel allFutures(pending)

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

proc start*(m: ELManager, syncChain = true) {.gcsafe.} =
  if m.elConnections.len == 0:
    return

  if m.hasJwtSecret and m.checkChainIdLoopFut.isNil:
    m.checkChainIdLoopFut = m.startCheckChainIdLoop()

func `$`(x: Quantity): string =
  $(x.uint64)

func `$`(x: BlockObject): string =
  $(x.number) & " [" & $(x.hash) & "]"

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

  template request(actionDesc: static string,
                   action: untyped): untyped =
    stdout.write actionDesc & "..."
    stdout.flushFile()
    var res: typeof(read action)
    try:
      let fut = action
      res = await fut.wait(web3RequestsTimeout)
      when res is BlockObject:
        res = raiseIfNil res
      stdout.write "\r" & actionDesc & ": " & $res
    except CatchableError as err:
      stdout.write "\r" & actionDesc & ": Error(" & err.msg & ")"
    stdout.write "\n"
    res

  discard request "Chain ID":
    web3.provider.eth_chainId()

  discard request "Sync status":
    web3.provider.eth_syncing()

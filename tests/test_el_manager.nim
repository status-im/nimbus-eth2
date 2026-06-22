# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/net,
  unittest2,
  chronos,
  chronicles,
  json_rpc/[rpcserver, errors],
  web3/[primitives, conversions, engine_api_types],
  eth/common/eth_types,
  ../beacon_chain/el/[el_conf, el_manager],
  ../beacon_chain/spec/[digest, engine_authentication, forks],
  ../beacon_chain/networking/network_metadata,
  ./testutil

from std/sequtils import allIt

proc allocatePort(): Port {.raises: [TransportError].} =
  ## Allocate a free port by using a counter starting from an unused port range
  ## Each allocation increments the counter
  let srv = createStreamServer(static(initTAddress("127.0.0.1:0")))
  let port = srv.localAddress().port
  waitFor srv.closeWait()
  port

# Mock execution client state for testing
type
  MockEngineState = ref object
    ## Tracks the state of a mock execution client for testing scenarios, mainly
    ## for the purpose of testing failure, timeout and error scenarios (rather
    ## than specific payload properties)
    chainId: UInt256
    shouldFailNewPayload: bool
    shouldFailForkchoice: bool
    shouldFailGetPayload: bool
    shouldFailChainId: bool
    newPayloadCallCount: int
    newPayloadV5CallCount: int
    forkchoiceCallCount: int
    forkchoiceV4CallCount: int
    getPayloadCallCount: int
    getPayloadV6CallCount: int
    chainIdCallCount: int
    responseDelay: Duration
    blockNumber: uint64

  MockSetup = ref object
    state: MockEngineState
    server: RpcHttpServer
    url: EngineApiUrl

func createMockEngineState(
    chainId: UInt256 = 1.u256, initialBlockNumber: uint64 = 1000
): MockEngineState =
  ## Create a new mock engine state with default or custom values
  MockEngineState(
    chainId: chainId,
    shouldFailNewPayload: false,
    shouldFailForkchoice: false,
    shouldFailGetPayload: false,
    shouldFailChainId: false,
    newPayloadCallCount: 0,
    newPayloadV5CallCount: 0,
    getPayloadCallCount: 0,
    getPayloadV6CallCount: 0,
    forkchoiceCallCount: 0,
    forkchoiceV4CallCount: 0,
    chainIdCallCount: 0,
    responseDelay: 0.milliseconds,
    blockNumber: initialBlockNumber,
  )

func setupMockEngineAPI(server: RpcServer, state: MockEngineState) =
  ## Setup a mock execution engine API on the RPC server
  server.rpc("engine_newPayloadV4", EthJson) do(
    payload: ExecutionPayloadV3,
    expectedBlobVersionedHashes: Opt[seq[Hash32]],
    parentBeaconBlockRoot: Opt[Hash32],
    executionRequests: Opt[seq[seq[byte]]]
  ) -> PayloadStatusV1:
    inc state.newPayloadCallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailNewPayload:
      raise
        (ref ApplicationError)(code: -32603, msg: "Internal error: newPayloadV4 failed")

    PayloadStatusV1(
      status: PayloadExecutionStatus.valid, latestValidHash: Opt.some(payload.blockHash)
    )

  server.rpc("engine_newPayloadV5", EthJson) do(
    payload: ExecutionPayloadV4,
    expectedBlobVersionedHashes: Opt[seq[Hash32]],
    parentBeaconBlockRoot: Opt[Hash32],
    executionRequests: Opt[seq[seq[byte]]]
  ) -> PayloadStatusV1:
    inc state.newPayloadV5CallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailNewPayload:
      raise
        (ref ApplicationError)(code: -32603, msg: "Internal error: newPayloadV5 failed")

    PayloadStatusV1(
      status: PayloadExecutionStatus.valid, latestValidHash: Opt.some(payload.blockHash)
    )

  server.rpc("engine_forkchoiceUpdatedV3", EthJson) do(
    fcState: ForkchoiceStateV1, payloadAttributes: Opt[PayloadAttributesV3]
  ) -> ForkchoiceUpdatedResponse:
    inc state.forkchoiceCallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailForkchoice:
      raise (ref ApplicationError)(
        code: -32603, msg: "Internal error: forkchoiceUpdatedV3 failed"
      )

    ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(
        status: PayloadExecutionStatus.valid,
        latestValidHash: Opt.some(fcState.headBlockHash),
      ),
      payloadId:
        if payloadAttributes.isSome:
          Opt.some(Bytes8([1'u8, 2, 3, 4, 5, 6, 7, 8]))
        else:
          Opt.none(Bytes8),
    )

  server.rpc("engine_forkchoiceUpdatedV4", EthJson) do(
    fcState: ForkchoiceStateV1, payloadAttributes: Opt[PayloadAttributesV4]
  ) -> ForkchoiceUpdatedResponse:
    inc state.forkchoiceV4CallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailForkchoice:
      raise (ref ApplicationError)(
        code: -32603, msg: "Internal error: forkchoiceUpdatedV4 failed"
      )

    ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(
        status: PayloadExecutionStatus.valid,
        latestValidHash: Opt.some(fcState.headBlockHash),
      ),
      payloadId:
        if payloadAttributes.isSome:
          Opt.some(Bytes8([1'u8, 2, 3, 4, 5, 6, 7, 8]))
        else:
          Opt.none(Bytes8),
    )

  server.rpc("engine_getPayloadV4", EthJson) do(payloadId: Bytes8) -> GetPayloadV4Response:
    inc state.getPayloadCallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailGetPayload:
      raise
        (ref ApplicationError)(code: -32603, msg: "Internal error: getPayloadV4 failed")

    GetPayloadV4Response()

  server.rpc("engine_getPayloadV6", EthJson) do(payloadId: Bytes8) -> GetPayloadV6Response:
    inc state.getPayloadV6CallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailGetPayload:
      raise
        (ref ApplicationError)(code: -32603, msg: "Internal error: getPayloadV6 failed")

    GetPayloadV6Response()

  server.rpc("eth_chainId", EthJson) do() -> UInt256:
    inc state.chainIdCallCount
    if state.responseDelay > 0.milliseconds:
      await sleepAsync(state.responseDelay)

    if state.shouldFailChainId:
      raise (ref ApplicationError)(
        code: -32603, msg: "Internal error: chain id query failed"
      )

    state.chainId

proc newMockRpcServer(
    state: MockEngineState, port: Port
): RpcHttpServer {.raises: [CatchableError].} =
  ## Create and start a new mock RPC server on the given port
  let server = newRpcHttpServer()
  setupMockEngineAPI(server, state)

  server.addHttpServer(
    address = initTAddress("127.0.0.1", port), maxRequestBodySize = 16 * 1024 * 1024
  )

  server.start()
  server

func createEngineApiUrl(
    port: Port, jwtSecret: Opt[JwtSharedKey] = Opt.none(JwtSharedKey)
): EngineApiUrl =
  let urlStr = "http://127.0.0.1:" & $port.uint16
  EngineApiUrl.init(urlStr, jwtSecret)

proc mockSetup(): MockSetup {.raises: [CatchableError].}  =
  let
    port = allocatePort()
    state = createMockEngineState()
    server = newMockRpcServer(state, port)

  server.start()

  MockSetup(state: state, server: server, url: createEngineApiUrl(port))

proc close(setup: MockSetup) =
  waitFor setup.server.stop()
  waitFor setup.server.closeWait()

type
  TcpProxy = ref object
    server: StreamServer
    target: TransportAddress
    pipes: seq[StreamTransport]

  WsMockSetup = ref object
    state: MockEngineState
    server: RpcWebSocketServer
    proxy: TcpProxy
    url: EngineApiUrl

proc pipeData(src, dst: StreamTransport) {.async: (raises: []).} =
  var buf: array[4096, byte]
  try:
    while true:
      let n = await src.readOnce(addr buf[0], buf.len)
      if n <= 0:
        break
      discard await dst.write(addr buf[0], n)
  except TransportError:
    discard # pipe ends when either side is closed/severed
  except CancelledError:
    discard
  # Propagate the close to the other side of the pipe
  await noCancel allFutures(src.closeWait(), dst.closeWait())

proc startTcpProxy(target: TransportAddress): TcpProxy {.
    raises: [TransportOsError].} =
  let proxy = TcpProxy(target: target)

  proc handler(server: StreamServer, client: StreamTransport) {.
      async: (raises: []).} =
    let upstream =
      try:
        await connect(proxy.target)
      except TransportError:
        await noCancel client.closeWait()
        return
      except CancelledError:
        await noCancel client.closeWait()
        return
    proxy.pipes.add client
    proxy.pipes.add upstream
    asyncSpawn pipeData(client, upstream)
    asyncSpawn pipeData(upstream, client)

  proxy.server = createStreamServer(
    static(initTAddress("127.0.0.1:0")), handler, {ServerFlags.ReuseAddr})
  proxy.server.start()
  proxy

proc severConnections(proxy: TcpProxy) {.async: (raises: []).} =
  for transp in move(proxy.pipes):
    await noCancel transp.closeWait()

proc wsMockSetup(): WsMockSetup {.raises: [TransportError, JsonRpcError].} =
  let
    state = createMockEngineState()
    server = newRpcWebSocketServer("127.0.0.1", allocatePort())
  setupMockEngineAPI(server, state)
  server.start()

  let proxy = startTcpProxy(server.localAddress())
  WsMockSetup(
    state: state, server: server, proxy: proxy,
    url: EngineApiUrl.init(
      "ws://127.0.0.1:" & $proxy.server.localAddress().port.uint16))

proc close(setup: WsMockSetup) =
  waitFor setup.proxy.severConnections()
  try:
    setup.proxy.server.stop()
  except TransportOsError:
    discard
  waitFor setup.proxy.server.closeWait()
  setup.server.stop()
  waitFor setup.server.closeWait()

proc fcuValid(
    manager: ELManager, deadlineMs = 250
): Future[bool] {.async: (raises: [CancelledError]).} =
  let (status, _) = await manager.forkchoiceUpdated(
    ForkchoiceStateV1.init(ZERO_HASH, ZERO_HASH, ZERO_HASH),
    Opt.none(PayloadAttributesV3),
    sleepAsync(deadlineMs.milliseconds), false)
  status == PayloadExecutionStatus.valid

proc fcuValidEventually(
    manager: ELManager
): Future[bool] {.async: (raises: [CancelledError]).} =
  let deadline = Moment.now() + 10.seconds
  while Moment.now() < deadline:
    if await manager.fcuValid():
      return true
    await sleepAsync(10.milliseconds)
  false

suite "EL Manager - Helpers":
  test "Rewrite URLs":
    var
      gethHttpUrl = "http://localhost:8545"
      gethHttpsUrl = "https://localhost:8545"
      gethWsUrl = "ws://localhost:8545"
      unspecifiedProtocolUrl = "localhost:8545"

    fixupWeb3Urls gethHttpUrl
    fixupWeb3Urls gethHttpsUrl
    fixupWeb3Urls gethWsUrl
    fixupWeb3Urls unspecifiedProtocolUrl

    check:
      gethHttpUrl == "http://localhost:8545"
      gethHttpsUrl == "https://localhost:8545"
      unspecifiedProtocolUrl == "ws://localhost:8545"

      gethWsUrl == "ws://localhost:8545"

func createELManager(
    engines: seq[EngineApiUrl], eth1Network: Opt[Eth1Network] = Opt.none(Eth1Network)
): ELManager =
  ELManager.new(engines, eth1Network)

suite "EL Manager - Async Operations":
  setup:
    var mockState = createMockEngineState(chainId = 1.u256)
    var mockPort = allocatePort()
    var server = newMockRpcServer(mockState, mockPort)

  teardown:
    try:
      waitFor server.stop()
      waitFor server.closeWait()
    except CatchableError:
      discard

  test "ELManager can be started and stopped safely":
    let engineUrl = createEngineApiUrl(mockPort)
    let manager = createELManager(@[engineUrl])
    manager.start()
    check manager.hasConnection()
    # Start is async-spawned internally, just verify no crash

  test "ELManager with custom chain network":
    mockState.chainId = 11155111.u256
    let engineUrl = createEngineApiUrl(mockPort)
    let manager = createELManager(@[engineUrl], Opt.some(sepolia))
    manager.start()

    check manager.hasConnection()

suite "EL Manager - forkchoiceUpdated":
  setup:
    let setup = mockSetup()

  teardown:
    setup.close()

  test "forkchoiceUpdated basic call":
    let manager = createELManager(@[setup.url])
    manager.start()

    check setup.state.forkchoiceCallCount == 0

    let state =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status, payload) = waitFor manager.forkchoiceUpdated(
      state, Opt.none(PayloadAttributesV3), sleepAsync(5.seconds), false
    )

    # Verify the call was made
    check:
      setup.state.forkchoiceCallCount == 1
      status == PayloadExecutionStatus.valid

  test "forkchoiceUpdatedV4 basic call":
    let manager = createELManager(@[setup.url])
    manager.start()

    check setup.state.forkchoiceCallCount == 0

    let state =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status, payload) = waitFor manager.forkchoiceUpdated(
      state, Opt.none(PayloadAttributesV4), sleepAsync(5.seconds), false
    )

    # Verify the call was made
    check:
      setup.state.forkchoiceV4CallCount == 1
      status == PayloadExecutionStatus.valid

  test "forkchoiceUpdated with payload attributes":
    let manager = createELManager(@[setup.url])
    manager.start()

    let attributes = Opt.some(
      PayloadAttributesV3.init(
        1234567890, Eth2Digest.default, EthAddress.default, @[], Eth2Digest.default
      )
    )

    check setup.state.forkchoiceCallCount == 0

    let state =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status, payload) =
      waitFor manager.forkchoiceUpdated(state, attributes, sleepAsync(5.seconds), false)

    check:
      setup.state.forkchoiceCallCount == 1
      status == PayloadExecutionStatus.valid
      # When attributes are provided, a payload ID should be assigned
      payload.isSome

  test "forkchoiceUpdated with response delay":
    setup.state.responseDelay = 100.milliseconds
    let manager = createELManager(@[setup.url])
    manager.start()

    let deadline = sleepAsync(5.seconds)

    let startTime = Moment.now()
    let state2 =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status2, payload2) = waitFor manager.forkchoiceUpdated(
      state2, Opt.none(PayloadAttributesV3), deadline, false
    )
    let duration = Moment.now() - startTime

    # Should have taken at least as long as the response delay
    check duration >= setup.state.responseDelay
    check status2 == PayloadExecutionStatus.valid

  test "forkchoiceUpdated multiple sequential calls":
    let manager = createELManager(@[setup.url])
    manager.start()

    let deadline = sleepAsync(5.seconds)

    check setup.state.forkchoiceCallCount == 0

    for i in 1 .. 3:
      let state3 = ForkchoiceStateV1.init(
        Eth2Digest.default, Eth2Digest.default, Eth2Digest.default
      )
      let (status3, _) = waitFor manager.forkchoiceUpdated(
        state3, Opt.none(PayloadAttributesV3), deadline, false
      )
      check:
        status3 == PayloadExecutionStatus.valid
        setup.state.forkchoiceCallCount == i

  test "forkchoiceUpdated times out without selected response":
    setup.state.shouldFailForkchoice = true
    let manager = createELManager(@[setup.url])
    manager.start()

    const
      deadline = 2.seconds
      overhead = 2.seconds
      testTimeout = 30.seconds
    static: doAssert deadline + overhead < testTimeout
    let
      state = ForkchoiceStateV1.init(ZERO_HASH, ZERO_HASH, ZERO_HASH)
      startTime = Moment.now()
      fut = manager.forkchoiceUpdated(
        state, Opt.none(PayloadAttributesV3), sleepAsync(deadline), true)
      completed = waitFor fut.withTimeout(testTimeout)
      elapsed = Moment.now() - startTime

    if not completed:
      waitFor fut.cancelAndWait()
    check completed

    let (status, _) = fut.read()
    check:
      setup.state.forkchoiceCallCount > 1
      elapsed < deadline + overhead
      status == PayloadExecutionStatus.syncing

suite "EL Manager - getPayload":
  setup:
    var setup = mockSetup()

  teardown:
    setup.close()

  test "success without retry":
    let
      manager = createELManager(@[setup.url])
      state = ForkchoiceStateV1.init(ZERO_HASH, ZERO_HASH, ZERO_HASH)
      attrs = PayloadAttributesV3.init(
        0'u64, ZERO_HASH, default(Eth1Address),
        default(seq[capella.Withdrawal]), ZERO_HASH)
      resp =
        waitFor manager.getPayload(electra.ExecutionPayloadForSigning, state, attrs)

    check:
      setup.state.getPayloadCallCount == 1
      resp.isOk()

  test "success without retry using getPayloadV6":
    let
      manager = createELManager(@[setup.url])
      state = ForkchoiceStateV1.init(ZERO_HASH, ZERO_HASH, ZERO_HASH)
      attrs = PayloadAttributesV4.init(
        0'u64, ZERO_HASH, default(Eth1Address),
        default(seq[capella.Withdrawal]), ZERO_HASH, Slot(1), 60_000_000'u64)
      resp =
        waitFor manager.getPayload(gloas.ExecutionPayloadForSigning, state, attrs)

    check:
      setup.state.getPayloadV6CallCount == 1
      resp.isOk()

suite "EL Manager - newPayload":
  setup:
    var setup = mockSetup()

  teardown:
    setup.close()

  test "success without retry":
    let
      manager = createELManager(@[setup.url])

      resp = waitFor manager.newPayload(
        default(electra.BeaconBlock), noEnvelope, sleepAsync(10.seconds), false
      )

    check:
      setup.state.newPayloadCallCount == 1
      resp.isOk()

  test "success without retry using newPayloadV5":
    let
      manager = createELManager(@[setup.url])

      resp = waitFor manager.newPayload(
        default(gloas.BeaconBlock), default(ExecutionPayloadEnvelope),
        sleepAsync(10.seconds), false
      )

    check:
      setup.state.newPayloadV5CallCount == 1
      resp.isOk()

  test "newPayload times out without selected response":
    setup.state.shouldFailNewPayload = true
    let manager = createELManager(@[setup.url])
    manager.start()

    const
      deadline = 2.seconds
      overhead = 2.seconds
      testTimeout = 30.seconds
    static: doAssert deadline + overhead < testTimeout
    let
      startTime = Moment.now()
      fut = manager.newPayload(
        fulu.BeaconBlock(), noEnvelope, sleepAsync(deadline), true)
      completed = waitFor fut.withTimeout(testTimeout)
      elapsed = Moment.now() - startTime

    if not completed:
      waitFor fut.cancelAndWait()
    check completed

    let resp = fut.read()
    check:
      setup.state.newPayloadCallCount > 1
      elapsed < deadline + overhead
      resp.isNone

suite "EL Manager - Payload Request Caching":
  setup:
    let setup = mockSetup()

  teardown:
    setup.close()

  test "getPayload reuses cached forkchoiceUpdated when parameters match":
    ## This test verifies that when getPayload is called with the same parameters
    ## as the previous forkchoiceUpdated call, it reuses that cached response
    ## instead of making a new forkchoiceUpdated call
    let manager = createELManager(@[setup.url])
    manager.start()

    let attrsPayload = PayloadAttributesV3.init(
      1234567890, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    let attributes = Opt.some(attrsPayload)

    # First, make a forkchoiceUpdated call with payload attributes
    check setup.state.forkchoiceCallCount == 0
    let state =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status, payloadId) =
      waitFor manager.forkchoiceUpdated(state, attributes, sleepAsync(5.seconds), false)

    check:
      setup.state.forkchoiceCallCount == 1
      status == PayloadExecutionStatus.valid
      payloadId.isSome

    # Now call getPayload - this should reuse the cached forkchoiceUpdated result
    let stateForGet =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let payload = waitFor manager.getPayload(
      electra.ExecutionPayloadForSigning, stateForGet, attrsPayload
    )

    check:
      # forkchoiceUpdated should still have been called only once
      setup.state.forkchoiceCallCount == 1
      setup.state.getPayloadCallCount == 1
      payload.isSome

  test "getPayload makes new forkchoiceUpdated when parameters change":
    ## This test verifies that when getPayload is called with different parameters
    ## than the previous forkchoiceUpdated call, it makes a new forkchoiceUpdated request
    let manager = createELManager(@[setup.url])
    manager.start()
    let
      attrs1 = PayloadAttributesV3.init(
        1234567890, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
      )
      attributes1 = Opt.some(attrs1)

    # First forkchoiceUpdated call
    let state1 =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status1, _) = waitFor manager.forkchoiceUpdated(
      state1, attributes1, sleepAsync(5.seconds), false
    )
    check:
      setup.state.forkchoiceCallCount == 1
      status1 == PayloadExecutionStatus.valid

    # Now change a parameter (timestamp) and call getPayload
    let stateForGet2 =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let attrsGet2 = PayloadAttributesV3.init(
      1234567999, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    let payload = waitFor manager.getPayload(
      electra.ExecutionPayloadForSigning, stateForGet2, attrsGet2
    )

    check:
      # Should have made a new forkchoiceUpdated call due to parameter mismatch
      setup.state.forkchoiceCallCount == 2
      setup.state.getPayloadCallCount == 1
      payload.isSome

  test "multiple sequential forkchoiceUpdated calls with payload attributes":
    ## This test verifies that successive forkchoiceUpdated calls each update
    ## the cached payload request appropriately
    let manager = createELManager(@[setup.url])
    manager.start()

    let attrsSeq = PayloadAttributesV3.init(
      1000, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    let attributes = Opt.some(attrsSeq)

    # Make multiple sequential forkchoiceUpdated calls
    for i in 1 .. 3:
      let stateSeq = ForkchoiceStateV1.init(
        Eth2Digest.default, Eth2Digest.default, Eth2Digest.default
      )
      let (status, payloadId) = waitFor manager.forkchoiceUpdated(
        stateSeq, attributes, sleepAsync(5.seconds), false
      )
      check:
        setup.state.forkchoiceCallCount == i
        status == PayloadExecutionStatus.valid
        payloadId.isSome

  test "forkchoiceUpdated without payload attributes doesn't cache":
    ## This test verifies that forkchoiceUpdated calls without payload attributes
    ## don't cache a payload request (since they won't be used for payload preparation)
    let manager = createELManager(@[setup.url])
    manager.start()

    # Make a forkchoiceUpdated call WITHOUT payload attributes
    let stateNoAttrs =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status, _) = waitFor manager.forkchoiceUpdated(
      stateNoAttrs, Opt.none(PayloadAttributesV3), sleepAsync(5.seconds), false
    )

    check:
      setup.state.forkchoiceCallCount == 1
      status == PayloadExecutionStatus.valid

  test "concurrent forkchoiceUpdated calls":
    ## This test verifies that multiple concurrent forkchoiceUpdated calls
    ## all complete successfully
    let manager = createELManager(@[setup.url])
    manager.start()

    let attrsConcurrent = PayloadAttributesV3.init(
      1000, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    let attributes = Opt.some(attrsConcurrent)

    let
      stateC = ForkchoiceStateV1.init(
        Eth2Digest.default, Eth2Digest.default, Eth2Digest.default
      )
      fut1 = manager.forkchoiceUpdated(stateC, attributes, sleepAsync(5.seconds), false)
      fut2 = manager.forkchoiceUpdated(stateC, attributes, sleepAsync(5.seconds), false)
      fut3 = manager.forkchoiceUpdated(stateC, attributes, sleepAsync(5.seconds), false)

    let
      res1 = waitFor fut1
      res2 = waitFor fut2
      res3 = waitFor fut3

    # All should complete successfully
    for (status, payloadId) in [res1, res2, res3]:
      check:
        status == PayloadExecutionStatus.valid
        payloadId.isSome

    # Should have made 3 calls since they ran concurrently
    check setup.state.forkchoiceCallCount == 3

  test "getPayload with different forkchoiceUpdated attributes":
    ## This test creates different scenarios where getPayload is called with
    ## varying attributes to test the caching logic under different conditions
    let manager = createELManager(@[setup.url])
    manager.start()

    let withdrawals = seq[capella.Withdrawal] @[]

    # Scenario 1: forkchoiceUpdated with attributes, then getPayload with same params
    let attrsVar = PayloadAttributesV3.init(
      1000, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    var attributes = Opt.some(attrsVar)

    let stateA =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    discard waitFor manager.forkchoiceUpdated(
      stateA, attributes, sleepAsync(5.seconds), false
    )

    check setup.state.forkchoiceCallCount == 1

    let stateGet1 =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let attrsGet1 = PayloadAttributesV3.init(
      1000, Eth2Digest.default, Eth1Address.default, withdrawals, Eth2Digest.default
    )
    discard waitFor manager.getPayload(
      electra.ExecutionPayloadForSigning, stateGet1, attrsGet1
    )

    check setup.state.forkchoiceCallCount == 1 # Should still be 1

    # Scenario 2: forkchoiceUpdated with different timestamp
    let attrsVar2 = PayloadAttributesV3.init(
      2000, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    attributes = Opt.some(attrsVar2)

    let stateB =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    discard waitFor manager.forkchoiceUpdated(
      stateB, attributes, sleepAsync(5.seconds), false
    )

    check setup.state.forkchoiceCallCount == 2

    let stateGet2 =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let attrsGet2b = PayloadAttributesV3.init(
      2000, Eth2Digest.default, Eth1Address.default, withdrawals, Eth2Digest.default
    )
    discard waitFor manager.getPayload(
      electra.ExecutionPayloadForSigning, stateGet2, attrsGet2b
    )

    check setup.state.forkchoiceCallCount == 2 # Should still be 2

suite "EL Manager - Multiple Engines":
  setup:
    var
      setup1 = mockSetup()
      setup2 = mockSetup()

  teardown:
    setup2.close()
    setup1.close()

  test "forkchoiceUpdated with multiple engines":
    ## This test verifies that forkchoiceUpdated is sent to all configured engines
    let manager = createELManager(@[setup1.url, setup2.url])
    manager.start()

    let stateMulti =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let (status, _) = waitFor manager.forkchoiceUpdated(
      stateMulti, Opt.none(PayloadAttributesV3), sleepAsync(5.seconds), false
    )

    check:
      status == PayloadExecutionStatus.valid
      setup1.state.forkchoiceCallCount == 1
      setup2.state.forkchoiceCallCount == 1

  test "newPayload with multiple engines":
    ## This test verifies that newPayload sends the payload to all configured engines
    let manager = createELManager(@[setup1.url, setup2.url])

    let resp = waitFor manager.newPayload(
      default(electra.BeaconBlock), noEnvelope, sleepAsync(10.seconds), false
    )

    check:
      setup1.state.newPayloadCallCount == 1
      setup2.state.newPayloadCallCount == 1
      resp.isOk()

  test "getPayload with multiple engines":
    ## This test verifies that getPayload properly handles multiple engines
    let manager = createELManager(@[setup1.url, setup2.url])
    manager.start()

    let stateMultiGet =
      ForkchoiceStateV1.init(Eth2Digest.default, Eth2Digest.default, Eth2Digest.default)
    let attrsMulti = PayloadAttributesV3.init(
      1000, Eth2Digest.default, Eth1Address.default, @[], Eth2Digest.default
    )
    let payload = waitFor manager.getPayload(
      electra.ExecutionPayloadForSigning, stateMultiGet, attrsMulti
    )

    check:
      # Should attempt to get payload from engines
      setup1.state.getPayloadCallCount == 1
      setup2.state.getPayloadCallCount == 1
      payload.isSome

  test "two engines, one broken, retry":
    let manager = createELManager(@[setup1.url, setup2.url])
    setup2.state.shouldFailNewPayload = true
    let resp = waitFor manager.newPayload(
      default(electra.BeaconBlock), noEnvelope, sleepAsync(10.seconds), true
    )

    check:
      setup1.state.newPayloadCallCount == 1
      setup2.state.newPayloadCallCount > 1
      resp.isOk()

suite "EL Manager - WebSocket reconnection":
  setup:
    let
      setup = wsMockSetup()
      manager = createELManager(@[setup.url])

  teardown:
    setup.close()

  test "reconnects after EL restart (working connection)":
    check (0 ..< 3).allIt(waitFor manager.fcuValid())
    check setup.state.forkchoiceCallCount == 3

    waitFor setup.proxy.severConnections()

    # The connection degrades after `connectionStateChangeHysteresisThreshold`
    # failed requests and is re-established
    check:
      waitFor manager.fcuValidEventually()
      setup.state.forkchoiceCallCount > 3

  test "reconnects after EL restart (degraded connection)":
    check waitFor manager.fcuValid()

    # The connection transitions to the Degraded state
    setup.state.shouldFailForkchoice = true
    for _ in 0 ..< connectionStateChangeHysteresisThreshold + 1:
      discard waitFor manager.fcuValid()
    check not manager.hasAnyWorkingConnection()

    # The EL serves a few requests, but not enough to transition to a Working
    # state, then restarts again
    setup.state.shouldFailForkchoice = false
    let healthyCalls = setup.state.forkchoiceCallCount
    check (0 ..< 3).allIt(waitFor manager.fcuValid())
    check setup.state.forkchoiceCallCount == healthyCalls + 3

    waitFor setup.proxy.severConnections()

    # The EL manager re-establishes a connection and resumes engine calls
    check:
      waitFor manager.fcuValidEventually()
      setup.state.forkchoiceCallCount > healthyCalls + 3

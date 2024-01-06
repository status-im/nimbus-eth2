## Fake execution engine API implementation useful for testing beacon node without a running execution node

# Nimbus
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/typetraits,
  stew/byteutils,
  json_rpc/[rpcserver, errors],
  web3/[conversions, engine_api_types, eth_api_types],
  chronicles

proc setupEngineAPI*(server: RpcServer) =
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/paris.md#engine_newpayloadv1
  # cannot use `params` as param name. see https:#github.com/status-im/nim-json-rpc/issues/128
  server.rpc("engine_newPayloadV1") do(payload: ExecutionPayloadV1) -> PayloadStatusV1:
    info "engine_newPayloadV1",
      number = $(distinctBase payload.blockNumber), hash = payload.blockHash

    return PayloadStatusV1(
      status: PayloadExecutionStatus.syncing,
    )

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/shanghai.md#engine_newpayloadv2
  server.rpc("engine_newPayloadV2") do(payload: ExecutionPayloadV2) -> PayloadStatusV1:
    info "engine_newPayloadV2", payload

    return PayloadStatusV1(
      status: PayloadExecutionStatus.syncing,
    )

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/paris.md#engine_getpayloadv1
  server.rpc("engine_getPayloadV1") do(payloadId: PayloadID) -> ExecutionPayloadV1:
    info "engine_getPayloadV1",
      id = payloadId.toHex

    raise (ref InvalidRequest)(
      code: engineApiUnknownPayload,
      msg: "Unkown payload"
    )

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/paris.md#engine_exchangetransitionconfigurationv1
  server.rpc("engine_exchangeTransitionConfigurationV1") do(conf: TransitionConfigurationV1) -> TransitionConfigurationV1:
    info "engine_exchangeTransitionConfigurationV1",
      ttd = conf.terminalTotalDifficulty,
      number = uint64(conf.terminalBlockNumber),
      blockHash = conf.terminalBlockHash

    return conf

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/paris.md#engine_forkchoiceupdatedv1
  server.rpc("engine_forkchoiceUpdatedV1") do(
      update: ForkchoiceStateV1,
      payloadAttributes: Option[PayloadAttributesV1]) -> ForkchoiceUpdatedResponse:
    info "engine_forkchoiceUpdatedV1",
      update,
      payloadAttributes

    return ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(
      status: PayloadExecutionStatus.syncing))

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/shanghai.md#engine_forkchoiceupdatedv2
  server.rpc("engine_forkchoiceUpdatedV2") do(
      forkchoiceState: ForkchoiceStateV1, payloadAttributes: Option[PayloadAttributesV2]) -> ForkchoiceUpdatedResponse:
    info "engine_forkchoiceUpdatedV2",
      forkchoiceState, payloadAttributes

    return ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(
      status: PayloadExecutionStatus.syncing))

  server.rpc("eth_getBlockByNumber") do(
      quantityTag: string, fullTransactions: bool) -> JsonNode:
    info "eth_getBlockByNumber", quantityTag, fullTransactions

    return if quantityTag == "latest":
      %BlockObject(number: 1000.Quantity)
    else:
      newJObject()

  server.rpc("eth_getBlockByHash") do(
      data: string, fullTransactions: bool) -> BlockObject:
    info "eth_getBlockByHash", data = toHex(data), fullTransactions

    return BlockObject(number: 1000.Quantity)

  server.rpc("eth_chainId") do() -> Quantity:
    info "eth_chainId"

    return 1.Quantity

when isMainModule:
  let server = newRpcHttpServer(
        # authHooks = @[httpJwtAuthHook, httpCorsHook],
  )

  server.addHttpServer(
    initTAddress("127.0.0.1", 8551),
    maxRequestBodySize = 16 * 1024 * 1024)

  server.setupEngineAPI()
  server.start()

  when compiles(waitFor waitSignal(SIGINT)):
    waitFor waitSignal(SIGINT)
    waitFor server.stop()
  else:
    runForever()

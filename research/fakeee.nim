## Fake execution engine API implementation useful for testing beacon node without a running execution node

# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/typetraits,
  json_rpc/[rpcserver, errors],
  web3/[conversions, engine_api_types],
  chronicles

proc setupEngineAPI*(server: RpcServer) =
  # https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_newpayloadv1
  # cannot use `params` as param name. see https:#github.com/status-im/nim-json-rpc/issues/128
  server.rpc("engine_newPayloadV1") do(payload: ExecutionPayloadV1) -> PayloadStatusV1:
    info "engine_newPayloadV1",
      number = $(distinctBase payload.blockNumber), hash = payload.blockHash

    return PayloadStatusV1(
      status: PayloadExecutionStatus.syncing,
    )

  # https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_getpayloadv1
  server.rpc("engine_getPayloadV1") do(payloadId: PayloadID) -> ExecutionPayloadV1:
    info "engine_getPayloadV1",
      id = payloadId.toHex

    raise (ref InvalidRequest)(
      code: engineApiUnknownPayload,
      msg: "Unkown payload"
    )

  # https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_exchangetransitionconfigurationv1
  server.rpc("engine_exchangeTransitionConfigurationV1") do(conf: TransitionConfigurationV1) -> TransitionConfigurationV1:
    info "engine_exchangeTransitionConfigurationV1",
      ttd = conf.terminalTotalDifficulty,
      number = uint64(conf.terminalBlockNumber),
      blockHash = conf.terminalBlockHash

    return conf

  # https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_forkchoiceupdatedv1
  server.rpc("engine_forkchoiceUpdatedV1") do(
      update: ForkchoiceStateV1,
      payloadAttributes: Option[PayloadAttributesV1]) -> ForkchoiceUpdatedResponse:
    info "engine_forkchoiceUpdatedV1",
      meth = "forkchoiceUpdatedV1",
      update,
      payloadAttributes

    return ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(
      status: PayloadExecutionStatus.syncing))

when isMainModule:
  let server = newRpcHttpServer(
        [initTAddress("127.0.0.1", 8551)],
        # authHooks = @[httpJwtAuthHook, httpCorsHook]
  )

  server.setupEngineAPI()
  server.start()

  waitFor waitSignal(SIGINT)
  waitFor server.stop()

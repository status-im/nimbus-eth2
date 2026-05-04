# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## Fake execution engine API implementation useful for testing beacon node without a running execution node

import
  std/typetraits,
  stew/byteutils,
  json_rpc/[rpcserver, errors],
  web3/[conversions, engine_api_types, eth_api_types],
  chronicles

proc setupEngineAPI*(server: RpcServer) =
  server.rpc(EthJson):
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/paris.md#engine_newpayloadv1
    # cannot use `params` as param name. see https:#github.com/status-im/nim-json-rpc/issues/128
    proc engine_newPayloadV1(payload: ExecutionPayloadV1): PayloadStatusV1 =
      info "engine_newPayloadV1",
        number = $(distinctBase payload.blockNumber), hash = payload.blockHash

      return PayloadStatusV1(
        status: PayloadExecutionStatus.syncing,
      )

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/shanghai.md#engine_newpayloadv2
    proc engine_newPayloadV2(payload: ExecutionPayloadV2): PayloadStatusV1 =
      info "engine_newPayloadV2", payload

      return PayloadStatusV1(
        status: PayloadExecutionStatus.syncing,
      )

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/paris.md#engine_getpayloadv1
    proc engine_getPayloadV1(payloadId: Bytes8): ExecutionPayloadV1 {.raises: [ApplicationError].} =
      info "engine_getPayloadV1",
        id = payloadId.toHex

      raise (ref ApplicationError)(
        code: engineApiUnknownPayload,
        msg: "Unknown payload"
      )

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/paris.md#engine_forkchoiceupdatedv1
    proc engine_forkchoiceUpdatedV1(
        update: ForkchoiceStateV1,
        payloadAttributes: Opt[PayloadAttributesV1]): ForkchoiceUpdatedResponse =
      info "engine_forkchoiceUpdatedV1",
        update,
        payloadAttributes

      return ForkchoiceUpdatedResponse(
        payloadStatus: PayloadStatusV1(
        status: PayloadExecutionStatus.syncing))

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/shanghai.md#engine_forkchoiceupdatedv2
    proc engine_forkchoiceUpdatedV2(
        forkchoiceState: ForkchoiceStateV1, payloadAttributes: Opt[PayloadAttributesV2]): ForkchoiceUpdatedResponse =
      info "engine_forkchoiceUpdatedV2",
        forkchoiceState, payloadAttributes

      return ForkchoiceUpdatedResponse(
        payloadStatus: PayloadStatusV1(
        status: PayloadExecutionStatus.syncing))

    proc eth_getBlockByNumber(
        quantityTag: string, fullTransactions: bool): JsonString =
      info "eth_getBlockByNumber", quantityTag, fullTransactions

      return if quantityTag == "latest":
        EthJson.encode(BlockObject(number: 1000.Quantity)).JsonString
      else:
        "{}".JsonString

    proc eth_getBlockByHash(
        data: string, fullTransactions: bool): BlockObject =
      info "eth_getBlockByHash", data = toHex(data), fullTransactions

      return BlockObject(number: 1000.Quantity)

    proc eth_chainId(): UInt256 =
      info "eth_chainId"

      return 1.u256

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

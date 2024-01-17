# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  confutils, presto,
  ../beacon_chain/spec/datatypes/capella,
  ../beacon_chain/rpc/rest_utils,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client

const HttpOk = 200

type
  ParentHeaderInfo = object
    block_number: uint64
    timestamp: uint64

  MevMockConf* = object
    # Deliberately no default. Assuming such has caused too many CI issues
    port {. desc: "REST HTTP server port" .}: int

proc getPrevRandao(restClient: RestClientRef):
    Future[Opt[Eth2Digest]] {.async.} =
  let resp: RestResponse[rest_types.GetStateRandaoResponse] =
    await restClient.getStateRandao(StateIdent.init(StateIdentType.Head))

  return if resp.status == HttpOk:
    Opt.some resp.data.data.randao
  else:
    Opt.none Eth2Digest

proc getParentBlock(restClient: RestClientRef):
    Future[Opt[ParentHeaderInfo]] {.async.} =
  let
    respMaybe: Option[ref ForkedSignedBeaconBlock] =
      # defaultRuntimeConfig only kicks in for SSZ and this can use JSON
      await restClient.getBlockV2(
        BlockIdent.init(BlockIdentType.Head), defaultRuntimeConfig)
    resp =
      if respMaybe.isSome and not respMaybe.get.isNil:
        respMaybe.get[]
      else:
        return Opt.none ParentHeaderInfo

  withBlck(resp):
    when consensusFork >= ConsensusFork.Capella:
      return Opt.some ParentHeaderInfo(
        block_number: forkyBlck.message.body.execution_payload.block_number,
        timestamp: forkyBlck.message.body.execution_payload.timestamp)
    else:
      discard

proc getWithdrawals(restClient: RestClientRef):
    Future[Opt[seq[Withdrawal]]] {.async.} =
  let resp: RestResponse[rest_types.GetNextWithdrawalsResponse] =
    await restClient.getNextWithdrawals(StateIdent.init(StateIdentType.Head))

  return if resp.status == HttpOk:
    Opt.some resp.data.data
  else:
    Opt.none seq[Withdrawal]

proc getInfo(parent_hash: Eth2Digest):
    Future[Opt[capella.ExecutionPayload]] {.async.} =
  const DEFAULT_GAS_LIMIT: uint64 = 30000000

  # TODO parallelize with await allFutures() to at least mitigate head race
  var restClient: RestClientRef
  let
    prev_randao = (await getPrevRandao(restClient)).valueOr:
      return Opt.none capella.ExecutionPayload
    parent_block_info = (await getParentBlock(restClient)).valueOr:
      return Opt.none capella.ExecutionPayload
    withdrawals = (await getWithdrawals(restClient)).valueOr:
      return Opt.none capella.ExecutionPayload

  var execution_payload = capella.ExecutionPayload(
    parent_hash: parent_hash,
    fee_recipient: default(ExecutionAddress), # only a CL suggestion
    logs_bloom: default(BloomLogs),
    timestamp: parentBlockInfo.timestamp,
    prev_randao: prev_randao,
    block_number: parent_block_info.block_number,
    gas_limit: DEFAULT_GAS_LIMIT,
    gas_used: 0,
    extra_data: default(List[byte, 32]),
    transactions: default(List[Transaction, 1048576]),
    withdrawals: List[capella.Withdrawal, 16].init(withdrawals)
  )

  return Opt.some execution_payload

func getExecutionPayloadHeader(execution_payload: capella.ExecutionPayload):
   capella.ExecutionPayloadHeader =
  capella.ExecutionPayloadHeader(
    parent_hash: execution_payload.parent_hash,
    fee_recipient: execution_payload.fee_recipient,
    state_root: execution_payload.state_root,
    receipts_root: execution_payload.receipts_root,
    logs_bloom: execution_payload.logs_bloom,
    prev_randao: execution_payload.prev_randao,
    block_number: execution_payload.block_number,
    gas_limit: execution_payload.gas_limit,
    gas_used: execution_payload.gas_used,
    timestamp: execution_payload.timestamp,
    base_fee_per_gas: execution_payload.base_fee_per_gas,
    block_hash: execution_payload.block_hash,
    extra_data: execution_payload.extra_data,
    transactions_root: hash_tree_root(execution_payload.transactions),
    withdrawals_root: hash_tree_root(execution_payload.withdrawals))

func getSignedUnblindedBeaconBlock(
    signedBlindedBlck: capella_mev.SignedBlindedBeaconBlock,
    execution_payload: capella.ExecutionPayload): capella.SignedBeaconBlock =
  template blindedBlck: untyped = signedBlindedBlck.message
  var blck = capella.SignedBeaconBlock(
    message: capella.BeaconBlock(
      slot: blindedBlck.slot,
      parent_root: blindedBlck.parent_root,
      state_root: blindedBlck.state_root,
      body: capella.BeaconBlockBody(
        randao_reveal: blindedBlck.body.randao_reveal,
        eth1_data: blindedBlck.body.eth1_data,
        graffiti: blindedBlck.body.graffiti,
        proposer_slashings: blindedBlck.body.proposer_slashings,
        attester_slashings: blindedBlck.body.attester_slashings,
        deposits: blindedBlck.body.deposits,
        voluntary_exits: blindedBlck.body.voluntary_exits,
        sync_aggregate: blindedBlck.body.sync_aggregate,
        execution_payload: execution_payload,
        bls_to_execution_changes:
          blindedBlck.body.bls_to_execution_changes)),
    signature: signedBlindedBlck.signature)
  blck.root = hash_tree_root(blck.message)
  blck

proc setupEngineAPI*(router: var RestRouter, payloadCache:
    TableRef[Eth2Digest, capella.ExecutionPayload]) =
  router.api(MethodPost, "/eth/v1/builder/validators") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:

    if contentBody.isNone:
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    # No-op, deliberately. For this purpse, the only thing this does
    return RestApiResponse.jsonResponse("")

  router.api(MethodGet, "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}") do (
    slot: Slot, parent_hash: Eth2Digest, pubkey: ValidatorPubKey) -> RestApiResponse:
    if parent_hash.isErr:
      return RestApiResponse.jsonError(Http400, "No parent head hash provided")
    let execution_payload = (await getInfo(parent_hash.get)).valueOr:
      return RestApiResponse.jsonError(Http400, "Error getting parent head information")
    payloadCache[hash_tree_root(execution_payload)] = execution_payload
    return RestApiResponse.jsonResponse(
      getExecutionPayloadHeader(execution_payload))

  router.api(MethodPost, "/eth/v1/builder/blinded_blocks") do (
      contentBody: Option[ContentBody]) -> RestApiResponse:
    if contentBody.isNone:
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    let
      body = contentBody.get()
      restBlock = decodeBody(
         capella_mev.SignedBlindedBeaconBlock, body).valueOr:
       return RestApiResponse.jsonError(Http400, InvalidBlockObjectError,
                                        $error)
      execution_header_root = hash_tree_root(
        restBlock.message.body.execution_payload_header)

    return if execution_header_root in payloadCache:
      RestApiResponse.jsonResponse(getSignedUnblindedBeaconBlock(
        restBlock, payloadCache[execution_header_root]))
    else:
      return RestApiResponse.jsonError(Http400, "Unknown execution payload")

  router.api(MethodGet, "/eth/v1/builder/status") do () -> RestApiResponse:
    return RestApiResponse.response("", Http200, "text/plain")

when isMainModule:
  let conf = MevMockConf.load()
  var router = RestRouter.init(proc(pattern: string, value: string): int = 0)
  var payloadCache: TableRef[Eth2Digest, capella.ExecutionPayload]
  setupEngineAPI(router, payloadCache)

  let server = RestServerRef.new(
    router, initTAddress("127.0.0.1", conf.port)).get()

  server.start()

  when compiles(waitFor waitSignal(SIGINT)):
    waitFor waitSignal(SIGINT)
    waitFor server.stop()
  else:
    runForever()

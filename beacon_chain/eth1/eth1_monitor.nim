# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[deques, options, strformat, strutils, sequtils, tables,
       typetraits, uri, json],
  # Nimble packages:
  chronos, metrics, chronicles/timings, stint/endians2,
  web3, web3/ethtypes as web3Types, web3/ethhexstrings, web3/engine_api,
  eth/common/eth_types,
  eth/async_utils, stew/[byteutils, objects, shims/hashes],
  # Local modules:
  ../spec/[eth2_merkleization, forks, helpers],
  ../spec/datatypes/[base, phase0, bellatrix],
  ../networking/network_metadata,
  ../consensus_object_pools/block_pools_types,
  ".."/[beacon_chain_db, beacon_node_status, beacon_clock],
  ./merkle_minimal

from std/times import getTime, inSeconds, initTime, `-`
from ../spec/engine_authentication import getSignedIatToken

export
  web3Types, deques,
  beacon_chain_db.DepositContractSnapshot

logScope:
  topics = "eth1"

type
  PubKeyBytes = DynamicBytes[48, 48]
  WithdrawalCredentialsBytes = DynamicBytes[32, 32]
  SignatureBytes = DynamicBytes[96, 96]
  Int64LeBytes = DynamicBytes[8, 8]

contract(DepositContract):
  proc deposit(pubkey: PubKeyBytes,
               withdrawalCredentials: WithdrawalCredentialsBytes,
               signature: SignatureBytes,
               deposit_data_root: FixedBytes[32])

  proc get_deposit_root(): FixedBytes[32]
  proc get_deposit_count(): Int64LeBytes

  proc DepositEvent(pubkey: PubKeyBytes,
                    withdrawalCredentials: WithdrawalCredentialsBytes,
                    amount: Int64LeBytes,
                    signature: SignatureBytes,
                    index: Int64LeBytes) {.event.}

const
  web3Timeouts = 60.seconds
  hasDepositRootChecks = defined(has_deposit_root_checks)
  hasGenesisDetection* = defined(has_genesis_detection)

type
  Eth1BlockNumber* = uint64
  Eth1BlockTimestamp* = uint64
  Eth1BlockHeader = web3Types.BlockHeader

  GenesisStateRef = ref phase0.BeaconState

  Eth1Block* = ref object
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
    deposits*: seq[DepositData]
    voteData*: Eth1Data

    when hasGenesisDetection:
      activeValidatorsCount*: uint64

  Eth1Chain* = object
    db: BeaconChainDB
    cfg: RuntimeConfig
    finalizedBlockHash: Eth2Digest
    finalizedDepositsMerkleizer: DepositsMerkleizer

      ## The latest block that reached a 50% majority vote from
      ## the Eth2 validators according to the follow distance and
      ## the ETH1_VOTING_PERIOD

    blocks: Deque[Eth1Block]
      ## A non-forkable chain of blocks ending at the block with
      ## ETH1_FOLLOW_DISTANCE offset from the head.

    blocksByHash: Table[BlockHash, Eth1Block]

    hasConsensusViolation: bool
      ## The local chain contradicts the observed consensus on the network

  Eth1MonitorState = enum
    Initialized
    Started
    ReadyToRestartToPrimary
    Failed
    Stopping
    Stopped

  Eth1Monitor* = ref object
    state: Eth1MonitorState
    startIdx: int
    web3Urls: seq[string]
    eth1Network: Option[Eth1Network]
    depositContractAddress*: Eth1Address
    forcePolling: bool
    jwtSecret: Option[seq[byte]]

    dataProvider: Web3DataProviderRef
    latestEth1Block: Option[FullBlockId]

    depositsChain: Eth1Chain
    eth1Progress: AsyncEvent

    terminalBlockHash*: Option[BlockHash]
    terminalBlockNumber*: Option[Quantity]

    runFut: Future[void]
    stopFut: Future[void]
    getBeaconTime: GetBeaconTimeFn

    when hasGenesisDetection:
      genesisValidators: seq[ImmutableValidatorData]
      genesisValidatorKeyToIndex: Table[ValidatorPubKey, ValidatorIndex]
      genesisState: GenesisStateRef
      genesisStateFut: Future[void]

  Web3DataProvider* = object
    url: string
    web3: Web3
    ns: Sender[DepositContract]
    blockHeadersSubscription: Subscription

  Web3DataProviderRef* = ref Web3DataProvider

  FullBlockId* = object
    number: Eth1BlockNumber
    hash: BlockHash

  DataProviderFailure* = object of CatchableError
  CorruptDataProvider* = object of DataProviderFailure
  DataProviderTimeout* = object of DataProviderFailure

  DisconnectHandler* = proc () {.gcsafe, raises: [Defect].}

  DepositEventHandler* = proc (
    pubkey: PubKeyBytes,
    withdrawalCredentials: WithdrawalCredentialsBytes,
    amount: Int64LeBytes,
    signature: SignatureBytes,
    merkleTreeIndex: Int64LeBytes,
    j: JsonNode) {.gcsafe, raises: [Defect].}

  BlockProposalEth1Data* = object
    vote*: Eth1Data
    deposits*: seq[Deposit]
    hasMissingDeposits*: bool

declareCounter failed_web3_requests,
  "Failed web3 requests"

declareGauge eth1_latest_head,
  "The highest Eth1 block number observed on the network"

declareGauge eth1_synced_head,
  "Block number of the highest synchronized block according to follow distance"

declareGauge eth1_finalized_head,
  "Block number of the highest Eth1 block finalized by Eth2 consensus"

declareGauge eth1_finalized_deposits,
  "Number of deposits that were finalized by the Eth2 consensus"

declareGauge eth1_chain_len,
  "The length of the in-memory chain of Eth1 blocks"

template cfg(m: Eth1Monitor): auto =
  m.depositsChain.cfg

when hasGenesisDetection:
  import ../spec/[beaconstate, signatures]

  template hasEnoughValidators(m: Eth1Monitor, blk: Eth1Block): bool =
    blk.activeValidatorsCount >= m.cfg.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT

  func chainHasEnoughValidators(m: Eth1Monitor): bool =
    m.depositsChain.blocks.len > 0 and m.hasEnoughValidators(m.depositsChain.blocks[^1])

  func isAfterMinGenesisTime(m: Eth1Monitor, blk: Eth1Block): bool =
    doAssert blk.timestamp != 0
    let t = genesis_time_from_eth1_timestamp(m.cfg, uint64 blk.timestamp)
    t >= m.cfg.MIN_GENESIS_TIME

  func isGenesisCandidate(m: Eth1Monitor, blk: Eth1Block): bool =
    m.hasEnoughValidators(blk) and m.isAfterMinGenesisTime(blk)

  proc findGenesisBlockInRange(m: Eth1Monitor, startBlock, endBlock: Eth1Block):
                               Future[Eth1Block] {.gcsafe.}

  proc signalGenesis(m: Eth1Monitor, genesisState: GenesisStateRef) =
    m.genesisState = genesisState

    if not m.genesisStateFut.isNil:
      m.genesisStateFut.complete()
      m.genesisStateFut = nil

  func allGenesisDepositsUpTo(m: Eth1Monitor, totalDeposits: uint64): seq[DepositData] =
    for i in 0 ..< int64(totalDeposits):
      result.add m.depositsChain.db.genesisDeposits.get(i)

  proc createGenesisState(m: Eth1Monitor, eth1Block: Eth1Block): GenesisStateRef =
    notice "Generating genesis state",
      blockNum = eth1Block.number,
      blockHash = eth1Block.voteData.block_hash,
      blockTimestamp = eth1Block.timestamp,
      totalDeposits = eth1Block.voteData.deposit_count,
      activeValidators = eth1Block.activeValidatorsCount

    var deposits = m.allGenesisDepositsUpTo(eth1Block.voteData.deposit_count)

    result = newClone(initialize_beacon_state_from_eth1(
      m.cfg,
      eth1Block.voteData.block_hash,
      eth1Block.timestamp.uint64,
      deposits, {}))

    if eth1Block.activeValidatorsCount != 0:
      doAssert result.validators.lenu64 == eth1Block.activeValidatorsCount

  proc produceDerivedData(m: Eth1Monitor, deposit: DepositData) =
    let htr = hash_tree_root(deposit)

    if verify_deposit_signature(m.cfg, deposit):
      let pubkey = deposit.pubkey
      if pubkey notin m.genesisValidatorKeyToIndex:
        let idx = ValidatorIndex m.genesisValidators.len
        m.genesisValidators.add ImmutableValidatorData(
          pubkey: pubkey,
          withdrawal_credentials: deposit.withdrawal_credentials)
        m.genesisValidatorKeyToIndex[pubkey] = idx

  proc processGenesisDeposit*(m: Eth1Monitor, newDeposit: DepositData) =
    m.depositsChain.db.genesisDeposits.add newDeposit
    m.produceDerivedData(newDeposit)

template depositChainBlocks*(m: Eth1Monitor): Deque[Eth1Block] =
  m.depositsChain.blocks

template finalizedDepositsMerkleizer(m: Eth1Monitor): auto =
  m.depositsChain.finalizedDepositsMerkleizer

proc fixupWeb3Urls*(web3Url: var string) =
  var normalizedUrl = toLowerAscii(web3Url)
  if not (normalizedUrl.startsWith("https://") or
          normalizedUrl.startsWith("http://") or
          normalizedUrl.startsWith("wss://") or
          normalizedUrl.startsWith("ws://")):
    warn "The Web3 URL does not specify a protocol. Assuming a WebSocket server", web3Url
    web3Url = "ws://" & web3Url

template toGaugeValue(x: Quantity): int64 =
  toGaugeValue(distinctBase x)

# TODO: Add cfg validation
# MIN_GENESIS_ACTIVE_VALIDATOR_COUNT should be larger than SLOTS_PER_EPOCH
#  doAssert SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE < GENESIS_DELAY,
#             "Invalid configuration: GENESIS_DELAY is set too low"

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(genesis_time: uint64, slot: Slot): uint64 =
  genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time(state: ForkedHashedBeaconState): uint64 =
  let eth1_voting_period_start_slot =
    getStateField(state, slot) - getStateField(state, slot) mod
      SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(
    getStateField(state, genesis_time), eth1_voting_period_start_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(cfg: RuntimeConfig,
                        blk: Eth1Block,
                        period_start: uint64): bool =
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE <= period_start) and
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE * 2 >= period_start)

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func asConsensusExecutionPayload*(rpcExecutionPayload: ExecutionPayloadV1):
    bellatrix.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  bellatrix.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient:
      ExecutionAddress(data: rpcExecutionPayload.feeRecipient.distinctBase),
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data:
      List[byte, MAX_EXTRA_DATA_BYTES].init(
        rpcExecutionPayload.extraData.distinctBase),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)))

func asEngineExecutionPayload*(executionPayload: bellatrix.ExecutionPayload):
    ExecutionPayloadV1 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV1(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: Address(executionPayload.fee_recipient.data),
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.asBlockHash,
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData:
      DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction))

func shortLog*(b: Eth1Block): string =
  try:
    &"{b.number}:{shortLog b.voteData.block_hash}(deposits = {b.voteData.deposit_count})"
  except ValueError as exc: raiseAssert exc.msg

template findBlock(chain: Eth1Chain, eth1Data: Eth1Data): Eth1Block =
  getOrDefault(chain.blocksByHash, asBlockHash(eth1Data.block_hash), nil)

func makeSuccessorWithoutDeposits(existingBlock: Eth1Block,
                                  successor: BlockObject): Eth1Block =
  result = Eth1Block(
    number: Eth1BlockNumber successor.number,
    timestamp: Eth1BlockTimestamp successor.timestamp,
    voteData: Eth1Data(
      block_hash: successor.hash.asEth2Digest,
      deposit_count: existingBlock.voteData.deposit_count,
      deposit_root: existingBlock.voteData.deposit_root))

  when hasGenesisDetection:
    result.activeValidatorsCount = existingBlock.activeValidatorsCount

func latestCandidateBlock(chain: Eth1Chain, periodStart: uint64): Eth1Block =
  for i in countdown(chain.blocks.len - 1, 0):
    let blk = chain.blocks[i]
    if is_candidate_block(chain.cfg, blk, periodStart):
      return blk

proc popFirst(chain: var Eth1Chain) =
  let removed = chain.blocks.popFirst
  chain.blocksByHash.del removed.voteData.block_hash.asBlockHash
  eth1_chain_len.set chain.blocks.len.int64

proc addBlock*(chain: var Eth1Chain, newBlock: Eth1Block) =
  chain.blocks.addLast newBlock
  chain.blocksByHash[newBlock.voteData.block_hash.asBlockHash] = newBlock
  eth1_chain_len.set chain.blocks.len.int64

func hash*(x: Eth1Data): Hash =
  hash(x.block_hash)

template awaitWithRetries*[T](lazyFutExpr: Future[T],
                              retries = 3,
                              timeout = web3Timeouts): untyped =
  const
    reqType = astToStr(lazyFutExpr)
  var
    retryDelayMs = 16000
    f: Future[T]
    attempts = 0

  while true:
    f = lazyFutExpr
    yield f or sleepAsync(timeout)
    if not f.finished:
      await cancelAndWait(f)
    elif f.failed:
      when not (f.error of CatchableError):
        static: doAssert false, "f.error not CatchableError"
      debug "Web3 request failed", req = reqType, err = f.error.msg
      inc failed_web3_requests
    else:
      break

    inc attempts
    if attempts >= retries:
      var errorMsg = reqType & " failed " & $retries & " times"
      if f.failed: errorMsg &= ". Last error: " & f.error.msg
      raise newException(DataProviderFailure, errorMsg)

    await sleepAsync(chronos.milliseconds(retryDelayMs))
    retryDelayMs *= 2

  read(f)

proc close(p: Web3DataProviderRef): Future[void] {.async.} =
  if p.blockHeadersSubscription != nil:
    try:
      awaitWithRetries(p.blockHeadersSubscription.unsubscribe())
    except CatchableError:
      debug "Failed to clean up block headers subscription properly"

  await p.web3.close()

proc getBlockByHash(p: Web3DataProviderRef, hash: BlockHash):
                    Future[BlockObject] =
  return p.web3.provider.eth_getBlockByHash(hash, false)

proc getBlockByNumber*(p: Web3DataProviderRef,
                       number: Eth1BlockNumber): Future[BlockObject] =
  let hexNumber = try: &"0x{number:X}" # No leading 0's!
  except ValueError as exc: raiseAssert exc.msg # Never fails
  p.web3.provider.eth_getBlockByNumber(hexNumber, false)

proc getPayload*(p: Eth1Monitor,
                 payloadId: bellatrix.PayloadID): Future[engine_api.ExecutionPayloadV1] =
  # Eth1 monitor can recycle connections without (external) warning; at least,
  # don't crash.
  if p.isNil:
    warn "getPayload: nil Eth1Monitor; returning empty ExecutionPayload"

  if p.isNil or p.dataProvider.isNil:
    var epr: Future[engine_api.ExecutionPayloadV1]
    epr.complete(default(engine_api.ExecutionPayloadV1))
    return epr

  if p.dataProvider.web3.isNil:
    warn "getPayload: nil dataProvider.web3"
    var epr: Future[engine_api.ExecutionPayloadV1] # TODO refactor
    epr.complete(default(engine_api.ExecutionPayloadV1))
    return epr

  if p.dataProvider.web3.provider.isNil:
    warn "getPayload: nil dataProvider.web3.provider"
    var epr: Future[engine_api.ExecutionPayloadV1] # TODO refactor
    epr.complete(default(engine_api.ExecutionPayloadV1))
    return epr

  p.dataProvider.web3.provider.engine_getPayloadV1(FixedBytes[8] payloadId)

proc newPayload*(p: Eth1Monitor, payload: engine_api.ExecutionPayloadV1):
    Future[PayloadStatusV1] =
  # Eth1 monitor can recycle connections without (external) warning; at least,
  # don't crash.
  if p.dataProvider.isNil:
    var epr: Future[PayloadStatusV1]
    epr.complete(PayloadStatusV1(status: PayloadExecutionStatus.syncing))
    return epr

  p.dataProvider.web3.provider.engine_newPayloadV1(payload)

proc forkchoiceUpdated*(p: Eth1Monitor,
                        headBlock, finalizedBlock: Eth2Digest):
                        Future[engine_api.ForkchoiceUpdatedResponse] =
  # Eth1 monitor can recycle connections without (external) warning; at least,
  # don't crash.
  if p.isNil:
    warn "forkchoiceUpdated (non-proposal): nil Eth1Monitor; returning syncing"

  if p.isNil or p.dataProvider.isNil:
    var fcuR: Future[engine_api.ForkchoiceUpdatedResponse]
    fcuR.complete(engine_api.ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing)))
    return fcuR

  if p.dataProvider.web3.isNil:
    warn "forkchoiceUpdated (non-proposal): nil dataProvider.web3"
    var fcuR: Future[engine_api.ForkchoiceUpdatedResponse]
    fcuR.complete(engine_api.ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing)))
    return fcuR

  if p.dataProvider.web3.provider.isNil:
    warn "forkchoiceUpdated (non-proposal): nil dataProvider.web3.provider"
    var fcuR: Future[engine_api.ForkchoiceUpdatedResponse]
    fcuR.complete(engine_api.ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing)))
    return fcuR

  p.dataProvider.web3.provider.engine_forkchoiceUpdatedV1(
    ForkchoiceStateV1(
      headBlockHash: headBlock.asBlockHash,

      # https://hackmd.io/@n0ble/kintsugi-spec#Engine-API
      # "CL client software MUST use headBlockHash value as a stub for the
      # safeBlockHash parameter"
      safeBlockHash: headBlock.asBlockHash,

      finalizedBlockHash: finalizedBlock.asBlockHash),
    none(engine_api.PayloadAttributesV1))

proc forkchoiceUpdated*(p: Eth1Monitor,
                        headBlock, finalizedBlock: Eth2Digest,
                        timestamp: uint64,
                        randomData: array[32, byte],
                        suggestedFeeRecipient: Eth1Address):
                        Future[engine_api.ForkchoiceUpdatedResponse] =
  # Eth1 monitor can recycle connections without (external) warning; at least,
  # don't crash.
  if p.isNil:
    warn "forkchoiceUpdated (proposal): nil Eth1Monitor; returning syncing"

  if p.isNil or p.dataProvider.isNil:
    var fcuR: Future[engine_api.ForkchoiceUpdatedResponse]
    fcuR.complete(engine_api.ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing)))
    return fcuR

  if p.dataProvider.web3.isNil:
    warn "forkchoiceUpdated (proposal): nil dataProvider.web3"
    var fcuR: Future[engine_api.ForkchoiceUpdatedResponse]
    fcuR.complete(engine_api.ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing)))
    return fcuR

  if p.dataProvider.web3.provider.isNil:
    warn "forkchoiceUpdated (proposal): nil dataProvider.web3.provider"
    var fcuR: Future[engine_api.ForkchoiceUpdatedResponse]
    fcuR.complete(engine_api.ForkchoiceUpdatedResponse(
      payloadStatus: PayloadStatusV1(status: PayloadExecutionStatus.syncing)))
    return fcuR

  p.dataProvider.web3.provider.engine_forkchoiceUpdatedV1(
    ForkchoiceStateV1(
      headBlockHash: headBlock.asBlockHash,

      # https://hackmd.io/@n0ble/kintsugi-spec#Engine-API
      # "CL client software MUST use headBlockHash value as a stub for the
      # safeBlockHash parameter"
      safeBlockHash: headBlock.asBlockHash,

      finalizedBlockHash: finalizedBlock.asBlockHash),
    some(engine_api.PayloadAttributesV1(
      timestamp: Quantity timestamp,
      prevRandao: FixedBytes[32] randomData,
      suggestedFeeRecipient: suggestedFeeRecipient)))

# TODO can't be defined within exchangeTransitionConfiguration
proc `==`(x, y: Quantity): bool {.borrow, noSideEffect.}

proc exchangeTransitionConfiguration*(p: Eth1Monitor): Future[void] {.async.} =
  # Eth1 monitor can recycle connections without (external) warning; at least,
  # don't crash.
  if p.isNil:
    warn "exchangeTransitionConfiguration: nil Eth1Monitor"

  if p.isNil or p.dataProvider.isNil:
    return

  let ccTransitionConfiguration = TransitionConfigurationV1(
    terminalTotalDifficulty: p.depositsChain.cfg.TERMINAL_TOTAL_DIFFICULTY,
    terminalBlockHash:
      if p.terminalBlockHash.isSome:
        p.terminalBlockHash.get
      else:
        # https://github.com/nim-lang/Nim/issues/19802
        (static(default(BlockHash))),
    terminalBlockNumber:
      if p.terminalBlockNumber.isSome:
        p.terminalBlockNumber.get
      else:
        # https://github.com/nim-lang/Nim/issues/19802
        (static(default(Quantity))))
  let ecTransitionConfiguration =
    await p.dataProvider.web3.provider.engine_exchangeTransitionConfigurationV1(
      ccTransitionConfiguration)
  if ccTransitionConfiguration != ecTransitionConfiguration:
    warn "exchangeTransitionConfiguration: Configuration mismatch detected",
      consensusTerminalTotalDifficulty =
        $ccTransitionConfiguration.terminalTotalDifficulty,
      consensusTerminalBlockHash =
        ccTransitionConfiguration.terminalBlockHash,
      consensusTerminalBlockNumber =
        ccTransitionConfiguration.terminalBlockNumber.uint64,
      executionTerminalTotalDifficulty =
        $ecTransitionConfiguration.terminalTotalDifficulty,
      executionTerminalBlockHash =
        ecTransitionConfiguration.terminalBlockHash,
      executionTerminalBlockNumber =
        ecTransitionConfiguration.terminalBlockNumber.uint64

template readJsonField(j: JsonNode, fieldName: string, ValueType: type): untyped =
  var res: ValueType
  fromJson(j[fieldName], fieldName, res)
  res

template init[N: static int](T: type DynamicBytes[N, N]): T =
  T newSeq[byte](N)

func depositEventsToBlocks(depositsList: JsonNode): seq[Eth1Block] {.
    raises: [Defect, CatchableError].} =
  if depositsList.kind != JArray:
    raise newException(CatchableError,
      "Web3 provider didn't return a list of deposit events")

  var lastEth1Block: Eth1Block

  for logEvent in depositsList:
    let
      blockNumber = Eth1BlockNumber readJsonField(logEvent, "blockNumber", Quantity)
      blockHash = readJsonField(logEvent, "blockHash", BlockHash)
      logData = strip0xPrefix(logEvent["data"].getStr)

    if lastEth1Block == nil or lastEth1Block.number != blockNumber:
      lastEth1Block = Eth1Block(
        number: blockNumber,
        voteData: Eth1Data(block_hash: blockHash.asEth2Digest))

      result.add lastEth1Block

    var
      pubkey = init PubKeyBytes
      withdrawalCredentials = init WithdrawalCredentialsBytes
      amount = init Int64LeBytes
      signature = init SignatureBytes
      index = init Int64LeBytes

    var offset = 0
    offset += decode(logData, offset, pubkey)
    offset += decode(logData, offset, withdrawalCredentials)
    offset += decode(logData, offset, amount)
    offset += decode(logData, offset, signature)
    offset += decode(logData, offset, index)

    if pubkey.len != 48 or
       withdrawalCredentials.len != 32 or
       amount.len != 8 or
       signature.len != 96 or
       index.len != 8:
      raise newException(CorruptDataProvider, "Web3 provider supplied invalid deposit logs")

    lastEth1Block.deposits.add DepositData(
      pubkey: ValidatorPubKey.init(pubkey.toArray),
      withdrawal_credentials: Eth2Digest(data: withdrawalCredentials.toArray),
      amount: bytes_to_uint64(amount.toArray),
      signature: ValidatorSig.init(signature.toArray))

proc fetchTimestamp(p: Web3DataProviderRef, blk: Eth1Block) {.async.} =
  let web3block = awaitWithRetries(
    p.getBlockByHash(blk.voteData.block_hash.asBlockHash))
  blk.timestamp = Eth1BlockTimestamp web3block.timestamp

type
  DepositContractDataStatus = enum
    Fetched
    VerifiedCorrect
    DepositRootIncorrect
    DepositRootUnavailable
    DepositCountIncorrect
    DepositCountUnavailable

when hasDepositRootChecks:
  const
    contractCallTimeout = seconds(60)

  template awaitOrRaiseOnTimeout[T](fut: Future[T],
                                    timeout: Duration): T =
    awaitWithTimeout(fut, timeout):
      raise newException(DataProviderTimeout, "Timeout")

  func fetchDepositContractData(p: Web3DataProviderRef, blk: Eth1Block):
                                Future[DepositContractDataStatus] {.async.} =
    let
      depositRoot = p.ns.get_deposit_root.call(blockNumber = blk.number)
      rawCount = p.ns.get_deposit_count.call(blockNumber = blk.number)

    try:
      let fetchedRoot = asEth2Digest(
        awaitOrRaiseOnTimeout(depositRoot, contractCallTimeout))
      if blk.voteData.deposit_root.isZero:
        blk.voteData.deposit_root = fetchedRoot
        result = Fetched
      elif blk.voteData.deposit_root == fetchedRoot:
        result = VerifiedCorrect
      else:
        result = DepositRootIncorrect
    except CatchableError as err:
      debug "Failed to fetch deposits root",
        blockNumber = blk.number,
        err = err.msg
      result = DepositRootUnavailable

    try:
      let fetchedCount = bytes_to_uint64(array[8, byte](
        awaitOrRaiseOnTimeout(rawCount, contractCallTimeout)))
      if blk.voteData.deposit_count == 0:
        blk.voteData.deposit_count = fetchedCount
      elif blk.voteData.deposit_count != fetchedCount:
        result = DepositCountIncorrect
    except CatchableError as err:
      debug "Failed to fetch deposits count",
            blockNumber = blk.number,
            err = err.msg
      result = DepositCountUnavailable

proc onBlockHeaders(p: Web3DataProviderRef,
                    blockHeaderHandler: BlockHeaderHandler,
                    errorHandler: SubscriptionErrorHandler) {.async.} =
  info "Waiting for new Eth1 block headers"

  p.blockHeadersSubscription = awaitWithRetries(
    p.web3.subscribeForBlockHeaders(blockHeaderHandler, errorHandler))

func getDepositsRoot*(m: DepositsMerkleizer): Eth2Digest =
  mixInLength(m.getFinalHash, int m.totalChunks)

func eth1DataFromMerkleizer(eth1Block: Eth2Digest,
                            merkleizer: DepositsMerkleizer): Eth1Data =
  Eth1Data(
    block_hash: eth1Block,
    deposit_count: merkleizer.getChunkCount,
    deposit_root: merkleizer.getDepositsRoot)

proc pruneOldBlocks(chain: var Eth1Chain, depositIndex: uint64) =
  let initialChunks = chain.finalizedDepositsMerkleizer.getChunkCount
  var lastBlock: Eth1Block

  while chain.blocks.len > 0:
    let blk = chain.blocks.peekFirst
    if blk.voteData.deposit_count >= depositIndex:
      break
    else:
      for deposit in blk.deposits:
        chain.finalizedDepositsMerkleizer.addChunk hash_tree_root(deposit).data
    chain.popFirst()
    lastBlock = blk

  if chain.finalizedDepositsMerkleizer.getChunkCount > initialChunks:
    chain.finalizedBlockHash = lastBlock.voteData.block_hash
    chain.db.putEth2FinalizedTo DepositContractSnapshot(
      eth1Block: lastBlock.voteData.block_hash,
      depositContractState: chain.finalizedDepositsMerkleizer.toDepositContractState)

    eth1_finalized_head.set lastBlock.number.toGaugeValue
    eth1_finalized_deposits.set lastBlock.voteData.deposit_count.toGaugeValue

    debug "Eth1 blocks pruned",
           newTailBlock = lastBlock.voteData.block_hash,
           depositsCount = lastBlock.voteData.deposit_count

func advanceMerkleizer(chain: Eth1Chain,
                       merkleizer: var DepositsMerkleizer,
                       depositIndex: uint64): bool =
  if chain.blocks.len == 0:
    return depositIndex == merkleizer.getChunkCount

  if chain.blocks.peekLast.voteData.deposit_count < depositIndex:
    return false

  let
    firstBlock = chain.blocks[0]
    depositsInLastPrunedBlock = firstBlock.voteData.deposit_count -
                                firstBlock.deposits.lenu64

  # advanceMerkleizer should always be called shortly after prunning the chain
  doAssert depositsInLastPrunedBlock == merkleizer.getChunkCount

  for blk in chain.blocks:
    for deposit in blk.deposits:
      if merkleizer.getChunkCount < depositIndex:
        merkleizer.addChunk hash_tree_root(deposit).data
      else:
        return true

  return merkleizer.getChunkCount == depositIndex

func getDepositsRange(chain: Eth1Chain, first, last: uint64): seq[DepositData] =
  # TODO It's possible to make this faster by performing binary search that
  #      will locate the blocks holding the `first` and `last` indices.
  # TODO There is an assumption here that the requested range will be present
  #      in the Eth1Chain. This should hold true at the single call site right
  #      now, but we need to guard the pre-conditions better.
  for blk in chain.blocks:
    if blk.voteData.deposit_count <= first:
      continue

    let firstDepositIdxInBlk = blk.voteData.deposit_count - blk.deposits.lenu64
    if firstDepositIdxInBlk >= last:
      return

    for i in 0 ..< blk.deposits.lenu64:
      let globalIdx = firstDepositIdxInBlk + i
      if globalIdx >= first and globalIdx < last:
        result.add blk.deposits[i]

func lowerBound(chain: Eth1Chain, depositCount: uint64): Eth1Block =
  # TODO: This can be replaced with a proper binary search in the
  #       future, but the `algorithm` module currently requires an
  #       `openArray`, which the `deques` module can't provide yet.
  for eth1Block in chain.blocks:
    if eth1Block.voteData.deposit_count > depositCount:
      return
    result = eth1Block

proc trackFinalizedState(chain: var Eth1Chain,
                         finalizedEth1Data: Eth1Data,
                         finalizedStateDepositIndex: uint64,
                         blockProposalExpected = false): bool =
  # Returns true if the Eth1Monitor is synced to the finalization point
  if chain.blocks.len == 0:
    debug "Eth1 chain not initialized"
    return false

  let latest = chain.blocks.peekLast
  if latest.voteData.deposit_count < finalizedEth1Data.deposit_count:
    if blockProposalExpected:
      error "The Eth1 chain is not synced",
            ourDepositsCount = latest.voteData.deposit_count,
            targetDepositsCount = finalizedEth1Data.deposit_count
    return false

  let matchingBlock = chain.lowerBound(finalizedEth1Data.deposit_count)
  result = if matchingBlock != nil:
    if matchingBlock.voteData.deposit_root == finalizedEth1Data.deposit_root:
      true
    else:
      error "Corrupted deposits history detected",
            ourDepositsCount = matchingBlock.voteData.deposit_count,
            taretDepositsCount = finalizedEth1Data.deposit_count,
            ourDepositsRoot = matchingBlock.voteData.deposit_root,
            targetDepositsRoot = finalizedEth1Data.deposit_root
      chain.hasConsensusViolation = true
      false
  else:
    error "The Eth1 chain is in inconsistent state",
          checkpointHash = finalizedEth1Data.block_hash,
          checkpointDeposits = finalizedEth1Data.deposit_count,
          localChainStart = shortLog(chain.blocks.peekFirst),
          localChainEnd = shortLog(chain.blocks.peekLast)
    chain.hasConsensusViolation = true
    false

  if result:
    chain.pruneOldBlocks(finalizedStateDepositIndex)

template trackFinalizedState*(m: Eth1Monitor,
                              finalizedEth1Data: Eth1Data,
                              finalizedStateDepositIndex: uint64): bool =
  trackFinalizedState(m.depositsChain, finalizedEth1Data, finalizedStateDepositIndex)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#get_eth1_data
proc getBlockProposalData*(chain: var Eth1Chain,
                           state: ForkedHashedBeaconState,
                           finalizedEth1Data: Eth1Data,
                           finalizedStateDepositIndex: uint64): BlockProposalEth1Data =
  let
    periodStart = voting_period_start_time(state)
    hasLatestDeposits = chain.trackFinalizedState(finalizedEth1Data,
                                                  finalizedStateDepositIndex,
                                                  blockProposalExpected = true)

  var otherVotesCountTable = initCountTable[Eth1Data]()
  for vote in getStateField(state, eth1_data_votes):
    let eth1Block = chain.findBlock(vote)
    if eth1Block != nil and
       eth1Block.voteData.deposit_root == vote.deposit_root and
       vote.deposit_count >= getStateField(state, eth1_data).deposit_count and
       is_candidate_block(chain.cfg, eth1Block, periodStart):
      otherVotesCountTable.inc vote
    else:
      debug "Ignoring eth1 vote",
            root = vote.block_hash,
            deposits = vote.deposit_count,
            depositsRoot = vote.deposit_root,
            localDeposits = getStateField(state, eth1_data).deposit_count

  let
    stateDepositIdx = getStateField(state, eth1_deposit_index)
    stateDepositsCount = getStateField(state, eth1_data).deposit_count

  # A valid state should never have this condition, but it doesn't hurt
  # to be extra defensive here because we are working with uint types
  var pendingDepositsCount = if stateDepositsCount > stateDepositIdx:
    stateDepositsCount - stateDepositIdx
  else:
    0

  if otherVotesCountTable.len > 0:
    let (winningVote, votes) = otherVotesCountTable.largest
    debug "Voting on eth1 head with majority", votes
    result.vote = winningVote
    if uint64((votes + 1) * 2) > SLOTS_PER_ETH1_VOTING_PERIOD:
      pendingDepositsCount = winningVote.deposit_count - stateDepositIdx

  else:
    let latestBlock = chain.latestCandidateBlock(periodStart)
    if latestBlock == nil:
      debug "No acceptable eth1 votes and no recent candidates. Voting no change"
      result.vote = getStateField(state, eth1_data)
    else:
      debug "No acceptable eth1 votes. Voting for latest candidate"
      result.vote = latestBlock.voteData

  if pendingDepositsCount > 0:
    if hasLatestDeposits:
      let
        totalDepositsInNewBlock = min(MAX_DEPOSITS, pendingDepositsCount)
        postStateDepositIdx = stateDepositIdx + pendingDepositsCount
        deposits = chain.getDepositsRange(stateDepositIdx, postStateDepositIdx)
        depositRoots = mapIt(deposits, hash_tree_root(it))

      var scratchMerkleizer = copy chain.finalizedDepositsMerkleizer
      if chain.advanceMerkleizer(scratchMerkleizer, stateDepositIdx):
        let proofs = scratchMerkleizer.addChunksAndGenMerkleProofs(depositRoots)
        for i in 0 ..< totalDepositsInNewBlock:
          var proof: array[33, Eth2Digest]
          proof[0..31] = proofs.getProof(i.int)
          proof[32] = default(Eth2Digest)
          proof[32].data[0..7] = toBytesLE uint64(postStateDepositIdx)
          result.deposits.add Deposit(data: deposits[i], proof: proof)
      else:
        error "The Eth1 chain is in inconsistent state" # This should not really happen
        result.hasMissingDeposits = true
    else:
      result.hasMissingDeposits = true

template getBlockProposalData*(m: Eth1Monitor,
                               state: ForkedHashedBeaconState,
                               finalizedEth1Data: Eth1Data,
                               finalizedStateDepositIndex: uint64):
                               BlockProposalEth1Data =
  getBlockProposalData(
    m.depositsChain, state, finalizedEth1Data, finalizedStateDepositIndex)

proc getJsonRpcRequestHeaders(jwtSecret: Option[seq[byte]]):
    auto =
  if jwtSecret.isSome:
    let secret = jwtSecret.get
    (proc(): seq[(string, string)] =
      # https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1
      @[("Authorization", "Bearer " & getSignedIatToken(
        secret, (getTime() - initTime(0, 0)).inSeconds))])
  else:
    (proc(): seq[(string, string)] = @[])

proc new*(T: type Web3DataProvider,
          depositContractAddress: Eth1Address,
          web3Url: string,
          jwtSecret: Option[seq[byte]]):
          Future[Result[Web3DataProviderRef, string]] {.async.} =
  let web3Fut = newWeb3(web3Url, getJsonRpcRequestHeaders(jwtSecret))
  yield web3Fut or sleepAsync(chronos.seconds(10))
  if (not web3Fut.finished) or web3Fut.failed:
    await cancelAndWait(web3Fut)
    if web3Fut.failed:
      return err "Failed to setup web3 connection: " & web3Fut.readError.msg
    else:
      return err "Failed to setup web3 connection"

  let
    web3 = web3Fut.read
    ns = web3.contractSender(DepositContract, depositContractAddress)

  return ok Web3DataProviderRef(url: web3Url, web3: web3, ns: ns)

proc putInitialDepositContractSnapshot*(db: BeaconChainDB,
                                        s: DepositContractSnapshot) =
  let existingStart = db.getEth2FinalizedTo()
  if not existingStart.isOk:
    db.putEth2FinalizedTo(s)

template getOrDefault[T, E](r: Result[T, E]): T =
  type TT = T
  get(r, default(TT))

proc init*(T: type Eth1Chain, cfg: RuntimeConfig, db: BeaconChainDB): T =
  let
    finalizedDeposits =
      if db != nil:
        db.getEth2FinalizedTo().getOrDefault()
      else:
        default(DepositContractSnapshot)
    m = DepositsMerkleizer.init(finalizedDeposits.depositContractState)

  T(db: db,
    cfg: cfg,
    finalizedBlockHash: finalizedDeposits.eth1Block,
    finalizedDepositsMerkleizer: m)

proc createInitialDepositSnapshot*(
    depositContractAddress: Eth1Address,
    depositContractDeployedAt: BlockHashOrNumber,
    web3Url: string,
    jwtSecret: Option[seq[byte]]): Future[Result[DepositContractSnapshot, string]]
    {.async.} =

  let dataProviderRes =
    await Web3DataProvider.new(depositContractAddress, web3Url, jwtSecret)
  if dataProviderRes.isErr:
    return err(dataProviderRes.error)
  var dataProvider = dataProviderRes.get

  let knownStartBlockHash =
    if depositContractDeployedAt.isHash:
      depositContractDeployedAt.hash
    else:
      try:
        var blk = awaitWithRetries(
          dataProvider.getBlockByNumber(depositContractDeployedAt.number))
        blk.hash.asEth2Digest
      except CatchableError as err:
        return err(err.msg)

  return ok DepositContractSnapshot(eth1Block: knownStartBlockHash)

proc currentEpoch(m: Eth1Monitor): Epoch =
  if m.getBeaconTime != nil:
    m.getBeaconTime().slotOrZero.epoch
  else:
    Epoch 0

proc init*(T: type Eth1Monitor,
           cfg: RuntimeConfig,
           db: BeaconChainDB,
           getBeaconTime: GetBeaconTimeFn,
           web3Urls: seq[string],
           depositContractSnapshot: Option[DepositContractSnapshot],
           eth1Network: Option[Eth1Network],
           forcePolling: bool,
           jwtSecret: Option[seq[byte]]): T =
  doAssert web3Urls.len > 0
  var web3Urls = web3Urls
  for url in mitems(web3Urls):
    fixupWeb3Urls url

  if depositContractSnapshot.isSome:
    putInitialDepositContractSnapshot(db, depositContractSnapshot.get)

  T(state: Initialized,
    depositsChain: Eth1Chain.init(cfg, db),
    depositContractAddress: cfg.DEPOSIT_CONTRACT_ADDRESS,
    getBeaconTime: getBeaconTime,
    web3Urls: web3Urls,
    eth1Network: eth1Network,
    eth1Progress: newAsyncEvent(),
    forcePolling: forcePolling,
    jwtSecret: jwtSecret)

proc safeCancel(fut: var Future[void]) =
  if not fut.isNil and not fut.finished:
    fut.cancel()
  fut = nil

func clear(chain: var Eth1Chain) =
  chain.blocks.clear()
  chain.blocksByHash.clear()
  chain.hasConsensusViolation = false

proc detectPrimaryProviderComingOnline(m: Eth1Monitor) {.async.} =
  const checkInterval = chronos.seconds(30)

  let
    web3Url = m.web3Urls[0]
    initialRunFut = m.runFut

  # This is a way to detect that the monitor was restarted. When this
  # happens, this function will just return terminating the "async thread"
  while m.runFut == initialRunFut:
    let tempProviderRes = await Web3DataProvider.new(
      m.depositContractAddress,
      web3Url,
      m.jwtSecret)

    if tempProviderRes.isErr:
      await sleepAsync(checkInterval)
      continue

    var tempProvider = tempProviderRes.get

    # Use one of the get/request-type methods from
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-alpha.9/src/engine/specification.md#underlying-protocol
    # which does nit take parameters and returns a small structure, to ensure
    # this works with engine API endpoints.
    let testRequest = tempProvider.web3.provider.eth_syncing()

    yield testRequest or sleepAsync(web3Timeouts)

    traceAsyncErrors tempProvider.close()

    if testRequest.completed and m.state == Started:
      m.state = ReadyToRestartToPrimary
      return
    else:
      await sleepAsync(checkInterval)

proc doStop(m: Eth1Monitor) {.async.} =
  safeCancel m.runFut

  if m.dataProvider != nil:
    await m.dataProvider.close()
    m.dataProvider = nil

proc ensureDataProvider*(m: Eth1Monitor) {.async.} =
  if m.isNil or not m.dataProvider.isNil:
    return

  let web3Url = m.web3Urls[m.startIdx mod m.web3Urls.len]
  inc m.startIdx

  m.dataProvider = block:
    let v = await Web3DataProvider.new(
      m.depositContractAddress, web3Url, m.jwtSecret)
    if v.isErr():
      raise (ref CatchableError)(msg: v.error())
    v.get()

proc stop(m: Eth1Monitor) {.async.} =
  if m.state in {Started, ReadyToRestartToPrimary}:
    m.state = Stopping
    m.stopFut = m.doStop()
    await m.stopFut
    m.state = Stopped
  elif m.state == Stopping:
    await m.stopFut

const
  votedBlocksSafetyMargin = 50

func latestEth1BlockNumber(m: Eth1Monitor): Eth1BlockNumber =
  if m.latestEth1Block.isSome:
    Eth1BlockNumber m.latestEth1Block.get.number
  else:
    Eth1BlockNumber 0

func earliestBlockOfInterest(m: Eth1Monitor): Eth1BlockNumber =
  m.latestEth1BlockNumber - (2 * m.cfg.ETH1_FOLLOW_DISTANCE) - votedBlocksSafetyMargin

proc syncBlockRange(m: Eth1Monitor,
                    merkleizer: ref DepositsMerkleizer,
                    fromBlock, toBlock,
                    fullSyncFromBlock: Eth1BlockNumber) {.gcsafe, async.} =
  doAssert m.depositsChain.blocks.len > 0 and m.dataProvider != nil

  var currentBlock = fromBlock
  while currentBlock <= toBlock:
    var
      depositLogs: JsonNode = nil
      blocksPerRequest = 5000'u64 # This is roughly a day of Eth1 blocks
      maxBlockNumberRequested: Eth1BlockNumber
      backoff = 100

    while true:
      maxBlockNumberRequested = min(toBlock, currentBlock + blocksPerRequest - 1)

      template retryOrRaise(err: ref CatchableError) =
        blocksPerRequest = blocksPerRequest div 2
        if blocksPerRequest == 0:
          raise err
        continue

      debug "Obtaining deposit log events",
            fromBlock = currentBlock,
            toBlock = maxBlockNumberRequested,
            backoff

      debug.logTime "Deposit logs obtained":
        # Reduce all request rate until we have a more general solution
        # for dealing with Infura's rate limits
        await sleepAsync(milliseconds(backoff))
        let jsonLogsFut = m.dataProvider.ns.getJsonLogs(
          DepositEvent,
          fromBlock = some blockId(currentBlock),
          toBlock = some blockId(maxBlockNumberRequested))

        depositLogs = try:
          # Downloading large amounts of deposits can be quite slow
          awaitWithTimeout(jsonLogsFut, web3Timeouts):
            retryOrRaise newException(DataProviderTimeout,
              "Request time out while obtaining json logs")
        except CatchableError as err:
          debug "Request for deposit logs failed", err = err.msg
          inc failed_web3_requests
          backoff = (backoff * 3) div 2
          retryOrRaise err

      currentBlock = maxBlockNumberRequested + 1
      break

    let blocksWithDeposits = depositEventsToBlocks(depositLogs)

    for i in 0 ..< blocksWithDeposits.len:
      let blk = blocksWithDeposits[i]

      for deposit in blk.deposits:
        merkleizer[].addChunk hash_tree_root(deposit).data

      blk.voteData.deposit_count = merkleizer[].getChunkCount
      blk.voteData.deposit_root = merkleizer[].getDepositsRoot

      if blk.number > fullSyncFromBlock:
        let lastBlock = m.depositsChain.blocks.peekLast
        for n in max(lastBlock.number + 1, fullSyncFromBlock) ..< blk.number:
          debug "Obtaining block without deposits", blockNum = n
          let blockWithoutDeposits = awaitWithRetries(
            m.dataProvider.getBlockByNumber(n))

          m.depositsChain.addBlock(
            lastBlock.makeSuccessorWithoutDeposits(blockWithoutDeposits))
          eth1_synced_head.set blockWithoutDeposits.number.toGaugeValue

      m.depositsChain.addBlock blk
      eth1_synced_head.set blk.number.toGaugeValue

    if blocksWithDeposits.len > 0:
      let lastIdx = blocksWithDeposits.len - 1
      template lastBlock: auto = blocksWithDeposits[lastIdx]

      let status = when hasDepositRootChecks:
        awaitWithRetries m.dataProvider.fetchDepositContractData(lastBlock)
      else:
        DepositRootUnavailable

      when hasDepositRootChecks:
        debug "Deposit contract state verified",
              status = $status,
              ourCount = lastBlock.voteData.deposit_count,
              ourRoot = lastBlock.voteData.deposit_root

      case status
      of DepositRootIncorrect, DepositCountIncorrect:
        raise newException(CorruptDataProvider,
          "The deposit log events disagree with the deposit contract state")
      else:
        discard

      info "Eth1 sync progress",
        blockNumber = lastBlock.number,
        depositsProcessed = lastBlock.voteData.deposit_count

    when hasGenesisDetection:
      if blocksWithDeposits.len > 0:
        for blk in blocksWithDeposits:
          for deposit in blk.deposits:
            m.processGenesisDeposit(deposit)
          blk.activeValidatorsCount = m.genesisValidators.lenu64

        let depositContractState = DepositContractSnapshot(
          eth1Block: blocksWithDeposits[^1].voteData.block_hash,
          depositContractState: merkleizer[].toDepositContractState)

        m.depositsChain.db.putEth2FinalizedTo depositContractState

      if m.genesisStateFut != nil and m.chainHasEnoughValidators:
        let lastIdx = m.depositsChain.blocks.len - 1
        template lastBlock: auto = m.depositsChain.blocks[lastIdx]

        if maxBlockNumberRequested == toBlock and
           (m.depositsChain.blocks.len == 0 or lastBlock.number != toBlock):
          let web3Block = awaitWithRetries(
            m.dataProvider.getBlockByNumber(toBlock))

          debug "Latest block doesn't hold deposits. Obtaining it",
                 ts = web3Block.timestamp.uint64,
                 number = web3Block.number.uint64

          m.depositsChain.addBlock lastBlock.makeSuccessorWithoutDeposits(web3Block)
        else:
          awaitWithRetries m.dataProvider.fetchTimestamp(lastBlock)

        var genesisBlockIdx = m.depositsChain.blocks.len - 1
        if m.isAfterMinGenesisTime(m.depositsChain.blocks[genesisBlockIdx]):
          for i in 1 ..< blocksWithDeposits.len:
            let idx = (m.depositsChain.blocks.len - 1) - i
            let blk = m.depositsChain.blocks[idx]
            awaitWithRetries m.dataProvider.fetchTimestamp(blk)
            if m.isGenesisCandidate(blk):
              genesisBlockIdx = idx
            else:
              break
          # We have a candidate state on our hands, but our current Eth1Chain
          # may consist only of blocks that have deposits attached to them
          # while the real genesis may have happened in a block without any
          # deposits (triggered by MIN_GENESIS_TIME).
          #
          # This can happen when the beacon node is launched after the genesis
          # event. We take a short cut when constructing the initial Eth1Chain
          # by downloading only deposit log entries. Thus, we'll see all the
          # blocks with deposits, but not the regular blocks in between.
          #
          # We'll handle this special case below by examing whether we are in
          # this potential scenario and we'll use a fast guessing algorith to
          # discover the ETh1 block with minimal valid genesis time.
          var genesisBlock = m.depositsChain.blocks[genesisBlockIdx]
          if genesisBlockIdx > 0:
            let genesisParent = m.depositsChain.blocks[genesisBlockIdx - 1]
            if genesisParent.timestamp == 0:
              awaitWithRetries m.dataProvider.fetchTimestamp(genesisParent)
            if m.hasEnoughValidators(genesisParent) and
               genesisBlock.number - genesisParent.number > 1:
              genesisBlock = awaitWithRetries(
                m.findGenesisBlockInRange(genesisParent, genesisBlock))

          m.signalGenesis m.createGenesisState(genesisBlock)

func init(T: type FullBlockId, blk: Eth1BlockHeader|BlockObject): T =
  FullBlockId(number: Eth1BlockNumber blk.number, hash: blk.hash)

proc startEth1Syncing(m: Eth1Monitor, delayBeforeStart: Duration) {.async.} =
  if m.state == Started:
    return

  let isFirstRun = m.state == Initialized
  let needsReset = m.state in {Failed, ReadyToRestartToPrimary}

  m.state = Started

  if delayBeforeStart != ZeroDuration:
    await sleepAsync(delayBeforeStart)

  # If the monitor died with an exception, the web3 provider may be in
  # an arbitary state, so we better reset it (not doing this has resulted
  # in resource leaks historically).
  if not m.dataProvider.isNil and needsReset:
    # We introduce a local var to eliminate the risk of scheduling two
    # competing calls to `close` below.
    let provider = m.dataProvider
    m.dataProvider = nil
    await provider.close()

  await m.ensureDataProvider()

  # We might need to reset the chain if the new provider disagrees
  # with the previous one regarding the history of the chain or if
  # we have detected a conensus violation - our view disagreeing with
  # the majority of the validators in the network.
  #
  # Consensus violations happen in practice because the web3 providers
  # sometimes return incomplete or incorrect deposit log events even
  # when they don't indicate any errors in the response. When this
  # happens, we are usually able to download the data successfully
  # on the second attempt.
  if m.latestEth1Block.isSome and m.depositsChain.blocks.len > 0:
    let needsReset = m.depositsChain.hasConsensusViolation or (block:
      let
        lastKnownBlock = m.depositsChain.blocks.peekLast
        matchingBlockAtNewProvider = awaitWithRetries(
          m.dataProvider.getBlockByNumber lastKnownBlock.number)

      lastKnownBlock.voteData.block_hash.asBlockHash != matchingBlockAtNewProvider.hash)

    if needsReset:
      m.depositsChain.clear()
      m.latestEth1Block = none(FullBlockId)

  template web3Url: string = m.dataProvider.url

  if web3Url != m.web3Urls[0]:
    asyncSpawn m.detectPrimaryProviderComingOnline()

  info "Starting Eth1 deposit contract monitoring",
    contract = $m.depositContractAddress

  if isFirstRun and m.eth1Network.isSome:
    try:
      let
        providerChain =
          awaitWithRetries m.dataProvider.web3.provider.eth_chainId()

        # https://eips.ethereum.org/EIPS/eip-155#list-of-chain-ids
        expectedChain = case m.eth1Network.get
          of mainnet: 1.Quantity
          of ropsten: 3.Quantity
          of rinkeby: 4.Quantity
          of goerli:  5.Quantity
          of sepolia: 11155111.Quantity   # https://chainid.network/
      if expectedChain != providerChain:
        fatal "The specified Web3 provider serves data for a different chain",
               expectedChain = distinctBase(expectedChain),
               providerChain = distinctBase(providerChain)
        quit 1
    except CatchableError as exc:
      # Typically because it's not synced through EIP-155, assuming this Web3
      # endpoint has been otherwise working.
      debug "startEth1Syncing: eth_chainId failed: ",
        error = exc.msg

  var mustUsePolling = m.forcePolling or
                       web3Url.startsWith("http://") or
                       web3Url.startsWith("https://")

  if not mustUsePolling:
    proc newBlockHeadersHandler(blk: Eth1BlockHeader)
                               {.raises: [Defect], gcsafe.} =
      try:
        if blk.number.uint64 > m.latestEth1BlockNumber:
          eth1_latest_head.set blk.number.toGaugeValue
          m.latestEth1Block = some FullBlockId.init(blk)
          m.eth1Progress.fire()
      except Exception:
        # TODO Investigate why this exception is being raised
        raiseAssert "AsyncEvent.fire should not raise exceptions"

    proc subscriptionErrorHandler(err: CatchableError)
                                 {.raises: [Defect], gcsafe.} =
      warn "Failed to subscribe for block headers. Switching to polling",
            err = err.msg
      mustUsePolling = true

    await m.dataProvider.onBlockHeaders(newBlockHeadersHandler,
                                        subscriptionErrorHandler)

  let shouldProcessDeposits = not m.depositContractAddress.isZeroMemory
  var scratchMerkleizer: ref DepositsMerkleizer
  var eth1SyncedTo: Eth1BlockNumber
  if shouldProcessDeposits and m.depositsChain.blocks.len == 0:
    let startBlock = awaitWithRetries(
      m.dataProvider.getBlockByHash(m.depositsChain.finalizedBlockHash.asBlockHash))

    m.depositsChain.addBlock Eth1Block(
      number: Eth1BlockNumber startBlock.number,
      timestamp: Eth1BlockTimestamp startBlock.timestamp,
      voteData: eth1DataFromMerkleizer(
        m.depositsChain.finalizedBlockHash,
        m.depositsChain.finalizedDepositsMerkleizer))

    eth1SyncedTo = Eth1BlockNumber startBlock.number

    eth1_synced_head.set eth1SyncedTo.toGaugeValue
    eth1_finalized_head.set eth1SyncedTo.toGaugeValue
    eth1_finalized_deposits.set(
      m.depositsChain.finalizedDepositsMerkleizer.getChunkCount.toGaugeValue)

    scratchMerkleizer = newClone(copy m.finalizedDepositsMerkleizer)

    debug "Starting Eth1 syncing", `from` = shortLog(m.depositsChain.blocks[0])

  while true:
    if bnStatus == BeaconNodeStatus.Stopping:
      when hasGenesisDetection:
        if not m.genesisStateFut.isNil:
          m.genesisStateFut.complete()
          m.genesisStateFut = nil
      await m.stop()
      return

    if m.depositsChain.hasConsensusViolation:
      raise newException(CorruptDataProvider, "Eth1 chain contradicts Eth2 consensus")

    if m.state == ReadyToRestartToPrimary:
      info "Primary web3 provider is back online. Restarting the Eth1 monitor"
      m.startIdx = 0
      return

    let nextBlock = if mustUsePolling:
      let blk = awaitWithRetries(
        m.dataProvider.web3.provider.eth_getBlockByNumber(blockId("latest"), false))

      let fullBlockId = FullBlockId.init(blk)

      if m.latestEth1Block.isSome and
         m.latestEth1Block.get == fullBlockId:
        await sleepAsync(m.cfg.SECONDS_PER_ETH1_BLOCK.int.seconds)
        continue

      m.latestEth1Block = some fullBlockId
      blk
    else:
      awaitWithTimeout(m.eth1Progress.wait(), 5.minutes):
        raise newException(CorruptDataProvider, "No eth1 chain progress for too long")

      m.eth1Progress.clear()

      if m.latestEth1Block.isNone:
        # It should not be possible for `latestEth1Block` to be none here.
        # Firing the `eth1Progress` event is always done after assinging
        # a value for it.
        continue

      awaitWithRetries m.dataProvider.getBlockByHash(m.latestEth1Block.get.hash)

    if m.currentEpoch >= m.cfg.BELLATRIX_FORK_EPOCH and m.terminalBlockHash.isNone:
      var terminalBlockCandidate = nextBlock

      info "startEth1Syncing: checking for merge terminal block",
        currentEpoch = m.currentEpoch,
        BELLATRIX_FORK_EPOCH = m.cfg.BELLATRIX_FORK_EPOCH,
        totalDifficulty = $nextBlock.totalDifficulty,
        ttd = $m.cfg.TERMINAL_TOTAL_DIFFICULTY,
        terminalBlockHash = m.terminalBlockHash

      if terminalBlockCandidate.totalDifficulty >= m.cfg.TERMINAL_TOTAL_DIFFICULTY:
        while not terminalBlockCandidate.parentHash.isZeroMemory:
          var parentBlock = awaitWithRetries(
            m.dataProvider.getBlockByHash(terminalBlockCandidate.parentHash))
          if parentBlock.totalDifficulty < m.cfg.TERMINAL_TOTAL_DIFFICULTY:
            break
          terminalBlockCandidate = parentBlock
        m.terminalBlockHash = some terminalBlockCandidate.hash
        m.terminalBlockNumber = some terminalBlockCandidate.number

    if shouldProcessDeposits and scratchMerkleizer != nil:
      if m.latestEth1BlockNumber <= m.cfg.ETH1_FOLLOW_DISTANCE:
        continue

      let targetBlock = m.latestEth1BlockNumber - m.cfg.ETH1_FOLLOW_DISTANCE
      if targetBlock <= eth1SyncedTo:
        continue

      let earliestBlockOfInterest = m.earliestBlockOfInterest()
      await m.syncBlockRange(scratchMerkleizer,
                             eth1SyncedTo + 1,
                             targetBlock,
                             earliestBlockOfInterest)
      eth1SyncedTo = targetBlock
      eth1_synced_head.set eth1SyncedTo.toGaugeValue

proc start(m: Eth1Monitor, delayBeforeStart: Duration) {.gcsafe.} =
  if m.runFut.isNil:
    let runFut = m.startEth1Syncing(delayBeforeStart)
    m.runFut = runFut
    runFut.addCallback do (p: pointer) {.gcsafe.}:
      if runFut.failed:
        if runFut == m.runFut:
          warn "Eth1 chain monitoring failure, restarting", err = runFut.error.msg
          m.state = Failed

      safeCancel m.runFut
      m.start(5.seconds)

proc start*(m: Eth1Monitor) =
  m.start(0.seconds)

proc getEth1BlockHash*(
    url: string, blockId: RtBlockIdentifier, jwtSecret: Option[seq[byte]]):
    Future[BlockHash] {.async.} =
  let web3 = await newWeb3(url, getJsonRpcRequestHeaders(jwtSecret))
  try:
    let blk = awaitWithRetries(
      web3.provider.eth_getBlockByNumber(blockId, false))
    return blk.hash
  finally:
    await web3.close()

proc testWeb3Provider*(web3Url: Uri,
                       depositContractAddress: Eth1Address,
                       jwtSecret: Option[seq[byte]]) {.async.} =
  template mustSucceed(action: static string, expr: untyped): untyped =
    try: expr
    except CatchableError as err:
      fatal("Failed to " & action, err = err.msg)
      quit 1

  let
    web3 = mustSucceed "connect to web3 provider":
      await newWeb3(
        $web3Url, getJsonRpcRequestHeaders(jwtSecret))
    latestBlock = mustSucceed "get latest block":
      awaitWithRetries web3.provider.eth_getBlockByNumber(blockId("latest"), false)
    syncStatus = mustSucceed "get sync status":
      awaitWithRetries web3.provider.eth_syncing()
    peers =
      try:
        awaitWithRetries web3.provider.net_peerCount()
      except:
        0
    clientVersion = mustSucceed "get client version":
      awaitWithRetries web3.provider.web3_clientVersion()
    mining = mustSucceed "get mining status":
      awaitWithRetries web3.provider.eth_mining()

  echo "Client Version: ", clientVersion
  echo "Network Peers: ", peers
  echo "Syncing: ", syncStatus
  echo "Latest block: ", latestBlock.number.uint64
  echo "Last Known Nonce: ", web3.lastKnownNonce
  echo "Mining: ", mining

  try:
    let chainId = awaitWithRetries web3.provider.eth_chainId()
    echo "Chain ID: ", chainId.uint64
  except DataProviderFailure as exc:
    # Typically because it's not synced through EIP-155.
    echo "Web3 provider does not provide chain ID: " & exc.msg

  let ns = web3.contractSender(DepositContract, depositContractAddress)
  try:
    let depositRoot = awaitWithRetries(
      ns.get_deposit_root.call(blockNumber = latestBlock.number.uint64))
    echo "Deposit root: ", depositRoot
  except CatchableError as err:
    echo "Web3 provider is not archive mode: ", err.msg

when hasGenesisDetection:
  proc loadPersistedDeposits*(monitor: Eth1Monitor) =
    for i in 0 ..< monitor.depositsChain.db.genesisDeposits.len:
      monitor.produceDerivedData monitor.depositsChain.db.genesisDeposits.get(i)

  proc findGenesisBlockInRange(m: Eth1Monitor, startBlock, endBlock: Eth1Block):
                               Future[Eth1Block] {.async.} =
    doAssert startBlock.timestamp != 0 and not m.isAfterMinGenesisTime(startBlock)
    doAssert endBlock.timestamp != 0 and m.isAfterMinGenesisTime(endBlock)
    doAssert m.hasEnoughValidators(startBlock)
    doAssert m.hasEnoughValidators(endBlock)

    var
      startBlock = startBlock
      endBlock = endBlock
      depositData = startBlock.voteData
      activeValidatorsCountDuringRange = startBlock.activeValidatorsCount

    while startBlock.number + 1 < endBlock.number:
      let
        MIN_GENESIS_TIME = m.cfg.MIN_GENESIS_TIME
        startBlockTime = genesis_time_from_eth1_timestamp(m.cfg, startBlock.timestamp)
        secondsPerBlock = float(endBlock.timestamp - startBlock.timestamp) /
                          float(endBlock.number - startBlock.number)
        blocksToJump = max(float(MIN_GENESIS_TIME - startBlockTime) / secondsPerBlock, 1.0)
        candidateNumber = min(endBlock.number - 1, startBlock.number + blocksToJump.uint64)
        candidateBlock = awaitWithRetries(
          m.dataProvider.getBlockByNumber(candidateNumber))

      var candidateAsEth1Block = Eth1Block(number: candidateBlock.number.uint64,
                                           timestamp: candidateBlock.timestamp.uint64,
                                           voteData: depositData)
      candidateAsEth1Block.voteData.block_hash = candidateBlock.hash.asEth2Digest

      let candidateGenesisTime = genesis_time_from_eth1_timestamp(
        m.cfg, candidateBlock.timestamp.uint64)

      notice "Probing possible genesis block",
        `block` = candidateBlock.number.uint64,
        candidateGenesisTime

      if candidateGenesisTime < MIN_GENESIS_TIME:
        startBlock = candidateAsEth1Block
      else:
        endBlock = candidateAsEth1Block

    if endBlock.activeValidatorsCount == 0:
      endBlock.activeValidatorsCount = activeValidatorsCountDuringRange

    return endBlock

  proc waitGenesis*(m: Eth1Monitor): Future[GenesisStateRef] {.async.} =
    if m.genesisState.isNil:
      m.start()

      if m.genesisStateFut.isNil:
        m.genesisStateFut = newFuture[void]("waitGenesis")

      info "Awaiting genesis event"
      await m.genesisStateFut
      m.genesisStateFut = nil

    if m.genesisState != nil:
      return m.genesisState
    else:
      doAssert bnStatus == BeaconNodeStatus.Stopping
      return nil

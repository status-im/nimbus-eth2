# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[deques, options, strformat, strutils, sequtils, tables,
       typetraits, uri, json],
  # Nimble packages:
  chronos, metrics, chronicles/timings, stint/endians2,
  json_rpc/[client, errors],
  web3, web3/ethhexstrings, web3/engine_api,
  eth/common/[eth_types, transaction],
  eth/async_utils, stew/[byteutils, objects, results, shims/hashes],
  # Local modules:
  ../spec/[deposit_snapshots, eth2_merkleization, forks, helpers],
  ../spec/datatypes/[base, phase0, bellatrix, deneb],
  ../networking/network_metadata,
  ../consensus_object_pools/block_pools_types,
  ".."/[beacon_chain_db, beacon_node_status, beacon_clock, future_combinators],
  "."/[merkle_minimal, el_conf]

from std/times import getTime, inSeconds, initTime, `-`
from ../spec/engine_authentication import getSignedIatToken

export
  el_conf, engine_api, deques, base, DepositTreeSnapshot

logScope:
  topics = "elmon"

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
  hasDepositRootChecks = defined(has_deposit_root_checks)

  targetBlocksPerLogsRequest = 1000'u64
    # TODO
    #
    # This is currently set to 1000, because this was the default maximum
    # value in Besu circa our 22.3.0 release. Previously, we've used 5000,
    # but this was effectively forcing the fallback logic in `syncBlockRange`
    # to always execute multiple requests before getting a successful response.
    #
    # Besu have raised this default to 5000 in https://github.com/hyperledger/besu/pull/5209
    # which is expected to ship in their next release.
    #
    # Full deposits sync time with various values for this parameter:
    #
    # Blocks per request | Geth running on the same host | Geth running on a more distant host
    # ----------------------------------------------------------------------------------------
    # 1000               |                      11m 20s  |                                 22m
    # 5000               |                       5m 20s  |                             15m 40s
    # 100000             |                       4m 10s  |                          not tested
    #
    # The number of requests scales linearly with the parameter value as you would expect.
    #
    # These results suggest that it would be reasonable for us to get back to 5000 once the
    # Besu release is well-spread within their userbase.

  # Engine API timeouts
  engineApiConnectionTimeout = 5.seconds  # How much we wait before giving up connecting to the Engine API
  web3RequestsTimeout* = 8.seconds # How much we wait for eth_* requests (e.g. eth_getBlockByHash)

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.2/src/engine/specification.md#request-2
  GETPAYLOAD_TIMEOUT = 1.seconds

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.2/src/engine/experimental/blob-extension.md#engine_getblobsbundlev1
  GETBLOBS_TIMEOUT = 1.seconds

type
  Eth1BlockNumber* = uint64
  Eth1BlockTimestamp* = uint64
  Eth1BlockHeader = engine_api.BlockHeader

  GenesisStateRef = ref phase0.BeaconState

  Eth1Block* = ref object
    hash*: Eth2Digest
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
      ## Basic properties of the block
      ## These must be initialized in the constructor

    deposits*: seq[DepositData]
      ## Deposits inside this particular block

    depositRoot*: Eth2Digest
    depositCount*: uint64
      ## Global deposits count and hash tree root of the entire sequence
      ## These are computed when the block is added to the chain (see `addBlock`)

  Eth1Chain* = object
    db: BeaconChainDB
    cfg: RuntimeConfig
    finalizedBlockHash: Eth2Digest
    finalizedDepositsMerkleizer: DepositsMerkleizer
      ## The latest block that reached a 50% majority vote from
      ## the Eth2 validators according to the follow distance and
      ## the ETH1_VOTING_PERIOD

    blocks*: Deque[Eth1Block]
      ## A non-forkable chain of blocks ending at the block with
      ## ETH1_FOLLOW_DISTANCE offset from the head.

    blocksByHash: Table[BlockHash, Eth1Block]

    headMerkleizer: DepositsMerkleizer
      ## Merkleizer state after applying all `blocks`

    hasConsensusViolation: bool
      ## The local chain contradicts the observed consensus on the network

  NoPayloadAttributesType = object
    ## A type with exactly one value, and which is not constructed via a `nil`
    ## value for a ref object, which which Nim 1.6 crashes with an ICE.

  NextExpectedPayloadParams* = object
    headBlockHash*: Eth2Digest
    safeBlockHash*: Eth2Digest
    finalizedBlockHash*: Eth2Digest
    payloadAttributes*: PayloadAttributesV2

  ELManager* = ref object
    eth1Network: Option[Eth1Network]
      ## If this value is supplied the EL monitor will check whether
      ## all configured EL nodes are connected to the same network.

    depositContractAddress*: Eth1Address
    depositContractBlockNumber: uint64
    depositContractBlockHash: BlockHash

    blocksPerLogsRequest: uint64
      ## This value is used to dynamically adjust the number of
      ## blocks we are trying to download at once during deposit
      ## syncing. By default, the value is set to the constant
      ## `targetBlocksPerLogsRequest`, but if the EL is failing
      ## to serve this number of blocks per single `eth_getLogs`
      ## request, we temporarily lower the value until the request
      ## succeeds. The failures are generally expected only in
      ## periods in the history for very high deposit density.

    elConnections: seq[ELConnection]
      ## All active EL connections

    eth1Chain: Eth1Chain
      ## At larger distances, this chain consists of all blocks
      ## with deposits. Within the relevant voting period, it
      ## also includes blocks without deposits because we must
      ## vote for a block only if it's part of our known history.

    syncTargetBlock: Option[Eth1BlockNumber]

    chainSyncingLoopFut: Future[void]
    exchangeTransitionConfigurationLoopFut: Future[void]
    stopFut: Future[void]

    nextExpectedPayloadParams*: Option[NextExpectedPayloadParams]

  EtcStatus {.pure.} = enum
    notExchangedYet
    exchangeError
    mismatch
    match

  DepositContractSyncStatus {.pure.} = enum
    unknown
    notSynced
    synced

  ConnectionState = enum
    NeverTested
    Working
    Degraded

  ELConnection* = ref object
    engineUrl: EngineApiUrl

    web3: Option[Web3]
      ## This will be `none` before connecting and while we are
      ## reconnecting after a lost connetion. You can wait on
      ## the future below for the moment the connection is active.

    connectingFut: Future[Result[Web3, string]]
      ## This future will be replaced when the connection is lost.

    etcStatus: EtcStatus
      ## The latest status of the `exchangeTransitionConfiguration`
      ## exchange.

    state: ConnectionState

    depositContractSyncStatus: DepositContractSyncStatus
      ## Are we sure that this EL has synced the deposit contract?

    lastPayloadId: Option[engine_api.PayloadID]

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

  BellatrixExecutionPayloadWithValue* = object
    executionPayload*: ExecutionPayloadV1
    blockValue*: UInt256

  CancunExecutionPayloadAndBlobs* = object
    executionPayload*: ExecutionPayloadV3
    blockValue*: UInt256
    kzgs*: seq[engine_api.KZGCommitment]
    blobs*: seq[engine_api.Blob]

  SomeEnginePayloadWithValue =
    BellatrixExecutionPayloadWithValue |
    GetPayloadV2Response |
    CancunExecutionPayloadAndBlobs

const
  NoPayloadAttributes* = default(NoPayloadAttributesType)

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

proc setDegradedState(connection: ELConnection,
                      requestName: string,
                      statusCode: int, errMsg: string) =
  case connection.state
  of NeverTested, Working:
    warn "Connection to EL node degraded",
      url = url(connection.engineUrl),
      failedRequest = requestName,
      statusCode, err = errMsg
  of Degraded:
    discard

  reset connection.web3
  connection.state = Degraded

proc setWorkingState(connection: ELConnection) =
  case connection.state
  of Degraded:
    info "Connection to EL node restored",
      url = url(connection.engineUrl)
  of NeverTested, Working:
    discard
  connection.state = Working

proc trackEngineApiRequest(connection: ELConnection,
                           request: FutureBase, requestName: string,
                           startTime: Moment, deadline: Future[void],
                           failureAllowed = false) =
  request.addCallback do (udata: pointer) {.gcsafe, raises: [Defect].}:
    # TODO `udata` is nil here. How come?
    # This forces us to create a GC cycle between the Future and the closure
    if request.completed:
      engine_api_request_duration_seconds.observe(
        float(milliseconds(Moment.now - startTime)) / 1000.0,
        [connection.engineUrl.url, requestName])

      connection.setWorkingState()

  deadline.addCallback do (udata: pointer) {.gcsafe, raises: [Defect].}:
    if not request.finished:
      request.cancel()
      engine_api_timeouts.inc(1, [connection.engineUrl.url, requestName])
    else:
      let statusCode = if not request.failed:
        200
      elif request.error of ErrorResponse:
        ((ref ErrorResponse) request.error).status
      else:
        0

      if request.failed and not failureAllowed:
        connection.setDegradedState(requestName, statusCode, request.error.msg)

      engine_api_responses.inc(1, [connection.engineUrl.url, requestName, $statusCode])

template awaitOrRaiseOnTimeout[T](fut: Future[T],
                                  timeout: Duration): T =
  awaitWithTimeout(fut, timeout):
    raise newException(DataProviderTimeout, "Timeout")

template trackedRequestWithTimeout[T](connection: ELConnection,
                                      requestName: static string,
                                      lazyRequestExpression: Future[T],
                                      timeout: Duration,
                                      failureAllowed = false): T =
  let
    connectionParam = connection
    startTime = Moment.now
    deadline = sleepAsync(timeout)
    request = lazyRequestExpression

  connectionParam.trackEngineApiRequest(
    request, requestName, startTime, deadline, failureAllowed)

  awaitWithTimeout(request, deadline):
    raise newException(DataProviderTimeout, "Timeout")

template cfg(m: ELManager): auto =
  m.eth1Chain.cfg

template db(m: ELManager): BeaconChainDB =
  m.eth1Chain.db

func hasJwtSecret*(m: ELManager): bool =
  for c in m.elConnections:
    if c.engineUrl.jwtSecret.isSome:
      return true

func isSynced*(m: ELManager): bool =
  m.syncTargetBlock.isSome and
  m.eth1Chain.blocks.len > 0 and
  m.syncTargetBlock.get <= m.eth1Chain.blocks[^1].number

template eth1ChainBlocks*(m: ELManager): Deque[Eth1Block] =
  m.eth1Chain.blocks

template finalizedDepositsMerkleizer(m: ELManager): auto =
  m.eth1Chain.finalizedDepositsMerkleizer

template headMerkleizer(m: ELManager): auto =
  m.eth1Chain.headMerkleizer

template toGaugeValue(x: Quantity): int64 =
  toGaugeValue(distinctBase x)

# TODO: Add cfg validation
# MIN_GENESIS_ACTIVE_VALIDATOR_COUNT should be larger than SLOTS_PER_EPOCH
#  doAssert SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE < GENESIS_DELAY,
#             "Invalid configuration: GENESIS_DELAY is set too low"

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.2/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(genesis_time: uint64, slot: Slot): uint64 =
  genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.2/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time(state: ForkedHashedBeaconState): uint64 =
  let eth1_voting_period_start_slot =
    getStateField(state, slot) - getStateField(state, slot) mod
      SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(
    getStateField(state, genesis_time), eth1_voting_period_start_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.2/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(cfg: RuntimeConfig,
                        blk: Eth1Block,
                        period_start: uint64): bool =
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE <= period_start) and
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE * 2 >= period_start)

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func asConsensusWithdrawal(w: WithdrawalV1): capella.Withdrawal =
  capella.Withdrawal(
    index: w.index.uint64,
    validator_index: w.validatorIndex.uint64,
    address: ExecutionAddress(data: w.address.distinctBase),
    amount: GWei w.amount)

func asEngineWithdrawal(w: capella.Withdrawal): WithdrawalV1 =
  WithdrawalV1(
    index: Quantity(w.index),
    validatorIndex: Quantity(w.validator_index),
    address: Address(w.address.data),
    amount: Quantity(w.amount))

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV1):
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
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)))

func asConsensusType*(payloadWithValue: BellatrixExecutionPayloadWithValue):
    bellatrix.ExecutionPayloadForSigning =
  bellatrix.ExecutionPayloadForSigning(
    executionPayload: payloadWithValue.executionPayload.asConsensusType,
    blockValue: payloadWithValue.blockValue)

template maybeDeref[T](o: Option[T]): T = o.get
template maybeDeref[V](v: V): V = v

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV1OrV2|ExecutionPayloadV2):
    capella.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  capella.ExecutionPayload(
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
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(maybeDeref rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)))

func asConsensusType*(payloadWithValue: engine_api.GetPayloadV2Response):
    capella.ExecutionPayloadForSigning =
  capella.ExecutionPayloadForSigning(
    executionPayload: payloadWithValue.executionPayload.asConsensusType,
    blockValue: payloadWithValue.blockValue)

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV3):
    deneb.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  deneb.ExecutionPayload(
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
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    excess_data_gas: rpcExecutionPayload.excessDataGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)))

func asConsensusType*(cancunPayload: CancunExecutionPayloadAndBlobs):
    deneb.ExecutionPayloadForSigning =
  deneb.ExecutionPayloadForSigning(
    executionPayload: cancunPayload.executionPayload.asConsensusType,
    blockValue: cancunPayload.blockValue,
    # TODO
    # The `mapIt` calls below are necessary only because we use different distinct
    # types for KZG commitments and Blobs in the `web3` and the `deneb` spec types.
    # Both are defined as `array[N, byte]` under the hood.
    kzgs: KZGCommitments cancunPayload.kzgs.mapIt(it.bytes),
    blobs: Blobs cancunPayload.blobs.mapIt(it.bytes)
  )

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
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction))

template toEngineWithdrawal(w: capella.Withdrawal): WithdrawalV1 =
  WithdrawalV1(
    index: Quantity(w.index),
    validatorIndex: Quantity(w.validator_index),
    address: Address(w.address.data),
    amount: Quantity(w.amount))

func asEngineExecutionPayload*(executionPayload: capella.ExecutionPayload):
    ExecutionPayloadV2 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)
  engine_api.ExecutionPayloadV2(
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
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction),
    withdrawals: mapIt(executionPayload.withdrawals, it.toEngineWithdrawal))

func asEngineExecutionPayload*(executionPayload: deneb.ExecutionPayload):
    ExecutionPayloadV3 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV3(
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
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    excessDataGas: executionPayload.excess_data_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction),
    withdrawals: mapIt(executionPayload.withdrawals, it.asEngineWithdrawal))

func shortLog*(b: Eth1Block): string =
  try:
    &"{b.number}:{shortLog b.hash}(deposits = {b.depositCount})"
  except ValueError as exc: raiseAssert exc.msg

template findBlock(chain: Eth1Chain, eth1Data: Eth1Data): Eth1Block =
  getOrDefault(chain.blocksByHash, asBlockHash(eth1Data.block_hash), nil)

func makeSuccessorWithoutDeposits(existingBlock: Eth1Block,
                                  successor: BlockObject): Eth1Block =
  result = Eth1Block(
    hash: successor.hash.asEth2Digest,
    number: Eth1BlockNumber successor.number,
    timestamp: Eth1BlockTimestamp successor.timestamp)

func latestCandidateBlock(chain: Eth1Chain, periodStart: uint64): Eth1Block =
  for i in countdown(chain.blocks.len - 1, 0):
    let blk = chain.blocks[i]
    if is_candidate_block(chain.cfg, blk, periodStart):
      return blk

proc popFirst(chain: var Eth1Chain) =
  let removed = chain.blocks.popFirst
  chain.blocksByHash.del removed.hash.asBlockHash
  eth1_chain_len.set chain.blocks.len.int64

func getDepositsRoot*(m: DepositsMerkleizer): Eth2Digest =
  mixInLength(m.getFinalHash, int m.totalChunks)

proc addBlock*(chain: var Eth1Chain, newBlock: Eth1Block) =
  for deposit in newBlock.deposits:
    chain.headMerkleizer.addChunk hash_tree_root(deposit).data

  newBlock.depositCount = chain.headMerkleizer.getChunkCount
  newBlock.depositRoot = chain.headMerkleizer.getDepositsRoot

  chain.blocks.addLast newBlock
  chain.blocksByHash[newBlock.hash.asBlockHash] = newBlock

  eth1_chain_len.set chain.blocks.len.int64

func toVoteData(blk: Eth1Block): Eth1Data =
  Eth1Data(
    deposit_root: blk.depositRoot,
    deposit_count: blk.depositCount,
    block_hash: blk.hash)

func hash*(x: Eth1Data): Hash =
  hash(x.block_hash)

proc close(connection: ELConnection): Future[void] {.async.} =
  if connection.web3.isSome:
    awaitWithTimeout(connection.web3.get.close(), 30.seconds):
      debug "Failed to close data provider in time"

func isConnected(connection: ELConnection): bool =
  connection.web3.isSome

func getJsonRpcRequestHeaders(jwtSecret: Option[seq[byte]]):
    auto =
  if jwtSecret.isSome:
    let secret = jwtSecret.get
    (proc(): seq[(string, string)] =
      # https://www.rfc-editor.org/rfc/rfc6750#section-6.1.1
      @[("Authorization", "Bearer " & getSignedIatToken(
        secret, (getTime() - initTime(0, 0)).inSeconds))])
  else:
    (proc(): seq[(string, string)] = @[])

proc newWeb3*(engineUrl: EngineApiUrl): Future[Web3] =
  newWeb3(engineUrl.url, getJsonRpcRequestHeaders(engineUrl.jwtSecret))

proc establishEngineApiConnection*(url: EngineApiUrl):
                                   Future[Result[Web3, string]] {.async.} =
  let web3Fut = newWeb3(url)
  yield web3Fut or sleepAsync(engineApiConnectionTimeout)

  if not web3Fut.completed:
    await cancelAndWait(web3Fut)
    if web3Fut.failed:
      return err "Failed to setup Engine API connection: " & web3Fut.readError.msg
    else:
      return err "Failed to setup Engine API connection"
  else:
    return ok web3Fut.read

proc tryConnecting(connection: ELConnection): Future[bool] {.async.} =
  if connection.isConnected:
    return true

  if connection.connectingFut == nil or
     connection.connectingFut.finished: # The previous attempt was not successful
    connection.connectingFut = establishEngineApiConnection(connection.engineUrl)

  let web3Res = await connection.connectingFut
  if web3Res.isErr:
    return false
  else:
    connection.web3 = some web3Res.get
    return true

proc connectedRpcClient(connection: ELConnection): Future[RpcClient] {.async.} =
  while not connection.isConnected:
    if not await connection.tryConnecting():
      await sleepAsync(chronos.seconds(10))

  return connection.web3.get.provider

proc getBlockByHash(rpcClient: RpcClient, hash: BlockHash): Future[BlockObject] =
  rpcClient.eth_getBlockByHash(hash, false)

proc getBlockByNumber*(rpcClient: RpcClient,
                       number: Eth1BlockNumber): Future[BlockObject] =
  let hexNumber = try:
    &"0x{number:X}" # No leading 0's!
  except ValueError as exc:
    # Since the format above is valid, failing here should not be possible
    raiseAssert exc.msg

  rpcClient.eth_getBlockByNumber(hexNumber, false)

proc getBlock(rpcClient: RpcClient, id: BlockHashOrNumber): Future[BlockObject] =
  if id.isHash:
    let hash = id.hash.asBlockHash()
    return rpcClient.getBlockByHash(hash)
  else:
    return rpcClient.getBlockByNumber(id.number)

func areSameAs(expectedParams: Option[NextExpectedPayloadParams],
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
    expectedParams.get.payloadAttributes.prevRandao.bytes == randomData.data and
    expectedParams.get.payloadAttributes.suggestedFeeRecipient == feeRecipient and
    expectedParams.get.payloadAttributes.withdrawals == withdrawals

proc forkchoiceUpdated(rpcClient: RpcClient,
                       state: ForkchoiceStateV1,
                       payloadAttributes: PayloadAttributesV1 |
                                          PayloadAttributesV2 |
                                          NoPayloadAttributesType):
                       Future[ForkchoiceUpdatedResponse] =
  when payloadAttributes is NoPayloadAttributesType:
    rpcClient.engine_forkchoiceUpdatedV1(state, none PayloadAttributesV1)
  elif payloadAttributes is PayloadAttributesV1:
    rpcClient.engine_forkchoiceUpdatedV1(state, some payloadAttributes)
  elif payloadAttributes is PayloadAttributesV2:
    rpcClient.engine_forkchoiceUpdatedV2(state, some payloadAttributes)
  else:
    static: doAssert false

func computeBlockValue(blk: ExecutionPayloadV1): UInt256 {.raises: [RlpError, Defect].} =
  for transactionBytes in blk.transactions:
    var rlp = rlpFromBytes distinctBase(transactionBytes)
    let transaction = rlp.read(eth_types.Transaction)
    result += distinctBase(effectiveGasTip(transaction, blk.baseFeePerGas)).u256

proc getPayloadFromSingleEL(
    connection: ELConnection,
    GetPayloadResponseType: type,
    isForkChoiceUpToDate: bool,
    headBlock, safeBlock, finalizedBlock: Eth2Digest,
    timestamp: uint64,
    randomData: Eth2Digest,
    suggestedFeeRecipient: Eth1Address,
    withdrawals: seq[WithdrawalV1]): Future[GetPayloadResponseType] {.async.} =

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
          PayloadAttributesV1(
            timestamp: Quantity timestamp,
            prevRandao: FixedBytes[32] randomData.data,
            suggestedFeeRecipient: suggestedFeeRecipient))
      elif GetPayloadResponseType is engine_api.GetPayloadV2Response or GetPayloadResponseType is CancunExecutionPayloadAndBlobs:
        let response = await rpcClient.forkchoiceUpdated(
          ForkchoiceStateV1(
            headBlockHash: headBlock.asBlockHash,
            safeBlockHash: safeBlock.asBlockHash,
            finalizedBlockHash: finalizedBlock.asBlockHash),
          PayloadAttributesV2(
            timestamp: Quantity timestamp,
            prevRandao: FixedBytes[32] randomData.data,
            suggestedFeeRecipient: suggestedFeeRecipient,
            withdrawals: withdrawals))
      else:
        static: doAssert false

      if response.payloadStatus.status != PayloadExecutionStatus.valid or
         response.payloadId.isNone:
        raise newException(CatchableError, "Head block is not a valid payload")

      # Give the EL some time to assemble the block
      await sleepAsync(chronos.milliseconds 500)

      response.payloadId.get
    else:
      raise newException(CatchableError, "No confirmed execution head yet")

  when GetPayloadResponseType is CancunExecutionPayloadAndBlobs:
    let
      response = await engine_api.getPayload(rpcClient,
                                             GetPayloadV3Response,
                                             payloadId)
      blobsBundle = await engine_getBlobsBundleV1(rpcClient, payloadId)
    # TODO validate the blobs bundle
    return CancunExecutionPayloadAndBlobs(
      executionPayload: response.executionPayload,
      blockValue: response.blockValue,
      kzgs: blobsBundle.kzgs, # TODO Avoid the copies here with `move`
      blobs: blobsBundle.blobs)
  elif GetPayloadResponseType is BellatrixExecutionPayloadWithValue:
    let payload= await engine_api.getPayload(rpcClient, ExecutionPayloadV1, payloadId)
    return BellatrixExecutionPayloadWithValue(
      executionPayload: payload,
      blockValue: computeBlockValue payload)
  else:
    return await engine_api.getPayload(rpcClient, GetPayloadResponseType, payloadId)

func cmpGetPayloadResponses(lhs, rhs: SomeEnginePayloadWithValue): int =
  cmp(distinctBase lhs.blockValue, distinctBase rhs.blockValue)

template EngineApiResponseType*(T: type bellatrix.ExecutionPayloadForSigning): type =
  BellatrixExecutionPayloadWithValue

template EngineApiResponseType*(T: type capella.ExecutionPayloadForSigning): type =
  engine_api.GetPayloadV2Response

template EngineApiResponseType*(T: type deneb.ExecutionPayloadForSigning): type =
  CancunExecutionPayloadAndBlobs

template payload(response: engine_api.ExecutionPayloadV1): engine_api.ExecutionPayloadV1 =
  response

template payload(response: engine_api.GetPayloadV2Response): engine_api.ExecutionPayloadV1OrV2 =
  response.executionPayload

template payload(response: engine_api.GetPayloadV3Response): engine_api.ExecutionPayloadV3 =
  response.executionPayload

template toEngineWithdrawals*(withdrawals: seq[capella.Withdrawal]): seq[WithdrawalV1] =
  mapIt(withdrawals, toEngineWithdrawal(it))

template toFork(T: type ExecutionPayloadV1): ConsensusFork =
  ConsensusFork.Bellatrix

template toFork(T: typedesc[ExecutionPayloadV1OrV2|ExecutionPayloadV2]): ConsensusFork =
  ConsensusFork.Capella

template toFork(T: type ExecutionPayloadV3): ConsensusFork =
  ConsensusFork.Deneb

proc getPayload*(m: ELManager,
                 PayloadType: type ForkyExecutionPayloadForSigning,
                 headBlock, safeBlock, finalizedBlock: Eth2Digest,
                 timestamp: uint64,
                 randomData: Eth2Digest,
                 suggestedFeeRecipient: Eth1Address,
                 withdrawals: seq[capella.Withdrawal]):
                 Future[Opt[PayloadType]] {.async.} =
  if m.elConnections.len == 0:
    return err()

  let
    engineApiWithdrawals = toEngineWithdrawals withdrawals
  let isFcUpToDate = m.nextExpectedPayloadParams.areSameAs(
    headBlock, safeBlock, finalizedBlock, timestamp,
    randomData, suggestedFeeRecipient, engineApiWithdrawals)

  let
    timeout = when PayloadType is deneb.ExecutionPayloadForSigning:
      # TODO We should follow the spec and track the timeouts of
      #      the individual engine API calls inside `getPayloadFromSingleEL`.
      GETPAYLOAD_TIMEOUT + GETBLOBS_TIMEOUT
    else:
      GETPAYLOAD_TIMEOUT
    deadline = sleepAsync(timeout)
    requests = m.elConnections.mapIt(it.getPayloadFromSingleEL(
      EngineApiResponseType(PayloadType),
      isFcUpToDate, headBlock, safeBlock, finalizedBlock,
      timestamp, randomData, suggestedFeeRecipient, engineApiWithdrawals
    ))
    requestsCompleted = allFutures(requests)

  await requestsCompleted or deadline

  var bestPayloadIdx = none int
  for idx, req in requests:
    if not req.finished:
      req.cancel()
    elif req.failed:
      error "Failed to get execution payload from EL",
             url = m.elConnections[idx].engineUrl.url,
             err = req.error.msg
    else:
      const payloadFork = PayloadType.toFork
      when payloadFork >= ConsensusFork.Capella:
        when payloadFork == ConsensusFork.Capella:
          # TODO: The engine_api module may offer an alternative API where it is guaranteed
          #       to return the correct response type (i.e. the rule below will be enforced
          #       during deserialization).
          if req.read.executionPayload.withdrawals.isNone:
            warn "Execution client returned a block without a 'withdrawals' field for a post-Shanghai block",
                  url = m.elConnections[idx].engineUrl.url
            continue

        if engineApiWithdrawals != req.read.executionPayload.withdrawals.maybeDeref:
          warn "Execution client did not return correct withdrawals",
            withdrawals_from_cl = engineApiWithdrawals,
            withdrawals_from_el = req.read.executionPayload.withdrawals

      if req.read.executionPayload.extraData.len > MAX_EXTRA_DATA_BYTES:
        warn "Execution client provided a block with invalid extraData (size exceeds limit)",
             size = req.read.executionPayload.extraData.len,
             limit = MAX_EXTRA_DATA_BYTES
        continue

      if bestPayloadIdx.isNone:
        bestPayloadIdx = some idx
      else:
        if cmpGetPayloadResponses(req.read, requests[bestPayloadIdx.get].read) > 0:
          bestPayloadIdx = some idx

  if bestPayloadIdx.isSome:
    return ok requests[bestPayloadIdx.get].read.asConsensusType
  else:
    return err()

proc waitELToSyncDeposits(connection: ELConnection,
                          minimalRequiredBlock: BlockHash) {.async.} =
  var rpcClient = await connection.connectedRpcClient()

  if connection.depositContractSyncStatus == DepositContractSyncStatus.synced:
    return

  var attempt = 0

  while true:
    try:
      discard connection.trackedRequestWithTimeout(
        "getBlockByHash",
        rpcClient.getBlockByHash(minimalRequiredBlock),
        web3RequestsTimeout,
        failureAllowed = true)
      connection.depositContractSyncStatus = DepositContractSyncStatus.synced
      return
    except CancelledError as err:
      trace "waitELToSyncDepositContract cancelled",
             url = connection.engineUrl.url
      raise err
    except CatchableError as err:
      connection.depositContractSyncStatus = DepositContractSyncStatus.notSynced
      if attempt == 0:
        warn "Failed to obtain the most recent known block from the execution " &
             "layer node (the node is probably not synced)",
             url = connection.engineUrl.url,
             blk = minimalRequiredBlock,
             err = err.msg
      elif attempt mod 60 == 0:
        # This warning will be produced every 30 minutes
        warn "Still failing to obtain the most recent known block from the " &
             "execution layer node (the node is probably still not synced)",
             url = connection.engineUrl.url,
             blk = minimalRequiredBlock,
             err = err.msg
      inc attempt
      await sleepAsync(seconds(30))
      rpcClient = await connection.connectedRpcClient()

func networkHasDepositContract(m: ELManager): bool =
  not m.cfg.DEPOSIT_CONTRACT_ADDRESS.isDefaultValue

func mostRecentKnownBlock(m: ELManager): BlockHash =
  if m.eth1Chain.finalizedDepositsMerkleizer.getChunkCount() > 0:
    m.eth1Chain.finalizedBlockHash.asBlockHash
  else:
    m.depositContractBlockHash

proc selectConnectionForChainSyncing(m: ELManager): Future[ELConnection] {.async.} =
  doAssert m.elConnections.len > 0

  let connectionsFuts = mapIt(
    m.elConnections,
    if m.networkHasDepositContract:
      FutureBase waitELToSyncDeposits(it, m.mostRecentKnownBlock)
    else:
      FutureBase connectedRpcClient(it))

  # TODO: Ideally, the cancellation will be handled automatically
  #       by a helper like `firstCompletedFuture`
  let firstConnected = try:
    await firstCompletedFuture(connectionsFuts)
  except CancelledError as err:
    for future in connectionsFuts:
      future.cancel()
    raise err

  for future in connectionsFuts:
    if future != firstConnected:
      future.cancel()

  return m.elConnections[find(connectionsFuts, firstConnected)]

proc sendNewPayloadToSingleEL(connection: ELConnection,
                              payload: engine_api.ExecutionPayloadV1):
                              Future[PayloadStatusV1] {.async.} =
  let rpcClient = await connection.connectedRpcClient()
  return await rpcClient.engine_newPayloadV1(payload)

proc sendNewPayloadToSingleEL(connection: ELConnection,
                              payload: engine_api.ExecutionPayloadV2):
                              Future[PayloadStatusV1] {.async.} =
  let rpcClient = await connection.connectedRpcClient()
  return await rpcClient.engine_newPayloadV2(payload)

proc sendNewPayloadToSingleEL(connection: ELConnection,
                              payload: engine_api.ExecutionPayloadV3):
                              Future[PayloadStatusV1] {.async.} =
  let rpcClient = await connection.connectedRpcClient()
  return await rpcClient.engine_newPayloadV3(payload)

type
  StatusRelation = enum
    newStatusIsPreferable
    oldStatusIsOk
    disagreement

func compareStatuses(newStatus, prevStatus: PayloadExecutionStatus): StatusRelation =
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
    selectedResponse: Option[int]
    disagreementAlreadyDetected: bool

func init(T: type ELConsensusViolationDetector): T =
  ELConsensusViolationDetector(selectedResponse: none int,
                               disagreementAlreadyDetected: false)

proc processResponse[ELResponseType](
    d: var ELConsensusViolationDetector,
    connections: openArray[ELConnection],
    requests: openArray[Future[ELResponseType]],
    idx: int) =

  if not requests[idx].completed:
    return

  let status = try: requests[idx].read.status
               except CatchableError: raiseAssert "checked above"
  if d.selectedResponse.isNone:
    d.selectedResponse = some idx
  elif not d.disagreementAlreadyDetected:
    let prevStatus = try: requests[d.selectedResponse.get].read.status
                     except CatchableError: raiseAssert "previously checked"
    case compareStatuses(status, prevStatus)
    of newStatusIsPreferable:
      d.selectedResponse = some idx
    of oldStatusIsOk:
      discard
    of disagreement:
      d.disagreementAlreadyDetected = true
      error "Execution layer consensus violation detected",
            responseType = name(ELResponseType),
            url1 = connections[d.selectedResponse.get].engineUrl.url,
            status1 = prevStatus,
            url2 = connections[idx].engineUrl.url,
            status2 = status

proc sendNewPayload*(m: ELManager,
                     payload: engine_api.ExecutionPayloadV1 | engine_api.ExecutionPayloadV2 | engine_api.ExecutionPayloadV3):
                     Future[PayloadExecutionStatus] {.async.} =
  let
    earlyDeadline = sleepAsync(chronos.seconds 1)
    startTime = Moment.now
    deadline = sleepAsync(NEWPAYLOAD_TIMEOUT)
    requests = m.elConnections.mapIt:
      let req = sendNewPayloadToSingleEL(it, payload)
      trackEngineApiRequest(it, req, "newPayload", startTime, deadline)
      req

    requestsCompleted = allFutures(requests)

  await requestsCompleted or earlyDeadline

  var
    stillPending = newSeq[Future[PayloadStatusV1]]()
    responseProcessor = init ELConsensusViolationDetector

  for idx, req in requests:
    if not req.finished:
      stillPending.add req
    elif req.completed:
      responseProcessor.processResponse(m.elConnections, requests, idx)

  if responseProcessor.disagreementAlreadyDetected:
    return PayloadExecutionStatus.invalid
  elif responseProcessor.selectedResponse.isSome:
    return requests[responseProcessor.selectedResponse.get].read.status

  await requestsCompleted or deadline

  for idx, req in requests:
    if req.completed and req in stillPending:
      responseProcessor.processResponse(m.elConnections, requests, idx)

  return if responseProcessor.disagreementAlreadyDetected:
    PayloadExecutionStatus.invalid
  elif responseProcessor.selectedResponse.isSome:
    requests[responseProcessor.selectedResponse.get].read.status
  else:
    PayloadExecutionStatus.syncing

proc forkchoiceUpdatedForSingleEL(
    connection: ELConnection,
    state: ref ForkchoiceStateV1,
    payloadAttributes: PayloadAttributesV1 | PayloadAttributesV2 |
                       NoPayloadAttributesType):
    Future[PayloadStatusV1] {.async.} =
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

proc forkchoiceUpdated*(m: ELManager,
                        headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
                        payloadAttributes: PayloadAttributesV1 | PayloadAttributesV2 |
                                           NoPayloadAttributesType):
                        Future[(PayloadExecutionStatus, Option[BlockHash])] {.async.} =
  doAssert not headBlockHash.isZero

  # Allow finalizedBlockHash to be 0 to avoid sync deadlocks.
  #
  # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md#pos-events
  # has "Before the first finalized block occurs in the system the finalized
  # block hash provided by this event is stubbed with
  # `0x0000000000000000000000000000000000000000000000000000000000000000`."
  # and
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/specs/bellatrix/validator.md#executionpayload
  # notes "`finalized_block_hash` is the hash of the latest finalized execution
  # payload (`Hash32()` if none yet finalized)"

  if m.elConnections.len == 0:
    return (PayloadExecutionStatus.syncing, none BlockHash)

  when payloadAttributes is PayloadAttributesV2:
    template payloadAttributesV2(): auto = payloadAttributes
  elif payloadAttributes is PayloadAttributesV1:
    template payloadAttributesV2(): auto = PayloadAttributesV2(
      timestamp: payloadAttributes.timestamp,
      prevRandao: payloadAttributes.prevRandao,
      suggestedFeeRecipient: payloadAttributes.suggestedFeeRecipient,
      withdrawals: @[])
  elif payloadAttributes is NoPayloadAttributesType:
    template payloadAttributesV2(): auto =
      # Because timestamp and prevRandao are both 0, won't false-positive match
      (static(default(PayloadAttributesV2)))
  else:
    static: doAssert false

  m.nextExpectedPayloadParams = some NextExpectedPayloadParams(
    headBlockHash: headBlockHash,
    safeBlockHash: safeBlockHash,
    finalizedBlockHash: finalizedBlockHash,
    payloadAttributes: payloadAttributesV2)

  let
    state = newClone ForkchoiceStateV1(
      headBlockHash: headBlockHash.asBlockHash,
      safeBlockHash: safeBlockHash.asBlockHash,
      finalizedBlockHash: finalizedBlockHash.asBlockHash)
    earlyDeadline = sleepAsync(chronos.seconds 1)
    startTime = Moment.now
    deadline = sleepAsync(FORKCHOICEUPDATED_TIMEOUT)
    requests = m.elConnections.mapIt:
      let req = it.forkchoiceUpdatedForSingleEL(state, payloadAttributes)
      trackEngineApiRequest(it, req, "forkchoiceUpdated", startTime, deadline)
      req
    requestsCompleted = allFutures(requests)

  await requestsCompleted or earlyDeadline

  var
    stillPending = newSeq[Future[PayloadStatusV1]]()
    responseProcessor = init ELConsensusViolationDetector

  for idx, req in requests:
    if not req.finished:
      stillPending.add req
    elif req.completed:
      responseProcessor.processResponse(m.elConnections, requests, idx)

  if responseProcessor.disagreementAlreadyDetected:
    return (PayloadExecutionStatus.invalid, none BlockHash)
  elif responseProcessor.selectedResponse.isSome:
    return (requests[responseProcessor.selectedResponse.get].read.status,
            requests[responseProcessor.selectedResponse.get].read.latestValidHash)

  await requestsCompleted or deadline

  for idx, req in requests:
    if req.completed and req in stillPending:
      responseProcessor.processResponse(m.elConnections, requests, idx)

  return if responseProcessor.disagreementAlreadyDetected:
    (PayloadExecutionStatus.invalid, none BlockHash)
  elif responseProcessor.selectedResponse.isSome:
    (requests[responseProcessor.selectedResponse.get].read.status,
     requests[responseProcessor.selectedResponse.get].read.latestValidHash)
  else:
    (PayloadExecutionStatus.syncing, none BlockHash)

proc forkchoiceUpdatedNoResult*(m: ELManager,
                                headBlockHash, safeBlockHash, finalizedBlockHash: Eth2Digest,
                                payloadAttributes: PayloadAttributesV1 | PayloadAttributesV2) {.async.} =
  discard await m.forkchoiceUpdated(
    headBlockHash, safeBlockHash, finalizedBlockHash, payloadAttributes)

# TODO can't be defined within exchangeConfigWithSingleEL
func `==`(x, y: Quantity): bool {.borrow.}

proc exchangeConfigWithSingleEL(m: ELManager, connection: ELConnection) {.async.} =
  let rpcClient = await connection.connectedRpcClient()

  if m.eth1Network.isSome and
     connection.etcStatus == EtcStatus.notExchangedYet:
    try:
      let
        providerChain =
          connection.trackedRequestWithTimeout(
            "chainId",
            rpcClient.eth_chainId(),
            web3RequestsTimeout)

        # https://eips.ethereum.org/EIPS/eip-155#list-of-chain-ids
        expectedChain = case m.eth1Network.get
          of mainnet: 1.Quantity
          of ropsten: 3.Quantity
          of rinkeby: 4.Quantity
          of goerli:  5.Quantity
          of sepolia: 11155111.Quantity   # https://chainid.network/
      if expectedChain != providerChain:
        warn "The specified EL client is connected to a different chain",
              url = connection.engineUrl,
              expectedChain = distinctBase(expectedChain),
              actualChain = distinctBase(providerChain)
        connection.etcStatus = EtcStatus.mismatch
        return
    except CatchableError as exc:
      # Typically because it's not synced through EIP-155, assuming this Web3
      # endpoint has been otherwise working.
      debug "Failed to obtain eth_chainId",
             error = exc.msg

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.2/src/engine/specification.md#engine_exchangetransitionconfigurationv1
  let
    ourConf = TransitionConfigurationV1(
      terminalTotalDifficulty: m.eth1Chain.cfg.TERMINAL_TOTAL_DIFFICULTY,
      terminalBlockHash: m.eth1Chain.cfg.TERMINAL_BLOCK_HASH,
      terminalBlockNumber: Quantity 0)
    elConf = try:
      connection.trackedRequestWithTimeout(
        "exchangeTransitionConfiguration",
        rpcClient.engine_exchangeTransitionConfigurationV1(ourConf),
        timeout = 1.seconds)
    except CatchableError as err:
      warn "Failed to exchange transition configuration",
            url = connection.engineUrl, err = err.msg
      connection.etcStatus = EtcStatus.exchangeError
      return

  connection.etcStatus =
    if ourConf.terminalTotalDifficulty != elConf.terminalTotalDifficulty:
      warn "Engine API configured with different terminal total difficulty",
            engineAPI_value = elConf.terminalTotalDifficulty,
            localValue = ourConf.terminalTotalDifficulty
      EtcStatus.mismatch
    elif ourConf.terminalBlockNumber != elConf.terminalBlockNumber:
      warn "Engine API reporting different terminal block number",
            engineAPI_value = elConf.terminalBlockNumber.uint64,
            localValue = ourConf.terminalBlockNumber.uint64
      EtcStatus.mismatch
    elif ourConf.terminalBlockHash != elConf.terminalBlockHash:
      warn "Engine API reporting different terminal block hash",
            engineAPI_value = elConf.terminalBlockHash,
            localValue = ourConf.terminalBlockHash
      EtcStatus.mismatch
    else:
      if connection.etcStatus == EtcStatus.notExchangedYet:
        # Log successful engine configuration exchange once at startup
        info "Successfully exchanged engine configuration",
             url = connection.engineUrl
      EtcStatus.match

proc exchangeTransitionConfiguration*(m: ELManager) {.async.} =
  if m.elConnections.len == 0:
    return

  let
    deadline = sleepAsync(3.seconds)
    requests = m.elConnections.mapIt(m.exchangeConfigWithSingleEL(it))
    requestsCompleted = allFutures(requests)

  await requestsCompleted or deadline

  var cancelled = 0
  for idx, req in requests:
    if not req.finished:
      m.elConnections[idx].etcStatus = EtcStatus.exchangeError
      req.cancel()
      inc cancelled

  if cancelled == requests.len:
    warn "Failed to exchange configuration with the configured EL end-points"

template readJsonField(j: JsonNode, fieldName: string, ValueType: type): untyped =
  var res: ValueType
  fromJson(j[fieldName], fieldName, res)
  res

template init[N: static int](T: type DynamicBytes[N, N]): T =
  T newSeq[byte](N)

proc fetchTimestamp(connection: ELConnection,
                    rpcClient: RpcClient,
                    blk: Eth1Block) {.async.} =
  debug "Fetching block timestamp", blockNum = blk.number

  let web3block = connection.trackedRequestWithTimeout(
    "getBlockByHash",
    rpcClient.getBlockByHash(blk.hash.asBlockHash),
    web3RequestsTimeout)

  blk.timestamp = Eth1BlockTimestamp web3block.timestamp

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
        hash: blockHash.asEth2Digest,
        number: blockNumber
        # The `timestamp` is set in `syncBlockRange` immediately
        # after calling this function, because we don't want to
        # make this function `async`
      )

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
    contractCallTimeout = 60.seconds

  proc fetchDepositContractData(connection: ELConnection,
                                rpcClient: RpcClient,
                                depositContact: Sender[DepositContract],
                                blk: Eth1Block): Future[DepositContractDataStatus] {.async.} =
    let
      startTime = Moment.now
      deadline = sleepAsync(contractCallTimeout)
      depositRoot = depositContract.get_deposit_root.call(blockNumber = blk.number)
      rawCount = depositContract.get_deposit_count.call(blockNumber = blk.number)

    # We allow failures on these requests becaues the clients
    # are expected to prune the state data for historical blocks
    connection.trackEngineApiRequest(
      depositRoot, "get_deposit_root", startTime, deadline,
      failureAllowed = true)
    connection.trackEngineApiRequest(
      rawCount, "get_deposit_count", startTime, deadline,
      failureAllowed = true)

    try:
      let fetchedRoot = asEth2Digest(
        awaitWithTimeout(depositRoot, deadline))
      if blk.depositRoot.isZero:
        blk.depositRoot = fetchedRoot
        result = Fetched
      elif blk.depositRoot == fetchedRoot:
        result = VerifiedCorrect
      else:
        result = DepositRootIncorrect
    except CatchableError as err:
      debug "Failed to fetch deposits root",
        blockNumber = blk.number,
        err = err.msg
      result = DepositRootUnavailable

    try:
      let fetchedCount = bytes_to_uint64(
        awaitWithTimeout(rawCount, deadline).toArray)
      if blk.depositCount == 0:
        blk.depositCount = fetchedCount
      elif blk.depositCount != fetchedCount:
        result = DepositCountIncorrect
    except CatchableError as err:
      debug "Failed to fetch deposits count",
            blockNumber = blk.number,
            err = err.msg
      result = DepositCountUnavailable

proc pruneOldBlocks(chain: var Eth1Chain, depositIndex: uint64) =
  ## Called on block finalization to delete old and now redundant data.
  let initialChunks = chain.finalizedDepositsMerkleizer.getChunkCount
  var lastBlock: Eth1Block

  while chain.blocks.len > 0:
    let blk = chain.blocks.peekFirst
    if blk.depositCount >= depositIndex:
      break
    else:
      for deposit in blk.deposits:
        chain.finalizedDepositsMerkleizer.addChunk hash_tree_root(deposit).data
    chain.popFirst()
    lastBlock = blk

  if chain.finalizedDepositsMerkleizer.getChunkCount > initialChunks:
    chain.finalizedBlockHash = lastBlock.hash
    chain.db.putDepositTreeSnapshot DepositTreeSnapshot(
      eth1Block: lastBlock.hash,
      depositContractState: chain.finalizedDepositsMerkleizer.toDepositContractState,
      blockHeight: lastBlock.number)

    eth1_finalized_head.set lastBlock.number.toGaugeValue
    eth1_finalized_deposits.set lastBlock.depositCount.toGaugeValue

    debug "Eth1 blocks pruned",
           newTailBlock = lastBlock.hash,
           depositsCount = lastBlock.depositCount

func advanceMerkleizer(chain: Eth1Chain,
                       merkleizer: var DepositsMerkleizer,
                       depositIndex: uint64): bool =
  if chain.blocks.len == 0:
    return depositIndex == merkleizer.getChunkCount

  if chain.blocks.peekLast.depositCount < depositIndex:
    return false

  let
    firstBlock = chain.blocks[0]
    depositsInLastPrunedBlock = firstBlock.depositCount -
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

iterator getDepositsRange*(chain: Eth1Chain, first, last: uint64): DepositData =
  # TODO It's possible to make this faster by performing binary search that
  #      will locate the blocks holding the `first` and `last` indices.
  # TODO There is an assumption here that the requested range will be present
  #      in the Eth1Chain. This should hold true at the call sites right now,
  #      but we need to guard the pre-conditions better.
  for blk in chain.blocks:
    if blk.depositCount <= first:
      continue

    let firstDepositIdxInBlk = blk.depositCount - blk.deposits.lenu64
    if firstDepositIdxInBlk >= last:
      break

    for i in 0 ..< blk.deposits.lenu64:
      let globalIdx = firstDepositIdxInBlk + i
      if globalIdx >= first and globalIdx < last:
        yield blk.deposits[i]

func lowerBound(chain: Eth1Chain, depositCount: uint64): Eth1Block =
  # TODO: This can be replaced with a proper binary search in the
  #       future, but the `algorithm` module currently requires an
  #       `openArray`, which the `deques` module can't provide yet.
  for eth1Block in chain.blocks:
    if eth1Block.depositCount > depositCount:
      return
    result = eth1Block

proc trackFinalizedState(chain: var Eth1Chain,
                         finalizedEth1Data: Eth1Data,
                         finalizedStateDepositIndex: uint64,
                         blockProposalExpected = false): bool =
  ## This function will return true if the ELManager is synced
  ## to the finalization point.

  if chain.blocks.len == 0:
    debug "Eth1 chain not initialized"
    return false

  let latest = chain.blocks.peekLast
  if latest.depositCount < finalizedEth1Data.deposit_count:
    if blockProposalExpected:
      error "The Eth1 chain is not synced",
            ourDepositsCount = latest.depositCount,
            targetDepositsCount = finalizedEth1Data.deposit_count
    return false

  let matchingBlock = chain.lowerBound(finalizedEth1Data.deposit_count)
  result = if matchingBlock != nil:
    if matchingBlock.depositRoot == finalizedEth1Data.deposit_root:
      true
    else:
      error "Corrupted deposits history detected",
            ourDepositsCount = matchingBlock.depositCount,
            taretDepositsCount = finalizedEth1Data.deposit_count,
            ourDepositsRoot = matchingBlock.depositRoot,
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

template trackFinalizedState*(m: ELManager,
                              finalizedEth1Data: Eth1Data,
                              finalizedStateDepositIndex: uint64): bool =
  trackFinalizedState(m.eth1Chain, finalizedEth1Data, finalizedStateDepositIndex)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.2/specs/phase0/validator.md#get_eth1_data
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
       eth1Block.depositRoot == vote.deposit_root and
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
      result.vote = latestBlock.toVoteData

  if pendingDepositsCount > 0:
    if hasLatestDeposits:
      let
        totalDepositsInNewBlock = min(MAX_DEPOSITS, pendingDepositsCount)
        postStateDepositIdx = stateDepositIdx + pendingDepositsCount
      var
        deposits = newSeqOfCap[DepositData](totalDepositsInNewBlock)
        depositRoots = newSeqOfCap[Eth2Digest](pendingDepositsCount)
      for data in chain.getDepositsRange(stateDepositIdx, postStateDepositIdx):
        if deposits.lenu64 < totalDepositsInNewBlock:
          deposits.add data
        depositRoots.add hash_tree_root(data)

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

template getBlockProposalData*(m: ELManager,
                               state: ForkedHashedBeaconState,
                               finalizedEth1Data: Eth1Data,
                               finalizedStateDepositIndex: uint64):
                               BlockProposalEth1Data =
  getBlockProposalData(
    m.eth1Chain, state, finalizedEth1Data, finalizedStateDepositIndex)

func new*(T: type ELConnection,
          engineUrl: EngineApiUrl): T =
  ELConnection(
    engineUrl: engineUrl,
    depositContractSyncStatus: DepositContractSyncStatus.unknown)

template getOrDefault[T, E](r: Result[T, E]): T =
  type TT = T
  get(r, default(TT))

proc init*(T: type Eth1Chain,
           cfg: RuntimeConfig,
           db: BeaconChainDB,
           depositContractBlockNumber: uint64,
           depositContractBlockHash: Eth2Digest): T =
  let
    (finalizedBlockHash, depositContractState) =
      if db != nil:
        let treeSnapshot = db.getDepositTreeSnapshot()
        if treeSnapshot.isSome:
          (treeSnapshot.get.eth1Block, treeSnapshot.get.depositContractState)
        else:
          let oldSnapshot = db.getUpgradableDepositSnapshot()
          if oldSnapshot.isSome:
            (oldSnapshot.get.eth1Block, oldSnapshot.get.depositContractState)
          else:
            db.putDepositTreeSnapshot DepositTreeSnapshot(
              eth1Block: depositContractBlockHash,
              blockHeight: depositContractBlockNumber)
            (depositContractBlockHash, default(DepositContractState))
      else:
        (depositContractBlockHash, default(DepositContractState))
    m = DepositsMerkleizer.init(depositContractState)

  T(db: db,
    cfg: cfg,
    finalizedBlockHash: finalizedBlockHash,
    finalizedDepositsMerkleizer: m,
    headMerkleizer: copy m)

proc new*(T: type ELManager,
          cfg: RuntimeConfig,
          depositContractBlockNumber: uint64,
          depositContractBlockHash: Eth2Digest,
          db: BeaconChainDB,
          engineApiUrls: seq[EngineApiUrl],
          eth1Network: Option[Eth1Network]): T =
  let
    eth1Chain = Eth1Chain.init(
      cfg, db, depositContractBlockNumber, depositContractBlockHash)

  debug "Initializing ELManager",
         depositContractBlockNumber,
         depositContractBlockHash

  T(eth1Chain: eth1Chain,
    depositContractAddress: cfg.DEPOSIT_CONTRACT_ADDRESS,
    depositContractBlockNumber: depositContractBlockNumber,
    depositContractBlockHash: depositContractBlockHash.asBlockHash,
    elConnections: mapIt(engineApiUrls, ELConnection.new(it)),
    eth1Network: eth1Network,
    blocksPerLogsRequest: targetBlocksPerLogsRequest)

proc safeCancel(fut: var Future[void]) =
  if not fut.isNil and not fut.finished:
    fut.cancel()
  fut = nil

func clear(chain: var Eth1Chain) =
  chain.blocks.clear()
  chain.blocksByHash.clear()
  chain.headMerkleizer = copy chain.finalizedDepositsMerkleizer
  chain.hasConsensusViolation = false

proc doStop(m: ELManager) {.async.} =
  safeCancel m.chainSyncingLoopFut
  safeCancel m.exchangeTransitionConfigurationLoopFut

  if m.elConnections.len > 0:
    let closeConnectionFutures = mapIt(m.elConnections, close(it))
    await allFutures(closeConnectionFutures)

proc stop(m: ELManager) {.async.} =
  if not m.stopFut.isNil:
    await m.stopFut
  else:
    m.stopFut = m.doStop()
    await m.stopFut
    m.stopFut = nil

const
  votedBlocksSafetyMargin = 50

func earliestBlockOfInterest(
    m: ELManager,
    latestEth1BlockNumber: Eth1BlockNumber): Eth1BlockNumber =
  let blocksOfInterestRange =
    SLOTS_PER_ETH1_VOTING_PERIOD +
    (2 * m.cfg.ETH1_FOLLOW_DISTANCE) +
    votedBlocksSafetyMargin

  if latestEth1BlockNumber > blocksOfInterestRange:
    latestEth1BlockNumber - blocksOfInterestRange
  else:
    0

proc syncBlockRange(m: ELManager,
                    connection: ELConnection,
                    rpcClient: RpcClient,
                    depositContract: Sender[DepositContract],
                    fromBlock, toBlock,
                    fullSyncFromBlock: Eth1BlockNumber) {.gcsafe, async.} =
  doAssert m.eth1Chain.blocks.len > 0

  var currentBlock = fromBlock
  while currentBlock <= toBlock:
    var
      depositLogs: JsonNode = nil
      maxBlockNumberRequested: Eth1BlockNumber
      backoff = 100

    while true:
      maxBlockNumberRequested =
        min(toBlock, currentBlock + m.blocksPerLogsRequest - 1)

      debug "Obtaining deposit log events",
            fromBlock = currentBlock,
            toBlock = maxBlockNumberRequested,
            backoff

      debug.logTime "Deposit logs obtained":
        # Reduce all request rate until we have a more general solution
        # for dealing with Infura's rate limits
        await sleepAsync(milliseconds(backoff))
        let
          startTime = Moment.now
          deadline = sleepAsync 30.seconds
          jsonLogsFut = depositContract.getJsonLogs(
            DepositEvent,
            fromBlock = some blockId(currentBlock),
            toBlock = some blockId(maxBlockNumberRequested))

        connection.trackEngineApiRequest(
          jsonLogsFut, "getLogs", startTime, deadline)

        depositLogs = try:
          # Downloading large amounts of deposits may take several minutes
          awaitWithTimeout(jsonLogsFut, deadline):
            raise newException(DataProviderTimeout,
              "Request time out while obtaining json logs")
        except CatchableError as err:
          debug "Request for deposit logs failed", err = err.msg
          inc failed_web3_requests
          backoff = (backoff * 3) div 2
          m.blocksPerLogsRequest = m.blocksPerLogsRequest div 2
          if m.blocksPerLogsRequest == 0:
            m.blocksPerLogsRequest = 1
            raise err
          continue
        m.blocksPerLogsRequest = min(
          (m.blocksPerLogsRequest * 3 + 1) div 2,
          targetBlocksPerLogsRequest)

      currentBlock = maxBlockNumberRequested + 1
      break

    let blocksWithDeposits = depositEventsToBlocks(depositLogs)

    for i in 0 ..< blocksWithDeposits.len:
      let blk = blocksWithDeposits[i]
      if blk.number > fullSyncFromBlock:
        await fetchTimestamp(connection, rpcClient, blk)
        let lastBlock = m.eth1Chain.blocks.peekLast
        for n in max(lastBlock.number + 1, fullSyncFromBlock) ..< blk.number:
          debug "Obtaining block without deposits", blockNum = n
          let blockWithoutDeposits = connection.trackedRequestWithTimeout(
            "getBlockByNumber",
            rpcClient.getBlockByNumber(n),
            web3RequestsTimeout)

          m.eth1Chain.addBlock(
            lastBlock.makeSuccessorWithoutDeposits(blockWithoutDeposits))
          eth1_synced_head.set blockWithoutDeposits.number.toGaugeValue

      m.eth1Chain.addBlock blk
      eth1_synced_head.set blk.number.toGaugeValue

    if blocksWithDeposits.len > 0:
      let lastIdx = blocksWithDeposits.len - 1
      template lastBlock: auto = blocksWithDeposits[lastIdx]

      let status = when hasDepositRootChecks:
        rpcClient.fetchDepositContractData(depositContract, lastBlock)
      else:
        DepositRootUnavailable

      when hasDepositRootChecks:
        debug "Deposit contract state verified",
              status = $status,
              ourCount = lastBlock.depositCount,
              ourRoot = lastBlock.depositRoot

      case status
      of DepositRootIncorrect, DepositCountIncorrect:
        raise newException(CorruptDataProvider,
          "The deposit log events disagree with the deposit contract state")
      else:
        discard

      info "Eth1 sync progress",
        blockNumber = lastBlock.number,
        depositsProcessed = lastBlock.depositCount

func init(T: type FullBlockId, blk: Eth1BlockHeader|BlockObject): T =
  FullBlockId(number: Eth1BlockNumber blk.number, hash: blk.hash)

func isNewLastBlock(m: ELManager, blk: Eth1BlockHeader|BlockObject): bool =
  m.latestEth1Block.isNone or blk.number.uint64 > m.latestEth1BlockNumber

func hasProperlyConfiguredConnection*(m: ELManager): bool =
  for connection in m.elConnections:
    if connection.etcStatus == EtcStatus.match:
      return true

  return false

proc startExchangeTransitionConfigurationLoop(m: ELManager) {.async.} =
  debug "Starting exchange transition configuration loop"

  while true:
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.2/src/engine/specification.md#engine_exchangetransitionconfigurationv1
    debug "Exchange transition configuration tick"
    traceAsyncErrors m.exchangeTransitionConfiguration()
    await sleepAsync(60.seconds)

proc syncEth1Chain(m: ELManager, connection: ELConnection) {.async.} =
  let rpcClient = awaitOrRaiseOnTimeout(connection.connectedRpcClient(),
                                        1.seconds)
  let
    # BEWARE
    # `connectedRpcClient` guarantees that connection.web3 will not be
    # `none` here, but it's not safe to initialize this later (e.g closer
    # to where it's used) because `connection.web3` may be set to `none`
    # at any time after a failed request. Luckily, the `contractSender`
    # object is very cheap to create.
    depositContract = connection.web3.get.contractSender(
      DepositContract, m.depositContractAddress)

    shouldProcessDeposits = not (
      m.depositContractAddress.isZeroMemory or
      m.eth1Chain.finalizedBlockHash.data.isZeroMemory)

  trace "Starting syncEth1Chain", shouldProcessDeposits

  logScope:
    url = connection.engineUrl.url

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
  #
  # TODO
  # Perhaps the above problem was manifesting only with the obsolete
  # JSON-RPC data providers, which can no longer be used with Nimbus.
  if m.eth1Chain.blocks.len > 0:
    let needsReset = m.eth1Chain.hasConsensusViolation or (block:
      let
        lastKnownBlock = m.eth1Chain.blocks.peekLast
        matchingBlockAtNewProvider = connection.trackedRequestWithTimeout(
          "getBlockByNumber",
          rpcClient.getBlockByNumber(lastKnownBlock.number),
          web3RequestsTimeout)

      lastKnownBlock.hash.asBlockHash != matchingBlockAtNewProvider.hash)

    if needsReset:
      trace "Resetting the Eth1 chain",
            hasConsensusViolation = m.eth1Chain.hasConsensusViolation
      m.eth1Chain.clear()

  var eth1SyncedTo: Eth1BlockNumber
  if shouldProcessDeposits:
    if m.eth1Chain.blocks.len == 0:
      let finalizedBlockHash = m.eth1Chain.finalizedBlockHash.asBlockHash
      let startBlock =
        connection.trackedRequestWithTimeout(
          "getBlockByHash",
          rpcClient.getBlockByHash(finalizedBlockHash),
          web3RequestsTimeout)

      m.eth1Chain.addBlock Eth1Block(
        hash: m.eth1Chain.finalizedBlockHash,
        number: Eth1BlockNumber startBlock.number,
        timestamp: Eth1BlockTimestamp startBlock.timestamp)

    eth1SyncedTo = m.eth1Chain.blocks[^1].number

    eth1_synced_head.set eth1SyncedTo.toGaugeValue
    eth1_finalized_head.set eth1SyncedTo.toGaugeValue
    eth1_finalized_deposits.set(
      m.eth1Chain.finalizedDepositsMerkleizer.getChunkCount.toGaugeValue)

    debug "Starting Eth1 syncing", `from` = shortLog(m.eth1Chain.blocks[^1])

  var didPollOnce = false
  while true:
    debug "syncEth1Chain tick"

    if bnStatus == BeaconNodeStatus.Stopping:
      await m.stop()
      return

    if m.eth1Chain.hasConsensusViolation:
      raise newException(CorruptDataProvider, "Eth1 chain contradicts Eth2 consensus")

    let latestBlock = try:
      connection.trackedRequestWithTimeout(
        "getBlockByNumber",
        rpcClient.eth_getBlockByNumber(blockId("latest"), false),
        web3RequestsTimeout)
    except CatchableError as err:
      warn "Failed to obtain the latest block from the EL", err = err.msg
      raise err

    m.syncTargetBlock = some(
      if Eth1BlockNumber(latestBlock.number) > m.cfg.ETH1_FOLLOW_DISTANCE:
        Eth1BlockNumber(latestBlock.number) - m.cfg.ETH1_FOLLOW_DISTANCE
      else:
        Eth1BlockNumber(0))
    if m.syncTargetBlock.get <= eth1SyncedTo:
      # The chain reorged to a lower height.
      # It's relatively safe to ignore that.
      await sleepAsync(m.cfg.SECONDS_PER_ETH1_BLOCK.int.seconds)
      continue

    eth1_latest_head.set latestBlock.number.toGaugeValue

    if shouldProcessDeposits and
       latestBlock.number.uint64 > m.cfg.ETH1_FOLLOW_DISTANCE:
      await m.syncBlockRange(connection,
                             rpcClient,
                             depositContract,
                             eth1SyncedTo + 1,
                             m.syncTargetBlock.get,
                             m.earliestBlockOfInterest(Eth1BlockNumber latestBlock.number))

    eth1SyncedTo = m.syncTargetBlock.get
    eth1_synced_head.set eth1SyncedTo.toGaugeValue

proc startChainSyncingLoop(m: ELManager) {.async.} =
  info "Starting execution layer deposits syncing",
        contract = $m.depositContractAddress

  var syncedConnectionFut = m.selectConnectionForChainSyncing()
  info "Connection attempt started"

  while true:
    try:
      await syncedConnectionFut or sleepAsync(60.seconds)
      if not syncedConnectionFut.finished:
        warn "No suitable EL connection for deposit syncing"
        await sleepAsync(chronos.seconds(30))
        continue

      await syncEth1Chain(m, syncedConnectionFut.read)
    except CatchableError as err:
      await sleepAsync(10.seconds)

      # A more detailed error is already logged by trackEngineApiRequest
      debug "Restarting the deposit syncing loop"

      # To be extra safe, we will make a fresh connection attempt
      await syncedConnectionFut.cancelAndWait()
      syncedConnectionFut = m.selectConnectionForChainSyncing()

proc start*(m: ELManager) {.gcsafe.} =
  if m.elConnections.len == 0:
    return

  ## Calling `ELManager.start()` on an already started ELManager is a noop
  if m.chainSyncingLoopFut.isNil:
    m.chainSyncingLoopFut =
      m.startChainSyncingLoop()

  if m.hasJwtSecret and m.exchangeTransitionConfigurationLoopFut.isNil:
    m.exchangeTransitionConfigurationLoopFut =
      m.startExchangeTransitionConfigurationLoop()

func `$`(x: Quantity): string =
  $(x.uint64)

func `$`(x: BlockObject): string =
  $(x.number) & " [" & $(x.hash) & "]"

proc testWeb3Provider*(web3Url: Uri,
                       depositContractAddress: Eth1Address,
                       jwtSecret: Option[seq[byte]]) {.async.} =
  stdout.write "Establishing web3 connection..."
  var web3: Web3
  try:
    web3 = awaitOrRaiseOnTimeout(
      newWeb3($web3Url, getJsonRpcRequestHeaders(jwtSecret)),
      5.seconds)
    stdout.write "\rEstablishing web3 connection: Connected\n"
  except CatchableError as err:
    stdout.write "\rEstablishing web3 connection: Failure(" & err.msg & ")\n"
    quit 1

  template request(actionDesc: static string,
                   action: untyped): untyped =
    stdout.write actionDesc & "..."
    stdout.flushFile()
    var res: typeof(read action)
    try:
      res = awaitOrRaiseOnTimeout(action, web3RequestsTimeout)
      stdout.write "\r" & actionDesc & ": " & $res
    except CatchableError as err:
      stdout.write "\r" & actionDesc & ": Error(" & err.msg & ")"
    stdout.write "\n"
    res

  let
    chainId = request "Chain ID":
      web3.provider.eth_chainId()

    latestBlock = request "Latest block":
      web3.provider.eth_getBlockByNumber(blockId("latest"), false)

    syncStatus = request "Sync status":
      web3.provider.eth_syncing()

    ns = web3.contractSender(DepositContract, depositContractAddress)

    depositRoot = request "Deposit root":
      ns.get_deposit_root.call(blockNumber = latestBlock.number.uint64)

import
  std/[deques, tables, hashes, options, strformat],
  chronos, web3, web3/ethtypes as web3Types, json, chronicles,
  eth/common/eth_types, eth/async_utils,
  spec/[datatypes, digest, crypto, beaconstate, helpers, validator],
  network_metadata, merkle_minimal

from times import epochTime

export
  web3Types

contract(DepositContract):
  proc deposit(pubkey: Bytes48,
               withdrawalCredentials: Bytes32,
               signature: Bytes96,
               deposit_data_root: FixedBytes[32])

  proc get_deposit_root(): FixedBytes[32]
  proc get_deposit_count(): Bytes8

  proc DepositEvent(pubkey: Bytes48,
                    withdrawalCredentials: Bytes32,
                    amount: Bytes8,
                    signature: Bytes96,
                    index: Bytes8) {.event.}
# TODO
# The raises list of this module are still not usable due to general
# Exceptions being reported from Chronos's asyncfutures2.

type
  Eth1BlockNumber* = uint64
  Eth1BlockTimestamp* = uint64
  Eth1BlockHeader = web3Types.BlockHeader

  Eth1Block* = ref object
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
    deposits*: seq[Deposit]
    voteData*: Eth1Data
    knownGoodDepositsCount*: Option[uint64]

  Eth1Chain* = object
    knownStart: Eth1Data
    knownStartBlockNum: Option[Eth1BlockNumber]

    blocks: Deque[Eth1Block]
    blocksByHash: Table[BlockHash, Eth1Block]
    allDeposits*: seq[Deposit]

  MainchainMonitor* = ref object
    preset: RuntimePreset
    depositContractAddress: Address
    dataProviderFactory*: DataProviderFactory

    genesisState: BeaconStateRef
    genesisStateFut: Future[void]
    genesisMonitoringFut: Future[void]

    eth1Chain: Eth1Chain

    depositQueue: AsyncQueue[Eth1BlockHeader]
    runFut: Future[void]

  DataProvider* = object of RootObj
  DataProviderRef* = ref DataProvider

  DataProviderFactory* = object
    desc: string
    new: proc(depositContractAddress: Address): Future[DataProviderRef] {.
      gcsafe
      # raises: [Defect]
    .}

  Web3DataProvider* = object of DataProvider
    url: string
    web3: Web3
    ns: Sender[DepositContract]
    blockHeadersSubscription: Subscription

  Web3DataProviderRef* = ref Web3DataProvider

  ReorgDepthLimitExceeded = object of CatchableError
  CorruptDataProvider = object of CatchableError

  DisconnectHandler* = proc () {.gcsafe, raises: [Defect].}

  DepositEventHandler* = proc (
    pubkey: Bytes48,
    withdrawalCredentials: Bytes32,
    amount: Bytes8,
    signature: Bytes96, merkleTreeIndex: Bytes8, j: JsonNode) {.raises: [Defect], gcsafe.}

const
  reorgDepthLimit = 1000
  web3Timeouts = 5.seconds
  followDistanceInSeconds = uint64(SECONDS_PER_ETH1_BLOCK * ETH1_FOLLOW_DISTANCE)

# TODO: Add preset validation
# MIN_GENESIS_ACTIVE_VALIDATOR_COUNT should be larger than SLOTS_PER_EPOCH
#  doAssert SECONDS_PER_ETH1_BLOCK * ETH1_FOLLOW_DISTANCE < GENESIS_DELAY,
#             "Invalid configuration: GENESIS_DELAY is set too low"

# TODO Nim's analysis on the lock level of the methods in this
# module seems broken. Investigate and file this as an issue.
{.push warning[LockLevel]: off.}

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(state: BeaconState, slot: Slot): uint64 =
  state.genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time*(state: BeaconState): uint64 =
  let eth1_voting_period_start_slot =
    state.slot - state.slot mod SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(state, eth1_voting_period_start_slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(blk: Eth1Block, period_start: uint64): bool =
  (blk.timestamp + SECONDS_PER_ETH1_BLOCK.uint64 * ETH1_FOLLOW_DISTANCE.uint64 <= period_start) and
  (blk.timestamp + SECONDS_PER_ETH1_BLOCK.uint64 * ETH1_FOLLOW_DISTANCE.uint64 * 2 >= period_start)

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func shortLog(b: Eth1Block): string =
  &"{b.number}:{shortLog b.voteData.block_hash}"

func getDepositsInRange(eth1Chain: Eth1Chain,
                        sinceBlock, latestBlock: Eth1BlockNumber): seq[Deposit] =
  ## Returns all deposits that happened AFTER the block `sinceBlock` (not inclusive).
  ## The deposits in `latestBlock` will be included.
  if latestBlock <= sinceBlock: return

  let firstBlockInCache = eth1Chain.blocks[0].number

  # This function should be used with indices obtained with `eth1Chain.findBlock`.
  # This guarantess that both of these indices will be valid:
  doAssert sinceBlock >= firstBlockInCache and
           (latestBlock - firstBlockInCache) < eth1Chain.blocks.lenu64
  let
    sinceBlockIdx = sinceBlock - firstBlockInCache
    latestBlockIdx = latestBlock - firstBlockInCache

  for i in (sinceBlockIdx + 1) ..< latestBlockIdx:
    result.add eth1Chain.blocks[i].deposits

template findBlock*(eth1Chain: Eth1Chain, hash: BlockHash): Eth1Block =
  eth1Chain.blocksByHash.getOrDefault(hash, nil)

template findBlock*(eth1Chain: Eth1Chain, eth1Data: Eth1Data): Eth1Block =
  getOrDefault(eth1Chain.blocksByHash, asBlockHash(eth1Data.block_hash), nil)

proc findParent*(eth1Chain: Eth1Chain, blk: BlockObject): Eth1Block =
  result = eth1Chain.findBlock(blk.parentHash)
  # a distinct type is stipped here:
  let blockNumber = Eth1BlockNumber(blk.number)
  if result != nil and result.number != blockNumber - 1:
    debug "Found inconsistent numbering of Eth1 blocks. Ignoring block.",
          blockHash = blk.hash.toHex, blockNumber,
          parentHash = blk.parentHash.toHex, parentNumber = result.number
    result = nil

func latestCandidateBlock(eth1Chain: Eth1Chain, periodStart: uint64): Eth1Block =
  for i in countdown(eth1Chain.blocks.len - 1, 0):
    let blk = eth1Chain.blocks[i]
    if is_candidate_block(blk, periodStart):
      return blk

func popBlock(eth1Chain: var Eth1Chain) =
  let removed = eth1Chain.blocks.popLast
  eth1Chain.blocksByHash.del removed.voteData.block_hash.asBlockHash

func trimHeight(eth1Chain: var Eth1Chain, blockNumber: Eth1BlockNumber) =
  ## Removes all blocks above certain `blockNumber`
  while eth1Chain.blocks.len > 0:
    if eth1Chain.blocks.peekLast.number > blockNumber:
      eth1Chain.popBlock()
    else:
      break

  if eth1Chain.blocks.len > 0:
    eth1Chain.allDeposits.setLen(eth1Chain.blocks[^1].voteData.deposit_count)
  else:
    eth1Chain.allDeposits.setLen(0)

func isSuccessorBlock(eth1Chain: Eth1Chain, newBlock: Eth1Block): bool =
  let currentDepositCount = if eth1Chain.blocks.len == 0:
    eth1Chain.knownStart.deposit_count
  else:
    let lastBlock = eth1Chain.blocks.peekLast
    if lastBlock.number >= newBlock.number: return false
    lastBlock.voteData.deposit_count

  (currentDepositCount + newBlock.deposits.lenu64) == newBlock.voteData.deposit_count

func addSuccessorBlock*(eth1Chain: var Eth1Chain, newBlock: Eth1Block): bool =
  result = isSuccessorBlock(eth1Chain, newBlock)
  if result:
    eth1Chain.allDeposits.add newBlock.deposits
    reset newBlock.deposits
    eth1Chain.blocks.addLast newBlock
    eth1Chain.blocksByHash[newBlock.voteData.block_hash.asBlockHash] = newBlock

func totalDeposits*(eth1Chain: Eth1Chain): int =
  for blk in eth1Chain.blocks:
    result += blk.deposits.len

func allDeposits*(eth1Chain: Eth1Chain): seq[Deposit] =
  for blk in eth1Chain.blocks:
    result.add blk.deposits

func clear*(eth1Chain: var Eth1Chain) =
  eth1Chain = default(Eth1Chain)

template hash*(x: Eth1Block): Hash =
  hash(x.voteData.block_hash.data)

template notImplemented =
  doAssert false, "Method not implemented"

method getBlockByHash*(p: DataProviderRef, hash: BlockHash): Future[BlockObject] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect]
.} =
  notImplemented

method getBlockByNumber*(p: DataProviderRef, hash: Eth1BlockNumber): Future[BlockObject] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect]
.} =
  notImplemented

method onDisconnect*(p: DataProviderRef, handler: DisconnectHandler) {.
  base
  gcsafe
  locks: 0
  # raises: []
.} =
  notImplemented

method onBlockHeaders*(p: DataProviderRef,
                       blockHeaderHandler: BlockHeaderHandler,
                       errorHandler: SubscriptionErrorHandler): Future[void] {.
  base
  gcsafe
  locks: 0
  # raises: []
.} =
  notImplemented

method close*(p: DataProviderRef): Future[void] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect]
.} =
  notImplemented

method fetchDepositData*(p: DataProviderRef,
                         fromBlock, toBlock: Eth1BlockNumber): Future[seq[Eth1Block]] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect, CatchableError]
.} =
  notImplemented

method fetchBlockDetails(p: DataProviderRef, blk: Eth1Block): Future[void] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect, CatchableError]
.} =
  notImplemented

proc new*(T: type Web3DataProvider,
          web3Url: string,
          depositContractAddress: Address): Future[ref Web3DataProvider] {.
  async
  # raises: [Defect]
.} =
  try:
    type R = ref T
    let
      web3 = await newWeb3(web3Url)
      ns = web3.contractSender(DepositContract, depositContractAddress)
    return R(url: web3Url, web3: web3, ns: ns)
  except CatchableError:
    return nil

func web3Provider*(web3Url: string): DataProviderFactory =
  proc factory(depositContractAddress: Address): Future[DataProviderRef] {.async.} =
      result = await Web3DataProvider.new(web3Url, depositContractAddress)

  DataProviderFactory(desc: "web3(" & web3Url & ")", new: factory)

method close*(p: Web3DataProviderRef): Future[void] {.async, locks: 0.} =
  if p.blockHeadersSubscription != nil:
    await p.blockHeadersSubscription.unsubscribe()

  await p.web3.close()

method getBlockByHash*(p: Web3DataProviderRef, hash: BlockHash): Future[BlockObject] =
  return p.web3.provider.eth_getBlockByHash(hash, false)

method getBlockByNumber*(p: Web3DataProviderRef, number: Eth1BlockNumber): Future[BlockObject] =
  return p.web3.provider.eth_getBlockByNumber(&"0x{number:X}", false)

proc getBlockNumber(p: DataProviderRef, hash: BlockHash): Future[Eth1BlockNumber] {.async.} =
  try:
    let blk = awaitWithTimeout(p.getBlockByHash(hash), web3Timeouts):
                               return 0
    return Eth1BlockNumber(blk.number)
  except CatchableError as exc:
    notice "Failed to get Eth1 block number from hash",
      hash = $hash, err = exc.msg
    raise

template readJsonField(j: JsonNode,
                       fieldName: string,
                       ValueType: type): untyped =
  var res: ValueType
  fromJson(j[fieldName], fieldName, res)
  res

proc readJsonDeposits(depositsList: JsonNode): seq[Eth1Block] =
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
      pubkey: Bytes48
      withdrawalCredentials: Bytes32
      amount: Bytes8
      signature: Bytes96
      index: Bytes8

    var offset = 0
    offset += decode(logData, offset, pubkey)
    offset += decode(logData, offset, withdrawalCredentials)
    offset += decode(logData, offset, amount)
    offset += decode(logData, offset, signature)
    offset += decode(logData, offset, index)

    lastEth1Block.deposits.add Deposit(
      data: DepositData(
        pubkey: ValidatorPubKey.init(array[48, byte](pubkey)),
        withdrawal_credentials: Eth2Digest(data: array[32, byte](withdrawalCredentials)),
        amount: bytes_to_uint64(array[8, byte](amount)),
        signature: ValidatorSig.init(array[96, byte](signature))))

method fetchDepositData*(p: Web3DataProviderRef,
                         fromBlock, toBlock: Eth1BlockNumber): Future[seq[Eth1Block]]
                        {.async, locks: 0.} =
  info "Obtaining deposit log events", fromBlock, toBlock
  return readJsonDeposits(await p.ns.getJsonLogs(DepositEvent,
                                                 fromBlock = some blockId(fromBlock),
                                                 toBlock = some blockId(toBlock)))

method fetchBlockDetails(p: Web3DataProviderRef, blk: Eth1Block) {.async.} =
  let
    web3Block = p.getBlockByNumber(blk.number)
    depositRoot = p.ns.get_deposit_root.call(blockNumber = blk.number)
    rawCount = p.ns.get_deposit_count.call(blockNumber = blk.number)

  discard await web3Block
  discard await depositRoot
  discard await rawCount

  let depositCount = bytes_to_uint64(array[8, byte](rawCount.read))

  blk.timestamp = Eth1BlockTimestamp(web3Block.read.timestamp)
  blk.voteData.deposit_count = depositCount
  blk.voteData.deposit_root = depositRoot.read.asEth2Digest

method onDisconnect*(p: Web3DataProviderRef, handler: DisconnectHandler) {.
  gcsafe
  locks: 0
  # raises: []
.} =
  p.web3.onDisconnect = handler

method onBlockHeaders*(p: Web3DataProviderRef,
                       blockHeaderHandler: BlockHeaderHandler,
                       errorHandler: SubscriptionErrorHandler): Future[void] {.
  async
  gcsafe
  locks: 0
  # raises: []
.} =
  if p.blockHeadersSubscription != nil:
    await p.blockHeadersSubscription.unsubscribe()

  info "Waiting for new Eth1 block headers"

  let options = newJObject()
  p.blockHeadersSubscription = await p.web3.subscribeForBlockHeaders(
    options, blockHeaderHandler, errorHandler)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#get_eth1_data
func getBlockProposalData*(eth1Chain: Eth1Chain,
                           state: BeaconState): (Eth1Data, seq[Deposit]) =
  template voteForNoChange() =
    return (state.eth1_data, newSeq[Deposit]())

  let prevBlock = eth1Chain.findBlock(state.eth1_data)
  if prevBlock == nil:
    # The Eth1 block currently referenced in the BeaconState is unknown to us.
    # This situation is not specifically covered in the honest validator spec,
    # but there is a similar condition where none of the eth1_data_votes is
    # present in our worldview. The suggestion there is to vote for "no change"
    # and we'll do the same here:
    voteForNoChange()

  let periodStart = voting_period_start_time(state)

  var otherVotesCountTable = initCountTable[Eth1Block]()
  for vote in state.eth1_data_votes:
    let eth1Block = eth1Chain.findBlock(vote)
    if eth1Block != nil and is_candidate_block(eth1Block, periodStart):
      otherVotesCountTable.inc eth1Block

  var ourVote: Eth1Block
  if otherVotesCountTable.len > 0:
    ourVote = otherVotesCountTable.largest.key
  else:
    ourVote = eth1Chain.latestCandidateBlock(periodStart)
    if ourVote == nil:
      voteForNoChange()

  (ourVote.voteData, eth1Chain.getDepositsInRange(prevBlock.number, ourVote.number))

template getBlockProposalData*(m: MainchainMonitor, state: BeaconState): untyped =
  getBlockProposalData(m.eth1Chain, state)

proc init*(T: type MainchainMonitor,
           preset: RuntimePreset,
           dataProviderFactory: DataProviderFactory,
           depositContractAddress: Eth1Address,
           startPosition: Eth1Data): T =
  T(preset: preset,
    depositQueue: newAsyncQueue[Eth1BlockHeader](),
    dataProviderFactory: dataProviderFactory,
    depositContractAddress: Address depositContractAddress,
    eth1Chain: Eth1Chain(knownStart: startPosition))

proc isCandidateForGenesis(preset: RuntimePreset,
                           timeNow: float,
                           blk: Eth1Block): bool =
  if float(blk.timestamp + followDistanceInSeconds) > timeNow:
    return false

  if genesis_time_from_eth1_timestamp(preset, blk.timestamp) < preset.MIN_GENESIS_TIME:
    return false

  if blk.knownGoodDepositsCount.isSome:
    blk.knownGoodDepositsCount.get >= preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
  else:
    blk.voteData.deposit_count >= preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT

proc minGenesisCandidateBlockIdx(m: MainchainMonitor): Option[int]
                                {.raises: [Defect].} =
  if m.eth1Chain.blocks.len == 0:
    return

  let now = epochTime()
  if not isCandidateForGenesis(m.preset, now, m.eth1Chain.blocks.peekLast):
    return

  var candidatePos = m.eth1Chain.blocks.len - 1
  while candidatePos > 1:
    if not isCandidateForGenesis(m.preset, now, m.eth1Chain.blocks[candidatePos - 1]):
      break
    dec candidatePos

  return some(candidatePos)

proc createBeaconStateAux(preset: RuntimePreset,
                          eth1Block: Eth1Block,
                          deposits: var openarray[Deposit]): BeaconStateRef =
  attachMerkleProofs deposits
  result = initialize_beacon_state_from_eth1(preset,
                                             eth1Block.voteData.block_hash,
                                             eth1Block.timestamp.uint64,
                                             deposits, {})
  var cache = StateCache()
  let activeValidators = count_active_validators(result[], GENESIS_EPOCH, cache)
  eth1Block.knownGoodDepositsCount = some activeValidators

proc createBeaconState(m: MainchainMonitor, eth1Block: Eth1Block): BeaconStateRef =
  createBeaconStateAux(
    m.preset,
    eth1Block,
    m.eth1Chain.allDeposits.toOpenArray(0, int(eth1Block.voteData.deposit_count - 1)))

proc signalGenesis(m: MainchainMonitor, genesisState: BeaconStateRef) =
  m.genesisState = genesisState

  if not m.genesisStateFut.isNil:
    m.genesisStateFut.complete()
    m.genesisStateFut = nil

proc findGenesisBlockInRange(m: MainchainMonitor,
                             startBlock, endBlock: Eth1Block): Future[Eth1Block]
                            {.async.} =
  let dataProvider = await m.dataProviderFactory.new(m.depositContractAddress)
  if dataProvider == nil:
    error "Failed to initialize Eth1 data provider",
          provider = m.dataProviderFactory.desc
    raise newException(CatchableError, "Failed to initialize Eth1 data provider")

  var
    startBlock = startBlock
    endBlock = endBlock
    depositData = startBlock.voteData

  while startBlock.number + 1 < endBlock.number:
    let
      MIN_GENESIS_TIME = m.preset.MIN_GENESIS_TIME
      startBlockTime = genesis_time_from_eth1_timestamp(m.preset, startBlock.timestamp)
      secondsPerBlock = float(endBlock.timestamp - startBlock.timestamp) /
                        float(endBlock.number - startBlock.number)
      blocksToJump = max(float(MIN_GENESIS_TIME - startBlockTime) / secondsPerBlock, 1.0)
      candidateNumber = min(endBlock.number - 1, startBlock.number + 1) # blocksToJump.uint64)
      candidateBlock = await dataProvider.getBlockByNumber(candidateNumber)

    var candidateAsEth1Block = Eth1Block(number: candidateBlock.number.uint64,
                                         timestamp: candidateBlock.timestamp.uint64,
                                         voteData: depositData)
    candidateAsEth1Block.voteData.block_hash = candidateBlock.hash.asEth2Digest

    let candidateGenesisTime = genesis_time_from_eth1_timestamp(
      m.preset, candidateBlock.timestamp.uint64)

    info "Probing possible genesis block",
      `block` = candidateBlock.number.uint64,
      candidateGenesisTime

    if candidateGenesisTime < MIN_GENESIS_TIME:
      startBlock = candidateAsEth1Block
    else:
      endBlock = candidateAsEth1Block

  return endBlock

proc checkForGenesisLoop(m: MainchainMonitor) {.async.} =
  while true:
    if not m.genesisState.isNil:
      return

    try:
      let genesisCandidateIdx = m.minGenesisCandidateBlockIdx
      if genesisCandidateIdx.isSome:
        let
          genesisCandidateIdx = genesisCandidateIdx.get
          genesisCandidate =  m.eth1Chain.blocks[genesisCandidateIdx]

        info "Generating state for candidate block for genesis",
             blockNum = genesisCandidate.number,
             blockHash = genesisCandidate.voteData.block_hash,
             potentialDeposits = genesisCandidate.voteData.deposit_count

        let
          candidateState = m.createBeaconState(genesisCandidate)

        if genesisCandidate.knownGoodDepositsCount.get >= m.preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
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
          if genesisCandidateIdx > 0:
            let preceedingEth1Block = m.eth1Chain.blocks[genesisCandidateIdx - 1]
            if preceedingEth1Block.voteData.deposit_root == genesisCandidate.voteData.deposit_root:
              preceedingEth1Block.knownGoodDepositsCount = genesisCandidate.knownGoodDepositsCount
            else:
              discard m.createBeaconState(preceedingEth1Block)

            if preceedingEth1Block.knownGoodDepositsCount.get >= m.preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT and
               genesisCandidate.number - preceedingEth1Block.number > 1:
              let genesisBlock = await m.findGenesisBlockInRange(preceedingEth1Block, genesisCandidate)
              if genesisBlock.number != genesisCandidate.number:
                m.signalGenesis m.createBeaconState(genesisBlock)
                return

          m.signalGenesis candidateState
          return
        else:
          info "Eth2 genesis candidate block rejected",
               `block` = shortLog(genesisCandidate),
               validDeposits = genesisCandidate.knownGoodDepositsCount.get,
               needed = m.preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
      else:
        # TODO: check for a stale monitor
        discard
    except CatchableError as err:
      debug "Unexpected error in checkForGenesisLoop", err = err.msg

    await sleepAsync(1.seconds)

proc waitGenesis*(m: MainchainMonitor): Future[BeaconStateRef] {.async.} =
  if m.genesisState.isNil:
    if m.genesisStateFut.isNil:
      m.genesisStateFut = newFuture[void]("waitGenesis")

    m.genesisMonitoringFut = m.checkForGenesisLoop()
    await m.genesisStateFut
    m.genesisStateFut = nil

  if m.genesisState != nil:
    return m.genesisState
  else:
    raiseAssert "Unreachable code"

func totalNonFinalizedBlocks(eth1Chain: Eth1Chain): Natural =
  # TODO: implement this precisely
  eth1Chain.blocks.len

func latestEth1Data(eth1Chain: Eth1Chain): Eth1Data =
  if eth1Chain.blocks.len > 0:
    eth1Chain.blocks[^1].voteData
  else:
    eth1Chain.knownStart

func knownInvalidDepositsCount(eth1Chain: Eth1Chain): uint64 =
  for i in countdown(eth1Chain.blocks.len - 1, 0):
    let blk = eth1Chain.blocks[i]
    if blk.knownGoodDepositsCount.isSome:
      return blk.voteData.deposit_count - blk.knownGoodDepositsCount.get

  return 0

func maxValidDeposits(eth1Chain: Eth1Chain): uint64 =
  if eth1Chain.blocks.len > 0:
    let lastBlock = eth1Chain.blocks[^1]
    lastBlock.knownGoodDepositsCount.get(
      lastBlock.voteData.deposit_count - eth1Chain.knownInvalidDepositsCount)
  else:
    0

proc processDeposits(m: MainchainMonitor,
                     dataProvider: DataProviderRef) {.async.} =
  # ATTENTION!
  # Please note that this code is using a queue to guarantee the
  # strict serial order of processing of deposits. If we had the
  # same code embedded in the deposit contracts events handler,
  # it could easily re-order the steps due to the intruptable
  # interleaved execution of async code.
  while true:
    let blk = await m.depositQueue.popFirst()
    m.eth1Chain.trimHeight(Eth1BlockNumber(blk.number) - 1)

    let latestKnownBlock = if m.eth1Chain.blocks.len > 0:
      m.eth1Chain.blocks[^1].number
    elif m.eth1Chain.knownStartBlockNum.isSome:
      m.eth1Chain.knownStartBlockNum.get
    else:
      m.eth1Chain.knownStartBlockNum = some(
        await dataProvider.getBlockNumber(m.eth1Chain.knownStart.block_hash.asBlockHash))
      m.eth1Chain.knownStartBlockNum.get

    let eth1Blocks = await dataProvider.fetchDepositData(latestKnownBlock + 1,
                                                         Eth1BlockNumber blk.number)
    if eth1Blocks.len == 0:
      if m.eth1Chain.maxValidDeposits > m.preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT and
         m.eth1Chain.knownStart.deposit_count == 0:
        let latestEth1Data = m.eth1Chain.latestEth1Data

        for missingBlockNum in latestKnownBlock + 1 ..< Eth1BlockNumber(blk.number):
          let missingBlock = await dataProvider.getBlockByNumber(missingBlockNum)
          doAssert m.eth1Chain.addSuccessorBlock Eth1Block(
            number: Eth1BlockNumber(missingBlock.number),
            timestamp: Eth1BlockTimestamp(missingBlock.timestamp),
            voteData: latestEth1Data)

        doAssert m.eth1Chain.addSuccessorBlock Eth1Block(
          number: Eth1BlockNumber(blk.number),
          timestamp: Eth1BlockTimestamp(blk.timestamp),
          voteData: latestEth1Data)
    else:
      template logBlockProcessed(blk) =
        info "Eth1 block processed",
             `block` = shortLog(blk), totalDeposits = blk.voteData.deposit_count

      await dataProvider.fetchBlockDetails(eth1Blocks[0])
      if m.eth1Chain.addSuccessorBlock(eth1Blocks[0]):
        logBlockProcessed eth1Blocks[0]

        for i in 1 ..< eth1Blocks.len:
          await dataProvider.fetchBlockDetails(eth1Blocks[i])
          if m.eth1Chain.addSuccessorBlock(eth1Blocks[i]):
            logBlockProcessed eth1Blocks[i]
          else:
            raise newException(CorruptDataProvider,
                               "A non-successor Eth1 block reported")
      else:
        # A non-continuous chain detected.
        # This could be the result of a deeper fork that was not reported
        # properly by the web3 provider. Since this should be an extremely
        # rare event we can afford to handle it in a relatively inefficient
        # manner. Let's delete half of our non-finalized chain and try again.
        var blocksToPop = 0
        if m.eth1Chain.blocks.len > 0:
          blocksToPop = max(1, m.eth1Chain.totalNonFinalizedBlocks div 2)
          for i in 0 ..< blocksToPop:
            m.eth1Chain.popBlock()
        warn "Web3 provider responded with a non-continous chain of deposits",
             backtrackedDeposits = blocksToPop
        m.depositQueue.addFirstNoWait blk

proc isRunning*(m: MainchainMonitor): bool =
  not m.runFut.isNil

func `===`(json: JsonNode, boolean: bool): bool =
  json.kind == JBool and json.bval == boolean

proc run(m: MainchainMonitor, delayBeforeStart: Duration) {.async.} =
  if delayBeforeStart != ZeroDuration:
    await sleepAsync(delayBeforeStart)

  let dataProvider = await m.dataProviderFactory.new(m.depositContractAddress)
  if dataProvider == nil:
    error "Failed to initialize Eth1 data provider",
          provider = m.dataProviderFactory.desc
    raise newException(CatchableError, "Failed to initialize Eth1 data provider")

  try:
    info "Starting Eth1 deposit contract monitoring",
      contract = $m.depositContractAddress,
      url = m.dataProviderFactory.desc

    await dataProvider.onBlockHeaders do (blk: Eth1BlockHeader)
                                         {.raises: [Defect], gcsafe.}:
      try:
        m.depositQueue.addLastNoWait(blk)
      except AsyncQueueFullError:
        raiseAssert "The depositQueue has no size limit"
      except Exception:
        # TODO Investigate why this exception is being raised
        raiseAssert "queue.addLastNoWait should not raise exceptions"
    do (err: CatchableError):
      debug "Error while processing Eth1 block headers subscription", err = err.msg

    await m.processDeposits(dataProvider)

  finally:
    await close(dataProvider)

proc safeCancel(fut: var Future[void]) =
  if not fut.isNil and not fut.finished:
    fut.cancel()
    fut = nil

proc stop*(m: MainchainMonitor) =
  safeCancel m.runFut
  safeCancel m.genesisMonitoringFut

proc start(m: MainchainMonitor, delayBeforeStart: Duration) =
  if m.runFut.isNil:
    let runFut = m.run(delayBeforeStart)
    m.runFut = runFut
    runFut.addCallback do (p: pointer):
      if runFut.failed:
        if runFut.error[] of CatchableError:
          if runFut == m.runFut:
            error "Mainchain monitor failure, restarting", err = runFut.error.msg
            m.stop()
            m.start(5.seconds)
        else:
          fatal "Fatal exception reached", err = runFut.error.msg
          quit 1

proc start*(m: MainchainMonitor) {.inline.} =
  m.start(0.seconds)

proc getEth1BlockHash*(url: string, blockId: RtBlockIdentifier): Future[BlockHash] {.async.} =
  let web3 = await newWeb3(url)
  try:
    let blk = await web3.provider.eth_getBlockByNumber(blockId, false)
    return blk.hash
  finally:
    await web3.close()

{.pop.}


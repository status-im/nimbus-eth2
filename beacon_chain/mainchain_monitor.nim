import
  deques, tables, hashes, options, strformat,
  chronos, web3, web3/ethtypes, json, chronicles, eth/async_utils,
  spec/[datatypes, digest, crypto, beaconstate, helpers, signatures],
  merkle_minimal

export
  ethtypes

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

  Eth1Block* = ref object
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
    deposits*: seq[Deposit]
    voteData*: Eth1Data

  Eth1Chain* = object
    blocks: Deque[Eth1Block]
    blocksByHash: Table[BlockHash, Eth1Block]

  MainchainMonitor* = ref object
    depositContractAddress: Address
    startBlock: Option[Eth2Digest]

    dataProviderFactory*: DataProviderFactory

    genesisState: NilableBeaconStateRef
    genesisStateFut: Future[void]

    eth1Chain: Eth1Chain

    depositQueue: AsyncQueue[DepositQueueElem]
    runFut: Future[void]

  Web3EventType = enum
    NewEvent
    RemovedEvent

  DepositQueueElem = (BlockHash, Web3EventType)

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
    subscription: Subscription

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

# TODO Nim's analysis on the lock level of the methods in this
# module seems broken. Investigate and file this as an issue.
{.push warning[LockLevel]: off.}

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(state: BeaconState, slot: Slot): uint64 =
  state.genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time*(state: BeaconState): uint64 =
  let eth1_voting_period_start_slot =
    state.slot - state.slot mod SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(state, eth1_voting_period_start_slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(blk: Eth1Block, period_start: uint64): bool =
  (blk.timestamp + SECONDS_PER_ETH1_BLOCK.uint64 * ETH1_FOLLOW_DISTANCE.uint64 <= period_start) and
  (blk.timestamp + SECONDS_PER_ETH1_BLOCK.uint64 * ETH1_FOLLOW_DISTANCE.uint64 * 2 >= period_start)

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func getDepositsInRange(eth1Chain: Eth1Chain,
                        sinceBlock, latestBlock: Eth1BlockNumber): seq[Deposit] =
  ## Returns all deposits that happened AFTER the block `sinceBlock` (not inclusive).
  ## The deposits in `latestBlock` will be included.
  if latestBlock <= sinceBlock: return

  let firstBlockInCache = eth1Chain.blocks[0].number

  # This function should be used with indices obtained with `eth1Chain.findBlock`.
  # This guarantess that both of these indices will be valid:
  doAssert sinceBlock >= firstBlockInCache and
           int(latestBlock - firstBlockInCache) < eth1Chain.blocks.len
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

func trimHeight(eth1Chain: var Eth1Chain, blockNumber: Eth1BlockNumber) =
  ## Removes all blocks above certain `blockNumber`
  if eth1Chain.blocks.len == 0:
    return

  let newLen = max(0, int(blockNumber - eth1Chain.blocks[0].number + 1))
  for i in newLen ..< eth1Chain.blocks.len:
    let removed = eth1Chain.blocks.popLast
    eth1Chain.blocksByHash.del removed.voteData.block_hash.asBlockHash

template purgeChain*(eth1Chain: var Eth1Chain, blk: Eth1Block) =
  ## This is used when we discover that a previously considered block
  ## is no longer part of the selected chain (due to a reorg). We can
  ## then remove from our chain together with all blocks that follow it.
  trimHeight(eth1Chain, blk.number - 1)

func purgeChain*(eth1Chain: var Eth1Chain, blockHash: BlockHash) =
  let blk = eth1Chain.findBlock(blockHash)
  if blk != nil: eth1Chain.purgeChain(blk)

template purgeDescendants*(eth1CHain: Eth1Chain, blk: Eth1Block) =
  trimHeight(eth1Chain, blk.number)

func addBlock*(eth1Chain: var Eth1Chain, newBlock: Eth1Block) =
  if eth1Chain.blocks.len > 0:
    doAssert eth1Chain.blocks.peekLast.number + 1 == newBlock.number
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

method onDisconnect*(p: DataProviderRef, handler: DisconnectHandler) {.
  base
  gcsafe
  locks: 0
  # raises: []
.} =
  notImplemented

method onDepositEvent*(p: DataProviderRef,
                       startBlock: Eth1BlockNumber,
                       handler: DepositEventHandler): Future[void] {.
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

method hasDepositContract*(p: DataProviderRef,
                           web3Block: BlockObject): Future[bool] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect, CatchableError]
.} =
  notImplemented

method fetchDepositData*(p: DataProviderRef,
                         web3Block: BlockObject): Future[Eth1Block] {.
  base
  gcsafe
  locks: 0
  # raises: [Defect, CatchableError]
.} =
  notImplemented

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
           dataProviderFactory: DataProviderFactory,
           depositContractAddress: string,
           startBlock: Option[Eth2Digest]): T =
  T(depositQueue: newAsyncQueue[DepositQueueElem](),
    dataProviderFactory: dataProviderFactory,
    depositContractAddress: Address.fromHex(depositContractAddress),
    startBlock: startBlock)

proc readJsonDeposits(depositsList: JsonNode): seq[Deposit] =
  if depositsList.kind != JArray:
    raise newException(CatchableError,
      "Web3 provider didn't return a list of deposit events")

  for logEvent in depositsList:
    var logData = strip0xPrefix(logEvent["data"].getStr)
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

    result.add Deposit(
      data: DepositData(
        pubkey: ValidatorPubKey.init(array[48, byte](pubkey)),
        withdrawal_credentials: Eth2Digest(data: array[32, byte](withdrawalCredentials)),
        amount: bytes_to_int(array[8, byte](amount)),
        signature: ValidatorSig.init(array[96, byte](signature))))

proc checkForGenesisEvent(m: MainchainMonitor) =
  if not m.genesisState.isNil:
    return

  let lastBlock = m.eth1Chain.blocks.peekLast
  const totalDepositsNeeded = max(SLOTS_PER_EPOCH,
                                  MIN_GENESIS_ACTIVE_VALIDATOR_COUNT)

  if lastBlock.timestamp.uint64 >= MIN_GENESIS_TIME.uint64 and
     m.eth1Chain.totalDeposits >= totalDepositsNeeded:
    # This block is a genesis candidate
    let startTime = lastBlock.timestamp.uint64
    var genesisDeposits = m.eth1Chain.allDeposits
    attachMerkleProofs genesisDeposits
    var s = initialize_beacon_state_from_eth1(lastBlock.voteData.block_hash,
                                              startTime, genesisDeposits, {})
    if is_valid_genesis_state(s[]):
      # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
      info "Eth2 genesis state detected",
        genesisTime = startTime,
        genesisEth1Block = lastBlock.voteData.block_hash

      s.genesis_time = startTime
      m.genesisState = s

      if not m.genesisStateFut.isNil:
        m.genesisStateFut.complete()
        m.genesisStateFut = nil

proc processDeposits(m: MainchainMonitor,
                     dataProvider: DataProviderRef,
                     startBlkNum: Eth1BlockNumber) {.async.} =
  # ATTENTION!
  # Please note that this code is using a queue to guarantee the
  # strict serial order of processing of deposits. If we had the
  # same code embedded in the deposit contracts events handler,
  # it could easily re-order the steps due to the intruptable
  # interleaved execution of async code.
  while true:
    let (blockHash, eventType) = await m.depositQueue.popFirst()

    if eventType == RemovedEvent:
      info "New Eth1 head selected. Purging history of deposits",
            purgedBlock = $blockHash
      m.eth1Chain.purgeChain(blockHash)
      continue

    let cachedBlock = m.eth1Chain.findBlock(blockHash)
    if cachedBlock == nil:
      try:
        let web3Block = await dataProvider.getBlockByHash(blockHash)
        doAssert Eth1BlockNumber(web3Block.number) > startBlkNum
        let eth1Block = await dataProvider.fetchDepositData(web3Block)

        var cachedParent = m.eth1Chain.findParent(web3Block)
        if cachedParent == nil:
          # We are missing the parent block.
          # This shouldn't be happening if the deposits events are reported in
          # proper order, but nevertheless let's try to repair our chain:
          var chainOfParents = newSeq[Eth1Block]()
          var parentHash = web3Block.parentHash

          var expectedParentBlockNumber = web3Block.number.uint64 - 1
          debug "Eth1 parent block missing. Attempting to request from the network",
                 parentHash = parentHash.toHex, expectedParentBlockNumber

          while true:
            if chainOfParents.len > reorgDepthLimit:
              error "Detected Eth1 re-org exceeded the maximum depth limit",
                    headBlockHash = web3Block.hash.toHex,
                    ourHeadHash = m.eth1Chain.blocks.peekLast.voteData.block_hash
              raise newException(ReorgDepthLimitExceeded, "Reorg depth limit exceeded")

            let parentWeb3Block = await dataProvider.getBlockByHash(parentHash)
            if parentWeb3Block.number.uint64 != expectedParentBlockNumber:
              error "Eth1 data provider supplied invalid parent block",
                    parentBlockNumber = parentWeb3Block.number.uint64,
                    expectedParentBlockNumber, parentHash = parentHash.toHex
              raise newException(CorruptDataProvider,
                                 "Parent block with incorrect number")

            if expectedParentBlockNumber <= startBlkNum or
               startBlkNum == 0 and not await dataProvider.hasDepositContract(parentWeb3Block):
              # We've reached the deposit contract creation
              # No more deposit events are expected
              m.eth1Chain.clear()
              for i in countdown(chainOfParents.len - 1, 0):
                m.eth1Chain.addBlock chainOfParents[i]
              cachedParent = m.eth1Chain.blocks.peekLast
              break

            chainOfParents.add(await dataProvider.fetchDepositData(parentWeb3Block))
            let localParent = m.eth1Chain.findParent(parentWeb3Block)
            if localParent != nil:
              m.eth1Chain.purgeDescendants(localParent)
              for i in countdown(chainOfParents.len - 1, 0):
                m.eth1Chain.addBlock chainOfParents[i]
              cachedParent = m.eth1Chain.blocks.peekLast
              break

            dec expectedParentBlockNumber
            parentHash = parentWeb3Block.parentHash

        m.eth1Chain.purgeDescendants(cachedParent)

        # TODO: We may check that the new deposits produce a merkle
        #       root matching the `deposit_root` value from the block.
        #       Not doing this is equivalent to trusting the Eth1
        #       execution engine and data provider.
        info "Eth1 block processed", eth1data = eth1Block.voteData
        m.eth1Chain.addBlock eth1Block
        m.checkForGenesisEvent()

      except CatchableError as err:
        # Connection problem? Put the unprocessed deposit back to queue.
        # Raising the exception here will lead to a restart of the whole monitor.
        m.depositQueue.addFirstNoWait((blockHash, eventType))
        raise err

proc isRunning*(m: MainchainMonitor): bool =
  not m.runFut.isNil

proc getGenesis*(m: MainchainMonitor): Future[BeaconStateRef] {.async.} =
  if m.genesisState.isNil:
    if m.genesisStateFut.isNil:
      m.genesisStateFut = newFuture[void]("getGenesis")
    await m.genesisStateFut
    m.genesisStateFut = nil

  if m.genesisState != nil:
    return m.genesisState
  else:
    result = new BeaconStateRef # make the compiler happy
    raiseAssert "Unreachable code"

method getBlockByHash*(p: Web3DataProviderRef, hash: BlockHash): Future[BlockObject] =
  return p.web3.provider.eth_getBlockByHash(hash, false)

method close*(p: Web3DataProviderRef): Future[void] {.async, locks: 0.} =
  if p.subscription != nil:
    await p.subscription.unsubscribe()
  await p.web3.close()

method hasDepositContract*(p: Web3DataProviderRef,
                           web3Block: BlockObject): Future[bool] {.async, locks: 0.} =
  result = await p.ns.isDeployed(web3Block.blockId)

method fetchDepositData*(p: Web3DataProviderRef,
                         web3Block: BlockObject): Future[Eth1Block] {.async, locks: 0.} =
  let
    blockHash = web3Block.hash
    blockId = web3Block.blockId
    depositRoot = await p.ns.get_deposit_root.call(blockNumber = web3Block.number.uint64)
    rawCount = await p.ns.get_deposit_count.call(blockNumber = web3Block.number.uint64)
    depositCount = bytes_to_int(array[8, byte](rawCount))
    depositsJson = await p.ns.getJsonLogs(DepositEvent, fromBlock = some(blockId), toBlock = some(blockId))
    deposits = readJsonDeposits(depositsJson)

  return Eth1Block(
    number: Eth1BlockNumber(web3Block.number),
    timestamp: Eth1BlockTimestamp(web3Block.timestamp),
    deposits: deposits,
    voteData: Eth1Data(deposit_root: depositRoot.asEth2Digest,
                       deposit_count: depositCount,
                       block_hash: blockHash.asEth2Digest))

method onDisconnect*(p: Web3DataProviderRef, handler: DisconnectHandler) {.
  gcsafe
  locks: 0
  # raises: []
.} =
  p.web3.onDisconnect = handler

method onDepositEvent*(p: Web3DataProviderRef,
                       startBlock: Eth1BlockNumber,
                       handler: DepositEventHandler): Future[void] {.
  async
  gcsafe
  locks: 0
  # raises: []
.} =
  if p.subscription != nil:
    await p.subscription.unsubscribe()

  p.subscription = await p.ns.subscribe(
    DepositEvent, %*{"fromBlock": &"0x{startBlock:X}"}, handler)

proc getBlockNumber(p: DataProviderRef, hash: BlockHash): Future[Eth1BlockNumber] {.async.} =
  debug "Querying block number", hash = $hash

  try:
    let blk = awaitWithTimeout(p.getBlockByHash(hash), web3Timeouts):
                               return 0
    return Eth1BlockNumber(blk.number)
  except CatchableError as exc:
    notice "Failed to get Eth1 block number from hash",
      hash = $hash, err = exc.msg
    raise

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

proc run(m: MainchainMonitor, delayBeforeStart: Duration) {.async.} =
  if delayBeforeStart != ZeroDuration:
    await sleepAsync(delayBeforeStart)

  let dataProvider = await m.dataProviderFactory.new(m.depositContractAddress)
  if dataProvider == nil:
    error "Failed to initialize Eth1 data provider",
          provider = m.dataProviderFactory.desc
    raise newException(CatchableError, "Failed to initialize Eth1 data provider")

  try:
    let startBlkNum = if m.startBlock.isSome:
      await dataProvider.getBlockNumber(m.startBlock.get.asBlockHash)
    else:
      0

    info "Monitoring eth1 deposits",
      fromBlock = startBlkNum.uint64,
      contract = $m.depositContractAddress,
      url = m.dataProviderFactory.desc

    await dataProvider.onDepositEvent(Eth1BlockNumber(startBlkNum)) do (
        pubkey: Bytes48,
        withdrawalCredentials: Bytes32,
        amount: Bytes8,
        signature: Bytes96, merkleTreeIndex: Bytes8, j: JsonNode)
        {.raises: [Defect], gcsafe.}:
      try:
        let
          blockHash = BlockHash.fromHex(j["blockHash"].getStr())
          eventType = if j.hasKey("removed"): RemovedEvent
                      else: NewEvent

        m.depositQueue.addLastNoWait((blockHash, eventType))

      except CatchableError as exc:
        warn "Received invalid deposit", err = exc.msg, j
      except Exception as err:
        # chronos still raises exceptions which inherit directly from Exception
        if err[] of Defect:
          raise (ref Defect)(err)
        else:
          warn "Received invalid deposit", err = err.msg, j

    await m.processDeposits(dataProvider, startBlkNum)
  finally:
    await close(dataProvider)

proc start(m: MainchainMonitor, delayBeforeStart: Duration) =
  if m.runFut.isNil:
    let runFut = m.run(delayBeforeStart)
    m.runFut = runFut
    runFut.addCallback do (p: pointer):
      if runFut.failed:
        if runFut.error[] of CatchableError:
          if runFut == m.runFut:
            error "Mainchain monitor failure, restarting", err = runFut.error.msg
            m.runFut = nil
            m.start(5.seconds)
        else:
          fatal "Fatal exception reached", err = runFut.error.msg
          quit 1

proc start*(m: MainchainMonitor) {.inline.} =
  m.start(0.seconds)

proc stop*(m: MainchainMonitor) =
  if not m.runFut.isNil:
    m.runFut.cancel()
    m.runFut = nil

proc getLatestEth1BlockHash*(url: string): Future[Eth2Digest] {.async.} =
  let web3 = await newWeb3(url)
  try:
    let blk = await web3.provider.eth_getBlockByNumber("latest", false)
    return Eth2Digest(data: array[32, byte](blk.hash))
  finally:
    await web3.close()

{.pop.}


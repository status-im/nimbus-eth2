import
  std/[deques, tables, hashes, options, strformat, strutils],
  chronos, web3, web3/ethtypes as web3Types, json, chronicles,
  eth/common/eth_types, eth/async_utils,
  spec/[datatypes, digest, crypto, beaconstate, helpers, signatures],
  ssz, beacon_chain_db, network_metadata, merkle_minimal, beacon_node_status

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

  Database* = object

  Eth1Block* = ref object
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
    deposits*: seq[Deposit]
    voteData*: Eth1Data
    knownValidatorsCount*: Option[uint64]

  Eth1Chain* = object
    knownStart: Eth1Data
    knownStartBlockNum: Option[Eth1BlockNumber]

    blocks: Deque[Eth1Block]
    blocksByHash: Table[BlockHash, Eth1Block]

  MainchainMonitor* = ref object
    db: BeaconChainDB
    preset: RuntimePreset

    dataProvider: Web3DataProviderRef
    depositQueue: AsyncQueue[Eth1BlockHeader]
    eth1Chain: Eth1Chain

    genesisState: NilableBeaconStateRef
    genesisStateFut: Future[void]
    genesisMonitoringFut: Future[void]

    runFut: Future[void]

  Web3DataProvider* = object
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
  web3Timeouts = 5.seconds

template depositContractAddress(m: MainchainMonitor): Eth1Address =
  m.dataProvider.ns.contractAddress

template web3Url(m: MainchainMonitor): string =
  m.dataProvider.url

# TODO: Add preset validation
# MIN_GENESIS_ACTIVE_VALIDATOR_COUNT should be larger than SLOTS_PER_EPOCH
#  doAssert SECONDS_PER_ETH1_BLOCK * preset.ETH1_FOLLOW_DISTANCE < GENESIS_DELAY,
#             "Invalid configuration: GENESIS_DELAY is set too low"

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0-rc.0/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(state: BeaconState, slot: Slot): uint64 =
  state.genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0-rc.0/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time*(state: BeaconState): uint64 =
  let eth1_voting_period_start_slot =
    state.slot - state.slot mod SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(state, eth1_voting_period_start_slot)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0-rc.0/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(preset: RuntimePreset, blk: Eth1Block, period_start: uint64): bool =
  (blk.timestamp + SECONDS_PER_ETH1_BLOCK.uint64 * preset.ETH1_FOLLOW_DISTANCE <= period_start) and
  (blk.timestamp + SECONDS_PER_ETH1_BLOCK.uint64 * preset.ETH1_FOLLOW_DISTANCE * 2 >= period_start)

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func shortLog*(b: Eth1Block): string =
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

func latestCandidateBlock(eth1Chain: Eth1Chain, preset: RuntimePreset, periodStart: uint64): Eth1Block =
  for i in countdown(eth1Chain.blocks.len - 1, 0):
    let blk = eth1Chain.blocks[i]
    if is_candidate_block(preset, blk, periodStart):
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
    eth1Chain.blocks.addLast newBlock
    eth1Chain.blocksByHash[newBlock.voteData.block_hash.asBlockHash] = newBlock

proc allDepositsUpTo*(m: MainchainMonitor, totalDeposits: uint64): seq[Deposit] =
  for i in 0'u64 ..< totalDeposits:
    result.add Deposit(data: m.db.deposits.get(i))

func clear*(eth1Chain: var Eth1Chain) =
  eth1Chain = default(Eth1Chain)

template hash*(x: Eth1Block): Hash =
  hash(x.voteData.block_hash.data)

proc close*(p: Web3DataProviderRef): Future[void] {.async, locks: 0.} =
  if p.blockHeadersSubscription != nil:
    await p.blockHeadersSubscription.unsubscribe()

  await p.web3.close()

proc getBlockByHash*(p: Web3DataProviderRef, hash: BlockHash): Future[BlockObject] =
  return p.web3.provider.eth_getBlockByHash(hash, false)

proc getBlockByNumber*(p: Web3DataProviderRef, number: Eth1BlockNumber): Future[BlockObject] =
  return p.web3.provider.eth_getBlockByNumber(&"0x{number:X}", false)

proc getBlockNumber(p: Web3DataProviderRef, hash: BlockHash): Future[Eth1BlockNumber] {.async.} =
  try:
    let blk = awaitWithTimeout(p.getBlockByHash(hash), web3Timeouts):
                               return 0
    return Eth1BlockNumber(blk.number)
  except CatchableError as exc:
    debug "Failed to get Eth1 block number from hash",
          hash = $hash, err = exc.msg
    raise exc

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

proc fetchDepositData*(p: Web3DataProviderRef,
                       fromBlock, toBlock: Eth1BlockNumber): Future[seq[Eth1Block]]
                       {.async, locks: 0.} =
  info "Obtaining deposit log events", fromBlock, toBlock
  return readJsonDeposits(await p.ns.getJsonLogs(DepositEvent,
                                                 fromBlock = some blockId(fromBlock),
                                                 toBlock = some blockId(toBlock)))

proc fetchBlockDetails(p: Web3DataProviderRef, blk: Eth1Block) {.async.} =
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

proc onDisconnect*(p: Web3DataProviderRef, handler: DisconnectHandler) {.
  gcsafe
  locks: 0
  # raises: []
.} =
  p.web3.onDisconnect = handler

proc onBlockHeaders*(p: Web3DataProviderRef,
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

  p.blockHeadersSubscription = await p.web3.subscribeForBlockHeaders(
    blockHeaderHandler, errorHandler)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#get_eth1_data
proc getBlockProposalData*(m: MainchainMonitor,
                           state: BeaconState): (Eth1Data, seq[Deposit]) =
  template voteForNoChange() =
    result[0] = state.eth1_data
    return

  let prevBlock = m.eth1Chain.findBlock(state.eth1_data)
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
    let eth1Block = m.eth1Chain.findBlock(vote)
    if eth1Block != nil and is_candidate_block(m.preset, eth1Block, periodStart):
      otherVotesCountTable.inc eth1Block

  if otherVotesCountTable.len > 0:
    let (winningBlock, votes) = otherVotesCountTable.largest
    result[0] = winningBlock.voteData
    if uint64((votes + 1) * 2) > SLOTS_PER_ETH1_VOTING_PERIOD:
      result[1] = m.eth1Chain.getDepositsInRange(prevBlock.number,
                                                 winningBlock.number)
      # TODO This can be significantly more optimal
      var newAllDeposits = m.allDepositsUpTo(winningBlock.voteData.deposit_count)
      newAllDeposits.add result[1]
      attachMerkleProofs(newAllDeposits)
      for i in 0 ..< result[1].len:
        result[1][i].proof = newAllDeposits[newAllDeposits.len - result[1].len + i].proof
  else:
    let latestBlock = m.eth1Chain.latestCandidateBlock(m.preset, periodStart)
    if latestBlock == nil:
      voteForNoChange()
    else:
      result[0] = latestBlock.voteData
      return

proc init*(T: type MainchainMonitor,
           db: BeaconChainDB,
           preset: RuntimePreset,
           web3Url: string,
           depositContractAddress: Eth1Address,
           depositContractDeployedAt: string): Future[Result[T, string]] {.async.} =
  let web3 = try: await newWeb3(web3Url)
             except CatchableError as err:
               return err "Failed to setup web3 connection"
  let
    ns = web3.contractSender(DepositContract, depositContractAddress)
    dataProvider = Web3DataProviderRef(url: web3Url, web3: web3, ns: ns)

  let
    previouslyPersistedTo = db.getEth1PersistedTo()
    knownStart = previouslyPersistedTo.get:
      # `previouslyPersistedTo` wall null, we start from scratch
      let deployedAtHash = if depositContractDeployedAt.startsWith "0x":
        try: BlockHash.fromHex depositContractDeployedAt
        except ValueError:
          return err "Invalid hex value specified for deposit-contract-block"
      else:
        let blockNum = try: parseBiggestUInt depositContractDeployedAt
                       except ValueError:
                         return err "Invalid nummeric value for deposit-contract-block"
        try:
          let blk = await dataProvider.getBlockByNumber(blockNum)
          blk.hash
        except CatchableError:
          return err("Failed to obtain block hash for block number " & $blockNum)
      Eth1Data(block_hash: deployedAtHash.asEth2Digest, deposit_count: 0)

  return ok T(
    db: db,
    preset: preset,
    dataProvider: dataProvider,
    depositQueue: newAsyncQueue[Eth1BlockHeader](),
    eth1Chain: Eth1Chain(knownStart: knownStart))

proc persistFinalizedBlocks(m: MainchainMonitor, timeNow: float): tuple[
  genesisBlock: Eth1Block,
  previousBlock: Eth1Block
] =
  let followDistanceInSeconds = uint64(SECONDS_PER_ETH1_BLOCK) *
                                m.preset.ETH1_FOLLOW_DISTANCE
  var prevBlock: Eth1Block

  # TODO: The DB operations should be executed as a transaction here
  block: # TODO Begin Transaction
    while m.eth1Chain.blocks.len > 0:
      let blk = m.eth1Chain.blocks.peekFirst
      if float(blk.timestamp + followDistanceInSeconds) > timeNow:
        break

      for deposit in blk.deposits:
        m.db.deposits.add deposit.data

        if verify_deposit_signature(m.preset, deposit.data):
          let pubkey = deposit.data.pubkey
          if pubkey notin m.db.validatorsByKey:
            let idx = m.db.validators.len
            m.db.validators.add ImmutableValidatorData(
              pubkey: pubkey,
              withdrawal_credentials: deposit.data.withdrawal_credentials)
            m.db.validatorsByKey.insert(pubkey, ValidatorIndex idx)

      # TODO The len property is currently stored in memory which
      #      makes it unsafe in the face of failed transactions
      blk.knownValidatorsCount = some m.db.validators.len

      discard m.eth1Chain.blocks.popFirst()
      m.eth1Chain.blocksByHash.del blk.voteData.block_hash.asBlockHash

      let blockGenesisTime = genesis_time_from_eth1_timestamp(m.preset,
                                                              blk.timestamp)
      if blockGenesisTime >= m.preset.MIN_GENESIS_TIME and
         m.db.validators.len >= m.preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
        result = (blk, prevBlock)

      prevBlock = blk

    if prevBlock != nil:
      # TODO commit transaction
      m.db.putEth1PersistedTo prevBlock.voteData
      m.eth1Chain.knownStart = prevBlock.voteData
      notice "Eth1 sync progress",
              blockNumber = prevBlock.number,
              depositsProcessed = prevBlock.voteData.deposit_count

    # TODO Commit

proc createGenesisState(m: MainchainMonitor, eth1Block: Eth1Block): BeaconStateRef =
  notice "Generating genesis state",
    blockNum = eth1Block.number,
    blockHash = eth1Block.voteData.block_hash,
    totalDeposits = eth1Block.voteData.deposit_count,
    activeValidators = eth1Block.knownValidatorsCount.get

  var deposits = m.allDepositsUpTo(eth1Block.voteData.deposit_count)
  attachMerkleProofs deposits

  initialize_beacon_state_from_eth1(m.preset,
                                    eth1Block.voteData.block_hash,
                                    eth1Block.timestamp.uint64,
                                    deposits, {})

proc signalGenesis(m: MainchainMonitor, genesisState: BeaconStateRef) =
  m.genesisState = genesisState

  if not m.genesisStateFut.isNil:
    m.genesisStateFut.complete()
    m.genesisStateFut = nil

proc findGenesisBlockInRange(m: MainchainMonitor,
                             startBlock, endBlock: Eth1Block): Future[Eth1Block]
                            {.async.} =
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
      candidateBlock = await m.dataProvider.getBlockByNumber(candidateNumber)

    var candidateAsEth1Block = Eth1Block(number: candidateBlock.number.uint64,
                                         timestamp: candidateBlock.timestamp.uint64,
                                         voteData: depositData)
    candidateAsEth1Block.voteData.block_hash = candidateBlock.hash.asEth2Digest

    let candidateGenesisTime = genesis_time_from_eth1_timestamp(
      m.preset, candidateBlock.timestamp.uint64)

    notice "Probing possible genesis block",
      `block` = candidateBlock.number.uint64,
      candidateGenesisTime

    if candidateGenesisTime < MIN_GENESIS_TIME:
      startBlock = candidateAsEth1Block
    else:
      endBlock = candidateAsEth1Block

  return endBlock

proc safeCancel(fut: var Future[void]) =
  if not fut.isNil and not fut.finished:
    fut.cancel()
    fut = nil

proc stop*(m: MainchainMonitor) =
  safeCancel m.runFut
  safeCancel m.genesisMonitoringFut

template checkIfShouldStopMainchainMonitor(m: MainchainMonitor) =
  if bnStatus == BeaconNodeStatus.Stopping:
    if not m.genesisStateFut.isNil:
      m.genesisStateFut.complete()
      m.genesisStateFut = nil
    m.stop
    return

proc checkForGenesisLoop(m: MainchainMonitor) {.async.} =
  while true:
    m.checkIfShouldStopMainchainMonitor()

    if not m.genesisState.isNil:
      return

    try:
      # TODO: check for a stale monitor
      let
        now = epochTime()
        (genesisCandidate, genesisParent) = m.persistFinalizedBlocks(now)

      if genesisCandidate != nil:
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
        if genesisParent != nil:
          if genesisParent.knownValidatorsCount.get >= m.preset.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT and
             genesisParent.number - genesisParent.number > 1:
            let genesisBlock = await m.findGenesisBlockInRange(genesisParent, genesisCandidate)
            if genesisBlock.number != genesisCandidate.number:
              m.signalGenesis m.createGenesisState(genesisBlock)
              return

        let candidateState = m.createGenesisState(genesisCandidate)
        m.signalGenesis candidateState
        return

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

    if bnStatus == BeaconNodeStatus.Stopping:
      return new BeaconStateRef # cannot return nil...

  if m.genesisState != nil:
    return m.genesisState
  else:
    result = new BeaconStateRef # make the compiler happy
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
    if blk.knownValidatorsCount.isSome:
      return blk.voteData.deposit_count - blk.knownValidatorsCount.get

  return 0

func maxValidDeposits(eth1Chain: Eth1Chain): uint64 =
  if eth1Chain.blocks.len > 0:
    let lastBlock = eth1Chain.blocks[^1]
    lastBlock.knownValidatorsCount.get(
      lastBlock.voteData.deposit_count - eth1Chain.knownInvalidDepositsCount)
  else:
    0

proc processDeposits(m: MainchainMonitor,
                     dataProvider: Web3DataProviderRef) {.async.} =
  # ATTENTION!
  # Please note that this code is using a queue to guarantee the
  # strict serial order of processing of deposits. If we had the
  # same code embedded in the deposit contracts events handler,
  # it could easily re-order the steps due to the interruptible
  # interleaved execution of async code.
  while true:
    m.checkIfShouldStopMainchainMonitor()

    let now = epochTime()
    discard m.persistFinalizedBlocks(now)

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
        debug "Eth1 block processed",
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

  info "Starting Eth1 deposit contract monitoring",
    contract = $m.depositContractAddress, url = m.web3Url

  await m.dataProvider.onBlockHeaders do (blk: Eth1BlockHeader)
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

  await m.processDeposits(m.dataProvider)

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


import
  chronos, web3, json, chronicles,
  spec/[datatypes, digest, crypto, beaconstate, helpers],
  ./extras

type
  MainchainMonitor* = ref object
    web3Url: string
    depositContractAddress: Address

    genesisState: ref BeaconState
    genesisStateFut: Future[void]

    pendingDeposits: seq[Deposit]
    depositCount: uint64

    curBlock: uint64
    depositQueue: AsyncQueue[QueueElement]

    eth1Block: BlockHash
    eth1Data*: Eth1Data

    runFut: Future[void]

  QueueElement = (BlockHash, DepositData)

proc init*(
    T: type MainchainMonitor,
    web3Url, depositContractAddress: string,
    startBlock: Eth2Digest): T =
  T(
    web3Url: web3Url,
    depositContractAddress: Address.fromHex(depositContractAddress),
    depositQueue: newAsyncQueue[QueueElement](),
    eth1Block: BlockHash(startBlock.data),
  )

contract(DepositContract):
  proc deposit(pubkey: Bytes48, withdrawalCredentials: Bytes32, signature: Bytes96, deposit_data_root: FixedBytes[32])
  proc get_deposit_root(): FixedBytes[32]
  proc get_deposit_count(): Bytes8
  proc DepositEvent(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, index: Bytes8) {.event.}

const MIN_GENESIS_TIME = 0

proc updateEth1Data(m: MainchainMonitor, count: uint64, root: FixedBytes[32]) =
  m.eth1Data.deposit_count = count
  m.eth1Data.deposit_root.data = array[32, byte](root)
  m.eth1Data.block_hash.data = array[32, byte](m.eth1Block)

proc processDeposits(m: MainchainMonitor, web3: Web3) {.async.} =
  while true:
    let (blkHash, data) = await m.depositQueue.popFirst()
    var blk: BlockObject
    var depositCount: uint64
    var depositRoot: FixedBytes[32]
    try:
      blk = await web3.provider.eth_getBlockByHash(blkHash, false)

      let ns = web3.contractSender(DepositContract, m.depositContractAddress)

        # TODO: use m.eth1Block for web3 calls
      let cnt = await ns.get_deposit_count().call()
      depositRoot = await ns.get_deposit_root().call()
      depositCount = bytes_to_int(array[8, byte](cnt))

    except:
      # Connection problem? Put the unprocessed deposit back to queue
      m.depositQueue.addFirstNoWait((blkHash, data))
      raise

    debug "Got deposit from eth1", pubKey = data.pubKey

    let dep = datatypes.Deposit(data: data)
    m.pendingDeposits.add(dep)
    inc m.depositCount
    m.eth1Block = blkHash

    if m.pendingDeposits.len >= SLOTS_PER_EPOCH and
        m.pendingDeposits.len >= MIN_GENESIS_ACTIVE_VALIDATOR_COUNT and
        blk.timestamp.uint64 >= MIN_GENESIS_TIME.uint64:
      # This block is a genesis candidate
      var h: Eth2Digest
      h.data = array[32, byte](blkHash)
      let startTime = blk.timestamp.uint64
      var s = initialize_beacon_state_from_eth1(
        h, startTime, m.pendingDeposits, {skipValidation})

      if is_valid_genesis_state(s):
        # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
        s.genesis_time = startTime

        m.pendingDeposits.setLen(0)
        m.genesisState.new()
        m.genesisState[] = s
        if not m.genesisStateFut.isNil:
          m.genesisStateFut.complete()
          m.genesisStateFut = nil
        # TODO: Set curBlock to blk number

    # TODO: This should be progressing in more independent way.
    #       The Eth1 cross-link can advance even when there are no new deposits.
    m.updateEth1Data(depositCount, depositRoot)

proc isRunning*(m: MainchainMonitor): bool =
  not m.runFut.isNil

proc getGenesis*(m: MainchainMonitor): Future[BeaconState] {.async.} =
  if m.genesisState.isNil:
    if m.genesisStateFut.isNil:
      m.genesisStateFut = newFuture[void]("getGenesis")
    await m.genesisStateFut
    m.genesisStateFut = nil

  doAssert(not m.genesisState.isNil)
  return m.genesisState[]

proc getBlockNumber(web3: Web3, hash: BlockHash): Future[Quantity] {.async.} =
  debug "Querying block number", hash = $hash

  try:
    let blk = await web3.provider.eth_getBlockByHash(hash, false)
    return blk.number
  except CatchableError as exc:
    # TODO this doesn't make too much sense really, but what would be a
    #      reasonable behavior? no idea - the whole algorithm needs to be
    #      rewritten to match the spec.
    notice "Failed to get block number from hash, using current block instead",
      hash = $hash, err = exc.msg
    return await web3.provider.eth_blockNumber()

proc run(m: MainchainMonitor, delayBeforeStart: Duration) {.async.} =
  if delayBeforeStart != ZeroDuration:
    await sleepAsync(delayBeforeStart)

  let web3 = await newWeb3(m.web3Url)
  defer: await web3.close()

  let processFut = m.processDeposits(web3)

  web3.onDisconnect = proc() =
    error "Web3 server disconnected", ulr = m.web3Url
    processFut.cancel()

  # TODO this needs to implement follow distance and the rest of the honest
  #      validator spec..

  let startBlkNum = await web3.getBlockNumber(m.eth1Block)

  notice "Monitoring eth1 deposits",
    fromBlock = startBlkNum.uint64,
    contract = $m.depositContractAddress,
    url = m.web3Url

  let ns = web3.contractSender(DepositContract, m.depositContractAddress)

  let s = await ns.subscribe(DepositEvent, %*{"fromBlock": startBlkNum}) do(
      pubkey: Bytes48,
      withdrawalCredentials: Bytes32,
      amount: Bytes8,
      signature: Bytes96, merkleTreeIndex: Bytes8, j: JsonNode):
    try:
      let blkHash = BlockHash.fromHex(j["blockHash"].getStr())
      let amount = bytes_to_int(array[8, byte](amount))

      m.depositQueue.addLastNoWait((blkHash,
        DepositData(pubkey: ValidatorPubKey.init(array[48, byte](pubkey)),
          withdrawal_credentials: Eth2Digest(data: array[32, byte](withdrawalCredentials)),
          amount: amount,
          signature: ValidatorSig.init(array[96, byte](signature)))))
    except CatchableError as exc:
      warn "Received invalid deposit", err = exc.msg, j

  try:
    await processFut
  finally:
    await s.unsubscribe()

proc start(m: MainchainMonitor, delayBeforeStart: Duration) =
  if m.runFut.isNil:
    let runFut = m.run(delayBeforeStart)
    m.runFut = runFut
    runFut.addCallback() do(p: pointer):
      if runFut.failed and runFut == m.runFut:
        error "Mainchain monitor failure, restarting", err = runFut.error.msg
        m.runFut = nil
        m.start(5.seconds)

proc start*(m: MainchainMonitor) {.inline.} =
  m.start(0.seconds)

proc stop*(m: MainchainMonitor) =
  if not m.runFut.isNil:
    m.runFut.cancel()
    m.runFut = nil

proc getPendingDeposits*(m: MainchainMonitor): seq[Deposit] =
  # This should be a simple accessor for the reference kept above
  m.pendingDeposits

# TODO update after spec change removed Specials
# iterator getValidatorActions*(m: MainchainMonitor,
#                               fromBlock, toBlock: Eth2Digest): SpecialRecord =
#   # It's probably better if this doesn't return a SpecialRecord, but
#   # rather a more readable description of the change that can be packed
#   # in a SpecialRecord by the client of the API.
#   discard

proc getLatestEth1BlockHash*(url: string): Future[Eth2Digest] {.async.} =
  let web3 = await newWeb3(url)
  let blk = await web3.provider.eth_getBlockByNumber("latest", false)
  result.data = array[32, byte](blk.hash)
  await web3.close()

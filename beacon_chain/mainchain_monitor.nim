import
  chronos, web3, json,
  spec/[datatypes, digest, crypto, beaconstate, helpers],
  ./extras

type
  MainchainMonitor* = ref object
    web3Url: string
    web3: Web3
    depositContractAddress: Address

    genesisState: ref BeaconState
    genesisStateFut: Future[void]

    pendingDeposits: seq[Deposit]
    depositCount: uint64

    curBlock: uint64
    depositQueue: AsyncQueue[QueueElement]

    eth1Block: BlockHash
    eth1Data*: Eth1Data

  QueueElement = (BlockHash, DepositData)


proc init*(T: type MainchainMonitor, web3Url, depositContractAddress: string, startBlock: Eth2Digest): T =
  result.new()
  result.web3Url = web3Url
  result.depositContractAddress = Address.fromHex(depositContractAddress)
  result.depositQueue = newAsyncQueue[QueueElement]()
  result.eth1Block = BlockHash(startBlock.data)

contract(DepositContract):
  proc deposit(pubkey: Bytes48, withdrawalCredentials: Bytes32, signature: Bytes96, deposit_data_root: FixedBytes[32])
  proc get_deposit_root(): FixedBytes[32]
  proc get_deposit_count(): Bytes8
  proc DepositEvent(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, index: Bytes8) {.event.}

const MIN_GENESIS_TIME = 0

proc updateEth1Data*(m: MainchainMonitor) {.async.} =
  let ns = m.web3.contractSender(DepositContract, m.depositContractAddress)

  # TODO: use m.eth1Block for web3 calls
  let cnt = await ns.get_deposit_count().call()
  let htr = await ns.get_deposit_root().call()
  m.eth1Data.deposit_count = bytes_to_int(array[8, byte](cnt))
  m.eth1Data.deposit_root.data = array[32, byte](htr)
  m.eth1Data.block_hash.data = array[32, byte](m.eth1Block)

proc processDeposits(m: MainchainMonitor) {.async.} =
  while true:
    let (blkHash, data) = await m.depositQueue.popFirst()

    let blk = await m.web3.provider.eth_getBlockByHash(blkHash, false)
    let dep = datatypes.Deposit(data: data)
    m.pendingDeposits.add(dep)
    inc m.depositCount
    m.eth1Block = blkHash

    if m.pendingDeposits.len >= SLOTS_PER_EPOCH and m.pendingDeposits.len >= MIN_GENESIS_ACTIVE_VALIDATOR_COUNT and blk.timestamp.uint64 >= MIN_GENESIS_TIME.uint64:
      # This block is a genesis candidate
      var h: Eth2Digest
      h.data = array[32, byte](blkHash)
      let startTime = blk.timestamp.uint64
      var s = initialize_beacon_state_from_eth1(h, startTime, m.pendingDeposits, {skipValidation})

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
    await m.updateEth1Data

proc isRunning*(m: MainchainMonitor): bool =
  not m.web3.isNil

proc getGenesis*(m: MainchainMonitor): Future[BeaconState] {.async.} =
  if m.genesisState.isNil:
    if m.genesisStateFut.isNil:
      m.genesisStateFut = newFuture[void]("getGenesis")
    await m.genesisStateFut
    m.genesisStateFut = nil

  doAssert(not m.genesisState.isNil)
  return m.genesisState[]

proc run(m: MainchainMonitor) {.async.} =
  m.web3 = await newWeb3(m.web3Url)
  let ns = m.web3.contractSender(DepositContract, m.depositContractAddress)

  let s = await ns.subscribe(DepositEvent, %*{"fromBlock": m.eth1Block}) do(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, merkleTreeIndex: Bytes8, j: JsonNode):

    let blkHash = BlockHash.fromHex(j["blockHash"].getStr())
    let amount = bytes_to_int(array[8, byte](amount))

    m.depositQueue.addLastNoWait((blkHash,
      DepositData(pubkey: ValidatorPubKey.init(array[48, byte](pubkey)),
        withdrawal_credentials: Eth2Digest(data: array[32, byte](withdrawalCredentials)),
        amount: amount,
        signature: ValidatorSig.init(array[96, byte](signature)))))

  try:
    await m.processDeposits()
  finally:
    await s.unsubscribe()
    # await m.web3.close()
    m.web3 = nil

proc start*(m: MainchainMonitor) =
  asyncCheck m.run()

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

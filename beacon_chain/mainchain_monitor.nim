import
  chronos, web3, json,
  spec/[datatypes, digest, crypto, beaconstate, helpers],
  ./extras

import web3/ethtypes

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

  QueueElement = (BlockHash, DepositData)


proc init*(T: type MainchainMonitor, web3Url, depositContractAddress: string): T =
  result.new()
  result.web3Url = web3Url
  result.depositContractAddress = Address.fromHex(depositContractAddress)
  result.depositQueue = newAsyncQueue[QueueElement]()

contract(DepositContract):
  proc deposit(pubkey: Bytes48, withdrawalCredentials: Bytes32, signature: Bytes96)
  proc get_hash_tree_root(): BlockHash
  proc get_deposit_count(): Bytes8
  proc DepositEvent(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, index: Bytes8) {.event.}

const MIN_GENESIS_TIME = 0

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
      let s = initialize_beacon_state_from_eth1(h, blk.timestamp.uint64, m.pendingDeposits, {skipValidation})

      if is_valid_genesis_state(s):
        m.pendingDeposits.setLen(0)
        m.genesisState.new()
        m.genesisState[] = s
        if not m.genesisStateFut.isNil:
          m.genesisStateFut.complete()
          m.genesisStateFut = nil
        # TODO: Set curBlock to blk number

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

  let s = await ns.subscribe(DepositEvent, %*{"fromBlock": "0x0"}) do(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, merkleTreeIndex: Bytes8, j: JsonNode):

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

proc getBeaconBlockRef*(m: MainchainMonitor): Future[Eth1Data] {.async.} =
  let ns = m.web3.contractSender(DepositContract, m.depositContractAddress)

  # TODO: use m.eth1Block for web3 calls
  let cnt = await ns.get_deposit_count().call()
  let htr = await ns.get_hash_tree_root().call()
  result.deposit_count = bytes_to_int(array[8, byte](cnt))
  result.deposit_root.data = array[32, byte](htr)
  result.block_hash.data = array[32, byte](m.eth1Block)

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

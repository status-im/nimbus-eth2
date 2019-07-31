import conf, chronos, web3, json,
  spec/[bitfield, datatypes, digest, crypto, beaconstate, helpers, validator], extras

contract(DepositContract):
  proc deposit(pubkey: Bytes48, withdrawalCredentials: Bytes32, signature: Bytes96)
  proc DepositEvent(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, index: Bytes8) {.event.}

const MIN_GENESIS_TIME = 0

type
  QueueElement = (BlockHash, DepositData)

  DepositCollector = ref object
    deposits: seq[datatypes.Deposit]
    queue: AsyncQueue[QueueElement]

proc processDeposit(d: DepositCollector, web3: Web3): Future[BeaconState] {.async.} =
  while true:
    let (blkHash, data) = await d.queue.popFirst()

    let blk = await web3.provider.eth_getBlockByHash(blkHash, false)
    let dep = datatypes.Deposit(data: data)
    d.deposits.add(dep)

    if d.deposits.len >= SLOTS_PER_EPOCH and d.deposits.len >= MIN_GENESIS_ACTIVE_VALIDATOR_COUNT and blk.timestamp.uint64 >= MIN_GENESIS_TIME.uint64:
      # This block is a genesis candidate
      var h: Eth2Digest
      h.data = array[32, byte](blkHash)
      let s = initialize_beacon_state_from_eth1(h, blk.timestamp.uint64, d.deposits, {skipValidation})
  
      if is_valid_genesis_state(s):
        return s

proc getGenesisFromEth1*(conf: BeaconNodeConf): Future[BeaconState] {.async.} =
  let web3 = await newWeb3(conf.depositWeb3Url)

  var contractAddress = Address.fromHex(conf.depositContractAddress)
  var defaultAccount: Address
  var ns = web3.contractSender(DepositContract, contractAddress, defaultAccount)

  var deposits = DepositCollector()
  deposits.queue = newAsyncQueue[QueueElement]()

  let s = await ns.subscribe(DepositEvent, %*{"fromBlock": "0x0"}) do(pubkey: Bytes48, withdrawalCredentials: Bytes32, amount: Bytes8, signature: Bytes96, merkleTreeIndex: Bytes8, j: JsonNode):

    let blkHash = BlockHash.fromHex(j["blockHash"].getStr())
    let amount = bytes_to_int(array[8, byte](amount))

    deposits.queue.addLastNoWait((blkHash,
      DepositData(pubkey: ValidatorPubKey.init(array[48, byte](pubkey)),
        withdrawal_credentials: Eth2Digest(data: array[32, byte](withdrawalCredentials)),
        amount: amount,
        signature: ValidatorSig.init(array[96, byte](signature)))))

  let genesisState = await processDeposit(deposits, web3)
  await s.unsubscribe()
  return genesisState


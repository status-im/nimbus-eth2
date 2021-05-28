import
  json, strutils,
  chronos, confutils, chronicles,
  web3, web3/ethtypes as web3Types,
  eth/async_utils,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/spec/helpers

type
  CliFlags = object
    web3Url {.
      name: "web3-url".}: string
    depositContractAddress {.
      name: "deposit-contract".}: string
    startBlock {.
      name: "start-block".}: uint64
    endBlock {.
      name: "start-block".}: Option[uint64]
    outDepositsFile {.
      defaultValue: "deposits.csv"
      name: "out-deposits-file".}: OutFile

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

const
  web3Timeouts = 60.seconds

proc main(flags: CliFlags) {.async.} =
  let web3 = waitFor newWeb3(flags.web3Url)

  let endBlock = if flags.endBlock.isSome:
    flags.endBlock.get
  else:
    awaitWithRetries(web3.provider.eth_getBlockByNumber(blockId"latest", false)).number.uint64

  let depositContract = web3.contractSender(
    DepositContract,
    Eth1Address.fromHex flags.depositContractAddress)

  var depositsFile = open(string flags.outDepositsFile, fmWrite)
  depositsFile.write(
    "block", ",",
    "transaction", ",",
    "depositor", ",",
    "amount", ",",
    "validatorKey", ",",
    "withdrawalCredentials", "\n")

  var currentBlock = flags.startBlock
  while currentBlock < endBlock:
    var
      blocksPerRequest = 5000'u64 # This is roughly a day of Eth1 blocks
      backoff = 100

    while true:
      let maxBlockNumberRequested = min(endBlock, currentBlock + blocksPerRequest - 1)

      template retryOrRaise(err: ref CatchableError) =
        blocksPerRequest = blocksPerRequest div 2
        if blocksPerRequest == 0:
          raise err
        continue

      debug "Obtaining deposit log events",
            fromBlock = currentBlock,
            toBlock = maxBlockNumberRequested,
            backoff

      # Reduce all request rate until we have a more general solution
      # for dealing with Infura's rate limits
      await sleepAsync(milliseconds(backoff))

      let jsonLogsFut = depositContract.getJsonLogs(
        DepositEvent,
        fromBlock = some blockId(currentBlock),
        toBlock = some blockId(maxBlockNumberRequested))

      let depositLogs = try:
        # Downloading large amounts of deposits can be quite slow
        awaitWithTimeout(jsonLogsFut, web3Timeouts):
          retryOrRaise newException(DataProviderTimeout,
            "Request time out while obtaining json logs")
      except CatchableError as err:
        debug "Request for deposit logs failed", err = err.msg
        backoff = (backoff * 3) div 2
        retryOrRaise err

      currentBlock = maxBlockNumberRequested + 1
      for deposit in depositLogs:
        let txNode = deposit{"transactionHash"}
        if txNode != nil and txNode.kind == JString:
          var
            pubkey: Bytes48
            withdrawalCredentials: Bytes32
            amount: Bytes8
            signature: Bytes96
            index: Bytes8

          let blockNum = parseHexInt deposit["blockNumber"].str
          let depositData = strip0xPrefix(deposit["data"].getStr)
          var offset = 0
          offset += decode(depositData, offset, pubkey)
          offset += decode(depositData, offset, withdrawalCredentials)
          offset += decode(depositData, offset, amount)
          offset += decode(depositData, offset, signature)
          offset += decode(depositData, offset, index)

          let txHash = TxHash.fromHex txNode.str
          let tx = awaitWithRetries web3.provider.eth_getTransactionByHash(txHash)

          depositsFile.write(
            $blockNum, ",",
            $txHash, ",",
            $tx.source, ",",
            $bytes_to_uint64(array[8, byte](amount)), ",",
            $pubkey, ",",
            $withdrawalCredentials, "\n")
          depositsFile.flushFile()

  info "Done"

waitFor main(load CliFlags)


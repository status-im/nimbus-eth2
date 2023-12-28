# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[json, options],
  chronos, bearssl/rand, chronicles, confutils, stint, json_serialization,
  web3, eth/keys, eth/p2p/discoveryv5/random2,
  stew/[io2, byteutils], json_rpc/jsonmarshal,
  ../beacon_chain/conf,
  ../beacon_chain/el/el_manager,
  ../beacon_chain/networking/eth2_network,
  ../beacon_chain/spec/eth2_merkleization,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
  ../beacon_chain/validators/keystore_management,
  ./logtrace

from std/os import changeFileExt, fileExists
from std/sequtils import mapIt, toSeq
from std/times import toUnix
from ../beacon_chain/spec/beaconstate import initialize_beacon_state_from_eth1
from ../tests/mocking/mock_genesis import mockEth1BlockHash

# Compiled version of /scripts/depositContract.v.py in this repo
# The contract was compiled in Remix (https://remix.ethereum.org/) with vyper (remote) compiler.
const depositContractCode =
  hexToSeqByte staticRead "../beacon_chain/el/deposit_contract_code.txt"

# For nim-confutils, which uses this kind of init(Type, value) pattern
func init(T: type IpAddress, ip: IpAddress): T = ip

type
  Eth1Address = web3.Address

  StartUpCommand {.pure.} = enum
    generateDeposits
    createTestnet
    createTestnetEnr
    run
    sendDeposits
    analyzeLogs
    deployDepositContract
    sendEth

  CliConfig* = object
    web3Url* {.
      defaultValue: "",
      desc: "URL of the Web3 server to observe Eth1"
      name: "web3-url" }: string

    privateKey* {.
      defaultValue: ""
      desc: "Private key of the controlling account"
      name: "private-key" }: string

    askForKey* {.
      defaultValue: false
      desc: "Ask for an Eth1 private key interactively"
      name: "ask-for-key" }: bool

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    case cmd* {.command.}: StartUpCommand
    of StartUpCommand.deployDepositContract:
      discard

    of StartUpCommand.sendEth:
      toAddress* {.name: "to".}: Eth1Address
      valueEth* {.name: "eth".}: string

    of StartUpCommand.generateDeposits:
      simulationDepositsCount* {.
        desc: "The number of validator keystores to generate"
        name: "count" }: Natural

      outValidatorsDir* {.
        desc: "A directory to store the generated validator keystores"
        name: "out-validators-dir" }: OutDir

      outSecretsDir* {.
        desc: "A directory to store the generated keystore password files"
        name: "out-secrets-dir" }: OutDir

      outDepositsFile* {.
        desc: "A LaunchPad deposits file to write"
        name: "out-deposits-file" }: OutFile

      threshold* {.
        defaultValue: 1
        desc: "Used to generate distributed keys"
        name: "threshold" }: uint32

      remoteValidatorsCount* {.
        defaultValue: 0
        desc: "The number of distributed validators validator"
        name: "remote-validators-count" }: uint32

      remoteSignersUrls* {.
        desc: "URLs of the remote signers"
        name: "remote-signer" }: seq[string]

    of StartUpCommand.createTestnet:
      testnetDepositsFile* {.
        desc: "A LaunchPad deposits file for the genesis state validators"
        name: "deposits-file" .}: InputFile

      totalValidators* {.
        desc: "The number of validator deposits in the newly created chain"
        name: "total-validators" .}: uint64

      bootstrapAddress* {.
        desc: "The public IP address that will be advertised as a bootstrap node for the testnet"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "bootstrap-address" .}: IpAddress

      bootstrapPort* {.
        desc: "The TCP/UDP port that will be used by the bootstrap node"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: $defaultEth2TcpPortDesc
        name: "bootstrap-port" .}: Port

      dataDir* {.
        desc: "Nimbus data directory where the keys of the bootstrap node will be placed"
        name: "data-dir" .}: OutDir

      netKeyFile* {.
        desc: "Source of network (secp256k1) private key file"
        name: "netkey-file" .}: OutFile

      netKeyInsecurePassword* {.
        desc: "Use pre-generated INSECURE password for network private key file"
        defaultValue: false,
        name: "insecure-netkey-password" .}: bool

      genesisTime* {.
        desc: "Unix epoch time of the network genesis"
        name: "genesis-time" .}: Option[uint64]

      genesisOffset* {.
        desc: "Seconds from now to add to genesis time"
        name: "genesis-offset" .}: Option[int]

      executionGenesisBlock* {.
        desc: "The execution genesis block in a merged testnet"
        name: "execution-genesis-block" .}: Option[InputFile]

      capellaForkEpoch* {.
        defaultValue: FAR_FUTURE_EPOCH
        desc: "The epoch of the Capella hard-fork"
        name: "capella-fork-epoch" .}: Epoch

      denebForkEpoch* {.
        defaultValue: FAR_FUTURE_EPOCH
        desc: "The epoch of the Deneb hard-fork"
        name: "deneb-fork-epoch" .}: Epoch

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot"
        name: "output-genesis" .}: OutFile

      outputDepositTreeSnapshot* {.
        desc: "Output file where to write the initial deposit tree snapshot"
        name: "output-deposit-tree-snapshot" .}: OutFile

      outputBootstrapFile* {.
        desc: "Output file with list of bootstrap nodes for the network"
        name: "output-bootstrap-file" .}: OutFile

    of StartUpCommand.createTestnetEnr:
      inputBootstrapEnr* {.
        desc: "Path to the bootstrap ENR"
        name: "bootstrap-enr" .}: InputFile

      enrDataDir* {.
        desc: "Nimbus data directory where the keys of the node will be placed"
        name: "data-dir" .}: OutDir

      enrNetKeyFile* {.
        desc: "Source of network (secp256k1) private key file"
        name: "enr-netkey-file" .}: OutFile

      enrNetKeyInsecurePassword* {.
        desc: "Use pre-generated INSECURE password for network private key file"
        defaultValue: false,
        name: "insecure-netkey-password" .}: bool

      enrAddress* {.
        desc: "The public IP address of that ENR"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "enr-address" .}: IpAddress

      enrPort* {.
        desc: "The TCP/UDP port of that ENR"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: $defaultEth2TcpPortDesc
        name: "enr-port" .}: Port

    of StartUpCommand.sendDeposits:
      depositsFile* {.
        desc: "A LaunchPad deposits file"
        name: "deposits-file" }: InputFile

      depositContractAddress* {.
        desc: "Address of the deposit contract"
        name: "deposit-contract" }: Eth1Address

      minDelay* {.
        defaultValue: 0.0
        desc: "Minimum possible delay between making two deposits (in seconds)"
        name: "min-delay" }: float

      maxDelay* {.
        defaultValue: 0.0
        desc: "Maximum possible delay between making two deposits (in seconds)"
        name: "max-delay" }: float

    of StartUpCommand.run:
      discard

    of StartUpCommand.analyzeLogs:
      logFiles* {.
        desc: "Specifies one or more log files",
        abbr: "f",
        name: "log-file" .}: seq[string]

      simDir* {.
        desc: "Specifies path to eth2_network_simulation directory",
        defaultValue: "",
        name: "sim-dir" .}: string

      netDir* {.
        desc: "Specifies path to network build directory",
        defaultValue: "",
        name: "net-dir" .}: string

      logDir* {.
        desc: "Specifies path with bunch of logs",
        defaultValue: "",
        name: "log-dir" .}: string

      ignoreSerializationErrors* {.
        desc: "Ignore serialization errors while parsing log files",
        defaultValue: true,
        name: "ignore-errors" .}: bool

      dumpSerializationErrors* {.
        desc: "Dump full serialization errors while parsing log files",
        defaultValue: false ,
        name: "dump-errors" .}: bool

      nodes* {.
        desc: "Specifies node names which logs will be used",
        name: "nodes" .}: seq[string]

      allowedLag* {.
        desc: "Allowed latency lag multiplier",
        defaultValue: 2.0,
        name: "lag" .}: float

      constPreset* {.
        desc: "The const preset being used"
        defaultValue: "mainnet"
        name: "const-preset" .}: string

type
  PubKeyBytes = DynamicBytes[48, 48]
  WithdrawalCredentialsBytes = DynamicBytes[32, 32]
  SignatureBytes = DynamicBytes[96, 96]

contract(DepositContract):
  proc deposit(pubkey: PubKeyBytes,
               withdrawalCredentials: WithdrawalCredentialsBytes,
               signature: SignatureBytes,
               deposit_data_root: FixedBytes[32])

template `as`(address: Eth1Address, T: type bellatrix.ExecutionAddress): T =
  T(data: distinctBase(address))

template `as`(address: BlockHash, T: type Eth2Digest): T =
  asEth2Digest(address)

func getOrDefault[T](x: Option[T]): T =
  if x.isSome:
    x.get
  else:
    default T

func `as`(blk: BlockObject, T: type bellatrix.ExecutionPayloadHeader): T =
  T(parent_hash: blk.parentHash as Eth2Digest,
    fee_recipient: blk.miner as ExecutionAddress,
    state_root: blk.stateRoot as Eth2Digest,
    receipts_root: blk.receiptsRoot as Eth2Digest,
    logs_bloom: BloomLogs(data: distinctBase(blk.logsBloom)),
    prev_randao: Eth2Digest(data: blk.difficulty.toByteArrayBE), # Is BE correct here?
    block_number: uint64 blk.number,
    gas_limit: uint64 blk.gasLimit,
    gas_used: uint64 blk.gasUsed,
    timestamp: uint64 blk.timestamp,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(blk.extraData.bytes),
    base_fee_per_gas: blk.baseFeePerGas.getOrDefault(),
    block_hash: blk.hash as Eth2Digest,
    transactions_root: blk.transactionsRoot as Eth2Digest)

func `as`(blk: BlockObject, T: type capella.ExecutionPayloadHeader): T =
  T(parent_hash: blk.parentHash as Eth2Digest,
    fee_recipient: blk.miner as ExecutionAddress,
    state_root: blk.stateRoot as Eth2Digest,
    receipts_root: blk.receiptsRoot as Eth2Digest,
    logs_bloom: BloomLogs(data: distinctBase(blk.logsBloom)),
    prev_randao: Eth2Digest(data: blk.difficulty.toByteArrayBE),
    block_number: uint64 blk.number,
    gas_limit: uint64 blk.gasLimit,
    gas_used: uint64 blk.gasUsed,
    timestamp: uint64 blk.timestamp,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(blk.extraData.bytes),
    base_fee_per_gas: blk.baseFeePerGas.getOrDefault(),
    block_hash: blk.hash as Eth2Digest,
    transactions_root: blk.transactionsRoot as Eth2Digest,
    withdrawals_root: blk.withdrawalsRoot.getOrDefault() as Eth2Digest)

func `as`(blk: BlockObject, T: type deneb.ExecutionPayloadHeader): T =
  T(parent_hash: blk.parentHash as Eth2Digest,
    fee_recipient: blk.miner as ExecutionAddress,
    state_root: blk.stateRoot as Eth2Digest,
    receipts_root: blk.receiptsRoot as Eth2Digest,
    logs_bloom: BloomLogs(data: distinctBase(blk.logsBloom)),
    prev_randao: Eth2Digest(data: blk.difficulty.toByteArrayBE),
    block_number: uint64 blk.number,
    gas_limit: uint64 blk.gasLimit,
    gas_used: uint64 blk.gasUsed,
    timestamp: uint64 blk.timestamp,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(blk.extraData.bytes),
    base_fee_per_gas: blk.baseFeePerGas.getOrDefault(),
    block_hash: blk.hash as Eth2Digest,
    transactions_root: blk.transactionsRoot as Eth2Digest,
    withdrawals_root: blk.withdrawalsRoot.getOrDefault() as Eth2Digest,
    blob_gas_used: uint64 blk.blobGasUsed.getOrDefault(),
    excess_blob_gas: uint64 blk.excessBlobGas.getOrDefault())

func createDepositTreeSnapshot(deposits: seq[DepositData],
                               blockHash: Eth2Digest,
                               blockHeight: uint64): DepositTreeSnapshot =
  var merkleizer = DepositsMerkleizer.init()
  for i, deposit in deposits:
    let htr = hash_tree_root(deposit)
    merkleizer.addChunk(htr.data)

  DepositTreeSnapshot(
    eth1Block: blockHash,
    depositContractState: merkleizer.toDepositContractState,
    blockHeight: blockHeight)

proc createEnr(rng: var HmacDrbgContext,
               dataDir: string,
               netKeyFile: string,
               netKeyInsecurePassword: bool,
               cfg: RuntimeConfig,
               forkId: seq[byte],
               address: IpAddress,
               port: Port): enr.Record
               {.raises: [CatchableError].} =
  type MetaData = altair.MetaData
  let
    networkKeys = rng.getPersistentNetKeys(
      dataDir, netKeyFile, netKeyInsecurePassword, allowLoadExisting = false)

    netMetadata = MetaData()
    bootstrapEnr = enr.Record.init(
      1, # sequence number
      networkKeys.seckey.asEthKey,
      some(address),
      some(port),
      some(port),
      [
        toFieldPair(enrForkIdField, forkId),
        toFieldPair(enrAttestationSubnetsField, SSZ.encode(netMetadata.attnets))
      ])
  bootstrapEnr.tryGet()

proc doCreateTestnetEnr(config: CliConfig,
                        rng: var HmacDrbgContext)
                       {.raises: [CatchableError].} =
  let
    cfg = getRuntimeConfig(config.eth2Network)
    bootstrapEnr = parseBootstrapAddress(toSeq(lines(string config.inputBootstrapEnr))[0]).get()
    forkIdField = bootstrapEnr.tryGet(enrForkIdField, seq[byte]).get()
    enr =
      createEnr(rng, string config.enrDataDir, string config.enrNetKeyFile,
        config.enrNetKeyInsecurePassword, cfg, forkIdField,
        config.enrAddress, config.enrPort)
  stderr.writeLine(enr.toURI)

proc doCreateTestnet*(config: CliConfig,
                      rng: var HmacDrbgContext)
                     {.raises: [CatchableError].} =
  let launchPadDeposits = try:
    Json.loadFile(config.testnetDepositsFile.string, seq[LaunchPadDeposit])
  except SerializationError as err:
    error "Invalid LaunchPad deposits file",
          err = formatMsg(err, config.testnetDepositsFile.string)
    quit 1

  var deposits: seq[DepositData]
  for i in 0 ..< launchPadDeposits.len:
    deposits.add(launchPadDeposits[i] as DepositData)

  let
    startTime = if config.genesisTime.isSome:
      config.genesisTime.get
    else:
      uint64(times.toUnix(times.getTime()) + config.genesisOffset.get(0))
    outGenesis = config.outputGenesis.string
    eth1Hash = mockEth1BlockHash # TODO: Can we set a more appropriate value?
    cfg = getRuntimeConfig(config.eth2Network)

  # This is intentionally left default initialized, when the user doesn't
  # provide an execution genesis block. The generated genesis state will
  # then be considered non-finalized merged state according to the spec.
  var genesisBlock = BlockObject()

  if config.executionGenesisBlock.isSome:
    logScope:
      path = config.executionGenesisBlock.get.string

    if not fileExists(config.executionGenesisBlock.get.string):
      error "The specified execution genesis block file doesn't exist"
      quit 1

    let genesisBlockContents = readAllChars(config.executionGenesisBlock.get.string)
    if genesisBlockContents.isErr:
      error "Failed to read the specified execution genesis block file",
            err = genesisBlockContents.error
      quit 1

    try:
      let blockAsJson = try:
        parseJson genesisBlockContents.get
      except CatchableError as err:
        error "Failed to parse the genesis block json", err = err.msg
        quit 1
      except:
        # TODO The Nim json library should not raise bare exceptions
        raiseAssert "The Nim json library raise a bare exception"
      fromJson(blockAsJson, "", genesisBlock)
    except CatchableError as err:
      error "Failed to load the genesis block from json",
            err = err.msg
      quit 1

  template createAndSaveState(genesisExecutionPayloadHeader: auto): Eth2Digest =
    var initialState = newClone(initialize_beacon_state_from_eth1(
        cfg, eth1Hash, startTime, deposits, genesisExecutionPayloadHeader,
        {skipBlsValidation}))
    # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
    initialState.genesis_time = startTime

    doAssert initialState.validators.len > 0

    # let outGenesisExt = splitFile(outGenesis).ext
    #if cmpIgnoreCase(outGenesisExt, ".json") == 0:

    # let outGenesisJson = outGenesis & ".json"
    # RestJson.saveFile(outGenesisJson, initialState, pretty = true)
    # info "JSON genesis file written", path = outGenesisJson

    let outSszGenesis = outGenesis.changeFileExt "ssz"
    SSZ.saveFile(outSszGenesis, initialState[])
    info "SSZ genesis file written",
          path = outSszGenesis, fork = kind(typeof initialState[])

    SSZ.saveFile(
      config.outputDepositTreeSnapshot.string,
      createDepositTreeSnapshot(
        deposits,
        genesisExecutionPayloadHeader.block_hash,
        genesisExecutionPayloadHeader.block_number))

    initialState[].genesis_validators_root

  let genesisValidatorsRoot =
    if config.denebForkEpoch == 0:
      createAndSaveState(genesisBlock as deneb.ExecutionPayloadHeader)
    elif config.capellaForkEpoch == 0:
      createAndSaveState(genesisBlock as capella.ExecutionPayloadHeader)
    else:
      createAndSaveState(genesisBlock as bellatrix.ExecutionPayloadHeader)

  let bootstrapFile = string config.outputBootstrapFile
  if bootstrapFile.len > 0:
    let
      forkId = getENRForkID(
        cfg,
        Epoch(0),
        genesisValidatorsRoot)
      enr =
        createEnr(rng, string config.dataDir, string config.netKeyFile,
          config.netKeyInsecurePassword, cfg, SSZ.encode(forkId),
          config.bootstrapAddress, config.bootstrapPort)
    writeFile(bootstrapFile, enr.toURI)
    echo "Wrote ", bootstrapFile

proc deployContract(web3: Web3, code: seq[byte]): Future[ReceiptObject] {.async.} =
  let tr = EthSend(
    `from`: web3.defaultAccount,
    data: code,
    gas: Quantity(3000000).some,
    gasPrice: Quantity(1).some)

  let r = await web3.send(tr)
  result = await web3.getMinedTransactionReceipt(r)

proc sendEth(web3: Web3, to: Eth1Address, valueEth: int): Future[TxHash] =
  let tr = EthSend(
    `from`: web3.defaultAccount,
    gas: Quantity(3000000).some,
    gasPrice: Quantity(1).some,
    value: some(valueEth.u256 * 1000000000000000000.u256),
    to: some(to))
  web3.send(tr)

type
  DelayGenerator = proc(): chronos.Duration {.gcsafe, raises: [].}

func ethToWei(eth: UInt256): UInt256 =
  eth * 1000000000000000000.u256

proc initWeb3(web3Url, privateKey: string): Future[Web3] {.async.} =
  result = await newWeb3(web3Url)
  if privateKey.len != 0:
    result.privateKey = some(keys.PrivateKey.fromHex(privateKey)[])
  else:
    let accounts = await result.provider.eth_accounts()
    doAssert(accounts.len > 0)
    result.defaultAccount = accounts[0]

# TODO: async functions should note take `seq` inputs because
#       this leads to full copies.
proc sendDeposits(deposits: seq[LaunchPadDeposit],
                  web3Url, privateKey: string,
                  depositContractAddress: Eth1Address,
                  delayGenerator: DelayGenerator = nil) {.async.} =
  notice "Sending deposits",
    web3 = web3Url,
    depositContract = depositContractAddress

  var web3 = await initWeb3(web3Url, privateKey)
  let gasPrice = int(await web3.provider.eth_gasPrice()) * 2
  let depositContract = web3.contractSender(DepositContract,
                                            Eth1Address depositContractAddress)
  for i in 4200 ..< deposits.len:
    let dp = deposits[i] as DepositData

    while true:
      try:
        let tx = depositContract.deposit(
          PubKeyBytes(@(dp.pubkey.toRaw())),
          WithdrawalCredentialsBytes(@(dp.withdrawal_credentials.data)),
          SignatureBytes(@(dp.signature.toRaw())),
          FixedBytes[32](hash_tree_root(dp).data))

        let status = await tx.send(value = 32.u256.ethToWei, gasPrice = gasPrice)

        info "Deposit sent", tx = $status

        if delayGenerator != nil:
          await sleepAsync(delayGenerator())

        break
      except CatchableError:
        await sleepAsync(chronos.seconds 60)
        web3 = await initWeb3(web3Url, privateKey)

{.pop.} # TODO confutils.nim(775, 17) Error: can raise an unlisted exception: ref IOError

when isMainModule:
  import
    web3/confutils_defs,
    ../beacon_chain/filepath

  from std/terminal import readPasswordFromStdin

  proc main() {.async.} =
    var conf = try: CliConfig.load()
    except CatchableError as exc:
      raise exc
    except Exception as exc: # TODO fix confutils
      raiseAssert exc.msg

    let rng = HmacDrbgContext.new()

    if conf.cmd == StartUpCommand.generateDeposits:
      let
        mnemonic = generateMnemonic(rng[])
        seed = getSeed(mnemonic, KeystorePass.init "")
        cfg = getRuntimeConfig(conf.eth2Network)

      if (let res = secureCreatePath(string conf.outValidatorsDir); res.isErr):
        warn "Could not create validators folder",
          path = string conf.outValidatorsDir, err = ioErrorMsg(res.error)

      if (let res = secureCreatePath(string conf.outSecretsDir); res.isErr):
        warn "Could not create secrets folder",
          path = string conf.outSecretsDir, err = ioErrorMsg(res.error)

      let deposits = generateDeposits(
        cfg,
        rng[],
        seed,
        0, conf.simulationDepositsCount,
        string conf.outValidatorsDir,
        string conf.outSecretsDir,
        conf.remoteSignersUrls,
        conf.threshold,
        conf.remoteValidatorsCount,
        KeystoreMode.Fast)

      if deposits.isErr:
        fatal "Failed to generate deposits", err = deposits.error
        quit 1

      let launchPadDeposits =
        mapIt(deposits.value, LaunchPadDeposit.init(cfg, it))

      Json.saveFile(string conf.outDepositsFile, launchPadDeposits)
      notice "Deposit data written", filename = conf.outDepositsFile
      quit 0

    var deposits: seq[LaunchPadDeposit]
    if conf.cmd == StartUpCommand.sendDeposits:
      deposits = Json.loadFile(string conf.depositsFile, seq[LaunchPadDeposit])

    if conf.askForKey:
      var
        privateKey: string  # TODO consider using a SecretString type
        reasonForKey = ""

      if conf.cmd == StartUpCommand.sendDeposits:
        let
          depositsWord = if deposits.len > 1: "deposits" else: "deposit"
          totalEthNeeded = 32 * deposits.len
        reasonForKey = " in order to make your $1 (you'll need access to $2 ETH)" %
                       [depositsWord, $totalEthNeeded]

      echo "Please enter your Goerli Eth1 private key in hex form (e.g. 0x1a2...f3c)" &
            reasonForKey

      if not readPasswordFromStdin("> ", privateKey):
        error "Failed to read an Eth1 private key from standard input"

      if privateKey.len > 0:
        conf.privateKey = privateKey.string

    case conf.cmd
    of StartUpCommand.createTestnet:
      let rng = HmacDrbgContext.new()
      doCreateTestnet(conf, rng[])

    of StartUpCommand.createTestnetEnr:
      let rng = HmacDrbgContext.new()
      doCreateTestnetEnr(conf, rng[])

    of StartUpCommand.deployDepositContract:
      let web3 = await initWeb3(conf.web3Url, conf.privateKey)
      let receipt = await web3.deployContract(depositContractCode)
      echo receipt.contractAddress.get, ";", receipt.blockHash

    of StartUpCommand.sendEth:
      let web3 = await initWeb3(conf.web3Url, conf.privateKey)
      echo await sendEth(web3, conf.toAddress, conf.valueEth.parseInt)

    of StartUpCommand.sendDeposits:
      var delayGenerator: DelayGenerator
      if not (conf.maxDelay > 0.0):
        conf.maxDelay = conf.minDelay
      elif conf.minDelay > conf.maxDelay:
        echo "The minimum delay should not be larger than the maximum delay"
        quit 1

      if conf.maxDelay > 0.0:
        delayGenerator = proc (): chronos.Duration =
          let
            minDelay = (conf.minDelay*1000).int64
            maxDelay = (conf.maxDelay*1000).int64
          chronos.milliseconds (rng[].rand(maxDelay - minDelay) + minDelay)

      await sendDeposits(deposits, conf.web3Url, conf.privateKey,
                         conf.depositContractAddress, delayGenerator)

    of StartUpCommand.run:
      discard

    of StartUpCommand.analyzeLogs:
      try:
        logtrace.run(LogTraceConf(
          cmd: logtrace.StartUpCommand.localSimChecks,
          logFiles: conf.logFiles,
          simDir: conf.simDir,
          netDir: conf.netDir,
          logDir: conf.logDir,
          ignoreSerializationErrors: conf.ignoreSerializationErrors,
          dumpSerializationErrors: conf.dumpSerializationErrors,
          nodes: conf.nodes,
          allowedLag: conf.allowedLag,
          constPreset: conf.constPreset
        ))
      except CatchableError as err:
        fatal "Unexpected error in logtrace", err = err.msg
      except Exception as exc:
        # TODO: Investigate where is this coming from?
        fatal "Unexpected exception in logtrace", err = exc.msg

    of StartUpCommand.generateDeposits:
      # This is handled above before the case statement
      discard

  waitFor main()

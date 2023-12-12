# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  os, sequtils, strutils, options, json, terminal,
  chronos, chronicles, confutils, stint, json_serialization,
  ../filepath,
  ../networking/network_metadata,
  web3, web3/confutils_defs, eth/keys, eth/p2p/discoveryv5/random2,
  stew/[io2, byteutils],
  ../spec/eth2_merkleization,
  ../spec/datatypes/base,
  ../validators/keystore_management

# Compiled version of /scripts/depositContract.v.py in this repo
# The contract was compiled in Remix (https://remix.ethereum.org/) with vyper (remote) compiler.
const contractCode =
  hexToSeqByte staticRead "deposit_contract_code.txt"

type
  Eth1Address = web3.Address

  StartUpCommand {.pure.} = enum
    deploy
    sendEth
    generateSimulationDeposits
    sendDeposits

  CliConfig = object
    web3Url* {.
      defaultValue: "",
      desc: "URL of the Web3 server to observe Eth1"
      name: "web3-url" }: string

    privateKey* {.
      defaultValue: ""
      desc: "Private key of the controlling account"
      name: "private-key" }: string

    askForKey {.
      defaultValue: false
      desc: "Ask for an Eth1 private key interactively"
      name: "ask-for-key" }: bool

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    case cmd* {.command.}: StartUpCommand
    of deploy:
      discard

    of sendEth:
      toAddress {.name: "to".}: Eth1Address
      valueEth {.name: "eth".}: string

    of generateSimulationDeposits:
      simulationDepositsCount {.
        desc: "The number of validator keystores to generate"
        name: "count" }: Natural

      outValidatorsDir {.
        desc: "A directory to store the generated validator keystores"
        name: "out-validators-dir" }: OutDir

      outSecretsDir {.
        desc: "A directory to store the generated keystore password files"
        name: "out-secrets-dir" }: OutDir

      outDepositsFile {.
        desc: "A LaunchPad deposits file to write"
        name: "out-deposits-file" }: OutFile

      threshold {.
        defaultValue: 1
        desc: "Used to generate distributed keys"
        name: "threshold" }: uint32

      remoteValidatorsCount {.
        defaultValue: 0
        desc: "The number of distributed validators validator"
        name: "remote-validators-count" }: uint32

      remoteSignersUrls {.
        desc: "URLs of the remote signers"
        name: "remote-signer" }: seq[string]

    of sendDeposits:
      depositsFile {.
        desc: "A LaunchPad deposits file"
        name: "deposits-file" }: InputFile

      depositContractAddress {.
        desc: "Address of the deposit contract"
        name: "deposit-contract" }: Eth1Address

      minDelay {.
        defaultValue: 0.0
        desc: "Minimum possible delay between making two deposits (in seconds)"
        name: "min-delay" }: float

      maxDelay {.
        defaultValue: 0.0
        desc: "Maximum possible delay between making two deposits (in seconds)"
        name: "max-delay" }: float

type
  PubKeyBytes = DynamicBytes[48, 48]
  WithdrawalCredentialsBytes = DynamicBytes[32, 32]
  SignatureBytes = DynamicBytes[96, 96]

contract(DepositContract):
  proc deposit(pubkey: PubKeyBytes,
               withdrawalCredentials: WithdrawalCredentialsBytes,
               signature: SignatureBytes,
               deposit_data_root: FixedBytes[32])

proc deployContract*(web3: Web3, code: seq[byte]): Future[ReceiptObject] {.async.} =
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
  DelayGenerator* = proc(): chronos.Duration {.gcsafe, raises: [].}

proc ethToWei(eth: UInt256): UInt256 =
  eth * 1000000000000000000.u256

proc initWeb3(web3Url, privateKey: string): Future[Web3] {.async.} =
  result = await newWeb3(web3Url)
  if privateKey.len != 0:
    result.privateKey = some(PrivateKey.fromHex(privateKey)[])
  else:
    let accounts = await result.provider.eth_accounts()
    doAssert(accounts.len > 0)
    result.defaultAccount = accounts[0]

# TODO: async functions should note take `seq` inputs because
#       this leads to full copies.
proc sendDeposits*(deposits: seq[LaunchPadDeposit],
                   web3Url, privateKey: string,
                   depositContractAddress: Eth1Address,
                   delayGenerator: DelayGenerator = nil) {.async.} =
  notice "Sending deposits",
    web3 = web3Url,
    depositContract = depositContractAddress

  var web3 = await initWeb3(web3Url, privateKey)
  let gasPrice = int(await web3.provider.eth_gasPrice()) * 2
  let depositContract = web3.contractSender(DepositContract,
                                            Address depositContractAddress)
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
        await sleepAsync(60.seconds)
        web3 = await initWeb3(web3Url, privateKey)

{.pop.} # TODO confutils.nim(775, 17) Error: can raise an unlisted exception: ref IOError
proc main() {.async.} =
  var conf = try: CliConfig.load()
  except CatchableError as exc:
    raise exc
  except Exception as exc: # TODO fix confutils
    raiseAssert exc.msg

  let rng = HmacDrbgContext.new()

  if conf.cmd == StartUpCommand.generateSimulationDeposits:
    let
      mnemonic = generateMnemonic(rng[])
      seed = getSeed(mnemonic, KeystorePass.init "")
      cfg = getRuntimeConfig(conf.eth2Network)
      threshold = if conf.remoteSignersUrls.len > 0: conf.threshold
                  else: 0

    if conf.remoteValidatorsCount > 0 and
       conf.remoteSignersUrls.len == 0:
      fatal "Please specify at least one remote signer URL"
      quit 1

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
      threshold,
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

  let web3 = await initWeb3(conf.web3Url, conf.privateKey)

  case conf.cmd
  of StartUpCommand.deploy:
    let receipt = await web3.deployContract(contractCode)
    echo receipt.contractAddress.get, ";", receipt.blockHash

  of StartUpCommand.sendEth:
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

  of StartUpCommand.generateSimulationDeposits:
    # This is handled above before the case statement
    discard

when isMainModule: waitFor main()

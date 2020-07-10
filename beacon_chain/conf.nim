{.push raises: [Defect].}

import
  os, options,
  chronicles, chronicles/options as chroniclesOptions,
  confutils, confutils/defs, confutils/std/net,
  json_serialization, web3/ethtypes,
  network_metadata, spec/[crypto, keystore, digest]

export
  defs, enabledLogLevel, parseCmdArg, completeCmdArg,
  network_metadata

type
  ValidatorKeyPath* = TypedInputFile[ValidatorPrivKey, Txt, "privkey"]

  BNStartUpCmd* = enum
    noCommand
    createTestnet
    deposits
    wallets

  WalletsCmd* {.pure.} = enum
    create  = "Creates a new EIP-2386 wallet"
    restore = "Restores a wallet from cold storage"
    list    = "Lists details about all wallets"

  DepositsCmd* {.pure.} = enum
    create = "Creates validator keystores and deposits"
    send   = "Sends prepared deposits to the validator deposit contract"
    status = "Displays status information about all deposits"

  VCStartUpCmd* = enum
    VCNoCommand

  Web3Url* = distinct string

  BeaconNodeConf* = object
    logLevel* {.
      defaultValue: "DEBUG"
      desc: "Sets the log level"
      name: "log-level" }: string

    eth2Network* {.
      desc: "The Eth2 network to join"
      name: "network" }: Option[string]

    dataDir* {.
      defaultValue: config.defaultDataDir()
      desc: "The directory where nimbus will store all blockchain data"
      abbr: "d"
      name: "data-dir" }: OutDir

    web3Url* {.
      defaultValue: ""
      desc: "URL of the Web3 server to observe Eth1"
      name: "web3-url" }: string

    depositContractAddress* {.
      desc: "Address of the deposit contract"
      name: "deposit-contract" }: Option[Eth1Address]

    depositContractDeployedAt* {.
      desc: "The Eth1 block hash where the deposit contract has been deployed"
      name: "deposit-contract-block" }: Option[Eth1BlockHash]

    nonInteractive* {.
      desc: "Do not display interative prompts. Quit on missing configuration"
      name: "non-interactive" }: bool

    case cmd* {.
      command
      defaultValue: noCommand }: BNStartUpCmd

    of noCommand:
      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network"
        abbr: "b"
        name: "bootstrap-node" }: seq[string]

      bootstrapNodesFile* {.
        defaultValue: ""
        desc: "Specifies a line-delimited file of bootstrap Ethereum network addresses"
        name: "bootstrap-file" }: InputFile

      libp2pAddress* {.
        defaultValue: defaultListenAddress(config)
        desc: "Listening address for the Ethereum LibP2P traffic"
        name: "listen-address" }: ValidIpAddress

      tcpPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "Listening TCP port for Ethereum LibP2P traffic"
        name: "tcp-port" }: Port

      udpPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "Listening UDP port for node discovery"
        name: "udp-port" }: Port

      maxPeers* {.
        defaultValue: 79 # The Wall gets released
        desc: "The maximum number of peers to connect to"
        name: "max-peers" }: int

      nat* {.
        desc: "Specify method to use for determining public address. " &
              "Must be one of: any, none, upnp, pmp, extip:<IP>"
        defaultValue: "any" }: string

      validators* {.
        required
        desc: "Path to a validator keystore"
        abbr: "v"
        name: "validator" }: seq[ValidatorKeyPath]

      validatorsDirFlag* {.
        desc: "A directory containing validator keystores"
        name: "validators-dir" }: Option[InputDir]

      secretsDirFlag* {.
        desc: "A directory containing validator keystore passwords"
        name: "secrets-dir" }: Option[InputDir]

      walletsDirFlag* {.
        desc: "A directory containing wallet files"
        name: "wallets-dir" }: Option[InputDir]

      stateSnapshot* {.
        desc: "SSZ file specifying a recent state snapshot"
        abbr: "s"
        name: "state-snapshot" }: Option[InputFile]

      stateSnapshotContents* {.hidden.}: ref string
        # This is ref so we can mutate it (to erase it) after the initial loading.

      runtimePreset* {.hidden.}: RuntimePreset

      nodeName* {.
        defaultValue: ""
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be selected for each --data-dir folder"
        name: "node-name" }: string

      verifyFinalization* {.
        defaultValue: false
        desc: "Specify whether to verify finalization occurs on schedule, for testing"
        name: "verify-finalization" }: bool

      stopAtEpoch* {.
        defaultValue: 0
        desc: "A positive epoch selects the epoch at which to stop"
        name: "stop-at-epoch" }: uint64

      metricsEnabled* {.
        defaultValue: false
        desc: "Enable the metrics server"
        name: "metrics" }: bool

      metricsAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Listening address of the metrics server"
        name: "metrics-address" }: ValidIpAddress

      metricsPort* {.
        defaultValue: 8008
        desc: "Listening HTTP port of the metrics server"
        name: "metrics-port" }: Port

      statusBarEnabled* {.
        defaultValue: true
        desc: "Display a status bar at the bottom of the terminal screen"
        name: "status-bar" }: bool

      statusBarContents* {.
        defaultValue: "peers: $connected_peers;" &
                      "finalized: $finalized_root:$finalized_epoch;" &
                      "head: $head_root:$head_epoch:$head_epoch_slot;" &
                      "time: $epoch:$epoch_slot ($slot)|" &
                      "ETH: $attached_validators_balance"
        desc: "Textual template for the contents of the status bar"
        name: "status-bar-contents" }: string

      rpcEnabled* {.
        defaultValue: false
        desc: "Enable the JSON-RPC server"
        name: "rpc" }: bool

      rpcPort* {.
        defaultValue: defaultEth2RpcPort
        desc: "HTTP port for the JSON-RPC service"
        name: "rpc-port" }: Port

      rpcAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Listening address of the RPC server"
        name: "rpc-address" }: ValidIpAddress

      dumpEnabled* {.
        defaultValue: false
        desc: "Write SSZ dumps of blocks, attestations and states to data dir"
        name: "dump" }: bool

    of createTestnet:
      testnetDepositsDir* {.
        desc: "Directory containing validator keystores"
        name: "validators-dir" }: InputDir

      totalValidators* {.
        desc: "The number of validator deposits in the newly created chain"
        name: "total-validators" }: uint64

      firstValidator* {.
        defaultValue: 0
        desc: "Index of first validator to add to validator list"
        name: "first-validator" }: uint64

      lastUserValidator* {.
        defaultValue: config.totalValidators - 1,
        desc: "The last validator index that will free for taking from a testnet participant"
        name: "last-user-validator" }: uint64

      bootstrapAddress* {.
        defaultValue: ValidIpAddress.init("127.0.0.1")
        desc: "The public IP address that will be advertised as a bootstrap node for the testnet"
        name: "bootstrap-address" }: ValidIpAddress

      bootstrapPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "The TCP/UDP port that will be used by the bootstrap node"
        name: "bootstrap-port" }: Port

      genesisOffset* {.
        defaultValue: 5
        desc: "Seconds from now to add to genesis time"
        name: "genesis-offset" }: int

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot"
        name: "output-genesis" }: OutFile

      withGenesisRoot* {.
        defaultValue: false
        desc: "Include a genesis root in 'network.json'"
        name: "with-genesis-root" }: bool

      outputBootstrapFile* {.
        desc: "Output file with list of bootstrap nodes for the network"
        name: "output-bootstrap-file" }: OutFile

    of wallets:
      case walletsCmd* {.command.}: WalletsCmd
      of WalletsCmd.create:
        createdWalletName* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "name"}: Option[WalletName]

        nextAccount* {.
          desc: "Initial value for the 'nextaccount' property of the wallet"
          name: "next-account" }: Option[Natural]

        createdWalletFile* {.
          desc: "Output wallet file"
          name: "out" }: Option[OutFile]

      of WalletsCmd.restore:
        restoredWalletName* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "name"}: Option[WalletName]

        restoredDepositsCount* {.
          desc: "Expected number of deposits to recover. If not specified, " &
                "Nimbus will try to guess the number by inspecting the latest " &
                "beacon state"
          name: "deposits".}: Option[Natural]

        restoredWalletFile* {.
          desc: "Output wallet file"
          name: "out" }: Option[OutFile]

      of WalletsCmd.list:
        discard

    of deposits:
      depositPrivateKey* {.
        defaultValue: ""
        desc: "Private key of the controlling (sending) account",
        name: "deposit-private-key" }: string

      case depositsCmd* {.command.}: DepositsCmd
      of DepositsCmd.create:
        totalDeposits* {.
          defaultValue: 1
          desc: "Number of deposits to generate"
          name: "count" }: int

        existingWalletId* {.
          desc: "An existing wallet ID. If not specified, a new wallet will be created"
          name: "wallet" }: Option[WalletName]

        outValidatorsDir* {.
          defaultValue: "validators"
          desc: "Output folder for validator keystores and deposits"
          name: "out-deposits-dir" }: string

        outSecretsDir* {.
          defaultValue: "secrets"
          desc: "Output folder for randomly generated keystore passphrases"
          name: "out-secrets-dir" }: string

        askForKey* {.
          defaultValue: false
          desc: "Ask for an Eth1 private key used to fund the deposits"
          name: "ask-for-key" }: bool

        dontSend* {.
          defaultValue: false,
          desc: "By default, all created deposits are also immediately sent " &
                "to the validator deposit contract. You can use this option to " &
                "prevent this behavior. Use the `deposits send` command to send " &
                "the deposit transactions at your convenience later"
          name: "dont-send" .}: bool

      of DepositsCmd.send:
        depositsDir* {.
          defaultValue: "validators"
          desc: "A folder with validator metadata created by the `deposits create` command"
          name: "deposits-dir" }: string

        minDelay* {.
          defaultValue: 0.0
          desc: "Minimum possible delay between making two deposits (in seconds)"
          name: "min-delay" }: float

        maxDelay* {.
          defaultValue: 0.0
          desc: "Maximum possible delay between making two deposits (in seconds)"
          name: "max-delay" }: float

      of DepositsCmd.status:
        discard

  ValidatorClientConf* = object
    logLevel* {.
      defaultValue: "DEBUG"
      desc: "Sets the log level."
      name: "log-level" }: string

    dataDir* {.
      defaultValue: config.defaultDataDir()
      desc: "The directory where nimbus will store all blockchain data"
      abbr: "d"
      name: "data-dir" }: OutDir

    nonInteractive* {.
      desc: "Do not display interative prompts. Quit on missing configuration"
      name: "non-interactive" }: bool

    case cmd* {.
      command
      defaultValue: VCNoCommand }: VCStartUpCmd

    of VCNoCommand:
      rpcPort* {.
        defaultValue: defaultEth2RpcPort
        desc: "HTTP port of the server to connect to for RPC"
        name: "rpc-port" }: Port

      rpcAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Address of the server to connect to for RPC"
        name: "rpc-address" }: ValidIpAddress

      validators* {.
        required
        desc: "Attach a validator by supplying a keystore path"
        abbr: "v"
        name: "validator" }: seq[ValidatorKeyPath]

      validatorsDirFlag* {.
        desc: "A directory containing validator keystores"
        name: "validators-dir" }: Option[InputDir]

      secretsDirFlag* {.
        desc: "A directory containing validator keystore passwords"
        name: "secrets-dir" }: Option[InputDir]

proc defaultDataDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  getHomeDir() / dataDir / "BeaconNode"

func dumpDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dataDir / "dump"

func dumpDirInvalid*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dumpDir / "invalid" # things that failed validation

func dumpDirIncoming*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dumpDir / "incoming" # things that couldn't be validated (missingparent etc)

func dumpDirOutgoing*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dumpDir / "outgoing" # things we produced

proc createDumpDirs*(conf: BeaconNodeConf) =
  if conf.dumpEnabled:
    try:
      createDir(conf.dumpDirInvalid)
      createDir(conf.dumpDirIncoming)
      createDir(conf.dumpDirOutgoing)
    except CatchableError as err:
      # Dumping is mainly a debugging feature, so ignore these..
      warn "Cannot create dump directories", msg = err.msg

func parseCmdArg*(T: type Eth1Address, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  fromHex(T, string input)

func completeCmdArg*(T: type Eth1Address, input: TaintedString): seq[string] =
  return @[]

func parseCmdArg*(T: type Eth1BlockHash, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  fromHex(T, string input)

func completeCmdArg*(T: type Eth1BlockHash, input: TaintedString): seq[string] =
  return @[]

func parseCmdArg*(T: type WalletName, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  if input.len == 0:
    raise newException(ValueError, "The wallet name should not be empty")
  if input[0] == '_':
    raise newException(ValueError, "The wallet name should not start with an underscore")
  return T(input)

func completeCmdArg*(T: type WalletName, input: TaintedString): seq[string] =
  return @[]

func validatorsDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  string conf.validatorsDirFlag.get(InputDir(conf.dataDir / "validators"))

func secretsDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  string conf.secretsDirFlag.get(InputDir(conf.dataDir / "secrets"))

func walletsDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  string conf.walletsDirFlag.get(InputDir(conf.dataDir / "wallets"))

func databaseDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dataDir / "db"

func defaultListenAddress*(conf: BeaconNodeConf|ValidatorClientConf): ValidIpAddress =
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  (static ValidIpAddress.init("0.0.0.0"))

func defaultAdminListenAddress*(conf: BeaconNodeConf|ValidatorClientConf): ValidIpAddress =
  (static ValidIpAddress.init("127.0.0.1"))

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)


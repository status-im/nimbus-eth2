{.push raises: [Defect].}

import
  os, options, strformat, strutils,
  chronicles, confutils, json_serialization,
  confutils/defs, confutils/std/net,
  chronicles/options as chroniclesOptions,
  spec/[crypto]

export
  defs, enabledLogLevel, parseCmdArg, completeCmdArg

type
  ValidatorKeyPath* = TypedInputFile[ValidatorPrivKey, Txt, "privkey"]

  BNStartUpCmd* = enum
    noCommand
    importValidator
    createTestnet
    makeDeposits

  VCStartUpCmd* = enum
    VCNoCommand

  Eth1Network* = enum
    custom
    mainnet
    rinkeby
    goerli

  BeaconNodeConf* = object
    logLevel* {.
      defaultValue: "DEBUG"
      desc: "Sets the log level."
      name: "log-level" }: string

    eth1Network* {.
      defaultValue: goerli
      desc: "The Eth1 network tracked by the beacon node."
      name: "eth1-network" }: Eth1Network

    quickStart* {.
      defaultValue: false
      desc: "Run in quickstart mode"
      name: "quick-start" }: bool

    dataDir* {.
      defaultValue: config.defaultDataDir()
      desc: "The directory where nimbus will store all blockchain data."
      abbr: "d"
      name: "data-dir" }: OutDir

    web3Url* {.
      defaultValue: ""
      desc: "URL of the Web3 server to observe Eth1."
      name: "web3-url" }: string

    depositContractAddress* {.
      defaultValue: ""
      desc: "Address of the deposit contract."
      name: "deposit-contract" }: string

    case cmd* {.
      command
      defaultValue: noCommand }: BNStartUpCmd

    of noCommand:
      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network."
        abbr: "b"
        name: "bootstrap-node" }: seq[string]

      bootstrapNodesFile* {.
        defaultValue: ""
        desc: "Specifies a line-delimited file of bootsrap Ethereum network addresses."
        name: "bootstrap-file" }: InputFile

      libp2pAddress* {.
        defaultValue: defaultListenAddress(config)
        desc: "Listening address for the Ethereum LibP2P traffic."
        name: "listen-address"}: IpAddress

      tcpPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "Listening TCP port for Ethereum LibP2P traffic."
        name: "tcp-port" }: Port

      udpPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "Listening UDP port for node discovery."
        name: "udp-port" }: Port

      maxPeers* {.
        defaultValue: 10
        desc: "The maximum number of peers to connect to"
        name: "max-peers" }: int

      nat* {.
        desc: "Specify method to use for determining public address. " &
              "Must be one of: any, none, upnp, pmp, extip:<IP>."
        defaultValue: "any" }: string

      validators* {.
        required
        desc: "Path to a validator private key, as generated by makeDeposits."
        abbr: "v"
        name: "validator" }: seq[ValidatorKeyPath]

      externalValidators* {.
        defaultValue: false
        desc: "Specify whether validators should be in an external process (a validator client) which communicates with the beacon node or they should be embedded."
        name: "external-validators" }: bool

      stateSnapshot* {.
        desc: "Json file specifying a recent state snapshot."
        abbr: "s"
        name: "state-snapshot" }: Option[InputFile]

      nodeName* {.
        defaultValue: ""
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be seleceted for each --dataDir folder."
        name: "node-name" }: string

      verifyFinalization* {.
        defaultValue: false
        desc: "Specify whether to verify finalization occurs on schedule, for testing."
        name: "verify-finalization" }: bool

      stopAtEpoch* {.
        defaultValue: 0
        desc: "A positive epoch selects the epoch at which to stop."
        name: "stop-at-epoch" }: uint64

      metricsEnabled* {.
        defaultValue: false
        desc: "Enable the metrics server."
        name: "metrics" }: bool

      metricsAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Listening address of the metrics server."
        name: "metrics-address" }: IpAddress

      metricsPort* {.
        defaultValue: 8008
        desc: "Listening HTTP port of the metrics server."
        name: "metrics-port" }: Port

      statusBarEnabled* {.
        defaultValue: true
        desc: "Display a status bar at the bottom of the terminal screen."
        name: "status-bar" }: bool

      statusBarContents* {.
        defaultValue: "peers: $connected_peers; " &
                      "epoch: $epoch, slot: $epoch_slot/$slots_per_epoch ($slot); " &
                      "finalized epoch: $last_finalized_epoch |" &
                      "ETH: $attached_validators_balance"
        desc: "Textual template for the contents of the status bar."
        name: "status-bar-contents" }: string

      rpcEnabled* {.
        defaultValue: false
        desc: "Enable the JSON-RPC server"
        name: "rpc" }: bool

      rpcPort* {.
        defaultValue: defaultEth2RpcPort
        desc: "HTTP port for the JSON-RPC service."
        name: "rpc-port" }: Port

      rpcAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Listening address of the RPC server"
        name: "rpc-address" }: IpAddress

      dumpEnabled* {.
        defaultValue: false
        desc: "Write SSZ dumps of blocks, attestations and states to data dir"
        name: "dump" }: bool

    of createTestnet:
      validatorsDir* {.
        desc: "Directory containing validator descriptors named 'vXXXXXXX.deposit.json'."
        abbr: "d"
        name: "validators-dir" }: InputDir

      totalValidators* {.
        desc: "The number of validators in the newly created chain."
        name: "total-validators" }: uint64

      firstValidator* {.
        defaultValue: 0
        desc: "Index of first validator to add to validator list."
        name: "first-validator" }: uint64

      lastUserValidator* {.
        defaultValue: config.totalValidators - 1,
        desc: "The last validator index that will free for taking from a testnet participant."
        name: "last-user-validator" }: uint64

      bootstrapAddress* {.
        defaultValue: parseIpAddress("127.0.0.1")
        desc: "The public IP address that will be advertised as a bootstrap node for the testnet."
        name: "bootstrap-address" }: IpAddress

      bootstrapPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "The TCP/UDP port that will be used by the bootstrap node."
        name: "bootstrap-port" }: Port

      genesisOffset* {.
        defaultValue: 5
        desc: "Seconds from now to add to genesis time."
        abbr: "g"
        name: "genesis-offset" }: int

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot."
        name: "output-genesis" }: OutFile

      withGenesisRoot* {.
        defaultValue: false
        desc: "Include a genesis root in 'network.json'."
        name: "with-genesis-root" }: bool

      outputBootstrapFile* {.
        desc: "Output file with list of bootstrap nodes for the network."
        name: "output-bootstrap-file" }: OutFile

    of importValidator:
      keyFiles* {.
        desc: "File with validator key to be imported (in hex form)."
        name: "keyfile" }: seq[ValidatorKeyPath]

    of makeDeposits:
      totalQuickstartDeposits* {.
        defaultValue: 0
        desc: "Number of quick-start deposits to generate."
        name: "quickstart-deposits" }: int

      totalRandomDeposits* {.
        defaultValue: 0
        desc: "Number of secure random deposits to generate."
        name: "random-deposits" }: int

      depositsDir* {.
        defaultValue: "validators"
        desc: "Folder to write deposits to."
        name: "deposits-dir" }: string

      depositPrivateKey* {.
        defaultValue: ""
        desc: "Private key of the controlling (sending) account",
        name: "deposit-private-key" }: string

      minDelay* {.
        defaultValue: 0.0
        desc: "Minimum possible delay between making two deposits (in seconds)"
        name: "min-delay" }: float

      maxDelay* {.
        defaultValue: 0.0
        desc: "Maximum possible delay between making two deposits (in seconds)"
        name: "max-delay" }: float

  ValidatorClientConf* = object
    logLevel* {.
      defaultValue: "DEBUG"
      desc: "Sets the log level."
      name: "log-level" }: string

    dataDir* {.
      defaultValue: config.defaultDataDir()
      desc: "The directory where nimbus will store all blockchain data."
      abbr: "d"
      name: "data-dir" }: OutDir

    case cmd* {.
      command
      defaultValue: VCNoCommand }: VCStartUpCmd

    of VCNoCommand:
      rpcPort* {.
        defaultValue: defaultEth2RpcPort
        desc: "HTTP port of the server to connect to for RPC."
        name: "rpc-port" }: Port

      rpcAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Address of the server to connect to for RPC."
        name: "rpc-address" }: IpAddress

      validators* {.
        required
        desc: "Path to a validator private key, as generated by makeDeposits."
        abbr: "v"
        name: "validator" }: seq[ValidatorKeyPath]

      stateSnapshot* {.
        desc: "Json file specifying a recent state snapshot."
        abbr: "s"
        name: "state-snapshot" }: Option[InputFile]

      delayStart* {.
        defaultValue: 0
        desc: "Seconds from now to delay the starting of the validator client (useful for debug purposes when starting before the beacon node in a script)."
        abbr: "g"
        name: "delay-start" }: int

proc defaultDataDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  getHomeDir() / dataDir / "BeaconNode"

proc validatorFileBaseName*(validatorIdx: int): string =
  # there can apparently be tops 4M validators so we use 7 digits..
  try:
    fmt"v{validatorIdx:07}"
  except ValueError as e:
    raiseAssert e.msg

func dumpDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dataDir / "dump"

func localValidatorsDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dataDir / "validators"

func databaseDir*(conf: BeaconNodeConf|ValidatorClientConf): string =
  conf.dataDir / "db"

func defaultListenAddress*(conf: BeaconNodeConf|ValidatorClientConf): IpAddress =
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  return static: parseIpAddress("0.0.0.0")

func defaultAdminListenAddress*(conf: BeaconNodeConf|ValidatorClientConf): IpAddress =
  return static: parseIpAddress("127.0.0.1")

iterator validatorKeys*(conf: BeaconNodeConf|ValidatorClientConf): ValidatorPrivKey =
  for validatorKeyFile in conf.validators:
    try:
      yield validatorKeyFile.load
    except CatchableError as err:
      warn "Failed to load validator private key",
        file = validatorKeyFile.string, err = err.msg

  try:
    for kind, file in walkDir(conf.localValidatorsDir):
      if kind in {pcFile, pcLinkToFile} and
          cmpIgnoreCase(".privkey", splitFile(file).ext) == 0:
        try:
          yield ValidatorPrivKey.init(readFile(file).string)
        except CatchableError as err:
          warn "Failed to load a validator private key", file, err = err.msg
  except OSError as err:
    warn "Cannot load validator keys",
      dir = conf.localValidatorsDir, err = err.msg

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)

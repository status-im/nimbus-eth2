# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  strutils, os, options, unicode, uri,
  chronicles, chronicles/options as chroniclesOptions,
  confutils, confutils/defs, confutils/std/net, stew/shims/net as stewNet,
  stew/io2, unicodedb/properties, normalize,
  eth/common/eth_types as commonEthTypes, eth/net/nat,
  eth/p2p/discoveryv5/enr,
  json_serialization, web3/[ethtypes, confutils_defs],
  spec/[crypto, keystore, digest, datatypes, network],
  ./networking/network_metadata,
  filepath

export
  uri,
  defaultEth2TcpPort, enabledLogLevel, ValidIpAddress,
  defs, parseCmdArg, completeCmdArg, network_metadata

const
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  defaultListenAddress* = (static ValidIpAddress.init("0.0.0.0"))
  defaultAdminListenAddress* = (static ValidIpAddress.init("127.0.0.1"))

type
  BNStartUpCmd* = enum
    noCommand
    createTestnet
    deposits
    wallets
    record
    web3

  WalletsCmd* {.pure.} = enum
    create  = "Creates a new EIP-2386 wallet"
    restore = "Restores a wallet from cold storage"
    list    = "Lists details about all wallets"

  DepositsCmd* {.pure.} = enum
    createTestnetDeposits = "Creates validator keystores and deposits for testnet usage"
    `import` = "Imports password-protected keystores interactively"
    # status   = "Displays status information about all deposits"
    exit     = "Submits a validator voluntary exit"

  VCStartUpCmd* = enum
    VCNoCommand

  RecordCmd* {.pure.} = enum
    create  = "Create a new ENR"
    print = "Print the content of a given ENR"

  Web3Cmd* {.pure.} = enum
    test = "Test a web3 provider"

  Web3Mode* {.pure.} = enum
    auto # Enabled only when validators are attached
    enabled # Always enabled
    disabled # Always disabled

  SlashingDbKind* {.pure.} = enum
    v1
    v2
    both

  StateDbKind* {.pure.} = enum
    sql
    file

  BeaconNodeConf* = object
    logLevel* {.
      defaultValue: "INFO"
      desc: "Sets the log level for process and topics (e.g. \"DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none\") [=INFO]"
      name: "log-level" }: string

    logFile* {.
      desc: "Specifies a path for the written Json log file"
      name: "log-file" }: Option[OutFile]

    eth2Network* {.
      desc: "The Eth2 network to join [=mainnet]"
      name: "network" }: Option[string]

    dataDir* {.
      defaultValue: config.defaultDataDir()
      desc: "The directory where nimbus will store all blockchain data"
      abbr: "d"
      name: "data-dir" }: OutDir

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" }: Option[InputDir]

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" }: Option[InputDir]

    walletsDirFlag* {.
      desc: "A directory containing wallet files"
      name: "wallets-dir" }: Option[InputDir]

    web3Urls* {.
      desc: "One of more Web3 provider URLs used for obtaining deposit contract data"
      name: "web3-url" }: seq[string]

    web3Mode* {.
      hidden
      defaultValue: Web3Mode.auto
      desc: "URL of the Web3 server to observe Eth1"
      name: "web3-mode" }: Web3Mode

    nonInteractive* {.
      desc: "Do not display interative prompts. Quit on missing configuration"
      name: "non-interactive" }: bool

    netKeyFile* {.
      defaultValue: "random",
      desc: "Source of network (secp256k1) private key file " &
            "(random|<path>) [=random]"
      name: "netkey-file" }: string

    netKeyInsecurePassword* {.
      defaultValue: false,
      desc: "Use pre-generated INSECURE password for network private key " &
            "file [=false]"
      name: "insecure-netkey-password" }: bool

    agentString* {.
      defaultValue: "nimbus",
      desc: "Node agent string which is used as identifier in network"
      name: "agent-string" }: string

    subscribeAllSubnets* {.
      defaultValue: false,
      desc: "Subscribe to all attestation subnet topics when gossiping"
      name: "subscribe-all-subnets" }: bool

    slashingDbKind* {.
      hidden
      defaultValue: SlashingDbKind.v2
      desc: "The slashing DB flavour to use (v1, v2 or both) [=both]"
      name: "slashing-db-kind" }: SlashingDbKind

    stateDbKind* {.
      hidden
      defaultValue: StateDbKind.sql
      desc: "State DB kind (sql, file) [=sql]"
      name: "state-db-kind" }: StateDbKind

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

      listenAddress* {.
        defaultValue: defaultListenAddress
        desc: "Listening address for the Ethereum LibP2P and Discovery v5 " &
          "traffic [=0.0.0.0]"
        name: "listen-address" }: ValidIpAddress

      tcpPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "Listening TCP port for Ethereum LibP2P traffic [=9000]"
        name: "tcp-port" }: Port

      udpPort* {.
        defaultValue: defaultEth2TcpPort
        desc: "Listening UDP port for node discovery [=9000]"
        name: "udp-port" }: Port

      maxPeers* {.
        defaultValue: 160 # 5 (fanout) * 64 (subnets) / 2 (subs) for a heathy mesh
        desc: "The maximum number of peers to connect to [=160]"
        name: "max-peers" }: int

      nat* {.
        desc: "Specify method to use for determining public address. " &
              "Must be one of: any, none, upnp, pmp, extip:<IP>"
        defaultValue: NatConfig(hasExtIp: false, nat: NatAny)
        name: "nat" .}: NatConfig

      enrAutoUpdate* {.
        defaultValue: false
        desc: "Discovery can automatically update its ENR with the IP address " &
              "and UDP port as seen by other nodes it communicates with. " &
              "This option allows to enable/disable this functionality"
        name: "enr-auto-update" .}: bool

      weakSubjectivityCheckpoint* {.
        desc: "Weak subjectivity checkpoint in the format block_root:epoch_number"
        name: "weak-subjectivity-checkpoint" }: Option[Checkpoint]

      finalizedCheckpointState* {.
        desc: "SSZ file specifying a recent finalized state"
        name: "finalized-checkpoint-state" }: Option[InputFile]

      finalizedCheckpointBlock* {.
        desc: "SSZ file specifying a recent finalized block"
        name: "finalized-checkpoint-block" }: Option[InputFile]

      nodeName* {.
        defaultValue: ""
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be selected for each --data-dir folder"
        name: "node-name" }: string

      graffiti* {.
        desc: "The graffiti value that will appear in proposed blocks. " &
              "You can use a 0x-prefixed hex encoded string to specify raw bytes"
        name: "graffiti" }: Option[GraffitiBytes]

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
        desc: "Enable the metrics server [=false]"
        name: "metrics" }: bool

      metricsAddress* {.
        defaultValue: defaultAdminListenAddress
        desc: "Listening address of the metrics server [=127.0.0.1]"
        name: "metrics-address" }: ValidIpAddress

      metricsPort* {.
        defaultValue: 8008
        desc: "Listening HTTP port of the metrics server [=8008]"
        name: "metrics-port" }: Port

      statusBarEnabled* {.
        defaultValue: true
        desc: "Display a status bar at the bottom of the terminal screen"
        name: "status-bar" }: bool

      statusBarContents* {.
        defaultValue: "peers: $connected_peers;" &
                      "finalized: $finalized_root:$finalized_epoch;" &
                      "head: $head_root:$head_epoch:$head_epoch_slot;" &
                      "time: $epoch:$epoch_slot ($slot);" &
                      "sync: $sync_status|" &
                      "ETH: $attached_validators_balance"
        desc: "Textual template for the contents of the status bar"
        name: "status-bar-contents" }: string

      rpcEnabled* {.
        defaultValue: false
        desc: "Enable the JSON-RPC server [=false]"
        name: "rpc" }: bool

      rpcPort* {.
        defaultValue: defaultEth2RpcPort
        desc: "HTTP port for the JSON-RPC service [=9190]"
        name: "rpc-port" }: Port

      rpcAddress* {.
        defaultValue: defaultAdminListenAddress
        desc: "Listening address of the RPC server [=127.0.0.1]"
        name: "rpc-address" }: ValidIpAddress

      restEnabled* {.
        defaultValue: false
        desc: "Enable the REST server"
        name: "rest" }: bool

      restPort* {.
        defaultValue: DefaultEth2RestPort
        desc: "HTTP port for the REST service"
        name: "rest-port" }: Port

      restAddress* {.
        defaultValue: defaultAdminListenAddress(config)
        desc: "Listening address of the REST server"
        name: "rest-address" }: ValidIpAddress

      inProcessValidators* {.
        defaultValue: true # the use of the nimbus_signing_process binary by default will be delayed until async I/O over stdin/stdout is developed for the child process.
        desc: "Disable the push model (the beacon node tells a signing process with the private keys of the validators what to sign and when) and load the validators in the beacon node itself"
        name: "in-process-validators" }: bool

      discv5Enabled* {.
        defaultValue: true
        desc: "Enable Discovery v5 [=true]"
        name: "discv5" }: bool

      dumpEnabled* {.
        defaultValue: false
        desc: "Write SSZ dumps of blocks, attestations and states to data dir [=false]"
        name: "dump" }: bool

      directPeers* {.
        desc: "The list of priviledged, secure and known peers to connect and maintain the connection to, this requires a not random netkey-file. In the complete multiaddress format like: /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>. Peering agreements are established out of band and must be reciprocal."
        name: "direct-peer" .}: seq[string]

      doppelgangerDetection* {.
        defaultValue: true
        desc: "Whether to detect whether another validator is be running the same validator keys [=true]"
        name: "doppelganger-detection"
      }: bool

    of createTestnet:
      testnetDepositsFile* {.
        desc: "A LaunchPad deposits file for the genesis state validators"
        name: "deposits-file" }: InputFile

      totalValidators* {.
        desc: "The number of validator deposits in the newly created chain"
        name: "total-validators" }: uint64

      firstValidator* {.
        defaultValue: 0
        desc: "Index of first validator to add to validator list"
        name: "first-validator" }: uint64

      lastUserValidator* {.
        defaultValue: config.totalValidators - 1,
        desc: "The last validator index that will be free for taking from a testnet participant"
        name: "last-user-validator" }: uint64

      bootstrapAddress* {.
        defaultValue: init(ValidIpAddress, "127.0.0.1")
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
        nextAccount* {.
          desc: "Initial value for the 'nextaccount' property of the wallet"
          name: "next-account" }: Option[Natural]

        createdWalletNameFlag* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "name"}: Option[WalletName]

        createdWalletFileFlag* {.
          desc: "Output wallet file"
          name: "out" }: Option[OutFile]

      of WalletsCmd.restore:
        restoredWalletNameFlag* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "name"}: Option[WalletName]

        restoredWalletFileFlag* {.
          desc: "Output wallet file"
          name: "out" }: Option[OutFile]

        restoredDepositsCount* {.
          desc: "Expected number of deposits to recover. If not specified, " &
                "Nimbus will try to guess the number by inspecting the latest " &
                "beacon state"
          name: "deposits".}: Option[Natural]

      of WalletsCmd.list:
        discard

    of deposits:
      case depositsCmd* {.command.}: DepositsCmd
      of DepositsCmd.createTestnetDeposits:
        totalDeposits* {.
          defaultValue: 1
          desc: "Number of deposits to generate"
          name: "count" }: int

        existingWalletId* {.
          desc: "An existing wallet ID. If not specified, a new wallet will be created"
          name: "wallet" }: Option[WalletName]

        outValidatorsDir* {.
          defaultValue: "validators"
          desc: "Output folder for validator keystores"
          name: "out-validators-dir" }: string

        outSecretsDir* {.
          defaultValue: "secrets"
          desc: "Output folder for randomly generated keystore passphrases"
          name: "out-secrets-dir" }: string

        outDepositsFile* {.
          desc: "The name of generated deposits file"
          name: "out-deposits-file" }: Option[OutFile]

        newWalletNameFlag* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "new-wallet-name" }: Option[WalletName]

        newWalletFileFlag* {.
          desc: "Output wallet file"
          name: "new-wallet-file" }: Option[OutFile]

      #[
      of DepositsCmd.status:
        discard
      ]#

      of DepositsCmd.`import`:
        importedDepositsDir* {.
          argument
          desc: "A directory with keystores to import" }: Option[InputDir]

      of DepositsCmd.exit:
        exitedValidator* {.
          name: "validator"
          desc: "Validator index or a public key of the exited validator" }: string

        rpcUrlForExit* {.
          name: "rpc-url"
          defaultValue: parseUri("http://localhost:" & $defaultEth2RpcPort)
          desc: "URL of the beacon node JSON-RPC service" }: Uri

        exitAtEpoch* {.
          name: "epoch"
          desc: "The desired exit epoch" }: Option[uint64]

    of record:
      case recordCmd* {.command.}: RecordCmd
      of RecordCmd.create:
        ipExt* {.
          desc: "External IP address"
          name: "ip" .}: ValidIpAddress

        tcpPortExt* {.
          desc: "External TCP port"
          name: "tcp-port" .}: Port

        udpPortExt* {.
          desc: "External UDP port"
          name: "udp-port" .}: Port

        seqNumber* {.
          defaultValue: 1,
          desc: "Record sequence number"
          name: "seq-number" .}: uint

        fields* {.
          desc: "Additional record key pairs, provide as <string>:<bytes in hex>"
          name: "field" .}: seq[(string)]

      of RecordCmd.print:
        recordPrint* {.
          argument
          desc: "ENR URI of the record to print"
          name: "enr" .}: Record

    of web3:
      case web3Cmd* {.command.}: Web3Cmd
      of Web3Cmd.test:
        web3TestUrl* {.
          argument
          desc: "The web3 provider URL to test"
          name: "url" }: Uri

  ValidatorClientConf* = object
    logLevel* {.
      defaultValue: "INFO"
      desc: "Sets the log level [=INFO]"
      name: "log-level" }: string

    logFile* {.
      desc: "Specifies a path for the written Json log file"
      name: "log-file" }: Option[OutFile]

    dataDir* {.
      defaultValue: config.defaultDataDir()
      desc: "The directory where nimbus will store all blockchain data"
      abbr: "d"
      name: "data-dir" }: OutDir

    nonInteractive* {.
      desc: "Do not display interative prompts. Quit on missing configuration"
      name: "non-interactive" }: bool

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" }: Option[InputDir]

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" }: Option[InputDir]

    case cmd* {.
      command
      defaultValue: VCNoCommand }: VCStartUpCmd

    of VCNoCommand:
      graffiti* {.
        desc: "The graffiti value that will appear in proposed blocks. " &
              "You can use a 0x-prefixed hex encoded string to specify raw bytes"
        name: "graffiti" }: Option[GraffitiBytes]

      stopAtEpoch* {.
        defaultValue: 0
        desc: "A positive epoch selects the epoch at which to stop"
        name: "stop-at-epoch" }: uint64

      rpcPort* {.
        defaultValue: defaultEth2RpcPort
        desc: "HTTP port of the server to connect to for RPC [=9190]"
        name: "rpc-port" }: Port

      rpcAddress* {.
        defaultValue: defaultAdminListenAddress
        desc: "Address of the server to connect to for RPC [=127.0.0.1]"
        name: "rpc-address" }: ValidIpAddress

      retryDelay* {.
        defaultValue: 10
        desc: "Delay in seconds between retries after unsuccessful attempts to connect to a beacon node [=10]"
        name: "retry-delay" }: int

proc defaultDataDir*(config: BeaconNodeConf|ValidatorClientConf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  getHomeDir() / dataDir / "BeaconNode"

func dumpDir*(config: BeaconNodeConf|ValidatorClientConf): string =
  config.dataDir / "dump"

func dumpDirInvalid*(config: BeaconNodeConf|ValidatorClientConf): string =
  config.dumpDir / "invalid" # things that failed validation

func dumpDirIncoming*(config: BeaconNodeConf|ValidatorClientConf): string =
  config.dumpDir / "incoming" # things that couldn't be validated (missingparent etc)

func dumpDirOutgoing*(config: BeaconNodeConf|ValidatorClientConf): string =
  config.dumpDir / "outgoing" # things we produced

proc createDumpDirs*(config: BeaconNodeConf) =
  if config.dumpEnabled:
    let resInv = secureCreatePath(config.dumpDirInvalid)
    if resInv.isErr():
      warn "Could not create dump directory", path = config.dumpDirInvalid
    let resInc = secureCreatePath(config.dumpDirIncoming)
    if resInc.isErr():
      warn "Could not create dump directory", path = config.dumpDirIncoming
    let resOut = secureCreatePath(config.dumpDirOutgoing)
    if resOut.isErr():
      warn "Could not create dump directory", path = config.dumpDirOutgoing

func parseCmdArg*(T: type GraffitiBytes, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  GraffitiBytes.init(string input)

func completeCmdArg*(T: type GraffitiBytes, input: TaintedString): seq[string] =
  return @[]

func parseCmdArg*(T: type BlockHashOrNumber, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  init(BlockHashOrNumber, string input)

func completeCmdArg*(T: type BlockHashOrNumber, input: TaintedString): seq[string] =
  return @[]

func parseCmdArg*(T: type Uri, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  parseUri(input.string)

func completeCmdArg*(T: type Uri, input: TaintedString): seq[string] =
  return @[]

func parseCmdArg*(T: type Checkpoint, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  let sepIdx = find(input.string, ':')
  if sepIdx == -1:
    raise newException(ValueError,
      "The weak subjectivity checkpoint must be provided in the `block_root:epoch_number` format")
  T(root: Eth2Digest.fromHex(input[0 ..< sepIdx]),
    epoch: parseBiggestUInt(input[sepIdx .. ^1]).Epoch)

func completeCmdArg*(T: type Checkpoint, input: TaintedString): seq[string] =
  return @[]

proc isPrintable(rune: Rune): bool =
  # This can be eventually replaced by the `unicodeplus` package, but a single
  # proc does not justify the extra dependencies at the moment:
  # https://github.com/nitely/nim-unicodeplus
  # https://github.com/nitely/nim-segmentation
  rune == Rune(0x20) or unicodeCategory(rune) notin ctgC+ctgZ

func parseCmdArg*(T: type WalletName, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  if input.len == 0:
    raise newException(ValueError, "The wallet name should not be empty")
  if input[0] == '_':
    raise newException(ValueError, "The wallet name should not start with an underscore")
  for rune in runes(input.string):
    if not rune.isPrintable:
      raise newException(ValueError, "The wallet name should consist only of printable characters")

  # From the Unicode Normalization FAQ (https://unicode.org/faq/normalization.html):
  # NFKC is the preferred form for identifiers, especially where there are security concerns
  # (see UTR #36 http://www.unicode.org/reports/tr36/)
  return T(toNFKC(input))

func completeCmdArg*(T: type WalletName, input: TaintedString): seq[string] =
  return @[]

proc parseCmdArg*(T: type enr.Record, p: TaintedString): T
    {.raises: [ConfigurationError, Defect].} =
  if not fromURI(result, p):
    raise newException(ConfigurationError, "Invalid ENR")

proc completeCmdArg*(T: type enr.Record, val: TaintedString): seq[string] =
  return @[]

func validatorsDir*(config: BeaconNodeConf|ValidatorClientConf): string =
  string config.validatorsDirFlag.get(InputDir(config.dataDir / "validators"))

func secretsDir*(config: BeaconNodeConf|ValidatorClientConf): string =
  string config.secretsDirFlag.get(InputDir(config.dataDir / "secrets"))

func walletsDir*(config: BeaconNodeConf): string =
  if config.walletsDirFlag.isSome:
    config.walletsDirFlag.get.string
  else:
    config.dataDir / "wallets"

func outWalletName*(config: BeaconNodeConf): Option[WalletName] =
  proc fail {.noReturn.} =
    raiseAssert "outWalletName should be used only in the right context"

  case config.cmd
  of wallets:
    case config.walletsCmd
    of WalletsCmd.create: config.createdWalletNameFlag
    of WalletsCmd.restore: config.restoredWalletNameFlag
    of WalletsCmd.list: fail()
  of deposits:
    case config.depositsCmd
    of DepositsCmd.createTestnetDeposits: config.newWalletNameFlag
    else: fail()
  else:
    fail()

func outWalletFile*(config: BeaconNodeConf): Option[OutFile] =
  proc fail {.noReturn.} =
    raiseAssert "outWalletName should be used only in the right context"

  case config.cmd
  of wallets:
    case config.walletsCmd
    of WalletsCmd.create: config.createdWalletFileFlag
    of WalletsCmd.restore: config.restoredWalletFileFlag
    of WalletsCmd.list: fail()
  of deposits:
    case config.depositsCmd
    of DepositsCmd.createTestnetDeposits: config.newWalletFileFlag
    else: fail()
  else:
    fail()

func databaseDir*(config: BeaconNodeConf|ValidatorClientConf): string =
  config.dataDir / "db"

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)

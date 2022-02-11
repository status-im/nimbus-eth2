# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[strutils, os, options, unicode, uri],
  metrics,

  chronicles, chronicles/options as chroniclesOptions,
  confutils, confutils/defs, confutils/std/net, stew/shims/net as stewNet,
  stew/[io2, byteutils], unicodedb/properties, normalize,
  eth/common/eth_types as commonEthTypes, eth/net/nat,
  eth/p2p/discoveryv5/enr,
  json_serialization, web3/[ethtypes, confutils_defs],

  ./spec/[keystore, network],
  ./spec/datatypes/base,
  ./networking/network_metadata,
  ./validators/slashing_protection_common,
  ./filepath

export
  uri, nat, enr,
  defaultEth2TcpPort, enabledLogLevel, ValidIpAddress,
  defs, parseCmdArg, completeCmdArg, network_metadata,
  network, BlockHashOrNumber

declareGauge network_name, "network name", ["name"]

const
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  defaultListenAddress* = (static ValidIpAddress.init("0.0.0.0"))
  defaultAdminListenAddress* = (static ValidIpAddress.init("127.0.0.1"))
  defaultSigningNodeRequestTimeout* = 60

type
  BNStartUpCmd* {.pure.} = enum
    noCommand
    createTestnet
    deposits
    wallets
    record
    web3
    slashingdb
    trustedNodeSync

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

  SNStartUpCmd* = enum
    SNNoCommand

  RecordCmd* {.pure.} = enum
    create  = "Create a new ENR"
    print = "Print the content of a given ENR"

  Web3Cmd* {.pure.} = enum
    test = "Test a web3 provider"

  SlashingDbKind* {.pure.} = enum
    v1
    v2
    both

  StdoutLogKind* {.pure.} = enum
    Auto = "auto"
    Colors = "colors"
    NoColors = "nocolors"
    Json = "json"
    None = "none"

  SlashProtCmd* = enum
    `import` = "Import a EIP-3076 slashing protection interchange file"
    `export` = "Export a EIP-3076 slashing protection interchange file"
    # migrateAll = "Export and remove the whole validator slashing protection DB."
    # migrate = "Export and remove specified validators from Nimbus."

  BeaconNodeConf* = object
    logLevel* {.
      desc: "Sets the log level for process and topics (e.g. \"DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none\")"
      defaultValue: "INFO"
      name: "log-level" }: string

    logStdout* {.
      hidden
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-format" }: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written Json log file (deprecated)"
      name: "log-file" }: Option[OutFile]

    eth2Network* {.
      desc: "The Eth2 network to join"
      defaultValueDesc: "mainnet"
      name: "network" }: Option[string]

    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data"
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
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
      desc: "One or more Web3 provider URLs used for obtaining deposit contract data"
      name: "web3-url" }: seq[string]

    web3ForcePolling* {.
      hidden
      defaultValue: false
      desc: "Force the use of polling when determining the head block of Eth1"
      name: "web3-force-polling" }: bool

    nonInteractive* {.
      desc: "Do not display interative prompts. Quit on missing configuration"
      name: "non-interactive" }: bool

    netKeyFile* {.
      desc: "Source of network (secp256k1) private key file " &
            "(random|<path>)"
      defaultValue: "random",
      name: "netkey-file" }: string

    netKeyInsecurePassword* {.
      desc: "Use pre-generated INSECURE password for network private key file"
      defaultValue: false,
      name: "insecure-netkey-password" }: bool

    agentString* {.
      defaultValue: "nimbus",
      desc: "Node agent string which is used as identifier in network"
      name: "agent-string" }: string

    subscribeAllSubnets* {.
      defaultValue: false,
      desc: "Subscribe to all subnet topics when gossiping"
      name: "subscribe-all-subnets" }: bool

    slashingDbKind* {.
      hidden
      defaultValue: SlashingDbKind.v2
      desc: "The slashing DB flavour to use"
      name: "slashing-db-kind" }: SlashingDbKind

    numThreads* {.
      defaultValue: 1,
      desc: "Number of worker threads (set this to 0 to use as many threads as there are CPU cores available)"
      name: "num-threads" }: int

    case cmd* {.
      command
      defaultValue: BNStartUpCmd.noCommand }: BNStartUpCmd

    of BNStartUpCmd.noCommand:
      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network"
        abbr: "b"
        name: "bootstrap-node" }: seq[string]

      bootstrapNodesFile* {.
        desc: "Specifies a line-delimited file of bootstrap Ethereum network addresses"
        defaultValue: ""
        name: "bootstrap-file" }: InputFile

      listenAddress* {.
        desc: "Listening address for the Ethereum LibP2P and Discovery v5 traffic"
        defaultValue: defaultListenAddress
        defaultValueDesc: "0.0.0.0"
        name: "listen-address" }: ValidIpAddress

      tcpPort* {.
        desc: "Listening TCP port for Ethereum LibP2P traffic"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: "9000"
        name: "tcp-port" }: Port

      udpPort* {.
        desc: "Listening UDP port for node discovery"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: "9000"
        name: "udp-port" }: Port

      maxPeers* {.
        desc: "The maximum number of peers to connect to"
        defaultValue: 160 # 5 (fanout) * 64 (subnets) / 2 (subs) for a heathy mesh
        name: "max-peers" }: int

      nat* {.
        desc: "Specify method to use for determining public address. " &
              "Must be one of: any, none, upnp, pmp, extip:<IP>"
        defaultValue: NatConfig(hasExtIp: false, nat: NatAny)
        defaultValueDesc: "any"
        name: "nat" .}: NatConfig

      enrAutoUpdate* {.
        desc: "Discovery can automatically update its ENR with the IP address " &
              "and UDP port as seen by other nodes it communicates with. " &
              "This option allows to enable/disable this functionality"
        defaultValue: false
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
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be selected for each --data-dir folder"
        defaultValue: ""
        name: "node-name" }: string

      graffiti* {.
        desc: "The graffiti value that will appear in proposed blocks. " &
              "You can use a 0x-prefixed hex encoded string to specify raw bytes"
        name: "graffiti" }: Option[GraffitiBytes]

      verifyFinalization* {.
        hidden
        desc: "Specify whether to verify finalization occurs on schedule (debug only)"
        defaultValue: false
        name: "verify-finalization" }: bool

      stopAtEpoch* {.
        desc: "A positive epoch selects the epoch at which to stop"
        defaultValue: 0
        name: "stop-at-epoch" }: uint64

      metricsEnabled* {.
        desc: "Enable the metrics server"
        defaultValue: false
        name: "metrics" }: bool

      metricsAddress* {.
        desc: "Listening address of the metrics server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: "127.0.0.1"
        name: "metrics-address" }: ValidIpAddress

      metricsPort* {.
        desc: "Listening HTTP port of the metrics server"
        defaultValue: 8008
        name: "metrics-port" }: Port

      statusBarEnabled* {.
        desc: "Display a status bar at the bottom of the terminal screen"
        defaultValue: true
        name: "status-bar" }: bool

      statusBarContents* {.
        desc: "Textual template for the contents of the status bar"
        defaultValue: "peers: $connected_peers;" &
                      "finalized: $finalized_root:$finalized_epoch;" &
                      "head: $head_root:$head_epoch:$head_epoch_slot;" &
                      "time: $epoch:$epoch_slot ($slot);" &
                      "sync: $sync_status|" &
                      "ETH: $attached_validators_balance"
        defaultValueDesc: ""
        name: "status-bar-contents" }: string

      rpcEnabled* {.
        desc: "Enable the JSON-RPC server"
        defaultValue: false
        name: "rpc" }: bool

      rpcPort* {.
        desc: "HTTP port for the JSON-RPC service"
        defaultValue: defaultEth2RpcPort
        defaultValueDesc: "9190"
        name: "rpc-port" }: Port

      rpcAddress* {.
        desc: "Listening address of the RPC server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: "127.0.0.1"
        name: "rpc-address" }: ValidIpAddress

      restEnabled* {.
        desc: "Enable the REST server"
        defaultValue: false
        name: "rest" }: bool

      restPort* {.
        desc: "Port for the REST server"
        defaultValue: DefaultEth2RestPort
        defaultValueDesc: "5052"
        name: "rest-port" }: Port

      restAddress* {.
        desc: "Listening address of the REST server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: "127.0.0.1"
        name: "rest-address" }: ValidIpAddress

      restAllowedOrigin* {.
        desc: "Limit the access to the REST API to a particular hostname " &
              "(for CORS-enabled clients such as browsers)"
        name: "rest-allow-origin" }: Option[string]

      restCacheSize* {.
        defaultValue: 3
        desc: "The maximum number of recently accessed states that are kept in " &
              "memory. Speeds up requests obtaining information for consecutive " &
              "slots or epochs."
        name: "rest-statecache-size" }: Natural

      restCacheTtl* {.
        defaultValue: 60
        desc: "The number of seconds to keep recently accessed states in memory"
        name: "rest-statecache-ttl" }: Natural

      restRequestTimeout* {.
        defaultValue: 0
        defaultValueDesc: "infinite"
        desc: "The number of seconds to wait until complete REST request " &
              "will be received"
        name: "rest-request-timeout" }: Natural

      restMaxRequestBodySize* {.
        defaultValue: 16_384
        desc: "Maximum size of REST request body (kilobytes)"
        name: "rest-max-body-size" }: Natural

      restMaxRequestHeadersSize* {.
        defaultValue: 64
        desc: "Maximum size of REST request headers (kilobytes)"
        name: "rest-max-headers-size" }: Natural

      keymanagerEnabled* {.
        desc: "Enable the REST keymanager API (BETA version)"
        defaultValue: false
        name: "keymanager" }: bool

      keymanagerPort* {.
        desc: "Listening port for the REST keymanager API"
        defaultValue: DefaultEth2RestPort
        defaultValueDesc: "5052"
        name: "keymanager-port" }: Port

      keymanagerAddress* {.
        desc: "Listening port for the REST keymanager API"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: "127.0.0.1"
        name: "keymanager-address" }: ValidIpAddress

      keymanagerAllowedOrigin* {.
        desc: "Limit the access to the Keymanager API to a particular hostname " &
              "(for CORS-enabled clients such as browsers)"
        name: "keymanager-allow-origin" }: Option[string]

      keymanagerTokenFile* {.
        desc: "A file specifying the authorizition token required for accessing the keymanager API"
        name: "keymanager-token-file" }: Option[InputFile]

      inProcessValidators* {.
        desc: "Disable the push model (the beacon node tells a signing process with the private keys of the validators what to sign and when) and load the validators in the beacon node itself"
        defaultValue: true # the use of the nimbus_signing_process binary by default will be delayed until async I/O over stdin/stdout is developed for the child process.
        name: "in-process-validators" }: bool

      discv5Enabled* {.
        desc: "Enable Discovery v5"
        defaultValue: true
        name: "discv5" }: bool

      dumpEnabled* {.
        desc: "Write SSZ dumps of blocks, attestations and states to data dir"
        defaultValue: false
        name: "dump" }: bool

      directPeers* {.
        desc: "The list of priviledged, secure and known peers to connect and maintain the connection to, this requires a not random netkey-file. In the complete multiaddress format like: /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>. Peering agreements are established out of band and must be reciprocal."
        name: "direct-peer" .}: seq[string]

      doppelgangerDetection* {.
        desc: "If enabled, the beacon node prudently listens for 2 epochs for attestations from a validator with the same index (a doppelganger), before sending an attestation itself. This protects against slashing (due to double-voting) but means you will miss two attestations when restarting."
        defaultValue: true
        name: "doppelganger-detection"
      }: bool

      syncHorizon* {.
        hidden
        desc: "Number of empty slots to process before considering the client out of sync"
        defaultValue: MaxEmptySlotCount
        defaultValueDesc: "50"
        name: "sync-horizon" }: uint64

      # https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/merge/client-settings.md#override-terminal-total-difficulty
      # TODO nim-confutils on 32-bit platforms overflows decoding integers
      # requiring 64-bit representations and doesn't build when specifying
      # UInt256 directly, so pass this through for decoding elsewhere.
      terminalTotalDifficultyOverride* {.
        hidden
        desc: "Override pre-configured TERMINAL_TOTAL_DIFFICULTY parameter"
        name: "terminal-total-difficulty-override"
      }: Option[string]

      validatorMonitorAuto* {.
        desc: "Automatically monitor locally active validators (BETA)"
        defaultValue: false
        name: "validator-monitor-auto" }: bool

      validatorMonitorPubkeys* {.
        desc: "One or more validators to monitor - works best when --subscribe-all-subnets is enabled (BETA)"
        name: "validator-monitor-pubkey" }: seq[ValidatorPubKey]

      validatorMonitorTotals* {.
        desc: "Publish metrics to single 'totals' label for better collection performance when monitoring many validators (BETA)"
        defaultValue: false
        name: "validator-monitor-totals" }: bool

      proposerBoosting* {.
        hidden
        desc: "Enable proposer boosting; temporary option feature gate (debugging; option will be removed)",
        defaultValue: false
        name: "proposer-boosting-debug" }: bool

    of BNStartUpCmd.createTestnet:
      testnetDepositsFile* {.
        desc: "A LaunchPad deposits file for the genesis state validators"
        name: "deposits-file" }: InputFile

      totalValidators* {.
        desc: "The number of validator deposits in the newly created chain"
        name: "total-validators" }: uint64

      bootstrapAddress* {.
        desc: "The public IP address that will be advertised as a bootstrap node for the testnet"
        defaultValue: init(ValidIpAddress, "127.0.0.1")
        defaultValueDesc: "127.0.0.1"
        name: "bootstrap-address" }: ValidIpAddress

      bootstrapPort* {.
        desc: "The TCP/UDP port that will be used by the bootstrap node"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: "9000"
        name: "bootstrap-port" }: Port

      genesisOffset* {.
        desc: "Seconds from now to add to genesis time"
        defaultValue: 5
        name: "genesis-offset" }: int

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot"
        name: "output-genesis" }: OutFile

      outputBootstrapFile* {.
        desc: "Output file with list of bootstrap nodes for the network"
        name: "output-bootstrap-file" }: OutFile

    of BNStartUpCmd.wallets:
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

    of BNStartUpCmd.deposits:
      case depositsCmd* {.command.}: DepositsCmd
      of DepositsCmd.createTestnetDeposits:
        totalDeposits* {.
          desc: "Number of deposits to generate"
          defaultValue: 1
          name: "count" }: int

        existingWalletId* {.
          desc: "An existing wallet ID. If not specified, a new wallet will be created"
          name: "wallet" }: Option[WalletName]

        outValidatorsDir* {.
          desc: "Output folder for validator keystores"
          defaultValue: "validators"
          name: "out-validators-dir" }: string

        outSecretsDir* {.
          desc: "Output folder for randomly generated keystore passphrases"
          defaultValue: "secrets"
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

        exitAtEpoch* {.
          name: "epoch"
          desc: "The desired exit epoch" }: Option[uint64]

        restUrlForExit* {.
          desc: "URL of the beacon node REST service"
          name: "rest-url" }: Option[Uri]

        rpcUrlForExit* {.
          desc: "URL of the beacon node JSON-RPC service"
          name: "rpc-url" }:  Option[Uri]

    of BNStartUpCmd.record:
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
          desc: "Record sequence number"
          defaultValue: 1,
          name: "seq-number" .}: uint

        fields* {.
          desc: "Additional record key pairs, provide as <string>:<bytes in hex>"
          name: "field" .}: seq[(string)]

      of RecordCmd.print:
        recordPrint* {.
          argument
          desc: "ENR URI of the record to print"
          name: "enr" .}: Record

    of BNStartUpCmd.web3:
      case web3Cmd* {.command.}: Web3Cmd
      of Web3Cmd.test:
        web3TestUrl* {.
          argument
          desc: "The web3 provider URL to test"
          name: "url" }: Uri

    of BNStartUpCmd.slashingdb:
      case slashingdbCmd* {.command.}: SlashProtCmd
      of SlashProtCmd.`import`:
        importedInterchangeFile* {.
          desc: "EIP-3076 slashing protection interchange file to import"
          argument .}: InputFile
      of SlashProtCmd.`export`:
        exportedValidators* {.
          desc: "Limit the export to specific validators " &
                "(specified as numeric indices or public keys)"
          abbr: "v"
          name: "validator" }: seq[PubKey0x]
        exportedInterchangeFile* {.
          desc: "EIP-3076 slashing protection interchange file to export"
          argument }: OutFile

    of BNStartUpCmd.trustedNodeSync:
      trustedNodeUrl* {.
        desc: "URL of the REST API to sync from"
        defaultValue: "http://localhost:5052"
        name: "trusted-node-url"
      .}: string

      blockId* {.
        desc: "Block id to sync to - this can be a block root, slot number, \"finalized\" or \"head\""
        defaultValue: "finalized"
      .}: string

      backfillBlocks* {.
        desc: "Backfill blocks directly from REST server instead of fetching via API"
        defaultValue: true
        name: "backfill"}: bool

  ValidatorClientConf* = object
    logLevel* {.
      desc: "Sets the log level"
      defaultValue: "INFO"
      name: "log-level" }: string

    logStdout* {.
      hidden
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-format" }: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written Json log file (deprecated)"
      name: "log-file" }: Option[OutFile]

    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data"
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
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

    keymanagerEnabled* {.
      desc: "Enable the REST keymanager API (BETA version)"
      defaultValue: false
      name: "keymanager" }: bool

    keymanagerPort* {.
      desc: "Listening port for the REST keymanager API"
      defaultValue: DefaultEth2RestPort
      defaultValueDesc: "5052"
      name: "keymanager-port" }: Port

    keymanagerAddress* {.
      desc: "Listening port for the REST keymanager API"
      defaultValue: defaultAdminListenAddress
      defaultValueDesc: "127.0.0.1"
      name: "keymanager-address" }: ValidIpAddress

    keymanagerTokenFile* {.
      desc: "A file specifying the authorizition token required for accessing the keymanager API"
      name: "keymanager-token-file" }: Option[InputFile]

    case cmd* {.
      command
      defaultValue: VCNoCommand }: VCStartUpCmd

    of VCNoCommand:
      graffiti* {.
        desc: "The graffiti value that will appear in proposed blocks. " &
              "You can use a 0x-prefixed hex encoded string to specify " &
              "raw bytes"
        name: "graffiti" }: Option[GraffitiBytes]

      stopAtEpoch* {.
        desc: "A positive epoch selects the epoch at which to stop"
        defaultValue: 0
        name: "stop-at-epoch" }: uint64

      beaconNodes* {.
        desc: "URL addresses to one or more beacon node HTTP REST APIs",
        name: "beacon-node" }: seq[string]

  SigningNodeConf* = object
    logLevel* {.
      desc: "Sets the log level"
      defaultValue: "INFO"
      name: "log-level" }: string

    logStdout* {.
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-stdout" }: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written Json log file"
      name: "log-file" }: Option[OutFile]

    nonInteractive* {.
      desc: "Do not display interative prompts. Quit on missing configuration"
      name: "non-interactive" }: bool

    dataDir* {.
      desc: "The directory where nimbus will store validator's keys"
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
      abbr: "d"
      name: "data-dir" }: OutDir

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" }: Option[InputDir]

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" }: Option[InputDir]

    serverIdent* {.
      desc: "Server identifier which will be used in HTTP Host header"
      name: "server-ident" }: Option[string]

    requestTimeout* {.
      desc: "Request timeout, maximum time that node will wait for remote " &
            "client request (in seconds)"
      defaultValue: defaultSigningNodeRequestTimeout
      name: "request-timeout" }: int

    case cmd* {.
      command
      defaultValue: SNNoCommand }: SNStartUpCmd

    of SNNoCommand:
      bindPort* {.
        desc: "Port for the REST (BETA version) HTTP server"
        defaultValue: DefaultEth2RestPort
        defaultValueDesc: "5052"
        name: "bind-port" }: Port

      bindAddress* {.
        desc: "Listening address of the REST (BETA version) HTTP server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: "127.0.0.1"
        name: "bind-address" }: ValidIpAddress

      tlsEnabled* {.
        desc: "Use secure TLS communication for REST (BETA version) server"
        defaultValue: false
        name: "tls" }: bool

      tlsCertificate* {.
        desc: "Path to SSL certificate file"
        name: "tls-cert" }: Option[InputFile]

      tlsPrivateKey* {.
        desc: "Path to SSL ceritificate's private key"
        name: "tls-key" }: Option[InputFile]

  AnyConf* = BeaconNodeConf | ValidatorClientConf | SigningNodeConf

proc defaultDataDir*(config: AnyConf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  getHomeDir() / dataDir / "BeaconNode"

func dumpDir*(config: AnyConf): string =
  config.dataDir / "dump"

func dumpDirInvalid*(config: AnyConf): string =
  config.dumpDir / "invalid" # things that failed validation

func dumpDirIncoming*(config: AnyConf): string =
  config.dumpDir / "incoming" # things that couldn't be validated (missingparent etc)

func dumpDirOutgoing*(config: AnyConf): string =
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

func parseCmdArg*(T: type PubKey0x, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  PubKey0x(hexToPaddedByteArray[RawPubKeySize](input.string))

func parseCmdArg*(T: type ValidatorPubKey, input: TaintedString): T
                 {.raises: [ValueError, Defect].} =
  let res = ValidatorPubKey.fromHex(input.string)
  if res.isErr(): raise (ref ValueError)(msg: $res.error())
  res.get()

func completeCmdArg*(T: type PubKey0x, input: TaintedString): seq[string] =
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

func validatorsDir*(config: AnyConf): string =
  string config.validatorsDirFlag.get(InputDir(config.dataDir / "validators"))

func secretsDir*(config: AnyConf): string =
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

func databaseDir*(config: AnyConf): string =
  config.dataDir / "db"

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)

proc loadEth2Network*(config: BeaconNodeConf): Eth2NetworkMetadata {.raises: [Defect, IOError].} =
  network_name.set(2, labelValues = [config.eth2Network.get(otherwise = "mainnet")])
  if config.eth2Network.isSome:
    getMetadataForNetwork(config.eth2Network.get)
  else:
    when const_preset == "mainnet":
      mainnetMetadata
    else:
      # Presumably other configurations can have other defaults, but for now
      # this simplifies the flow
      echo "Must specify network on non-mainnet node"
      quit 1

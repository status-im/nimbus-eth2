# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[options, unicode, uri],
  metrics,

  chronicles, chronicles/options as chroniclesOptions,
  confutils, confutils/defs, confutils/std/net,
  confutils/toml/defs as confTomlDefs,
  confutils/toml/std/net as confTomlNet,
  confutils/toml/std/uri as confTomlUri,
  serialization/errors, stew/shims/net as stewNet,
  stew/[io2, byteutils], unicodedb/properties, normalize,
  eth/common/eth_types as commonEthTypes, eth/net/nat,
  eth/p2p/discoveryv5/enr,
  json_serialization, web3/[primitives, confutils_defs],
  kzg4844/kzg_ex,
  ./spec/[engine_authentication, keystore, network, crypto],
  ./spec/datatypes/base,
  ./networking/network_metadata,
  ./validators/slashing_protection_common,
  ./el/el_conf,
  ./filepath

from std/os import getHomeDir, parentDir, `/`
from std/strutils import parseBiggestUInt, replace
from fork_choice/fork_choice_types
  import ForkChoiceVersion
from consensus_object_pools/block_pools_types_light_client
  import LightClientDataImportMode

export
  uri, nat, enr,
  defaultEth2TcpPort, enabledLogLevel,
  defs, parseCmdArg, completeCmdArg, network_metadata,
  el_conf, network, BlockHashOrNumber,
  confTomlDefs, confTomlNet, confTomlUri,
  LightClientDataImportMode

declareGauge network_name, "network name", ["name"]

const
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  defaultListenAddress* = (static parseIpAddress("0.0.0.0"))
  defaultAdminListenAddress* = (static parseIpAddress("127.0.0.1"))
  defaultSigningNodeRequestTimeout* = 60
  defaultBeaconNode* = "http://127.0.0.1:" & $defaultEth2RestPort
  defaultBeaconNodeUri* = parseUri(defaultBeaconNode)
  defaultGasLimit* = 30_000_000

  defaultListenAddressDesc* = $defaultListenAddress
  defaultAdminListenAddressDesc* = $defaultAdminListenAddress
  defaultBeaconNodeDesc = $defaultBeaconNode

when defined(windows):
  {.pragma: windowsOnly.}
  {.pragma: posixOnly, hidden.}
else:
  {.pragma: windowsOnly, hidden.}
  {.pragma: posixOnly.}

type
  BNStartUpCmd* {.pure.} = enum
    noCommand
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

  HistoryMode* {.pure.} = enum
    Archive = "archive"
    Prune = "prune"

  SlashProtCmd* = enum
    `import` = "Import a EIP-3076 slashing protection interchange file"
    `export` = "Export a EIP-3076 slashing protection interchange file"
    # migrateAll = "Export and remove the whole validator slashing protection DB."
    # migrate = "Export and remove specified validators from Nimbus."

  ImportMethod* {.pure.} = enum
    Normal = "normal"
    SingleSalt = "single-salt"

  BlockMonitoringType* {.pure.} = enum
    Disabled = "disabled"
    Poll = "poll"
    Event = "event"

  Web3SignerUrl* = object
    url*: Uri
    provenBlockProperties*: seq[string] # empty if this is not a verifying Web3Signer

  BeaconNodeConf* = object
    configFile* {.
      desc: "Loads the configuration from a TOML file"
      name: "config-file" .}: Option[InputFile]

    logLevel* {.
      desc: "Sets the log level for process and topics (e.g. \"DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none\")"
      defaultValue: "INFO"
      name: "log-level" .}: string

    logStdout* {.
      hidden
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-format" .}: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written JSON log file (deprecated)"
      name: "log-file" .}: Option[OutFile]

    eth2Network* {.
      desc: "The Eth2 network to join"
      defaultValueDesc: "mainnet"
      name: "network" .}: Option[string]

    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data"
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
      abbr: "d"
      name: "data-dir" .}: OutDir

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" .}: Option[InputDir]

    verifyingWeb3Signers* {.
      desc: "Remote Web3Signer URL that will be used as a source of validators"
      name: "verifying-web3-signer-url" .}: seq[Uri]

    provenBlockProperties* {.
      desc: "The field path of a block property that will be sent for verification to the verifying Web3Signer (for example \".execution_payload.fee_recipient\")"
      name: "proven-block-property" .}: seq[string]

    web3Signers* {.
      desc: "Remote Web3Signer URL that will be used as a source of validators"
      name: "web3-signer-url" .}: seq[Uri]

    web3signerUpdateInterval* {.
      desc: "Number of seconds between validator list updates"
      name: "web3-signer-update-interval"
      defaultValue: 3600 .}: Natural

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" .}: Option[InputDir]

    walletsDirFlag* {.
      desc: "A directory containing wallet files"
      name: "wallets-dir" .}: Option[InputDir]

    eraDirFlag* {.
      hidden
      desc: "A directory containing era files"
      name: "era-dir" .}: Option[InputDir]

    web3ForcePolling* {.
      hidden
      desc: "Force the use of polling when determining the head block of Eth1 (obsolete)"
      name: "web3-force-polling" .}: Option[bool]

    web3Urls* {.
      desc: "One or more execution layer Engine API URLs"
      name: "web3-url" .}: seq[EngineApiUrlConfigValue]

    elUrls* {.
      desc: "One or more execution layer Engine API URLs"
      name: "el" .}: seq[EngineApiUrlConfigValue]

    noEl* {.
      defaultValue: false
      desc: "Don't use an EL. The node will remain optimistically synced and won't be able to perform validator duties"
      name: "no-el" .}: bool

    optimistic* {.
      hidden # deprecated > 22.12
      desc: "Run the node in optimistic mode, allowing it to optimistically sync without an execution client (flag deprecated, always on)"
      name: "optimistic".}: Option[bool]

    requireEngineAPI* {.
      hidden  # Deprecated > 22.9
      desc: "Require Nimbus to be configured with an Engine API end-point after the Bellatrix fork epoch"
      name: "require-engine-api-in-bellatrix" .}: Option[bool]

    nonInteractive* {.
      desc: "Do not display interactive prompts. Quit on missing configuration"
      name: "non-interactive" .}: bool

    netKeyFile* {.
      desc: "Source of network (secp256k1) private key file " &
            "(random|<path>)"
      defaultValue: "random",
      name: "netkey-file" .}: string

    netKeyInsecurePassword* {.
      desc: "Use pre-generated INSECURE password for network private key file"
      defaultValue: false,
      name: "insecure-netkey-password" .}: bool

    agentString* {.
      defaultValue: "nimbus",
      desc: "Node agent string which is used as identifier in network"
      name: "agent-string" .}: string

    subscribeAllSubnets* {.
      defaultValue: false,
      desc: "Subscribe to all subnet topics when gossiping"
      name: "subscribe-all-subnets" .}: bool

    slashingDbKind* {.
      hidden
      defaultValue: SlashingDbKind.v2
      desc: "The slashing DB flavour to use"
      name: "slashing-db-kind" .}: SlashingDbKind

    numThreads* {.
      defaultValue: 0,
      desc: "Number of worker threads (\"0\" = use as many threads as there are CPU cores available)"
      name: "num-threads" .}: int

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/authentication.md#key-distribution
    jwtSecret* {.
      desc: "A file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens"
      name: "jwt-secret" .}: Option[InputFile]

    case cmd* {.
      command
      defaultValue: BNStartUpCmd.noCommand .}: BNStartUpCmd

    of BNStartUpCmd.noCommand:
      runAsServiceFlag* {.
        windowsOnly
        defaultValue: false,
        desc: "Run as a Windows service"
        name: "run-as-service" .}: bool

      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network"
        abbr: "b"
        name: "bootstrap-node" .}: seq[string]

      bootstrapNodesFile* {.
        desc: "Specifies a line-delimited file of bootstrap Ethereum network addresses"
        defaultValue: ""
        name: "bootstrap-file" .}: InputFile

      listenAddress* {.
        desc: "Listening address for the Ethereum LibP2P and Discovery v5 traffic"
        defaultValue: defaultListenAddress
        defaultValueDesc: $defaultListenAddressDesc
        name: "listen-address" .}: IpAddress

      tcpPort* {.
        desc: "Listening TCP port for Ethereum LibP2P traffic"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: $defaultEth2TcpPortDesc
        name: "tcp-port" .}: Port

      udpPort* {.
        desc: "Listening UDP port for node discovery"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: $defaultEth2TcpPortDesc
        name: "udp-port" .}: Port

      maxPeers* {.
        desc: "The target number of peers to connect to"
        defaultValue: 160 # 5 (fanout) * 64 (subnets) / 2 (subs) for a heathy mesh
        name: "max-peers" .}: int

      hardMaxPeers* {.
        desc: "The maximum number of peers to connect to. Defaults to maxPeers * 1.5"
        name: "hard-max-peers" .}: Option[int]

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

      enableYamux* {.
        hidden
        desc: "Enable the Yamux multiplexer"
        defaultValue: false
        name: "enable-yamux" .}: bool

      weakSubjectivityCheckpoint* {.
        desc: "Weak subjectivity checkpoint in the format block_root:epoch_number"
        name: "weak-subjectivity-checkpoint" .}: Option[Checkpoint]

      externalBeaconApiUrl* {.
        desc: "External beacon API to use for syncing (on empty database)"
        name: "external-beacon-api-url" .}: Option[string]

      syncLightClient* {.
        desc: "Accelerate sync using light client"
        defaultValue: true
        name: "sync-light-client" .}: bool

      trustedBlockRoot* {.
        desc: "Recent trusted finalized block root to sync from external " &
              "beacon API (with `--external-beacon-api-url`). " &
              "Uses the light client sync protocol to obtain the latest " &
              "finalized checkpoint (LC is initialized from trusted block root)"
        name: "trusted-block-root" .}: Option[Eth2Digest]

      trustedStateRoot* {.
        desc: "Recent trusted finalized state root to sync from external " &
              "beacon API (with `--external-beacon-api-url`)"
        name: "trusted-state-root" .}: Option[Eth2Digest]

      finalizedCheckpointState* {.
        desc: "SSZ file specifying a recent finalized state"
        name: "finalized-checkpoint-state" .}: Option[InputFile]

      genesisState* {.
        desc: "SSZ file specifying the genesis state of the network (for networks without a built-in genesis state)"
        name: "genesis-state" .}: Option[InputFile]

      genesisStateUrl* {.
        desc: "URL for obtaining the genesis state of the network (for networks without a built-in genesis state)"
        name: "genesis-state-url" .}: Option[Uri]

      finalizedDepositTreeSnapshot* {.
        desc: "SSZ file specifying a recent finalized EIP-4881 deposit tree snapshot"
        name: "finalized-deposit-tree-snapshot" .}: Option[InputFile]

      finalizedCheckpointBlock* {.
        hidden
        desc: "SSZ file specifying a recent finalized block"
        name: "finalized-checkpoint-block" .}: Option[InputFile]

      nodeName* {.
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be selected for each --data-dir folder"
        defaultValue: ""
        name: "node-name" .}: string

      graffiti* {.
        desc: "The graffiti value that will appear in proposed blocks. " &
              "You can use a 0x-prefixed hex encoded string to specify raw bytes"
        name: "graffiti" .}: Option[GraffitiBytes]

      strictVerification* {.
        hidden
        desc: "Specify whether to verify finalization occurs on schedule (debug only)"
        defaultValue: false
        name: "verify-finalization" .}: bool

      stopAtEpoch* {.
        hidden
        desc: "The wall-time epoch at which to exit the program. (for testing purposes)"
        defaultValue: 0
        name: "debug-stop-at-epoch" .}: uint64

      stopAtSyncedEpoch* {.
        hidden
        desc: "The synced epoch at which to exit the program. (for testing purposes)"
        defaultValue: 0
        name: "stop-at-synced-epoch" .}: uint64

      metricsEnabled* {.
        desc: "Enable the metrics server"
        defaultValue: false
        name: "metrics" .}: bool

      metricsAddress* {.
        desc: "Listening address of the metrics server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "metrics-address" .}: IpAddress

      metricsPort* {.
        desc: "Listening HTTP port of the metrics server"
        defaultValue: 8008
        name: "metrics-port" .}: Port

      statusBarEnabled* {.
        posixOnly
        desc: "Display a status bar at the bottom of the terminal screen"
        defaultValue: true
        name: "status-bar" .}: bool

      statusBarContents* {.
        posixOnly
        desc: "Textual template for the contents of the status bar"
        defaultValue: "peers: $connected_peers;" &
                      "finalized: $finalized_root:$finalized_epoch;" &
                      "head: $head_root:$head_epoch:$head_epoch_slot;" &
                      "time: $epoch:$epoch_slot ($slot);" &
                      "sync: $sync_status|" &
                      "ETH: $attached_validators_balance"
        defaultValueDesc: ""
        name: "status-bar-contents" .}: string

      rpcEnabled* {.
        # Deprecated > 1.7.0
        hidden
        desc: "Deprecated for removal"
        name: "rpc" .}: Option[bool]

      rpcPort* {.
        # Deprecated > 1.7.0
        hidden
        desc: "Deprecated for removal"
        name: "rpc-port" .}: Option[Port]

      rpcAddress* {.
        # Deprecated > 1.7.0
        hidden
        desc: "Deprecated for removal"
        name: "rpc-address" .}: Option[IpAddress]

      restEnabled* {.
        desc: "Enable the REST server"
        defaultValue: false
        name: "rest" .}: bool

      restPort* {.
        desc: "Port for the REST server"
        defaultValue: defaultEth2RestPort
        defaultValueDesc: $defaultEth2RestPortDesc
        name: "rest-port" .}: Port

      restAddress* {.
        desc: "Listening address of the REST server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "rest-address" .}: IpAddress

      restAllowedOrigin* {.
        desc: "Limit the access to the REST API to a particular hostname " &
              "(for CORS-enabled clients such as browsers)"
        name: "rest-allow-origin" .}: Option[string]

      restCacheSize* {.
        defaultValue: 3
        desc: "The maximum number of recently accessed states that are kept in " &
              "memory. Speeds up requests obtaining information for consecutive " &
              "slots or epochs."
        name: "rest-statecache-size" .}: Natural

      restCacheTtl* {.
        defaultValue: 60
        desc: "The number of seconds to keep recently accessed states in memory"
        name: "rest-statecache-ttl" .}: Natural

      restRequestTimeout* {.
        defaultValue: 0
        defaultValueDesc: "infinite"
        desc: "The number of seconds to wait until complete REST request " &
              "will be received"
        name: "rest-request-timeout" .}: Natural

      restMaxRequestBodySize* {.
        defaultValue: 16_384
        desc: "Maximum size of REST request body (kilobytes)"
        name: "rest-max-body-size" .}: Natural

      restMaxRequestHeadersSize* {.
        defaultValue: 128
        desc: "Maximum size of REST request headers (kilobytes)"
        name: "rest-max-headers-size" .}: Natural
        ## NOTE: If you going to adjust this value please check value
        ## ``ClientMaximumValidatorIds`` and comments in
        ## `spec/eth2_apis/rest_types.nim`. This values depend on each other.

      keymanagerEnabled* {.
        desc: "Enable the REST keymanager API"
        defaultValue: false
        name: "keymanager" .}: bool

      keymanagerPort* {.
        desc: "Listening port for the REST keymanager API"
        defaultValue: defaultEth2RestPort
        defaultValueDesc: $defaultEth2RestPortDesc
        name: "keymanager-port" .}: Port

      keymanagerAddress* {.
        desc: "Listening port for the REST keymanager API"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "keymanager-address" .}: IpAddress

      keymanagerAllowedOrigin* {.
        desc: "Limit the access to the Keymanager API to a particular hostname " &
              "(for CORS-enabled clients such as browsers)"
        name: "keymanager-allow-origin" .}: Option[string]

      keymanagerTokenFile* {.
        desc: "A file specifying the authorization token required for accessing the keymanager API"
        name: "keymanager-token-file" .}: Option[InputFile]

      lightClientDataServe* {.
        desc: "Serve data for enabling light clients to stay in sync with the network"
        defaultValue: true
        name: "light-client-data-serve" .}: bool

      lightClientDataImportMode* {.
        desc: "Which classes of light client data to import. " &
              "Must be one of: none, only-new, full (slow startup), on-demand (may miss validator duties)"
        defaultValue: LightClientDataImportMode.OnlyNew
        defaultValueDesc: $LightClientDataImportMode.OnlyNew
        name: "light-client-data-import-mode" .}: LightClientDataImportMode

      lightClientDataMaxPeriods* {.
        desc: "Maximum number of sync committee periods to retain light client data"
        name: "light-client-data-max-periods" .}: Option[uint64]

      inProcessValidators* {.
        desc: "Disable the push model (the beacon node tells a signing process with the private keys of the validators what to sign and when) and load the validators in the beacon node itself"
        defaultValue: true # the use of the nimbus_signing_process binary by default will be delayed until async I/O over stdin/stdout is developed for the child process.
        name: "in-process-validators" .}: bool

      discv5Enabled* {.
        desc: "Enable Discovery v5"
        defaultValue: true
        name: "discv5" .}: bool

      dumpEnabled* {.
        desc: "Write SSZ dumps of blocks, attestations and states to data dir"
        defaultValue: false
        name: "dump" .}: bool

      directPeers* {.
        desc: "The list of privileged, secure and known peers to connect and maintain the connection to. This requires a not random netkey-file. In the multiaddress format like: /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>, or enr format (enr:-xx). Peering agreements are established out of band and must be reciprocal"
        name: "direct-peer" .}: seq[string]

      doppelgangerDetection* {.
        desc: "If enabled, the beacon node prudently listens for 2 epochs for attestations from a validator with the same index (a doppelganger), before sending an attestation itself. This protects against slashing (due to double-voting) but means you will miss two attestations when restarting."
        defaultValue: true
        name: "doppelganger-detection" .}: bool

      syncHorizon* {.
        hidden
        desc: "Number of empty slots to process before considering the client out of sync"
        defaultValue: MaxEmptySlotCount
        defaultValueDesc: "50"
        name: "sync-horizon" .}: uint64

      terminalTotalDifficultyOverride* {.
        hidden
        desc: "Deprecated for removal"
        name: "terminal-total-difficulty-override" .}: Option[string]

      validatorMonitorAuto* {.
        desc: "Monitor validator activity automatically for validators active on this beacon node"
        defaultValue: true
        name: "validator-monitor-auto" .}: bool

      validatorMonitorPubkeys* {.
        desc: "One or more validators to monitor - works best when --subscribe-all-subnets is enabled"
        name: "validator-monitor-pubkey" .}: seq[ValidatorPubKey]

      validatorMonitorDetails* {.
        desc: "Publish detailed metrics for each validator individually - may incur significant overhead with large numbers of validators"
        defaultValue: false
        name: "validator-monitor-details" .}: bool

      validatorMonitorTotals* {.
        hidden
        desc: "Deprecated in favour of --validator-monitor-details"
        name: "validator-monitor-totals" .}: Option[bool]

      safeSlotsToImportOptimistically* {.
        # Never unhidden or documented, and deprecated > 22.9.1
        hidden
        desc: "Deprecated for removal"
        name: "safe-slots-to-import-optimistically" .}: Option[uint16]

      # Same option as appears in Lighthouse and Prysm
      # https://lighthouse-book.sigmaprime.io/suggested-fee-recipient.html
      # https://github.com/prysmaticlabs/prysm/pull/10312
      suggestedFeeRecipient* {.
        desc: "Suggested fee recipient"
        name: "suggested-fee-recipient" .}: Option[Address]

      suggestedGasLimit* {.
        desc: "Suggested gas limit"
        defaultValue: defaultGasLimit
        name: "suggested-gas-limit" .}: uint64

      payloadBuilderEnable* {.
        desc: "Enable external payload builder"
        defaultValue: false
        name: "payload-builder" .}: bool

      payloadBuilderUrl* {.
        desc: "Payload builder URL"
        defaultValue: ""
        name: "payload-builder-url" .}: string

      # Flag name and semantics borrowed from Prysm
      # https://github.com/prysmaticlabs/prysm/pull/12227/files
      localBlockValueBoost* {.
        desc: "Increase execution layer block values for builder bid comparison by a percentage"
        defaultValue: 0
        name: "local-block-value-boost" .}: uint8

      historyMode* {.
        desc: "Retention strategy for historical data (archive/prune)"
        defaultValue: HistoryMode.Prune
        name: "history".}: HistoryMode

      # https://notes.ethereum.org/@bbusa/dencun-devnet-6
      # "Please ensure that there is a way for us to specify the file through a
      # runtime flag such as --trusted-setup-file (or similar)."
      trustedSetupFile* {.
        hidden
        desc: "Experimental, debug option; could disappear at any time without warning"
        name: "temporary-debug-trusted-setup-file" .}: Option[string]

      bandwidthEstimate* {.
        hidden
        desc: "Bandwidth estimate for the node (bits per second)"
        name: "debug-bandwidth-estimate" .}: Option[Natural]

      forkChoiceVersion* {.
        hidden
        desc: "Forkchoice version to use. " &
              "Must be one of: stable"
        name: "debug-forkchoice-version" .}: Option[ForkChoiceVersion]

    of BNStartUpCmd.wallets:
      case walletsCmd* {.command.}: WalletsCmd
      of WalletsCmd.create:
        nextAccount* {.
          desc: "Initial value for the 'nextaccount' property of the wallet"
          name: "next-account" .}: Option[Natural]

        createdWalletNameFlag* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "name" .}: Option[WalletName]

        createdWalletFileFlag* {.
          desc: "Output wallet file"
          name: "out" .}: Option[OutFile]

      of WalletsCmd.restore:
        restoredWalletNameFlag* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "name" .}: Option[WalletName]

        restoredWalletFileFlag* {.
          desc: "Output wallet file"
          name: "out" .}: Option[OutFile]

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
          name: "count" .}: int

        existingWalletId* {.
          desc: "An existing wallet ID. If not specified, a new wallet will be created"
          name: "wallet" .}: Option[WalletName]

        outValidatorsDir* {.
          desc: "Output folder for validator keystores"
          defaultValue: "validators"
          name: "out-validators-dir" .}: string

        outSecretsDir* {.
          desc: "Output folder for randomly generated keystore passphrases"
          defaultValue: "secrets"
          name: "out-secrets-dir" .}: string

        outDepositsFile* {.
          desc: "The name of generated deposits file"
          name: "out-deposits-file" .}: Option[OutFile]

        newWalletNameFlag* {.
          desc: "An easy-to-remember name for the wallet of your choice"
          name: "new-wallet-name" .}: Option[WalletName]

        newWalletFileFlag* {.
          desc: "Output wallet file"
          name: "new-wallet-file" .}: Option[OutFile]

      #[
      of DepositsCmd.status:
        discard
      ]#

      of DepositsCmd.`import`:
        importedDepositsDir* {.
          argument
          desc: "A directory with keystores to import" .}: Option[InputDir]

        importMethod* {.
          desc: "Specifies which import method will be used (" &
                "normal, single-salt)"
          defaultValue: ImportMethod.Normal
          name: "method" .}: ImportMethod

      of DepositsCmd.exit:
        exitedValidators* {.
          desc: "One or more validator index, public key or a keystore path of " &
                "the exited validator(s)"
          name: "validator" .}: seq[string]

        exitAllValidatorsFlag* {.
          desc: "Exit all validators in the specified data directory or validators directory"
          defaultValue: false
          name: "all" .}: bool

        exitAtEpoch* {.
          name: "epoch"
          defaultValueDesc: "immediately"
          desc: "The desired exit epoch" .}: Option[uint64]

        restUrlForExit* {.
          desc: "URL of the beacon node REST service"
          defaultValue: defaultBeaconNode
          defaultValueDesc: $defaultBeaconNodeDesc
          name: "rest-url" .}: string

        printData* {.
          desc: "Print signed exit message instead of publishing it"
          defaultValue: false
          name: "print" .}: bool

    of BNStartUpCmd.record:
      case recordCmd* {.command.}: RecordCmd
      of RecordCmd.create:
        ipExt* {.
          desc: "External IP address"
          name: "ip" .}: IpAddress

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
          name: "url" .}: Uri

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
          name: "validator" .}: seq[PubKey0x]
        exportedInterchangeFile* {.
          desc: "EIP-3076 slashing protection interchange file to export"
          argument .}: OutFile

    of BNStartUpCmd.trustedNodeSync:
      trustedNodeUrl* {.
        desc: "URL of the REST API to sync from"
        defaultValue: defaultBeaconNode
        defaultValueDesc: $defaultBeaconNodeDesc
        name: "trusted-node-url"
      .}: string

      stateId* {.
        desc: "State id to sync to - this can be \"finalized\", a slot number or state hash or \"head\""
        name: "state-id"
      .}: Option[string]

      blockId* {.
        hidden
        desc: "Block id to sync to - this can be a block root, slot number, \"finalized\" or \"head\" (deprecated)"
      .}: Option[string]

      lcTrustedBlockRoot* {.
        desc: "Recent trusted finalized block root to initialize light client from"
        name: "trusted-block-root" .}: Option[Eth2Digest]

      backfillBlocks* {.
        desc: "Backfill blocks directly from REST server instead of fetching via API"
        defaultValue: true
        name: "backfill" .}: bool

      reindex* {.
        desc: "Recreate historical state index at end of backfill, allowing full history access (requires full backfill)"
        defaultValue: false .}: bool

      downloadDepositSnapshot* {.
        desc: "Also try to download a snapshot of the deposit contract state"
        defaultValue: false
        name: "with-deposit-snapshot" .}: bool

  ValidatorClientConf* = object
    configFile* {.
      desc: "Loads the configuration from a TOML file"
      name: "config-file" .}: Option[InputFile]

    logLevel* {.
      desc: "Sets the log level"
      defaultValue: "INFO"
      name: "log-level" .}: string

    logStdout* {.
      hidden
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-format" .}: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written JSON log file (deprecated)"
      name: "log-file" .}: Option[OutFile]

    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data"
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
      abbr: "d"
      name: "data-dir" .}: OutDir

    doppelgangerDetection* {.
      # TODO This description is shared between the BN and the VC.
      #      Extract it in a constant (confutils fix may be needed).
      desc: "If enabled, the validator client prudently listens for 2 epochs " &
            "for attestations from a validator with the same index " &
            "(a doppelganger), before sending an attestation itself. This " &
            "protects against slashing (due to double-voting) but means you " &
            "will miss two attestations when restarting."
      defaultValue: true
      name: "doppelganger-detection" .}: bool

    nonInteractive* {.
      desc: "Do not display interactive prompts. Quit on missing configuration"
      name: "non-interactive" .}: bool

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" .}: Option[InputDir]

    verifyingWeb3Signers* {.
      desc: "Remote Web3Signer URL that will be used as a source of validators"
      name: "verifying-web3-signer-url" .}: seq[Uri]

    provenBlockProperties* {.
      desc: "The field path of a block property that will be sent for verification to the verifying Web3Signer (for example \".execution_payload.fee_recipient\")"
      name: "proven-block-property" .}: seq[string]

    web3signerUpdateInterval* {.
      desc: "Number of seconds between validator list updates"
      name: "web3-signer-update-interval"
      defaultValue: 3600 .}: Natural

    web3Signers* {.
      desc: "Remote Web3Signer URL that will be used as a source of validators"
      name: "web3-signer-url" .}: seq[Uri]

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" .}: Option[InputDir]

    restRequestTimeout* {.
      defaultValue: 0
      defaultValueDesc: "infinite"
      desc: "The number of seconds to wait until complete REST request " &
            "will be received"
      name: "rest-request-timeout" .}: Natural

    restMaxRequestBodySize* {.
      defaultValue: 16_384
      desc: "Maximum size of REST request body (kilobytes)"
      name: "rest-max-body-size" .}: Natural

    restMaxRequestHeadersSize* {.
      defaultValue: 64
      desc: "Maximum size of REST request headers (kilobytes)"
      name: "rest-max-headers-size" .}: Natural

    # Same option as appears in Lighthouse and Prysm
    # https://lighthouse-book.sigmaprime.io/suggested-fee-recipient.html
    # https://github.com/prysmaticlabs/prysm/pull/10312
    suggestedFeeRecipient* {.
      desc: "Suggested fee recipient"
      name: "suggested-fee-recipient" .}: Option[Address]

    suggestedGasLimit* {.
      desc: "Suggested gas limit"
      defaultValue: 30_000_000
      name: "suggested-gas-limit" .}: uint64

    keymanagerEnabled* {.
      desc: "Enable the REST keymanager API"
      defaultValue: false
      name: "keymanager" .}: bool

    keymanagerPort* {.
      desc: "Listening port for the REST keymanager API"
      defaultValue: defaultEth2RestPort
      defaultValueDesc: $defaultEth2RestPortDesc
      name: "keymanager-port" .}: Port

    keymanagerAddress* {.
      desc: "Listening port for the REST keymanager API"
      defaultValue: defaultAdminListenAddress
      defaultValueDesc: $defaultAdminListenAddressDesc
      name: "keymanager-address" .}: IpAddress

    keymanagerAllowedOrigin* {.
      desc: "Limit the access to the Keymanager API to a particular hostname " &
            "(for CORS-enabled clients such as browsers)"
      name: "keymanager-allow-origin" .}: Option[string]

    keymanagerTokenFile* {.
      desc: "A file specifying the authorizition token required for accessing the keymanager API"
      name: "keymanager-token-file" .}: Option[InputFile]

    metricsEnabled* {.
      desc: "Enable the metrics server (BETA)"
      defaultValue: false
      name: "metrics" .}: bool

    metricsAddress* {.
      desc: "Listening address of the metrics server (BETA)"
      defaultValue: defaultAdminListenAddress
      defaultValueDesc: $defaultAdminListenAddressDesc
      name: "metrics-address" .}: IpAddress

    metricsPort* {.
      desc: "Listening HTTP port of the metrics server (BETA)"
      defaultValue: 8108
      name: "metrics-port" .}: Port

    graffiti* {.
      desc: "The graffiti value that will appear in proposed blocks. " &
            "You can use a 0x-prefixed hex encoded string to specify " &
            "raw bytes"
      name: "graffiti" .}: Option[GraffitiBytes]

    stopAtEpoch* {.
      desc: "A positive epoch selects the epoch at which to stop"
      defaultValue: 0
      name: "debug-stop-at-epoch" .}: uint64

    payloadBuilderEnable* {.
      desc: "Enable usage of beacon node with external payload builder (BETA)"
      defaultValue: false
      name: "payload-builder" .}: bool

    distributedEnabled* {.
      desc: "Enable usage of Obol middleware (BETA)"
      defaultValue: false
      name: "distributed".}: bool

    beaconNodes* {.
      desc: "URL addresses to one or more beacon node HTTP REST APIs",
      defaultValue: @[defaultBeaconNodeUri]
      defaultValueDesc: $defaultBeaconNodeUri
      name: "beacon-node" .}: seq[Uri]

    monitoringType* {.
      desc: "Enable block monitoring which are seen by beacon node (BETA)"
      defaultValue: BlockMonitoringType.Disabled
      name: "block-monitor-type".}: BlockMonitoringType

  SigningNodeConf* = object
    configFile* {.
      desc: "Loads the configuration from a TOML file"
      name: "config-file" .}: Option[InputFile]

    logLevel* {.
      desc: "Sets the log level"
      defaultValue: "INFO"
      name: "log-level" .}: string

    logStdout* {.
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-stdout" .}: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written JSON log file"
      name: "log-file" .}: Option[OutFile]

    nonInteractive* {.
      desc: "Do not display interactive prompts. Quit on missing configuration"
      name: "non-interactive" .}: bool

    dataDir* {.
      desc: "The directory where nimbus will store validator's keys"
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
      abbr: "d"
      name: "data-dir" .}: OutDir

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" .}: Option[InputDir]

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" .}: Option[InputDir]

    expectedFeeRecipient* {.
      desc: "Signatures for blocks will require proofs of the specified " &
            "fee recipient"
      name: "expected-fee-recipient".}: Option[Address]

    serverIdent* {.
      desc: "Server identifier which will be used in HTTP Host header"
      name: "server-ident" .}: Option[string]

    requestTimeout* {.
      desc: "Request timeout, maximum time that node will wait for remote " &
            "client request (in seconds)"
      defaultValue: defaultSigningNodeRequestTimeout
      name: "request-timeout" .}: int

    bindPort* {.
      desc: "Port for the REST HTTP server"
      defaultValue: defaultEth2RestPort
      defaultValueDesc: $defaultEth2RestPortDesc
      name: "bind-port" .}: Port

    bindAddress* {.
      desc: "Listening address of the REST HTTP server"
      defaultValue: defaultAdminListenAddress
      defaultValueDesc: $defaultAdminListenAddressDesc
      name: "bind-address" .}: IpAddress

    tlsEnabled* {.
      desc: "Use secure TLS communication for REST server"
      defaultValue: false
      name: "tls" .}: bool

    tlsCertificate* {.
      desc: "Path to SSL certificate file"
      name: "tls-cert" .}: Option[InputFile]

    tlsPrivateKey* {.
      desc: "Path to SSL ceritificate's private key"
      name: "tls-key" .}: Option[InputFile]

  AnyConf* = BeaconNodeConf | ValidatorClientConf | SigningNodeConf

proc defaultDataDir*[Conf](config: Conf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  getHomeDir() / dataDir / "BeaconNode"

func dumpDir(config: AnyConf): string =
  config.dataDir / "dump"

func dumpDirInvalid*(config: AnyConf): string =
  config.dumpDir / "invalid" # things that failed validation

func dumpDirIncoming*(config: AnyConf): string =
  config.dumpDir / "incoming" # things that couldn't be validated (missingparent etc)

func dumpDirOutgoing*(config: AnyConf): string =
  config.dumpDir / "outgoing" # things we produced

proc createDumpDirs*(config: BeaconNodeConf) =
  proc fail {.noreturn.} =
    raiseAssert "createDumpDirs should be used only in the right context"

  case config.cmd
  of BNStartUpCmd.noCommand:
    if config.dumpEnabled:
      if (let res = secureCreatePath(config.dumpDirInvalid); res.isErr):
        warn "Could not create dump directory",
          path = config.dumpDirInvalid, err = ioErrorMsg(res.error)
      if (let res = secureCreatePath(config.dumpDirIncoming); res.isErr):
        warn "Could not create dump directory",
          path = config.dumpDirIncoming, err = ioErrorMsg(res.error)
      if (let res = secureCreatePath(config.dumpDirOutgoing); res.isErr):
        warn "Could not create dump directory",
          path = config.dumpDirOutgoing, err = ioErrorMsg(res.error)
  else: fail()

func parseCmdArg*(T: type Eth2Digest, input: string): T
                 {.raises: [ValueError].} =
  Eth2Digest.fromHex(input)

func completeCmdArg*(T: type Eth2Digest, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type GraffitiBytes, input: string): T
                 {.raises: [ValueError].} =
  GraffitiBytes.init(input)

func completeCmdArg*(T: type GraffitiBytes, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type BlockHashOrNumber, input: string): T
                 {.raises: [ValueError].} =
  init(BlockHashOrNumber, input)

func completeCmdArg*(T: type BlockHashOrNumber, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type Uri, input: string): T
                 {.raises: [ValueError].} =
  parseUri(input)

func completeCmdArg*(T: type Uri, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type PubKey0x, input: string): T
                 {.raises: [ValueError].} =
  PubKey0x(hexToPaddedByteArray[RawPubKeySize](input))

func parseCmdArg*(T: type ValidatorPubKey, input: string): T
                 {.raises: [ValueError].} =
  let res = ValidatorPubKey.fromHex(input)
  if res.isErr(): raise (ref ValueError)(msg: $res.error())
  res.get()

func completeCmdArg*(T: type PubKey0x, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type Checkpoint, input: string): T
                 {.raises: [ValueError].} =
  let sepIdx = find(input, ':')
  if sepIdx == -1 or sepIdx == input.len - 1:
    raise newException(ValueError,
      "The weak subjectivity checkpoint must be provided in the `block_root:epoch_number` format")

  var root: Eth2Digest
  hexToByteArrayStrict(input.toOpenArray(0, sepIdx - 1), root.data)

  T(root: root, epoch: parseBiggestUInt(input[sepIdx + 1 .. ^1]).Epoch)

func completeCmdArg*(T: type Checkpoint, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type Epoch, input: string): T
                 {.raises: [ValueError].} =
  Epoch parseBiggestUInt(input)

func completeCmdArg*(T: type Epoch, input: string): seq[string] =
  return @[]

func isPrintable(rune: Rune): bool =
  # This can be eventually replaced by the `unicodeplus` package, but a single
  # proc does not justify the extra dependencies at the moment:
  # https://github.com/nitely/nim-unicodeplus
  # https://github.com/nitely/nim-segmentation
  rune == Rune(0x20) or unicodeCategory(rune) notin ctgC+ctgZ

func parseCmdArg*(T: type WalletName, input: string): T
                 {.raises: [ValueError].} =
  if input.len == 0:
    raise newException(ValueError, "The wallet name should not be empty")
  if input[0] == '_':
    raise newException(ValueError, "The wallet name should not start with an underscore")
  for rune in runes(input):
    if not rune.isPrintable:
      raise newException(ValueError, "The wallet name should consist only of printable characters")

  # From the Unicode Normalization FAQ (https://unicode.org/faq/normalization.html):
  # NFKC is the preferred form for identifiers, especially where there are security concerns
  # (see UTR #36 http://www.unicode.org/reports/tr36/)
  return T(toNFKC(input))

func completeCmdArg*(T: type WalletName, input: string): seq[string] =
  return @[]

proc parseCmdArg*(T: type enr.Record, p: string): T {.raises: [ValueError].} =
  if not fromURI(result, p):
    raise newException(ValueError, "Invalid ENR")

func completeCmdArg*(T: type enr.Record, val: string): seq[string] =
  return @[]

func validatorsDir*[Conf](config: Conf): string =
  string config.validatorsDirFlag.get(InputDir(config.dataDir / "validators"))

func secretsDir*[Conf](config: Conf): string =
  string config.secretsDirFlag.get(InputDir(config.dataDir / "secrets"))

func walletsDir*(config: BeaconNodeConf): string =
  string config.walletsDirFlag.get(InputDir(config.dataDir / "wallets"))

func eraDir*(config: BeaconNodeConf): string =
  # The era directory should be shared between networks of the same type..
  string config.eraDirFlag.get(InputDir(config.dataDir / "era"))

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22791
func outWalletName*(config: BeaconNodeConf): Option[WalletName] =
  proc fail {.noreturn.} =
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
{.pop.}

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22791
func outWalletFile*(config: BeaconNodeConf): Option[OutFile] =
  proc fail {.noreturn.} =
    raiseAssert "outWalletFile should be used only in the right context"

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
{.pop.}

func databaseDir*(dataDir: OutDir): string =
  dataDir / "db"

template databaseDir*(config: AnyConf): string =
  config.dataDir.databaseDir

func runAsService*(config: BeaconNodeConf): bool =
  case config.cmd
  of noCommand:
    config.runAsServiceFlag
  else:
    false

func web3SignerUrls*(conf: AnyConf): seq[Web3SignerUrl] =
  for url in conf.web3Signers:
    result.add Web3SignerUrl(url: url)

  for url in conf.verifyingWeb3Signers:
    result.add Web3SignerUrl(url: url,
                             provenBlockProperties: conf.provenBlockProperties)

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)

template raiseUnexpectedValue(r: var TomlReader, msg: string) =
  # TODO: We need to implement `raiseUnexpectedValue` for TOML,
  # so the correct line and column information can be included
  # in error messages:
  raise newException(SerializationError, msg)

proc readValue*(r: var TomlReader, value: var Epoch)
               {.raises: [SerializationError, IOError].} =
  value = Epoch r.parseInt(uint64)

proc readValue*(r: var TomlReader, value: var GraffitiBytes)
               {.raises: [SerializationError, IOError].} =
  try:
    value = GraffitiBytes.init(r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue("A printable string or 0x-prefixed hex-encoded raw bytes expected")

proc readValue*(r: var TomlReader, val: var NatConfig)
               {.raises: [SerializationError].} =
  val = try: parseCmdArg(NatConfig, r.readValue(string))
        except CatchableError as err:
          raise newException(SerializationError, err.msg)

proc readValue*(r: var TomlReader, a: var Eth2Digest)
               {.raises: [IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue("Hex string expected")

proc readValue*(reader: var TomlReader, value: var ValidatorPubKey)
               {.raises: [SerializationError].} =
  let keyAsString = try:
    reader.readValue(string)
  except CatchableError:
    raiseUnexpectedValue(reader, "A hex-encoded string expected")

  let key = ValidatorPubKey.fromHex(keyAsString)
  if key.isOk:
    value = key.get
  else:
    # TODO: Can we provide better diagnostic?
    raiseUnexpectedValue(reader, "Valid hex-encoded public key expected")

proc readValue*(r: var TomlReader, a: var PubKey0x)
               {.raises: [SerializationError].} =
  try:
    a = parseCmdArg(PubKey0x, r.readValue(string))
  except CatchableError:
    r.raiseUnexpectedValue("a 0x-prefixed hex-encoded string expected")

proc readValue*(r: var TomlReader, a: var WalletName)
               {.raises: [SerializationError].} =
  try:
    a = parseCmdArg(WalletName, r.readValue(string))
  except CatchableError:
    r.raiseUnexpectedValue("string expected")

proc readValue*(r: var TomlReader, a: var Address)
               {.raises: [SerializationError].} =
  try:
    a = parseCmdArg(Address, r.readValue(string))
  except CatchableError:
    r.raiseUnexpectedValue("string expected")

proc loadEth2Network*(eth2Network: Option[string]): Eth2NetworkMetadata =
  const defaultName =
    when const_preset == "gnosis":
      "gnosis"
    elif const_preset == "mainnet":
      "mainnet"
    else:
      "(unspecified)"
  network_name.set(2, labelValues = [eth2Network.get(otherwise = defaultName)])

  if eth2Network.isSome:
    getMetadataForNetwork(eth2Network.get)
  else:
    when const_preset == "gnosis":
      getMetadataForNetwork("gnosis")
    elif const_preset == "mainnet":
      getMetadataForNetwork("mainnet")
    else:
      # Presumably other configurations can have other defaults, but for now
      # this simplifies the flow
      fatal "Must specify network on non-mainnet node"
      quit 1

template loadEth2Network*(config: BeaconNodeConf): Eth2NetworkMetadata =
  loadEth2Network(config.eth2Network)

func defaultFeeRecipient*(conf: AnyConf): Opt[Eth1Address] =
  if conf.suggestedFeeRecipient.isSome:
    Opt.some conf.suggestedFeeRecipient.get
  else:
    # https://github.com/nim-lang/Nim/issues/19802
    (static(Opt.none Eth1Address))

proc loadJwtSecret(
    rng: var HmacDrbgContext,
    dataDir: string,
    jwtSecret: Opt[InputFile],
    allowCreate: bool): Opt[seq[byte]] =
  # Some Web3 endpoints aren't compatible with JWT, but if explicitly chosen,
  # use it regardless.
  if jwtSecret.isSome or allowCreate:
    let secret = rng.checkJwtSecret(dataDir, jwtSecret)
    if secret.isErr:
      fatal "Specified a JWT secret file which couldn't be loaded",
        err = secret.error
      quit 1

    Opt.some secret.get
  else:
    Opt.none seq[byte]

func configJwtSecretOpt*(jwtSecret: Option[InputFile]): Opt[InputFile] =
  if jwtSecret.isSome:
    Opt.some jwtSecret.get
  else:
    Opt.none InputFile

proc loadJwtSecret*(
    rng: var HmacDrbgContext,
    config: BeaconNodeConf,
    allowCreate: bool): Opt[seq[byte]] =
  rng.loadJwtSecret(
    string(config.dataDir), config.jwtSecret.configJwtSecretOpt, allowCreate)

proc engineApiUrls*(config: BeaconNodeConf): seq[EngineApiUrl] =
  let elUrls = if config.noEl:
    return newSeq[EngineApiUrl]()
  elif config.elUrls.len == 0 and config.web3Urls.len == 0:
    @[getDefaultEngineApiUrl(config.jwtSecret)]
  else:
    config.elUrls

  (elUrls & config.web3Urls).toFinalEngineApiUrls(
    config.jwtSecret.configJwtSecretOpt)

proc loadKzgTrustedSetup*(): Result[void, string] =
  const
    vendorDir = currentSourcePath.parentDir.replace('\\', '/') & "/../vendor"
    trustedSetup = staticRead(
      vendorDir & "/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt")

  if const_preset == "mainnet" or const_preset == "minimal":
    Kzg.loadTrustedSetupFromString(trustedSetup)
  else:
    ok()

proc loadKzgTrustedSetup*(trustedSetupPath: string): Result[void, string] =
  try:
    Kzg.loadTrustedSetupFromString(readFile(trustedSetupPath))
  except IOError as err:
    err(err.msg)

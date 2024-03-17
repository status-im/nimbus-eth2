{.push raises: [].}

import
  std/[options, unicode, uri],
  confutils, confutils/defs, confutils/std/net,
  stew/[io2, byteutils],
  json_serialization, web3/[primitives, confutils_defs],
  ./spec/[keystore, network, crypto],
  ./spec/datatypes/base,
  ./networking/network_metadata,
  ./filepath

from std/os import getHomeDir, parentDir, `/`
from std/strutils import parseBiggestUInt, replace
export
  uri,
  defaultEth2TcpPort,
  defs, parseCmdArg, completeCmdArg, network_metadata,
  network

{.pragma: windowsOnly, hidden.}
{.pragma: posixOnly.}

type
  BNStartUpCmd* {.pure.} = enum
    noCommand
    deposits
    wallets
    web3
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
                      "head: $head_root:$head_epoch:$head_epoch_slot$next_consensus_fork;" &
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

    of BNStartUpCmd.wallets:
      case walletsCmd* {.command.}: WalletsCmd
      of WalletsCmd.create:
        nextAccount* {.
          desc: "Initial value for the 'nextaccount' property of the wallet"
          name: "next-account" .}: Option[Natural]

        createdWalletFileFlag* {.
          desc: "Output wallet file"
          name: "out" .}: Option[OutFile]

      of WalletsCmd.restore:
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

        printData* {.
          desc: "Print signed exit message instead of publishing it"
          defaultValue: false
          name: "print" .}: bool

    of BNStartUpCmd.web3:
      case web3Cmd* {.command.}: Web3Cmd
      of Web3Cmd.test:
        web3TestUrl* {.
          argument
          desc: "The web3 provider URL to test"
          name: "url" .}: Uri

    of BNStartUpCmd.trustedNodeSync:
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

  AnyConf* = BeaconNodeConf

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
        discard
      if (let res = secureCreatePath(config.dumpDirIncoming); res.isErr):
        discard
      if (let res = secureCreatePath(config.dumpDirOutgoing); res.isErr):
        discard
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

func parseCmdArg*(T: type Uri, input: string): T
                 {.raises: [ValueError].} =
  parseUri(input)

func completeCmdArg*(T: type Uri, input: string): seq[string] =
  return @[]

func parseCmdArg*(T: type ValidatorPubKey, input: string): T
                 {.raises: [ValueError].} =
  let res = ValidatorPubKey.fromHex(input)
  if res.isErr(): raise (ref ValueError)(msg: $res.error())
  res.get()

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

proc loadEth2Network*(eth2Network: Option[string]): Eth2NetworkMetadata =
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

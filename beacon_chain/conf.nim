import
  std/[options, unicode, uri],
  confutils, confutils/defs, confutils/std/net,
  stew/[io2, byteutils],
  json_serialization,
  ./spec/crypto,
  ./spec/datatypes/base

from std/os import getHomeDir, parentDir, `/`
from std/strutils import parseBiggestUInt, replace
export
  uri,
  defs, parseCmdArg, completeCmdArg

{.pragma: windowsOnly, hidden.}
{.pragma: posixOnly.}

type
  BNStartUpCmd* {.pure.} = enum
    noCommand

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

  AnyConf* = BeaconNodeConf

proc defaultDataDir*[Conf](config: Conf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  getHomeDir() / dataDir / "BeaconNode"

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

func validatorsDir*[Conf](config: Conf): string =
  string config.validatorsDirFlag.get(InputDir(config.dataDir / "validators"))

func secretsDir*[Conf](config: Conf): string =
  string config.secretsDirFlag.get(InputDir(config.dataDir / "secrets"))

func walletsDir*(config: BeaconNodeConf): string =
  string config.walletsDirFlag.get(InputDir(config.dataDir / "wallets"))

func eraDir*(config: BeaconNodeConf): string =
  # The era directory should be shared between networks of the same type..
  string config.eraDirFlag.get(InputDir(config.dataDir / "era"))

func databaseDir*(dataDir: OutDir): string =
  dataDir / "db"

template databaseDir*(config: AnyConf): string =
  config.dataDir.databaseDir

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)

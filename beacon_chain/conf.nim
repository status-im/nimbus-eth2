import
  os, options, strformat,
  confutils/defs, chronicles/options as chroniclesOptions,
  spec/[crypto, datatypes], time, version

export
  defs

const
  defaultPort = 9000

type
  ValidatorKeyPath* = TypedInputFile[ValidatorPrivKey, Txt, "privkey"]

  StartUpCommand* = enum
    noCommand
    importValidator
    createTestnet
    updateTestnet

  BeaconNodeConf* = object
    logLevel* {.
      desc: "Sets the log level",
      defaultValue: enabledLogLevel.}: LogLevel

    network* {.
      desc: "The network Nimbus should connect to. " &
            "Possible values: testnet0, testnet1, mainnet, custom-network.json"
      longform: "network"
      shortform: "n"
      defaultValue: "testnet0".}: string

    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data."
      shortform: "d"
      defaultValue: config.defaultDataDir().}: OutDir

    case cmd* {.
      command
      defaultValue: noCommand.}: StartUpCommand

    of noCommand:
      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network."
        longform: "bootstrapNode"
        shortform: "b".}: seq[string]

      bootstrapNodesFile* {.
        desc: "Specifies a line-delimited file of bootsrap Ethereum network addresses"
        shortform: "f"
        defaultValue: "".}: InputFile

      tcpPort* {.
        desc: "TCP listening port"
        defaultValue: defaultPort .}: int

      udpPort* {.
        desc: "UDP listening port",
        defaultValue: defaultPort .}: int

      nat* {.
        desc: "Specify method to use for determining public address. Must be one of: any, extip:<IP>"
        defaultValue: "any" .}: string

      validators* {.
        required
        desc: "Path to a validator private key, as generated by validator_keygen"
        longform: "validator"
        shortform: "v".}: seq[ValidatorKeyPath]

      stateSnapshot* {.
        desc: "Json file specifying a recent state snapshot"
        shortform: "s".}: Option[TypedInputFile[BeaconState, Json, "json"]]

      nodename* {.
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be seleceted for each --dataDir folder"
        defaultValue: ""}: string

    of createTestnet:
      networkId* {.
        desc: "An unique numeric identifier for the network".}: uint64

      validatorsDir* {.
        desc: "Directory containing validator descriptors named vXXXXXXX.deposit.json"
        shortform: "d".}: InputDir

      numValidators* {.
        desc: "The number of validators in the newly created chain".}: uint64

      firstValidator* {.
        desc: "Index of first validator to add to validator list"
        defaultValue: 0 .}: uint64

      firstUserValidator* {.
        desc: "The first validator index that will free for taking from a testnet participant"
        defaultValue: 0 .}: uint64

      bootstrapAddress* {.
        desc: "The public IP address that will be advertised as a bootstrap node for the testnet"
        defaultValue: "127.0.0.1".}: string

      bootstrapPort* {.
        desc: "The TCP/UDP port that will be used by the bootstrap node"
        defaultValue: defaultPort .}: int

      genesisOffset* {.
        desc: "Seconds from now to add to genesis time"
        shortForm: "g"
        defaultValue: 5 .}: int

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot".}: OutFile

      outputNetwork* {.
        desc: "Output file where to write the initial state snapshot".}: OutFile

    of importValidator:
      keyFiles* {.
        longform: "keyfile"
        desc: "File with validator key to be imported (in hex form)".}: seq[ValidatorKeyPath]

    of updateTestnet:
      discard

proc defaultDataDir*(conf: BeaconNodeConf): string =
  let dataDir = when defined(windows):
    "AppData" / "Roaming" / "Nimbus"
  elif defined(macosx):
    "Library" / "Application Support" / "Nimbus"
  else:
    ".cache" / "nimbus"

  let networkDir = if conf.network in ["testnet0", "testnet1", "mainnet"]:
    conf.network
  else:
    # TODO: This seems silly. Perhaps we should error out here and ask
    # the user to specify dataDir as well.
    "tempnet"

  getHomeDir() / dataDir / "BeaconNode" / networkDir

proc validatorFileBaseName*(validatorIdx: int): string =
  # there can apparently be tops 4M validators so we use 7 digits..
  fmt"v{validatorIdx:07}"


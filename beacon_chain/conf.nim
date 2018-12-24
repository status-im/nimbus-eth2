import
  os, options,
  confutils/defs, milagro_crypto, json_serialization,
  spec/[crypto, datatypes], randao, time

export
  json_serialization

type
  ValidatorKeyPath* = distinct string

  StartUpCommand* = enum
    noCommand
    createChain

  ChainStartupData* = object
    validatorDeposits*: seq[Deposit]
    genesisTime*: Timestamp

  PrivateValidatorData* = object
    privKey*: ValidatorPrivKey
    randao*: Randao

  BeaconNodeConf* = object
    case cmd* {.
      command
      defaultValue: noCommand.}: StartUpCommand

    of noCommand:
      dataDir* {.
        desc: "The directory where nimbus will store all blockchain data."
        shortform: "d"
        defaultValue: getConfigDir() / "nimbus".}: DirPath

      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network."
        longform: "bootstrapNode"
        shortform: "b".}: seq[string]

      bootstrapNodesFile* {.
        desc: "Specifies a line-delimited file of bootsrap Ethereum network addresses"
        shortform: "f"
        defaultValue: "".}: FilePath

      tcpPort* {.
        desc: "TCP listening port".}: int

      udpPort* {.
        desc: "UDP listening port".}: int

      validators* {.
        required
        desc: "A path to a pair of public and private keys for a validator. " &
              "Nimbus will automatically add the extensions .privkey and .pubkey."
        longform: "validator"
        shortform: "v".}: seq[PrivateValidatorData]

      stateSnapshot* {.
        desc: "Json file specifying a recent state snapshot"
        shortform: "s".}: Option[BeaconState]

    of createChain:
      chainStartupData* {.
        desc: ""
        shortform: "c".}: ChainStartupData

      outputStateFile* {.
        desc: "Output file where to write the initial state snapshot"
        longform: "out"
        shortform: "o".}: OutFilePath

proc readFileBytes(path: string): seq[byte] =
  cast[seq[byte]](readFile(path))

proc loadPrivKey*(p: ValidatorKeyPath): ValidatorPrivKey =
  initSigKey(readFileBytes(string(p) & ".privkey"))

proc loadRandao*(p: ValidatorKeyPath): Randao =
  initRandao(readFileBytes(string(p) & ".randao"))

proc parseCmdArg*(T: type ValidatorKeyPath, input: TaintedString): T =
  result = T(input)
  discard loadPrivKey(result)
  discard loadRandao(result)

template mustBeFilePath(input: TaintedString) =
  if not fileExists(string input):
    raise newException(ValueError, "")

template handledAsJsonFilename(T: untyped) {.dirty.} =
  proc parseCmdArg*(_: type T, input: TaintedString): T =
    input.mustBeFilePath
    #return Json.loadFile(string(input), T)

handledAsJsonFilename BeaconState
handledAsJsonFilename ChainStartupData
handledAsJsonFilename PrivateValidatorData


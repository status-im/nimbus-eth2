import
  tables, strutils, os,
  stew/shims/macros, nimcrypto/hash,
  web3/[ethtypes, conversions],
  chronicles,
  spec/presets,
  spec/datatypes,
  json_serialization,
  json_serialization/std/[options, sets, net], serialization/errors

# ATTENTION! This file will produce a large C file, because we are inlining
# genesis states as C literals in the generated code (and blobs in the final
# binary). It makes sense to keep the file small and separated from the rest
# of the module in order go gain maximum efficiency in incremental compilation.
#
# TODO:
# We can compress the embedded states with snappy before embedding them here.

{.push raises: [Defect].}

export
  ethtypes, conversions, RuntimePreset

type
  Eth1Address* = ethtypes.Address
  Eth1BlockHash* = ethtypes.BlockHash

  Eth1Network* = enum
    mainnet
    rinkeby
    goerli

  PresetIncompatible* = object of CatchableError

  Eth2NetworkMetadata* = object
    case incompatible*: bool
    of false:
      eth1Network*: Option[Eth1Network]
      runtimePreset*: RuntimePreset

      # Parsing `enr.Records` is still not possible at compile-time
      bootstrapNodes*: seq[string]

      depositContractAddress*: Eth1Address
      depositContractDeployedAt*: string

      # Please note that we are using `string` here because SSZ.decode
      # is not currently usable at compile time and we want to load the
      # network metadata into a constant.
      #
      # We could have also used `seq[byte]`, but this results in a lot
      # more generated code that slows down compilation. The impact on
      # compilation times of embedding the genesis as a string is roughly
      # 0.1s on my machine (you can test this by choosing an invalid name
      # for the genesis file below).
      #
      # `genesisData` will have `len == 0` for networks with a still
      # unknown genesis state.
      genesisData*: string
    else:
      incompatibilityDesc*: string

const presetValueLoaders = genExpr(nnkBracket):
  for constName in PresetValue:
    let
      constNameIdent = ident $constName
      constType = ident getType(constName)

    yield quote do:
      (
        proc (preset: var RuntimePreset, presetValue: string): bool
             {.gcsafe, noSideEffect, raises: [Defect].} =
          try:
            when PresetValue.`constNameIdent` in runtimeValues:
              preset.`constNameIdent` = parse(`constType`, presetValue)
              true
            elif PresetValue.`constNameIdent` in ignoredValues:
              true
            else:
              `constType`(`constNameIdent`) == parse(`constType`, presetValue)
          except CatchableError:
            false
      )

proc extractRuntimePreset*(configPath: string, configData: PresetFile): RuntimePreset
                          {.raises: [PresetIncompatible, Defect].} =
  result = RuntimePreset()

  for name, value in configData.values:
    if not presetValueLoaders[name.int](result, value):
      let errMsg = "The preset '" & configPath & "'is not compatible with " &
                   "the current build due to an incompatible value " &
                   $name & " = " & value.string
      raise newException(PresetIncompatible, errMsg)

proc loadEth2NetworkMetadata*(path: string): Eth2NetworkMetadata
                             {.raises: [CatchableError, Defect].} =
  try:
    let
      genesisPath = path / "genesis.ssz"
      configPath = path / "config.yaml"
      depositContractPath = path / "deposit_contract.txt"
      depositContractBlockPath = path / "deposit_contract_block.txt"
      bootstrapNodesPath = path / "bootstrap_nodes.txt"

      runtimePreset = if fileExists(configPath):
        extractRuntimePreset(configPath, readPresetFile(configPath))
      else:
        mainnetRuntimePreset

      depositContractAddress = if fileExists(depositContractPath):
        Eth1Address.fromHex readFile(depositContractPath).strip
      else:
        default(Eth1Address)

      depositContractBlock = if fileExists(depositContractBlockPath):
        readFile(depositContractBlockPath).strip
      else:
        ""

      bootstrapNodes = if fileExists(bootstrapNodesPath):
        readFile(bootstrapNodesPath).splitLines()
      else:
        @[]

      genesisData = if fileExists(genesisPath): readFile(genesisPath)
                    else: ""

    Eth2NetworkMetadata(
      incompatible: false,
      eth1Network: some goerli,
      runtimePreset: runtimePreset,
      bootstrapNodes: bootstrapNodes,
      depositContractAddress: depositContractAddress,
      depositContractDeployedAt: depositContractBlock,
      genesisData: genesisData)

  except PresetIncompatible as err:
    Eth2NetworkMetadata(incompatible: true,
                        incompatibilityDesc: err.msg)

const
  mainnetMetadata* = when const_preset == "mainnet":
    Eth2NetworkMetadata(
      incompatible: false, # TODO: This can be more accurate if we verify
                           # that there are no constant overrides
      eth1Network: some mainnet,
      runtimePreset: mainnetRuntimePreset,
      # TODO The values below are just placeholders for now
      bootstrapNodes: @[],
      depositContractAddress: Eth1Address.fromHex "0x1234567890123456789012345678901234567890",
      depositContractDeployedAt: "0",
      genesisData: "")
  else:
    Eth2NetworkMetadata(
      incompatible: true,
      incompatibilityDesc: "This build is compiled with the " & const_preset & " const preset. " &
                           "It's not compatible with mainnet")

const
  altonaMetadata* = loadEth2NetworkMetadata(
    currentSourcePath.parentDir / ".." / "vendor" / "eth2-testnets" / "shared" / "altona")

  medallaMetadata* = loadEth2NetworkMetadata(
    currentSourcePath.parentDir / ".." / "vendor" / "eth2-testnets" / "shared" / "medalla")

  testnet0Metadata* = loadEth2NetworkMetadata(
    currentSourcePath.parentDir / ".." / "vendor" / "eth2-testnets" / "nimbus" / "testnet0")

  testnet1Metadata* = loadEth2NetworkMetadata(
    currentSourcePath.parentDir / ".." / "vendor" / "eth2-testnets" / "nimbus" / "testnet1")

{.pop.} # the following pocedures raise more than just `Defect`

proc getMetadataForNetwork*(eth2Network: Option[string]):
                            Option[Eth2NetworkMetadata] =
  if eth2Network.isSome:
    let
      networkName = eth2Network.get
      metadata = case toLowerAscii(networkName)
        of "mainnet":
          mainnetMetadata
        of "altona":
          altonaMetadata
        of "medalla":
          medallaMetadata
        of "testnet0":
          testnet0Metadata
        of "testnet1":
          testnet1Metadata
        else:
          if fileExists(networkName):
            try:
              Json.loadFile(networkName, Eth2NetworkMetadata)
            except SerializationError as err:
              echo err.formatMsg(networkName)
              quit 1
          else:
            fatal "Unrecognized network name", networkName
            quit 1

    if metadata.incompatible:
      fatal "The selected network is not compatible with the current build",
             reason = metadata.incompatibilityDesc
      quit 1
    return some metadata

proc getRuntimePresetForNetwork*(eth2Network: Option[string]):
                                 RuntimePreset =
  let metadata = getMetadataForNetwork(eth2Network)
  return if metadata.isSome:
    metadata.get.runtimePreset
  else:
    defaultRuntimePreset

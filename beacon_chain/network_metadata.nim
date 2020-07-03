import
  os, strutils,
  stew/byteutils, stew/shims/macros, nimcrypto/hash,
  eth/common/[eth_types, eth_types_json_serialization],
  spec/presets/custom

# ATTENTION! This file will produce a large C file, because we are inlining
# genesis states as C literals in the generated code (and blobs in the final
# binary). It makes sense to keep the file small and separated from the rest
# of the module in order go gain maximum efficiency in incremental compilation.
#
# TODO:
# We can compress the embedded states with snappy before embedding them here.

{.push raises: [Defect].}

export
  eth_types_json_serialization

type
  Eth1Address* = eth_types.EthAddress
  Eth1BlockHash* = eth_types.Hash256

  Eth1Network* = enum
    mainnet
    rinkeby
    goerli

  Eth2Network* = enum
    customEth2Network
    altona

  PresetIncompatible* = object of CatchableError

  Eth2NetworkMetadata* = object
    eth1Network*: Eth1Network
    runtimePreset*: RuntimePreset

    # Parsing `enr.Records` is still not possible at compile-time
    bootstrapNodes*: seq[string]

    depositContractAddress*: Eth1Address
    depositContractDeployedAt*: Eth1BlockHash

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

const presetValueLoaders = genCode(nnkBracket):
  for constName in PresetValue:
    let
      constNameIdent = ident $constName
      constType = ident getType(constName)

    yield quote do:
      proc (preset: RuntimePreset, presetValue: string): bool
           {.gcsafe, noSideEffect, raises: [Defect].} =
        try:
          when `constNameIdent` in runtimeValues:
            preset.`constNameIdent` = parse(`constType`, presetValue)
            true
          else:
            `constNameIdent` == parse(`constType`, presetValue)
        except CatchableError:
          false

proc loadEth2NetworkMetadata*(path: string): Eth2NetworkMetadata
                             {.raises: [CatchableError, Defect].} =
  let
    genesisPath = path / "genesis.ssz"
    config = readPresetFile(path / "config.yaml")

  var runtimePreset = RuntimePreset()

  for name, value in config.values:
    if name notin runtimeValues:
      if not presetValueLoaders[name](runtimePreset, value):
        raise newException(PresetIncompatible,
          "The preset '{path}' is not compatible with the current build due to an incompatible value {name} = {value}")

  Eth2NetworkMetadata(
    eth1Network: goerli,
    runtimePreset: runtimePreset,
    bootstrapNodes: readFile(path / "bootstrap_nodes.txt").split("\n"),
    depositContractAddress: Eth1Address.fromHex readFile(path / "deposit_contract.txt").strip,
    depositContractDeployedAt: Eth1BlockHash.fromHex readFile(path / "deposit_contract_block.txt").strip,
    genesisData: if fileExists(genesisPath): readFile(genesisPath) else: "")

const
  mainnetMetadata* = Eth2NetworkMetadata(
    eth1Network: mainnet,
    runtimePreset: RuntimePreset(
      MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 16384,
      MIN_GENESIS_TIME: 1578009600,
      GENESIS_FORK_VERSION: [byte 0, 0, 0, 0],
      GENESIS_DELAY: 172800),
    # TODO The values below are just placeholders for now
    bootstrapNodes: @[],
    depositContractAddress: "0x1234567890123456789012345678901234567890",
    depositContractDeployedAt: "",
    genesisData: "")

  altonaMetadata* = loadEth2NetworkMetadata(
    currentSourcePath.parentDir / ".." / "vendor" / "eth2-testnets" / "shared" / "altona")


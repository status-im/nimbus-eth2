import
  os, strutils,
  stew/byteutils, nimcrypto/hash,
  eth/common/[eth_types, eth_types_json_serialization]

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

  Eth2NetworkMetadata* = object
    eth1Network*: Eth1Network

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

proc loadEth2NetworkMetadata*(path: string): Eth2NetworkMetadata
                             {.raises: [CatchableError, Defect].} =
  let
    genesisPath = path / "genesis.ssz"

  Eth2NetworkMetadata(
    eth1Network: goerli,
    bootstrapNodes: readFile(path / "bootstrap_nodes.txt").split("\n"),
    depositContractAddress: Eth1Address.fromHex readFile(path / "deposit_contract.txt").strip,
    depositContractDeployedAt: Eth1BlockHash.fromHex readFile(path / "deposit_contract_block.txt").strip,
    genesisData: if fileExists(genesisPath): readFile(genesisPath) else: "")

const
  altonaMetadata* = loadEth2NetworkMetadata(
    currentSourcePath.parentDir / ".." / "vendor" / "eth2-testnets" / "shared" / "altona")


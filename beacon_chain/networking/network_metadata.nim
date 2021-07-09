# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  tables, strutils, os,
  stew/shims/macros, nimcrypto/hash,
  eth/common/eth_types as commonEthTypes,
  web3/[ethtypes, conversions],
  chronicles,
  json_serialization,
  json_serialization/std/[options, sets, net], serialization/errors,
  ../ssz/navigator,
  eth/common/eth_types_json_serialization,
  ../spec/[presets, datatypes, digest]

# ATTENTION! This file will produce a large C file, because we are inlining
# genesis states as C literals in the generated code (and blobs in the final
# binary). It makes sense to keep the file small and separated from the rest
# of the module in order go gain maximum efficiency in incremental compilation.
#
# TODO(zah):
# We can compress the embedded states with snappy before embedding them here.

export
  ethtypes, conversions, RuntimeConfig

type
  Eth1BlockHash* = ethtypes.BlockHash

  Eth1Network* = enum
    mainnet
    rinkeby
    goerli

  Eth2NetworkMetadata* = object
    case incompatible*: bool
    of false:
      # TODO work-around a Nim codegen issue where upon constant assignment
      #      the compiler will copy `incompatibilityDesc` even when the case
      #      branch is not active and thus it will override the first variable
      #      in this branch.
      dummy: string
      eth1Network*: Option[Eth1Network]
      cfg*: RuntimeConfig

      # Parsing `enr.Records` is still not possible at compile-time
      bootstrapNodes*: seq[string]

      depositContractDeployedAt*: BlockHashOrNumber

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
      genesisDepositsSnapshot*: string
    else:
      incompatibilityDesc*: string

const
  eth2testnetsDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor/eth2-testnets"

proc loadEth2NetworkMetadata*(path: string): Eth2NetworkMetadata
                             {.raises: [CatchableError, Defect].} =
  # Load data in eth2-networks format
  # https://github.com/eth2-clients/eth2-networks/

  try:
    let
      genesisPath = path & "/genesis.ssz"
      genesisDepositsSnapshotPath = path & "/genesis_deposit_contract_snapshot.ssz"
      configPath = path & "/config.yaml"
      depositContractBlockPath = path & "/deposit_contract_block.txt"
      bootstrapNodesPath = path & "/bootstrap_nodes.txt"

      runtimeConfig = if fileExists(configPath):
        let (cfg, unknowns) = readRuntimeConfig(configPath)
        if unknowns.len > 0:
          when nimvm:
            # TODO better printing
            echo "Unknown constants in file: " & unknowns
          else:
            warn "Unknown constants in config file", unknowns
        cfg
      else:
        defaultRuntimeConfig

      depositContractBlock = if fileExists(depositContractBlockPath):
        readFile(depositContractBlockPath).strip
      else:
        ""

      depositContractDeployedAt = if depositContractBlock.len > 0:
        BlockHashOrNumber.init(depositContractBlock)
      else:
        BlockHashOrNumber(isHash: false, number: 1)

      bootstrapNodes = if fileExists(bootstrapNodesPath):
        readFile(bootstrapNodesPath).splitLines()
      elif "yeerongpilly" in path: # doesn't come with boostrap_nodes.txt
        @[
          "enr:-KG4QNFYe_ASIxDXpZXtzyZcndMr1QyQnAr0EXXgJq8qj1UaS8TNK_LYyG-B14RkMfDRUEhF3bihIjfeyVNZYGgjL8EDhGV0aDKQf_nhygAAQQX__________4JpZIJ2NIJpcIQDFuG2iXNlY3AyNTZrMaECcnSX6eiDjA01nO4vSzHEiAz5h95HUBL6KqSehXmvUGeDdGNwgiMog3VkcIIjKA",
          "enr:-KG4QPWCj_yDwL5APPetgWzVbkKmhFAVL9iZOI14cpiorPDLIKl1htlOJ4_R8zS1MFcnoJRMmMTxBbHXpjwpc_A3Nn4DhGV0aDKQf_nhygAAQQX__________4JpZIJ2NIJpcIQDE-qUiXNlY3AyNTZrMaECzrP1L8i28thLTEwnCIUgEanpCVQbHZe0Bb3crPc2o36DdGNwgiMog3VkcIIjKA",
        ]
      else:
        @[]

      genesisData = if fileExists(genesisPath):
        readFile(genesisPath)
      else:
        ""

      genesisDepositsSnapshot = if fileExists(genesisDepositsSnapshotPath):
        readFile(genesisDepositsSnapshotPath)
      else:
        ""

    Eth2NetworkMetadata(
      incompatible: false,
      eth1Network: some goerli,
      cfg: runtimeConfig,
      bootstrapNodes: bootstrapNodes,
      depositContractDeployedAt: depositContractDeployedAt,
      genesisData: genesisData,
      genesisDepositsSnapshot: genesisDepositsSnapshot)

  except PresetIncompatibleError as err:
    Eth2NetworkMetadata(incompatible: true,
                        incompatibilityDesc: err.msg)

template eth2Network(path: string): Eth2NetworkMetadata =
  loadEth2NetworkMetadata(eth2testnetsDir & "/" & path)

const
  mainnetMetadata* = eth2Network "shared/mainnet"
  pyrmontMetadata* = eth2Network "shared/pyrmont"
  praterMetadata* = eth2Network "shared/prater"
  yeerongpillyMetadata* = eth2Network "teku/yeerongpilly"

proc getMetadataForNetwork*(networkName: string): Eth2NetworkMetadata {.raises: [Defect, IOError].} =
  var
    metadata = case toLowerAscii(networkName)
      of "mainnet":
        mainnetMetadata
      of "pyrmont":
        pyrmontMetadata
      of "prater":
        praterMetadata
      of "yeerongpilly":
        yeerongpillyMetadata
      else:
        if fileExists(networkName / "config.yaml"):
          try:
            loadEth2NetworkMetadata(networkName)
          except CatchableError as exc:
            fatal "Cannot load network", msg = exc.msg, networkName
            quit 1
        else:
          fatal "config.yaml not found for network", networkName
          quit 1

  if metadata.incompatible:
    fatal "The selected network is not compatible with the current build",
            reason = metadata.incompatibilityDesc
    quit 1
  return metadata

proc getRuntimePresetForNetwork*(
    eth2Network: Option[string]): RuntimeConfig {.raises: [Defect, IOError].} =
  if eth2Network.isSome:
    return getMetadataForNetwork(eth2Network.get).cfg
  return defaultRuntimeConfig

proc extractGenesisValidatorRootFromSnapshop*(
    snapshot: string): Eth2Digest {.raises: [Defect, IOError, SszError].} =
  sszMount(snapshot, BeaconState).genesis_validators_root[]

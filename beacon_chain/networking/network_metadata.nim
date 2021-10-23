# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[sequtils, strutils, os],
  stew/shims/macros, nimcrypto/hash,
  eth/common/eth_types as commonEthTypes,
  web3/[ethtypes, conversions],
  chronicles,
  eth/common/eth_types_json_serialization,
  ssz_serialization/navigator,
  ../spec/eth2_ssz_serialization,
  ../spec/datatypes/phase0

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
      # If the eth1Network is specified, the Eth1Monitor will perform some
      # additional checks to ensure we are connecting to a web3 provider
      # serving data for the same network. The value can be set to `None`
      # for custom networks and testing purposes.
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
  eth2NetworksDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor/eth2-networks"

proc readBootstrapNodes*(path: string): seq[string] {.raises: [IOError, Defect].} =
  # Read a list of ENR values from a YAML file containing a flat list of entries
  if fileExists(path):
    splitLines(readFile(path)).
      filterIt(it.startsWith("enr:")).
      mapIt(it.strip())
  else:
    @[]

proc readBootEnr*(path: string): seq[string] {.raises: [IOError, Defect].} =
  # Read a list of ENR values from a YAML file containing a flat list of entries
  if fileExists(path):
    splitLines(readFile(path)).
      filterIt(it.startsWith("- enr:")).
      mapIt(it[2..^1].strip())
  else:
    @[]

proc loadEth2NetworkMetadata*(
    path: string,
    eth1Network: Option[Eth1Network]): Eth2NetworkMetadata
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
      bootEnrPath = path & "/boot_enr.yaml"

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

      bootstrapNodes = deduplicate(
        readBootstrapNodes(bootstrapNodesPath) &
        readBootEnr(bootEnrPath))

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
      eth1Network: eth1Network,
      cfg: runtimeConfig,
      bootstrapNodes: bootstrapNodes,
      depositContractDeployedAt: depositContractDeployedAt,
      genesisData: genesisData,
      genesisDepositsSnapshot: genesisDepositsSnapshot)

  except PresetIncompatibleError as err:
    Eth2NetworkMetadata(incompatible: true,
                        incompatibilityDesc: err.msg)

template eth2Network(path: string): Eth2NetworkMetadata =
  loadEth2NetworkMetadata(
    eth2NetworksDir & "/" & path,
    some(if "mainnet" in path: Eth1Network.mainnet else: Eth1Network.goerli))

const
  mainnetMetadata* = eth2Network "shared/mainnet"
  pyrmontMetadata* = eth2Network "shared/pyrmont"
  praterMetadata* = eth2Network "shared/prater"

proc getMetadataForNetwork*(networkName: string): Eth2NetworkMetadata {.raises: [Defect, IOError].} =
  var
    metadata = case toLowerAscii(networkName)
      of "mainnet":
        mainnetMetadata
      of "pyrmont":
        pyrmontMetadata
      of "prater":
        praterMetadata
      else:
        if fileExists(networkName / "config.yaml"):
          try:
            loadEth2NetworkMetadata(networkName, none(Eth1Network))
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

proc getRuntimeConfig*(
    eth2Network: Option[string]): RuntimeConfig {.raises: [Defect, IOError].} =
  if eth2Network.isSome:
    return getMetadataForNetwork(eth2Network.get).cfg
  return defaultRuntimeConfig

proc extractGenesisValidatorRootFromSnapshot*(
    snapshot: string): Eth2Digest {.raises: [Defect, IOError, SszError].} =
  sszMount(snapshot, phase0.BeaconState).genesis_validators_root[]

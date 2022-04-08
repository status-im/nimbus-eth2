# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[sequtils, strutils, os],
  stew/byteutils, stew/shims/macros, nimcrypto/hash,
  eth/common/eth_types as commonEthTypes,
  web3/[ethtypes, conversions],
  chronicles,
  eth/common/eth_types_json_serialization,
  ssz_serialization/navigator,
  ../spec/eth2_ssz_serialization,
  ../spec/datatypes/phase0

from ../consensus_object_pools/block_pools_types_light_client
  import ImportLightClientData

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

  Eth2NetworkConfigDefaults* = object
    ## Network specific config defaults
    serveLightClientData*: bool
    importLightClientData*: ImportLightClientData

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

      configDefaults*: Eth2NetworkConfigDefaults
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

proc loadEth2NetworkMetadata*(path: string, eth1Network = none(Eth1Network)): Eth2NetworkMetadata
                             {.raises: [CatchableError, Defect].} =
  # Load data in eth2-networks format
  # https://github.com/eth-clients/eth2-networks

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

      enableLightClientData =
        if genesisData.len >= 40:
          # SSZ processing at compile time does not work well.
          #
          # `BeaconState` layout:
          # ```
          # - genesis_time: uint64
          # - genesis_validators_root: Eth2Digest
          # - ...
          # ```
          #
          # Comparing the first 40 bytes covers those two fields,
          # which should identify the network with high likelihood.
          let data = (genesisData[0 ..< 40].toHex())
          data in [
            # Prater
            "60F4596000000000043DB0D9A83813551EE2F33450D23797757D430911A9320530AD8A0EABC43EFB"
          ]
        else:
          false

      configDefaults =
        Eth2NetworkConfigDefaults(
          serveLightClientData:
            enableLightClientData,
          importLightClientData:
            if enableLightClientData:
              ImportLightClientData.OnlyNew
            else:
              ImportLightClientData.None
        )

    Eth2NetworkMetadata(
      incompatible: false,
      eth1Network: eth1Network,
      cfg: runtimeConfig,
      bootstrapNodes: bootstrapNodes,
      depositContractDeployedAt: depositContractDeployedAt,
      genesisData: genesisData,
      genesisDepositsSnapshot: genesisDepositsSnapshot,
      configDefaults: configDefaults)

  except PresetIncompatibleError as err:
    Eth2NetworkMetadata(incompatible: true,
                        incompatibilityDesc: err.msg)

proc loadCompileTimeNetworkMetadata(
    path: string,
    eth1Network = none(Eth1Network)): Eth2NetworkMetadata {.raises: [Defect].} =
  try:
    result = loadEth2NetworkMetadata(path, eth1Network)
    if result.incompatible:
      macros.error "The current build is misconfigured. " &
                   "Attempt to load an incompatible network metadata: " &
                   result.incompatibilityDesc
  except CatchableError as err:
    macros.error "Failed to load network metadata at '" & path & "': " & err.msg

template eth2Network(path: string, eth1Network: Eth1Network): Eth2NetworkMetadata =
  loadCompileTimeNetworkMetadata(eth2NetworksDir & "/" & path,
                                 some eth1Network)

when not defined(gnosisChainBinary):
  when const_preset == "mainnet":
    const
      mainnetMetadata* = eth2Network("shared/mainnet", mainnet)
      praterMetadata* = eth2Network("shared/prater", goerli)

  proc getMetadataForNetwork*(networkName: string): Eth2NetworkMetadata {.raises: [Defect, IOError].} =
    template loadRuntimeMetadata: auto =
      if fileExists(networkName / "config.yaml"):
        try:
          loadEth2NetworkMetadata(networkName)
        except CatchableError as exc:
          fatal "Cannot load network", msg = exc.msg, networkName
          quit 1
      else:
        fatal "config.yaml not found for network", networkName
        quit 1

    var
      metadata = when const_preset == "mainnet":
        case toLowerAscii(networkName)
        of "mainnet":
          mainnetMetadata
        of "prater":
          praterMetadata
        else:
          loadRuntimeMetadata()
      else:
        loadRuntimeMetadata()

    if metadata.incompatible:
      fatal "The selected network is not compatible with the current build",
              reason = metadata.incompatibilityDesc
      quit 1
    metadata

  proc getRuntimeConfig*(
      eth2Network: Option[string]): RuntimeConfig {.raises: [Defect, IOError].} =
    if eth2Network.isSome:
      return getMetadataForNetwork(eth2Network.get).cfg
    defaultRuntimeConfig

else:
  const
    gnosisChainMetadata* = loadCompileTimeNetworkMetadata(
      currentSourcePath.parentDir.replace('\\', '/') & "/../../media/gnosis")

  proc checkNetworkParameterUse*(eth2Network: Option[string]) =
    if eth2Network.isSome and eth2Network.get != "gnosis":
      fatal "The only supported value for the --network parameter is 'gnosis'"
      quit 1

  proc getRuntimeConfig*(eth2Network: Option[string]): RuntimeConfig {.raises: [Defect, IOError].} =
    checkNetworkParameterUse eth2Network
    gnosisChainMetadata.cfg

proc extractGenesisValidatorRootFromSnapshot*(
    snapshot: string): Eth2Digest {.raises: [Defect, IOError, SszError].} =
  sszMount(snapshot, phase0.BeaconState).genesis_validators_root[]

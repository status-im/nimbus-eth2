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
  import LightClientDataImportMode

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
    ropsten
    rinkeby
    goerli
    sepolia

  Eth2NetworkConfigDefaults* = object
    ## Network specific config defaults
    lightClientEnable*: bool
    lightClientDataServe*: bool
    lightClientDataImportMode*: LightClientDataImportMode

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

type DeploymentPhase* {.pure.} = enum
  None,
  Devnet,
  Testnet,
  Mainnet

func deploymentPhase*(genesisData: string): DeploymentPhase =
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
  # ''.join('%02X'%b for b in open("network_name/genesis.ssz", "rb").read()[:40])
  if genesisData.len < 40:
    return DeploymentPhase.None

  const
    mainnets = [
      # Mainnet
      "5730C65F000000004B363DB94E286120D76EB905340FDD4E54BFE9F06BF33FF6CF5AD27F511BFE95",
    ]
    testnets = [
      # Kiln
      "0C572B620000000099B09FCD43E5905236C370F184056BEC6E6638CFC31A323B304FC4AA789CB4AD",
    ]
    devnets = [
      # Ropsten
      "F0DB94620000000044F1E56283CA88B35C789F7F449E52339BC1FEFE3A45913A43A6D16EDCD33CF1",
      # Sepolia
      "607DB06200000000D8EA171F3C94AEA21EBC42A1ED61052ACF3F9209C00E4EFBAADDAC09ED9B8078",
      # Mainnet Shadow Fork 9
      "0C2ECC6200000000209BA2806D11E2394A9C6682815453EDCFDBA1DCE0C25D71BCFEF6363FBD3A43",
      # Prater
      "60F4596000000000043DB0D9A83813551EE2F33450D23797757D430911A9320530AD8A0EABC43EFB",
      # Goerli Shadow Fork 5
      "7CFDD76200000000E45F26D5A29B0ED5A9F62F248B842A30DD7B7FBA0B5B104EAB271EFC04E0CF66",
      # Mainnet Shadow Fork 10
      "35A3DE620000000049836C2A8BEC13B221BC496FCD3774C60EF145402D9754F00DBA0BE881C3A69E",
    ]

  let data = (genesisData[0 ..< 40].toHex())
  if data in mainnets:
    return DeploymentPhase.Mainnet
  if data in testnets:
    return DeploymentPhase.Testnet
  if data in devnets:
    return DeploymentPhase.Devnet
  DeploymentPhase.None

const
  eth2NetworksDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor/eth2-networks"
  mergeTestnetsDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor/merge-testnets"

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
      deployBlockPath = path & "/deploy_block.txt"
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

      deployBlock = if fileExists(deployBlockPath):
        readFile(deployBlockPath).strip
      else:
        ""

      depositContractDeployedAt = if depositContractBlock.len > 0:
        BlockHashOrNumber.init(depositContractBlock)
      elif deployBlock.len > 0:
        BlockHashOrNumber.init(deployBlock)
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

      deploymentPhase = genesisData.deploymentPhase

      configDefaults =
        Eth2NetworkConfigDefaults(
          lightClientEnable:
            false, # Only produces debug logs so far
          lightClientDataServe:
            deploymentPhase <= DeploymentPhase.Testnet,
          lightClientDataImportMode:
            if deploymentPhase <= DeploymentPhase.Testnet:
              LightClientDataImportMode.OnlyNew
            else:
              LightClientDataImportMode.None
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

template mergeTestnet(path: string, eth1Network: Eth1Network): Eth2NetworkMetadata =
  loadCompileTimeNetworkMetadata(mergeTestnetsDir & "/" & path,
                                 some eth1Network)

when not defined(gnosisChainBinary):
  when const_preset == "mainnet":
    const
      mainnetMetadata* = eth2Network("shared/mainnet", mainnet)
      praterMetadata* = eth2Network("shared/prater", goerli)
      ropstenMetadata* = mergeTestnet("ropsten-beacon-chain", ropsten)
      sepoliaMetadata* = mergeTestnet("sepolia", sepolia)
    static:
      for network in [mainnetMetadata, praterMetadata, ropstenMetadata, sepoliaMetadata]:
        checkForkConsistency(network.cfg)

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
        of "prater", "goerli":
          praterMetadata
        of "ropsten":
          ropstenMetadata
        of "sepolia":
          sepoliaMetadata
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
    gnosisMetadata* = loadCompileTimeNetworkMetadata(
      currentSourcePath.parentDir.replace('\\', '/') & "/../../media/gnosis")

  static: checkForkConsistency(gnosisMetadata.cfg)

  proc checkNetworkParameterUse*(eth2Network: Option[string]) =
    # Support `gnosis-chain` as network name which was used in v22.3
    if eth2Network.isSome and eth2Network.get notin ["gnosis", "gnosis-chain"]:
      fatal "The only supported value for the --network parameter is 'gnosis'"
      quit 1

    if eth2Network.isSome and eth2Network.get == "gnosis-chain":
      warn "`--network:gnosis-chain` is deprecated, use `--network:gnosis` instead"

  proc getRuntimeConfig*(eth2Network: Option[string]): RuntimeConfig {.raises: [Defect, IOError].} =
    checkNetworkParameterUse eth2Network
    gnosisMetadata.cfg

proc extractGenesisValidatorRootFromSnapshot*(
    snapshot: string): Eth2Digest {.raises: [Defect, IOError, SszError].} =
  sszMount(snapshot, phase0.BeaconState).genesis_validators_root[]

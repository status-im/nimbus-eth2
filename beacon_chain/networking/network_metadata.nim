# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sequtils, strutils, os],
  stew/[byteutils, objects], stew/shims/macros, nimcrypto/hash,
  web3/[ethtypes, conversions],
  chronicles,
  eth/common/eth_types_json_serialization,
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
    ropsten
    rinkeby
    goerli
    sepolia

  Eth2NetworkMetadata* = object
    case incompatible*: bool
    of false:
      # TODO work-around a Nim codegen issue where upon constant assignment
      #      the compiler will copy `incompatibilityDesc` even when the case
      #      branch is not active and thus it will override the first variable
      #      in this branch.
      dummy: string
      # If the eth1Network is specified, the ELManager will perform some
      # additional checks to ensure we are connecting to a web3 provider
      # serving data for the same network. The value can be set to `None`
      # for custom networks and testing purposes.
      eth1Network*: Option[Eth1Network]
      cfg*: RuntimeConfig

      # Parsing `enr.Records` is still not possible at compile-time
      bootstrapNodes*: seq[string]

      depositContractBlock*: uint64
      depositContractBlockHash*: Eth2Digest

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
      depositContractBlockHashPath = path & "/deposit_contract_block_hash.txt"
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

      depositContractBlockStr = if fileExists(depositContractBlockPath):
        readFile(depositContractBlockPath).strip
      else:
        ""

      depositContractBlockHashStr = if fileExists(depositContractBlockHashPath):
        readFile(depositContractBlockHashPath).strip
      else:
        ""

      deployBlockStr = if fileExists(deployBlockPath):
        readFile(deployBlockPath).strip
      else:
        ""

      depositContractBlock = if depositContractBlockStr.len > 0:
        parseBiggestUInt depositContractBlockStr
      elif deployBlockStr.len > 0:
        parseBiggestUInt deployBlockStr
      elif not runtimeConfig.DEPOSIT_CONTRACT_ADDRESS.isDefaultValue:
        raise newException(ValueError,
          "A network with deposit contract should specify the " &
          "deposit contract deployment block in a file named " &
          "deposit_contract_block.txt or deploy_block.txt")
      else:
        1'u64

      depositContractBlockHash = if depositContractBlockHashStr.len > 0:
        Eth2Digest.strictParse(depositContractBlockHashStr)
      elif not runtimeConfig.DEPOSIT_CONTRACT_ADDRESS.isDefaultValue:
        raise newException(ValueError,
          "A network with deposit contract should specify the " &
          "deposit contract deployment block hash in a file " &
          "name deposit_contract_block_hash.txt")
      else:
        default(Eth2Digest)

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
      depositContractBlock: depositContractBlock,
      depositContractBlockHash: depositContractBlockHash,
      genesisData: genesisData,
      genesisDepositsSnapshot: genesisDepositsSnapshot)

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

when const_preset == "gnosis":
  const
    gnosisMetadata* = loadCompileTimeNetworkMetadata(
      currentSourcePath.parentDir.replace('\\', '/') &
      "/../../vendor/gnosis-chain-configs/mainnet")
  static:
    checkForkConsistency(gnosisMetadata.cfg)
    doAssert gnosisMetadata.cfg.CAPELLA_FORK_EPOCH == FAR_FUTURE_EPOCH
    doAssert gnosisMetadata.cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH

elif const_preset == "mainnet":
  const
    mainnetMetadata* = eth2Network("shared/mainnet", mainnet)
    praterMetadata* = eth2Network("shared/prater", goerli)
    sepoliaMetadata* = mergeTestnet("sepolia", sepolia)
  static:
    for network in [mainnetMetadata, praterMetadata, sepoliaMetadata]:
      checkForkConsistency(network.cfg)

    for network in [mainnetMetadata, praterMetadata]:
      doAssert network.cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH

proc getMetadataForNetwork*(
    networkName: string): Eth2NetworkMetadata {.raises: [Defect, IOError].} =
  template loadRuntimeMetadata(): auto =
    if fileExists(networkName / "config.yaml"):
      try:
        loadEth2NetworkMetadata(networkName)
      except CatchableError as exc:
        fatal "Cannot load network", msg = exc.msg, networkName
        quit 1
    else:
      fatal "config.yaml not found for network", networkName
      quit 1

  if networkName == "ropsten":
    warn "Ropsten is unsupported; https://blog.ethereum.org/2022/11/30/ropsten-shutdown-announcement suggests migrating to Goerli or Sepolia"

  let metadata =
    when const_preset == "gnosis":
      case toLowerAscii(networkName)
      of "gnosis":
        gnosisMetadata
      of "gnosis-chain":
        warn "`--network:gnosis-chain` is deprecated, " &
          "use `--network:gnosis` instead"
        gnosisMetadata
      else:
        loadRuntimeMetadata()

    elif const_preset == "mainnet":
      case toLowerAscii(networkName)
      of "mainnet":
        mainnetMetadata
      of "prater", "goerli":
        praterMetadata
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
  ## Returns the run-time config for a network specified on the command line
  ## If the network is not explicitly specified, the function will act as the
  ## regular Nimbus binary, returning the mainnet config.
  ##
  ## TODO the assumption that the input variable is a CLI config option is not
  ## quite appropriate in such as low-level function. The "assume mainnet by
  ## default" behavior is something that should be handled closer to the `conf`
  ## layer.
  if eth2Network.isSome:
    return getMetadataForNetwork(eth2Network.get).cfg

  when const_preset == "mainnet":
    mainnetMetadata.cfg
  elif const_preset == "gnosis":
    gnosisMetadata.cfg
  else:
    # This is a non-standard build (i.e. minimal), and the function was most
    # likely executed in a test. The best we can do is return a fully default
    # config:
    defaultRuntimeConfig

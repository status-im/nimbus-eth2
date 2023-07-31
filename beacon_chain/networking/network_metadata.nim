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
  ../spec/eth2_ssz_serialization

# TODO(zah):
# We can compress the embedded states with snappy before embedding them here.

# ATTENTION! This file is intentionally avoiding the Nim `/` operator for
# constructing paths. The standard operator is relying the `DirSep` constant
# which depends on the selected target OS (when doing cross-compilation), so
# the compile-time manipulation of paths performed here will break (e.g. when
# cross-compiling for Windows from Linux)
#
# Nim seems to need a more general solution for detecting the host OS during
# compilation, so a host OS specific separator can be used when deriving paths
# from `currentSourcePath`.

export
  ethtypes, conversions, RuntimeConfig

const
  vendorDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor"

  incbinEnabled* = sizeof(pointer) == 8

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

      # `genesisData` will have `len == 0` for networks with a still
      # unknown genesis state.
      when incbinEnabled:
        genesisData*: seq[byte]
      else:
        genesisData*: string

      genesisDepositsSnapshot*: string
    else:
      incompatibilityDesc*: string

template genesisBytes*(metadata: Eth2NetworkMetadata): auto =
  when incbinEnabled:
    metadata.genesisData
  else:
    metadata.genesisData.toOpenArrayByte(0, metadata.genesisData.high)

proc readBootstrapNodes*(path: string): seq[string] {.raises: [IOError].} =
  # Read a list of ENR values from a YAML file containing a flat list of entries
  if fileExists(path):
    splitLines(readFile(path)).
      filterIt(it.startsWith("enr:")).
      mapIt(it.strip())
  else:
    @[]

proc readBootEnr*(path: string): seq[string] {.raises: [IOError].} =
  # Read a list of ENR values from a YAML file containing a flat list of entries
  if fileExists(path):
    splitLines(readFile(path)).
      filterIt(it.startsWith("- enr:")).
      mapIt(it[2..^1].strip())
  else:
    @[]

proc loadEth2NetworkMetadata*(
    path: string, eth1Network = none(Eth1Network), loadGenesis = true):
    Eth2NetworkMetadata {.raises: [CatchableError].} =
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

      genesisData = if loadGenesis and fileExists(genesisPath):
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
      genesisData:
        when incbinEnabled: toBytes genesisData
        else: genesisData,
      genesisDepositsSnapshot: genesisDepositsSnapshot)

  except PresetIncompatibleError as err:
    Eth2NetworkMetadata(incompatible: true,
                        incompatibilityDesc: err.msg)

proc loadCompileTimeNetworkMetadata(
    path: string,
    eth1Network = none(Eth1Network),
    loadGenesis = true): Eth2NetworkMetadata {.raises: [].} =
  if fileExists(path & "/config.yaml"):
    try:
      result = loadEth2NetworkMetadata(path, eth1Network, loadGenesis)
      if result.incompatible:
        macros.error "The current build is misconfigured. " &
                     "Attempt to load an incompatible network metadata: " &
                     result.incompatibilityDesc
    except CatchableError as err:
      macros.error "Failed to load network metadata at '" & path & "': " & err.msg
  else:
    macros.error "config.yaml not found for network '" & path

when const_preset == "gnosis":
  import stew/assign2

  when incbinEnabled:
    let
      gnosisGenesis {.importc: "gnosis_mainnet_genesis".}: ptr UncheckedArray[byte]
      gnosisGenesisSize {.importc: "gnosis_mainnet_genesis_size".}: int

      chiadoGenesis {.importc: "gnosis_chiado_genesis".}: ptr UncheckedArray[byte]
      chiadoGenesisSize {.importc: "gnosis_chiado_genesis_size".}: int

    # let `.incbin` in assembly file find the binary file through search path
    {.passc: "-I" & vendorDir.}
    {.compile: "network_metadata_gnosis.S".}

  const
    gnosisMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/gnosis-chain-configs/mainnet",
      none(Eth1Network), not incbinEnabled)
    chiadoMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/gnosis-chain-configs/chiado",
      none(Eth1Network), not incbinEnabled)

  static:
    for network in [gnosisMetadata, chiadoMetadata]:
      checkForkConsistency(network.cfg)

    for network in [gnosisMetadata, chiadoMetadata]:
      doAssert network.cfg.ALTAIR_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.BELLATRIX_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.CAPELLA_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH

elif const_preset == "mainnet":
  import stew/assign2

  when incbinEnabled:
    # Nim is very inefficent at loading large constants from binary files so we
    # use this trick instead which saves significant amounts of compile time
    let
      mainnetGenesis {.importc: "eth2_mainnet_genesis".}: ptr UncheckedArray[byte]
      mainnetGenesisSize {.importc: "eth2_mainnet_genesis_size".}: int

      praterGenesis {.importc: "eth2_goerli_genesis".}: ptr UncheckedArray[byte]
      praterGenesisSize {.importc: "eth2_goerli_genesis_size".}: int

      sepoliaGenesis {.importc: "eth2_sepolia_genesis".}: ptr UncheckedArray[byte]
      sepoliaGenesisSize {.importc: "eth2_sepolia_genesis_size".}: int

    # let `.incbin` in assembly file find the binary file through search path
    {.passc: "-I" & vendorDir.}
    {.compile: "network_metadata_mainnet.S".}

  const
    mainnetMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/eth2-networks/shared/mainnet", some mainnet, not incbinEnabled)
    praterMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/eth2-networks/shared/prater", some goerli, not incbinEnabled)
    sepoliaMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/sepolia/bepolia", some sepolia, not incbinEnabled)

  static:
    for network in [mainnetMetadata, praterMetadata, sepoliaMetadata]:
      checkForkConsistency(network.cfg)

    for network in [mainnetMetadata, praterMetadata, sepoliaMetadata]:
      doAssert network.cfg.ALTAIR_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.BELLATRIX_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.CAPELLA_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH

proc getMetadataForNetwork*(
    networkName: string): Eth2NetworkMetadata {.raises: [IOError].} =
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

  template withGenesis(metadata, genesis: untyped): untyped =
    when incbinEnabled:
      var tmp = metadata
      case tmp.incompatible
      of false:
        assign(tmp.genesisData, genesis.toOpenArray(0, `genesis Size` - 1))
      of true:
        raiseAssert "Unreachable"  # `loadCompileTimeNetworkMetadata`
      tmp
    else:
      metadata

  let metadata =
    when const_preset == "gnosis":
      case toLowerAscii(networkName)
      of "gnosis":
        withGenesis(gnosisMetadata, gnosisGenesis)
      of "gnosis-chain":
        warn "`--network:gnosis-chain` is deprecated, " &
          "use `--network:gnosis` instead"
        withGenesis(gnosisMetadata, gnosisGenesis)
      of "chiado":
        withGenesis(chiadoMetadata, chiadoGenesis)
      else:
        loadRuntimeMetadata()

    elif const_preset == "mainnet":
      case toLowerAscii(networkName)
      of "mainnet":
        withGenesis(mainnetMetadata, mainnetGenesis)
      of "prater", "goerli":
        withGenesis(praterMetadata, praterGenesis)
      of "sepolia":
        withGenesis(sepoliaMetadata, sepoliaGenesis)
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
    eth2Network: Option[string]): RuntimeConfig {.raises: [IOError].} =
  ## Returns the run-time config for a network specified on the command line
  ## If the network is not explicitly specified, the function will act as the
  ## regular Nimbus binary, returning the mainnet config.
  ##
  ## TODO the assumption that the input variable is a CLI config option is not
  ## quite appropriate in such as low-level function. The "assume mainnet by
  ## default" behavior is something that should be handled closer to the `conf`
  ## layer.
  let metadata =
    if eth2Network.isSome:
      getMetadataForNetwork(eth2Network.get)
    else:
      when const_preset == "mainnet":
        mainnetMetadata
      elif const_preset == "gnosis":
        gnosisMetadata
      else:
        # This is a non-standard build (i.e. minimal), and the function was
        # most likely executed in a test. The best we can do is return a fully
        # default config:
        return defaultRuntimeConfig

  return
    case metadata.incompatible
    of false:
      metadata.cfg
    of true:
      # `getMetadataForNetwork` / `loadCompileTimeNetworkMetadata`
      raiseAssert "Unreachable"

# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sequtils, strutils, os],
  stew/[byteutils, objects], stew/shims/macros, nimcrypto/hash,
  web3/[conversions],
  web3/primitives as web3types,
  chronicles,
  eth/common/eth_types_json_serialization,
  ../spec/[eth2_ssz_serialization, forks]

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
  web3types, conversions, RuntimeConfig

const
  vendorDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor"

  incbinEnabled* = sizeof(pointer) == 8

type
  Eth1BlockHash* = web3types.BlockHash

  Eth1Network* = enum
    mainnet
    goerli
    sepolia
    holesky

  GenesisMetadataKind* = enum
    NoGenesis
    UserSuppliedFile
    BakedIn
    BakedInUrl

  DownloadInfo* = object
    url: string
    digest: Eth2Digest

  GenesisMetadata* = object
    case kind*: GenesisMetadataKind
    of NoGenesis:
      discard
    of UserSuppliedFile:
      path*: string
    of BakedIn:
      networkName*: string
    of BakedInUrl:
      url*: string
      digest*: Eth2Digest

  Eth2NetworkMetadata* = object
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

    genesis*: GenesisMetadata
    genesisDepositsSnapshot*: string

func hasGenesis*(metadata: Eth2NetworkMetadata): bool =
  metadata.genesis.kind != NoGenesis

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
    path: string,
    eth1Network = none(Eth1Network),
    isCompileTime = false,
    downloadGenesisFrom = none(DownloadInfo),
    useBakedInGenesis = none(string)
): Result[Eth2NetworkMetadata, string] {.raises: [IOError, PresetFileError].} =
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

      genesisDepositsSnapshot = if fileExists(genesisDepositsSnapshotPath):
        readFile(genesisDepositsSnapshotPath)
      else:
        ""

    ok Eth2NetworkMetadata(
      eth1Network: eth1Network,
      cfg: runtimeConfig,
      bootstrapNodes: bootstrapNodes,
      depositContractBlock: depositContractBlock,
      depositContractBlockHash: depositContractBlockHash,
      genesis:
        if downloadGenesisFrom.isSome:
          GenesisMetadata(kind: BakedInUrl,
                          url: downloadGenesisFrom.get.url,
                          digest: downloadGenesisFrom.get.digest)
        elif useBakedInGenesis.isSome:
          GenesisMetadata(kind: BakedIn, networkName: useBakedInGenesis.get)
        elif fileExists(genesisPath) and not isCompileTime:
          GenesisMetadata(kind: UserSuppliedFile, path: genesisPath)
        else:
          GenesisMetadata(kind: NoGenesis),
      genesisDepositsSnapshot: genesisDepositsSnapshot)

  except PresetIncompatibleError as err:
    err err.msg

  except ValueError as err:
    raise (ref PresetFileError)(msg: err.msg)

proc loadCompileTimeNetworkMetadata(
    path: string,
    eth1Network = none(Eth1Network),
    useBakedInGenesis = none(string),
    downloadGenesisFrom = none(DownloadInfo)): Eth2NetworkMetadata =
  if fileExists(path & "/config.yaml"):
    try:
      let res = loadEth2NetworkMetadata(
        path, eth1Network, isCompileTime = true,
        downloadGenesisFrom = downloadGenesisFrom,
        useBakedInGenesis = useBakedInGenesis)
      if res.isErr:
        macros.error "The current build is misconfigured. " &
                     "Attempt to load an incompatible network metadata: " &
                     res.error
      return res.get
    except IOError as err:
      macros.error "Failed to load network metadata at '" & path & "': " &
                   "IOError - " & err.msg
    except PresetFileError as err:
      macros.error "Failed to load network metadata at '" & path & "': " &
                   "PresetFileError - " & err.msg
  else:
    macros.error "config.yaml not found for network '" & path

when const_preset == "gnosis":
  when incbinEnabled:
    let
      gnosisGenesis* {.importc: "gnosis_mainnet_genesis".}: ptr UncheckedArray[byte]
      gnosisGenesisSize* {.importc: "gnosis_mainnet_genesis_size".}: int

      chiadoGenesis* {.importc: "gnosis_chiado_genesis".}: ptr UncheckedArray[byte]
      chiadoGenesisSize* {.importc: "gnosis_chiado_genesis_size".}: int

    # let `.incbin` in assembly file find the binary file through search path
    {.passc: "-I" & vendorDir.}
    {.compile: "network_metadata_gnosis.S".}

  else:
    const
      gnosisGenesis* = slurp(
        vendorDir & "/gnosis-chain-configs/mainnet/genesis.ssz")

      chiadoGenesis* = slurp(
        vendorDir & "/gnosis-chain-configs/chiado/genesis.ssz")

  const
    gnosisMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/gnosis-chain-configs/mainnet",
      none(Eth1Network),
      useBakedInGenesis = some "gnosis")

    chiadoMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/gnosis-chain-configs/chiado",
      none(Eth1Network),
      useBakedInGenesis = some "chiado")

  static:
    for network in [gnosisMetadata, chiadoMetadata]:
      checkForkConsistency(network.cfg)

    for network in [gnosisMetadata, chiadoMetadata]:
      doAssert network.cfg.ALTAIR_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.BELLATRIX_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.CAPELLA_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH

elif const_preset == "mainnet":
  when incbinEnabled:
    # Nim is very inefficent at loading large constants from binary files so we
    # use this trick instead which saves significant amounts of compile time
    {.push hint[GlobalVar]:off.}
    let
      mainnetGenesis* {.importc: "eth2_mainnet_genesis".}: ptr UncheckedArray[byte]
      mainnetGenesisSize* {.importc: "eth2_mainnet_genesis_size".}: int

      praterGenesis* {.importc: "eth2_goerli_genesis".}: ptr UncheckedArray[byte]
      praterGenesisSize* {.importc: "eth2_goerli_genesis_size".}: int

      sepoliaGenesis* {.importc: "eth2_sepolia_genesis".}: ptr UncheckedArray[byte]
      sepoliaGenesisSize* {.importc: "eth2_sepolia_genesis_size".}: int
    {.pop.}

    # let `.incbin` in assembly file find the binary file through search path
    {.passc: "-I" & vendorDir.}
    {.compile: "network_metadata_mainnet.S".}

  else:
    const
      mainnetGenesis* = slurp(
        vendorDir & "/eth2-networks/shared/mainnet/genesis.ssz")

      praterGenesis* = slurp(
        vendorDir & "/goerli/prater/genesis.ssz")

      sepoliaGenesis* = slurp(
        vendorDir & "/sepolia/bepolia/genesis.ssz")

  const
    mainnetMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/eth2-networks/shared/mainnet",
      some mainnet,
      useBakedInGenesis = some "mainnet")

    praterMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/goerli/prater",
      some goerli,
      useBakedInGenesis = some "prater")

    holeskyMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/holesky/custom_config_data",
      some holesky,
      downloadGenesisFrom = some DownloadInfo(
        url: "https://github.com/status-im/nimbus-eth2/releases/download/v23.9.1/holesky-genesis.ssz.sz",
        digest: Eth2Digest.fromHex "0x0ea3f6f9515823b59c863454675fefcd1d8b4f2dbe454db166206a41fda060a0"))

    sepoliaMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/sepolia/bepolia",
      some sepolia,
      useBakedInGenesis = some "sepolia")

  static:
    for network in [mainnetMetadata, praterMetadata, sepoliaMetadata, holeskyMetadata]:
      checkForkConsistency(network.cfg)

    for network in [mainnetMetadata, praterMetadata, sepoliaMetadata, holeskyMetadata]:
      doAssert network.cfg.ALTAIR_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.BELLATRIX_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.CAPELLA_FORK_EPOCH < FAR_FUTURE_EPOCH
    for network in [praterMetadata]:
      doAssert network.cfg.DENEB_FORK_EPOCH < FAR_FUTURE_EPOCH
    for network in [mainnetMetadata, sepoliaMetadata, holeskyMetadata]:
      doAssert network.cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH

proc getMetadataForNetwork*(networkName: string): Eth2NetworkMetadata =
  template loadRuntimeMetadata(): auto =
    if fileExists(networkName / "config.yaml"):
      try:
        let res = loadEth2NetworkMetadata(networkName)
        res.valueOr:
          fatal "The selected network is not compatible with the current build",
            reason = res.error
          quit 1
      except IOError as exc:
        fatal "Cannot load network: IOError", msg = exc.msg, networkName
        quit 1
      except PresetFileError as exc:
        fatal "Cannot load network: PresetFileError", msg = exc.msg, networkName
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
      of "chiado":
        chiadoMetadata
      else:
        loadRuntimeMetadata()

    elif const_preset == "mainnet":
      case toLowerAscii(networkName)
      of "mainnet":
        mainnetMetadata
      of "prater", "goerli":
        praterMetadata
      of "holesky":
        holeskyMetadata
      of "sepolia":
        sepoliaMetadata
      else:
        loadRuntimeMetadata()

    else:
      loadRuntimeMetadata()

  metadata

proc getRuntimeConfig*(eth2Network: Option[string]): RuntimeConfig =
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

  metadata.cfg

template bakedInGenesisStateAsBytes(networkName: untyped): untyped =
  when incbinEnabled:
    `networkName Genesis`.toOpenArray(0, `networkName GenesisSize` - 1)
  else:
    `networkName Genesis`.toOpenArrayByte(0, `networkName Genesis`.high)

const
  availableOnlyInMainnetBuild =
    "Baked-in genesis states for the official Ethereum " &
    "networks are available only in the mainnet build of Nimbus"

  availableOnlyInGnosisBuild =
    "Baked-in genesis states for the Gnosis network " &
    "are available only in the gnosis build of Nimbus"

when const_preset in ["mainnet", "gnosis"]:
  template bakedBytes*(metadata: GenesisMetadata): auto =
    case metadata.networkName
    of "mainnet":
      when const_preset == "mainnet":
        bakedInGenesisStateAsBytes mainnet
      else:
        raiseAssert availableOnlyInMainnetBuild
    of "prater":
      when const_preset == "mainnet":
        bakedInGenesisStateAsBytes prater
      else:
        raiseAssert availableOnlyInMainnetBuild
    of "sepolia":
      when const_preset == "mainnet":
        bakedInGenesisStateAsBytes sepolia
      else:
        raiseAssert availableOnlyInMainnetBuild
    of "gnosis":
      when const_preset == "gnosis":
        bakedInGenesisStateAsBytes gnosis
      else:
        raiseAssert availableOnlyInGnosisBuild
    of "chiado":
      when const_preset == "gnosis":
        bakedInGenesisStateAsBytes chiado
      else:
        raiseAssert availableOnlyInGnosisBuild
    else:
      raiseAssert "The baked network metadata should use one of the name above"

  func bakedGenesisValidatorsRoot*(metadata: Eth2NetworkMetadata): Opt[Eth2Digest] =
    case metadata.genesis.kind
    of BakedIn:
      try:
        let header = SSZ.decode(
          toOpenArray(metadata.genesis.bakedBytes, 0, sizeof(BeaconStateHeader) - 1),
          BeaconStateHeader)
        Opt.some header.genesis_validators_root
      except SerializationError:
        raiseAssert "Invalid baken-in genesis state"
    else:
      Opt.none Eth2Digest
else:
  func bakedBytes*(metadata: GenesisMetadata): seq[byte] =
    raiseAssert "Baked genesis states are not available in the current build mode"

  func bakedGenesisValidatorsRoot*(metadata: Eth2NetworkMetadata): Opt[Eth2Digest] =
    Opt.none Eth2Digest

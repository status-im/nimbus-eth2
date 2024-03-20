import
  std/[sequtils, strutils, os],
  stew/[byteutils, objects], stew/shims/macros, nimcrypto/hash,
  web3/[conversions],
  web3/primitives as web3types,
  eth/common/eth_types_json_serialization,
  ../spec/[eth2_ssz_serialization, forks]

export
  web3types, conversions, RuntimeConfig

const
  vendorDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor"

type
  Eth1BlockHash = web3types.BlockHash

  Eth1Network = enum
    mainnet
    goerli
    sepolia
    holesky

  GenesisMetadataKind* = enum
    NoGenesis
    UserSuppliedFile
    BakedIn
    BakedInUrl

  DownloadInfo = object
    url: string
    digest: Eth2Digest

  GenesisMetadata = object
    case kind*: GenesisMetadataKind
    of NoGenesis:
      discard
    of UserSuppliedFile:
      path: string
    of BakedIn:
      networkName: string
    of BakedInUrl:
      url: string
      digest: Eth2Digest

  Eth2NetworkMetadata* = object
    eth1Network: Option[Eth1Network]
    cfg*: RuntimeConfig

    bootstrapNodes: seq[string]

    depositContractBlock: uint64
    depositContractBlockHash: Eth2Digest

    genesis*: GenesisMetadata
    genesisDepositsSnapshot: string

func hasGenesis*(metadata: Eth2NetworkMetadata): bool =
  metadata.genesis.kind != NoGenesis

proc readBootstrapNodes(path: string): seq[string] {.raises: [IOError].} =
  if fileExists(path):
    splitLines(readFile(path)).
      filterIt(it.startsWith("enr:")).
      mapIt(it.strip())
  else:
    @[]

proc readBootEnr(path: string): seq[string] {.raises: [IOError].} =
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
            echo "Unknown constants in config file", unknowns
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

when const_preset == "mainnet":
  const
    mainnetGenesis = slurp(
      vendorDir & "/eth2-networks/shared/mainnet/genesis.ssz")

    praterGenesis = slurp(
      vendorDir & "/goerli/prater/genesis.ssz")

    sepoliaGenesis = slurp(
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
      doAssert network.cfg.DENEB_FORK_EPOCH < FAR_FUTURE_EPOCH
      doAssert network.cfg.ELECTRA_FORK_EPOCH == FAR_FUTURE_EPOCH
      static: doAssert ConsensusFork.high == ConsensusFork.Electra

proc getMetadataForNetwork*(networkName: string): Eth2NetworkMetadata =
  template loadRuntimeMetadata(): auto =
    if fileExists(networkName / "config.yaml"):
      try:
        let res = loadEth2NetworkMetadata(networkName)
        res.valueOr:
          quit 1
      except IOError:
        quit 1
      except PresetFileError:
        quit 1
    else:
      quit 1

  let metadata =
    when const_preset == "gnosis":
      case toLowerAscii(networkName)
      of "gnosis":
        gnosisMetadata
      of "gnosis-chain":
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

proc getRuntimeConfig(eth2Network: Option[string]): RuntimeConfig =
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

when const_preset in ["mainnet", "gnosis"]:
  template bakedInGenesisStateAsBytes(networkName: untyped): untyped =
    `networkName Genesis`.toOpenArrayByte(0, `networkName Genesis`.high)

  const
    availableOnlyInMainnetBuild =
      "Baked-in genesis states for the official Ethereum " &
      "networks are available only in the mainnet build of Nimbus"

    availableOnlyInGnosisBuild =
      "Baked-in genesis states for the Gnosis network " &
      "are available only in the gnosis build of Nimbus"

  template bakedBytes(metadata: GenesisMetadata): auto =
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
  func bakedBytes(metadata: GenesisMetadata): seq[byte] =
    raiseAssert "Baked genesis states are not available in the current build mode"

  func bakedGenesisValidatorsRoot(metadata: Eth2NetworkMetadata): Opt[Eth2Digest] =
    Opt.none Eth2Digest

import stew/io2

proc fetchGenesisBytes*(
    metadata: Eth2NetworkMetadata): seq[byte] =
  case metadata.genesis.kind
  of NoGenesis:
    raiseAssert "fetchGenesisBytes should be called only when metadata.hasGenesis is true"
  of BakedIn:
    result = @(metadata.genesis.bakedBytes)
  of BakedInUrl:
    raiseAssert "genesis state downlading unsuppoorted"
  of UserSuppliedFile:
    result = readAllBytes(metadata.genesis.path).tryGet()

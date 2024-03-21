import
  std/[strutils, os],
  stew/[byteutils, objects], stew/shims/macros, nimcrypto/hash,
  eth/common/eth_types_json_serialization,
  ../spec/[eth2_ssz_serialization, forks]

export RuntimeConfig

const
  vendorDir = currentSourcePath.parentDir.replace('\\', '/') & "/../../vendor"

type
  Eth1Network = enum
    mainnet
    sepolia

  GenesisMetadataKind* = enum
    NoGenesis
    UserSuppliedFile
    BakedIn
    BakedInUrl

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

proc loadEth2NetworkMetadata*(
    path: string,
    eth1Network = none(Eth1Network),
    isCompileTime = false,
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

      genesisDepositsSnapshot = if fileExists(genesisDepositsSnapshotPath):
        readFile(genesisDepositsSnapshotPath)
      else:
        ""

    ok Eth2NetworkMetadata(
      eth1Network: eth1Network,
      cfg: runtimeConfig,
      depositContractBlock: depositContractBlock,
      depositContractBlockHash: depositContractBlockHash,
      genesis:
        if useBakedInGenesis.isSome:
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
    useBakedInGenesis = none(string)): Eth2NetworkMetadata =
  if fileExists(path & "/config.yaml"):
    try:
      let res = loadEth2NetworkMetadata(
        path, eth1Network, isCompileTime = true,
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

    sepoliaGenesis = slurp(
      vendorDir & "/sepolia/bepolia/genesis.ssz")

  const
    mainnetMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/eth2-networks/shared/mainnet",
      some mainnet,
      useBakedInGenesis = some "mainnet")

    sepoliaMetadata = loadCompileTimeNetworkMetadata(
      vendorDir & "/sepolia/bepolia",
      some sepolia,
      useBakedInGenesis = some "sepolia")

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
    when const_preset == "mainnet":
      case toLowerAscii(networkName)
      of "mainnet":
        mainnetMetadata
      of "sepolia":
        sepoliaMetadata
      else:
        loadRuntimeMetadata()

    else:
      loadRuntimeMetadata()

  metadata

when const_preset in ["mainnet", "gnosis"]:
  template bakedInGenesisStateAsBytes(networkName: untyped): untyped =
    `networkName Genesis`.toOpenArrayByte(0, `networkName Genesis`.high)

  const
    availableOnlyInMainnetBuild =
      "Baked-in genesis states for the official Ethereum " &
      "networks are available only in the mainnet build of Nimbus"

  template bakedBytes(metadata: GenesisMetadata): auto =
    case metadata.networkName
    of "mainnet":
      when const_preset == "mainnet":
        bakedInGenesisStateAsBytes mainnet
      else:
        raiseAssert availableOnlyInMainnetBuild
    of "sepolia":
      when const_preset == "mainnet":
        bakedInGenesisStateAsBytes sepolia
      else:
        raiseAssert availableOnlyInMainnetBuild
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

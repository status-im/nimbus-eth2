{.push raises: [].}

import
  std/[strutils, parseutils, tables, typetraits],
  chronos/timer,
  stew/[byteutils], stint, web3/primitives as web3types

export stint, web3types.toHex, web3types.`==`

const
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#withdrawal-prefixes
  BLS_WITHDRAWAL_PREFIX*: byte = 0
  ETH1_ADDRESS_WITHDRAWAL_PREFIX*: byte = 1

  # Constants from `validator.md` not covered by config/presets in the spec
  TARGET_AGGREGATORS_PER_COMMITTEE*: uint64 = 16

  # Not used anywhere; only for network preset checking
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION: uint64 = 256
  TTFB_TIMEOUT* = 5'u64
  MESSAGE_DOMAIN_INVALID_SNAPPY*: array[4, byte] = [0x00, 0x00, 0x00, 0x00]
  MESSAGE_DOMAIN_VALID_SNAPPY*: array[4, byte] = [0x01, 0x00, 0x00, 0x00]

type
  Version* = distinct array[4, byte]
  Eth1Address* = web3types.Address

  RuntimeConfig* = object
    ## https://github.com/ethereum/consensus-specs/tree/v1.4.0-beta.4/configs
    PRESET_BASE*: string
    CONFIG_NAME*: string

    # Transition
    TERMINAL_TOTAL_DIFFICULTY*: UInt256
    TERMINAL_BLOCK_HASH*: BlockHash
    TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH*: uint64  # Not actively used, but part of the spec

    # Genesis
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT*: uint64
    MIN_GENESIS_TIME*: uint64
    GENESIS_FORK_VERSION*: Version
    GENESIS_DELAY*: uint64

    # Forking
    ALTAIR_FORK_VERSION*: Version
    ALTAIR_FORK_EPOCH*: uint64
    BELLATRIX_FORK_VERSION*: Version
    BELLATRIX_FORK_EPOCH*: uint64
    CAPELLA_FORK_VERSION*: Version
    CAPELLA_FORK_EPOCH*: uint64
    DENEB_FORK_VERSION*: Version
    DENEB_FORK_EPOCH*: uint64
    ELECTRA_FORK_VERSION*: Version
    ELECTRA_FORK_EPOCH*: uint64

    # Time parameters
    # TODO SECONDS_PER_SLOT*: uint64
    SECONDS_PER_ETH1_BLOCK*: uint64
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64
    SHARD_COMMITTEE_PERIOD*: uint64
    ETH1_FOLLOW_DISTANCE*: uint64

    # Validator cycle
    INACTIVITY_SCORE_BIAS*: uint64
    INACTIVITY_SCORE_RECOVERY_RATE*: uint64
    EJECTION_BALANCE*: uint64
    MIN_PER_EPOCH_CHURN_LIMIT*: uint64
    CHURN_LIMIT_QUOTIENT*: uint64
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT*: uint64

    # Fork choice
    # TODO PROPOSER_SCORE_BOOST*: uint64
    # TODO REORG_HEAD_WEIGHT_THRESHOLD*: uint64
    # TODO REORG_PARENT_WEIGHT_THRESHOLD*: uint64
    # TODO REORG_MAX_EPOCHS_SINCE_FINALIZATION*: uint64

    # Deposit contract
    DEPOSIT_CHAIN_ID*: uint64
    DEPOSIT_NETWORK_ID*: uint64
    DEPOSIT_CONTRACT_ADDRESS*: Eth1Address

    # Networking
    # TODO GOSSIP_MAX_SIZE*: uint64
    # TODO MAX_REQUEST_BLOCKS*: uint64
    # TODO EPOCHS_PER_SUBNET_SUBSCRIPTION*: uint64
    MIN_EPOCHS_FOR_BLOCK_REQUESTS*: uint64
    # TODO MAX_CHUNK_SIZE*: uint64
    # TODO TTFB_TIMEOUT*: uint64
    # TODO RESP_TIMEOUT*: uint64
    # TODO ATTESTATION_PROPAGATION_SLOT_RANGE*: uint64
    # TODO MAXIMUM_GOSSIP_CLOCK_DISPARITY*: uint64
    # TODO MESSAGE_DOMAIN_INVALID_SNAPPY*: array[4, byte]
    # TODO MESSAGE_DOMAIN_VALID_SNAPPY*: array[4, byte]
    # TODO SUBNETS_PER_NODE*: uint64
    # TODO ATTESTATION_SUBNET_COUNT*: uint64
    # TODO ATTESTATION_SUBNET_EXTRA_BITS*: uint64
    # TODO ATTESTATION_SUBNET_PREFIX_BITS*: uint64

    # Deneb
    # TODO MAX_REQUEST_BLOCKS_DENEB*: uint64
    # TODO MAX_REQUEST_BLOB_SIDECARS*: uint64
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS*: uint64
    # TODO BLOB_SIDECAR_SUBNET_COUNT*: uint64

  PresetFile* = object
    values*: Table[string, string]
    missingValues*: seq[string]

  PresetFileError* = object of CatchableError
  PresetIncompatibleError* = object of CatchableError

const
  const_preset* {.strdefine.} = "mainnet"

  # No-longer used values from legacy config files
  ignoredValues = [
    "TRANSITION_TOTAL_DIFFICULTY", # Name that appears in some altair alphas, obsolete, remove when no more testnets
    "MIN_ANCHOR_POW_BLOCK_DIFFICULTY", # Name that appears in some altair alphas, obsolete, remove when no more testnets
    "RANDOM_SUBNETS_PER_VALIDATOR",    # Removed in consensus-specs v1.4.0
  ]

when const_preset == "mainnet":
  import ./presets/mainnet
  export mainnet

  # TODO Move this to RuntimeConfig
  const SECONDS_PER_SLOT* {.intdefine.}: uint64 = 12

  # The default run-time config specifies the default configuration values
  # that will be used if a particular run-time config is missing specific
  # confugration values (which will be then taken from this config object).
  # It mostly matches the mainnet config with the exception of few properties
  # such as `CONFIG_NAME`, `TERMINAL_TOTAL_DIFFICULTY`, `*_FORK_EPOCH`, etc
  # which must be effectively overriden in all network (including mainnet).
  const defaultRuntimeConfig* = RuntimeConfig(
    # Mainnet config

    # Extends the mainnet preset
    PRESET_BASE: "mainnet",

    # Free-form short name of the network that this configuration applies to - known
    # canonical network names include:
    # * 'mainnet' - there can be only one
    # * 'prater' - testnet
    # * 'ropsten' - testnet
    # * 'sepolia' - testnet
    # * 'holesky' - testnet
    # Must match the regex: [a-z0-9\-]
    CONFIG_NAME: "",

    # Transition
    # ---------------------------------------------------------------
    # TBD, 2**256-2**10 is a placeholder
    TERMINAL_TOTAL_DIFFICULTY:
      u256"115792089237316195423570985008687907853269984665640564039457584007913129638912",
    # By default, don't use these params
    TERMINAL_BLOCK_HASH: BlockHash.fromHex(
      "0x0000000000000000000000000000000000000000000000000000000000000000"),

    # Genesis
    # ---------------------------------------------------------------
    # `2**14` (= 16,384)
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 16384,
    # Dec 1, 2020, 12pm UTC
    MIN_GENESIS_TIME: 1606824000,
    # Mainnet initial fork version, recommend altering for testnets
    GENESIS_FORK_VERSION: Version [byte 0x00, 0x00, 0x00, 0x00],
    # 604800 seconds (7 days)
    GENESIS_DELAY: 604800,

    # Forking
    # ---------------------------------------------------------------
    # Some forks are disabled for now:
    #  - These may be re-assigned to another fork-version later
    #  - Temporarily set to max uint64 value: 2**64 - 1

    # Altair
    ALTAIR_FORK_VERSION: Version [byte 0x01, 0x00, 0x00, 0x00],
    ALTAIR_FORK_EPOCH: (not 0'u64),
    # Bellatrix
    BELLATRIX_FORK_VERSION: Version [byte 0x02, 0x00, 0x00, 0x00],
    BELLATRIX_FORK_EPOCH: (not 0'u64),
    # Capella
    CAPELLA_FORK_VERSION: Version [byte 0x03, 0x00, 0x00, 0x00],
    CAPELLA_FORK_EPOCH: (not 0'u64),
    # Deneb
    DENEB_FORK_VERSION: Version [byte 0x04, 0x00, 0x00, 0x00],
    DENEB_FORK_EPOCH: (not 0'u64),
    # Electra
    ELECTRA_FORK_VERSION: Version [byte 0x05, 0x00, 0x00, 0x00],
    ELECTRA_FORK_EPOCH: (not 0'u64),

    # Time parameters
    # ---------------------------------------------------------------
    # 12 seconds
    # TODO SECONDS_PER_SLOT: 12,
    # 14 (estimate from Eth1 mainnet)
    SECONDS_PER_ETH1_BLOCK: 14,
    # 2**8 (= 256) epochs ~27 hours
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256,
    # 2**8 (= 256) epochs ~27 hours
    SHARD_COMMITTEE_PERIOD: 256,
    # 2**11 (= 2,048) Eth1 blocks ~8 hours
    ETH1_FOLLOW_DISTANCE: 2048,


    # Validator cycle
    # ---------------------------------------------------------------
    # 2**2 (= 4)
    INACTIVITY_SCORE_BIAS: 4,
    # 2**4 (= 16)
    INACTIVITY_SCORE_RECOVERY_RATE: 16,
    # 2**4 * 10**9 (= 16,000,000,000) Gwei
    EJECTION_BALANCE: 16000000000'u64,
    # 2**2 (= 4)
    MIN_PER_EPOCH_CHURN_LIMIT: 4,
    # 2**16 (= 65,536)
    CHURN_LIMIT_QUOTIENT: 65536,
    # [New in Deneb:EIP7514] 2**3 (= 8)
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 8,

    # Deposit contract
    # ---------------------------------------------------------------
    # Ethereum PoW Mainnet
    DEPOSIT_CHAIN_ID: 1,
    DEPOSIT_NETWORK_ID: 1,
    DEPOSIT_CONTRACT_ADDRESS: default(Eth1Address),

    # Networking
    # ---------------------------------------------------------------
    # `10 * 2**20` (= 10485760, 10 MiB)
    # TODO GOSSIP_MAX_SIZE: 10485760,
    # `2**10` (= 1024)
    # TODO MAX_REQUEST_BLOCKS: 1024,
    # `2**8` (= 256)
    # TODO EPOCHS_PER_SUBNET_SUBSCRIPTION: 256,
    # `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + CHURN_LIMIT_QUOTIENT // 2` (= 33024, ~5 months)
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: 33024,
    # `10 * 2**20` (=10485760, 10 MiB)
    # TODO MAX_CHUNK_SIZE: 10485760,
    # 5s
    # TODO TTFB_TIMEOUT: 5,
    # 10s
    # TODO RESP_TIMEOUT: 10,
    # TODO ATTESTATION_PROPAGATION_SLOT_RANGE: 32,
    # 500ms
    # TODO MAXIMUM_GOSSIP_CLOCK_DISPARITY: 500,
    # TODO MESSAGE_DOMAIN_INVALID_SNAPPY: [byte 0x00, 0x00, 0x00, 0x00],
    # TODO MESSAGE_DOMAIN_VALID_SNAPPY: [byte 0x01, 0x00, 0x00, 0x00],
    # 2 subnets per node
    # TODO SUBNETS_PER_NODE: 2,
    # 2**8 (= 64)
    # TODO ATTESTATION_SUBNET_COUNT: 64,
    # TODO ATTESTATION_SUBNET_EXTRA_BITS: 0,
    # ceillog2(ATTESTATION_SUBNET_COUNT) + ATTESTATION_SUBNET_EXTRA_BITS
    # TODO ATTESTATION_SUBNET_PREFIX_BITS: 6,

    # Deneb
    # `2**7` (=128)
    # TODO MAX_REQUEST_BLOCKS_DENEB: 128,
    # MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK
    # TODO MAX_REQUEST_BLOB_SIDECARS: 768,
    # `2**12` (= 4096 epochs, ~18 days)
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: 4096,
    # `6`
    # TODO BLOB_SIDECAR_SUBNET_COUNT: 6,
  )

elif const_preset == "gnosis":
  import ./presets/gnosis
  export gnosis

  # TODO Move this to RuntimeConfig
  const SECONDS_PER_SLOT* {.intdefine.}: uint64 = 5

  # The default run-time config specifies the default configuration values
  # that will be used if a particular run-time config is missing specific
  # confugration values (which will be then taken from this config object).
  # It mostly matches the gnosis config with the exception of few properties
  # such as `CONFIG_NAME`, `TERMINAL_TOTAL_DIFFICULTY`, `*_FORK_EPOCH`, etc
  # which must be effectively overriden in all network (including mainnet).
  const defaultRuntimeConfig* = RuntimeConfig(
    # Mainnet config

    # Extends the mainnet preset
    PRESET_BASE: "gnosis",

    # Free-form short name of the network that this configuration applies to - known
    # canonical network names include:
    # * 'mainnet' - there can be only one
    # * 'prater' - testnet
    # * 'ropsten' - testnet
    # * 'sepolia' - testnet
    # * 'holesky' - testnet
    # Must match the regex: [a-z0-9\-]
    CONFIG_NAME: "",

    # Transition
    # ---------------------------------------------------------------
    # TBD, 2**256-2**10 is a placeholder
    TERMINAL_TOTAL_DIFFICULTY:
      u256"115792089237316195423570985008687907853269984665640564039457584007913129638912",
    # By default, don't use these params
    TERMINAL_BLOCK_HASH: BlockHash.fromHex(
      "0x0000000000000000000000000000000000000000000000000000000000000000"),

    # Genesis
    # ---------------------------------------------------------------
    # `2**14` (= 16,384)
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 4096,
    # Dec 1, 2020, 12pm UTC
    MIN_GENESIS_TIME: 1638968400,
    # Mainnet initial fork version, recommend altering for testnets
    GENESIS_FORK_VERSION: Version [byte 0x00, 0x00, 0x00, 0x64],
    # 604800 seconds (7 days)
    GENESIS_DELAY: 604800,

    # Forking
    # ---------------------------------------------------------------
    # Some forks are disabled for now:
    #  - These may be re-assigned to another fork-version later
    #  - Temporarily set to max uint64 value: 2**64 - 1

    # Altair
    ALTAIR_FORK_VERSION: Version [byte 0x01, 0x00, 0x00, 0x64],
    ALTAIR_FORK_EPOCH: (not 0'u64),
    # Bellatrix
    BELLATRIX_FORK_VERSION: Version [byte 0x02, 0x00, 0x00, 0x64],
    BELLATRIX_FORK_EPOCH: (not 0'u64),
    # Capella
    CAPELLA_FORK_VERSION: Version [byte 0x03, 0x00, 0x00, 0x64],
    CAPELLA_FORK_EPOCH: (not 0'u64),
    # Deneb
    DENEB_FORK_VERSION: Version [byte 0x04, 0x00, 0x00, 0x64],
    DENEB_FORK_EPOCH: (not 0'u64),
    # Electra
    ELECTRA_FORK_VERSION: Version [byte 0x05, 0x00, 0x00, 0x64],
    ELECTRA_FORK_EPOCH: (not 0'u64),


    # Time parameters
    # ---------------------------------------------------------------
    # 12 seconds
    # TODO SECONDS_PER_SLOT: 12,
    # 14 (estimate from Eth1 mainnet)
    SECONDS_PER_ETH1_BLOCK: 5,
    # 2**8 (= 256) epochs ~27 hours
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256,
    # 2**8 (= 256) epochs ~27 hours
    SHARD_COMMITTEE_PERIOD: 256,
    # 2**11 (= 2,048) Eth1 blocks ~8 hours
    ETH1_FOLLOW_DISTANCE: 2048,


    # Validator cycle
    # ---------------------------------------------------------------
    # 2**2 (= 4)
    INACTIVITY_SCORE_BIAS: 4,
    # 2**4 (= 16)
    INACTIVITY_SCORE_RECOVERY_RATE: 16,
    # 2**4 * 10**9 (= 16,000,000,000) Gwei
    EJECTION_BALANCE: 16000000000'u64,
    # 2**2 (= 4)
    MIN_PER_EPOCH_CHURN_LIMIT: 4,
    # 2**16 (= 65,536)
    CHURN_LIMIT_QUOTIENT: 4096,
    # [New in Deneb:EIP7514] 2**3 (= 8)
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 8,

    # Deposit contract
    # ---------------------------------------------------------------
    # Gnosis PoW Mainnet
    DEPOSIT_CHAIN_ID: 100,
    DEPOSIT_NETWORK_ID: 100,
    DEPOSIT_CONTRACT_ADDRESS: default(Eth1Address),

    # Networking
    # ---------------------------------------------------------------
    # `10 * 2**20` (= 10485760, 10 MiB)
    # TODO GOSSIP_MAX_SIZE: 10485760,
    # `2**10` (= 1024)
    # TODO MAX_REQUEST_BLOCKS: 1024,
    # `2**8` (= 256)
    # TODO EPOCHS_PER_SUBNET_SUBSCRIPTION: 256,
    # `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + CHURN_LIMIT_QUOTIENT // 2` (= 33024, ~5 months)
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: 33024,
    # `10 * 2**20` (=10485760, 10 MiB)
    # TODO MAX_CHUNK_SIZE: 10485760,
    # 5s
    # TODO TTFB_TIMEOUT: 5,
    # 10s
    # TODO RESP_TIMEOUT: 10,
    # TODO ATTESTATION_PROPAGATION_SLOT_RANGE: 32,
    # 500ms
    # TODO MAXIMUM_GOSSIP_CLOCK_DISPARITY: 500,
    # TODO MESSAGE_DOMAIN_INVALID_SNAPPY: [byte 0x00, 0x00, 0x00, 0x00],
    # TODO MESSAGE_DOMAIN_VALID_SNAPPY: [byte 0x01, 0x00, 0x00, 0x00],
    # 2 subnets per node
    # TODO SUBNETS_PER_NODE: 2,
    # 2**8 (= 64)
    # TODO ATTESTATION_SUBNET_COUNT: 64,
    # TODO ATTESTATION_SUBNET_EXTRA_BITS: 0,
    # ceillog2(ATTESTATION_SUBNET_COUNT) + ATTESTATION_SUBNET_EXTRA_BITS
    # TODO ATTESTATION_SUBNET_PREFIX_BITS: 6,

    # Deneb
    # `2**7` (=128)
    # TODO MAX_REQUEST_BLOCKS_DENEB: 128,
    # MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK
    # TODO MAX_REQUEST_BLOB_SIDECARS: 768,
    # `2**12` (= 4096 epochs, ~18 days)
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: 16384,
    # `6`
    # TODO BLOB_SIDECAR_SUBNET_COUNT: 6,
  )

elif const_preset == "minimal":
  import ./presets/minimal
  export minimal

  const SECONDS_PER_SLOT* {.intdefine.}: uint64 = 6

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/configs/minimal.yaml
  const defaultRuntimeConfig* = RuntimeConfig(
    # Minimal config

    # Extends the minimal preset
    PRESET_BASE: "minimal",

    # Free-form short name of the network that this configuration applies to - known
    # canonical network names include:
    # * 'mainnet' - there can be only one
    # * 'prater' - testnet
    # * 'ropsten' - testnet
    # * 'sepolia' - testnet
    # * 'holesky' - testnet
    # Must match the regex: [a-z0-9\-]
    CONFIG_NAME: "minimal",

    # Transition
    # ---------------------------------------------------------------
    # 2**256-2**10 for testing minimal network
    TERMINAL_TOTAL_DIFFICULTY:
      u256"115792089237316195423570985008687907853269984665640564039457584007913129638912",
    # By default, don't use these params
    TERMINAL_BLOCK_HASH: BlockHash.fromHex(
      "0x0000000000000000000000000000000000000000000000000000000000000000"),


    # Genesis
    # ---------------------------------------------------------------
    # [customized]
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 64,
    # Jan 3, 2020
    MIN_GENESIS_TIME: 1578009600,
    # Highest byte set to 0x01 to avoid collisions with mainnet versioning
    GENESIS_FORK_VERSION: Version [byte 0x00, 0x00, 0x00, 0x01],
    # [customized] Faster to spin up testnets, but does not give validator reasonable warning time for genesis
    GENESIS_DELAY: 300,


    # Forking
    # ---------------------------------------------------------------
    # Values provided for illustrative purposes.
    # Individual tests/testnets may set different values.

    # Altair
    ALTAIR_FORK_VERSION: Version [byte 0x01, 0x00, 0x00, 0x01],
    ALTAIR_FORK_EPOCH: uint64(uint64.high),
    # Bellatrix
    BELLATRIX_FORK_VERSION: Version [byte 0x02, 0x00, 0x00, 0x01],
    BELLATRIX_FORK_EPOCH: uint64(uint64.high),
    # Capella
    CAPELLA_FORK_VERSION: Version [byte 0x03, 0x00, 0x00, 0x01],
    CAPELLA_FORK_EPOCH: uint64(uint64.high),
    # Deneb
    DENEB_FORK_VERSION: Version [byte 0x04, 0x00, 0x00, 0x01],
    DENEB_FORK_EPOCH: uint64(uint64.high),
    # Electra
    ELECTRA_FORK_VERSION: Version [byte 0x05, 0x00, 0x00, 0x01],
    ELECTRA_FORK_EPOCH: uint64(uint64.high),


    # Time parameters
    # ---------------------------------------------------------------
    # [customized] Faster for testing purposes
    # TODO SECONDS_PER_SLOT: 6,
    # 14 (estimate from Eth1 mainnet)
    SECONDS_PER_ETH1_BLOCK: 14,
    # 2**8 (= 256) epochs
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256,
    # [customized] higher frequency of committee turnover and faster time to acceptable voluntary exit
    SHARD_COMMITTEE_PERIOD: 64,
    # [customized] process deposits more quickly, but insecure
    ETH1_FOLLOW_DISTANCE: 16,


    # Validator cycle
    # ---------------------------------------------------------------
    # 2**2 (= 4)
    INACTIVITY_SCORE_BIAS: 4,
    # 2**4 (= 16)
    INACTIVITY_SCORE_RECOVERY_RATE: 16,
    # 2**4 * 10**9 (= 16,000,000,000) Gwei
    EJECTION_BALANCE: 16000000000'u64,
    # [customized] more easily demonstrate the difference between this value and the activation churn limit
    MIN_PER_EPOCH_CHURN_LIMIT: 2,
    # [customized] scale queue churn at much lower validator counts for testing
    CHURN_LIMIT_QUOTIENT: 32,
    # [New in Deneb:EIP7514] [customized]
    MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT: 4,


    # Deposit contract
    # ---------------------------------------------------------------
    # Ethereum Goerli testnet
    DEPOSIT_CHAIN_ID: 5,
    DEPOSIT_NETWORK_ID: 5,
    # Configured on a per testnet basis
    DEPOSIT_CONTRACT_ADDRESS: default(Eth1Address),

    # Networking
    # ---------------------------------------------------------------
    # `10 * 2**20` (= 10485760, 10 MiB)
    # TODO GOSSIP_MAX_SIZE: 10485760,
    # `2**10` (= 1024)
    # TODO MAX_REQUEST_BLOCKS: 1024,
    # `2**8` (= 256)
    # TODO EPOCHS_PER_SUBNET_SUBSCRIPTION: 256,
    # [customized] `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + CHURN_LIMIT_QUOTIENT // 2` (= 272)
    MIN_EPOCHS_FOR_BLOCK_REQUESTS: 272,
    # `10 * 2**20` (=10485760, 10 MiB)
    # TODO MAX_CHUNK_SIZE: 10485760,
    # 5s
    # TODO TTFB_TIMEOUT: 5,
    # 10s
    # TODO RESP_TIMEOUT: 10,
    # TODO ATTESTATION_PROPAGATION_SLOT_RANGE: 32,
    # 500ms
    # TODO MAXIMUM_GOSSIP_CLOCK_DISPARITY: 500,
    # TODO MESSAGE_DOMAIN_INVALID_SNAPPY: [byte 0x00, 0x00, 0x00, 0x00],
    # TODO MESSAGE_DOMAIN_VALID_SNAPPY: [byte 0x01, 0x00, 0x00, 0x00],
    # 2 subnets per node
    # TODO SUBNETS_PER_NODE: 2,
    # 2**8 (= 64)
    # TODO ATTESTATION_SUBNET_COUNT: 64,
    # TODO ATTESTATION_SUBNET_EXTRA_BITS: 0,
    # ceillog2(ATTESTATION_SUBNET_COUNT) + ATTESTATION_SUBNET_EXTRA_BITS
    # TODO ATTESTATION_SUBNET_PREFIX_BITS: 6,

    # Deneb
    # `2**7` (=128)
    # TODO MAX_REQUEST_BLOCKS_DENEB: 128,
    # MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK
    # TODO MAX_REQUEST_BLOB_SIDECARS: 768,
    # `2**12` (= 4096 epochs, ~18 days)
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS: 4096,
    # `6`
    # TODO BLOB_SIDECAR_SUBNET_COUNT: 6,
  )

else:
  {.error: "Only mainnet, gnosis, and minimal presets supported".}
  # macro createConstantsFromPreset*(path: static string): untyped =
  #   result = newStmtList()

  #   let preset = try: readPresetFile(path)
  #                except CatchableError as err:
  #                  error err.msg # TODO: This should be marked as noreturn
  #                  return

  #   for name, value in preset.values:
  #     let
  #       typ = getType(name)
  #       value = if typ in ["int64", "uint64", "byte"]: typ & "(" & value & ")"
  #               else: "parse(" & typ & ", \"" & value & "\")"
  #     try:
  #       result.add parseStmt("const $1* {.intdefine.} = $2" % [$name, value])
  #     except ValueError:
  #       doAssert false, "All values in the presets are printable"

  #   if preset.missingValues.card > 0:
  #     warning "Missing constants in preset: " & $preset.missingValues

  # createConstantsFromPreset const_preset

const SLOTS_PER_SYNC_COMMITTEE_PERIOD* =
  SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.3/specs/phase0/p2p-interface.md#configuration
func safeMinEpochsForBlockRequests*(cfg: RuntimeConfig): uint64 =
  cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY + cfg.CHURN_LIMIT_QUOTIENT div 2

func parse(T: type uint64, input: string): T {.raises: [ValueError].} =
  var res: BiggestUInt
  if input.len > 2 and input[0] == '0' and input[1] == 'x':
    if parseHex(input, res) != input.len:
      raise newException(ValueError, "The constant value should be a valid hex integer")
  else:
    if parseBiggestUInt(input, res) != input.len:
      raise newException(ValueError, "The constant value should be a valid unsigned integer")

  uint64(res)

template parse(T: type byte, input: string): T =
  byte parse(uint64, input)

func parse(T: type array[4, byte], input: string): T
           {.raises: [ValueError].} =
  hexToByteArray(input, 4)

func parse(T: type Version, input: string): T
           {.raises: [ValueError].} =
  Version hexToByteArray(input, 4)

template parse(T: type uint64, input: string): T =
  uint64 parse(uint64, input)

template parse(T: type string, input: string): T =
  input.strip(chars = {'"', '\''})

template parse(T: type Eth1Address, input: string): T =
  Eth1Address.fromHex(input)

template parse(T: type BlockHash, input: string): T =
  BlockHash.fromHex(input)

template parse(T: type UInt256, input: string): T =
  parse(input, UInt256, 10)

template name*(cfg: RuntimeConfig): string =
  if cfg.CONFIG_NAME.len() > 0:
    cfg.CONFIG_NAME
  else:
    const_preset

func defaultLightClientDataMaxPeriods*(cfg: RuntimeConfig): uint64 =
  const epochsPerPeriod = EPOCHS_PER_SYNC_COMMITTEE_PERIOD
  let maxEpochs = cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS
  (maxEpochs + epochsPerPeriod - 1) div epochsPerPeriod

# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[macros, strutils, parseutils, tables],
  stew/endians2,
  web3/[ethtypes]

export
  toBytesBE

const
  BLS_WITHDRAWAL_PREFIX*: byte = 0

  # Constants from `validator.md` not covered by config/presets in the spec
  TARGET_AGGREGATORS_PER_COMMITTEE*: uint64 = 16
  RANDOM_SUBNETS_PER_VALIDATOR*: uint64 = 1
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION*: uint64 = 256

type
  Slot* = distinct uint64
  Epoch* = distinct uint64
  Version* = distinct array[4, byte]
  Eth1Address* = ethtypes.Address

  RuntimeConfig* = object
    ## https://github.com/ethereum/eth2.0-specs/tree/1d5c4ecffbadc70b62189cb4219be055b8efa2e9/configs

    PRESET_BASE*: string

    # Genesis
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT*: uint64
    MIN_GENESIS_TIME*: uint64
    GENESIS_FORK_VERSION*: Version
    GENESIS_DELAY*: uint64

    # Altair
    ALTAIR_FORK_VERSION*: Version
    ALTAIR_FORK_EPOCH*: Epoch

    # Merge
    MERGE_FORK_VERSION*: Version
    MERGE_FORK_EPOCH*: Epoch

    # Sharding
    SHARDING_FORK_VERSION*: Version
    SHARDING_FORK_EPOCH*: Epoch

    MIN_ANCHOR_POW_BLOCK_DIFFICULTY*: uint64

    # SECONDS_PER_SLOT*: uint64
    SECONDS_PER_ETH1_BLOCK*: uint64
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64
    SHARD_COMMITTEE_PERIOD*: uint64
    ETH1_FOLLOW_DISTANCE*: uint64

    INACTIVITY_SCORE_BIAS*: uint64
    INACTIVITY_SCORE_RECOVERY_RATE*: uint64
    EJECTION_BALANCE*: uint64
    MIN_PER_EPOCH_CHURN_LIMIT*: uint64
    CHURN_LIMIT_QUOTIENT*: uint64

    DEPOSIT_CHAIN_ID*: uint64
    DEPOSIT_NETWORK_ID*: uint64
    DEPOSIT_CONTRACT_ADDRESS*: Eth1Address

  PresetFile* = object
    values*: Table[TaintedString, TaintedString]
    missingValues*: seq[string]

  PresetFileError* = object of CatchableError
  PresetIncompatibleError* = object of CatchableError

const
  const_preset* {.strdefine.} = "mainnet"

  # These constants cannot really be overriden in a preset.
  # If we encounter them, we'll just ignore the preset value.
  # TODO verify the value against the constant instead
  ignoredValues* = [
    "SECONDS_PER_SLOT",

    "BLS_WITHDRAWAL_PREFIX",

    "MAX_COMMITTEES_PER_SLOT",
    "TARGET_COMMITTEE_SIZE",
    "MAX_VALIDATORS_PER_COMMITTEE",
    "SHUFFLE_ROUND_COUNT",
    "HYSTERESIS_QUOTIENT",
    "HYSTERESIS_DOWNWARD_MULTIPLIER",
    "HYSTERESIS_UPWARD_MULTIPLIER",
    "SAFE_SLOTS_TO_UPDATE_JUSTIFIED",
    "MIN_DEPOSIT_AMOUNT",
    "MAX_EFFECTIVE_BALANCE",
    "EFFECTIVE_BALANCE_INCREMENT",
    "MIN_ATTESTATION_INCLUSION_DELAY",
    "SLOTS_PER_EPOCH",
    "MIN_SEED_LOOKAHEAD",
    "MAX_SEED_LOOKAHEAD",
    "EPOCHS_PER_ETH1_VOTING_PERIOD",
    "SLOTS_PER_HISTORICAL_ROOT",
    "MIN_EPOCHS_TO_INACTIVITY_PENALTY",
    "EPOCHS_PER_HISTORICAL_VECTOR",
    "EPOCHS_PER_SLASHINGS_VECTOR",
    "HISTORICAL_ROOTS_LIMIT",
    "VALIDATOR_REGISTRY_LIMIT",
    "BASE_REWARD_FACTOR",
    "WHISTLEBLOWER_REWARD_QUOTIENT",
    "PROPOSER_REWARD_QUOTIENT",
    "INACTIVITY_PENALTY_QUOTIENT",
    "MIN_SLASHING_PENALTY_QUOTIENT",
    "PROPORTIONAL_SLASHING_MULTIPLIER",
    "MAX_PROPOSER_SLASHINGS",
    "MAX_ATTESTER_SLASHINGS",
    "MAX_ATTESTATIONS",
    "MAX_DEPOSITS",
    "MAX_VOLUNTARY_EXITS",

    "TARGET_AGGREGATORS_PER_COMMITTEE",
    "RANDOM_SUBNETS_PER_VALIDATOR",
    "EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION",
    "ATTESTATION_SUBNET_COUNT",

    "DOMAIN_BEACON_PROPOSER",
    "DOMAIN_BEACON_ATTESTER",
    "DOMAIN_RANDAO",
    "DOMAIN_DEPOSIT",
    "DOMAIN_VOLUNTARY_EXIT",
    "DOMAIN_SELECTION_PROOF",
    "DOMAIN_AGGREGATE_AND_PROOF",
    "DOMAIN_SYNC_COMMITTEE",
    "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF",
    "DOMAIN_CONTRIBUTION_AND_PROOF",

    "CONFIG_NAME",

    "TRANSITION_TOTAL_DIFFICULTY", # Name that appears in some altair alphas, obsolete, remove when no more testnets
  ]

when const_preset == "mainnet":
  import ./presets/mainnet
  export mainnet

  # TODO Move this to RuntimeConfig
  const SECONDS_PER_SLOT* {.intdefine.}: uint64 = 12

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.8/configs/mainnet.yaml
  # TODO Read these from yaml file
  const defaultRuntimeConfig* = RuntimeConfig(
    PRESET_BASE: "mainnet",

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
    ALTAIR_FORK_EPOCH: Epoch(uint64.high),
    # Merge
    MERGE_FORK_VERSION: Version [byte 0x02, 0x00, 0x00, 0x00],
    MERGE_FORK_EPOCH: Epoch(uint64.high),
    # Sharding
    SHARDING_FORK_VERSION: Version [byte 0x03, 0x00, 0x00, 0x00],
    SHARDING_FORK_EPOCH: Epoch(uint64.high),

    # TBD, 2**32 is a placeholder. Merge transition approach is in active R&D.
    MIN_ANCHOR_POW_BLOCK_DIFFICULTY: 4294967296'u64,


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


    # Deposit contract
    # ---------------------------------------------------------------
    # Ethereum PoW Mainnet
    DEPOSIT_CHAIN_ID: 1,
    DEPOSIT_NETWORK_ID: 1,
    DEPOSIT_CONTRACT_ADDRESS: Eth1Address.fromHex("0x00000000219ab540356cBB839Cbe05303d7705Fa")
  )

elif const_preset == "minimal":
  import ./presets/minimal
  export minimal

  const SECONDS_PER_SLOT* {.intdefine.}: uint64 = 6

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.8/configs/minimal.yaml
  const defaultRuntimeConfig* = RuntimeConfig(
    # Minimal config

    # Extends the minimal preset
    PRESET_BASE: "minimal",

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
    ALTAIR_FORK_EPOCH: Epoch(uint64.high),
    # Merge
    MERGE_FORK_VERSION: Version [byte 0x02, 0x00, 0x00, 0x01],
    MERGE_FORK_EPOCH: Epoch(uint64.high),
    # Sharding
    SHARDING_FORK_VERSION: Version [byte 0x03, 0x00, 0x00, 0x01],
    SHARDING_FORK_EPOCH: Epoch(uint64.high),

    # TBD, 2**32 is a placeholder. Merge transition approach is in active R&D.
    MIN_ANCHOR_POW_BLOCK_DIFFICULTY: 4294967296'u64,


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
    # 2**2 (= 4)
    MIN_PER_EPOCH_CHURN_LIMIT: 4,
    # 2**16 (= 65,536)
    CHURN_LIMIT_QUOTIENT: 65536,


    # Deposit contract
    # ---------------------------------------------------------------
    # Ethereum Goerli testnet
    DEPOSIT_CHAIN_ID: 5,
    DEPOSIT_NETWORK_ID: 5,
    # Configured on a per testnet basis
    DEPOSIT_CONTRACT_ADDRESS: Eth1Address.fromHex("0x1234567890123456789012345678901234567890")
  )

else:
  {.error: "Only mainnet and minimal presets supported".}
  # macro createConstantsFromPreset*(path: static string): untyped =
  #   result = newStmtList()

  #   let preset = try: readPresetFile(path)
  #                except CatchableError as err:
  #                  error err.msg # TODO: This should be marked as noReturn
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

func parse(T: type uint64, input: string): T {.raises: [ValueError, Defect].} =
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

func parse(T: type Version, input: string): T
           {.raises: [ValueError, Defect].} =
  Version toBytesBE(uint32 parse(uint64, input))

template parse(T: type Slot, input: string): T =
  Slot parse(uint64, input)

template parse(T: type Epoch, input: string): T =
  Epoch parse(uint64, input)

template parse(T: type string, input: string): T =
  input.strip(chars = {'"', '\''})

template parse(T: type Eth1Address, input: string): T =
  Eth1Address.fromHex(input)

proc readRuntimeConfig*(
    path: string): (RuntimeConfig, seq[string]) {.
    raises: [IOError, PresetFileError, PresetIncompatibleError, Defect].} =
  var
    lineNum = 0
    cfg = defaultRuntimeConfig
    unknowns: seq[string]

  template lineinfo: string =
    try: "$1($2) " % [path, $lineNum]
    except ValueError: path

  template fail(msg) =
    raise newException(PresetFileError, lineinfo() & msg)

  var names: seq[string]
  for name, field in cfg.fieldPairs():
    names.add name

  var values: Table[string, string]
  for line in splitLines(readFile(path)):
    inc lineNum
    if line.len == 0 or line[0] == '#': continue

    var lineParts = line.split(":")
    if lineParts.len != 2:
      fail "Invalid syntax: A preset file should include only assignments in the form 'ConstName: Value'"

    if lineParts[0] in ignoredValues: continue

    if lineParts[0] notin names:
      unknowns.add(lineParts[0])

    values[lineParts[0]] = lineParts[1].strip

  for name, field in cfg.fieldPairs():
    if name in values:
      try:
        field = parse(typeof(field), values[name])
      except ValueError:
        raise (ref PresetFileError)(msg: "Unable to parse " & name)

  if cfg.PRESET_BASE != const_preset:
    raise (ref PresetIncompatibleError)(
      msg: "Config not compatible with binary, compile with -d:const_preset=" & cfg.PRESET_BASE)

  (cfg, unknowns)

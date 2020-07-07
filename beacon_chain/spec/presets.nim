import
  macros, strutils, parseutils, tables,
  stew/endians2

{.push raises: [Defect].}

export
  toBytesBE

type
  Slot* = distinct uint64
  Epoch* = distinct uint64
  Version* = distinct array[4, byte]

  PresetValue* {.pure.} = enum
    BASE_REWARD_FACTOR
    BLS_WITHDRAWAL_PREFIX
    CHURN_LIMIT_QUOTIENT
    DEPOSIT_CONTRACT_ADDRESS
    DOMAIN_AGGREGATE_AND_PROOF
    DOMAIN_BEACON_ATTESTER
    DOMAIN_BEACON_PROPOSER
    DOMAIN_DEPOSIT
    DOMAIN_RANDAO
    DOMAIN_SELECTION_PROOF
    DOMAIN_VOLUNTARY_EXIT
    EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE
    EFFECTIVE_BALANCE_INCREMENT
    EJECTION_BALANCE
    EPOCHS_PER_ETH1_VOTING_PERIOD
    EPOCHS_PER_HISTORICAL_VECTOR
    EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION
    EPOCHS_PER_SLASHINGS_VECTOR
    ETH1_FOLLOW_DISTANCE
    GENESIS_FORK_VERSION
    GENESIS_DELAY
    HISTORICAL_ROOTS_LIMIT
    HYSTERESIS_DOWNWARD_MULTIPLIER
    HYSTERESIS_QUOTIENT
    HYSTERESIS_UPWARD_MULTIPLIER
    INACTIVITY_PENALTY_QUOTIENT
    MAX_ATTESTATIONS
    MAX_ATTESTER_SLASHINGS
    MAX_COMMITTEES_PER_SLOT
    MAX_DEPOSITS
    MAX_EFFECTIVE_BALANCE
    MAX_EPOCHS_PER_CROSSLINK
    MAX_PROPOSER_SLASHINGS
    MAX_SEED_LOOKAHEAD
    MAX_VALIDATORS_PER_COMMITTEE
    MAX_VOLUNTARY_EXITS
    MIN_ATTESTATION_INCLUSION_DELAY
    MIN_DEPOSIT_AMOUNT
    MIN_EPOCHS_TO_INACTIVITY_PENALTY
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
    MIN_GENESIS_TIME
    MIN_PER_EPOCH_CHURN_LIMIT
    MIN_SEED_LOOKAHEAD
    MIN_SLASHING_PENALTY_QUOTIENT
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    PROPOSER_REWARD_QUOTIENT
    RANDOM_SUBNETS_PER_VALIDATOR
    SAFE_SLOTS_TO_UPDATE_JUSTIFIED
    SECONDS_PER_ETH1_BLOCK
    SECONDS_PER_SLOT
    SHARD_COMMITTEE_PERIOD
    SHUFFLE_ROUND_COUNT
    SLOTS_PER_EPOCH
    SLOTS_PER_HISTORICAL_ROOT
    TARGET_AGGREGATORS_PER_COMMITTEE
    TARGET_COMMITTEE_SIZE
    VALIDATOR_REGISTRY_LIMIT
    WHISTLEBLOWER_REWARD_QUOTIENT

  RuntimePreset* = object
    GENESIS_FORK_VERSION*: Version
    GENESIS_DELAY*: uint64
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT*: uint64
    MIN_GENESIS_TIME*: uint64

  PresetFile* = object
    values*: Table[PresetValue, TaintedString]
    missingValues*: set[PresetValue]

  PresetFileError* = object of CatchableError

const
  const_preset* {.strdefine.} = "mainnet"

  runtimeValues* = {
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
    MIN_GENESIS_TIME,
    GENESIS_FORK_VERSION,
    GENESIS_DELAY,
  }

  # These constants cannot really be overriden in a preset.
  # If we encounter them, we'll just ignore the preset value.
  ignoredValues* = {
    # The deposit contract address is loaded through a dedicated
    # metadata file. It would break the property we are exploiting
    # right now that all preset values can be parsed as uint64
    DEPOSIT_CONTRACT_ADDRESS,

    # These are defined as an enum in datatypes.nim:
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_RANDAO,
    DOMAIN_DEPOSIT,
    DOMAIN_VOLUNTARY_EXIT,
    DOMAIN_SELECTION_PROOF,
    DOMAIN_AGGREGATE_AND_PROOF,
  }

  presetValueTypes* = {
    BASE_REWARD_FACTOR: "uint64",
    BLS_WITHDRAWAL_PREFIX: "byte",
    EFFECTIVE_BALANCE_INCREMENT: "uint64",
    EJECTION_BALANCE: "uint64",
    EPOCHS_PER_SLASHINGS_VECTOR: "uint64",
    GENESIS_DELAY: "uint64",
    GENESIS_FORK_VERSION: "Version",
    INACTIVITY_PENALTY_QUOTIENT: "uint64",
    MAX_EFFECTIVE_BALANCE: "uint64",
    MIN_DEPOSIT_AMOUNT: "uint64",
    MIN_EPOCHS_TO_INACTIVITY_PENALTY: "uint64",
    MIN_GENESIS_TIME: "uint64",
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: "uint64",
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: "uint64",
    PROPOSER_REWARD_QUOTIENT: "uint64",
    SECONDS_PER_SLOT: "uint64",
    WHISTLEBLOWER_REWARD_QUOTIENT: "uint64",
  }.toTable

func parse*(T: type uint64, input: string): T
           {.raises: [ValueError, Defect].} =
  var res: BiggestUInt
  if input.len > 2 and input[0] == '0' and input[1] == 'x':
    if parseHex(input, res) != input.len:
      raise newException(ValueError, "The constant value should be a valid hex integer")
  else:
    if parseBiggestUInt(input, res) != input.len:
      raise newException(ValueError, "The constant value should be a valid unsigned integer")

  result = uint64(res)

template parse*(T: type byte, input: string): T =
  byte parse(uint64, input)

template parse*(T: type int, input: string): T =
  # TODO: remove this
  int parse(uint64, input)

proc parse*(T: type Version, input: string): T
           {.raises: [ValueError, Defect].} =
  Version toBytesBE(uint32 parse(uint64, input))

template parse*(T: type Slot, input: string): T =
  Slot parse(uint64, input)

template getType*(presetValue: PresetValue): string =
  presetValueTypes.getOrDefault(presetValue, "int")

template toUInt64*(v: Version): uint64 =
  fromBytesBE(uint64, array[4, byte](v))

template entireSet(T: type enum): untyped =
  {low(T) .. high(T)}

proc readPresetFile*(path: string): PresetFile
                    {.raises: [IOError, PresetFileError, Defect].} =
  var
    lineNum = 0
    presetValues = ignoredValues

  template lineinfo: string =
    try: "$1($2) " % [path, $lineNum]
    except ValueError: path

  template fail(msg) =
    raise newException(PresetFileError, lineinfo() & msg)

  for line in splitLines(readFile(path)):
    inc lineNum
    if line.len == 0 or line[0] == '#': continue

    var lineParts = line.split(":")
    if lineParts.len != 2:
      fail "Invalid syntax: A preset file should include only assignments in the form 'ConstName: Value'"

    let value = try: parseEnum[PresetValue](lineParts[0])
                except ValueError: fail "Unrecognized constant in a preset: " & lineParts[0]

    if value in ignoredValues: continue
    presetValues.incl value
    result.values.add value, lineParts[1].strip

  result.missingValues = PresetValue.entireSet - presetValues

const
  mainnetRuntimePreset* = RuntimePreset(
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 16384,
    MIN_GENESIS_TIME: 1578009600,
    GENESIS_FORK_VERSION: Version [byte 0, 0, 0, 0],
    GENESIS_DELAY: 172800)

  minimalRuntimePreset* = RuntimePreset(
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 64,
    MIN_GENESIS_TIME: 1578009600,
    GENESIS_FORK_VERSION: Version [byte 0, 0, 0, 1],
    GENESIS_DELAY: 300)

when const_preset == "mainnet":
  template defaultRuntimePreset*: auto = mainnetRuntimePreset
  import ./presets/v0_12_1/mainnet
  export mainnet

elif const_preset == "minimal":
  template defaultRuntimePreset*: auto = minimalRuntimePreset
  import ./presets/v0_12_1/minimal
  export minimal

else:
  macro createConstantsFromPreset*(path: static string): untyped =
    result = newStmtList()

    let preset = try: readPresetFile(path)
                 except CatchableError as err:
                   error err.msg # TODO: This should be marked as noReturn
                   return

    for name, value in preset.values:
      var value = string value
      if presetValueTypes.hasKey(name):
        let typ = presetValueTypes[name]
        value = typ & "(" & value & ")"

      result.add parseStmt("const $1* {.intdefine.} = $2" % [$name, value])

    if preset.missingValues.card > 0:
      warning "Missing constants in preset: " & $preset.missingValues

  createConstantsFromPreset const_preset

  const defaultRuntimePreset* = RuntimePreset(
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
    MIN_GENESIS_TIME: MIN_GENESIS_TIME,
    GENESIS_FORK_VERSION: GENESIS_FORK_VERSION,
    GENESIS_DELAY: GENESIS_DELAY)


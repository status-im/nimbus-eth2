import
  macros, strutils, parseutils, tables,
  stew/endians2

export
  toBytesBE

type
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

const
  runtimeValues* = {
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
    MIN_GENESIS_TIME,
    DEPOSIT_CONTRACT_ADDRESS,
    GENESIS_FORK_VERSION,
    GENESIS_DELAY,
  }

  # These constants cannot really be overriden in a preset.
  # If we encounter them, we'll just ignore the preset value.
  ignoredValues = {
    # The deposit contract address is loaded through a dedicated
    # metadata file. It would break the property we are exploiting
    # right now that all preset values can be parsed as uint64
    DEPOSIT_CONTRACT_ADDRESS

    # These are defined as an enum in datatypes.nim:
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_RANDAO,
    DOMAIN_DEPOSIT,
    DOMAIN_VOLUNTARY_EXIT,
    DOMAIN_SELECTION_PROOF,
    DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_CUSTODY_BIT_SLASHING,
  }

  presetValueTypes* = {
    BASE_REWARD_FACTOR: "uint64",
    BLS_WITHDRAWAL_PREFIX: "byte",
    EFFECTIVE_BALANCE_INCREMENT: "uint64",
    EJECTION_BALANCE: "uint64",
    EPOCHS_PER_SLASHINGS_VECTOR: "uint64",
    GENESIS_FORK_VERSION: "Version",
    GENESIS_SLOT: "Slot",
    INACTIVITY_PENALTY_QUOTIENT: "uint64",
    MAX_EFFECTIVE_BALANCE: "uint64",
    MIN_DEPOSIT_AMOUNT: "uint64",
    MIN_EPOCHS_TO_INACTIVITY_PENALTY: "uint64",
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: "uint64",
    PROPOSER_REWARD_QUOTIENT: "uint64",
    SECONDS_PER_SLOT: "uint64",
    WHISTLEBLOWER_REWARD_QUOTIENT: "uint64",
  }.toTable

func parse*(T: type uint64, input: string): T
           {.raises: [ValueError, Defect].} =
  if input.len > 2 and input[0] == '0' and input[1] == 'x':
    parseHex(input, result)
  else:
    parseInt(input, result)

template parse*(T: type byte, input: string): T =
  byte parse(uint64, input)

proc parse*(T: type Version, input: string): T =
  toBytesBE(uint32 parse(uint64, input))

template parse*(T: type Slot, input: string): T =
  Slot parse(uint64, input)

template getType*(presetValue: PresetValue): string =
  presetValueTypes.getOrDefault(presetValue, "int")

template entireSet(T: type enum): untyped =
  {low(T) .. high(T)}

macro genRuntimePresetType: untyped =
  var fields = newTree(nnkRecList)

  for field in runtimeValues:
    fields.add newTree(nnkIdentDefs,
                       ident $field,
                       ident getType(field),
                       newEmptyNode()) # default value

  result = newTree(nnkObjectTy,
                   newEmptyNode(), # pragmas
                   newEmptyNode(), # base type
                   fields)

type
  RuntimePresetObj* = genRuntimePresetType()
  RuntimePreset* = ref RuntimePresetObj

  PresetFile = object
    values*: Table[PresetValue, TaintedString]
    missingValues*: set[PresetValue]

  PresetFileError = object of CatchableError

proc readPresetFile(path: string): PresetFile
                   {.raises: [IOError, PresetFileError, Defect].} =
  var
    lineNum = 0
    presetValues = ignoredValues

  template lineinfo: string =
    "$1($2) " % [path, $lineNum]

  template fail(msg) =
    raise newException(PresetFileError, lineinfo & msg)

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
    result.add value, lineParts[1]

  result.missingValues = PresetValue.entireSet - presetValues

macro createConstantsFromPreset*(path: static string): untyped =
  result = newStmtList()

  let preset = try: loadPreset(path)
               except PresetError as err: error err.msg

  for name, value in preset:
    var value = value
    if presetValueTypes.hasKey(name):
      let typ = presetValueTypes[name]
      value = typ & "(" & value & ")"

    result.add parseStmt("const $1* {.intdefine.} = $2" % [name, value])

  if preset.missingValues.card > 0:
    warning "Missing constants in preset: " & $preset.missingValues


import
  macros, strutils, tables

type
  BeaconChainConstants* = enum
    BASE_REWARDS_PER_EPOCH
    BASE_REWARD_FACTOR
    BLS_WITHDRAWAL_PREFIX
    CHURN_LIMIT_QUOTIENT
    DEPOSIT_CONTRACT_TREE_DEPTH
    DOMAIN_BEACON_ATTESTER
    DOMAIN_BEACON_PROPOSER
    DOMAIN_DEPOSIT
    DOMAIN_RANDAO
    DOMAIN_VOLUNTARY_EXIT
    EFFECTIVE_BALANCE_INCREMENT
    EJECTION_BALANCE
    EPOCHS_PER_HISTORICAL_VECTOR
    EPOCHS_PER_SLASHINGS_VECTOR
    ETH1_FOLLOW_DISTANCE
    GENESIS_EPOCH
    GENESIS_SLOT
    HISTORICAL_ROOTS_LIMIT
    INACTIVITY_PENALTY_QUOTIENT
    JUSTIFICATION_BITS_LENGTH
    MAX_ATTESTATIONS
    MAX_ATTESTER_SLASHINGS
    MAX_COMMITTEES_PER_SLOT
    MAX_DEPOSITS
    MAX_EFFECTIVE_BALANCE
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
    PERSISTENT_COMMITTEE_PERIOD
    PROPOSER_REWARD_QUOTIENT
    SAFE_SLOTS_TO_UPDATE_JUSTIFIED
    SECONDS_PER_DAY
    SECONDS_PER_SLOT
    SHUFFLE_ROUND_COUNT
    SLOTS_PER_EPOCH
    SLOTS_PER_ETH1_VOTING_PERIOD
    SLOTS_PER_HISTORICAL_ROOT
    TARGET_COMMITTEE_SIZE
    VALIDATOR_REGISTRY_LIMIT
    WHISTLEBLOWER_REWARD_QUOTIENT

const
  # These constants cannot really be overriden in a preset.
  # If we encounter them, we'll just ignore the preset value.
  dubiousConstants = {
    # They are derived from other constants:
    GENESIS_EPOCH,
    SECONDS_PER_DAY,

    # These are defined as an enum in datatypes.nim:
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_DEPOSIT,
    DOMAIN_RANDAO,
    DOMAIN_VOLUNTARY_EXIT,
  }

const
  customTypes = {
    GENESIS_SLOT: "Slot",
    BLS_WITHDRAWAL_PREFIX: "byte",
    BASE_REWARD_FACTOR: "uint64",
    EFFECTIVE_BALANCE_INCREMENT: "uint64",
    EJECTION_BALANCE: "uint64",
    EPOCHS_PER_SLASHINGS_VECTOR: "uint64",
    INACTIVITY_PENALTY_QUOTIENT: "uint64",
    MAX_EFFECTIVE_BALANCE: "uint64",
    MIN_DEPOSIT_AMOUNT: "uint64",
    MIN_EPOCHS_TO_INACTIVITY_PENALTY: "uint64",
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: "uint64",
    PERSISTENT_COMMITTEE_PERIOD: "uint64",
    PROPOSER_REWARD_QUOTIENT: "uint64",
    SECONDS_PER_SLOT: "uint64",
    WHISTLEBLOWER_REWARD_QUOTIENT: "uint64",
  }.toTable

template entireSet(T: type enum): untyped =
  {low(T) .. high(T)}

macro loadCustomPreset*(path: static string): untyped =
  result = newStmtList()

  var
    presetContents = staticRead(path)
    presetConstants = dubiousConstants
    lineNum = 0

  for line in splitLines(presetContents):
    inc lineNum
    if line.len == 0 or line[0] == '#': continue

    template lineinfo: string =
      "$1($2) " % [path, $lineNum]

    var constParts = line.split(":")
    if constParts.len != 2:
      error lineinfo & "Invalid syntax: A preset file should include only assignments in the form 'ConstName: Value'"

    try:
      let constant = parseEnum[BeaconChainConstants](constParts[0])
      if constant in dubiousConstants: continue
      constParts.add customTypes.getOrDefault(constant, "int")
      presetConstants.incl constant
    except ValueError:
      warning lineinfo & "Unrecognized constant in a preset: " & constParts[0]
      continue

    result.add parseStmt("const $1* {.intdefine.} = $3($2)" % constParts)

  let missingConstants = BeaconChainConstants.entireSet - presetConstants
  if missingConstants.card > 0:
    warning "Missing constants in preset: " & $missingConstants


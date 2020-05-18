import
  macros, strutils, tables,
  stew/endians2

export
  toBytesBE

type
  BeaconChainConstants* {.pure.} = enum
    BASE_REWARDS_PER_EPOCH
    BASE_REWARD_FACTOR
    BLS_WITHDRAWAL_PREFIX
    CHURN_LIMIT_QUOTIENT
    CUSTODY_PERIOD_TO_RANDAO_PADDING
    DEPOSIT_CONTRACT_ADDRESS
    DEPOSIT_CONTRACT_TREE_DEPTH
    DOMAIN_AGGREGATE_AND_PROOF
    DOMAIN_BEACON_ATTESTER
    DOMAIN_BEACON_PROPOSER
    DOMAIN_CUSTODY_BIT_SLASHING
    DOMAIN_DEPOSIT
    DOMAIN_LIGHT_CLIENT
    DOMAIN_RANDAO
    DOMAIN_SELECTION_PROOF
    DOMAIN_SHARD_COMMITTEE
    DOMAIN_SHARD_PROPOSAL
    DOMAIN_VOLUNTARY_EXIT
    EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS
    EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE
    EFFECTIVE_BALANCE_INCREMENT
    EJECTION_BALANCE
    EPOCHS_PER_CUSTODY_PERIOD
    EPOCHS_PER_ETH1_VOTING_PERIOD
    EPOCHS_PER_HISTORICAL_VECTOR
    EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION
    EPOCHS_PER_SLASHINGS_VECTOR
    ETH1_FOLLOW_DISTANCE
    GASPRICE_ADJUSTMENT_COEFFICIENT
    GENESIS_EPOCH
    GENESIS_FORK_VERSION
    GENESIS_SLOT
    HISTORICAL_ROOTS_LIMIT
    HYSTERESIS_DOWNWARD_MULTIPLIER
    HYSTERESIS_QUOTIENT
    HYSTERESIS_UPWARD_MULTIPLIER
    INACTIVITY_PENALTY_QUOTIENT
    INITIAL_ACTIVE_SHARDS
    JUSTIFICATION_BITS_LENGTH
    LIGHT_CLIENT_COMMITTEE_PERIOD
    LIGHT_CLIENT_COMMITTEE_SIZE
    MAX_ATTESTATIONS
    MAX_ATTESTER_SLASHINGS
    MAX_COMMITTEES_PER_SLOT
    MAX_CUSTODY_KEY_REVEALS
    MAX_CUSTODY_SLASHINGS
    MAX_DEPOSITS
    MAX_EARLY_DERIVED_SECRET_REVEALS
    MAX_EFFECTIVE_BALANCE
    MAX_EPOCHS_PER_CROSSLINK
    MAX_GASPRICE
    MAX_PROPOSER_SLASHINGS
    MAX_REVEAL_LATENESS_DECREMENT
    MAX_SEED_LOOKAHEAD
    MAX_SHARDS
    MAX_SHARD_BLOCKS_PER_ATTESTATION
    MAX_SHARD_BLOCK_CHUNKS
    MAX_VALIDATORS_PER_COMMITTEE
    MAX_VOLUNTARY_EXITS
    MINOR_REWARD_QUOTIENT
    MIN_ATTESTATION_INCLUSION_DELAY
    MIN_DEPOSIT_AMOUNT
    MIN_EPOCHS_TO_INACTIVITY_PENALTY
    MIN_GASPRICE
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT
    MIN_GENESIS_DELAY
    MIN_GENESIS_TIME
    MIN_PER_EPOCH_CHURN_LIMIT
    MIN_SEED_LOOKAHEAD
    MIN_SLASHING_PENALTY_QUOTIENT
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    ONLINE_PERIOD
    PERSISTENT_COMMITTEE_PERIOD
    PHASE_1_FORK_VERSION
    PROPOSER_REWARD_QUOTIENT
    RANDAO_PENALTY_EPOCHS
    RANDOM_SUBNETS_PER_VALIDATOR
    SAFE_SLOTS_TO_UPDATE_JUSTIFIED
    SECONDS_PER_DAY
    SECONDS_PER_ETH1_BLOCK
    SECONDS_PER_SLOT
    SHARD_BLOCK_CHUNK_SIZE
    SHARD_BLOCK_OFFSETS
    SHARD_COMMITTEE_PERIOD
    SHUFFLE_ROUND_COUNT
    SLOTS_PER_EPOCH
    SLOTS_PER_HISTORICAL_ROOT
    TARGET_AGGREGATORS_PER_COMMITTEE
    TARGET_COMMITTEE_SIZE
    TARGET_SHARD_BLOCK_SIZE
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
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_RANDAO,
    DOMAIN_DEPOSIT,
    DOMAIN_VOLUNTARY_EXIT,
    DOMAIN_SELECTION_PROOF,
    DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_SHARD_PROPOSAL,
    DOMAIN_SHARD_COMMITTEE,
    DOMAIN_LIGHT_CLIENT,
    DOMAIN_CUSTODY_BIT_SLASHING,
  }

const
  forkVersionConversionFn = "'u32.toBytesBE"
    # The fork version appears as a number in the preset,
    # but our codebase works with a byte array.

  customTypes = {
    BASE_REWARD_FACTOR: "'u64",
    BLS_WITHDRAWAL_PREFIX: ".byte",
    EFFECTIVE_BALANCE_INCREMENT: "'u64",
    EJECTION_BALANCE: "'u64",
    EPOCHS_PER_SLASHINGS_VECTOR: "'u64",
    GENESIS_FORK_VERSION: forkVersionConversionFn,
    GENESIS_SLOT: ".Slot",
    INACTIVITY_PENALTY_QUOTIENT: "'u64",
    MAX_EFFECTIVE_BALANCE: "'u64",
    MIN_DEPOSIT_AMOUNT: "'u64",
    MIN_EPOCHS_TO_INACTIVITY_PENALTY: "'u64",
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY: "'u64",
    PERSISTENT_COMMITTEE_PERIOD: "'u64",
    PHASE_1_FORK_VERSION: forkVersionConversionFn,
    PROPOSER_REWARD_QUOTIENT: "'u64",
    SECONDS_PER_SLOT: "'u64",
    WHISTLEBLOWER_REWARD_QUOTIENT: "'u64",
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
      if customTypes.hasKey(constant):
        constParts.add customTypes[constant]
      presetConstants.incl constant
    except ValueError:
      warning lineinfo & "Unrecognized constant in a preset: " & constParts[0]
      continue

    if constParts.len == 3:
      result.add parseStmt("const $1* {.intdefine.} = $2$3" % constParts)
    else:
      result.add parseStmt("const $1* {.intdefine.} = $2" % constParts)

  let missingConstants = BeaconChainConstants.entireSet - presetConstants
  if missingConstants.card > 0:
    warning "Missing constants in preset: " & $missingConstants


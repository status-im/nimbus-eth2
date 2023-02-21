# Minimal preset - Phase0
# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.3/presets/minimal/phase0.yaml

const
  #
  # Misc
  # ---------------------------------------------------------------
  # [customized] Just 4 committees for slot for testing purposes
  MAX_COMMITTEES_PER_SLOT* {.intdefine.}: uint64 = 4
  # [customized] insecure, but fast
  TARGET_COMMITTEE_SIZE*: uint64 = 4
  # 2**11 (= 2,048)
  MAX_VALIDATORS_PER_COMMITTEE*: uint64 = 2048
  # [customized] Faster, but insecure.
  SHUFFLE_ROUND_COUNT*: uint64 = 10
  # 4
  HYSTERESIS_QUOTIENT*: uint64 = 4
  # 1 (minus 0.25)
  HYSTERESIS_DOWNWARD_MULTIPLIER*: uint64 = 1
  # 5 (plus 1.25)
  HYSTERESIS_UPWARD_MULTIPLIER*: uint64 = 5


  # Fork Choice
  # ---------------------------------------------------------------
  # 2**1 (= 1)
  SAFE_SLOTS_TO_UPDATE_JUSTIFIED*: uint64 = 2


  # Gwei values
  # ---------------------------------------------------------------
  # 2**0 * 10**9 (= 1,000,000,000) Gwei
  MIN_DEPOSIT_AMOUNT*: uint64 = 1000000000
  # 2**5 * 10**9 (= 32,000,000,000) Gwei
  MAX_EFFECTIVE_BALANCE*: uint64 = 32000000000'u64
  # 2**0 * 10**9 (= 1,000,000,000) Gwei
  EFFECTIVE_BALANCE_INCREMENT*: uint64 = 1000000000


  # Time parameters
  # ---------------------------------------------------------------
  # 2**0 (= 1) slots 12 seconds
  MIN_ATTESTATION_INCLUSION_DELAY*: uint64 = 1
  # [customized] fast epochs
  SLOTS_PER_EPOCH* {.intdefine.}: uint64 = 8
  # 2**0 (= 1) epochs 6.4 minutes
  MIN_SEED_LOOKAHEAD*: uint64 = 1
  # 2**2 (= 4) epochs 25.6 minutes
  MAX_SEED_LOOKAHEAD*: uint64 = 4
  # [customized] higher frequency new deposits from eth1 for testing
  EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64 = 4
  # [customized] smaller state
  SLOTS_PER_HISTORICAL_ROOT*: uint64 = 64
  # 2**2 (= 4) epochs 25.6 minutes
  MIN_EPOCHS_TO_INACTIVITY_PENALTY*: uint64 = 4


  # State list lengths
  # ---------------------------------------------------------------
  # [customized] smaller state
  EPOCHS_PER_HISTORICAL_VECTOR*: uint64 = 64
  # [customized] smaller state
  EPOCHS_PER_SLASHINGS_VECTOR*: uint64 = 64
  # 2**24 (= 16,777,216) historical roots, ~26,131 years
  HISTORICAL_ROOTS_LIMIT*: uint64 = 16777216
  # 2**40 (= 1,099,511,627,776) validator spots
  VALIDATOR_REGISTRY_LIMIT*: uint64 = 1099511627776'u64


  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # 2**6 (= 64)
  BASE_REWARD_FACTOR* {.intdefine.}: uint64 = 64
  # 2**9 (= 512)
  WHISTLEBLOWER_REWARD_QUOTIENT*: uint64 = 512
  # 2**3 (= 8)
  PROPOSER_REWARD_QUOTIENT*: uint64 = 8
  # [customized] 2**25 (= 33,554,432)
  INACTIVITY_PENALTY_QUOTIENT*: uint64 = 33554432
  # [customized] 2**6 (= 64)
  MIN_SLASHING_PENALTY_QUOTIENT*: uint64 = 64
  # [customized] 2 (lower safety margin than Phase 0 genesis but different than mainnet config for testing)
  PROPORTIONAL_SLASHING_MULTIPLIER*: uint64 = 2


  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_PROPOSER_SLASHINGS*: uint64 = 16
  # 2**1 (= 2)
  MAX_ATTESTER_SLASHINGS*: uint64 = 2
  # 2**7 (= 128)
  MAX_ATTESTATIONS*: uint64 = 128
  # 2**4 (= 16)
  MAX_DEPOSITS*: uint64 = 16
  # 2**4 (= 16)
  MAX_VOLUNTARY_EXITS*: uint64 = 16

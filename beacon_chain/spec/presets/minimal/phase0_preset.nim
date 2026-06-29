# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Minimal preset - Phase0
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/presets/minimal/phase0.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # [customized] 2**2 (= 4) committees
  MAX_COMMITTEES_PER_SLOT* {.intdefine.}: uint64 = 4
  # [customized] 2**2 (= 4) committees
  TARGET_COMMITTEE_SIZE*: uint64 = 4
  # 2**11 (= 2,048) validators
  MAX_VALIDATORS_PER_COMMITTEE*: uint64 = 2048
  # [customized]
  SHUFFLE_ROUND_COUNT*: uint64 = 10
  # 4
  HYSTERESIS_QUOTIENT*: uint64 = 4
  # 1 (minus 0.25)
  HYSTERESIS_DOWNWARD_MULTIPLIER*: uint64 = 1
  # 5 (plus 1.25)
  HYSTERESIS_UPWARD_MULTIPLIER*: uint64 = 5

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
  # 2**0 (= 1) slots
  MIN_ATTESTATION_INCLUSION_DELAY*: uint64 = 1
  # [customized] 2**3 (= 8) slots
  SLOTS_PER_EPOCH* {.intdefine.}: uint64 = 8
  # 2**0 (= 1) epochs
  MIN_SEED_LOOKAHEAD*: uint64 = 1
  # 2**2 (= 4) epochs
  MAX_SEED_LOOKAHEAD*: uint64 = 4
  # [customized] 2**2 (= 4) epochs
  EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64 = 4
  # [customized] 2**6 (= 64) slots
  SLOTS_PER_HISTORICAL_ROOT*: uint64 = 64
  # 2**2 (= 4) epochs
  MIN_EPOCHS_TO_INACTIVITY_PENALTY*: uint64 = 4

  # State list lengths
  # ---------------------------------------------------------------
  # [customized] 2**6 (= 64) epochs
  EPOCHS_PER_HISTORICAL_VECTOR*: uint64 = 64
  # [customized] 2**6 (= 64) epochs
  EPOCHS_PER_SLASHINGS_VECTOR*: uint64 = 64
  # 2**24 (= 16,777,216) historical roots
  HISTORICAL_ROOTS_LIMIT*: uint64 = 16777216
  # 2**40 (= 1,099,511,627,776) validator spots
  VALIDATOR_REGISTRY_LIMIT*: uint64 = 1099511627776'u64

  # Rewards and penalties
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
  # [customized] 2 (lower safety margin than Phase0 genesis but different than mainnet config for testing)
  PROPORTIONAL_SLASHING_MULTIPLIER*: uint64 = 2

  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16) proposer slashings
  MAX_PROPOSER_SLASHINGS*: uint64 = 16
  # 2**1 (= 2) attester slashings
  MAX_ATTESTER_SLASHINGS*: uint64 = 2
  # 2**7 (= 128) attestations
  MAX_ATTESTATIONS*: uint64 = 128
  # 2**4 (= 16) deposits
  MAX_DEPOSITS*: uint64 = 16
  # 2**4 (= 16) voluntary exits
  MAX_VOLUNTARY_EXITS*: uint64 = 16

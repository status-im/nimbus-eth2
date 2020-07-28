# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file contains constants that are part of the spec and thus subject to
# serialization and spec updates.

import
  math

{.experimental: "codeReordering".} # SLOTS_PER_EPOCH is use before being defined in spec

const
  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/configs/minimal.yaml#L4

  # Changed
  MAX_COMMITTEES_PER_SLOT*: uint64 = 4
  TARGET_COMMITTEE_SIZE*: uint64 = 4

  # Unchanged
  MAX_VALIDATORS_PER_COMMITTEE*: uint64 = 2048
  MIN_PER_EPOCH_CHURN_LIMIT*: uint64 = 4
  CHURN_LIMIT_QUOTIENT*: uint64 = 2'u64 ^ 16

  # Changed
  SHUFFLE_ROUND_COUNT*: uint64 = 10

  # Unchanged
  HYSTERESIS_QUOTIENT*: uint64 = 4
  HYSTERESIS_DOWNWARD_MULTIPLIER*: uint64 = 1
  HYSTERESIS_UPWARD_MULTIPLIER*: uint64 = 5

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/configs/minimal.yaml#L58

  # Unchanged
  MIN_DEPOSIT_AMOUNT*: uint64 = 2'u64^0 * 10'u64^9
  MAX_EFFECTIVE_BALANCE*: uint64 = 2'u64^5 * 10'u64^9
  EJECTION_BALANCE*: uint64 = 2'u64^4 * 10'u64^9
  EFFECTIVE_BALANCE_INCREMENT*: uint64 = 2'u64^0 * 10'u64^9

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/configs/minimal/phase0.yaml#L73

  BLS_WITHDRAWAL_PREFIX*: byte = 0

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/configs/minimal.yaml#L77
  # Changed: Faster to spin up testnets, but does not give validator
  # reasonable warning time for genesis

  # Unchanged
  SECONDS_PER_SLOT*{.intdefine.}: uint64 = 6

  # Unchanged
  MIN_ATTESTATION_INCLUSION_DELAY*: uint64 = 1

  # Changed
  SLOTS_PER_EPOCH* {.intdefine.}: uint64 = 8

  # Unchanged
  MIN_SEED_LOOKAHEAD*: uint64 = 1
  MAX_SEED_LOOKAHEAD*: uint64 = 4

  # Changed
  EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64 = 4
  SLOTS_PER_HISTORICAL_ROOT*: uint64 = 64

  # Unchanged
  MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64 = 2'u64^8

  SHARD_COMMITTEE_PERIOD*: uint64 = 64 # epochs

  # Unchanged
  MAX_EPOCHS_PER_CROSSLINK*: uint64 = 4

  # Changed
  MIN_EPOCHS_TO_INACTIVITY_PENALTY*: uint64 = 2'u64^2

  # State vector lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/configs/minimal/phase0.yaml#L108

  # Changed
  EPOCHS_PER_HISTORICAL_VECTOR*: uint64 = 64
  EPOCHS_PER_SLASHINGS_VECTOR*: uint64 = 64

  # Unchanged
  HISTORICAL_ROOTS_LIMIT*: uint64 = 16777216
  VALIDATOR_REGISTRY_LIMIT*: uint64 = 1099511627776'u64

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/configs/minimal/phase0.yaml#L120

  BASE_REWARD_FACTOR*: uint64 = 2'u64^6
  WHISTLEBLOWER_REWARD_QUOTIENT*: uint64 = 2'u64^9
  PROPOSER_REWARD_QUOTIENT*: uint64 = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT*: uint64 = 2'u64^24
  MIN_SLASHING_PENALTY_QUOTIENT*: uint64 = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/configs/minimal/phase0.yaml#L134

  MAX_PROPOSER_SLASHINGS*: uint64 = 2'u64 ^ 4
  MAX_ATTESTER_SLASHINGS*: uint64 = 2'u64 ^ 1
  MAX_ATTESTATIONS*: uint64 = 2'u64 ^ 7
  MAX_DEPOSITS*: uint64 = 2'u64 ^ 4
  MAX_VOLUNTARY_EXITS*: uint64 = 2'u64 ^ 4

  # Deposit contract
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/configs/minimal/phase0.yaml#L52

  # Ethereum Goerli testnet
  DEPOSIT_CHAIN_ID* = 5
  DEPOSIT_NETWORK_ID* = 5

  # Fork choice
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/configs/minimal/phase0.yaml#L32

  # Changed
  SAFE_SLOTS_TO_UPDATE_JUSTIFIED*: uint64 = 2

  # Validators
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/configs/minimal.yaml#L38

  # Changed
  ETH1_FOLLOW_DISTANCE* {.intdefine.}: uint64 = 16 # blocks

  # Unchanged
  TARGET_AGGREGATORS_PER_COMMITTEE*: uint64 = 16 # validators
  RANDOM_SUBNETS_PER_VALIDATOR*: uint64 = 1 # subnet
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION*: uint64 = 256 # epochs ~ 27 hours
  SECONDS_PER_ETH1_BLOCK* {.intdefine.}: uint64 = 14 # estimate from Eth1 mainnet)

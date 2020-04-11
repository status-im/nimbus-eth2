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

type
  Slot* = distinct uint64
  Epoch* = distinct uint64

{.experimental: "codeReordering".} # SLOTS_PER_EPOCH is use before being defined in spec

const
  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L4

  # Changed
  MAX_COMMITTEES_PER_SLOT* = 4
  TARGET_COMMITTEE_SIZE* = 4

  # Unchanged
  MAX_VALIDATORS_PER_COMMITTEE* = 2048
  MIN_PER_EPOCH_CHURN_LIMIT* = 4
  CHURN_LIMIT_QUOTIENT* = 2^16

  # Changed
  SHUFFLE_ROUND_COUNT* = 10
  MIN_GENESIS_ACTIVE_VALIDATOR_COUNT* {.intdefine.} = 64
  MIN_GENESIS_TIME* {.intdefine.} = 1578009600 # 3 Jan, 2020

  # Unchanged
  HYSTERESIS_QUOTIENT* = 4
  HYSTERESIS_DOWNWARD_MULTIPLIER* = 1
  HYSTERESIS_UPWARD_MULTIPLIER* = 5

  # Constants
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#constants
  # TODO "The following values are (non-configurable) constants" ...
  # Unchanged
  BASE_REWARDS_PER_EPOCH* = 4

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L58

  # Unchanged
  MIN_DEPOSIT_AMOUNT* = 2'u64^0 * 10'u64^9
  MAX_EFFECTIVE_BALANCE* = 2'u64^5 * 10'u64^9
  EJECTION_BALANCE* = 2'u64^4 * 10'u64^9
  EFFECTIVE_BALANCE_INCREMENT* = 2'u64^0 * 10'u64^9

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L70

  GENESIS_SLOT* = 0.Slot
  GENESIS_FORK_VERSION* = [0'u8, 0'u8, 0'u8, 1'u8]
  BLS_WITHDRAWAL_PREFIX* = 0'u8

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L77
  # Changed: Faster to spin up testnets, but does not give validator
  # reasonable warning time for genesis
  MIN_GENESIS_DELAY* = 300

  # Unchanged
  SECONDS_PER_SLOT*{.intdefine.} = 6'u64

  # Unchanged
  MIN_ATTESTATION_INCLUSION_DELAY* = 1

  # Changed
  SLOTS_PER_EPOCH* {.intdefine.} = 8

  # Unchanged
  MIN_SEED_LOOKAHEAD* = 1
  MAX_SEED_LOOKAHEAD* = 4

  # Changed
  EPOCHS_PER_ETH1_VOTING_PERIOD* = 2
  SLOTS_PER_HISTORICAL_ROOT* = 64

  # Unchanged
  MIN_VALIDATOR_WITHDRAWABILITY_DELAY* = 2'u64^8

  # Changed
  PERSISTENT_COMMITTEE_PERIOD* = 128

  # Unchanged
  MAX_EPOCHS_PER_CROSSLINK* = 4

  # Changed
  MIN_EPOCHS_TO_INACTIVITY_PENALTY* = 2'u64^2

  # State vector lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L105

  # Changed
  EPOCHS_PER_HISTORICAL_VECTOR* = 64
  EPOCHS_PER_SLASHINGS_VECTOR* = 64

  # Unchanged
  HISTORICAL_ROOTS_LIMIT* = 16777216
  VALIDATOR_REGISTRY_LIMIT* = 1099511627776

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L117

  BASE_REWARD_FACTOR* = 2'u64^6
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  PROPOSER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^25
  MIN_SLASHING_PENALTY_QUOTIENT* = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L131

  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_ATTESTER_SLASHINGS* = 2^0
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_VOLUNTARY_EXITS* = 2^4

  # Fork choice
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L32

  # Changed
  SAFE_SLOTS_TO_UPDATE_JUSTIFIED* = 2

  # Validators
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L38

  # Changed
  ETH1_FOLLOW_DISTANCE* = 16 # blocks

  # Unchanged
  TARGET_AGGREGATORS_PER_COMMITTEE* = 16 # validators
  RANDOM_SUBNETS_PER_VALIDATOR* = 1 # subnet
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION* = 256 # epochs ~ 27 hours
  SECONDS_PER_ETH1_BLOCK* = 14 # estimate from Eth1 mainnet)

  # Phase 1: Upgrade from Phase 0
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/configs/minimal.yaml#L161
  PHASE_1_FORK_VERSION* = 16777217
  INITIAL_ACTIVE_SHARDS* = 4
  INITIAL_GASPRICE* = 10

  # Phase 1: General
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/configs/minimal.yaml#L171
  MAX_SHARDS* = 8
  ONLINE_PERIOD* = 8 # epochs ~ 51 minutes
  LIGHT_CLIENT_COMMITTEE_SIZE* = 128
  LIGHT_CLIENT_COMMITTEE_PERIOD* = 256 # epochs
  SHARD_COMMITTEE_PERIOD* = 256 # epochs
  SHARD_BLOCK_CHUNK_SIZE* = 262144
  MAX_SHARD_BLOCK_CHUNKS* = 4
  TARGET_SHARD_BLOCK_SIZE* = 196608
  MAX_SHARD_BLOCKS_PER_ATTESTATION* = 12
  MAX_GASPRICE* = 16384 # Gwei
  MIN_GASPRICE* = 32 # Gwei
  GASPRICE_ADJUSTMENT_COEFFICIENT* = 8

  # Phase 1 - Custody game
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/configs/minimal.yaml#L201
  # TODO those are included in minimal.yaml but not mainnet.yaml
  #      Why?
  RANDAO_PENALTY_EPOCHS* = 2
  EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS* = 4096 # epochs
  EPOCHS_PER_CUSTODY_PERIOD* = 2048

  # Time parameters
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/configs/minimal.yaml#L204
  CUSTODY_PERIOD_TO_RANDAO_PADDING* = 2048
  MAX_REVEAL_LATENESS_DECREMENT* = 128

  # Max operations
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/configs/minimal.yaml#L216
  MAX_CUSTODY_KEY_REVEALS* = 256
  MAX_EARLY_DERIVED_SECRET_REVEALS* = 1
  MAX_CUSTODY_SLASHINGS* = 1

  # Reward and penalty quotients
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/configs/minimal.yaml#L222
  EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE* = 2
  MINOR_REWARD_QUOTIENT* = 256

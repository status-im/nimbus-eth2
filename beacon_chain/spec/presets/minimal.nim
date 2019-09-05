# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file contains constants that are part of the spec and thus subject to
# serialization and spec updates.

import
  # Standard library
  math,
  # Third-party
  eth/common,
  # Internals
  ../crypto, ../digest

type
  Slot* = distinct uint64
  Epoch* = distinct uint64

{.experimental: "codeReordering".} # SLOTS_PER_EPOCH is use before being defined in spec

const
  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/configs/minimal.yaml#L4

  # Changed
  SHARD_COUNT* {.intdefine.} = 8
  TARGET_COMMITTEE_SIZE* = 4

  # Unchanged
  MAX_VALIDATORS_PER_COMMITTEE* = 4096
  MIN_PER_EPOCH_CHURN_LIMIT* = 4
  CHURN_LIMIT_QUOTIENT* = 2^16
  BASE_REWARDS_PER_EPOCH* = 5

  # Changed
  SHUFFLE_ROUND_COUNT* = 10
  MIN_GENESIS_ACTIVE_VALIDATOR_COUNT* {.intdefine.} = 99
  MIN_GENESIS_TIME* {.intdefine.} = 0

  # Constants
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#constants
  # TODO "The following values are (non-configurable) constants" ...
  # Unchanged
  DEPOSIT_CONTRACT_TREE_DEPTH* = 32

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#gwei-values

  # Unchanged
  MIN_DEPOSIT_AMOUNT* = 2'u64^0 * 10'u64^9
  MAX_EFFECTIVE_BALANCE* = 2'u64^5 * 10'u64^9
  EJECTION_BALANCE* = 2'u64^4 * 10'u64^9
  EFFECTIVE_BALANCE_INCREMENT* = 2'u64^0 * 10'u64^9

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/configs/minimal.yaml#L44

  # Unchanged
  GENESIS_SLOT* = 0.Slot
  BLS_WITHDRAWAL_PREFIX* = 0'u8

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_fork-choice.md#time-parameters

  # Unchanged
  SECONDS_PER_SLOT*{.intdefine.} = 6'u64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#time-parameters
  # Unchanged
  MIN_ATTESTATION_INCLUSION_DELAY* = 1

  # Changed
  SLOTS_PER_EPOCH* {.intdefine.} = 8

  # Unchanged
  MIN_SEED_LOOKAHEAD* = 1
  ACTIVATION_EXIT_DELAY* = 4

  # Changed
  SLOTS_PER_ETH1_VOTING_PERIOD* = 16
  SLOTS_PER_HISTORICAL_ROOT* = 64 # doesn't work with GENESIS_SLOT == 0?

  # Unchanged
  MIN_VALIDATOR_WITHDRAWABILITY_DELAY* = 2'u64^8
  PERSISTENT_COMMITTEE_PERIOD* = 2'u64^11
  MAX_EPOCHS_PER_CROSSLINK* = 4
  MIN_EPOCHS_TO_INACTIVITY_PENALTY* = 2'u64^2

  # State vector lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/configs/minimal.yaml#L79

  # Changed
  EPOCHS_PER_HISTORICAL_VECTOR* = 64
  EPOCHS_PER_SLASHINGS_VECTOR* = 64
  HISTORICAL_ROOTS_LIMIT* = 16777216
  VALIDATOR_REGISTRY_LIMIT* = 1099511627776

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#rewards-and-penalties

  # Unchanged
  BASE_REWARD_FACTOR* = 2'u64^6
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  PROPOSER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^25
  MIN_SLASHING_PENALTY_QUOTIENT* = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#max-operations-per-block

  # Unchanged
  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_ATTESTER_SLASHINGS* = 2^0
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_VOLUNTARY_EXITS* = 2^4
  MAX_TRANSFERS* = 0


type
  # Signature domains
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#signature-domain-types
  DomainType* {.pure.} = enum
    DOMAIN_BEACON_PROPOSER = 0
    DOMAIN_RANDAO = 1
    DOMAIN_ATTESTATION = 2
    DOMAIN_DEPOSIT = 3
    DOMAIN_VOLUNTARY_EXIT = 4
    DOMAIN_TRANSFER = 5

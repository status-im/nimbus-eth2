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

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/configs/constant_presets/minimal.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#misc

  # Changed
  SHARD_COUNT* {.intdefine.} = 8
  TARGET_COMMITTEE_SIZE* = 4

  # Unchanged
  MAX_INDICES_PER_ATTESTATION* = 4096
  MIN_PER_EPOCH_CHURN_LIMIT* = 4
  CHURN_LIMIT_QUOTIENT* = 2^16
  BASE_REWARDS_PER_EPOCH* = 5

  # Changed
  SHUFFLE_ROUND_COUNT* = 10

  # Deposit contract
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#deposit-contract

  # Unchanged
  DEPOSIT_CONTRACT_ADDRESS = "0x1234567890123456789012345678901234567890"
  DEPOSIT_CONTRACT_TREE_DEPTH* = 32

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#gwei-values

  # Unchanged
  MIN_DEPOSIT_AMOUNT* = 2'u64^0 * 10'u64^9
  MAX_EFFECTIVE_BALANCE* = 2'u64^5 * 10'u64^9
  EJECTION_BALANCE* = 2'u64^4 * 10'u64^9
  EFFECTIVE_BALANCE_INCREMENT* = 2'u64^0 * 10'u64^9

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#initial-values

  # Unchanged
  GENESIS_FORK_VERSION* = [0'u8, 0'u8, 0'u8, 0'u8]
  GENESIS_SLOT* = 64.Slot
  FAR_FUTURE_EPOCH* = (not 0'u64).Epoch # 2^64 - 1 in spec
  BLS_WITHDRAWAL_PREFIX_BYTE* = 0'u8

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_fork-choice.md#time-parameters

  # Unchanged
  SECONDS_PER_SLOT*{.intdefine.} = 6'u64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#time-parameters
  # Unchanged
  MIN_ATTESTATION_INCLUSION_DELAY* = 2'u64^2

  # Changed
  SLOTS_PER_EPOCH* {.intdefine.} = 64

  # Unchanged
  MIN_SEED_LOOKAHEAD* = 1
  ACTIVATION_EXIT_DELAY* = 4

  # Changed
  SLOTS_PER_ETH1_VOTING_PERIOD* = 16
  SLOTS_PER_HISTORICAL_ROOT* = 64

  # Unchanged
  MIN_VALIDATOR_WITHDRAWABILITY_DELAY* = 2'u64^8
  PERSISTENT_COMMITTEE_PERIOD* = 2'u64^11
  MAX_CROSSLINK_EPOCHS* = 2'u64^6
  MIN_EPOCHS_TO_INACTIVITY_PENALTY* = 2'u64^2

  # State list lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#state-list-lengths

  # Changed
  LATEST_RANDAO_MIXES_LENGTH* = 64
  LATEST_ACTIVE_INDEX_ROOTS_LENGTH* = 64
  LATEST_SLASHED_EXIT_LENGTH* = 64

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#reward-and-penalty-quotients

  # Unchanged
  BASE_REWARD_QUOTIENT* = 2'u64^5
  WHISTLEBLOWING_REWARD_QUOTIENT* = 2'u64^9
  PROPOSER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^25
  MIN_SLASHING_PENALTY_QUOTIENT* = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#max-operations-per-block

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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.2/specs/core/0_beacon-chain.md#signature-domains
  SignatureDomain* {.pure.} = enum
    DOMAIN_BEACON_PROPOSER = 0
    DOMAIN_RANDAO = 1
    DOMAIN_ATTESTATION = 2
    DOMAIN_DEPOSIT = 3
    DOMAIN_VOLUNTARY_EXIT = 4
    DOMAIN_TRANSFER = 5

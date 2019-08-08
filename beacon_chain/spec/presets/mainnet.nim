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

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/configs/constant_presets/mainnet.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#misc

  SHARD_COUNT* {.intdefine.} = 1024 ##\
  ## Number of shards supported by the network - validators will jump around
  ## between these shards and provide attestations to their state.
  ## Compile with -d:SHARD_COUNT=4 for fewer shard (= better with low validator counts)

  TARGET_COMMITTEE_SIZE* = 2^7 ##\
  ## Number of validators in the committee attesting to one shard
  ## Per spec:
  ## For the safety of crosslinks `TARGET_COMMITTEE_SIZE` exceeds
  ## [the recommended minimum committee size of 111](https://vitalik.ca/files/Ithaca201807_Sharding.pdf);
  ## with sufficient active validators (at least
  ## `SLOTS_PER_EPOCH * TARGET_COMMITTEE_SIZE`), the shuffling algorithm ensures
  ## committee sizes at least `TARGET_COMMITTEE_SIZE`. (Unbiasable randomness
  ## with a Verifiable Delay Function (VDF) will improve committee robustness
  ## and lower the safe minimum committee size.)

  MAX_VALIDATORS_PER_COMMITTEE* = 2^12 ##\
  ## votes

  MIN_PER_EPOCH_CHURN_LIMIT* = 4

  CHURN_LIMIT_QUOTIENT* = 2^16

  SHUFFLE_ROUND_COUNT* = 90

  # Constants (TODO: not actually configurable)
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#constants
  BASE_REWARDS_PER_EPOCH* = 5

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#gwei-values

  MIN_DEPOSIT_AMOUNT* = 2'u64^0 * 10'u64^9 ##\
  ## Minimum amounth of ETH that can be deposited in one call - deposits can
  ## be used either to top up an existing validator or commit to a new one

  MAX_EFFECTIVE_BALANCE* = 2'u64^5 * 10'u64^9 ##\
  ## Maximum amounth of ETH that can be deposited in one call

  EJECTION_BALANCE* = 2'u64^4 * 10'u64^9 ##\
  ## Once the balance of a validator drops below this, it will be ejected from
  ## the validator pool

  EFFECTIVE_BALANCE_INCREMENT* = 2'u64^0 * 10'u64^9

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/configs/constant_presets/mainnet.yaml#L44

  GENESIS_FORK_VERSION* = [0'u8, 0'u8, 0'u8, 0'u8]
  GENESIS_SLOT* = 0.Slot
  BLS_WITHDRAWAL_PREFIX* = 0'u8

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_fork-choice.md#time-parameters

  SECONDS_PER_SLOT*{.intdefine.} = 6'u64 # Compile with -d:SECONDS_PER_SLOT=1 for 6x faster slots
  ## TODO consistent time unit across projects, similar to C++ chrono?

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#time-parameters
  MIN_ATTESTATION_INCLUSION_DELAY* = 1 ##\
  ## (24 seconds)
  ## Number of slots that attestations stay in the attestation
  ## pool before being added to a block.
  ## The attestation delay exists so that there is time for attestations to
  ## propagate before the block is created.
  ## When creating an attestation, the validator will look at the best
  ## information known to at that time, and may not revise it during the same
  ## slot (see `is_double_vote`) - the delay gives the validator a chance to
  ## wait towards the end of the slot and still have time to publish the
  ## attestation.

  SLOTS_PER_EPOCH* {.intdefine.} = 64 ##\
  ## (~6.4 minutes)
  ## slots that make up an epoch, at the end of which more heavy
  ## processing is done
  ## Compile with -d:SLOTS_PER_EPOCH=4 for shorter epochs

  MIN_SEED_LOOKAHEAD* = 1 ##\
  ## epochs (~6.4 minutes)

  ACTIVATION_EXIT_DELAY* = 4 ##\
  ## epochs (~25.6 minutes)

  SLOTS_PER_ETH1_VOTING_PERIOD* = 1024 ##\
  ## slots (~1.7 hours)

  SLOTS_PER_HISTORICAL_ROOT* = 8192 ##\
  ## slots (13 hours)

  MIN_VALIDATOR_WITHDRAWABILITY_DELAY* = 2'u64^8 ##\
  ## epochs (~27 hours)

  PERSISTENT_COMMITTEE_PERIOD* = 2'u64^11 ##\
  ## epochs (9 days)

  MAX_EPOCHS_PER_CROSSLINK* = 2'u64^6 ##\
  ## epochs (~7 hours)

  MIN_EPOCHS_TO_INACTIVITY_PENALTY* = 2'u64^2 ##\
  ## epochs (25.6 minutes)

  # State list lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#state-list-lengths
  LATEST_RANDAO_MIXES_LENGTH* = 8192
  EPOCHS_PER_HISTORICAL_VECTOR* = 65536
  EPOCHS_PER_SLASHINGS_VECTOR* = 8192
  HISTORICAL_ROOTS_LIMIT* = 16777216
  VALIDATOR_REGISTRY_LIMIT* = 1099511627776

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#rewards-and-penalties
  BASE_REWARD_FACTOR* = 2'u64^6
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  PROPOSER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^25
  MIN_SLASHING_PENALTY_QUOTIENT* = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#max-operations-per-block
  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_ATTESTER_SLASHINGS* = 2^0
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_VOLUNTARY_EXITS* = 2^4
  MAX_TRANSFERS* = 0

  MIN_GENESIS_TIME* {.intdefine.} = 0
  MIN_GENESIS_ACTIVE_VALIDATOR_COUNT* {.intdefine.} = 99

type
  # Signature domains
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#signature-domain-types
  DomainType* {.pure.} = enum
    DOMAIN_BEACON_PROPOSER = 0
    DOMAIN_RANDAO = 1
    DOMAIN_ATTESTATION = 2
    DOMAIN_DEPOSIT = 3
    DOMAIN_VOLUNTARY_EXIT = 4
    DOMAIN_TRANSFER = 5

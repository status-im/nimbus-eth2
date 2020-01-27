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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L6

  MAX_COMMITTEES_PER_SLOT* {.intdefine.} = 64

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

  MAX_VALIDATORS_PER_COMMITTEE* = 2048 ##\
  ## votes

  MIN_PER_EPOCH_CHURN_LIMIT* = 4
  CHURN_LIMIT_QUOTIENT* = 2^16
  SHUFFLE_ROUND_COUNT* = 90
  MIN_GENESIS_TIME* {.intdefine.} = 1578009600
  MIN_GENESIS_ACTIVE_VALIDATOR_COUNT* {.intdefine.} = 16384

  # Constants (TODO: not actually configurable)
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#constants
  BASE_REWARDS_PER_EPOCH* = 4

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L52

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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L64
  GENESIS_SLOT* = 0.Slot
  GENESIS_FORK_VERSION* = 0x00000000
  BLS_WITHDRAWAL_PREFIX* = 0'u8

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L71
  MIN_GENESIS_DELAY* = 86400 # 86400 seconds (1 day)

  SECONDS_PER_SLOT*{.intdefine.} = 12'u64 # Compile with -d:SECONDS_PER_SLOT=1 for 12x faster slots
  ## TODO consistent time unit across projects, similar to C++ chrono?

  MIN_ATTESTATION_INCLUSION_DELAY* = 1 ##\
  ## (12 seconds)
  ## Number of slots that attestations stay in the attestation
  ## pool before being added to a block.
  ## The attestation delay exists so that there is time for attestations to
  ## propagate before the block is created.
  ## When creating an attestation, the validator will look at the best
  ## information known to at that time, and may not revise it during the same
  ## slot (see `is_double_vote`) - the delay gives the validator a chance to
  ## wait towards the end of the slot and still have time to publish the
  ## attestation.

  SLOTS_PER_EPOCH* {.intdefine.} = 32 ##\
  ## (~6.4 minutes)
  ## slots that make up an epoch, at the end of which more heavy
  ## processing is done
  ## Compile with -d:SLOTS_PER_EPOCH=4 for shorter epochs

  MIN_SEED_LOOKAHEAD* = 1 ##\
  ## epochs (~6.4 minutes)

  MAX_SEED_LOOKAHEAD* = 4 ##\
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

  EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS* = 16384

  # State vector lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L102
  EPOCHS_PER_HISTORICAL_VECTOR* = 65536
  EPOCHS_PER_SLASHINGS_VECTOR* = 8192
  HISTORICAL_ROOTS_LIMIT* = 16777216
  VALIDATOR_REGISTRY_LIMIT* = 1099511627776

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L114
  BASE_REWARD_FACTOR* = 2'u64^6
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  PROPOSER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^25
  MIN_SLASHING_PENALTY_QUOTIENT* = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L128
  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_ATTESTER_SLASHINGS* = 2^0
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_VOLUNTARY_EXITS* = 2^4

  # Fork choice
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L26
  SAFE_SLOTS_TO_UPDATE_JUSTIFIED* = 8 # 96 seconds

  # Validators
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/configs/mainnet.yaml#L32
  ETH1_FOLLOW_DISTANCE* = 1024 # blocks ~ 4 hours
  TARGET_AGGREGATORS_PER_COMMITTEE* = 16 # validators
  RANDOM_SUBNETS_PER_VALIDATOR* = 1 # subnet
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION* = 256 # epochs ~ 27 hours
  SECONDS_PER_ETH1_BLOCK* = 14 # estimate from Eth1 mainnet)

  # Phase 1 - Sharding
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase1/shard-data-chains.md#time-parameters
  # TODO those are included in minimal.yaml but not mainnet.yaml
  #      Why?
  # SHARD_SLOTS_PER_BEACON_SLOT* = 2 # spec: SHARD_SLOTS_PER_EPOCH
  # EPOCHS_PER_SHARD_PERIOD* = 4
  # PHASE_1_FORK_EPOCH* = 8
  # PHASE_1_FORK_SLOT* = 64

  # Phase 1 - Custody game
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase1/custody-game.md#constants
  # TODO those are included in minimal.yaml but not mainnet.yaml
  #      Why?
  # EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS* = 4096 # epochs
  # EPOCHS_PER_CUSTODY_PERIOD* = 4
  # CUSTODY_PERIOD_TO_RANDAO_PADDING* = 4

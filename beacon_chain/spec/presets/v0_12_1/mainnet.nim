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
  Version* = distinct array[4, byte]

{.experimental: "codeReordering".} # SLOTS_PER_EPOCH is use before being defined in spec

const
  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L6

  MAX_COMMITTEES_PER_SLOT* {.intdefine.} = 64

  TARGET_COMMITTEE_SIZE* = 128 ##\
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

  HYSTERESIS_QUOTIENT* = 4
  HYSTERESIS_DOWNWARD_MULTIPLIER* = 1
  HYSTERESIS_UPWARD_MULTIPLIER* = 5

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L58

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
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L70
  BLS_WITHDRAWAL_PREFIX* = 0'u8

  # Time parameters
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L77

  SECONDS_PER_SLOT* {.intdefine.} = 12'u64 # Compile with -d:SECONDS_PER_SLOT=1 for 12x faster slots
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

  SHARD_COMMITTEE_PERIOD* = 256 # epochs (~27 hours)

  MAX_SEED_LOOKAHEAD* = 4 ##\
  ## epochs (~25.6 minutes)

  EPOCHS_PER_ETH1_VOTING_PERIOD* = 32 ##\
  ##  epochs (~3.4 hours)

  SLOTS_PER_HISTORICAL_ROOT* = 8192 ##\
  ## slots (13 hours)

  MIN_VALIDATOR_WITHDRAWABILITY_DELAY* = 2'u64^8 ##\
  ## epochs (~27 hours)

  MAX_EPOCHS_PER_CROSSLINK* = 2'u64^6 ##\
  ## epochs (~7 hours)

  MIN_EPOCHS_TO_INACTIVITY_PENALTY* = 2'u64^2 ##\
  ## epochs (25.6 minutes)

  # State vector lengths
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L105

  EPOCHS_PER_HISTORICAL_VECTOR* = 65536 ##\
  ## epochs (~0.8 years)

  EPOCHS_PER_SLASHINGS_VECTOR* = 8192 ##\
  ## epochs (~36 days)

  HISTORICAL_ROOTS_LIMIT* = 16777216 ##\
  ## epochs (~26,131 years)

  VALIDATOR_REGISTRY_LIMIT* = 1099511627776

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L117
  BASE_REWARD_FACTOR* = 2'u64^6
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  PROPOSER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^24
  MIN_SLASHING_PENALTY_QUOTIENT* = 32 # 2^5

  # Max operations per block
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L131
  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_ATTESTER_SLASHINGS* = 2^1
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_VOLUNTARY_EXITS* = 2^4

  # Fork choice
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L32
  SAFE_SLOTS_TO_UPDATE_JUSTIFIED* = 8 # 96 seconds

  # Validators
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L38
  ETH1_FOLLOW_DISTANCE* {.intdefine.} = 1024 # blocks ~ 4 hours
  TARGET_AGGREGATORS_PER_COMMITTEE* = 16 # validators
  RANDOM_SUBNETS_PER_VALIDATOR* = 1 # subnet
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION* = 256 # epochs ~ 27 hours
  SECONDS_PER_ETH1_BLOCK* {.intdefine.} = 14 # (estimate from Eth1 mainnet)

  # Phase 1: Upgrade from Phase 0
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L161
  PHASE_1_FORK_VERSION* = 1
  PHASE_1_GENESIS_SLOT* = 32 # [STUB]
  INITIAL_ACTIVE_SHARDS* = 64

  # Phase 1: General
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L166
  MAX_SHARDS* = 1024
  ONLINE_PERIOD* = 8 # epochs (~51 min)
  LIGHT_CLIENT_COMMITTEE_SIZE* = 128
  LIGHT_CLIENT_COMMITTEE_PERIOD* = 256 # epochs (~27 hours)
  SHARD_BLOCK_CHUNK_SIZE* = 262144
  MAX_SHARD_BLOCK_CHUNKS* = 4
  TARGET_SHARD_BLOCK_SIZE* = 196608
  MAX_SHARD_BLOCKS_PER_ATTESTATION* = 12
  MAX_GASPRICE* = 16384  # Gwei
  MIN_GASPRICE* = 8 # Gwei
  GASPRICE_ADJUSTMENT_COEFFICIENT* = 8

  # Phase 1: Custody game
  # ---------------------------------------------------------------
  # Time parameters
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L199
  RANDAO_PENALTY_EPOCHS* = 2 # epochs (12.8 minutes)
  EPOCHS_PER_CUSTODY_PERIOD* = 2048 # epochs (~9 days)
  MAX_REVEAL_LATENESS_DECREMENT* = 128 # epochs (~14 hours)

  # Max operations
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L211
  MAX_CUSTODY_KEY_REVEALS* = 256
  MAX_EARLY_DERIVED_SECRET_REVEALS* = 1
  MAX_CUSTODY_SLASHINGS* = 1

  # Reward and penalty quotients
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/configs/mainnet.yaml#L217
  EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE* = 2
  MINOR_REWARD_QUOTIENT* = 256

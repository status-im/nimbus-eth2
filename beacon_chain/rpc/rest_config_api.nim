# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/[endians2, base10], chronicles,
       nimcrypto/utils as ncrutils
import ".."/beacon_node,
       ".."/eth1/eth1_monitor,
       ".."/spec/forks,
       "."/rest_utils

export rest_utils

logScope: topics = "rest_config"

proc installConfigApiHandlers*(router: var RestRouter, node: BeaconNode) =
  let
    cachedForkSchedule =
      RestApiResponse.prepareJsonResponse(getForkSchedule(node.dag.cfg))
    cachedConfigSpec =
      RestApiResponse.prepareJsonResponse(
        (
          # https://github.com/ethereum/consensus-specs/blob/v1.0.1/configs/mainnet/phase0.yaml
          CONFIG_NAME:
            const_preset,

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/presets/mainnet/phase0.yaml
          MAX_COMMITTEES_PER_SLOT:
            Base10.toString(MAX_COMMITTEES_PER_SLOT),
          TARGET_COMMITTEE_SIZE:
            Base10.toString(TARGET_COMMITTEE_SIZE),
          MAX_VALIDATORS_PER_COMMITTEE:
            Base10.toString(MAX_VALIDATORS_PER_COMMITTEE),
          SHUFFLE_ROUND_COUNT:
            Base10.toString(SHUFFLE_ROUND_COUNT),
          HYSTERESIS_QUOTIENT:
            Base10.toString(HYSTERESIS_QUOTIENT),
          HYSTERESIS_DOWNWARD_MULTIPLIER:
            Base10.toString(HYSTERESIS_DOWNWARD_MULTIPLIER),
          HYSTERESIS_UPWARD_MULTIPLIER:
            Base10.toString(HYSTERESIS_UPWARD_MULTIPLIER),
          SAFE_SLOTS_TO_UPDATE_JUSTIFIED:
            Base10.toString(SAFE_SLOTS_TO_UPDATE_JUSTIFIED),
          MIN_DEPOSIT_AMOUNT:
            Base10.toString(MIN_DEPOSIT_AMOUNT),
          MAX_EFFECTIVE_BALANCE:
            Base10.toString(MAX_EFFECTIVE_BALANCE),
          EFFECTIVE_BALANCE_INCREMENT:
            Base10.toString(EFFECTIVE_BALANCE_INCREMENT),
          MIN_ATTESTATION_INCLUSION_DELAY:
            Base10.toString(MIN_ATTESTATION_INCLUSION_DELAY),
          SLOTS_PER_EPOCH:
            Base10.toString(SLOTS_PER_EPOCH),
          MIN_SEED_LOOKAHEAD:
            Base10.toString(MIN_SEED_LOOKAHEAD),
          MAX_SEED_LOOKAHEAD:
            Base10.toString(MAX_SEED_LOOKAHEAD),
          EPOCHS_PER_ETH1_VOTING_PERIOD:
            Base10.toString(EPOCHS_PER_ETH1_VOTING_PERIOD),
          SLOTS_PER_HISTORICAL_ROOT:
            Base10.toString(SLOTS_PER_HISTORICAL_ROOT),
          MIN_EPOCHS_TO_INACTIVITY_PENALTY:
            Base10.toString(MIN_EPOCHS_TO_INACTIVITY_PENALTY),
          EPOCHS_PER_HISTORICAL_VECTOR:
            Base10.toString(EPOCHS_PER_HISTORICAL_VECTOR),
          EPOCHS_PER_SLASHINGS_VECTOR:
            Base10.toString(EPOCHS_PER_SLASHINGS_VECTOR),
          HISTORICAL_ROOTS_LIMIT:
            Base10.toString(HISTORICAL_ROOTS_LIMIT),
          VALIDATOR_REGISTRY_LIMIT:
            Base10.toString(VALIDATOR_REGISTRY_LIMIT),
          BASE_REWARD_FACTOR:
            Base10.toString(BASE_REWARD_FACTOR),
          WHISTLEBLOWER_REWARD_QUOTIENT:
            Base10.toString(WHISTLEBLOWER_REWARD_QUOTIENT),
          PROPOSER_REWARD_QUOTIENT:
            Base10.toString(PROPOSER_REWARD_QUOTIENT),
          INACTIVITY_PENALTY_QUOTIENT:
            Base10.toString(INACTIVITY_PENALTY_QUOTIENT),
          MIN_SLASHING_PENALTY_QUOTIENT:
            Base10.toString(MIN_SLASHING_PENALTY_QUOTIENT),
          PROPORTIONAL_SLASHING_MULTIPLIER:
            Base10.toString(PROPORTIONAL_SLASHING_MULTIPLIER),
          MAX_PROPOSER_SLASHINGS:
            Base10.toString(MAX_PROPOSER_SLASHINGS),
          MAX_ATTESTER_SLASHINGS:
            Base10.toString(MAX_ATTESTER_SLASHINGS),
          MAX_ATTESTATIONS:
            Base10.toString(MAX_ATTESTATIONS),
          MAX_DEPOSITS:
            Base10.toString(MAX_DEPOSITS),
          MAX_VOLUNTARY_EXITS:
            Base10.toString(MAX_VOLUNTARY_EXITS),

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/presets/mainnet/altair.yaml
          INACTIVITY_PENALTY_QUOTIENT_ALTAIR:
            Base10.toString(INACTIVITY_PENALTY_QUOTIENT_ALTAIR),
          MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR:
            Base10.toString(MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR),
          PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR:
            Base10.toString(PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR),
          SYNC_COMMITTEE_SIZE:
            Base10.toString(uint64(SYNC_COMMITTEE_SIZE)),
          EPOCHS_PER_SYNC_COMMITTEE_PERIOD:
            Base10.toString(EPOCHS_PER_SYNC_COMMITTEE_PERIOD),
          MIN_SYNC_COMMITTEE_PARTICIPANTS:
            Base10.toString(uint64(MIN_SYNC_COMMITTEE_PARTICIPANTS)),

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/configs/mainnet.yaml
          PRESET_BASE:
            node.dag.cfg.PRESET_BASE,
          TERMINAL_TOTAL_DIFFICULTY:
            toString(node.dag.cfg.TERMINAL_TOTAL_DIFFICULTY),
          TERMINAL_BLOCK_HASH:
            $node.dag.cfg.TERMINAL_BLOCK_HASH,
          MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
            Base10.toString(node.dag.cfg.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT),
          MIN_GENESIS_TIME:
            Base10.toString(node.dag.cfg.MIN_GENESIS_TIME),
          GENESIS_FORK_VERSION:
            "0x" & $node.dag.cfg.GENESIS_FORK_VERSION,
          GENESIS_DELAY:
            Base10.toString(node.dag.cfg.GENESIS_DELAY),
          ALTAIR_FORK_VERSION:
            "0x" & $node.dag.cfg.ALTAIR_FORK_VERSION,
          ALTAIR_FORK_EPOCH:
            Base10.toString(uint64(node.dag.cfg.ALTAIR_FORK_EPOCH)),
          MERGE_FORK_VERSION:
            "0x" & $node.dag.cfg.MERGE_FORK_VERSION,
          MERGE_FORK_EPOCH:
            Base10.toString(uint64(node.dag.cfg.MERGE_FORK_EPOCH)),
          SHARDING_FORK_VERSION:
            "0x" & $node.dag.cfg.SHARDING_FORK_VERSION,
          SHARDING_FORK_EPOCH:
            Base10.toString(uint64(node.dag.cfg.SHARDING_FORK_EPOCH)),
          SECONDS_PER_SLOT:
            Base10.toString(SECONDS_PER_SLOT),
          SECONDS_PER_ETH1_BLOCK:
            Base10.toString(node.dag.cfg.SECONDS_PER_ETH1_BLOCK),
          MIN_VALIDATOR_WITHDRAWABILITY_DELAY:
            Base10.toString(node.dag.cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY),
          SHARD_COMMITTEE_PERIOD:
            Base10.toString(node.dag.cfg.SHARD_COMMITTEE_PERIOD),
          ETH1_FOLLOW_DISTANCE:
            Base10.toString(node.dag.cfg.ETH1_FOLLOW_DISTANCE),
          INACTIVITY_SCORE_BIAS:
            Base10.toString(node.dag.cfg.INACTIVITY_SCORE_BIAS),
          INACTIVITY_SCORE_RECOVERY_RATE:
            Base10.toString(node.dag.cfg.INACTIVITY_SCORE_RECOVERY_RATE),
          EJECTION_BALANCE:
            Base10.toString(node.dag.cfg.EJECTION_BALANCE),
          MIN_PER_EPOCH_CHURN_LIMIT:
            Base10.toString(node.dag.cfg.MIN_PER_EPOCH_CHURN_LIMIT),
          CHURN_LIMIT_QUOTIENT:
            Base10.toString(node.dag.cfg.CHURN_LIMIT_QUOTIENT),
          DEPOSIT_CHAIN_ID:
            Base10.toString(node.dag.cfg.DEPOSIT_CHAIN_ID),
          DEPOSIT_NETWORK_ID:
            Base10.toString(node.dag.cfg.DEPOSIT_NETWORK_ID),
          DEPOSIT_CONTRACT_ADDRESS:
            $node.dag.cfg.DEPOSIT_CONTRACT_ADDRESS,

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#constants
          # GENESIS_SLOT
          # GENESIS_EPOCH
          # FAR_FUTURE_EPOCH
          # BASE_REWARDS_PER_EPOCH
          # DEPOSIT_CONTRACT_TREE_DEPTH
          # JUSTIFICATION_BITS_LENGTH
          # ENDIANNESS
          BLS_WITHDRAWAL_PREFIX:
            "0x" & ncrutils.toHex([BLS_WITHDRAWAL_PREFIX]),
          ETH1_ADDRESS_WITHDRAWAL_PREFIX:
            "0x" & ncrutils.toHex([ETH1_ADDRESS_WITHDRAWAL_PREFIX]),
          DOMAIN_BEACON_PROPOSER:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_BEACON_PROPOSER).toBytesLE()),
          DOMAIN_BEACON_ATTESTER:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_BEACON_ATTESTER).toBytesLE()),
          DOMAIN_RANDAO:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_RANDAO).toBytesLE()),
          DOMAIN_DEPOSIT:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_DEPOSIT).toBytesLE()),
          DOMAIN_VOLUNTARY_EXIT:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_VOLUNTARY_EXIT).toBytesLE()),
          DOMAIN_SELECTION_PROOF:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_SELECTION_PROOF).toBytesLE()),
          DOMAIN_AGGREGATE_AND_PROOF:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_AGGREGATE_AND_PROOF).toBytesLE()),

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/altair/beacon-chain.md#constants
          TIMELY_SOURCE_FLAG_INDEX:
            "0x" & ncrutils.toHex([byte(TIMELY_SOURCE_FLAG_INDEX)]),
          TIMELY_TARGET_FLAG_INDEX:
            "0x" & ncrutils.toHex([byte(TIMELY_TARGET_FLAG_INDEX)]),
          TIMELY_HEAD_FLAG_INDEX:
            "0x" & ncrutils.toHex([byte(TIMELY_HEAD_FLAG_INDEX)]),
          TIMELY_SOURCE_WEIGHT:
            Base10.toString(uint64(TIMELY_SOURCE_WEIGHT)),
          TIMELY_TARGET_WEIGHT:
            Base10.toString(uint64(TIMELY_TARGET_WEIGHT)),
          TIMELY_HEAD_WEIGHT:
            Base10.toString(uint64(TIMELY_HEAD_WEIGHT)),
          SYNC_REWARD_WEIGHT:
            Base10.toString(uint64(SYNC_REWARD_WEIGHT)),
          PROPOSER_WEIGHT:
            Base10.toString(uint64(PROPOSER_WEIGHT)),
          WEIGHT_DENOMINATOR:
            Base10.toString(uint64(WEIGHT_DENOMINATOR)),
          DOMAIN_SYNC_COMMITTEE:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_SYNC_COMMITTEE).toBytesLE()),
          DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF).toBytesLE()),
          DOMAIN_CONTRIBUTION_AND_PROOF:
            "0x" & ncrutils.toHex(
              uint32(DOMAIN_CONTRIBUTION_AND_PROOF).toBytesLE()),
          # PARTICIPATION_FLAG_WEIGHTS

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/validator.md#constants
          TARGET_AGGREGATORS_PER_COMMITTEE:
            Base10.toString(TARGET_AGGREGATORS_PER_COMMITTEE),
          RANDOM_SUBNETS_PER_VALIDATOR:
            Base10.toString(RANDOM_SUBNETS_PER_VALIDATOR),
          EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION:
            Base10.toString(EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION),
          ATTESTATION_SUBNET_COUNT:
            Base10.toString(uint64(ATTESTATION_SUBNET_COUNT)),

          # https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/altair/validator.md#constants
          TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE:
            Base10.toString(uint64(TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)),
          SYNC_COMMITTEE_SUBNET_COUNT:
            Base10.toString(uint64(SYNC_COMMITTEE_SUBNET_COUNT)),
        )
      )
    cachedDepositContract =
      RestApiResponse.prepareJsonResponse(
        (
          chain_id: $node.dag.cfg.DEPOSIT_CHAIN_ID,
          address: $node.dag.cfg.DEPOSIT_CONTRACT_ADDRESS
        )
      )

  # https://ethereum.github.io/beacon-APIs/#/Config/getForkSchedule
  router.api(MethodGet,
             "/api/eth/v1/config/fork_schedule") do () -> RestApiResponse:
    return RestApiResponse.response(cachedForkSchedule, Http200,
                                    "application/json")

  # https://ethereum.github.io/beacon-APIs/#/Config/getSpec
  router.api(MethodGet,
             "/api/eth/v1/config/spec") do () -> RestApiResponse:
    return RestApiResponse.response(cachedConfigSpec, Http200,
                                    "application/json")

  # https://ethereum.github.io/beacon-APIs/#/Config/getDepositContract
  router.api(MethodGet,
             "/api/eth/v1/config/deposit_contract") do () -> RestApiResponse:
    return RestApiResponse.response(cachedDepositContract, Http200,
                                    "application/json")

  router.redirect(
    MethodGet,
    "/eth/v1/config/fork_schedule",
    "/api/eth/v1/config/fork_schedule"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/config/spec",
    "/api/eth/v1/config/spec"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/config/deposit_contract",
    "/api/eth/v1/config/deposit_contract"
  )

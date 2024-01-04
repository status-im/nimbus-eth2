# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/[byteutils, base10], chronicles
import ".."/beacon_node,
       ".."/spec/forks,
       "."/rest_utils

export rest_utils

logScope: topics = "rest_config"

proc installConfigApiHandlers*(router: var RestRouter, node: BeaconNode) =
  template cfg(): auto = node.dag.cfg
  let
    cachedForkSchedule =
      RestApiResponse.prepareJsonResponse(getForkSchedule(cfg))
    cachedConfigSpec =
      RestApiResponse.prepareJsonResponse(
        (
          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.1/presets/mainnet/phase0.yaml
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

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/presets/mainnet/altair.yaml
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
          UPDATE_TIMEOUT:
            Base10.toString(UPDATE_TIMEOUT),

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/presets/mainnet/bellatrix.yaml
          INACTIVITY_PENALTY_QUOTIENT_BELLATRIX:
            Base10.toString(INACTIVITY_PENALTY_QUOTIENT_BELLATRIX),
          MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX:
            Base10.toString(MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX),
          PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX:
            Base10.toString(PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX),
          MAX_BYTES_PER_TRANSACTION:
            Base10.toString(uint64(MAX_BYTES_PER_TRANSACTION)),
          MAX_TRANSACTIONS_PER_PAYLOAD:
            Base10.toString(uint64(MAX_TRANSACTIONS_PER_PAYLOAD)),
          BYTES_PER_LOGS_BLOOM:
            Base10.toString(uint64(BYTES_PER_LOGS_BLOOM)),
          MAX_EXTRA_DATA_BYTES:
            Base10.toString(uint64(MAX_EXTRA_DATA_BYTES)),

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/presets/mainnet/capella.yaml
          MAX_BLS_TO_EXECUTION_CHANGES:
            Base10.toString(uint64(MAX_BLS_TO_EXECUTION_CHANGES)),
          MAX_WITHDRAWALS_PER_PAYLOAD:
            Base10.toString(uint64(MAX_WITHDRAWALS_PER_PAYLOAD)),
          MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP:
            Base10.toString(uint64(MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)),

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/presets/mainnet/deneb.yaml
          FIELD_ELEMENTS_PER_BLOB:
            Base10.toString(deneb_preset.FIELD_ELEMENTS_PER_BLOB),
          MAX_BLOB_COMMITMENTS_PER_BLOCK:
            Base10.toString(MAX_BLOB_COMMITMENTS_PER_BLOCK),
          MAX_BLOBS_PER_BLOCK:
            Base10.toString(MAX_BLOBS_PER_BLOCK),
          KZG_COMMITMENT_INCLUSION_PROOF_DEPTH:
            Base10.toString(uint64(KZG_COMMITMENT_INCLUSION_PROOF_DEPTH)),

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/configs/mainnet.yaml
          PRESET_BASE:
            cfg.PRESET_BASE,
          CONFIG_NAME:
            cfg.name(),
          TERMINAL_TOTAL_DIFFICULTY:
            toString(cfg.TERMINAL_TOTAL_DIFFICULTY),
          TERMINAL_BLOCK_HASH:
            $cfg.TERMINAL_BLOCK_HASH,
          TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH:
            Base10.toString(uint64(cfg.TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH)),
          MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
            Base10.toString(cfg.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT),
          MIN_GENESIS_TIME:
            Base10.toString(cfg.MIN_GENESIS_TIME),
          GENESIS_FORK_VERSION:
            "0x" & $cfg.GENESIS_FORK_VERSION,
          GENESIS_DELAY:
            Base10.toString(cfg.GENESIS_DELAY),
          ALTAIR_FORK_VERSION:
            "0x" & $cfg.ALTAIR_FORK_VERSION,
          ALTAIR_FORK_EPOCH:
            Base10.toString(uint64(cfg.ALTAIR_FORK_EPOCH)),
          BELLATRIX_FORK_VERSION:
            "0x" & $cfg.BELLATRIX_FORK_VERSION,
          BELLATRIX_FORK_EPOCH:
            Base10.toString(uint64(cfg.BELLATRIX_FORK_EPOCH)),
          CAPELLA_FORK_VERSION:
            "0x" & $cfg.CAPELLA_FORK_VERSION,
          CAPELLA_FORK_EPOCH:
            Base10.toString(uint64(cfg.CAPELLA_FORK_EPOCH)),
          DENEB_FORK_VERSION:
            "0x" & $cfg.DENEB_FORK_VERSION,
          DENEB_FORK_EPOCH:
            Base10.toString(uint64(cfg.DENEB_FORK_EPOCH)),
          SECONDS_PER_SLOT:
            Base10.toString(SECONDS_PER_SLOT),
          SECONDS_PER_ETH1_BLOCK:
            Base10.toString(cfg.SECONDS_PER_ETH1_BLOCK),
          MIN_VALIDATOR_WITHDRAWABILITY_DELAY:
            Base10.toString(cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY),
          SHARD_COMMITTEE_PERIOD:
            Base10.toString(cfg.SHARD_COMMITTEE_PERIOD),
          ETH1_FOLLOW_DISTANCE:
            Base10.toString(cfg.ETH1_FOLLOW_DISTANCE),
          INACTIVITY_SCORE_BIAS:
            Base10.toString(cfg.INACTIVITY_SCORE_BIAS),
          INACTIVITY_SCORE_RECOVERY_RATE:
            Base10.toString(cfg.INACTIVITY_SCORE_RECOVERY_RATE),
          EJECTION_BALANCE:
            Base10.toString(cfg.EJECTION_BALANCE),
          MIN_PER_EPOCH_CHURN_LIMIT:
            Base10.toString(cfg.MIN_PER_EPOCH_CHURN_LIMIT),
          CHURN_LIMIT_QUOTIENT:
            Base10.toString(cfg.CHURN_LIMIT_QUOTIENT),
          MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT:
            Base10.toString(cfg.MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT),
          PROPOSER_SCORE_BOOST:
            Base10.toString(PROPOSER_SCORE_BOOST),
          REORG_HEAD_WEIGHT_THRESHOLD:
            Base10.toString(REORG_HEAD_WEIGHT_THRESHOLD),
          REORG_PARENT_WEIGHT_THRESHOLD:
            Base10.toString(REORG_PARENT_WEIGHT_THRESHOLD),
          REORG_MAX_EPOCHS_SINCE_FINALIZATION:
            Base10.toString(uint64(REORG_MAX_EPOCHS_SINCE_FINALIZATION)),
          DEPOSIT_CHAIN_ID:
            Base10.toString(cfg.DEPOSIT_CHAIN_ID),
          DEPOSIT_NETWORK_ID:
            Base10.toString(cfg.DEPOSIT_NETWORK_ID),
          DEPOSIT_CONTRACT_ADDRESS:
            $cfg.DEPOSIT_CONTRACT_ADDRESS,
          GOSSIP_MAX_SIZE:
            Base10.toString(GOSSIP_MAX_SIZE),
          MAX_REQUEST_BLOCKS:
            Base10.toString(MAX_REQUEST_BLOCKS),
          EPOCHS_PER_SUBNET_SUBSCRIPTION:
            Base10.toString(EPOCHS_PER_SUBNET_SUBSCRIPTION),
          MIN_EPOCHS_FOR_BLOCK_REQUESTS:
            Base10.toString(cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS),
          MAX_CHUNK_SIZE:
            Base10.toString(MAX_CHUNK_SIZE),
          TTFB_TIMEOUT:
            Base10.toString(TTFB_TIMEOUT),
          RESP_TIMEOUT:
            Base10.toString(RESP_TIMEOUT),
          ATTESTATION_PROPAGATION_SLOT_RANGE:
            Base10.toString(ATTESTATION_PROPAGATION_SLOT_RANGE),
          MAXIMUM_GOSSIP_CLOCK_DISPARITY:
            Base10.toString(MAXIMUM_GOSSIP_CLOCK_DISPARITY.milliseconds.uint64),
          MESSAGE_DOMAIN_INVALID_SNAPPY:
            to0xHex(MESSAGE_DOMAIN_INVALID_SNAPPY),
          MESSAGE_DOMAIN_VALID_SNAPPY:
            to0xHex(MESSAGE_DOMAIN_VALID_SNAPPY),
          SUBNETS_PER_NODE:
            Base10.toString(SUBNETS_PER_NODE),
          ATTESTATION_SUBNET_COUNT:
            Base10.toString(ATTESTATION_SUBNET_COUNT),
          ATTESTATION_SUBNET_EXTRA_BITS:
            Base10.toString(ATTESTATION_SUBNET_EXTRA_BITS),
          ATTESTATION_SUBNET_PREFIX_BITS:
            Base10.toString(ATTESTATION_SUBNET_PREFIX_BITS),
          MAX_REQUEST_BLOCKS_DENEB:
            Base10.toString(MAX_REQUEST_BLOCKS_DENEB),
          MAX_REQUEST_BLOB_SIDECARS:
            Base10.toString(MAX_REQUEST_BLOB_SIDECARS),
          MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS:
            Base10.toString(cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS),
          BLOB_SIDECAR_SUBNET_COUNT:
            Base10.toString(BLOB_SIDECAR_SUBNET_COUNT),

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.3/specs/phase0/beacon-chain.md#constants
          # GENESIS_SLOT
          # GENESIS_EPOCH
          # FAR_FUTURE_EPOCH
          # BASE_REWARDS_PER_EPOCH
          # DEPOSIT_CONTRACT_TREE_DEPTH
          # JUSTIFICATION_BITS_LENGTH
          # ENDIANNESS
          BLS_WITHDRAWAL_PREFIX:
            to0xHex([BLS_WITHDRAWAL_PREFIX]),
          ETH1_ADDRESS_WITHDRAWAL_PREFIX:
            to0xHex([ETH1_ADDRESS_WITHDRAWAL_PREFIX]),
          DOMAIN_BEACON_PROPOSER:
            to0xHex(DOMAIN_BEACON_PROPOSER.data),
          DOMAIN_BEACON_ATTESTER:
            to0xHex(DOMAIN_BEACON_ATTESTER.data),
          DOMAIN_RANDAO:
            to0xHex(DOMAIN_RANDAO.data),
          DOMAIN_DEPOSIT:
            to0xHex(DOMAIN_DEPOSIT.data),
          DOMAIN_VOLUNTARY_EXIT:
            to0xHex(DOMAIN_VOLUNTARY_EXIT.data),
          DOMAIN_SELECTION_PROOF:
            to0xHex(DOMAIN_SELECTION_PROOF.data),
          DOMAIN_AGGREGATE_AND_PROOF:
            to0xHex(DOMAIN_AGGREGATE_AND_PROOF.data),

          # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#constants
          TIMELY_SOURCE_FLAG_INDEX:
            Base10.toString(uint64(ord(TIMELY_SOURCE_FLAG_INDEX))),
          TIMELY_TARGET_FLAG_INDEX:
            Base10.toString(uint64(ord(TIMELY_TARGET_FLAG_INDEX))),
          TIMELY_HEAD_FLAG_INDEX:
            Base10.toString(uint64(ord(TIMELY_HEAD_FLAG_INDEX))),
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
            to0xHex(DOMAIN_SYNC_COMMITTEE.data),
          DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF:
            to0xHex(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF.data),
          DOMAIN_CONTRIBUTION_AND_PROOF:
            to0xHex(DOMAIN_CONTRIBUTION_AND_PROOF.data),
          # PARTICIPATION_FLAG_WEIGHTS

          # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#domain-types
          DOMAIN_BLS_TO_EXECUTION_CHANGE:
            to0xHex(DOMAIN_BLS_TO_EXECUTION_CHANGE.data),

          # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#constants
          TARGET_AGGREGATORS_PER_COMMITTEE:
            Base10.toString(TARGET_AGGREGATORS_PER_COMMITTEE),

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/altair/validator.md#constants
          TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE:
            Base10.toString(uint64(TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)),
          SYNC_COMMITTEE_SUBNET_COUNT:
            Base10.toString(uint64(SYNC_COMMITTEE_SUBNET_COUNT)),
        )
      )
    cachedDepositContract =
      RestApiResponse.prepareJsonResponse(
        (
          chain_id: $cfg.DEPOSIT_CHAIN_ID,
          address: $cfg.DEPOSIT_CONTRACT_ADDRESS
        )
      )

  # https://ethereum.github.io/beacon-APIs/#/Config/getForkSchedule
  router.api(MethodGet,
             "/eth/v1/config/fork_schedule") do () -> RestApiResponse:
    return RestApiResponse.response(cachedForkSchedule, Http200,
                                    "application/json")

  # https://ethereum.github.io/beacon-APIs/#/Config/getSpec
  router.api(MethodGet,
             "/eth/v1/config/spec") do () -> RestApiResponse:
    return RestApiResponse.response(cachedConfigSpec, Http200,
                                    "application/json")

  # https://ethereum.github.io/beacon-APIs/#/Config/getDepositContract
  router.api(MethodGet,
             "/eth/v1/config/deposit_contract") do () -> RestApiResponse:
    return RestApiResponse.response(cachedDepositContract, Http200,
                                    "application/json")

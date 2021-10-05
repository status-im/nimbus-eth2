# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  stew/endians2,
  json_rpc/servers/httpserver,
  chronicles,
  nimcrypto/utils as ncrutils,
  ../beacon_node,
  ../eth1/eth1_monitor,
  ../spec/forks

logScope: topics = "configapi"

type
  RpcServer = RpcHttpServer

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

proc installConfigApiHandlers*(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Defect, CatchableError].} =
  rpcServer.rpc("get_v1_config_fork_schedule") do () -> seq[Fork]:
    return @[getStateField(node.dag.headState.data, fork)]

  rpcServer.rpc("get_v1_config_spec") do () -> JsonNode:
    return %*{
      # Note: This is intentionally only returning v1.0 config values.
      # Please use the REST API /eth/v1/config/spec to retrieve the full config.
      # https://github.com/ethereum/consensus-specs/blob/v1.0.1/configs/mainnet/phase0.yaml
      "MAX_COMMITTEES_PER_SLOT": $MAX_COMMITTEES_PER_SLOT,
      "TARGET_COMMITTEE_SIZE": $TARGET_COMMITTEE_SIZE,
      "MAX_VALIDATORS_PER_COMMITTEE": $MAX_VALIDATORS_PER_COMMITTEE,
      "MIN_PER_EPOCH_CHURN_LIMIT": $node.dag.cfg.MIN_PER_EPOCH_CHURN_LIMIT,
      "CHURN_LIMIT_QUOTIENT": $node.dag.cfg.CHURN_LIMIT_QUOTIENT,
      "SHUFFLE_ROUND_COUNT": $SHUFFLE_ROUND_COUNT,
      "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT":
        $node.dag.cfg.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
      "MIN_GENESIS_TIME": $node.dag.cfg.MIN_GENESIS_TIME,
      "HYSTERESIS_QUOTIENT": $HYSTERESIS_QUOTIENT,
      "HYSTERESIS_DOWNWARD_MULTIPLIER": $HYSTERESIS_DOWNWARD_MULTIPLIER,
      "HYSTERESIS_UPWARD_MULTIPLIER": $HYSTERESIS_UPWARD_MULTIPLIER,
      "SAFE_SLOTS_TO_UPDATE_JUSTIFIED": $SAFE_SLOTS_TO_UPDATE_JUSTIFIED,
      "ETH1_FOLLOW_DISTANCE": $node.dag.cfg.ETH1_FOLLOW_DISTANCE,
      "TARGET_AGGREGATORS_PER_COMMITTEE": $TARGET_AGGREGATORS_PER_COMMITTEE,
      "RANDOM_SUBNETS_PER_VALIDATOR": $RANDOM_SUBNETS_PER_VALIDATOR,
      "EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION":
        $EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION,
      "SECONDS_PER_ETH1_BLOCK": $node.dag.cfg.SECONDS_PER_ETH1_BLOCK,
      "DEPOSIT_CHAIN_ID": $node.dag.cfg.DEPOSIT_CHAIN_ID,
      "DEPOSIT_NETWORK_ID": $node.dag.cfg.DEPOSIT_NETWORK_ID,
      "DEPOSIT_CONTRACT_ADDRESS": $node.dag.cfg.DEPOSIT_CONTRACT_ADDRESS,
      "MIN_DEPOSIT_AMOUNT": $MIN_DEPOSIT_AMOUNT,
      "MAX_EFFECTIVE_BALANCE": $MAX_EFFECTIVE_BALANCE,
      "EJECTION_BALANCE": $node.dag.cfg.EJECTION_BALANCE,
      "EFFECTIVE_BALANCE_INCREMENT": $EFFECTIVE_BALANCE_INCREMENT,
      "GENESIS_FORK_VERSION":
        "0x" & $node.dag.cfg.GENESIS_FORK_VERSION,
      "BLS_WITHDRAWAL_PREFIX": "0x" & ncrutils.toHex([BLS_WITHDRAWAL_PREFIX]),
      "GENESIS_DELAY": $node.dag.cfg.GENESIS_DELAY,
      "SECONDS_PER_SLOT": $SECONDS_PER_SLOT,
      "MIN_ATTESTATION_INCLUSION_DELAY": $MIN_ATTESTATION_INCLUSION_DELAY,
      "SLOTS_PER_EPOCH": $SLOTS_PER_EPOCH,
      "MIN_SEED_LOOKAHEAD": $MIN_SEED_LOOKAHEAD,
      "MAX_SEED_LOOKAHEAD": $MAX_SEED_LOOKAHEAD,
      "EPOCHS_PER_ETH1_VOTING_PERIOD": $EPOCHS_PER_ETH1_VOTING_PERIOD,
      "SLOTS_PER_HISTORICAL_ROOT": $SLOTS_PER_HISTORICAL_ROOT,
      "MIN_VALIDATOR_WITHDRAWABILITY_DELAY":
        $node.dag.cfg.MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
      "SHARD_COMMITTEE_PERIOD": $node.dag.cfg.SHARD_COMMITTEE_PERIOD,
      "MIN_EPOCHS_TO_INACTIVITY_PENALTY": $MIN_EPOCHS_TO_INACTIVITY_PENALTY,
      "EPOCHS_PER_HISTORICAL_VECTOR": $EPOCHS_PER_HISTORICAL_VECTOR,
      "EPOCHS_PER_SLASHINGS_VECTOR": $EPOCHS_PER_SLASHINGS_VECTOR,
      "HISTORICAL_ROOTS_LIMIT": $HISTORICAL_ROOTS_LIMIT,
      "VALIDATOR_REGISTRY_LIMIT": $VALIDATOR_REGISTRY_LIMIT,
      "BASE_REWARD_FACTOR": $BASE_REWARD_FACTOR,
      "WHISTLEBLOWER_REWARD_QUOTIENT": $WHISTLEBLOWER_REWARD_QUOTIENT,
      "PROPOSER_REWARD_QUOTIENT": $PROPOSER_REWARD_QUOTIENT,
      "INACTIVITY_PENALTY_QUOTIENT": $INACTIVITY_PENALTY_QUOTIENT,
      "MIN_SLASHING_PENALTY_QUOTIENT": $MIN_SLASHING_PENALTY_QUOTIENT,
      "PROPORTIONAL_SLASHING_MULTIPLIER": $PROPORTIONAL_SLASHING_MULTIPLIER,
      "MAX_PROPOSER_SLASHINGS": $MAX_PROPOSER_SLASHINGS,
      "MAX_ATTESTER_SLASHINGS": $MAX_ATTESTER_SLASHINGS,
      "MAX_ATTESTATIONS": $MAX_ATTESTATIONS,
      "MAX_DEPOSITS": $MAX_DEPOSITS,
      "MAX_VOLUNTARY_EXITS": $MAX_VOLUNTARY_EXITS,
      "DOMAIN_BEACON_PROPOSER":
        "0x" & ncrutils.toHex(uint32(DOMAIN_BEACON_PROPOSER).toBytesLE()),
      "DOMAIN_BEACON_ATTESTER":
        "0x" & ncrutils.toHex(uint32(DOMAIN_BEACON_ATTESTER).toBytesLE()),
      "DOMAIN_RANDAO":
        "0x" & ncrutils.toHex(uint32(DOMAIN_RANDAO).toBytesLE()),
      "DOMAIN_DEPOSIT":
        "0x" & ncrutils.toHex(uint32(DOMAIN_DEPOSIT).toBytesLE()),
      "DOMAIN_VOLUNTARY_EXIT":
        "0x" & ncrutils.toHex(uint32(DOMAIN_VOLUNTARY_EXIT).toBytesLE()),
      "DOMAIN_SELECTION_PROOF":
        "0x" & ncrutils.toHex(uint32(DOMAIN_SELECTION_PROOF).toBytesLE()),
      "DOMAIN_AGGREGATE_AND_PROOF":
        "0x" & ncrutils.toHex(uint32(DOMAIN_AGGREGATE_AND_PROOF).toBytesLE())
    }

  rpcServer.rpc("get_v1_config_deposit_contract") do () -> JsonNode:
    return %*{
      "chain_id": $node.dag.cfg.DEPOSIT_CHAIN_ID,
      "address": node.dag.cfg.DEPOSIT_CONTRACT_ADDRESS
    }

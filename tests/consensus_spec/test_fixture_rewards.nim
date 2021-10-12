# beacon_chain
# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os,
  # Utilities
  stew/results,
  # Beacon chain internals
  ../../beacon_chain/spec/[validator, helpers, state_transition_epoch],
  ../../beacon_chain/spec/datatypes/phase0,
  # Test utilities
  ../testutil,
  ./fixtures_utils

const
  RewardsDirBase = SszTestsDir/const_preset/"phase0"/"rewards"
  RewardsDirBasic = RewardsDirBase/"basic"/"pyspec_tests"
  RewardsDirLeak = RewardsDirBase/"leak"/"pyspec_tests"
  RewardsDirRandom = RewardsDirBase/"random"/"pyspec_tests"

# https://github.com/ethereum/consensus-specs/tree/v1.0.1/tests/formats/rewards#rewards-tests
type Deltas = object
  rewards: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]
  penalties: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

func add(v: var Deltas, idx: int, delta: RewardDelta) =
  v.rewards[idx] += delta.rewards
  v.penalties[idx] += delta.penalties

func init(T: type Deltas, len: int): T =
  if not result.rewards.setLen(len):
    raiseAssert "setLen"
  if not result.penalties.setLen(len):
    raiseAssert "setLen"

proc runTest(rewardsDir, identifier: string) =
  let testDir = rewardsDir / identifier

  proc `testImpl _ rewards _ identifier`() =
    test "Rewards" & " - " & identifier & preset():
      var
        state = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, phase0.BeaconState))
        cache = StateCache()
      let
        sourceDeltas =
          parseTest(testDir/"source_deltas.ssz_snappy", SSZ, Deltas)
        targetDeltas =
          parseTest(testDir/"target_deltas.ssz_snappy", SSZ, Deltas)
        headDeltas = parseTest(testDir/"head_deltas.ssz_snappy", SSZ, Deltas)
        inclusionDelayDeltas =
          parseTest(testDir/"inclusion_delay_deltas.ssz_snappy", SSZ, Deltas)
        inactivityPenaltyDeltas =
          parseTest(testDir/"inactivity_penalty_deltas.ssz_snappy", SSZ, Deltas)

      var
        info: phase0.EpochInfo
        finality_delay = (state[].get_previous_epoch() - state[].finalized_checkpoint.epoch)

      info.init(state[])
      info.process_attestations(state[], cache)
      let
        total_balance = info.total_balances.current_epoch
        total_balance_sqrt = integer_squareroot(total_balance)

      var
        sourceDeltas2 = Deltas.init(state[].validators.len)
        targetDeltas2 = Deltas.init(state[].validators.len)
        headDeltas2 = Deltas.init(state[].validators.len)
        inclusionDelayDeltas2 = Deltas.init(state[].validators.len)
        inactivityPenaltyDeltas2 = Deltas.init(state[].validators.len)

      for index, validator in info.statuses.mpairs():
        if not is_eligible_validator(validator):
          continue

        let
          base_reward = get_base_reward_sqrt(
            state[], index.ValidatorIndex, total_balance_sqrt)

        sourceDeltas2.add(index, get_source_delta(
          validator, base_reward, info.total_balances, finality_delay))
        targetDeltas2.add(index, get_target_delta(
          validator, base_reward, info.total_balances, finality_delay))
        headDeltas2.add(index, get_head_delta(
          validator, base_reward, info.total_balances, finality_delay))

        let
          (inclusion_delay_delta, proposer_delta) =
            get_inclusion_delay_delta(validator, base_reward)
        inclusionDelayDeltas2.add(index, inclusion_delay_delta)

        inactivityPenaltyDeltas2.add(index, get_inactivity_penalty_delta(
          validator, base_reward, finality_delay))

        if proposer_delta.isSome:
          let proposer_index = proposer_delta.get()[0]
          inclusionDelayDeltas2.add(proposer_index.int, proposer_delta.get()[1])

      check:
        sourceDeltas.rewards.asSeq == sourceDeltas2.rewards.asSeq
        sourceDeltas.penalties.asSeq == sourceDeltas2.penalties.asSeq

        targetDeltas.rewards.asSeq == targetDeltas2.rewards.asSeq
        targetDeltas.penalties.asSeq == targetDeltas2.penalties.asSeq

        headDeltas.rewards.asSeq == headDeltas2.rewards.asSeq
        headDeltas.penalties.asSeq == headDeltas2.penalties.asSeq

        inclusionDelayDeltas.rewards.asSeq == inclusionDelayDeltas2.rewards.asSeq
        inclusionDelayDeltas.penalties.asSeq == inclusionDelayDeltas2.penalties.asSeq

        inactivityPenaltyDeltas.rewards.asSeq == inactivityPenaltyDeltas2.rewards.asSeq
        inactivityPenaltyDeltas.penalties.asSeq == inactivityPenaltyDeltas2.penalties.asSeq


  `testImpl _ rewards _ identifier`()

suite "Ethereum Foundation - Rewards " & preset():
  for rewardsDir in [RewardsDirBasic, RewardsDirLeak, RewardsDirRandom]:
    for kind, path in walkDir(rewardsDir, relative = true, checkDir = true):
      runTest(rewardsDir, path)

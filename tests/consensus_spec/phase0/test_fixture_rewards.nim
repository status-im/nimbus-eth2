# beacon_chain
# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  # Beacon chain internals
  ../../beacon_chain/spec/[validator, helpers, state_transition_epoch],
  ../../beacon_chain/spec/datatypes/phase0,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops

const
  RewardsDirBase = SszTestsDir/const_preset/"phase0"/"rewards"
  RewardsDirBasic = RewardsDirBase/"basic"/"pyspec_tests"
  RewardsDirLeak = RewardsDirBase/"leak"/"pyspec_tests"
  RewardsDirRandom = RewardsDirBase/"random"/"pyspec_tests"

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
    test "EF - Phase 0 - Rewards - " & identifier & preset():
      let
        state = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, phase0.BeaconState))
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
        cache = StateCache()
        info: phase0.EpochInfo
        finality_delay = (state[].get_previous_epoch() - state[].finalized_checkpoint.epoch)

      info.init(state[])
      info.process_attestations(state[], cache)
      let
        total_balance = info.balances.current_epoch
        total_balance_sqrt = integer_squareroot(total_balance)

      var
        sourceDeltas2 = Deltas.init(state[].validators.len)
        targetDeltas2 = Deltas.init(state[].validators.len)
        headDeltas2 = Deltas.init(state[].validators.len)
        inclusionDelayDeltas2 = Deltas.init(state[].validators.len)
        inactivityPenaltyDeltas2 = Deltas.init(state[].validators.len)

      for index, validator in info.validators.mpairs():
        if not is_eligible_validator(validator):
          continue

        let
          base_reward = get_base_reward_sqrt(
            state[], index.ValidatorIndex, total_balance_sqrt)

        sourceDeltas2.add(index, get_source_delta(
          validator, base_reward, info.balances, finality_delay))
        targetDeltas2.add(index, get_target_delta(
          validator, base_reward, info.balances, finality_delay))
        headDeltas2.add(index, get_head_delta(
          validator, base_reward, info.balances, finality_delay))

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
        sourceDeltas == sourceDeltas2
        targetDeltas == targetDeltas2
        headDeltas == headDeltas2
        inclusionDelayDeltas == inclusionDelayDeltas2
        inactivityPenaltyDeltas == inactivityPenaltyDeltas2

  `testImpl _ rewards _ identifier`()

suite "EF - Phase 0 - Rewards " & preset():
  for rewardsDir in [RewardsDirBasic, RewardsDirLeak, RewardsDirRandom]:
    for kind, path in walkDir(rewardsDir, relative = true, checkDir = true):
      runTest(rewardsDir, path)

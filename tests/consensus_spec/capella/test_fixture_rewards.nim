# beacon_chain
# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Beacon chain internals
  ../../beacon_chain/spec/[beaconstate, validator, helpers, state_transition_epoch],
  ../../beacon_chain/spec/datatypes/[altair, capella],
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops

const
  RewardsDirBase = SszTestsDir/const_preset/"capella"/"rewards"
  RewardsDirBasic = RewardsDirBase/"basic"/"pyspec_tests"
  RewardsDirLeak = RewardsDirBase/"leak"/"pyspec_tests"
  RewardsDirRandom = RewardsDirBase/"random"/"pyspec_tests"

func init(T: type Deltas, len: int): T =
  if not result.rewards.setLen(len):
    raiseAssert "setLen"
  if not result.penalties.setLen(len):
    raiseAssert "setLen"

proc runTest(rewardsDir, identifier: string) =
  let testDir = rewardsDir / identifier

  proc `testImpl _ rewards _ identifier`() =
    test "EF - Capella - Rewards - " & identifier & preset():
      var info: altair.EpochInfo

      let
        state = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, capella.BeaconState))
        flagDeltas = [
          parseTest(testDir/"source_deltas.ssz_snappy", SSZ, Deltas),
          parseTest(testDir/"target_deltas.ssz_snappy", SSZ, Deltas),
          parseTest(testDir/"head_deltas.ssz_snappy", SSZ, Deltas)]
        inactivityPenaltyDeltas =
          parseTest(testDir/"inactivity_penalty_deltas.ssz_snappy", SSZ, Deltas)

      info.init(state[])
      let
        total_balance = info.balances.current_epoch
        base_reward_per_increment = get_base_reward_per_increment(total_balance)

      static: doAssert PARTICIPATION_FLAG_WEIGHTS.len == 3
      var
        flagDeltas2 = [
          Deltas.init(state[].validators.len),
          Deltas.init(state[].validators.len),
          Deltas.init(state[].validators.len)]
        inactivityPenaltyDeltas2 = Deltas.init(state[].validators.len)

      let finality_delay = get_finality_delay(state[])

      for flag_index in 0 ..< PARTICIPATION_FLAG_WEIGHTS.len:
        for validator_index, delta in get_flag_index_deltas(
            state[], flag_index, base_reward_per_increment, info, finality_delay):
          if not is_eligible_validator(info.validators[validator_index]):
            continue
          flagDeltas2[flag_index].rewards[validator_index] = delta.rewards
          flagDeltas2[flag_index].penalties[validator_index] = delta.penalties

      for validator_index, delta in get_inactivity_penalty_deltas(
          defaultRuntimeConfig, state[], info):
        inactivityPenaltyDeltas2.penalties[validator_index] = delta

      check:
        flagDeltas == flagDeltas2
        inactivityPenaltyDeltas == inactivityPenaltyDeltas2

  `testImpl _ rewards _ identifier`()

suite "EF - Capella - Rewards " & preset():
  for rewardsDir in [RewardsDirBasic, RewardsDirLeak, RewardsDirRandom]:
    for kind, path in walkDir(rewardsDir, relative = true, checkDir = true):
      runTest(rewardsDir, path)

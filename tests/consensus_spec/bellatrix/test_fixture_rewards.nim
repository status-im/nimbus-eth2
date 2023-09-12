# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Beacon chain internals
  ../../../beacon_chain/spec/[beaconstate, validator, helpers, state_transition_epoch],
  ../../../beacon_chain/spec/datatypes/[altair, bellatrix],
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops

const
  RewardsDirBase = SszTestsDir/const_preset/"bellatrix"/"rewards"
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

  var info: altair.EpochInfo

  let
    state = newClone(
      parseTest(testDir/"pre.ssz_snappy", SSZ, bellatrix.BeaconState))
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

  var
    flagDeltas2: array[TimelyFlag, Deltas] = [
      Deltas.init(state[].validators.len),
      Deltas.init(state[].validators.len),
      Deltas.init(state[].validators.len)]
    inactivityPenaltyDeltas2 = Deltas.init(state[].validators.len)

  let finality_delay = get_finality_delay(state[])

  for validator_index, reward0, reward1, reward2, penalty0, penalty1, penalty2
      in get_flag_and_inactivity_deltas(
        defaultRuntimeConfig, state[], base_reward_per_increment, info,
        finality_delay):
    if not is_eligible_validator(info.validators[validator_index]):
      continue
    flagDeltas2[TimelyFlag.TIMELY_SOURCE_FLAG_INDEX].rewards[validator_index] =
      reward0
    flagDeltas2[TimelyFlag.TIMELY_TARGET_FLAG_INDEX].rewards[validator_index] =
      reward1
    flagDeltas2[TimelyFlag.TIMELY_HEAD_FLAG_INDEX].rewards[validator_index] =
      reward2
    flagDeltas2[TimelyFlag.TIMELY_SOURCE_FLAG_INDEX].penalties[validator_index] =
      penalty0
    flagDeltas2[TimelyFlag.TIMELY_TARGET_FLAG_INDEX].penalties[validator_index] =
      penalty1
    flagDeltas2[TimelyFlag.TIMELY_HEAD_FLAG_INDEX].penalties[validator_index] =
      0
    inactivityPenaltyDeltas2.penalties[validator_index] = penalty2

  check:
    flagDeltas == flagDeltas2
    inactivityPenaltyDeltas == inactivityPenaltyDeltas2

suite "EF - Bellatrix - Rewards " & preset():
  for rewardsDir in [RewardsDirBasic, RewardsDirLeak, RewardsDirRandom]:
    for kind, path in walkDir(rewardsDir, relative = true, checkDir = true):
      test "EF - Bellatrix - Rewards - " & path & preset():
        runTest(rewardsDir, path)

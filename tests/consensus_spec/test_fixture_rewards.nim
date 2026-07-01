# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ../../beacon_chain/spec/state_transition_epoch,
  ../testutil,
  ./fixtures_utils, ./os_ops

from ../../beacon_chain/spec/beaconstate import get_base_reward_per_increment

export ConsensusFork

func init(T: type Deltas, len: int): T =
  var res: T
  doAssert res.rewards.setLen(len)
  doAssert res.penalties.setLen(len)
  res

func add(v: var Deltas, idx: int, delta: RewardDelta) =
  v.rewards[idx] += delta.rewards
  v.penalties[idx] += delta.penalties

proc runRewardsTest*(
    rewardsDir, identifier: string, T: typedesc[phase0.BeaconState]) =
  let
    testDir = rewardsDir / identifier
    state = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
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
    cache: StateCache
    info: phase0.EpochInfo
  let finality_delay =
    state[].get_previous_epoch() - state[].finalized_checkpoint.epoch

  info.init(state[])
  info.process_attestations(state[], cache)
  let
    total_balance = info.balances.current_epoch
    total_balance_sqrt = integer_squareroot(distinctBase(total_balance))

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

proc runRewardsTest*[T:
    altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
    deneb.BeaconState | electra.BeaconState | fulu.BeaconState |
    gloas.BeaconState | heze.BeaconState](
    rewardsDir, identifier: string, _: typedesc[T]) =
  var info: altair.EpochInfo

  let
    testDir = rewardsDir / identifier
    state = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
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

  for validator_index, reward0, reward1, reward2, penalty0, penalty1, penalty2
      in get_flag_and_inactivity_deltas(
        defaultRuntimeConfig, state[], base_reward_per_increment, info,
        get_finality_delay(state[])):
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
      0.Gwei
    inactivityPenaltyDeltas2.penalties[validator_index] = penalty2

  check:
    flagDeltas == flagDeltas2
    inactivityPenaltyDeltas == inactivityPenaltyDeltas2

template rewardsTestSuite*(consensusFork: static ConsensusFork): untyped =
  const
    forkName = $consensusFork
    RewardsDirBase = SszTestsDir/const_preset/forkName/"rewards"
    RewardsDirBasic = RewardsDirBase/"basic"/"pyspec_tests"
    RewardsDirLeak = RewardsDirBase/"leak"/"pyspec_tests"
    RewardsDirRandom = RewardsDirBase/"random"/"pyspec_tests"

  suite "EF - " & forkName & " - Rewards " & preset():
    for rewardsDir in [RewardsDirBasic, RewardsDirLeak, RewardsDirRandom]:
      for kind, path in walkDir(rewardsDir, relative = true, checkDir = true):
        test "EF - " & forkName & " - Rewards - " & path & preset():
          runRewardsTest(rewardsDir, path, consensusFork.BeaconState)

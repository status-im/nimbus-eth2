# beacon_chain
# Copyright (c) 2020-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, unittest,
  # Utilities
  stew/results,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, state_transition_epoch],
  ../../beacon_chain/ssz,
  # Test utilities
  ../testutil,
  ./fixtures_utils

const
  RewardsDirBase = SszTestsDir/const_preset/"phase0"/"rewards"
  RewardsDirBasic = RewardsDirBase/"basic"/"pyspec_tests"
  RewardsDirLeak = RewardsDirBase/"leak"/"pyspec_tests"
  RewardsDirRandom = RewardsDirBase/"random"/"pyspec_tests"

# https://github.com/ethereum/eth2.0-specs/tree/v0.12.3/tests/formats/rewards#rewards-tests
type Deltas = object
  rewards: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]
  penalties: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

func compareDeltas(
    deltas: Deltas, rewardsPenalties: tuple[a: seq[Gwei], b: seq[Gwei]]):
    bool =
  deltas.rewards.asSeq == rewardsPenalties[0] and
    deltas.penalties.asSeq == rewardsPenalties[1]

proc runTest(rewardsDir, identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402
  let testDir = rewardsDir / identifier

  proc `testImpl _ rewards _ identifier`() =
    timedTest "Rewards" & " - " & identifier & preset():
      var
        state = newClone(parseTest(testDir/"pre.ssz", SSZ, BeaconState))
        cache = StateCache()
      let
        total_balance = get_total_active_balance(state[], cache)
        sourceDeltas = parseTest(testDir/"source_deltas.ssz", SSZ, Deltas)
        targetDeltas = parseTest(testDir/"target_deltas.ssz", SSZ, Deltas)
        headDeltas = parseTest(testDir/"head_deltas.ssz", SSZ, Deltas)
        inclusionDelayDeltas =
          parseTest(testDir/"inclusion_delay_deltas.ssz", SSZ, Deltas)
        inactivityPenaltyDeltas =
          parseTest(testDir/"inactivity_penalty_deltas.ssz", SSZ, Deltas)

      template get_deltas(body: untyped): untyped =
        var
          rewards {.inject.} = newSeq[Gwei](state[].validators.len)
          penalties {.inject.} = newSeq[Gwei](state[].validators.len)
        body
        (rewards, penalties)

      check:
        compareDeltas(sourceDeltas, get_deltas(
          get_source_deltas(state[], total_balance, rewards, penalties, cache)))
        compareDeltas(targetDeltas, get_deltas(
          get_target_deltas(state[], total_balance, rewards, penalties, cache)))
        compareDeltas(headDeltas, get_deltas(
          get_head_deltas(state[], total_balance, rewards, penalties, cache)))
        compareDeltas(inclusionDelayDeltas, get_deltas(
          get_inclusion_delay_deltas(state[], total_balance, rewards, cache)))
        compareDeltas(inactivityPenaltyDeltas, get_deltas(
          get_inactivity_penalty_deltas(state[], total_balance, penalties, cache)))

  `testImpl _ rewards _ identifier`()

suiteReport "Official - Rewards " & preset():
  for rewardsDir in [RewardsDirBasic, RewardsDirLeak, RewardsDirRandom]:
    for kind, path in walkDir(rewardsDir, true):
      runTest(rewardsDir, path)

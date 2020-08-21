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

const RewardsDir = SszTestsDir/const_preset/"phase0"/"rewards"/"core"/"pyspec_tests"

# https://github.com/ethereum/eth2.0-specs/tree/v0.12.2/tests/formats/rewards#rewards-tests
type Deltas = object
  rewards: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]
  penalties: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

func compareDeltas(
    deltas: Deltas, rewardsPenalties: tuple[a: seq[Gwei], b: seq[Gwei]]):
    bool =
  deltas.rewards.asSeq == rewardsPenalties[0] and
    deltas.penalties.asSeq == rewardsPenalties[1]

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402
  let testDir = RewardsDir / identifier

  proc `testImpl _ rewards _ identifier`() =
    timedTest "Rewards" & " - " & identifier & preset():
      var
        state = newClone(parseTest(testDir/"pre.ssz", SSZ, BeaconState))
        cache = StateCache()
      let
        total_balance = get_total_active_balance(state[].unsafeView(), cache)
        sourceDeltas = parseTest(testDir/"source_deltas.ssz", SSZ, Deltas)
        targetDeltas = parseTest(testDir/"target_deltas.ssz", SSZ, Deltas)
        headDeltas = parseTest(testDir/"head_deltas.ssz", SSZ, Deltas)
        inclusionDelayDeltas =
          parseTest(testDir/"inclusion_delay_deltas.ssz", SSZ, Deltas)
        inactivityPenaltyDeltas =
          parseTest(testDir/"inactivity_penalty_deltas.ssz", SSZ, Deltas)

      check:
        compareDeltas(sourceDeltas, get_source_deltas(state[].unsafeView, total_balance, cache))
        compareDeltas(targetDeltas, get_target_deltas(state[].unsafeView, total_balance, cache))
        compareDeltas(headDeltas, get_head_deltas(state[].unsafeView, total_balance, cache))
        inclusionDelayDeltas.rewards.asSeq ==
          get_inclusion_delay_deltas(state[].unsafeView, total_balance, cache)
        inactivityPenaltyDeltas.penalties.asSeq ==
          get_inactivity_penalty_deltas(state[].unsafeView, total_balance, cache)

  `testImpl _ rewards _ identifier`()

suiteReport "Official - Rewards " & preset():
  for kind, path in walkDir(RewardsDir, true):
    runTest(path)

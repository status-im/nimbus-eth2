# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ./testutil, ./testdbutil, ./teststateutil,
  ../beacon_chain/spec/forks,
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine]

from std/sequtils import mapIt
from ../beacon_chain/statediff import
  applyDiff, diffStates, getBeaconStateDiffSummary

# In live usage, it's unnecessary and excessive to keep both states in memory
# at once, but it simplifies testing so treat this explicitly as testing-only
# infrastructure.
func diffStates(state0, state1: capella.BeaconState): BeaconStateDiff =
  doAssert state1.slot > state0.slot
  doAssert state0.slot.is_epoch
  doAssert state1.slot == state0.slot + SLOTS_PER_EPOCH
  # TODO not here, but in dag, an isancestorof check
  doAssert state0.genesis_time == state1.genesis_time
  doAssert state0.genesis_validators_root == state1.genesis_validators_root
  doAssert state0.fork == state1.fork
  doAssert state1.historical_roots == state0.historical_roots
  doAssert state1.historical_summaries.len -
    state0.historical_summaries.len in [0, 1]

  diffStates(getBeaconStateDiffSummary(state0), state1)

when isMainModule:
  import chronicles # or some random compile error happens...

suite "state diff tests" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})

  test "random slot differences" & preset():
    let testStates = getTestStates(dag.headState, ConsensusFork.Capella)

    for i in 0 ..< testStates.len:
      for j in (i+1) ..< testStates.len:
        doAssert getStateField(testStates[i][], slot) <
          getStateField(testStates[j][], slot)
        if  getStateField(testStates[i][], slot) + SLOTS_PER_EPOCH !=
            getStateField(testStates[j][], slot):
          continue
        let
          tmpStateApplyBase = assignClone(testStates[i].capellaData.data)
          diff = diffStates(
            testStates[i].capellaData.data, testStates[j].capellaData.data)
        # Immutable parts of validators stored separately, so aren't part of
        # the state diff. Synthesize required portion here for testing.
        applyDiff(
          tmpStateApplyBase[],
          mapIt(
            getStateField(testStates[j][], validators).asSeq[
              getStateField(testStates[i][], validators).len ..
              getStateField(testStates[j][], validators).len - 1],
            it.getImmutableValidatorData),
          diff)
        check hash_tree_root(testStates[j][].capellaData.data) ==
          hash_tree_root(tmpStateApplyBase[])

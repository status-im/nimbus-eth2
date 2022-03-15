# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, sequtils,
  unittest2,
  ./testutil, ./testdbutil, ./teststateutil,
  ../beacon_chain/spec/datatypes/altair,
  ../beacon_chain/spec/[forks, helpers],
  ../beacon_chain/statediff,
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine]

when isMainModule:
  import chronicles # or some random compile error happens...

suite "state diff tests" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})

  test "random slot differences" & preset():
    let testStates = getTestStates(dag.headState, BeaconStateFork.Altair)

    for i in 0 ..< testStates.len:
      for j in (i+1) ..< testStates.len:
        doAssert getStateField(testStates[i][], slot) <
          getStateField(testStates[j][], slot)
        if getStateField(testStates[i][], slot) + SLOTS_PER_EPOCH != getStateField(testStates[j][], slot):
          continue
        let tmpStateApplyBase = assignClone(testStates[i].altairData.data)
        let diff = diffStates(
          testStates[i].altairData.data, testStates[j].altairData.data)
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
        check hash_tree_root(testStates[j][].altairData.data) ==
          hash_tree_root(tmpStateApplyBase[])

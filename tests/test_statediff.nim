# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, sequtils, unittest,
  ./testutil, ./teststateutil,
  ../beacon_chain/spec/[datatypes, digest, helpers, presets],
  ../beacon_chain/[beacon_node_types, statediff],
  ../beacon_chain/ssz,
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine, block_clearance]

when isMainModule:
  import chronicles # or some random compile error happens...

template wrappedTimedTest(name: string, body: untyped) =
  # `check` macro takes a copy of whatever it's checking, on the stack!
  # This leads to stack overflow
  # We can mitigate that by wrapping checks in proc
  block: # Symbol namespacing
    proc wrappedTest() =
      timedTest name:
        body
    wrappedTest()

suiteReport "state diff tests" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      dag = init(ChainDAGRef, defaultRuntimePreset, db)

  wrappedTimedTest "random slot differences" & preset():
    let testStates = getTestStates(dag.headState.data)

    for i in 0 ..< testStates.len:
      for j in (i+1) ..< testStates.len:
        doAssert testStates[i].data.slot < testStates[j].data.slot
        if testStates[i].data.slot + SLOTS_PER_EPOCH != testStates[j].data.slot:
          continue
        var tmpStateApplyBase = assignClone(testStates[i].data)
        let diff = diffStates(testStates[i].data, testStates[j].data)
        # Immutable parts of validators stored separately, so aren't part of
        # the state diff. Synthesize required portion here for testing.
        applyDiff(
          tmpStateApplyBase[],
          mapIt(testStates[j].data.validators.asSeq[
              testStates[i].data.validators.len ..
              testStates[j].data.validators.len - 1],
            it.getImmutableValidatorData),
          diff)
        check hash_tree_root(testStates[j].data) ==
          hash_tree_root(tmpStateApplyBase[])

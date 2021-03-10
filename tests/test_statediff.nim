# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, sequtils, unittest,
  ./testutil,
  ./helpers/math_helpers,
  ./mocking/mock_deposits,
  ../beacon_chain/spec/[beaconstate, datatypes, digest, helpers,
    state_transition, presets],
  ../beacon_chain/[beacon_node_types, statediff],
  ../beacon_chain/ssz,
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine, block_clearance]

when isMainModule:
  import chronicles # or some random compile error happens...

proc valid_deposit(state: var BeaconState) =
  # TODO copy/pasted from foo; refactor
  const deposit_amount = MAX_EFFECTIVE_BALANCE
  let validator_index = state.validators.len
  let deposit = mockUpdateStateForNewDeposit(
                  state,
                  uint64 validator_index,
                  deposit_amount,
                  flags = {}
                )

  let pre_val_count = state.validators.len
  let pre_balance = if validator_index < pre_val_count:
                      state.balances[validator_index]
                    else:
                      0
  check:
    process_deposit(defaultRuntimePreset(), state, deposit, {}).isOk
    state.validators.len == pre_val_count + 1
    state.balances.len == pre_val_count + 1
    state.balances[validator_index] == pre_balance + deposit.data.amount
    state.validators[validator_index].effective_balance ==
      round_multiple_down(
        min(MAX_EFFECTIVE_BALANCE, state.balances[validator_index]),
        EFFECTIVE_BALANCE_INCREMENT
      )

proc getTestStates(initialState: HashedBeaconState):
    seq[ref HashedBeaconState] =
  # Randomly generated slot numbers, with a jump to around
  # SLOTS_PER_HISTORICAL_ROOT to force wraparound of those
  # slot-based mod/increment fields.
  const stateEpochs = [
    0, 1,

    # Around minimal wraparound SLOTS_PER_HISTORICAL_ROOT wraparound
    5, 6, 7, 8, 9,

    39, 40, 97, 98, 99, 113, 114, 115, 116, 130, 131, 145, 146, 192, 193,
    232, 233, 237, 238,

    # Approaching and passing SLOTS_PER_HISTORICAL_ROOT wraparound
    254, 255, 256, 257, 258]

  var
    tmpState = assignClone(initialState)
    cache = StateCache()

  for i, epoch in stateEpochs:
    let slot = epoch.Epoch.compute_start_slot_at_epoch
    if tmpState.data.slot < slot:
      doAssert process_slots(tmpState[], slot, cache)
    if i mod 3 == 0:
      valid_deposit(tmpState.data)
    doAssert tmpState.data.slot == slot
    result.add assignClone(tmpState[])

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

# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
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
  ../beacon_chain/[beacon_node_types, ssz, statediff],
  ../beacon_chain/block_pools/[chain_dag, quarantine, clearance]

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

  wrappedTimedTest "delta-encoding/decoding roundtrip sanity" & preset():
    const
      balances0 = [
        18441870559'u64, 33446800397'u64, 11147100626'u64, 42603154274'u64,
        35932339237'u64, 59867680015'u64, 19647051219'u64, 63570367156'u64,
        43824455480'u64, 47579598334'u64, 22175553574'u64, 13601246675'u64,
        40046565997'u64, 19862192832'u64, 14541260920'u64, 25776220537'u64,
        53093805050'u64, 47082111792'u64, 24773067164'u64, 25673826779'u64,
        45827636611'u64, 31759878136'u64, 58103054360'u64, 50512782241'u64,
        31182839614'u64]

      balances1 = [
        42080447134'u64,  9723866886'u64, 21528919469'u64, 60580554318'u64,
        37463193877'u64, 18143243334'u64, 32030042150'u64, 51881718936'u64,
        17259308484'u64, 18169637307'u64, 48769712906'u64, 51088432822'u64,
        52895655180'u64, 26116017983'u64, 39305430230'u64, 24222097345'u64,
        39462882494'u64, 39596015040'u64, 37160795641'u64, 35339479924'u64,
        33636108383'u64, 15242724015'u64, 60815628681'u64, 32706350007'u64,
         8978429438'u64, 21322048864'u64, 22997808541'u64, 37068275007'u64,
        50938101702'u64, 14620153832'u64, 55162721187'u64, 26298968647'u64,
        17648055143'u64, 59996602297'u64, 30878159440'u64, 22415848926'u64,
        20768842475'u64]

      balances2 = [
        21675589964'u64, 13993227022'u64, 26438767944'u64, 41440196317'u64,
        41766461882'u64, 52661505859'u64, 42126387709'u64, 54445893868'u64,
        41509802863'u64, 36976355380'u64, 46813612650'u64, 41196532827'u64,
        23300952618'u64, 39031444988'u64, 37599530900'u64, 51850708563'u64,
        42648477675'u64, 48123583384'u64, 17001259539'u64, 41801119284'u64,
        44028789526'u64, 18179258736'u64, 50904978474'u64, 61199002779'u64,
        24333838181'u64, 39569287366'u64, 37714257632'u64, 27622624307'u64,
        63524818041'u64,  9470549646'u64, 41890932546'u64, 35929754455'u64,
        18073815159'u64, 61164677670'u64, 46599755663'u64, 39969979788'u64,
        19044350776'u64, 54818254044'u64, 48961544925'u64, 32004978192'u64,
        26380608851'u64, 31055862486'u64, 16774301884'u64, 34387075525'u64,
        30929489373'u64, 59224634642'u64, 39883929054'u64, 46052767920'u64,
        53119984525'u64]

      balances_empty: array[0, uint64] = []

      balances_single = [26971116287'u64]

    template test_roundtrip_balances(state_balances: untyped) =
      var balances = HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]()
      for balance in state_balances:
        balances.add balance

      check deltaDecodeBalances[uint64, Limit VALIDATOR_REGISTRY_LIMIT](
        deltaEncodeBalances[uint64, Limit VALIDATOR_REGISTRY_LIMIT](
          balances)) == balances

    test_roundtrip_balances(balances_empty)
    test_roundtrip_balances(balances_single)
    test_roundtrip_balances(balances0)
    test_roundtrip_balances(balances1)
    test_roundtrip_balances(balances2)

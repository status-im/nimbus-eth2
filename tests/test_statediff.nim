# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  options, unittest,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[datatypes, digest, helpers, state_transition, presets],
  ../beacon_chain/[beacon_node_types, ssz, statediff],
  ../beacon_chain/block_pools/[chain_dag, quarantine, clearance]

when isMainModule:
  import chronicles # or some random compile error happens...

func checkBeaconStates(a, b: BeaconState) =
  # TODO field-by-field macro; do want separate checks
  doAssert a.genesis_time == b.genesis_time
  doAssert a.genesis_validators_root == b.genesis_validators_root
  doAssert a.slot == b.slot
  doAssert a.fork == b.fork
  doAssert a.latest_block_header == b.latest_block_header
  doAssert a.block_roots == b.block_roots
  doAssert a.historical_roots == b.historical_roots
  doAssert a.eth1_data == b.eth1_data
  doAssert a.eth1_data_votes == b.eth1_data_votes
  doAssert a.eth1_deposit_index == b.eth1_deposit_index
  doAssert hash_tree_root(a.validators) == hash_tree_root(b.validators)
  doAssert a.balances == b.balances
  doAssert a.randao_mixes == b.randao_mixes
  doAssert a.slashings == b.slashings
  doAssert a.previous_epoch_attestations == b.previous_epoch_attestations
  doAssert a.current_epoch_attestations == b.current_epoch_attestations
  doAssert a.justification_bits == b.justification_bits
  doAssert a.previous_justified_checkpoint == b.previous_justified_checkpoint
  doAssert a.current_justified_checkpoint == b.current_justified_checkpoint
  doAssert a.finalized_checkpoint == b.finalized_checkpoint
  doAssert hash_tree_root(a) == hash_tree_root(b)

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
      quarantine = QuarantineRef()
      cache = StateCache()

  wrappedTimedTest "from genesis" & preset():
    var
      blck = makeTestBlock(dag.headState.data, dag.head.root, cache)
      tmpState = assignClone(dag.headState.data)
      tmpStateOriginal = assignClone(dag.headState.data)
      tmpStateApplyBase = assignClone(dag.headState.data)
    check:
      process_slots(
        tmpState[], tmpState.data.slot + 1.uint64, cache)

    #let anotherBlock = addTestBlock(tmpState[], dag.head.root, cache)
    block:
      let status = dag.addRawBlock(quarantine, blck, nil)
      check: status.isOk()

    block:
      let diff = diffState(tmpStateOriginal.data, tmpState.data)
      applyDiff(tmpStateApplyBase.data, diff)
      checkBeaconStates(tmpState.data, tmpStateApplyBase.data)
    #assign(tmpState[], dag.headState.data)

    check:
      process_slots(
        tmpState[], tmpState.data.slot + 80.uint, cache)

    block:
      let diff = diffState(tmpStateOriginal.data, tmpState.data)
      tmpStateApplyBase = assignClone(tmpStateOriginal[])
      applyDiff(tmpStateApplyBase.data, diff)
      when false:
        debugEcho "tso[0] = ", tmpStateOriginal.data.block_roots[0], "; tso[1] = ", tmpStateOriginal.data.block_roots[1]
        debugEcho "ts[0] = ", tmpState.data.block_roots[0], "; ts[1] = ", tmpState.data.block_roots[1]
        debugEcho "tsab[0] = ", tmpStateApplyBase.data.block_roots[1], "; tsab[1] = ", tmpStateApplyBase.data.block_roots[2]
      checkBeaconStates(tmpState.data, tmpStateApplyBase.data)

    # TODO more tests (different numbers of slots, adding validators, applying
    # complex blocks, wrap-around of mod-increment, sane behaviors with forks,
    # whether that's rejection or functioning well, starting from non-genesis,
    # etc)

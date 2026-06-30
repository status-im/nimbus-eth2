# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Status libraries
  unittest2,
  # Internal
  ../beacon_chain/consensus_object_pools/[
    blockchain_dag, inclusion_list_pool],
  ../beacon_chain/spec/[
    beaconstate, eth2_merkleization, forks, inclusion_list,
    state_transition],
  ../beacon_chain/beacon_clock,
  # Test utilities
  ./testutil, ./testdbutil, ./consensus_spec/fixtures_utils

func makeTx(bytes: openArray[byte]): bellatrix.Transaction =
  bellatrix.Transaction(@bytes)

func makeInclusionList(
    slot: Slot, validator_index: uint64, committee_root: Eth2Digest,
    txs: openArray[bellatrix.Transaction]): InclusionList =
  var il = InclusionList(
    slot: slot,
    validator_index: validator_index,
    inclusion_list_committee_root: committee_root)
  for tx in txs:
    doAssert il.transactions.add(tx)
  il

suite "Inclusion list pool" & preset():
  setup:
    const TOTAL_COMMITTEES = 1
    let
      cfg = genesisTestRuntimeConfig(ConsensusFork.Heze)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(
        ChainDAGRef, cfg,
        cfg.makeTestDB(TOTAL_COMMITTEES * PTC_SIZE),
        validatorMonitor, {})
      pool = newClone(InclusionListPool.init(dag))
      state = newClone(dag.headState)
    var
      cache: StateCache
      info = ForkedEpochInfo()
    check:
      process_slots(
        dag.cfg, state[], state[].slot + 1, cache, info, {}).isOk()
      state[].kind == ConsensusFork.Heze

    let
      hezeState = addr state[].hezeData.data
      slot = hezeState[].slot
      committee = get_inclusion_list_committee(hezeState[], slot, cache)
      committeeRoot = hash_tree_root(committee)
      wallTime = slot.start_beacon_time(dag.cfg.timeParams)

  test "Stores transactions for the slot" & preset():
    let
      member = committee[0]
      il = makeInclusionList(
        slot, member, committeeRoot, [makeTx([byte 0x01, 0x02])])

    check:
      pool[].addInclusionList(il, is_timely = true, wallTime)
      pool[].numSeen(slot, member) == 1

    let txs = pool[].getInclusionListTransactions(
      hezeState[], slot, cache, only_timely = true)
    check:
      txs.len == 1
      txs[0] == makeTx([byte 0x01, 0x02])

  test "Byte-identical resubmission is a no-op" & preset():
    let il = makeInclusionList(
      slot, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      pool[].addInclusionList(il, is_timely = true, wallTime)
      not pool[].addInclusionList(il, is_timely = true, wallTime)
      pool[].numSeen(slot, committee[0]) == 1

  test "Accepts two distinct lists then drops the third" & preset():
    let
      vi = committee[0]
      il1 = makeInclusionList(slot, vi, committeeRoot, [makeTx([byte 0x01])])
      il2 = makeInclusionList(slot, vi, committeeRoot, [makeTx([byte 0x02])])
      il3 = makeInclusionList(slot, vi, committeeRoot, [makeTx([byte 0x03])])

    check:
      pool[].addInclusionList(il1, is_timely = true, wallTime)
      pool[].addInclusionList(il2, is_timely = true, wallTime)
      not pool[].addInclusionList(il3, is_timely = true, wallTime)
      pool[].numSeen(slot, vi) == 2

  test "Untimely lists are excluded unless requested" & preset():
    let il = makeInclusionList(
      slot, committee[0], committeeRoot, [makeTx([byte 0xAA])])

    check pool[].addInclusionList(il, is_timely = false, wallTime)

    # only_timely = true drops it ...
    check pool[].getInclusionListTransactions(
      hezeState[], slot, cache, only_timely = true).len == 0

    # ... only_timely = false includes it.
    let all = pool[].getInclusionListTransactions(
      hezeState[], slot, cache, only_timely = false)
    check:
      all.len == 1
      all[0] == makeTx([byte 0xAA])

  test "Stale slots are pruned" & preset():
    let il = makeInclusionList(
      slot, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      pool[].addInclusionList(il, is_timely = true, wallTime)
      pool[].getInclusionListTransactions(
        hezeState[], slot, cache, only_timely = true).len == 1

    # Adding at a much later wall time prunes the original slot's store.
    let
      futureTime = (slot + 5).start_beacon_time(dag.cfg.timeParams)
      future = makeInclusionList(
        slot + 5, committee[1], committeeRoot, [makeTx([byte 0x02])])

    check:
      pool[].addInclusionList(future, is_timely = true, futureTime)
      pool[].getInclusionListTransactions(
        hezeState[], slot, cache, only_timely = true).len == 0

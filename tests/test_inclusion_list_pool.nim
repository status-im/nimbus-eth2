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

func makeTx(bytes: openArray[byte]): gloas.Transaction =
  gloas.Transaction(@bytes)

func makeInclusionList(
    slot: Slot, validator_index: uint64, committee_root: Eth2Digest,
    txs: openArray[gloas.Transaction],
    signature = default(ValidatorSig)): SignedInclusionList =
  ## The pool never inspects the signature - gossip validation has already done
  ## that - but retains it for `InclusionListsByIndices` to serve back.
  var il = InclusionList(
    slot: slot,
    validator_index: validator_index,
    inclusion_list_committee_root: committee_root)
  for tx in txs:
    il.transactions.add(tx)
  SignedInclusionList(message: il, signature: signature)

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
      pool = newClone(InclusionListPool.init(dag.timeParams))
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
      slot, committee, only_timely = true)
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
      slot, committee, only_timely = true).len == 0

    # ... only_timely = false includes it.
    let all = pool[].getInclusionListTransactions(
      slot, committee, only_timely = false)
    check:
      all.len == 1
      all[0] == makeTx([byte 0xAA])

  test "Stale slots are pruned" & preset():
    let il = makeInclusionList(
      slot, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      pool[].addInclusionList(il, is_timely = true, wallTime)
      pool[].getInclusionListTransactions(
        slot, committee, only_timely = true).len == 1

    # Adding at a much later wall time prunes the original slot's store.
    let
      futureTime = (slot + 5).start_beacon_time(dag.cfg.timeParams)
      future = makeInclusionList(
        slot + 5, committee[1], committeeRoot, [makeTx([byte 0x02])])

    check:
      pool[].addInclusionList(future, is_timely = true, futureTime)
      pool[].getInclusionListTransactions(
        slot, committee, only_timely = true).len == 0
      pool[].numSeen(slot, committee[0]) == 0

  test "A list one slot behind the wall slot is still accepted" & preset():
    # The live window is `[current_slot - 1, current_slot]`: a list for `slot`
    # remains admissible while the wall clock is at `slot + 1`.
    let
      wallNext = (slot + 1).start_beacon_time(dag.cfg.timeParams)
      il = makeInclusionList(
        slot, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      pool[].addInclusionList(il, is_timely = true, wallNext)
      pool[].getInclusionListTransactions(
        slot, committee, only_timely = true).len == 1

  test "A list past the lookback window is rejected" & preset():
    # Wall clock at `slot + 2` puts `slot` two behind, outside the window.
    let
      wallLate = (slot + 2).start_beacon_time(dag.cfg.timeParams)
      il = makeInclusionList(
        slot, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      not pool[].addInclusionList(il, is_timely = true, wallLate)
      pool[].numSeen(slot, committee[0]) == 0
      pool[].getInclusionListTransactions(
        slot, committee, only_timely = true).len == 0

  test "A list for a future slot is rejected" & preset():
    let il = makeInclusionList(
      slot + 1, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      not pool[].addInclusionList(il, is_timely = true, wallTime)
      pool[].numSeen(slot + 1, committee[0]) == 0

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/heze/p2p-interface.md#inclusionlistsbyindices-v1
  test "Serves stored lists, signature included" & preset():
    var signature: ValidatorSig
    signature.blob[0] = 0xAB

    let il = makeInclusionList(
      slot, committee[0], committeeRoot, [makeTx([byte 0x01])], signature)
    check pool[].addInclusionList(il, is_timely = true, wallTime)

    let served = pool[].getInclusionLists(
      slot, committeeRoot, [committee[0]], maxLists = 16)
    check:
      served.len == 1
      served[0] == il

    # A list is only served for the committee it was collected under ...
    check pool[].getInclusionLists(
      slot, ZERO_HASH, [committee[0]], maxLists = 16).len == 0

    # ... for the slot it belongs to ...
    check pool[].getInclusionLists(
      slot + 1, committeeRoot, [committee[0]], maxLists = 16).len == 0

    # ... and for validators the requester actually asked about.
    check pool[].getInclusionLists(
      slot, committeeRoot, [committee[0] + 1000], maxLists = 16).len == 0

  test "Untimely lists are still served over req/resp" & preset():
    # Timeliness is a fork choice notion, not a gossip validation rule, so it
    # must not gate what we respond with.
    let il = makeInclusionList(
      slot, committee[0], committeeRoot, [makeTx([byte 0x01])])

    check:
      pool[].addInclusionList(il, is_timely = false, wallTime)
      pool[].getInclusionLists(
        slot, committeeRoot, [committee[0]], maxLists = 16).len == 1

  test "Equivocators are not served" & preset():
    let
      vi = committee[0]
      il1 = makeInclusionList(slot, vi, committeeRoot, [makeTx([byte 0x01])])
      il2 = makeInclusionList(slot, vi, committeeRoot, [makeTx([byte 0x02])])

    check:
      pool[].addInclusionList(il1, is_timely = true, wallTime)
      pool[].getInclusionLists(
        slot, committeeRoot, [vi], maxLists = 16).len == 1

    # The second, distinct list marks the validator as an equivocator, and
    # Clients SHOULD NOT respond with inclusion lists from equivocators.
    check:
      pool[].addInclusionList(il2, is_timely = true, wallTime)
      pool[].getInclusionLists(
        slot, committeeRoot, [vi], maxLists = 16).len == 0

  test "Response is deduplicated and capped" & preset():
    let
      il0 = makeInclusionList(
        slot, committee[0], committeeRoot, [makeTx([byte 0x01])])
      il1 = makeInclusionList(
        slot, committee[1], committeeRoot, [makeTx([byte 0x02])])

    check:
      pool[].addInclusionList(il0, is_timely = true, wallTime)
      pool[].addInclusionList(il1, is_timely = true, wallTime)

    # A committee smaller than `INCLUSION_LIST_COMMITTEE_SIZE` cycles its
    # members, so the same validator can occupy several requested positions -
    # it must still be served only once.
    check pool[].getInclusionLists(
      slot, committeeRoot, [committee[0], committee[0], committee[1]],
      maxLists = 16).len == 2

    # Clients MAY limit the number of inclusion lists in the response.
    check pool[].getInclusionLists(
      slot, committeeRoot, [committee[0], committee[1]], maxLists = 1).len == 1

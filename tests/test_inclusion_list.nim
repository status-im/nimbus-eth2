# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[sets, tables],
  unittest2,
  ../beacon_chain/spec/[
    beaconstate, eth2_merkleization, forks, signatures, inclusion_list],
  ./consensus_spec/fixtures_utils,
  ./teststateutil,
  ./testblockutil,
  ./testutil

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

suite "Inclusion list" & preset():
  setup:
    let
      cfg = genesisTestRuntimeConfig(ConsensusFork.Heze)
      forkedState = initGenesisState(cfg)
    var cache = StateCache()

    check forkedState[].kind == ConsensusFork.Heze
    let
      state = addr forkedState[].hezeData.data
      slot = state[].slot
      committee = get_inclusion_list_committee(state[], slot, cache)
      committeeRoot = hash_tree_root(committee)

  test "get_inclusion_list_committee":
    # The committee always has exactly INCLUSION_LIST_COMMITTEE_SIZE members ...
    check committee.len == int INCLUSION_LIST_COMMITTEE_SIZE

    # ... and equals the slot's beacon committees concatenated and cycled, with
    # every member a valid validator index.
    var indices: seq[ValidatorIndex]
    let committees_per_slot =
      get_committee_count_per_slot(state[], slot.epoch, cache)
    for i in 0'u64 ..< committees_per_slot:
      indices.add get_beacon_committee(state[], slot, CommitteeIndex(i), cache)

    check indices.len > 0
    for i in 0 ..< int INCLUSION_LIST_COMMITTEE_SIZE:
      check:
        committee[i] == indices[i mod indices.len].uint64
        committee[i] < state[].validators.lenu64

  test "is_valid_inclusion_list_signature":
    const validator_index = 0'u64
    var signed: SignedInclusionList
    signed.message = makeInclusionList(
      slot, validator_index, committeeRoot, [makeTx([byte 0x01, 0x02])])
    signed.signature = get_inclusion_list_signature(
      state[].fork, state[].genesis_validators_root, signed.message,
      MockPrivKeys[validator_index.ValidatorIndex]).toValidatorSig

    check is_valid_inclusion_list_signature(state[], signed)

    # Wrong signer index breaks the signature ...
    var wrongIndex = signed
    wrongIndex.message.validator_index = 1
    check not is_valid_inclusion_list_signature(state[], wrongIndex)

    # ... a tampered message breaks it ...
    var tampered = signed
    tampered.message.slot = slot + 1
    check not is_valid_inclusion_list_signature(state[], tampered)

    # ... and an out-of-range validator index is rejected, not a crash.
    var outOfRange = signed
    outOfRange.message.validator_index = state[].validators.lenu64
    check not is_valid_inclusion_list_signature(state[], outOfRange)

  test "process_inclusion_list detects equivocation":
    var store: InclusionListStore
    let
      tx1 = makeTx([byte 0x01])
      tx2 = makeTx([byte 0x02])
      il = makeInclusionList(slot, 5, committeeRoot, [tx1])
      conflicting = makeInclusionList(slot, 5, committeeRoot, [tx2])

    store.process_inclusion_list(il, is_timely = true)
    check:
      store.inclusion_lists.getOrDefault(committeeRoot).len == 1
      committeeRoot notin store.equivocators

    # A byte-identical resubmission is a no-op, not an equivocation.
    store.process_inclusion_list(il, is_timely = true)
    check:
      store.inclusion_lists.getOrDefault(committeeRoot).len == 1
      committeeRoot notin store.equivocators

    # A conflicting list from the same validator marks it as an equivocator and
    # is not stored.
    store.process_inclusion_list(conflicting, is_timely = true)
    check:
      store.inclusion_lists.getOrDefault(committeeRoot).len == 1
      5'u64 in store.equivocators.getOrDefault(committeeRoot)

    # Once flagged, further lists from that validator are ignored outright.
    let later = makeInclusionList(slot, 5, committeeRoot, [makeTx([byte 0x03])])
    store.process_inclusion_list(later, is_timely = true)
    check store.inclusion_lists.getOrDefault(committeeRoot).len == 1

  test "get_inclusion_list_transactions dedups and filters":
    var store: InclusionListStore
    let
      tx1 = makeTx([byte 0x01])
      tx2 = makeTx([byte 0x02])
      tx3 = makeTx([byte 0x03])
      tx4 = makeTx([byte 0x04])
      tx5 = makeTx([byte 0x05])

    # Two timely lists with an overlapping transaction (tx2).
    store.process_inclusion_list(
      makeInclusionList(slot, 6, committeeRoot, [tx1, tx2]), is_timely = true)
    store.process_inclusion_list(
      makeInclusionList(slot, 7, committeeRoot, [tx2, tx3]), is_timely = true)
    # An untimely list (tx4).
    store.process_inclusion_list(
      makeInclusionList(slot, 8, committeeRoot, [tx4]), is_timely = false)
    # An equivocating validator (tx5) must be excluded entirely.
    store.process_inclusion_list(
      makeInclusionList(slot, 9, committeeRoot, [tx5]), is_timely = true)
    store.process_inclusion_list(
      makeInclusionList(slot, 9, committeeRoot, [tx1]), is_timely = true)

    # only_timely (default): tx1, tx2, tx3 deduped; tx4 untimely; tx5 equivocated.
    let timely = store.get_inclusion_list_transactions(state[], slot, cache)
    check:
      timely.len == 3
      tx1 in timely
      tx2 in timely
      tx3 in timely
      tx4 notin timely
      tx5 notin timely

    # only_timely = false additionally includes the untimely tx4, still no tx5.
    let all = store.get_inclusion_list_transactions(
      state[], slot, cache, only_timely = false)
    check:
      all.len == 4
      tx4 in all
      tx5 notin all

    # A mismatched committee root yields no transactions.
    let other = store.get_inclusion_list_transactions(
      state[], slot + 1, cache)
    check other.len == 0

  test "end-to-end: committee members sign, validate, and are collected":
    var store: InclusionListStore

    # Each committee member signs a list carrying one transaction keyed by its
    # validator index (so cycled/duplicate members produce identical lists, a
    # no-op rather than an equivocation).
    for member in committee:
      let mi = member.uint64
      var signed: SignedInclusionList
      signed.message = makeInclusionList(
        slot, mi, committeeRoot, [makeTx([byte (mi shr 8), byte mi])])
      signed.signature = get_inclusion_list_signature(
        state[].fork, state[].genesis_validators_root, signed.message,
        MockPrivKeys[member]).toValidatorSig

      # The committee root in the message is what the consumer recomputes ...
      check:
        signed.message.inclusion_list_committee_root == committeeRoot
        is_valid_inclusion_list_signature(state[], signed)

      store.process_inclusion_list(signed.message, is_timely = true)

    # every distinct member's transaction is collected exactly once,
    # with no validator flagged as an equivocator.
    var distinctMembers: HashSet[uint64]
    for member in committee:
      distinctMembers.incl member.uint64

    let txs = store.get_inclusion_list_transactions(state[], slot, cache)
    check:
      committeeRoot notin store.equivocators
      txs.len == distinctMembers.len

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

func makeTx(bytes: openArray[byte]): gloas.Transaction =
  gloas.Transaction(@bytes)

func makeInclusionList(
    slot: Slot, validator_index: uint64, dependent_root: Eth2Digest,
    txs: openArray[gloas.Transaction]): SignedInclusionList =
  var il = InclusionList(
    slot: slot,
    validator_index: validator_index,
    dependent_root: dependent_root)
  for tx in txs:
    il.transactions.add(tx)
  SignedInclusionList(message: il)

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
      dependentRoot = Eth2Digest.fromHex(
        "0x0101010101010101010101010101010101010101010101010101010101010101")
      key = (slot, dependentRoot)

  test "get_inclusion_list_committee":
    check committee.len == int INCLUSION_LIST_COMMITTEE_SIZE

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
    var signed = makeInclusionList(
      slot, validator_index, dependentRoot, [makeTx([byte 0x01, 0x02])])
    signed.signature = get_inclusion_list_signature(
      state[].fork, state[].genesis_validators_root, signed.message,
      MockPrivKeys[validator_index.ValidatorIndex]).toValidatorSig

    check is_valid_inclusion_list_signature(state[], signed)

    var wrongIndex = signed
    wrongIndex.message.validator_index = 1
    check not is_valid_inclusion_list_signature(state[], wrongIndex)

    var tampered = signed
    tampered.message.dependent_root = ZERO_HASH
    check not is_valid_inclusion_list_signature(state[], tampered)

    var outOfRange = signed
    outOfRange.message.validator_index = state[].validators.lenu64
    check not is_valid_inclusion_list_signature(state[], outOfRange)

  test "process_inclusion_list detects equivocation":
    var store: InclusionListStore
    let
      il = makeInclusionList(slot, 5, dependentRoot, [makeTx([byte 0x01])])
      conflicting =
        makeInclusionList(slot, 5, dependentRoot, [makeTx([byte 0x02])])
      otherRoot =
        makeInclusionList(slot, 5, ZERO_HASH, [makeTx([byte 0x02])])

    store.process_inclusion_list(il, timely = true)
    store.process_inclusion_list(il, timely = true)
    check:
      store.inclusion_lists.getOrDefault(key).len == 1
      not store.isEquivocator(key, 5)

    store.process_inclusion_list(conflicting, timely = false)
    check:
      store.inclusion_lists.getOrDefault(key).len == 1
      store.inclusion_lists.getOrDefault(key).getOrDefault(5)
        .signed_inclusion_list == il
      store.isEquivocator(key, 5)

    store.process_inclusion_list(otherRoot, timely = true)
    check not store.isEquivocator((slot, ZERO_HASH), 5)

  test "get_inclusion_list_transactions dedups and filters":
    var store: InclusionListStore
    let
      tx1 = makeTx([byte 0x01])
      tx2 = makeTx([byte 0x02])
      tx3 = makeTx([byte 0x03])
      tx4 = makeTx([byte 0x04])
      tx5 = makeTx([byte 0x05])

    store.process_inclusion_list(
      makeInclusionList(slot, 6, dependentRoot, [tx1, tx2]), timely = true)
    store.process_inclusion_list(
      makeInclusionList(slot, 7, dependentRoot, [tx2, tx3]), timely = true)
    store.process_inclusion_list(
      makeInclusionList(slot, 8, dependentRoot, [tx4]), timely = false)
    store.process_inclusion_list(
      makeInclusionList(slot, 9, dependentRoot, [tx5]), timely = true)
    store.process_inclusion_list(
      makeInclusionList(slot, 9, dependentRoot, [tx1]), timely = true)

    let timely = store.get_inclusion_list_transactions(slot, dependentRoot)
    check:
      timely.len == 3
      tx1 in timely
      tx2 in timely
      tx3 in timely

    let all = store.get_inclusion_list_transactions(
      slot, dependentRoot, only_timely = false)
    check:
      all.len == 4
      tx4 in all
      tx5 notin all

    check:
      store.get_inclusion_list_transactions(slot, ZERO_HASH).len == 0
      store.get_inclusion_list_transactions(slot + 1, dependentRoot).len == 0

  test "get_inclusion_list_bits and is_inclusion_list_bits_inclusive":
    var store: InclusionListStore
    store.process_inclusion_list(
      makeInclusionList(slot, committee[0], dependentRoot, [makeTx([byte 1])]),
      timely = true)
    store.process_inclusion_list(
      makeInclusionList(slot, committee[1], dependentRoot, [makeTx([byte 2])]),
      timely = false)

    let
      timelyBits = store.get_inclusion_list_bits(
        committee, slot, dependentRoot)
      allBits = store.get_inclusion_list_bits(
        committee, slot, dependentRoot, only_timely = false)
    for i, validator_index in committee:
      check:
        timelyBits[i] == (validator_index == committee[0])
        allBits[i] == (validator_index in [committee[0], committee[1]])

    check:
      store.is_inclusion_list_bits_inclusive(
        committee, slot, dependentRoot, timelyBits)
      store.is_inclusion_list_bits_inclusive(
        committee, slot, dependentRoot, allBits, only_timely = false)
      not store.is_inclusion_list_bits_inclusive(
        committee, slot, dependentRoot, timelyBits, only_timely = false)
      store.is_inclusion_list_bits_inclusive(
        committee, slot, ZERO_HASH, default(InclusionListBits))

  test "end-to-end: committee members sign, validate, and are collected":
    var
      store: InclusionListStore
      distinctMembers: HashSet[uint64]

    for member in committee:
      let mi = member.uint64
      var signed = makeInclusionList(
        slot, mi, dependentRoot, [makeTx([byte (mi shr 8), byte mi])])
      signed.signature = get_inclusion_list_signature(
        state[].fork, state[].genesis_validators_root, signed.message,
        MockPrivKeys[member]).toValidatorSig
      check is_valid_inclusion_list_signature(state[], signed)

      store.process_inclusion_list(signed, timely = true)
      distinctMembers.incl mi

    check:
      key notin store.equivocators
      store.get_inclusion_list_transactions(slot, dependentRoot).len ==
        distinctMembers.len

# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# EIP-7805 (FOCIL) inclusion list store and helpers
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md

{.push raises: [], gcsafe.}

import
  std/[sets, tables],
  ./datatypes/[base, bellatrix, gloas, heze],
  ./[beaconstate, eth2_merkleization]

export base, bellatrix, gloas, heze

type
  InclusionListKey* = (Slot, Eth2Digest)

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md#inclusionlistentry
  InclusionListEntry* = object
    signed_inclusion_list*: SignedInclusionList
    timely*: bool

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md#inclusionliststore
  InclusionListStore* = object
    inclusion_lists*: Table[InclusionListKey, Table[uint64, InclusionListEntry]]
    equivocators*: Table[InclusionListKey, HashSet[uint64]]

  InclusionListCommittee* = array[int INCLUSION_LIST_COMMITTEE_SIZE, uint64]

func isEquivocator*(
    store: InclusionListStore, key: InclusionListKey,
    validator_index: uint64): bool =
  store.equivocators.withValue(key, equivocators):
    return validator_index in equivocators
  false

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md#new-process_inclusion_list
func process_inclusion_list*(
    store: var InclusionListStore,
    signed_inclusion_list: SignedInclusionList, timely: bool) =
  template inclusion_list: untyped = signed_inclusion_list.message
  let
    key = (inclusion_list.slot, inclusion_list.dependent_root)
    validator_index = inclusion_list.validator_index
    lists = addr store.inclusion_lists.mgetOrPut(
      key, default(Table[uint64, InclusionListEntry]))

  lists[].withValue(validator_index, stored):
    if stored.signed_inclusion_list.message != inclusion_list:
      store.equivocators.mgetOrPut(key, default(HashSet[uint64])).incl(
        validator_index)
    return

  lists[][validator_index] = InclusionListEntry(
    signed_inclusion_list: signed_inclusion_list, timely: timely)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md#new-get_inclusion_list_transactions
func get_inclusion_list_transactions*(
    store: InclusionListStore, slot: Slot, dependent_root: Eth2Digest,
    only_timely = true): seq[gloas.Transaction] =
  let key = (slot, dependent_root)
  var
    transactions: seq[gloas.Transaction]
    seen: HashSet[Eth2Digest]

  store.inclusion_lists.withValue(key, lists):
    for validator_index, entry in lists:
      if store.isEquivocator(key, validator_index):
        continue
      if only_timely and not entry.timely:
        continue
      for transaction in entry.signed_inclusion_list.message.transactions:
        if not seen.containsOrIncl(hash_tree_root(transaction)):
          transactions.add transaction

  transactions

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md#new-get_inclusion_list_bits
func get_inclusion_list_bits*(
    store: InclusionListStore, committee: InclusionListCommittee, slot: Slot,
    dependent_root: Eth2Digest, only_timely = true): InclusionListBits =
  let key = (slot, dependent_root)
  var res: InclusionListBits

  store.inclusion_lists.withValue(key, lists):
    for i, validator_index in committee:
      lists.withValue(validator_index, entry):
        if not store.isEquivocator(key, validator_index) and
            (not only_timely or entry.timely):
          res.setBit(i)

  res

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/inclusion-list.md#new-is_inclusion_list_bits_inclusive
func is_inclusion_list_bits_inclusive*(
    store: InclusionListStore, committee: InclusionListCommittee, slot: Slot,
    dependent_root: Eth2Digest, inclusion_list_bits: InclusionListBits,
    only_timely = true): bool =
  store.get_inclusion_list_bits(
    committee, slot, dependent_root, only_timely).isSubsetOf(
      inclusion_list_bits)

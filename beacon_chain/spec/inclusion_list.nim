# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# EIP-7805 (FOCIL) inclusion list store and helpers
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/inclusion-list.md

{.push raises: [], gcsafe.}

import
  std/[sets, tables],
  ./datatypes/[base, bellatrix, gloas, heze],
  ./[beaconstate, eth2_merkleization]

export base, bellatrix, gloas, heze

type
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/inclusion-list.md#inclusionliststore
  InclusionListStore* = object
    inclusion_lists*: Table[Eth2Digest, Table[Eth2Digest, InclusionList]]
    inclusion_list_timeliness*: Table[Eth2Digest, bool]
    equivocators*: Table[Eth2Digest, HashSet[uint64]]

const
  emptyInclusionLists = default(Table[Eth2Digest, InclusionList])
  emptyEquivocators = default(HashSet[uint64])

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/inclusion-list.md#new-process_inclusion_list
func process_inclusion_list*(
    store: var InclusionListStore,
    inclusion_list: InclusionList,
    is_timely: bool) =
  let
    key = inclusion_list.inclusion_list_committee_root
    validator_index = inclusion_list.validator_index

  store.equivocators.withValue(key, equivocators):
    if validator_index in equivocators[]:
      return

  store.inclusion_lists.withValue(key, lists):
    for stored in lists[].values:
      if stored.validator_index != validator_index:
        continue
      if stored != inclusion_list:
        store.equivocators.mgetOrPut(key, emptyEquivocators).incl(validator_index)
      return

  let inclusion_list_root = hash_tree_root(inclusion_list)
  store.inclusion_lists.mgetOrPut(key, emptyInclusionLists)[
    inclusion_list_root] = inclusion_list
  store.inclusion_list_timeliness[inclusion_list_root] = is_timely

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/inclusion-list.md#new-get_inclusion_list_transactions
func get_inclusion_list_transactions*(
    store: InclusionListStore,
    state: heze.BeaconState,
    slot: Slot,
    cache: var StateCache,
    only_timely = true): seq[gloas.Transaction] =
  let
    committee = get_inclusion_list_committee(state, slot, cache)
    key = hash_tree_root(committee)

  var
    transactions: seq[gloas.Transaction]
    seen: HashSet[Eth2Digest]

  let equivocators = store.equivocators.getOrDefault(key)
  # `[]` raises KeyError; iterate by `pairs` to stay within `raises: []`.
  for committee_root, lists in store.inclusion_lists:
    if committee_root != key:
      continue
    for il_root, il in lists:
      if il.validator_index in equivocators:
        continue
      if only_timely and
          not store.inclusion_list_timeliness.getOrDefault(il_root):
        continue
      for transaction in il.transactions:
        if not seen.containsOrIncl(hash_tree_root(transaction)):
          transactions.add transaction

  transactions

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/heze/inclusion-list.md#new-get_inclusion_list_bits
func get_inclusion_list_bits(
    store: InclusionListStore,
    state: heze.BeaconState,
    slot: Slot,
    cache: var StateCache,
    only_timely = true): InclusionListBits =
  ## Return a ``BitArray`` over inclusion list committee indices with bits set
  ## for those who provided valid, non-equivocating inclusion lists for the
  ## given ``slot``.
  let
    committee = get_inclusion_list_committee(state, slot, cache)
    key = hash_tree_root(committee)

  template inclusion_lists: Table[Eth2Digest, InclusionList] =
    store.inclusion_lists.getOrDefault(key)
  let equivocators =
    store.equivocators.getOrDefault(key)
  template timeliness: Table[Eth2Digest, bool] =
    store.inclusion_list_timeliness


  var validator_indices: HashSet[uint64]
  for inclusion_list_root, inclusion_list in inclusion_lists:
    if inclusion_list.validator_index notin equivocators and
        (not only_timely or timeliness.getOrDefault(inclusion_list_root)):
      validator_indices.incl inclusion_list.validator_index

  var res: InclusionListBits
  for i, validator_index in committee:
    if validator_index in validator_indices:
      res.setBit(i)
  res

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/heze/inclusion-list.md#new-is_inclusion_list_bits_inclusive
func is_inclusion_list_bits_inclusive*(
    store: InclusionListStore,
    state: heze.BeaconState,
    slot: Slot,
    inclusion_list_bits: InclusionListBits,
    cache: var StateCache,
    only_timely = true): bool =
  ## Return ``true`` if and only if ``inclusion_list_bits`` has a bit set for
  ## every bit set in the local inclusion list bits for the given ``slot``.
  let local_inclusion_list_bits =
    get_inclusion_list_bits(store, state, slot, cache, only_timely)

  local_inclusion_list_bits.isSubsetOf(inclusion_list_bits)

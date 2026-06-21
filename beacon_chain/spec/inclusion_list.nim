# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# EIP-7805 (FOCIL) inclusion list store and helpers
# https://github.com/ethereum/consensus-specs/blob/master/specs/heze/inclusion-list.md

{.push raises: [], gcsafe.}

import
  std/[sets, tables],
  ./datatypes/[base, bellatrix, heze],
  ./[beaconstate, eth2_merkleization]

export base, bellatrix, heze

type
  InclusionListStore* = object
    ## Store of received inclusion lists for the current slot, keyed by the
    ## inclusion list committee root. Mirrors the spec `InclusionListStore`.
    inclusion_lists*: Table[Eth2Digest, Table[Eth2Digest, InclusionList]]
      ## committee_root -> (inclusion_list_root -> InclusionList)
    inclusion_list_timeliness*: Table[Eth2Digest, bool]
      ## inclusion_list_root -> whether it arrived before the IL deadline
    equivocators*: Table[Eth2Digest, HashSet[uint64]]
      ## committee_root -> validator indices observed to equivocate

# https://github.com/ethereum/consensus-specs/blob/master/specs/heze/inclusion-list.md#process_inclusion_list
func process_inclusion_list*(
    store: var InclusionListStore,
    inclusion_list: InclusionList,
    is_timely: bool) =
  ## Store ``inclusion_list`` and its timeliness, detecting equivocations
  ## (conflicting lists from the same committee member).
  let
    key = inclusion_list.inclusion_list_committee_root
    validator_index = inclusion_list.validator_index

  # Already a known equivocator for this committee: ignore.
  store.equivocators.withValue(key, equivocators):
    if validator_index in equivocators[]:
      return

  # A list from this validator was already stored: either it is identical (a
  # duplicate, ignore) or it conflicts (mark the validator as an equivocator).
  store.inclusion_lists.withValue(key, lists):
    for stored in lists[].values:
      if stored.validator_index != validator_index:
        continue
      if stored != inclusion_list:
        store.equivocators.mgetOrPut(
          key, default(HashSet[uint64])).incl(validator_index)
      return

  # First list seen from this validator for this committee: record it.
  let inclusion_list_root = hash_tree_root(inclusion_list)
  store.inclusion_lists.mgetOrPut(
    key, default(Table[Eth2Digest, InclusionList]))[
      inclusion_list_root] = inclusion_list
  store.inclusion_list_timeliness[inclusion_list_root] = is_timely

# https://github.com/ethereum/consensus-specs/blob/master/specs/heze/inclusion-list.md#get_inclusion_list_transactions
func get_inclusion_list_transactions*(
    store: InclusionListStore,
    state: heze.BeaconState,
    slot: Slot,
    cache: var StateCache,
    only_timely = true): seq[bellatrix.Transaction] =
  ## Return the unique transactions from all valid, non-equivocating inclusion
  ## lists matching this slot's committee root, optionally filtered to timely
  ## lists only.
  let
    committee = get_inclusion_list_committee(state, slot, cache)
    key = compute_inclusion_list_committee_root(committee)

  var
    transactions: seq[bellatrix.Transaction]
    seen: HashSet[Eth2Digest]

  let equivocators = store.equivocators.getOrDefault(key)
  # Iterate by `pairs` (non-raising); the outer table holds one entry per
  # committee root, so this matches at most a single committee.
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
        # Spec dedups with `set(transactions)`; dedup by transaction root.
        if not seen.containsOrIncl(hash_tree_root(transaction)):
          transactions.add transaction

  transactions

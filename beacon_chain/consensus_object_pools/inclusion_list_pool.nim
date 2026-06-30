# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[sequtils, sets, tables],
  chronicles,
  ../spec/[eth2_merkleization, inclusion_list],
  ./blockchain_dag,
  ../beacon_clock

logScope: topics = "ilpool"

const
  # An inclusion list is only relevant for its own slot; keep a small margin
  # before pruning, matching `PayloadAttestationPool`.
  IL_RETAIN_SLOTS = 2

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/p2p-interface.md
  # Gossip accepts at most the first two valid inclusion lists from a given
  # validator (so a single equivocation can still be propagated).
  MAX_INCLUSION_LISTS_PER_VALIDATOR = 2

  emptySeenSet = default(HashSet[Eth2Digest])
  emptySeenValidators = default(Table[uint64, HashSet[Eth2Digest]])
  emptyInclusionListStore = default(InclusionListStore)

type
  InclusionListPool* = object
    ## Node-level wrapper around the spec `InclusionListStore` (EIP-7805 /
    ## FOCIL). The spec store is keyed by inclusion-list committee root; here it
    ## is additionally bucketed per slot so that stale slots can be pruned.
    dag: ChainDAGRef
    stores: Table[Slot, InclusionListStore]
    # Distinct inclusion lists already seen per (slot, validator), used to
    # enforce the gossip "first or second valid message" bound.
    seen: Table[Slot, Table[uint64, HashSet[Eth2Digest]]]

func init*(T: type InclusionListPool, dag: ChainDAGRef): T =
  T(dag: dag)

func pruneOldEntries(pool: var InclusionListPool, wallTime: BeaconTime) =
  let current_slot = wallTime.slotOrZero(pool.dag.timeParams)

  # keep only recent slots - an inclusion list is only valid for its own slot
  let slotsToRemove = toSeq(pool.stores.keys).filterIt(
    it + IL_RETAIN_SLOTS < current_slot)

  for slot in slotsToRemove:
    pool.stores.del(slot)
    pool.seen.del(slot)

func numSeen*(
    pool: InclusionListPool, slot: Slot, validator_index: uint64): int =
  ## Number of distinct inclusion lists already accepted from `validator_index`
  ## for `slot`. Gossip validation uses this to enforce the per-validator bound.
  pool.seen.getOrDefault(slot, emptySeenValidators).getOrDefault(
    validator_index, emptySeenSet).len

func addInclusionList*(
    pool: var InclusionListPool, inclusion_list: InclusionList,
    is_timely: bool, wallTime: BeaconTime): bool =
  ## Record a (already validated) inclusion list into the per-slot store.
  ##
  ## Returns true if it was newly processed, false if it was a byte-identical
  ## resubmission or exceeded the per-validator bound of two distinct messages.
  pool.pruneOldEntries(wallTime)

  let
    slot = inclusion_list.slot
    validator_index = inclusion_list.validator_index
    il_root = hash_tree_root(inclusion_list)
    roots = addr pool.seen.mgetOrPut(slot).mgetOrPut(
      validator_index, emptySeenSet)

  # A byte-identical resubmission is a no-op, and the third distinct list from a
  # validator is dropped (the first two already cover any equivocation).
  if roots[].len >= MAX_INCLUSION_LISTS_PER_VALIDATOR or il_root in roots[]:
    return false

  roots[].incl il_root
  pool.stores.mgetOrPut(slot, emptyInclusionListStore).process_inclusion_list(
    inclusion_list, is_timely)

  true

func getInclusionListTransactions*(
    pool: InclusionListPool, state: heze.BeaconState, slot: Slot,
    cache: var StateCache, only_timely: bool): seq[bellatrix.Transaction] =
  ## Transactions a proposer must include for `slot`, drawn from the valid,
  ## non-equivocating inclusion lists collected for that slot's committee.
  pool.stores.getOrDefault(slot, emptyInclusionListStore).
    get_inclusion_list_transactions(state, slot, cache, only_timely)

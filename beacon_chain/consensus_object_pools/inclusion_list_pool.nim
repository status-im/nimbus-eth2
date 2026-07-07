# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
<<<<<<< HEAD
  std/[sequtils, tables],
=======
  std/[sets, tables],
>>>>>>> 48a392df9 (reviews)
  chronicles,
  ../spec/[eth2_ssz_serialization, inclusion_list],
  ../beacon_clock

logScope: topics = "ilpool"

const
  # A payload at slot N is constrained by the inclusion lists of slot N-1: the
  # fork-choice `record_payload_inclusion_list_satisfaction` reads
  # `get_inclusion_list_transactions(store, state, Slot(state.slot - 1))`. So an
  # inclusion list for slot S is consumed when processing a block/payload at
  # slot S+1, and - since the ePBS payload is revealed late in the slot and a
  # node may lag - as late as wall slot S+2. Pruning drops slot S once
  # `S + IL_RETAIN_SLOTS < current_slot`, so 2 retains S through S+2, the last
  # slot it can still be needed. (`InclusionListByCommitteeIndices` serving adds
  # no tighter bound: the spec sets no request slot-range.)
  IL_RETAIN_SLOTS = 2

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/specs/heze/p2p-interface.md#new-inclusion_list
  # [IGNORE] The `message` is either the first or second valid message
  # received from the validator with index `message.validator_index`.
  MAX_INCLUSION_LISTS_PER_VALIDATOR = 2

  emptySeenRoots = default(seq[Eth2Digest])
  emptyInclusionListStore = default(InclusionListStore)

type
  InclusionListPool* = object
    ## Node-level wrapper around the spec `InclusionListStore` (EIP-7805 /
    ## FOCIL). The spec store is keyed by inclusion-list committee root; here it
    ## is additionally bucketed per slot so that stale slots can be pruned.
    timeParams: TimeParams
    stores: Table[Slot, InclusionListStore]
    # Distinct inclusion lists already seen per (slot, validator), used to
    # enforce the gossip "first or second valid message" bound.
    seen: Table[(Slot, uint64), seq[Eth2Digest]]

func init*(T: type InclusionListPool, timeParams: TimeParams): T =
  T(timeParams: timeParams)

func pruneOldEntries(pool: var InclusionListPool, wallTime: BeaconTime) =
  let current_slot = wallTime.slotOrZero(pool.timeParams)

  # collect only the stale slots (a table can't be mutated while iterating),
  # rather than copying every key
  var slotsToRemove: seq[Slot]
  for slot in pool.stores.keys:
    if slot + IL_RETAIN_SLOTS < current_slot:
      slotsToRemove.add slot

  for key in toSeq(pool.seen.keys):
    if key[0] + IL_RETAIN_SLOTS < current_slot:
      pool.seen.del(key)

func numSeen*(
    pool: InclusionListPool, slot: Slot, validator_index: uint64): int =
  ## Number of distinct inclusion lists already accepted from `validator_index`
  ## for `slot`. Gossip validation uses this to enforce the per-validator bound.
  pool.seen.getOrDefault((slot, validator_index), emptySeenRoots).len

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
    roots = addr pool.seen.mgetOrPut(
      (slot, validator_index),
      newSeqOfCap[Eth2Digest](MAX_INCLUSION_LISTS_PER_VALIDATOR))

  # The first two distinct lists from a validator already cover any equivocation;
  # drop any further ones before spending a hash on them.
  if roots[].len >= MAX_INCLUSION_LISTS_PER_VALIDATOR:
    return false

  # A byte-identical resubmission is a no-op. A plain digest of the SSZ bytes
  # suffices to detect duplicates; the canonical `hash_tree_root` is needlessly
  # slower here.
  let il_digest = eth2digest(SSZ.encode(inclusion_list))
  if il_digest in roots[]:
    return false

  roots[].add il_digest
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

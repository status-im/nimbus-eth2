# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[sets, tables],
  chronicles,
  ../spec/inclusion_list,
  ../beacon_clock,
  ./blockchain_dag

logScope: topics = "ilpool"

const
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/p2p-interface.md#configs
  MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS* = 1

  # Lookback slots, the current slot and the next slot within gossip clock
  # disparity. Buckets are indexed by `slot mod IL_WINDOW`.
  IL_WINDOW = MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS + 2

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/p2p-interface.md#new-inclusion_list
  MAX_INCLUSION_LISTS_PER_VALIDATOR* = 2

type
  IlBucket = object
    slot: Slot
    store: InclusionListStore
    # Distinct lists accepted per validator, for the gossip per-validator bound
    seen: Table[uint64, seq[InclusionList]]

  InclusionListPool* = object
    ## Spec `InclusionListStore`, split into a ring of per-slot buckets
    timeParams: TimeParams
    buckets: array[IL_WINDOW, IlBucket]

const emptySeen = default(seq[InclusionList])

func init*(T: type InclusionListPool, timeParams: TimeParams): T =
  T(timeParams: timeParams)

func bucketIdx(slot: Slot): int =
  int(uint64(slot) mod uint64(IL_WINDOW))

func numSeen*(
    pool: InclusionListPool, slot: Slot, validator_index: uint64): int =
  ## Number of distinct lists accepted from `validator_index` for `slot`
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return 0
  pool.buckets[idx].seen.getOrDefault(validator_index, emptySeen).len

func addInclusionList*(
    pool: var InclusionListPool,
    signed_inclusion_list: SignedInclusionList,
    is_timely: bool, wallTime: BeaconTime): bool =
  ## Record an already-validated list. Returns false for duplicates, lists
  ## over the per-validator bound and slots outside the live window.
  template inclusion_list: untyped = signed_inclusion_list.message

  let
    current_slot = wallTime.slotOrZero(pool.timeParams)
    latest_slot = (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(
      pool.timeParams)
    slot = inclusion_list.slot
    validator_index = inclusion_list.validator_index

  for bucket in pool.buckets.mitems:
    if bucket.slot + MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS < current_slot:
      reset(bucket)

  if slot > latest_slot or
      slot + MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS < current_slot:
    return false

  let bucket = addr pool.buckets[bucketIdx(slot)]
  if bucket.slot != slot:
    bucket[] = IlBucket(slot: slot)

  let seen = addr bucket.seen.mgetOrPut(
    validator_index,
    newSeqOfCap[InclusionList](MAX_INCLUSION_LISTS_PER_VALIDATOR))

  if seen[].len >= MAX_INCLUSION_LISTS_PER_VALIDATOR or
      inclusion_list in seen[]:
    return false

  seen[].add inclusion_list
  bucket.store.process_inclusion_list(signed_inclusion_list, is_timely)

  true

func getInclusionListTransactions*(
    pool: InclusionListPool, slot: Slot, dependent_root: Eth2Digest,
    only_timely: bool): seq[gloas.Transaction] =
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return
  pool.buckets[idx].store.get_inclusion_list_transactions(
    slot, dependent_root, only_timely)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/p2p-interface.md#inclusionlistsbyindices-v1
func getInclusionLists*(
    pool: InclusionListPool, slot: Slot, dependent_root: Eth2Digest,
    validator_indices: openArray[uint64],
    maxLists: int): seq[SignedInclusionList] =
  ## Lists held for the requested validators, skipping equivocators and
  ## serving each validator at most once
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return

  template store: untyped = pool.buckets[idx].store
  let key = (slot, dependent_root)

  var
    res = newSeqOfCap[SignedInclusionList](min(maxLists, validator_indices.len))
    served: HashSet[uint64]

  store.inclusion_lists.withValue(key, lists):
    for validator_index in validator_indices:
      if res.len >= maxLists:
        break
      if served.containsOrIncl(validator_index) or
          store.isEquivocator(key, validator_index):
        continue
      lists.withValue(validator_index, entry):
        res.add entry.signed_inclusion_list

  res

func isInclusionListBitsInclusive*(
    pool: InclusionListPool, slot: Slot, dependent_root: Eth2Digest,
    committee: InclusionListCommittee, inclusion_list_bits: InclusionListBits,
    only_timely: bool): bool =
  ## With nothing collected for `slot`, any bits are trivially inclusive
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return true
  pool.buckets[idx].store.is_inclusion_list_bits_inclusive(
    committee, slot, dependent_root, inclusion_list_bits, only_timely)

proc getPayloadInclusionListTransactions*(
    pool: InclusionListPool, dag: ChainDAGRef, blck: BlockRef):
    Opt[seq[gloas.Transaction]] =
  ## Transactions the payload of `blck` must include, from the previous slot's
  ## lists on `blck`'s branch.
  ## `Opt.none` if the dependent root cannot be resolved, as opposed to an empty
  ## sequence, which every payload trivially satisfies.
  if blck.slot <= GENESIS_SLOT:
    return Opt.none(seq[gloas.Transaction])
  let
    slot = blck.slot - 1
    dependent_root = dag.get_shuffling_dependent_root(
        blck.bid, slot.epoch).valueOr:
      return Opt.none(seq[gloas.Transaction])

  Opt.some pool.getInclusionListTransactions(
    slot, dependent_root, only_timely = true)

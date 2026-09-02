# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  chronicles,
  ../spec/[eth2_ssz_serialization, inclusion_list],
  ../beacon_clock

logScope: topics = "ilpool"

const
  # https://github.com/ethereum/consensus-specs/pull/5462
  # An inclusion list for slot N constrains the block at slot N+1 and is used by
  # that slot's proposer and attesters, so a list for slot N stays live through
  # slot N+1. This is the spec lookback depth: at `current_slot`, lists from
  # `[current_slot - MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS, current_slot]` must
  # remain available (serving `InclusionListsByIndices` uses the same bound).
  MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS = 1

  # Live slots: `current_slot` plus the lookback behind it. This bounds the ring
  # array `buckets`, so it must stay a compile-time constant - not a RuntimeConfig
  # field. Buckets are indexed by `slot mod IL_WINDOW`; a slot leaving the window
  # is dropped when its index is reused or evicted on the next add.
  IL_WINDOW = MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS + 1

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/heze/p2p-interface.md#new-inclusion_list
  # [IGNORE] The `message` is either the first or second valid message
  # received from the validator with index `message.validator_index`.
  MAX_INCLUSION_LISTS_PER_VALIDATOR* = 2

  emptySeenRoots = default(seq[Eth2Digest])

type
  IlBucket = object
    slot: Slot
    store: InclusionListStore
    # Distinct inclusion lists already seen per validator, enforcing the gossip
    # "first or second valid message" bound.
    seen: Table[uint64, seq[Eth2Digest]]

  InclusionListPool* = object
    ## Node-level wrapper around the spec `InclusionListStore` (EIP-7805 /
    ## FOCIL). The spec store is keyed by inclusion-list committee root; here it
    ## is bucketed into a fixed ring of the `IL_WINDOW` live slots. The pool
    ## tracks a single (canonical) view, not competing forks: within this window
    ## the inclusion-list committee is seed-frozen and identical across forks, so
    ## a branch-specific slice is recovered at read time from the caller's state.
    timeParams: TimeParams
    buckets: array[IL_WINDOW, IlBucket]

func init*(T: type InclusionListPool, timeParams: TimeParams): T =
  T(timeParams: timeParams)

func bucketIdx(slot: Slot): int =
  int(uint64(slot) mod uint64(IL_WINDOW))

func numSeen*(
    pool: InclusionListPool, slot: Slot, validator_index: uint64): int =
  ## Number of distinct inclusion lists already accepted from `validator_index`
  ## for `slot`. Gossip validation uses this to enforce the per-validator bound.
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return 0
  pool.buckets[idx].seen.getOrDefault(validator_index, emptySeenRoots).len

func addInclusionList*(
    pool: var InclusionListPool, inclusion_list: InclusionList,
    is_timely: bool, wallTime: BeaconTime): bool =
  ## Record an (already validated) inclusion list into its slot's bucket.
  ##
  ## Returns true if it was newly processed, false if it was a byte-identical
  ## resubmission, exceeded the per-validator bound of two distinct messages, or
  ## fell outside the live window.
  let
    current_slot = wallTime.slotOrZero(pool.timeParams)
    slot = inclusion_list.slot
    validator_index = inclusion_list.validator_index

  # Drop buckets that have fallen out of the live window (bounded: `IL_WINDOW`).
  for bucket in pool.buckets.mitems:
    if bucket.slot + MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS < current_slot:
      reset(bucket)

  # Only the live window maps to a bucket; an out-of-window slot would otherwise
  # clobber a live one through the ring aliasing.
  if slot > current_slot or slot + MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS < current_slot:
    return false

  let bucket = addr pool.buckets[bucketIdx(slot)]
  if bucket.slot != slot:
    bucket[] = IlBucket(slot: slot)

  let roots = addr bucket.seen.mgetOrPut(
    validator_index, newSeqOfCap[Eth2Digest](MAX_INCLUSION_LISTS_PER_VALIDATOR))

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
  bucket.store.process_inclusion_list(inclusion_list, is_timely)

  true

func getInclusionListTransactions*(
    pool: InclusionListPool, slot: Slot, committee: InclusionListCommittee,
    only_timely: bool): seq[gloas.Transaction] =
  ## Transactions a proposer must include for `slot`, drawn from the valid,
  ## non-equivocating inclusion lists collected for that slot's committee.
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return
  pool.buckets[idx].store.get_inclusion_list_transactions(
    committee, only_timely)

func isInclusionListBitsInclusive*(
    pool: InclusionListPool, slot: Slot, committee: InclusionListCommittee,
    inclusion_list_bits: InclusionListBits, only_timely: bool): bool =
  ## Whether `inclusion_list_bits` covers every inclusion list this node has
  ## collected for `slot`. With nothing collected the local bits are empty, so
  ## any bits trivially satisfy this.
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return true
  pool.buckets[idx].store.is_inclusion_list_bits_inclusive(
    committee, inclusion_list_bits, only_timely)

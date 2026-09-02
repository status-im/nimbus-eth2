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
  ../beacon_clock

logScope: topics = "ilpool"

const
  # https://github.com/ethereum/consensus-specs/pull/5462
  # An inclusion list for slot N constrains the block at slot N+1 and is used by
  # that slot's proposer and attesters, so a list for slot N stays live through
  # slot N+1. This is the spec lookback depth: at `current_slot`, lists from
  # `[current_slot - MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS, current_slot]` must
  # remain available (serving `InclusionListsByIndices` uses the same bound).
  MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS* = 1

  # Live slots: `current_slot` plus the lookback behind it. This bounds the ring
  # array `buckets`, so it must stay a compile-time constant - not a RuntimeConfig
  # field. Buckets are indexed by `slot mod IL_WINDOW`; a slot leaving the window
  # is dropped when its index is reused or evicted on the next add.
  IL_WINDOW = MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS + 1

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/heze/p2p-interface.md#new-inclusion_list
  # [IGNORE] The `message` is either the first or second valid message
  # received from the validator with index `message.validator_index`.
  MAX_INCLUSION_LISTS_PER_VALIDATOR* = 2

type
  SeenInclusionList = object
    signed: SignedInclusionList
      ## `InclusionListsByIndices` serves the signature back along with the
      ## message, so the signed form is what gets retained here.

  IlBucket = object
    slot: Slot
    store: InclusionListStore
    # Distinct inclusion lists already seen per validator, enforcing the gossip
    # "first or second valid message" bound.
    seen: Table[uint64, seq[SeenInclusionList]]

  InclusionListPool* = object
    ## Node-level wrapper around the spec `InclusionListStore` (EIP-7805 /
    ## FOCIL). The spec store is keyed by inclusion-list committee root; here it
    ## is bucketed into a fixed ring of the `IL_WINDOW` live slots. The pool
    ## tracks a single (canonical) view, not competing forks: within this window
    ## the inclusion-list committee is seed-frozen and identical across forks, so
    ## a branch-specific slice is recovered at read time from the caller's state.
    timeParams: TimeParams
    buckets: array[IL_WINDOW, IlBucket]

const emptySeen = default(seq[SeenInclusionList])

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
  pool.buckets[idx].seen.getOrDefault(validator_index, emptySeen).len

func addInclusionList*(
    pool: var InclusionListPool,
    signed_inclusion_list: SignedInclusionList,
    is_timely: bool, wallTime: BeaconTime): bool =
  ## Record an (already validated) inclusion list into its slot's bucket.
  ##
  ## Returns true if it was newly processed, false if it repeats a message
  ## already held, exceeded the per-validator bound of two distinct messages, or
  ## fell outside the live window.
  template inclusion_list: untyped = signed_inclusion_list.message

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

  let seen = addr bucket.seen.mgetOrPut(
    validator_index,
    newSeqOfCap[SeenInclusionList](MAX_INCLUSION_LISTS_PER_VALIDATOR))

  # The first two distinct lists from a validator already cover any equivocation;
  # drop any further ones before comparing against what is held.
  if seen[].len >= MAX_INCLUSION_LISTS_PER_VALIDATOR:
    return false

  # Resubmitting a message already held is a no-op.
  for entry in seen[]:
    if entry.signed.message == inclusion_list:
      return false

  seen[].add SeenInclusionList(signed: signed_inclusion_list)
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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/heze/p2p-interface.md#inclusionlistsbyindices-v1
func getInclusionLists*(
    pool: InclusionListPool, slot: Slot,
    inclusion_list_committee_root: Eth2Digest,
    validator_indices: openArray[uint64],
    maxLists: int): seq[SignedInclusionList] =
  ## Inclusion lists held for `slot` by the validators at the requested
  ## committee positions. Everything here has already passed gossip validation.
  ## Timeliness is not consulted: it is a fork choice notion, not one of the
  ## gossip validation rules, so untimely lists are served too.
  let idx = bucketIdx(slot)
  if pool.buckets[idx].slot != slot:
    return

  template bucket: untyped = pool.buckets[idx]

  # Clients SHOULD NOT respond with inclusion lists from equivocators for the
  # requested `slot` and `inclusion_list_committee_root`.
  let equivocators =
    bucket.store.equivocators.getOrDefault(inclusion_list_committee_root)

  # A small committee cycles its members to fill `INCLUSION_LIST_COMMITTEE_SIZE`,
  # so one validator can occupy several requested positions - serve it once.
  var
    res = newSeqOfCap[SignedInclusionList](min(maxLists, validator_indices.len))
    served: HashSet[uint64]

  for validator_index in validator_indices:
    if res.len >= maxLists:
      break
    if validator_index in equivocators:
      continue
    if served.containsOrIncl(validator_index):
      continue

    for entry in bucket.seen.getOrDefault(validator_index, emptySeen):
      # A non-equivocator has at most one list here, collected under this node's
      # committee view - skip it if that isn't the committee being asked about.
      if entry.signed.message.inclusion_list_committee_root ==
          inclusion_list_committee_root:
        res.add entry.signed
        break

  res

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

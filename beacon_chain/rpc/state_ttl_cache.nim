# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronos, chronicles, ../spec/beaconstate, ../consensus_object_pools/blockchain_dag

type
  CacheEntry = ref object
    state: ref ForkedHashedBeaconState
    lastUsed: Moment

  # This is ref object because we need to capture it by
  # reference in the `scheduleEntryExpiration` function.
  StateTtlCache* = ref object
    entries: seq[CacheEntry]
    ttl: Duration

const slotDifferenceForCacheHit = 5 * SLOTS_PER_EPOCH

logScope:
  topics = "state_ttl_cache"

proc init*(T: type StateTtlCache, cacheSize: Natural, cacheTtl: Duration): T =
  doAssert cacheSize > 0

  StateTtlCache(entries: newSeq[CacheEntry](cacheSize), ttl: cacheTtl)

proc scheduleEntryExpiration(cache: StateTtlCache, entryIdx: int) =
  proc removeElement(arg: pointer) =
    if cache.entries[entryIdx] == nil:
      return
    let expirationTime = cache.entries[entryIdx].lastUsed + cache.ttl
    if expirationTime > Moment.now:
      return
    cache.entries[entryIdx] = nil
    debug "Cached REST state expired", index = entryIdx

  discard setTimer(Moment.now + cache.ttl, removeElement)

proc add*(cache: StateTtlCache, state: ref ForkedHashedBeaconState) =
  var
    now = Moment.now
    lruTime = now
    index = -1

  for i in 0 ..< cache.entries.len:
    if cache.entries[i] == nil:
      index = i
      break
    if cache.entries[i].lastUsed <= lruTime:
      index = i
      lruTime = cache.entries[i].lastUsed

  doAssert index != -1
  cache.entries[index] = CacheEntry(state: state, lastUsed: now)
  debug "Cached REST state added", index = index

  cache.scheduleEntryExpiration(index)

proc getClosestState*(
    cache: StateTtlCache, dag: ChainDAGRef, bsi: BlockSlotId
): ref ForkedHashedBeaconState =
  var
    bestSlotDifference = Slot.high
    index = -1

  for i in 0 ..< cache.entries.len:
    if cache.entries[i] == nil:
      continue

    let stateSlot = getStateField(cache.entries[i][].state[], slot)
    if stateSlot > bsi.slot:
      # We can use only states that can be advanced forward in time.
      continue

    let slotDifference = bsi.slot - stateSlot
    if slotDifference > slotDifferenceForCacheHit:
      # The state is too old to be useful as a rewind starting point.
      continue

    var cur = bsi
    for j in 0 ..< slotDifference:
      cur = dag.parentOrSlot(cur).valueOr:
        break

    if not cache.entries[i].state[].matches_block(cur.bid.root):
      # The cached state and the requested BlockSlot are at different branches
      # of history.
      continue

    if slotDifference < bestSlotDifference:
      bestSlotDifference = slotDifference.Slot
      index = i

  if index == -1:
    return nil

  cache.entries[index].lastUsed = Moment.now
  cache.scheduleEntryExpiration(index)

  return cache.entries[index].state

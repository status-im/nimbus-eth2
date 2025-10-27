# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/sets,
  chronicles,
  ../spec/[digest, forks, helpers],
  ../beacon_clock,
  ./blockchain_dag

logScope: topics = "bidpool"

type
  ExecutionPayloadBidPool* = object
    ## Pool for tracking execution payload bids received from builders
    ## Only stores the highest-value bid per (slot, parent_block_hash)
    dag*: ChainDAGRef
    highestBids*: Table[(Slot, Eth2Digest), SignedExecutionPayloadBid]
    seenBySlot*: Table[Slot, HashSet[uint64]]

func init*(
    T: type ExecutionPayloadBidPool,
    dag: ChainDAGRef): ExecutionPayloadBidPool =
  ExecutionPayloadBidPool(dag: dag)

proc addBid*(
    pool: var ExecutionPayloadBidPool,
    signedBid: SignedExecutionPayloadBid,
    wallTime: BeaconTime) =
  template bid: untyped = signedBid.message

  logScope:
    bid_slot = bid.slot
    builder_index = bid.builder_index
    bid_value = bid.value

  try:
    if bid.slot in pool.seenBySlot and
       bid.builder_index in pool.seenBySlot[bid.slot]:
      debug "Duplicate bid from builder, ignoring"
      return

    if bid.slot notin pool.seenBySlot:
      pool.seenBySlot[bid.slot] = initHashSet[uint64]()
    pool.seenBySlot[bid.slot].incl(bid.builder_index)

    debug "Bid marked as seen from builder"

    let parentKey = (bid.slot, bid.parent_block_hash)

    if parentKey in pool.highestBids:
      let currentHighest = pool.highestBids[parentKey]
      if bid.value > currentHighest.message.value:
        let previousValue = currentHighest.message.value
        pool.highestBids[parentKey] = signedBid
        debug "Updated highest bid for slot and parent",
          previous_value = previousValue,
          previous_builder = currentHighest.message.builder_index
      else:
        debug "Bid value not higher than current best, not storing",
          current_best = currentHighest.message.value
    else:
      pool.highestBids[parentKey] = signedBid
      debug "First bid for this slot and parent, storing"

  except KeyError:
    error "Unexpected KeyError in addBid",
      slot = bid.slot,
      builder_index = bid.builder_index

func getBidForSlotAndBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    builderIndex: uint64): Opt[SignedExecutionPayloadBid] =
  try:
    if (slot in pool.seenBySlot) and (builderIndex in pool.seenBySlot[slot]):
      for signedBid in pool.highestBids.values:
        if signedBid.message.slot == slot and
           signedBid.message.builder_index == builderIndex:
          return Opt.some(signedBid)
      return Opt.none(SignedExecutionPayloadBid)
    else:
      return Opt.none(SignedExecutionPayloadBid)
  except KeyError:
    return Opt.none(SignedExecutionPayloadBid)

func getHighestBidForSlotAndParent*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    parentBlockHash: Eth2Digest): Opt[SignedExecutionPayloadBid] =
  try:
    let key = (slot, parentBlockHash)
    if key in pool.highestBids:
      Opt.some(pool.highestBids[key])
    else:
      Opt.none(SignedExecutionPayloadBid)
  except KeyError:
    Opt.none(SignedExecutionPayloadBid)

func getBidForBlockRoot*(pool: ExecutionPayloadBidPool,
    blockRoot: Eth2Digest): Opt[SignedExecutionPayloadBid] =
  try:
    for signedBid in pool.highestBids.values:
      if signedBid.message.parent_block_root == blockRoot:
        return Opt.some(signedBid)
    return Opt.none(SignedExecutionPayloadBid)
  except KeyError:
    return Opt.none(SignedExecutionPayloadBid)

func hasBidForBlockRoot*(
    pool: ExecutionPayloadBidPool, blockRoot: Eth2Digest): bool =
  pool.getBidForBlockRoot(blockRoot).isSome()

func hasSeenBidFromBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot, builderIndex: uint64): bool =
  try:
    slot in pool.seenBySlot and builderIndex in pool.seenBySlot[slot]
  except KeyError:
    false

proc prune*(pool: var ExecutionPayloadBidPool, beforeSlot: Slot) =
  var
    removedHighest = 0
    removedSeenSlots = 0

  try:
    var toRemoveHighest: seq[(Slot, Eth2Digest)]
    for (slot, parent) in pool.highestBids.keys:
      if slot < beforeSlot:
        toRemoveHighest.add((slot, parent))

    for key in toRemoveHighest:
      pool.highestBids.del(key)
      inc removedHighest

    var toRemoveSeen: seq[Slot]
    for slot in pool.seenBySlot.keys:
      if slot < beforeSlot:
        toRemoveSeen.add(slot)

    for slot in toRemoveSeen:
      pool.seenBySlot.del(slot)
      inc removedSeenSlots

    if removedHighest > 0 or removedSeenSlots > 0:
      debug "Pruned old bids from pool",
        removed_highest_bids = removedHighest,
        removed_seen_slots = removedSeenSlots
  except KeyError:
    error "KeyError during bid pruning"

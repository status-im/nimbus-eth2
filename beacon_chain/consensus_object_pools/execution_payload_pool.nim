# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sets, tables],
  chronicles,
  ../spec/[digest, forks, helpers],
  ../beacon_clock,
  ./blockchain_dag

from std/sequtils import filterIt

logScope: topics = "bidpool"

type
  SlotBids* = object
    highestBids*: Table[Eth2Digest, SignedExecutionPayloadBid]
    seenBuilders*: HashSet[uint64]

  ExecutionPayloadBidPool* = object
    ## Pool for tracking execution payload bids received from builders
    ## Only stores the highest-value bid per (slot, parent_block_hash)
    dag*: ChainDAGRef
    slotBids*: Table[Slot, SlotBids]
    blockRootIndex*: Table[Eth2Digest, seq[(Slot, Eth2Digest)]]

func init*(
    T: type ExecutionPayloadBidPool,
    dag: ChainDAGRef): ExecutionPayloadBidPool =
  ExecutionPayloadBidPool(
    dag: dag,
    slotBids: initTable[Slot, SlotBids](),
    blockRootIndex: initTable[Eth2Digest, seq[(Slot, Eth2Digest)]]())

proc addBid*(
    pool: var ExecutionPayloadBidPool,
    signedBid: SignedExecutionPayloadBid,
    wallTime: BeaconTime) =
  template bid: untyped = signedBid.message

  logScope:
    bid_slot = bid.slot
    builder_index = bid.builder_index
    bid_value = bid.value

  let slotData = addr pool.slotBids.mgetOrPut(bid.slot, default(SlotBids))

  if bid.builder_index in slotData.seenBuilders:
    debug "Duplicate bid from builder, ignoring"
    return

  slotData.seenBuilders.incl(bid.builder_index)

  let currentBid = slotData.highestBids.getOrDefault(bid.parent_block_hash)
  if currentBid != default(SignedExecutionPayloadBid):
    if bid.value <= currentBid.message.value:
      debug "Bid value not higher than current best",
        current_best = currentBid.message.value
      return
    debug "Updated highest bid for slot and parent",
      previous_value = currentBid.message.value,
      previous_builder = currentBid.message.builder_index
  else:
    debug "First bid for this slot and parent"

  slotData.highestBids[bid.parent_block_hash] = signedBid

  pool.blockRootIndex.mgetOrPut(
    bid.parent_block_root, @[]).add((bid.slot, bid.parent_block_hash))

func getBidForSlotAndBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    builderIndex: uint64): Opt[SignedExecutionPayloadBid] =
  let slotData = pool.slotBids.getOrDefault(slot)

  for bid in slotData.highestBids.values:
    if bid.message.builder_index == builderIndex:
      return Opt.some(bid)
  Opt.none(SignedExecutionPayloadBid)

func getHighestBidForSlotAndParent*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    parentBlockHash: Eth2Digest): Opt[SignedExecutionPayloadBid] =
  let
    slotData = pool.slotBids.getOrDefault(slot)
    bid = slotData.highestBids.getOrDefault(parentBlockHash)
  if bid != default(SignedExecutionPayloadBid):
    Opt.some(bid)
  else:
    Opt.none(SignedExecutionPayloadBid)

func getBidForBlockRoot*(
    pool: ExecutionPayloadBidPool,
    blockRoot: Eth2Digest): Opt[SignedExecutionPayloadBid] =
  let references = pool.blockRootIndex.getOrDefault(blockRoot, @[])
  if references.len > 0:
    let (slot, parentHash) = references[0]
    return pool.getHighestBidForSlotAndParent(slot, parentHash)
  Opt.none(SignedExecutionPayloadBid)

func hasBidForBlockRoot*(
    pool: ExecutionPayloadBidPool, blockRoot: Eth2Digest): bool =
  pool.blockRootIndex.getOrDefault(blockRoot, @[]).len > 0

func hasSeenBidFromBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    builderIndex: uint64): bool =
  let slotData = pool.slotBids.getOrDefault(slot)
  builderIndex in slotData.seenBuilders

proc prune*(pool: var ExecutionPayloadBidPool, beforeSlot: Slot) =
  try:
    var slotsToRemove: seq[Slot]
    for slot in pool.slotBids.keys:
      if slot < beforeSlot:
        slotsToRemove.add(slot)

    for slot in slotsToRemove:
      if slot in pool.slotBids:
        for parentHash, bid in pool.slotBids[slot].highestBids:
          let blockRoot = bid.message.parent_block_root
          if blockRoot in pool.blockRootIndex:
            pool.blockRootIndex[blockRoot] =
              pool.blockRootIndex[blockRoot].filterIt(
                it != (slot, parentHash))
            if pool.blockRootIndex[blockRoot].len == 0:
              pool.blockRootIndex.del(blockRoot)

      pool.slotBids.del(slot)

  except KeyError:
    error "KeyError during bid pruning"

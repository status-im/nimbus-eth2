# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[sets, tables],
  chronicles,
  ../spec/[digest, forks, helpers],
  ../beacon_clock,
  ./blockchain_dag

logScope: topics = "bidpool"

type
  PayloadAvailability* {.pure.} = enum
    Timely
    Withheld

  BidKey = tuple
    parentBlockRoot: Eth2Digest
    payloadAvailability: PayloadAvailability

  SlotBids* = object
    highestBids*: Table[BidKey, gloas.SignedExecutionPayloadBid]
    seenBuilders*: HashSet[uint64]

  ExecutionPayloadBidPool* = object
    ## Pool for tracking execution payload bids received from builders.
    ## Only stores the highest-value bid per (slot, parentBlockRoot,
    ## payloadAvailability).
    dag*: ChainDAGRef
    slotBids*: Table[Slot, SlotBids]

func init*(
    T: type ExecutionPayloadBidPool,
    dag: ChainDAGRef): ExecutionPayloadBidPool =
  ExecutionPayloadBidPool(
    dag: dag,
    slotBids: initTable[Slot, SlotBids]())

proc payloadAvailability*(
    dag: ChainDAGRef,
    blck: BlockRef,
    executionBlockHash: Eth2Digest): Opt[PayloadAvailability] =
  let (blockHash, parentHash) = dag.loadExecutionAndParentBlockHash(blck)
  if blockHash.isSome and executionBlockHash == blockHash.unsafeGet:
    Opt.some PayloadAvailability.Timely
  elif parentHash.isSome and executionBlockHash == parentHash.unsafeGet:
    Opt.some PayloadAvailability.Withheld
  else:
    Opt.none PayloadAvailability

func prune*(pool: var ExecutionPayloadBidPool, beforeSlot: Slot) =
  var slotsToRemove: seq[Slot]
  for slot in pool.slotBids.keys:
    if slot < beforeSlot:
      slotsToRemove.add(slot)
  for slot in slotsToRemove:
    pool.slotBids.del(slot)

proc addBid*(
    pool: var ExecutionPayloadBidPool,
    signedBid: gloas.SignedExecutionPayloadBid,
    payloadAvailability: PayloadAvailability,
    wallTime: BeaconTime) =
  template bid: untyped = signedBid.message

  logScope:
    bid_slot = bid.slot
    builder_index = bid.builder_index
    bid_value = bid.value

  # Bids expire after their slot has passed
  pool.prune(beforeSlot =
    (wallTime - MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(pool.dag.timeParams))

  let slotData = addr pool.slotBids.mgetOrPut(bid.slot, default(SlotBids))

  if slotData.seenBuilders.containsOrIncl(bid.builder_index):
    debug "Duplicate bid from builder, ignoring"
    return

  let
    key = (bid.parent_block_root, payloadAvailability)
    currentBid = slotData.highestBids.getOrDefault(key)
  if currentBid != static(default(gloas.SignedExecutionPayloadBid)):
    if bid.value <= currentBid.message.value:
      debug "Bid value not higher than current best",
        current_best = currentBid.message.value
      return
    debug "Updated highest bid for slot and parent",
      previous_value = currentBid.message.value,
      previous_builder = currentBid.message.builder_index
  else:
    debug "First bid for this slot and parent"

  slotData.highestBids[key] = signedBid

func getBidForSlotAndBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    builderIndex: uint64): Opt[gloas.SignedExecutionPayloadBid] =
  let slotData = pool.slotBids.getOrDefault(slot)

  for bid in slotData.highestBids.values:
    if bid.message.builder_index == builderIndex:
      return Opt.some(bid)
  Opt.none(gloas.SignedExecutionPayloadBid)

func getHighestBidForSlotAndParent*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    parentBlockRoot: Eth2Digest, payloadAvailability: PayloadAvailability
): Opt[gloas.SignedExecutionPayloadBid] =
  let
    slotData = pool.slotBids.getOrDefault(slot)
    key = (parentBlockRoot, payloadAvailability)
    bid = slotData.highestBids.getOrDefault(key)
  if bid != static(default(gloas.SignedExecutionPayloadBid)):
    Opt.some(bid)
  else:
    Opt.none(gloas.SignedExecutionPayloadBid)

func hasSeenBidFromBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    builderIndex: uint64): bool =
  let slotData = pool.slotBids.getOrDefault(slot)
  builderIndex in slotData.seenBuilders

# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  stew/shims/hashes,
  chronicles,
  ../beacon_clock,
  ./blockchain_dag,
  ../spec/[digest, forks, helpers]

logScope: topics = "bidpool"

type
  BidKey* = object
    slot*: Slot
    builderIndex*: uint64

  BidDetail* = object
    bid*: SignedExecutionPayloadBid
    receivedAt*: BeaconTime

  ExecutionPayloadBidPool* = object
    ## Pool for tracking execution payload bids received from builders
    ## Bids are used for:
    ## 1. Data column sidecar validation (check blob commitments match)
    ## 2. Block production (proposers select highest-value bid)
    bids*: Table[BidKey, BidDetail]
    highestBids*: Table[(Slot, Eth2Digest), SignedExecutionPayloadBid]
      ## Track highest value bid per (slot, parent_block_hash)
    dag*: ChainDAGRef

func hash*(x: BidKey): Hash =
  hashAllFields(x)

func init*(
    T: type ExecutionPayloadBidPool,
    dag: ChainDAGRef): ExecutionPayloadBidPool =
  ExecutionPayloadBidPool(dag: dag)

proc addBid*(
    pool: var ExecutionPayloadBidPool,
    signedBid: SignedExecutionPayloadBid,
    wallTime: BeaconTime) =
  template bid: untyped = signedBid.message
  let
    key = BidKey(slot: bid.slot, builderIndex: bid.builder_index)
    parentKey = (bid.slot, bid.parent_block_hash)

  logScope:
    bid_slot = bid.slot
    builder_index = bid.builder_index
    bid_value = bid.value

  pool.bids[key] = BidDetail(bid: signedBid, receivedAt: wallTime)

  debug "Bid added to pool"

  # Update highest bid for (slot, parent_block_hash)
  try:
    if parentKey notin pool.highestBids or
        pool.highestBids[parentKey].message.value < bid.value:
      pool.highestBids[parentKey] = signedBid
      debug "Updated highest bid for slot and parent"
  except KeyError:
    # Shouldn't happen since we check 'notin' first
    pool.highestBids[parentKey] = signedBid
    debug "Updated highest bid for slot and parent (first bid)"

func getBid*(
    pool: ExecutionPayloadBidPool,
    blockRoot: Eth2Digest): Opt[SignedExecutionPayloadBid] =
  try:
    for detail in pool.bids.values:
      if detail.bid.message.parent_block_root == blockRoot:
        return Opt.some(detail.bid)
    Opt.none(SignedExecutionPayloadBid)
  except KeyError:
    Opt.none(SignedExecutionPayloadBid)

func hasBid*(
    pool: ExecutionPayloadBidPool,
    blockRoot: Eth2Digest): bool =
  pool.getBid(blockRoot).isSome()

func getBidForSlotAndBuilder*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    builderIndex: uint64): Opt[SignedExecutionPayloadBid] =
  let key = BidKey(slot: slot, builderIndex: builderIndex)
  try:
    if key in pool.bids:
      Opt.some(pool.bids[key].bid)
    else:
      Opt.none(SignedExecutionPayloadBid)
  except KeyError:
    Opt.none(SignedExecutionPayloadBid)

func getHighestBidForSlotAndParent*(
    pool: ExecutionPayloadBidPool, slot: Slot,
    parentBlockHash: Eth2Digest): Opt[SignedExecutionPayloadBid] =
  let key = (slot, parentBlockHash)
  try:
    if key in pool.highestBids:
      Opt.some(pool.highestBids[key])
    else:
      Opt.none(SignedExecutionPayloadBid)
  except KeyError:
    Opt.none(SignedExecutionPayloadBid)

proc prune*(pool: var ExecutionPayloadBidPool, finalizedSlot: Slot) =
  var
    toRemoveBids: seq[BidKey]
    toRemoveHighest: seq[(Slot, Eth2Digest)]

  try:
    for key, detail in pool.bids:
      if detail.bid.message.slot < finalizedSlot:
        toRemoveBids.add(key)

    for key, bid in pool.highestBids:
      if bid.message.slot < finalizedSlot:
        toRemoveHighest.add(key)

    for key in toRemoveBids:
      pool.bids.del(key)

    for key in toRemoveHighest:
      pool.highestBids.del(key)

    if toRemoveBids.len > 0:
      debug "Pruned old bids from pool",
        removed_bids = toRemoveBids.len,
        removed_highest = toRemoveHighest.len
  except KeyError:
    # Shouldn't happen, but handle gracefully
    debug "KeyError during bid pruning"

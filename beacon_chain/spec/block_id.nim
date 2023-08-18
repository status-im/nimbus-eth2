# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles,
  "."/[beacon_time, digest]

export beacon_time, digest

type
  BlockId* = object
    ## A BlockId is the root and the slot in which that block was
    ## produced - there are no guarantees that this block is part of
    ## the canonical chain, or that we have validated it - the type exists to
    ## tie a slot to the root which helps find the block in various indices and
    ## contexts
    slot*: Slot # slot first for nicer sorting / comparisons :)
    root*: Eth2Digest

  BlockSlotId* = object
    ## A BlockId at a slot equal to or higher than the slot of the block - when
    ## a slot is missing its block, we still need a way to communicate that the
    ## slot has changed - this type provides the necessary infrastructure
    bid*: BlockId
    slot*: Slot

func hash*(bid: BlockId): Hash =
  hash(bid.root)

func init*(T: type BlockSlotId, bid: BlockId, slot: Slot): T =
  doAssert slot >= bid.slot
  BlockSlotId(bid: bid, slot: slot)

func atSlot*(bid: BlockId): BlockSlotId =
  # BlockSlotId doesn't not have an atSlot function taking slot because it does
  # not share the parent-traversing features of `atSlot(BlockRef)`
  BlockSlotId.init(bid, bid.slot)

func isProposed*(bid: BlockId, slot: Slot): bool =
  ## Return true if `bid` was proposed in the given slot
  bid.slot == slot and not bid.root.isZero

func isProposed*(bsi: BlockSlotId): bool =
  ## Return true if `bs` represents the proposed block (as opposed to an empty
  ## slot)
  bsi.bid.isProposed(bsi.slot)

func shortLog*(v: BlockId): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  shortLog(v.root) & ":" & $v.slot

func shortLog*(v: BlockSlotId): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  if v.bid.slot == v.slot:
    shortLog(v.bid)
  else: # There was a gap - log it
    shortLog(v.bid) & "@" & $v.slot

chronicles.formatIt BlockId: shortLog(it)
chronicles.formatIt BlockSlotId: shortLog(it)

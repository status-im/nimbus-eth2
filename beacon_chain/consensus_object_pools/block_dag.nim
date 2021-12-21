# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronicles,

  ../spec/datatypes/[phase0, altair, merge],
  ../spec/[helpers]

export chronicles, phase0, altair, merge, helpers

type
  BlockId* = object
    ## A BlockId is the root and the slot in which that block was
    ## produced - there are no guarantees that this block is part of
    ## the canonical chain, or that we have validated it
    root*: Eth2Digest
    slot*: Slot

  BlockSlotId* = object
    ## A BlockId at a slot equal to or higher than the slot of the block
    bid*: BlockId
    slot*: Slot

  BlockRef* = ref object
    ## Node in object graph guaranteed to lead back to tail block, and to have
    ## a corresponding entry in database.
    ##
    ## All blocks identified by a `BlockRef` are valid per the state transition
    ## rules and that at some point were candidates for head selection. The
    ## ChainDAG offers stronger guarantees: it only returns `BlockRef` instances
    ## that are rooted in the currently finalized chain - however, these
    ## guarantees are valid only until the next head update - in particular,
    ## they are not valid across `await` calls.
    ##
    ## Block graph forms a tree - in particular, there are no cycles.

    bid*: BlockId ##\
      ## Root that can be used to retrieve block data from database

    parent*: BlockRef ##\
    ## Not nil, except for the tail

  BlockSlot* = object
    ## Unique identifier for a particular fork and time in the block chain -
    ## normally, there's a block for every slot, but in the case a block is not
    ## produced, the chain progresses anyway, producing a new state for every
    ## slot.
    blck*: BlockRef
    slot*: Slot ##\
      ## Slot time for this BlockSlot which may differ from blck.slot when time
      ## has advanced without blocks


template root*(blck: BlockRef): Eth2Digest = blck.bid.root
template slot*(blck: BlockRef): Slot = blck.bid.slot

func init*(T: type BlockRef, root: Eth2Digest, slot: Slot): BlockRef =
  BlockRef(
    bid: BlockId(root: root, slot: slot)
  )

func init*(T: type BlockRef, root: Eth2Digest, blck: SomeSomeBeaconBlock):
    BlockRef =
  BlockRef.init(root, blck.slot)

func toBlockId*(blck: SomeSomeSignedBeaconBlock): BlockId =
  BlockId(root: blck.root, slot: blck.message.slot)

func toBlockId*(blck: ForkedSignedBeaconBlock): BlockId =
  withBlck(blck): BlockId(root: blck.root, slot: blck.message.slot)

func parent*(bs: BlockSlot): BlockSlot =
  ## Return a blockslot representing the previous slot, using the parent block
  ## if the current slot had a block
  if bs.slot == Slot(0):
    BlockSlot(blck: nil, slot: Slot(0))
  else:
    BlockSlot(
      blck: if bs.slot > bs.blck.slot: bs.blck else: bs.blck.parent,
      slot: bs.slot - 1
    )

func parentOrSlot*(bs: BlockSlot): BlockSlot =
  ## Return a blockslot representing the previous slot, using the parent block
  ## with the current slot if the current had a block
  if bs.blck.isNil():
    BlockSlot(blck: nil, slot: Slot(0))
  elif bs.slot == bs.blck.slot:
    BlockSlot(blck: bs.blck.parent, slot: bs.slot)
  else:
    BlockSlot(blck: bs.blck, slot: bs.slot - 1)

func getDepth*(a, b: BlockRef): tuple[ancestor: bool, depth: int] =
  var b = b
  var depth = 0
  const maxDepth = (100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int)
  while true:
    if a == b:
      return (true, depth)

    # for now, use an assert for block chain length since a chain this long
    # indicates a circular reference here..
    doAssert depth < maxDepth
    depth += 1

    if a.slot >= b.slot or b.parent.isNil:
      return (false, depth)

    doAssert b.slot > b.parent.slot
    b = b.parent

func isAncestorOf*(a, b: BlockRef): bool =
  let (isAncestor, _) = getDepth(a, b)
  isAncestor

func link*(parent, child: BlockRef) =
  doAssert (not (parent.root == Eth2Digest() or child.root == Eth2Digest())),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent

func get_ancestor*(blck: BlockRef, slot: Slot,
    maxDepth = 100'i64 * 365 * 24 * 60 * 60 div SECONDS_PER_SLOT.int):
    BlockRef =
  ## https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/phase0/fork-choice.md#get_ancestor
  ## Return the most recent block as of the time at `slot` that not more recent
  ## than `blck` itself
  if isNil(blck): return nil

  var blck = blck

  var depth = 0

  while true:
    if blck.slot <= slot:
      return blck

    if isNil(blck.parent):
      return nil

    doAssert depth < maxDepth
    depth += 1

    blck = blck.parent

func atSlot*(blck: BlockRef, slot: Slot): BlockSlot =
  ## Return a BlockSlot at a given slot, with the block set to the closest block
  ## available. If slot comes from before the block, a suitable block ancestor
  ## will be used, else blck is returned as if all slots after it were empty.
  ## This helper is useful when imagining what the chain looked like at a
  ## particular moment in time, or when imagining what it will look like in the
  ## near future if nothing happens (such as when looking ahead for the next
  ## block proposal)
  BlockSlot(blck: blck.get_ancestor(slot), slot: slot)

func atSlot*(blck: BlockRef): BlockSlot =
  blck.atSlot(blck.slot)

func atSlot*(bid: BlockId, slot: Slot): BlockSlotId =
  BlockSlotId(bid: bid, slot: slot)

func atSlot*(bid: BlockId): BlockSlotId =
  bid.atSlot(bid.slot)

func atEpochStart*(blck: BlockRef, epoch: Epoch): BlockSlot =
  ## Return the BlockSlot corresponding to the first slot in the given epoch
  atSlot(blck, epoch.compute_start_slot_at_epoch())

func atSlotEpoch*(blck: BlockRef, epoch: Epoch): BlockSlot =
  ## Return the last block that was included in the chain leading
  ## up to the given epoch - this amounts to the state at the time
  ## when epoch processing for `epoch` has been done, but no block
  ## has yet been applied
  if epoch == GENESIS_EPOCH:
    blck.atEpochStart(epoch)
  else:
    let start = epoch.compute_start_slot_at_epoch()
    let tmp = blck.atSlot(start - 1)
    if isNil(tmp.blck):
      BlockSlot()
    else:
      tmp.blck.atSlot(start)

func toBlockSlotId*(bs: BlockSlot): BlockSlotId =
  if isNil(bs.blck):
    BlockSlotId()
  else:
    bs.blck.bid.atSlot(bs.slot)

func isProposed*(bid: BlockId, slot: Slot): bool =
  ## Return true if `bid` was proposed in the given slot
  bid.slot == slot

func isProposed*(blck: BlockRef, slot: Slot): bool =
  ## Return true if `blck` was proposed in the given slot
  not isNil(blck) and blck.bid.isProposed(slot)

func isProposed*(bs: BlockSlot): bool =
  ## Return true if `bs` represents the proposed block (as opposed to an empty
  ## slot)
  bs.blck.isProposed(bs.slot)

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

func shortLog*(v: BlockRef): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  if v.isNil():
    "nil:0"
  else:
    shortLog(v.bid)

func shortLog*(v: BlockSlot): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  if isNil(v.blck):
    "nil:0@" & $v.slot
  elif v.blck.slot == v.slot:
    shortLog(v.blck)
  else: # There was a gap - log it
    shortLog(v.blck) & "@" & $v.slot

chronicles.formatIt BlockId: shortLog(it)
chronicles.formatIt BlockSlotId: shortLog(it)
chronicles.formatIt BlockSlot: shortLog(it)
chronicles.formatIt BlockRef: shortLog(it)

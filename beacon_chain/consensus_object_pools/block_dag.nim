# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles,
  ../spec/forks

export chronicles, forks

type
  OptimisticStatus* {.pure.} = enum
    # A simplified version of `PayloadStatusV1`
    # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/sync/optimistic.md#helpers
    notValidated = "NOT_VALIDATED"
    valid = "VALID"
    invalidated = "INVALIDATED"

  BlockRef* = ref object
    ## Node in object graph guaranteed to lead back to finalized head, and to
    ## have a corresponding entry in database.
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

    executionBlockHash*: Opt[Eth2Digest]
    optimisticStatus*: OptimisticStatus

    parent*: BlockRef ##\
      ## Not nil, except for the finalized head

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

func init*(
    T: type BlockRef,
    root: Eth2Digest,
    executionBlockHash: Opt[Eth2Digest],
    optimisticStatus: OptimisticStatus,
    slot: Slot,
): BlockRef =
  BlockRef(
    bid: BlockId(root: root, slot: slot),
    executionBlockHash: executionBlockHash,
    optimisticStatus: optimisticStatus,
  )

func init*(
    T: type BlockRef, root: Eth2Digest, _: OptimisticStatus,
    blck: phase0.SomeBeaconBlock | altair.SomeBeaconBlock |
          phase0.TrustedBeaconBlock | altair.TrustedBeaconBlock): BlockRef =
  # Use same formal parameters for simplicity, but it's impossible for these
  # blocks to be optimistic.
  BlockRef.init(root, Opt.some ZERO_HASH, OptimisticStatus.valid, blck.slot)

func init*(
    T: type BlockRef, root: Eth2Digest, optimisticStatus: OptimisticStatus,
    blck: bellatrix.SomeBeaconBlock | bellatrix.TrustedBeaconBlock |
          capella.SomeBeaconBlock | capella.TrustedBeaconBlock |
          deneb.SomeBeaconBlock | deneb.TrustedBeaconBlock |
          electra.SomeBeaconBlock | electra.TrustedBeaconBlock |
          fulu.SomeBeaconBlock | fulu.TrustedBeaconBlock): BlockRef =
  BlockRef.init(
    root, Opt.some blck.body.execution_payload.block_hash, optimisticStatus, blck.slot
  )

func init*(
    T: type BlockRef, root: Eth2Digest, optimisticStatus: OptimisticStatus,
    blck: gloas.SomeBeaconBlock | gloas.TrustedBeaconBlock): BlockRef =
  BlockRef.init(
    root,
    Opt.some blck.body.signed_execution_payload_bid.message.block_hash,
    if optimisticStatus == OptimisticStatus.valid or
        blck.body.signed_execution_payload_bid.message.block_hash.isZero:
      OptimisticStatus.valid
    else:
      optimisticStatus,
    blck.slot,
  )

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

# This is used to detect internal inconsistencies, e.g., circular references.
# Note that `BlockRef` is only used for the non-finalized chain segment.
const defaultMaxDepth = 1'i64 shl 24  # More than enough for years

func getDepth*(a, b: BlockRef): tuple[ancestor: bool, depth: int] =
  var b = b
  var depth = 0
  while true:
    if a == b:
      return (true, depth)

    # for now, use an assert for block chain length since a chain this long
    # indicates a circular reference here..
    doAssert depth < defaultMaxDepth
    depth += 1

    if a.slot >= b.slot or b.parent.isNil:
      return (false, depth)

    doAssert b.slot > b.parent.slot
    b = b.parent

func isAncestorOf*(a, b: BlockRef): bool =
  let (isAncestor, _) = getDepth(a, b)
  isAncestor

func link*(parent, child: BlockRef) =
  doAssert (not (parent.root.isZero or child.root.isZero)),
    "blocks missing root!"
  doAssert parent.root != child.root, "self-references not allowed"

  child.parent = parent

func get_ancestor*(
    blck: BlockRef, slot: Slot, maxDepth = defaultMaxDepth): BlockRef =
  ## https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/fork-choice.md#get_ancestor
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

func atEpochStart*(blck: BlockRef, epoch: Epoch): BlockSlot =
  ## Return the BlockSlot corresponding to the first slot in the given epoch
  atSlot(blck, epoch.start_slot())

func atCheckpoint*(blck: BlockRef, checkpoint: Checkpoint): Opt[BlockSlot] =
  ## Rewind from `blck` to the given `checkpoint` iff it is an ancestor
  let target = blck.atSlot(checkpoint.epoch.start_slot)
  if target.blck == nil:
    return err()
  if target.blck.root != checkpoint.root:
    return err()
  ok target

func toBlockSlotId*(bs: BlockSlot): Opt[BlockSlotId] =
  if isNil(bs.blck):
    err()
  else:
    ok BlockSlotId.init(bs.blck.bid, bs.slot)

func isProposed*(blck: BlockRef, slot: Slot): bool =
  ## Return true if `blck` was proposed in the given slot
  not isNil(blck) and blck.bid.isProposed(slot)

func isProposed*(bs: BlockSlot): bool =
  ## Return true if `bs` represents the proposed block (as opposed to an empty
  ## slot)
  bs.blck.isProposed(bs.slot)

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

func executionValid*(blck: BlockRef): bool =
  blck.optimisticStatus == OptimisticStatus.valid

proc markExecutionValid*(blck: BlockRef, valid: bool) =
  ## Mark a block as having a valid or invalid excecution payload
  if not valid:
    blck.optimisticStatus = OptimisticStatus.invalidated
    debug "Optimistic status updated", blck = shortLog(blck), valid
  else:
    # Being valid implies that the ancestors are also valid
    var cur = blck

    while cur != nil and cur.optimisticStatus == OptimisticStatus.notValidated:
      cur.optimisticStatus = OptimisticStatus.valid
      debug "Optimistic status updated", blck = shortLog(cur), valid

      cur = cur.parent

chronicles.formatIt BlockSlot: shortLog(it)
chronicles.formatIt BlockRef: shortLog(it)

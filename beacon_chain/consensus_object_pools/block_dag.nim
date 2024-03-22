import
  ".."/spec/digest

type
  BlockId = object
    ## A BlockId is the root and the slot in which that block was
    ## produced - there are no guarantees that this block is part of
    ## the canonical chain, or that we have validated it - the type exists to
    ## tie a slot to the root which helps find the block in various indices and
    ## contexts
    slot: uint64 # slot first for nicer sorting / comparisons :)
    root: Eth2Digest

func shortLog(v: BlockId): string =
  # epoch:root when logging epoch, root:slot when logging slot!
  shortLog(v.root) & ":" & $v.slot
type
  BlockRef* = ref object
    bid*: BlockId

  BlockSlot* = object
    blck: BlockRef
    slot: uint64

template root*(blck: BlockRef): Eth2Digest = blck.bid.root
template slot*(blck: BlockRef): uint64 = blck.bid.slot

func init*(
    T: type BlockRef, root: Eth2Digest,
    slot: uint64):
    BlockRef =
  BlockRef(
    bid: BlockId(root: root, slot: slot))

func shortLog*(v: BlockRef): string =
  if v.isNil():
    "nil:0"
  else:
    shortLog(v.bid)

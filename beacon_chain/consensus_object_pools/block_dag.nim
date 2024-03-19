import ../spec/datatypes/base
from ".."/spec/block_id import BlockId, shortLog

type
  BlockRef* = ref object
    bid*: BlockId

  BlockSlot* = object
    blck: BlockRef
    slot: Slot

template root*(blck: BlockRef): Eth2Digest = blck.bid.root
template slot*(blck: BlockRef): Slot = blck.bid.slot

func init*(
    T: type BlockRef, root: Eth2Digest,
    slot: Slot):
    BlockRef =
  BlockRef(
    bid: BlockId(root: root, slot: slot))

func shortLog*(v: BlockRef): string =
  if v.isNil():
    "nil:0"
  else:
    shortLog(v.bid)

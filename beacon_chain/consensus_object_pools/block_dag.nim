import
  stew/byteutils

type
  Eth2Digest* = object
    data*: array[32, byte]

func shortLog*(x: Eth2Digest): string =
  x.data.toOpenArray(0, 3).toHex()

type
  BlockRef* = ref object
    slot: uint64
    root: Eth2Digest

func init*(
    T: type BlockRef, root: Eth2Digest, slot: uint64): BlockRef =
  BlockRef(root: root, slot: slot)

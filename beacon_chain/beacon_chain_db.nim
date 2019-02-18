import
  os, json, tables, options,
  chronicles, json_serialization, eth/common/eth_types_json_serialization,
  spec/[datatypes, digest, crypto],
  eth/trie/db, ssz

type
  BeaconChainDB* = ref object
    backend: TrieDatabaseRef

  DbKeyKind = enum
    kHashToState
    kHashToBlock
    kHeadBlock # Pointer to the most recent block seen
    kTailBlock # Pointer to the earliest finalized block
    kSlotToBlockRoots

func subkey(kind: DbKeyKind): array[1, byte] =
  result[0] = byte ord(kind)

func subkey[T](kind: DbKeyKind, key: T): auto =
  var res: array[sizeof(T) + 1, byte]
  res[0] = byte ord(kind)
  copyMem(addr res[1], unsafeAddr key, sizeof(key))
  return res

func subkey(kind: type BeaconState, key: Eth2Digest): auto =
  subkey(kHashToState, key.data)

func subkey(kind: type BeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)

proc init*(T: type BeaconChainDB, backend: TrieDatabaseRef): BeaconChainDB =
  new result
  result.backend = backend

proc toSeq(v: openarray[byte], ofType: type): seq[ofType] =
  if v.len != 0:
    assert(v.len mod sizeof(ofType) == 0)
    let sz = v.len div sizeof(ofType)
    result = newSeq[ofType](sz)
    copyMem(addr result[0], unsafeAddr v[0], v.len)

proc putBlock*(db: BeaconChainDB, key: Eth2Digest, value: BeaconBlock) =
  let slotKey = subkey(kSlotToBlockRoots, value.slot)
  var blockRootsBytes = db.backend.get(slotKey)
  var blockRoots = blockRootsBytes.toSeq(Eth2Digest)
  if key notin blockRoots:
    db.backend.put(subkey(type value, key), ssz.serialize(value))
    blockRootsBytes.setLen(blockRootsBytes.len + sizeof(key))
    copyMem(addr blockRootsBytes[^sizeof(key)], unsafeAddr key, sizeof(key))
    db.backend.put(slotKey, blockRootsBytes)

proc putHead*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.put(subkey(kHeadBlock), key.data) # TODO head block?

proc putState*(db: BeaconChainDB, key: Eth2Digest, value: BeaconState) =
  # TODO: prune old states
  # TODO: it might be necessary to introduce the concept of a "last finalized
  #       state" to the storage, so that clients with limited storage have
  #       a natural state to start recovering from. One idea is to keep a
  #       special pointer to the state that has ben finalized, and prune all
  #       other states.
  #       One issue is that what will become a finalized is revealed only
  #       long after that state has passed, meaning that we need to keep
  #       a history of "finalized state candidates" or possibly replay from
  #       the previous finalized state, if we have that stored. To consider
  #       here is that the gap between finalized and present state might be
  #       significant (days), meaning replay might be expensive.
  db.backend.put(subkey(type value, key), ssz.serialize(value))

proc putState*(db: BeaconChainDB, value: BeaconState) =
  db.putState(hash_tree_root_final(value), value)

proc putBlock*(db: BeaconChainDB, value: BeaconBlock) =
  db.putBlock(hash_tree_root_final(value), value)

proc putHeadBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.put(subkey(kHeadBlock), key.data) # TODO head block?

proc putTailBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.put(subkey(kTailBlock), key.data)

proc get(db: BeaconChainDB, key: auto, T: typedesc): Option[T] =
  let res = db.backend.get(key)
  if res.len != 0:
    ssz.deserialize(res, T)
  else:
    none(T)

proc getBlock*(db: BeaconChainDB, key: Eth2Digest): Option[BeaconBlock] =
  db.get(subkey(BeaconBlock, key), BeaconBlock)

proc getState*(db: BeaconChainDB, key: Eth2Digest): Option[BeaconState] =
  db.get(subkey(BeaconState, key), BeaconState)

proc getHeadBlock*(db: BeaconChainDB): Option[Eth2Digest] =
  db.get(subkey(kHeadBlock), Eth2Digest)

proc getTailBlock*(db: BeaconChainDB): Option[Eth2Digest] =
  db.get(subkey(kTailBlock), Eth2Digest)

proc getBlockRootsForSlot*(db: BeaconChainDB, slot: uint64): seq[Eth2Digest] =
  db.backend.get(subkey(kSlotToBlockRoots, slot)).toSeq(Eth2Digest)

proc containsBlock*(
    db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconBlock, key))

proc containsState*(
    db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconBlock, key))

iterator getAncestors*(db: BeaconChainDB, root: Eth2Digest):
    tuple[root: Eth2Digest, blck: BeaconBlock] =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found.

  var root = root
  while (let blck = db.getBlock(root); blck.isSome()):
    yield (root, blck.get())

    root = blck.get().parent_root

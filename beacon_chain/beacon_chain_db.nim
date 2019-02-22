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
    kHeadBlock

func subkey(kind: DbKeyKind): array[1, byte] =
  result[0] = byte ord(kind)

func subkey[N: static int](kind: DbKeyKind, key: array[N, byte]):
    array[N + 1, byte] =
  result[0] = byte ord(kind)
  result[1 .. ^1] = key

func subkey(kind: type BeaconState, key: Eth2Digest): auto =
  subkey(kHashToState, key.data)

func subkey(kind: type BeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)

proc init*(T: type BeaconChainDB, backend: TrieDatabaseRef): BeaconChainDB =
  new result
  result.backend = backend

proc putBlock*(db: BeaconChainDB, key: Eth2Digest, value: BeaconBlock) =
  db.backend.put(subkey(type value, key), ssz.serialize(value))

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

proc putBlock*(db: BeaconChainDB, value: BeaconBlock) =
  db.putBlock(hash_tree_root_final(value), value)

proc putState*(db: BeaconChainDB, value: BeaconState) =
  db.putState(hash_tree_root_final(value), value)

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

proc getHead*(db: BeaconChainDB): Option[BeaconBlock] =
  let key = db.backend.get(subkey(kHeadBlock))
  if key.len == sizeof(Eth2Digest):
    var tmp: Eth2Digest
    copyMem(addr tmp, unsafeAddr key[0], sizeof(tmp))

    db.getBlock(tmp)
  else:
    none(BeaconBlock)

proc containsBlock*(
    db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconBlock, key))

proc containsState*(
    db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconBlock, key))

proc getAncestors*(
    db: BeaconChainDB, blck: BeaconBlock,
    predicate: proc(blck: BeaconBlock): bool = nil): seq[BeaconBlock] =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found (or slot 0) or
  ## the predicate returns true (you found what you were looking for) - the list
  ## will include the last block as well
  ## TODO maybe turn into iterator? or add iterator also?

  result = @[blck]

  while result[^1].slot > 0.Slot:
    let parent = db.getBlock(result[^1].parent_root)

    if parent.isNone(): break

    result.add parent.get()

    if predicate != nil and predicate(parent.get()): break

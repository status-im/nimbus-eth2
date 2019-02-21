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

  DbTypes = BeaconState | BeaconBlock

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

proc put*(db: BeaconChainDB, key: Eth2Digest, value: BeaconBlock) =
  db.backend.put(subkey(type value, key), ssz.serialize(value))

proc putHead*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.put(subkey(kHeadBlock), key.data) # TODO head block?

proc put*(db: BeaconChainDB, key: Eth2Digest, value: BeaconState) =
  db.backend.put(subkey(type value, key), ssz.serialize(value))

proc put*(db: BeaconChainDB, value: DbTypes) =
  db.put(hash_tree_root_final(value), value)

proc get(db: BeaconChainDB, key: auto, T: typedesc): Option[T] =
  let res = db.backend.get(key)
  if res.len != 0:
    ssz.deserialize(res, T)
  else:
    none(T)

# TODO: T: type DbTypes fails with compiler error.. investigate
proc get*(db: BeaconChainDB, key: Eth2Digest, T: type BeaconBlock): Option[T] =
  db.get(subkey(T, key), T)

proc get*(db: BeaconChainDB, key: Eth2Digest, T: type BeaconState): Option[T] =
  db.get(subkey(T, key), T)

proc getHead*(db: BeaconChainDB, T: type BeaconBlock): Option[T] =
  let key = db.backend.get(subkey(kHeadBlock))
  if key.len == sizeof(Eth2Digest):
    var tmp: Eth2Digest
    copyMem(addr tmp, unsafeAddr key[0], sizeof(tmp))

    db.get(tmp, T)
  else:
    none(T)

proc contains*(
    db: BeaconChainDB, key: Eth2Digest, T: type DbTypes): bool =
  db.backend.contains(subkey(T, key))

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
    let parent = db.get(result[^1].parent_root, BeaconBlock)

    if parent.isNone(): break

    result.add parent.get()

    if predicate != nil and predicate(parent.get()): break

{.push raises: [Defect].}

import
  typetraits, stew/[results, objects, endians2],
  serialization, chronicles, snappy,
  eth/db/kvstore,
  ./spec/[datatypes, digest, crypto, state_transition],
  ./ssz/[ssz_serialization, merkleization]

type
  BeaconChainDB* = ref object
    ## Database storing resolved blocks and states - resolved blocks are such
    ## blocks that form a chain back to the tail block.
    ##
    ## We assume that the database backend is working / not corrupt - as such,
    ## we will raise a Defect any time there is an issue. This should be
    ## revisited in the future, when/if the calling code safely can handle
    ## corruption of this kind.
    ##
    ## We do however make an effort not to crash on invalid data inside the
    ## database - this may have a number of "natural" causes such as switching
    ## between different versions of the client and accidentally using an old
    ## database.
    backend: KvStoreRef

  DbKeyKind = enum
    kHashToState
    kHashToBlock
    kHeadBlock # Pointer to the most recent block selected by the fork choice
    kTailBlock ##\
    ## Pointer to the earliest finalized block - this is the genesis block when
    ## the chain starts, but might advance as the database gets pruned
    ## TODO: determine how aggressively the database should be pruned. For a
    ##       healthy network sync, we probably need to store blocks at least
    ##       past the weak subjectivity period.
    kBlockSlotStateRoot ## BlockSlot -> state_root mapping

# Subkeys essentially create "tables" within the key-value store by prefixing
# each entry with a table id

func subkey(kind: DbKeyKind): array[1, byte] =
  result[0] = byte ord(kind)

func subkey[N: static int](kind: DbKeyKind, key: array[N, byte]):
    array[N + 1, byte] =
  result[0] = byte ord(kind)
  result[1 .. ^1] = key

func subkey(kind: type BeaconState, key: Eth2Digest): auto =
  subkey(kHashToState, key.data)

func subkey(kind: type SignedBeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)

func subkey(root: Eth2Digest, slot: Slot): array[40, byte] =
  var ret: array[40, byte]
  # big endian to get a naturally ascending order on slots in sorted indices
  ret[0..<8] = toBytesBE(slot.uint64)
  # .. but 7 bytes should be enough for slots - in return, we get a nicely
  # rounded key length
  ret[0] = byte ord(kBlockSlotStateRoot)
  ret[8..<40] = root.data

  ret

proc init*(T: type BeaconChainDB, backend: KVStoreRef): BeaconChainDB =
  T(backend: backend)

proc snappyEncode(inp: openArray[byte]): seq[byte] =
  try:
    snappy.encode(inp)
  except CatchableError as err:
    raiseAssert err.msg

proc put(db: BeaconChainDB, key: openArray[byte], v: Eth2Digest) =
  db.backend.put(key, v.data).expect("working database")

proc put(db: BeaconChainDB, key: openArray[byte], v: auto) =
  db.backend.put(key, snappyEncode(SSZ.encode(v))).expect("working database")

proc get(db: BeaconChainDB, key: openArray[byte], T: type Eth2Digest): Opt[T] =
  var res: Opt[T]
  proc decode(data: openArray[byte]) =
    if data.len == 32:
      res.ok Eth2Digest(data: toArray(32, data))
    else:
      # If the data can't be deserialized, it could be because it's from a
      # version of the software that uses a different SSZ encoding
      warn "Unable to deserialize data, old database?",
       typ = name(T), dataLen = data.len
      discard

  discard db.backend.get(key, decode).expect("working database")

  res

proc get(db: BeaconChainDB, key: openArray[byte], res: var auto): bool =
  var found = false

  # TODO address is needed because there's no way to express lifetimes in nim
  #      we'll use unsafeAddr to find the code later
  var resPtr = unsafeAddr res # callback is local, ptr wont escape
  proc decode(data: openArray[byte]) =
    try:
      resPtr[] = SSZ.decode(snappy.decode(data), type res)
      found = true
    except SerializationError as e:
      # If the data can't be deserialized, it could be because it's from a
      # version of the software that uses a different SSZ encoding
      warn "Unable to deserialize data, old database?",
        err = e.msg, typ = name(type res), dataLen = data.len
      discard

  discard db.backend.get(key, decode).expect("working database")

  found

proc putBlock*(db: BeaconChainDB, key: Eth2Digest, value: SignedBeaconBlock) =
  db.put(subkey(type value, key), value)
proc putBlock*(db: BeaconChainDB, key: Eth2Digest, value: TrustedSignedBeaconBlock) =
  db.put(subkey(SignedBeaconBlock, key), value)

proc putState*(db: BeaconChainDB, key: Eth2Digest, value: BeaconState) =
  # TODO prune old states - this is less easy than it seems as we never know
  #      when or if a particular state will become finalized.

  db.put(subkey(type value, key), value)

proc putState*(db: BeaconChainDB, value: BeaconState) =
  db.putState(hash_tree_root(value), value)

proc putStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot,
    value: Eth2Digest) =
  db.put(subkey(root, slot), value)

proc putBlock*(db: BeaconChainDB, value: SomeSignedBeaconBlock) =
  # TODO this should perhaps be a TrustedSignedBeaconBlock, but there's no
  #      trivial way to coerce one type into the other, as it stands..
  db.putBlock(hash_tree_root(value.message), value)

proc delBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.del(subkey(SignedBeaconBlock, key)).expect(
    "working database")

proc delState*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.del(subkey(BeaconState, key)).expect("working database")

proc delStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot) =
  db.backend.del(subkey(root, slot)).expect("working database")

proc putHeadBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.put(subkey(kHeadBlock), key)

proc putTailBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.put(subkey(kTailBlock), key)

proc getBlock*(db: BeaconChainDB, key: Eth2Digest): Opt[TrustedSignedBeaconBlock] =
  # We only store blocks that we trust in the database
  result.ok(TrustedSignedBeaconBlock())
  if not db.get(subkey(SignedBeaconBlock, key), result.get):
    result.err()

proc getState*(
    db: BeaconChainDB, key: Eth2Digest, output: var BeaconState,
    rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126
  # TODO RVO is inefficient for large objects:
  #      https://github.com/nim-lang/Nim/issues/13879
  if not db.get(subkey(BeaconState, key), output):
    rollback(output)
    false
  else:
    true

proc getStateRoot*(db: BeaconChainDB,
                   root: Eth2Digest,
                   slot: Slot): Opt[Eth2Digest] =
  db.get(subkey(root, slot), Eth2Digest)

proc getHeadBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.get(subkey(kHeadBlock), Eth2Digest)

proc getTailBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.get(subkey(kTailBlock), Eth2Digest)

proc containsBlock*(db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(SignedBeaconBlock, key)).expect("working database")

proc containsState*(db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconState, key)).expect("working database")

iterator getAncestors*(db: BeaconChainDB, root: Eth2Digest):
    tuple[root: Eth2Digest, blck: TrustedSignedBeaconBlock] =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found.

  var res: tuple[root: Eth2Digest, blck: TrustedSignedBeaconBlock]
  res.root = root
  while db.get(subkey(SignedBeaconBlock, res.root), res.blck):
    yield res
    res.root = res.blck.message.parent_root

{.push raises: [Defect].}

import
  typetraits, stew/[results, objects, endians2],
  serialization, chronicles, snappy,
  eth/db/kvstore,
  ./spec/[datatypes, digest, crypto, helpers, state_transition],
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

const
  maxDecompressedDbRecordSize = 16*1024*1024

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

type GetResult = enum
  found
  notFound
  corrupted

proc get[T](db: BeaconChainDB, key: openArray[byte], output: var T): GetResult =
  var status = GetResult.notFound

  # TODO address is needed because there's no way to express lifetimes in nim
  #      we'll use unsafeAddr to find the code later
  var outputPtr = unsafeAddr output # callback is local, ptr wont escape
  proc decode(data: openArray[byte]) =
    try:
      let decompressed = snappy.decode(data, maxDecompressedDbRecordSize)
      if decompressed.len > 0:
        outputPtr[] = SSZ.decode(decompressed, T, updateRoot = false)
        status = GetResult.found
      else:
        warn "Corrupt snappy record found in database", typ = name(T)
        status = GetResult.corrupted
    except SerializationError as e:
      # If the data can't be deserialized, it could be because it's from a
      # version of the software that uses a different SSZ encoding
      warn "Unable to deserialize data, old database?",
        err = e.msg, typ = name(T), dataLen = data.len
      status = GetResult.corrupted

  discard db.backend.get(key, decode).expect("working database")

  status

proc putBlock*(db: BeaconChainDB, value: SignedBeaconBlock) =
  db.put(subkey(type value, value.root), value)
proc putBlock*(db: BeaconChainDB, value: TrustedSignedBeaconBlock) =
  db.put(subkey(SignedBeaconBlock, value.root), value)

proc putState*(db: BeaconChainDB, key: Eth2Digest, value: BeaconState) =
  # TODO prune old states - this is less easy than it seems as we never know
  #      when or if a particular state will become finalized.

  db.put(subkey(type value, key), value)

proc putState*(db: BeaconChainDB, value: BeaconState) =
  db.putState(hash_tree_root(value), value)

proc putStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot,
    value: Eth2Digest) =
  db.put(subkey(root, slot), value)

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
  if db.get(subkey(SignedBeaconBlock, key), result.get) != GetResult.found:
    result.err()
  else:
    # set root after deserializing (so it doesn't get zeroed)
    result.get().root = key

proc getState*(
    db: BeaconChainDB, key: Eth2Digest, output: var BeaconState,
    rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  ## Rollback will be called only if output was partially written - if it was
  ## not found at all, rollback will not be called
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126
  # TODO RVO is inefficient for large objects:
  #      https://github.com/nim-lang/Nim/issues/13879
  case db.get(subkey(BeaconState, key), output)
  of GetResult.found:
    true
  of GetResult.notFound:
    false
  of GetResult.corrupted:
    rollback(output)
    false

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
    TrustedSignedBeaconBlock =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found.

  var
    res: TrustedSignedBeaconBlock
    root = root
  while db.get(subkey(SignedBeaconBlock, root), res) == GetResult.found:
    res.root = root
    yield res
    root = res.message.parent_root

proc copyPrunedDatabase*(
    db: BeaconChainDB, copyDb: BeaconChainDB, dry_run, verbose: bool) =
  ## Create a pruned copy of the beacon chain database

  let
    headBlock = db.getHeadBlock()
    tailBlock = db.getTailBlock()

  doAssert headBlock.isOk and tailBlock.isOk
  doAssert db.getBlock(headBlock.get).isOk
  doAssert db.getBlock(tailBlock.get).isOk

  var
    beaconState: ref BeaconState
    finalizedEpoch: Epoch  # default value of 0 is conservative/safe
    prevBlockSlot = db.getBlock(db.getHeadBlock().get).get.message.slot

  beaconState = new BeaconState
  let headEpoch = db.getBlock(headBlock.get).get.message.slot.epoch

  # Tail states are specially addressed; no stateroot intermediary
  if not db.getState(
      db.getBlock(tailBlock.get).get.message.state_root, beaconState[],
      noRollback):
    doAssert false, "could not load tail state"
  if not dry_run:
    copyDb.putState(beaconState[])

  for signedBlock in getAncestors(db, headBlock.get):
    if not dry_run:
      copyDb.putBlock(signedBlock)
    if verbose:
      echo "copied block at slot ", signedBlock.message.slot

    for slot in countdown(prevBlockSlot, signedBlock.message.slot + 1):
      if slot mod SLOTS_PER_EPOCH != 0 or slot.epoch < finalizedEpoch:
        continue

      # Could even only ever copy these states, head and finalized
      let stateRequired = slot.epoch in [finalizedEpoch, headEpoch]

      # only do this for slot or etc of tailblock or on-or-after finalizedRoot of headBlock
      let sr = db.getStateRoot(signedBlock.root, slot)
      if sr.isErr:
        if stateRequired:
          doAssert false, "state root and state required"
        continue

      if not db.getState(sr.get, beaconState[], noRollback):
        # Don't copy dangling stateroot pointers
        if stateRequired:
          doAssert false, "state root and state required"
        continue

      finalizedEpoch = max(
        finalizedEpoch, beaconState.finalized_checkpoint.epoch)

      if not dry_run:
        copyDb.putStateRoot(signedBlock.root, slot, sr.get)
        copyDb.putState(beaconState[])
      if verbose:
        echo "copied state at slot ", slot, " from block at ", shortLog(signedBlock.message.slot)

    prevBlockSlot = signedBlock.message.slot

  if not dry_run:
    copyDb.putHeadBlock(headBlock.get)
    copyDb.putTailBlock(tailBlock.get)

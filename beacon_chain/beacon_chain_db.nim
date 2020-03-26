import
  options, typetraits, sequtils,
  serialization, chronicles,
  spec/[datatypes, digest, crypto],
  kvstore, ssz, persistent_store

type
  BeaconChainDB* = ref object
    ## Database storing resolved blocks and states - resolved blocks are such
    ## blocks that form a chain back to the tail block.
    backend: KVStoreRef
    persistent: ColdStorage

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
    kBlockHashToSlot ## BlockHash -> Slot : to allow to efficiently access coldStorage

func subkey(kind: DbKeyKind): array[1, byte] =
  result[0] = byte ord(kind)

func subkey[N: static int](kind: DbKeyKind, key: array[N, byte]):
    array[N + 1, byte] =
  result[0] = byte ord(kind)
  result[1 .. ^1] = key

func subkey(kind: DbKeyKind, key: uint64): array[sizeof(key) + 1, byte] =
  result[0] = byte ord(kind)
  copyMem(addr result[1], unsafeAddr key, sizeof(key))

func subkey(kind: type BeaconState, key: Eth2Digest): auto =
  subkey(kHashToState, key.data)

func subkey(kind: type SignedBeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)

func subkey(kind: type Eth2Digest, key: Eth2Digest): auto =
  subkey(kBlockHashToSlot, key.data)

func subkey(root: Eth2Digest, slot: Slot): auto =
  # TODO: Copy the SSZ data to `ret` properly.
  # We don't need multiple calls to SSZ.encode
  # Use memoryStream(ret) and SszWriter explicitly

  var
    # takes care of endians..
    rootSSZ = SSZ.encode(root)
    slotSSZ = SSZ.encode(slot)

  var ret: array[1 + 32 + 8, byte]
  doAssert sizeof(ret) == 1 + rootSSZ.len + slotSSZ.len,
    "Can't sizeof this in VM"

  ret[0] = byte ord(kBlockSlotStateRoot)

  copyMem(addr ret[1], unsafeaddr root, sizeof(root))
  copyMem(addr ret[1 + sizeof(root)], unsafeaddr slot, sizeof(slot))

  ret

proc init*(T: type BeaconChainDB, backend: KVStoreRef): BeaconChainDB =
  T(backend: backend, persistent: ColdStorage.init())

proc putBlock*(db: BeaconChainDB, key: Eth2Digest, value: SignedBeaconBlock) =
  # Saving the root in the root -> slot mapping
  db.backend.put(subkey(type key, key), SSZ.encode(value.message.slot))
  db.backend.put(subkey(type value, key), SSZ.encode(value))

proc putState*(db: BeaconChainDB, key: Eth2Digest, value: BeaconState) =
  # TODO prune old states - this is less easy than it seems as we never know
  #      when or if a particular state will become finalized.

  db.backend.put(subkey(type value, key), SSZ.encode(value))

proc putState*(db: BeaconChainDB, value: BeaconState) =
  db.putState(hash_tree_root(value), value)

proc putStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot,
    value: Eth2Digest) =
  db.backend.put(subkey(root, slot), value.data)

proc putBlock*(db: BeaconChainDB, value: SignedBeaconBlock) =
  db.putBlock(hash_tree_root(value.message), value)

proc delBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.del(subkey(SignedBeaconBlock, key))

proc delState*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.del(subkey(BeaconState, key))

proc delStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot) =
  db.backend.del(subkey(root, slot))

proc putHeadBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.put(subkey(kHeadBlock), key.data)

proc putTailBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.put(subkey(kTailBlock), key.data)

proc get(db: BeaconChainDB, key: auto, T: typedesc): Option[T] =
  var res: Option[T]
  discard db.backend.get(key) do (data: openArray[byte]):
    try:
      res = some(SSZ.decode(data, T))
    except SerializationError:
      # Please note that this is intentionally a normal assert.
      # We consider this a hard failure in debug mode, because
      # it suggests a corrupted database. Release builds "recover"
      # from the situation by failing to deliver a result from the
      # database.
      assert false
      error "Corrupt database entry", key, `type` = name(T)
  res

proc getState*(db: BeaconChainDB, key: Eth2Digest): Option[BeaconState] =
  db.get(subkey(BeaconState, key), BeaconState)

proc getStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot):
    Option[Eth2Digest] =
  db.get(subkey(root, slot), Eth2Digest)

proc getHeadBlock*(db: BeaconChainDB): Option[Eth2Digest] =
  db.get(subkey(kHeadBlock), Eth2Digest)

proc getTailBlock*(db: BeaconChainDB): Option[Eth2Digest] =
  db.get(subkey(kTailBlock), Eth2Digest)

proc containsBlock*(
    db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(SignedBeaconBlock, key))

proc containsState*(
    db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconState, key))

proc getBlockFromCold*(db: BeaconChainDB, key: Slot):Option[SignedBeaconBlock] =
  let id_len = db.persistent.indices.getSize()
  let headSlot = (id_len div 8) - 1 
  if headSlot < key:
    return
  
  var read_len = uint64 16  
  if key == headSlot:
    read_len = 8

  var off : Option[uint64]
  var len: Option[uint64]
  db.persistent.indices.read(key * 8, read_len) do (data: openArray[byte]):
      echo data
      try:
        off = some(SSZ.decode(data[0..7], uint64))
        if(read_len == 16):
          let next_off = some(SSZ.decode(data[8..^1], uint64))
          len = some(next_off.get - off.get)
        else:
          len = some(db.persistent.storage.getSize() - off.get())        
      except SerializationError:
        assert false
  #Read actual block info
  var blck : Option[SignedBeaconBlock]
  if off.isSome() and len.isSome():
    db.persistent.storage.read(off.get, len.get, proc(data: openArray[byte])=
      #do something with block data
      try:
        blck = some(SSZ.decode(data, SignedBeaconBlock))
      except SerializationError:
        assert false
    )
  
  blck  

proc putBlockCold*(db: BeaconChainDB, value: SignedBeaconBlock) =
  #Read Index
  let id_len = db.persistent.indices.getSize()
  let available_off = db.persistent.storage.getSize()
  #Are we in the correct slot?
  var curr_slot = (id_len div 8) - 1
  let diff = int value.message.slot - curr_slot 
  let next_slot = SSZ.encode(Slot(available_off))  
  let key = next_slot.cycle(diff)
  let val = SSZ.encode(value)
  # #Put in Persistent Store
  db.persistent.put(key,val)

proc getBlock*(db: BeaconChainDB, key: Eth2Digest): Option[SignedBeaconBlock] =
  if(db.containsBlock(key)):
    return db.get(subkey(SignedBeaconBlock, key), SignedBeaconBlock)
  let slot = db.get(subkey(Eth2Digest, key), uint64)
  if slot.isSome():
    return db.getBlockFromCold(Slot(slot.get))

iterator getAncestors*(db: BeaconChainDB, root: Eth2Digest):
    tuple[root: Eth2Digest, blck: SignedBeaconBlock] =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found.

  var root = root
  while (let blck = db.getBlock(root); blck.isSome()):
    yield (root, blck.get())
    root = blck.get().message.parent_root

proc pruneToColdStorage*(db: BeaconChainDB, root: Eth2Digest) =
  #Kind of inneficient, but we have to go from tail to head
  var temp_root = newSeq[Eth2Digest](0)
  for root, blck in db.getAncestors(root):
    if(not db.containsBlock(root)):
      break
    temp_root.add(root)
  
  for i in countdown(temp_root.len - 1, 0):
    let blck = db.getBlock(temp_root[i])
    if blck.isSome():
      db.putBlockCold(blck.get)
      db.delBlock(temp_root[i])
    
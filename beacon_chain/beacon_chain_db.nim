# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  typetraits, tables,
  stew/[assign2, byteutils, endians2, io2, objects, results],
  serialization, chronicles, snappy,
  eth/db/[kvstore, kvstore_sqlite3],
  ./networking/network_metadata, ./beacon_chain_db_immutable,
  ./spec/[crypto, datatypes, digest, state_transition],
  ./ssz/[ssz_serialization, merkleization],
  ./eth1/merkle_minimal,
  ./filepath

type
  # TODO when DirStoreRef and helpers are placed in a separate module, kvStore
  #      doesn't find it.. :/
  #      eth/db/kvstore.nim(75, 6) Error: type mismatch: got <DirStoreRef, openArray[byte], openArray[byte]>
  DirStoreRef* = ref object of RootObj
    # DirStore is an experimental storage based on plain files stored in a
    # directory tree - this _might_ be a suitable way of storing large blobs
    # efficiently, where sqlite sometimes struggles - see
    # https://github.com/status-im/nimbus-eth2/issues/2440
    #
    # The issue described by 2440 happens when both blocks and states are all
    # stored in a single, giant table. The slow deletes have since been
    # mitigated by using separate tables.

    root: string

proc splitName(db: DirStoreRef, name: openArray[byte]): tuple[dir, file: string] =
  # Splitting the name helps keep the number of files per directory down - up
  # to 65536 folders will be created
  if name.len() > 2:
    (db.root & "/" & name.toOpenArray(0, 1).toHex(), name.toOpenArray(2, name.high()).toHex())
  else:
    (db.root & "/" & "0000", name.toHex())

proc get*(db: DirStoreRef, key: openArray[byte], onData: DataProc): KvResult[bool] =
  let
    (root, name) = db.splitName(key)
    fileName = root & "/" & name

  var data: seq[byte]

  if readFile(fileName, data).isOk():
    onData(data)
    ok(true)
  else:
    # Serious errors are caught when writing, so we simplify things and say
    # the entry doesn't exist if for any reason we can't read it
    # TODO align this with `contains` that simply checks if the file exists
    ok(false)

proc del*(db: DirStoreRef, key: openArray[byte]): KvResult[void] =
  let
    (root, name) = db.splitName(key)
    fileName = root & "/" & name

  removeFile(fileName).mapErr(ioErrorMsg)

proc contains*(db: DirStoreRef, key: openArray[byte]): KvResult[bool] =
  let
    (root, name) = db.splitName(key)
    fileName = root & "/" & name

  ok(isFile(fileName))

proc put*(db: DirStoreRef, key, val: openArray[byte]): KvResult[void] =
  let
    (root, name) = db.splitName(key)
    fileName = root & "/" & name

  ? createPath(root).mapErr(ioErrorMsg)
  ? io2.writeFile(fileName, val).mapErr(ioErrorMsg)

  ok()

proc close*(db: DirStoreRef): KvResult[void] =
  discard

proc init*(T: type DirStoreRef, root: string): T =
  T(
    root: root,
  )

type
  DbSeq*[T] = object
    insertStmt: SqliteStmt[openArray[byte], void]
    selectStmt: SqliteStmt[int64, openArray[byte]]
    recordCount: int64

  DbMap*[K, V] = object
    db: SqStoreRef
    keyspace: int

  DepositsSeq = DbSeq[DepositData]
  ImmutableValidatorsSeq = DbSeq[ImmutableValidatorData]

  DepositsMerkleizer* = SszMerkleizer[depositContractLimit]

  DepositContractSnapshot* = object
    eth1Block*: Eth2Digest
    depositContractState*: DepositContractState

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
    preset*: RuntimePreset
    genesisDeposits*: DepositsSeq

    # ImmutableValidatorsSeq only stores the total count; it's a proxy for SQL
    # queries.
    immutableValidators*: ImmutableValidatorsSeq
    immutableValidatorsMem*: seq[ImmutableValidatorData]

    checkpoint*: proc() {.gcsafe, raises: [Defect].}

    stateStore: KvStoreRef

  Keyspaces* = enum
    defaultKeyspace = "kvstore"
    validatorIndexFromPubKey # Unused (?)
    stateNoValidators = "state_no_validators"

  DbKeyKind = enum
    kHashToState
    kHashToBlock
    kHeadBlock
      ## Pointer to the most recent block selected by the fork choice
    kTailBlock
      ## Pointer to the earliest finalized block - this is the genesis block when
      ## the chain starts, but might advance as the database gets pruned
      ## TODO: determine how aggressively the database should be pruned. For a
      ##       healthy network sync, we probably need to store blocks at least
      ##       past the weak subjectivity period.
    kBlockSlotStateRoot
      ## BlockSlot -> state_root mapping
    kGenesisBlockRoot
      ## Immutable reference to the network genesis state
      ## (needed for satisfying requests to the beacon node API).
    kEth1PersistedTo
      ## (Obsolete) Used to point to the the latest ETH1 block hash which
      ## satisfied the follow distance and had its deposits persisted to disk.
    kDepositsFinalizedByEth1
      ## A merkleizer checkpoint which can be used for computing the
      ## `deposit_root` of all eth1 finalized deposits (i.e. deposits
      ## confirmed by ETH1_FOLLOW_DISTANCE blocks). The `deposit_root`
      ## is acknowledged and confirmed by the attached web3 provider.
    kDepositsFinalizedByEth2
      ## A merkleizer checkpoint used for computing merkle proofs of
      ## deposits added to Eth2 blocks (it may lag behind the finalized
      ## eth1 deposits checkpoint).
    kHashToBlockSummary
      ## Cache of beacon block summaries - during startup when we construct the
      ## chain dag, loading full blocks takes a lot of time - the block
      ## summary contains a minimal snapshot of what's needed to instanciate
      ## the BlockRef tree.
    kSpeculativeDeposits
      ## A merkelizer checkpoint created on the basis of deposit events
      ## that we were not able to verify against a `deposit_root` served
      ## by the web3 provider. This may happen on Geth nodes that serve
      ## only recent contract state data (i.e. only recent `deposit_roots`).
    kHashToStateDiff
      ## Instead of storing full BeaconStates, one can store only the diff from
      ## a different state. As 75% of a typical BeaconState's serialized form's
      ## the validators, which are mostly immutable and append-only, just using
      ## a simple append-diff representation helps significantly. Various roots
      ## are stored in a mod-increment pattern across fixed-sized arrays, which
      ## addresses most of the rest of the BeaconState sizes.
    kHashToStateOnlyMutableValidators

  BeaconBlockSummary* = object
    slot*: Slot
    parent_root*: Eth2Digest

const
  # The largest object we're saving is the BeaconState, and by far, the largest
  # part of it is the validator - each validator takes up at least 129 bytes
  # in phase0,  which means 100k validators is >12mb - in addition to this,
  # there are several MB of hashes.
  maxDecompressedDbRecordSize = 64*1024*1024

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

func subkey(
    kind: type BeaconStateNoImmutableValidators, key: Eth2Digest): auto =
  subkey(kHashToStateOnlyMutableValidators, key.data)

func subkey(kind: type SignedBeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)

func subkey(kind: type BeaconBlockSummary, key: Eth2Digest): auto =
  subkey(kHashToBlockSummary, key.data)

func subkey(kind: type BeaconStateDiff, key: Eth2Digest): auto =
  subkey(kHashToStateDiff, key.data)

func subkey(root: Eth2Digest, slot: Slot): array[40, byte] =
  var ret: array[40, byte]
  # big endian to get a naturally ascending order on slots in sorted indices
  ret[0..<8] = toBytesBE(slot.uint64)
  # .. but 7 bytes should be enough for slots - in return, we get a nicely
  # rounded key length
  ret[0] = byte ord(kBlockSlotStateRoot)
  ret[8..<40] = root.data

  ret

template panic =
  # TODO(zah): Could we recover from a corrupted database?
  #            Review all usages.
  raiseAssert "The database should not be corrupted"

proc init*[T](Seq: type DbSeq[T], db: SqStoreRef, name: string): Seq =
  db.exec("""
    CREATE TABLE IF NOT EXISTS """ & name & """(
       id INTEGER PRIMARY KEY,
       value BLOB
    );
  """).expect "working database (disk broken/full?)"

  let
    insertStmt = db.prepareStmt(
      "INSERT INTO " & name & "(value) VALUES (?);",
      openArray[byte], void).expect("this is a valid statement")

    selectStmt = db.prepareStmt(
      "SELECT value FROM " & name & " WHERE id = ?;",
      int64, openArray[byte]).expect("this is a valid statement")

    countStmt = db.prepareStmt(
      "SELECT COUNT(1) FROM " & name & ";",
      NoParams, int64).expect("this is a valid statement")

  var recordCount = int64 0
  let countQueryRes = countStmt.exec do (res: int64):
    recordCount = res

  let found = countQueryRes.expect("working database (disk broken/full?)")
  if not found: panic()

  Seq(insertStmt: insertStmt,
      selectStmt: selectStmt,
      recordCount: recordCount)

proc add*[T](s: var DbSeq[T], val: T) =
  var bytes = SSZ.encode(val)
  s.insertStmt.exec(bytes).expect "working database (disk broken/full?)"
  inc s.recordCount

template len*[T](s: DbSeq[T]): int64 =
  s.recordCount

proc get*[T](s: DbSeq[T], idx: int64): T =
  # This is used only locally
  let resultAddr = addr result

  let queryRes = s.selectStmt.exec(idx + 1) do (recordBytes: openArray[byte]):
    try:
      resultAddr[] = decode(SSZ, recordBytes, T)
    except SerializationError:
      panic()

  let found = queryRes.expect("working database (disk broken/full?)")
  if not found: panic()

proc createMap*(db: SqStoreRef, keyspace: int;
                K, V: distinct type): DbMap[K, V] =
  DbMap[K, V](db: db, keyspace: keyspace)

proc insert*[K, V](m: var DbMap[K, V], key: K, value: V) =
  m.db.put(m.keyspace, SSZ.encode key, SSZ.encode value).expect("working database (disk broken/full?)")

proc contains*[K, V](m: DbMap[K, V], key: K): bool =
  contains(m.db, SSZ.encode key).expect("working database (disk broken/full?)")

template insert*[K, V](t: var Table[K, V], key: K, value: V) =
  add(t, key, value)

proc loadImmutableValidators(db: BeaconChainDB): seq[ImmutableValidatorData] =
  # TODO not called, but build fails otherwise
  for i in 0 ..< db.immutableValidators.len:
    result.add db.immutableValidators.get(i)

type
  SqKeyspaceStoreRef* = ref object of RootObj
    # Wrapper around SqStoreRef to target a particular keyspace - using
    # keyspaces helps keep performance decent when using large blobs in tables
    # that otherwise contain lots of rows.
    db: SqStoreRef
    keyspace: int

proc get*(db: SqKeyspaceStoreRef, key: openArray[byte], onData: DataProc): KvResult[bool] =
  get(db.db, db.keyspace, key, onData)

proc del*(db: SqKeyspaceStoreRef, key: openArray[byte]): KvResult[void] =
  del(db.db, db.keyspace, key)

proc contains*(db: SqKeyspaceStoreRef, key: openArray[byte]): KvResult[bool] =
  contains(db.db, db.keyspace, key)

proc put*(db: SqKeyspaceStoreRef, key, val: openArray[byte]): KvResult[void] =
  put(db.db, db.keyspace, key, val)

proc close*(db: SqKeyspaceStoreRef): KvResult[void] =
  ok() # Gets closed with the "default" keyspace

proc init(T: type SqKeyspaceStoreRef, db: SqStoreRef, keyspace: Keyspaces): T =
  T(
    db: db,
    keyspace: int(keyspace)
  )

proc new*(T: type BeaconChainDB,
          preset: RuntimePreset,
          dir: string,
          inMemory = false,
          fileStateStorage = false,
    ): BeaconChainDB =
  var sqliteStore = if inMemory:
      SqStoreRef.init("", "test", Keyspaces, inMemory = true).expect(
        "working database (out of memory?)")
    else:
      let s = secureCreatePath(dir)
      doAssert s.isOk # TODO(zah) Handle this in a better way

      SqStoreRef.init(
        dir, "nbc", Keyspaces,
        manualCheckpoint = true).expect("working database (disk broken/full?)")

  # Remove the deposits table we used before we switched
  # to storing only deposit contract checkpoints
  if sqliteStore.exec("DROP TABLE IF EXISTS deposits;").isErr:
    debug "Failed to drop the deposits table"

  var
    genesisDepositsSeq =
      DbSeq[DepositData].init(sqliteStore, "genesis_deposits")
    immutableValidatorsSeq =
      DbSeq[ImmutableValidatorData].init(sqliteStore, "immutable_validators")
    backend = kvStore sqliteStore
    stateStore =
      if inMemory or (not fileStateStorage):
        kvStore SqKeyspaceStoreRef.init(sqliteStore, stateNoValidators)
      else:
        kvStore DirStoreRef.init(dir & "/state")

  T(backend: backend,
    preset: preset,
    genesisDeposits: genesisDepositsSeq,
    immutableValidators: immutableValidatorsSeq,
    immutableValidatorsMem: loadImmutableValidators(immutableValidatorsSeq),
    checkpoint: proc() = sqliteStore.checkpoint(),
    stateStore: stateStore,
    )

proc snappyEncode(inp: openArray[byte]): seq[byte] =
  try:
    snappy.encode(inp)
  except CatchableError as err:
    raiseAssert err.msg

proc sszEncode(v: auto): seq[byte] =
  try:
    SSZ.encode(v)
  except IOError as err:
    # In-memory encode shouldn't fail!
    raiseAssert err.msg

proc putRaw(db: KvStoreRef, key: openArray[byte], v: Eth2Digest) =
  db.put(key, v.data).expect("working database (disk broken/full?)")

proc putEncoded(db: KvStoreRef, key: openArray[byte], v: auto) =
  db.put(key, snappyEncode(sszEncode(v))).expect(
    "working database (disk broken/full?)")

proc getRaw(db: KvStoreRef, key: openArray[byte], T: type Eth2Digest): Opt[T] =
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

  discard db.get(key, decode).expect("working database (disk broken/full?)")

  res

type GetResult = enum
  found = "Found"
  notFound = "Not found"
  corrupted = "Corrupted"

proc getEncoded[T](db: KvStoreRef, key: openArray[byte], output: var T): GetResult =
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

  discard db.get(key, decode).expect("working database (disk broken/full?)")

  status

proc close*(db: BeaconChainDB) =
  discard db.backend.close()

func toBeaconBlockSummary(v: SomeBeaconBlock): BeaconBlockSummary =
  BeaconBlockSummary(
    slot: v.slot,
    parent_root: v.parent_root,
  )

# TODO: we should only store TrustedSignedBeaconBlock in the DB.
proc putBlock*(db: BeaconChainDB, value: SignedBeaconBlock) =
  db.backend.putEncoded(subkey(type value, value.root), value)
  db.backend.putEncoded(
    subkey(BeaconBlockSummary, value.root), value.message.toBeaconBlockSummary())
proc putBlock*(db: BeaconChainDB, value: TrustedSignedBeaconBlock) =
  db.backend.putEncoded(subkey(SignedBeaconBlock, value.root), value)
  db.backend.putEncoded(
    subkey(BeaconBlockSummary, value.root), value.message.toBeaconBlockSummary())
proc putBlock*(db: BeaconChainDB, value: SigVerifiedSignedBeaconBlock) =
  db.backend.putEncoded(subkey(SignedBeaconBlock, value.root), value)
  db.backend.putEncoded(
    subkey(BeaconBlockSummary, value.root), value.message.toBeaconBlockSummary())

proc updateImmutableValidators(
    db: BeaconChainDB, immutableValidators: var seq[ImmutableValidatorData],
    validators: auto) =
  let
    numValidators = validators.lenu64
    origNumImmutableValidators = immutableValidators.lenu64

  doAssert immutableValidators.len == db.immutableValidators.len

  if numValidators <= origNumImmutableValidators:
    return

  for validatorIndex in origNumImmutableValidators ..< numValidators:
    # This precedes state storage
    let immutableValidator =
      getImmutableValidatorData(validators[validatorIndex])
    db.immutableValidators.add immutableValidator
    immutableValidators.add immutableValidator

proc putState*(db: BeaconChainDB, key: Eth2Digest, value: var BeaconState) =
  updateImmutableValidators(db, db.immutableValidatorsMem, value.validators)
  db.stateStore.putEncoded(
    subkey(BeaconStateNoImmutableValidators, key),
    isomorphicCast[BeaconStateNoImmutableValidators](value))

proc putState*(db: BeaconChainDB, value: var BeaconState) =
  db.putState(hash_tree_root(value), value)

proc putStateFull*(db: BeaconChainDB, key: Eth2Digest, value: BeaconState) =
  db.backend.putEncoded(subkey(BeaconState, key), value)

proc putStateFull*(db: BeaconChainDB, value: BeaconState) =
  db.putStateFull(hash_tree_root(value), value)

proc putStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot,
    value: Eth2Digest) =
  db.backend.putRaw(subkey(root, slot), value)

proc putStateDiff*(db: BeaconChainDB, root: Eth2Digest, value: BeaconStateDiff) =
  db.backend.putEncoded(subkey(BeaconStateDiff, root), value)

proc delBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.del(subkey(SignedBeaconBlock, key)).expect("working database (disk broken/full?)")
  db.backend.del(subkey(BeaconBlockSummary, key)).expect("working database (disk broken/full?)")

proc delState*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.del(subkey(BeaconState, key)).expect("working database (disk broken/full?)")
  db.stateStore.del(subkey(BeaconStateNoImmutableValidators, key)).expect(
    "working filesystem (disk broken/full?)")

proc delStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot) =
  db.backend.del(subkey(root, slot)).expect("working database (disk broken/full?)")

proc delStateDiff*(db: BeaconChainDB, root: Eth2Digest) =
  db.backend.del(subkey(BeaconStateDiff, root)).expect("working database (disk broken/full?)")

proc putHeadBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.putRaw(subkey(kHeadBlock), key)

proc putTailBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.putRaw(subkey(kTailBlock), key)

proc putGenesisBlockRoot*(db: BeaconChainDB, key: Eth2Digest) =
  db.backend.putRaw(subkey(kGenesisBlockRoot), key)

proc putEth1FinalizedTo*(db: BeaconChainDB,
                         eth1Checkpoint: DepositContractSnapshot) =
  db.backend.putEncoded(subkey(kDepositsFinalizedByEth1), eth1Checkpoint)

proc putEth2FinalizedTo*(db: BeaconChainDB,
                         eth1Checkpoint: DepositContractSnapshot) =
  db.backend.putEncoded(subkey(kDepositsFinalizedByEth2), eth1Checkpoint)

proc putSpeculativeDeposits*(db: BeaconChainDB,
                             eth1Checkpoint: DepositContractSnapshot) =
  db.backend.putEncoded(subkey(kSpeculativeDeposits), eth1Checkpoint)

proc getBlock*(db: BeaconChainDB, key: Eth2Digest): Opt[TrustedSignedBeaconBlock] =
  # We only store blocks that we trust in the database
  result.ok(TrustedSignedBeaconBlock())
  if db.backend.getEncoded(subkey(SignedBeaconBlock, key), result.get) != GetResult.found:
    result.err()
  else:
    # set root after deserializing (so it doesn't get zeroed)
    result.get().root = key

proc getBlockSummary*(db: BeaconChainDB, key: Eth2Digest): Opt[BeaconBlockSummary] =
  # We only store blocks that we trust in the database
  result.ok(BeaconBlockSummary())
  if db.backend.getEncoded(subkey(BeaconBlockSummary, key), result.get) != GetResult.found:
    result.err()

proc getStateOnlyMutableValidators(
    db: BeaconChainDB, store: KvStoreRef, key: Eth2Digest, output: var BeaconState,
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

  case store.getEncoded(
    subkey(
      BeaconStateNoImmutableValidators, key),
      isomorphicCast[BeaconStateNoImmutableValidators](output))
  of GetResult.found:
    let numValidators = output.validators.len
    doAssert db.immutableValidatorsMem.len >= numValidators

    for i in 0 ..< numValidators:
      let
        # Bypass hash cache invalidation
        dstValidator = addr output.validators.data[i]
        srcValidator = addr db.immutableValidatorsMem[i]

      assign(dstValidator.pubkey, srcValidator.pubkey)
      assign(dstValidator.withdrawal_credentials,
        srcValidator.withdrawal_credentials)

    output.validators.resetCache()

    true
  of GetResult.notFound:
    false
  of GetResult.corrupted:
    rollback(output)
    false

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
  if getStateOnlyMutableValidators(db, db.stateStore, key, output, rollback):
    return true

  case db.backend.getEncoded(subkey(BeaconState, key), output)
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
  db.backend.getRaw(subkey(root, slot), Eth2Digest)

proc getStateDiff*(db: BeaconChainDB,
                   root: Eth2Digest): Opt[BeaconStateDiff] =
  result.ok(BeaconStateDiff())
  if db.backend.getEncoded(subkey(BeaconStateDiff, root), result.get) != GetResult.found:
    result.err

proc getHeadBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.backend.getRaw(subkey(kHeadBlock), Eth2Digest)

proc getTailBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.backend.getRaw(subkey(kTailBlock), Eth2Digest)

proc getGenesisBlockRoot*(db: BeaconChainDB): Eth2Digest =
  db.backend.getRaw(subkey(kGenesisBlockRoot), Eth2Digest).expect(
    "The database must be seeded with the genesis state")

proc getEth1FinalizedTo*(db: BeaconChainDB): Opt[DepositContractSnapshot] =
  result.ok(DepositContractSnapshot())
  let r = db.backend.getEncoded(subkey(kDepositsFinalizedByEth1), result.get)
  if r != found: result.err()

proc getEth2FinalizedTo*(db: BeaconChainDB): Opt[DepositContractSnapshot] =
  result.ok(DepositContractSnapshot())
  let r = db.backend.getEncoded(subkey(kDepositsFinalizedByEth2), result.get)
  if r != found: result.err()

proc getSpeculativeDeposits*(db: BeaconChainDB): Opt[DepositContractSnapshot] =
  result.ok(DepositContractSnapshot())
  let r = db.backend.getEncoded(subkey(kSpeculativeDeposits), result.get)
  if r != found: result.err()

proc delSpeculativeDeposits*(db: BeaconChainDB) =
  db.backend.del(subkey(kSpeculativeDeposits)).expect("working database (disk broken/full?)")

proc containsBlock*(db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(SignedBeaconBlock, key)).expect("working database (disk broken/full?)")

proc containsState*(db: BeaconChainDB, key: Eth2Digest): bool =
  db.stateStore.contains(subkey(BeaconStateNoImmutableValidators, key)).expect(
      "working database  (disk broken/full?)") or
    db.backend.contains(subkey(BeaconState, key)).expect("working database (disk broken/full?)")

proc containsStateDiff*(db: BeaconChainDB, key: Eth2Digest): bool =
  db.backend.contains(subkey(BeaconStateDiff, key)).expect("working database (disk broken/full?)")

proc repairGenesisState*(db: BeaconChainDB, key: Eth2Digest): KvResult[void] =
  # Nimbus 1.0 reads and writes writes genesis BeaconState to `backend`
  # Nimbus 1.1 writes a genesis BeaconStateNoImmutableValidators to `backend` and
  # reads both BeaconState and BeaconStateNoImmutableValidators from `backend`
  # Nimbus 1.2 writes a genesis BeaconStateNoImmutableValidators to `stateStore`
  # and reads BeaconState from `backend` and BeaconStateNoImmutableValidators
  # from `stateStore`. This means that 1.2 cannot read a database created with
  # 1.1 and earlier versions can't read databases created with either of 1.1
  # and 1.2.
  # Here, we will try to repair the database so that no matter what, there will
  # be a `BeaconState` in `backend`:

  if ? db.backend.contains(subkey(BeaconState, key)):
    # No compatibility issues, life goes on
    discard
  elif ? db.backend.contains(subkey(BeaconStateNoImmutableValidators, key)):
    # 1.1 writes this but not a full state - rewrite a full state
    var output = new BeaconState
    if not getStateOnlyMutableValidators(db, db.backend, key, output[], noRollback):
      return err("Cannot load partial state")

    putStateFull(db, output[])
  elif ? db.stateStore.contains(subkey(BeaconStateNoImmutableValidators, key)):
    # 1.2 writes this but not a full state - rewrite a full state
    var output = new BeaconState
    if not getStateOnlyMutableValidators(db, db.stateStore, key, output[], noRollback):
      return err("Cannot load partial state")

    putStateFull(db, output[])

  ok()

iterator getAncestors*(db: BeaconChainDB, root: Eth2Digest):
    TrustedSignedBeaconBlock =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found.

  var
    res: TrustedSignedBeaconBlock
    root = root
  while db.backend.getEncoded(subkey(SignedBeaconBlock, root), res) == GetResult.found:
    res.root = root
    yield res
    root = res.message.parent_root

iterator getAncestorSummaries*(db: BeaconChainDB, root: Eth2Digest):
    tuple[root: Eth2Digest, summary: BeaconBlockSummary] =
  ## Load a chain of ancestors for blck - returns a list of blocks with the
  ## oldest block last (blck will be at result[0]).
  ##
  ## The search will go on until the ancestor cannot be found.

  var
    res: tuple[root: Eth2Digest, summary: BeaconBlockSummary]
    tmp: TrustedSignedBeaconBlock
    root = root

  while true:
    if db.backend.getEncoded(subkey(BeaconBlockSummary, root), res.summary) == GetResult.found:
      res.root = root
      yield res
    elif db.backend.getEncoded(subkey(SignedBeaconBlock, root), tmp) == GetResult.found:
      res.summary = tmp.message.toBeaconBlockSummary()
      db.backend.putEncoded(subkey(BeaconBlockSummary, root), res.summary)
      res.root = root
      yield res
    else:
      break

    root = res.summary.parent_root

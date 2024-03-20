import
  std/[typetraits, tables],
  results,
  stew/[arrayops, byteutils, io2, objects],
  serialization, snappy,
  eth/db/[kvstore, kvstore_sqlite3],
  ./networking/network_metadata,
  ./spec/[eth2_ssz_serialization,
          eth2_merkleization,
          forks,
          presets,
          state_transition],
  ./spec/datatypes/[phase0, altair, bellatrix],
  "."/filepath
from ./spec/datatypes/capella import BeaconState
from ./spec/datatypes/deneb import TrustedSignedBeaconBlock
export
  eth2_ssz_serialization, eth2_merkleization, kvstore,
  kvstore_sqlite3
type
  DbSeq[T] = object
    insertStmt: SqliteStmt[openArray[byte], void]
    selectStmt: SqliteStmt[int64, openArray[byte]]
    recordCount: int64
  FinalizedBlocks = object
    insertStmt: SqliteStmt[(int64, array[32, byte]), void]
    selectStmt: SqliteStmt[int64, array[32, byte]]
    selectAllStmt: SqliteStmt[NoParams, (int64, array[32, byte])]
    low: Opt[Slot]
    high: Opt[Slot]
  DepositsSeq = DbSeq[DepositData]
  BeaconChainDBV0 = ref object
    backend: KvStoreRef # kvstore
    stateStore: KvStoreRef # state_no_validators
  BeaconChainDB* = ref object
    db: SqStoreRef
    v0: BeaconChainDBV0
    genesisDeposits: DepositsSeq
    immutableValidatorsDb: DbSeq[ImmutableValidatorDataDb2]
    immutableValidators: seq[ImmutableValidatorData2]
    checkpoint: proc() {.gcsafe, raises: [].}
    keyValues: KvStoreRef # Random stuff using DbKeyKind - suitable for small values mainly!
    blocks: array[ConsensusFork, KvStoreRef] # BlockRoot -> TrustedSignedBeaconBlock
    blobs: KvStoreRef # (BlockRoot -> BlobSidecar)
    stateRoots: KvStoreRef # (Slot, BlockRoot) -> StateRoot
    statesNoVal: array[ConsensusFork, KvStoreRef] # StateRoot -> ForkBeaconStateNoImmutableValidators
    stateDiffs: KvStoreRef ##\
    summaries: KvStoreRef
    finalizedBlocks: FinalizedBlocks
  DbKeyKind = enum
    kHashToState
    kHashToBlock
    kHeadBlock
    kTailBlock
    kBlockSlotStateRoot
    kGenesisBlock
    kEth1PersistedTo # Obsolete
    kDepositsFinalizedByEth1 # Obsolete
    kOldDepositContractSnapshot
    kHashToBlockSummary # Block summaries for fast startup
    kSpeculativeDeposits
    kHashToStateDiff # Obsolete
    kHashToStateOnlyMutableValidators
    kBackfillBlock # Obsolete, was in `unstable` for a while, but never released
    kDepositTreeSnapshot # EIP-4881-compatible deposit contract state snapshot
  BeaconBlockSummary = object
    slot: Slot
    parent_root: Eth2Digest
func subkey(kind: DbKeyKind): array[1, byte] =
  result[0] = byte ord(kind)
func subkey[N: static int](kind: DbKeyKind, key: array[N, byte]):
    array[N + 1, byte] =
  result[0] = byte ord(kind)
  result[1 .. ^1] = key
func subkey(kind: type phase0.BeaconState, key: Eth2Digest): auto =
  subkey(kHashToState, key.data)
func subkey(kind: type phase0.SignedBeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)
func subkey(kind: type BeaconBlockSummary, key: Eth2Digest): auto =
  subkey(kHashToBlockSummary, key.data)
template expectDb(x: auto): untyped =
  x.expect("working database (disk broken/full?)")
proc init[T](
    Seq: type DbSeq[T], db: SqStoreRef, name: string,
    readOnly = false): KvResult[Seq] =
  let hasTable = if db.readOnly or readOnly:
    ? db.hasTable(name)
  else:
    ? db.exec("""
      CREATE TABLE IF NOT EXISTS '""" & name & """'(
        id INTEGER PRIMARY KEY,
        value BLOB
      );
    """)
    true
  if hasTable:
    let
      insertStmt = db.prepareStmt(
        "INSERT INTO '" & name & "'(value) VALUES (?);",
        openArray[byte], void, managed = false).expect("this is a valid statement")
      selectStmt = db.prepareStmt(
        "SELECT value FROM '" & name & "' WHERE id = ?;",
        int64, openArray[byte], managed = false).expect("this is a valid statement")
      countStmt = db.prepareStmt(
        "SELECT COUNT(1) FROM '" & name & "';",
        NoParams, int64, managed = false).expect("this is a valid statement")
    var recordCount = int64 0
    let countQueryRes = countStmt.exec do (res: int64):
      recordCount = res
    let found = ? countQueryRes
    if not found:
      return err("Cannot count existing items")
    countStmt.dispose()
    ok(Seq(insertStmt: insertStmt,
          selectStmt: selectStmt,
          recordCount: recordCount))
  else:
    ok(Seq())
proc close(s: var DbSeq) =
  s.insertStmt.dispose()
  s.selectStmt.dispose()
  reset(s)
proc add[T](s: var DbSeq[T], val: T) =
  doAssert(distinctBase(s.insertStmt) != nil, "database closed or table not preset")
  let bytes = SSZ.encode(val)
  s.insertStmt.exec(bytes).expectDb()
  inc s.recordCount
template len[T](s: DbSeq[T]): int64 =
  s.recordCount
proc get[T](s: DbSeq[T], idx: int64): T =
  doAssert(distinctBase(s.selectStmt) != nil, $T & " table not present for read at " & $(idx))
  let resultAddr = addr result
  let queryRes = s.selectStmt.exec(idx + 1) do (recordBytes: openArray[byte]):
    try:
      resultAddr[] = decode(SSZ, recordBytes, T)
    except SerializationError as exc:
      raiseAssert "cannot decode " & $T & " at index " & $idx & ": " & exc.msg
  let found = queryRes.expectDb()
  if not found:
    raiseAssert $T & " not found at index " & $(idx)
proc init(T: type FinalizedBlocks, db: SqStoreRef, name: string,
           readOnly = false): KvResult[T] =
  let hasTable = if db.readOnly or readOnly:
    ? db.hasTable(name)
  else:
    ? db.exec("""
      CREATE TABLE IF NOT EXISTS '""" & name & """'(
        id INTEGER PRIMARY KEY,
        value BLOB NOT NULL
      );""")
    true
  if hasTable:
    let
      insertStmt = db.prepareStmt(
        "REPLACE INTO '" & name & "'(id, value) VALUES (?, ?);",
        (int64, array[32, byte]), void, managed = false).expect("this is a valid statement")
      selectStmt = db.prepareStmt(
        "SELECT value FROM '" & name & "' WHERE id = ?;",
        int64, array[32, byte], managed = false).expect("this is a valid statement")
      selectAllStmt = db.prepareStmt(
        "SELECT id, value FROM '" & name & "' ORDER BY id;",
        NoParams, (int64, array[32, byte]), managed = false).expect("this is a valid statement")
      maxIdStmt = db.prepareStmt(
        "SELECT MAX(id) FROM '" & name & "';",
        NoParams, Option[int64], managed = false).expect("this is a valid statement")
      minIdStmt = db.prepareStmt(
        "SELECT MIN(id) FROM '" & name & "';",
        NoParams, Option[int64], managed = false).expect("this is a valid statement")
    var
      low, high: Opt[Slot]
      tmp: Option[int64]
    for rowRes in minIdStmt.exec(tmp):
      expectDb rowRes
      if tmp.isSome():
        low.ok(Slot(tmp.get()))
    for rowRes in maxIdStmt.exec(tmp):
      expectDb rowRes
      if tmp.isSome():
        high.ok(Slot(tmp.get()))
    maxIdStmt.dispose()
    minIdStmt.dispose()
    ok(T(insertStmt: insertStmt,
          selectStmt: selectStmt,
          selectAllStmt: selectAllStmt,
          low: low,
          high: high))
  else:
    ok(T())
proc close(s: var FinalizedBlocks) =
  s.insertStmt.dispose()
  s.selectStmt.dispose()
  s.selectAllStmt.dispose()
  reset(s)
proc get(s: FinalizedBlocks, idx: Slot): Opt[Eth2Digest] =
  if distinctBase(s.selectStmt) == nil: return Opt.none(Eth2Digest)
  var row: s.selectStmt.Result
  for rowRes in s.selectStmt.exec(int64(idx), row):
    expectDb rowRes
    return ok(Eth2Digest(data: row))
  return Opt.none(Eth2Digest)
proc loadImmutableValidators(vals: DbSeq[ImmutableValidatorDataDb2]): seq[ImmutableValidatorData2] =
  result = newSeqOfCap[ImmutableValidatorData2](vals.len())
  for i in 0 ..< vals.len:
    let tmp = vals.get(i)
    result.add ImmutableValidatorData2(
      pubkey: tmp.pubkey.loadValid(),
      withdrawal_credentials: tmp.withdrawal_credentials)
proc new(T: type BeaconChainDBV0,
          db: SqStoreRef,
          readOnly = false
    ): BeaconChainDBV0 =
  BeaconChainDBV0(
  )
proc new*(T: type BeaconChainDB,
          db: SqStoreRef,
          cfg: RuntimeConfig = defaultRuntimeConfig
    ): BeaconChainDB =
  if not db.readOnly:
    discard db.exec("DROP TABLE IF EXISTS deposits;")
    discard db.exec("DROP TABLE IF EXISTS validatorIndexFromPubKey;")
  var
    genesisDepositsSeq =
      DbSeq[DepositData].init(db, "genesis_deposits").expectDb()
    immutableValidatorsDb =
      DbSeq[ImmutableValidatorDataDb2].init(db, "immutable_validators2").expectDb()
    keyValues = kvStore db.openKvStore("key_values", true).expectDb()
    blocks = [
      kvStore db.openKvStore("blocks").expectDb(),
      kvStore db.openKvStore("altair_blocks").expectDb(),
      kvStore db.openKvStore("bellatrix_blocks").expectDb(),
      kvStore db.openKvStore("capella_blocks").expectDb(),
      kvStore db.openKvStore("deneb_blocks").expectDb(),
      kvStore db.openKvStore("electra_blocks").expectDb()]
    stateRoots = kvStore db.openKvStore("state_roots", true).expectDb()
    statesNoVal = [
      kvStore db.openKvStore("state_no_validators2").expectDb(),
      kvStore db.openKvStore("altair_state_no_validators").expectDb(),
      kvStore db.openKvStore("bellatrix_state_no_validators").expectDb(),
      kvStore db.openKvStore("capella_state_no_validator_pubkeys").expectDb(),
      kvStore db.openKvStore("deneb_state_no_validator_pubkeys").expectDb(),
      kvStore db.openKvStore("electra_state_no_validator_pubkeys").expectDb()]
    stateDiffs = kvStore db.openKvStore("state_diffs").expectDb()
    summaries = kvStore db.openKvStore("beacon_block_summaries", true).expectDb()
    finalizedBlocks = FinalizedBlocks.init(db, "finalized_blocks").expectDb()
  var blobs : KvStoreRef
  if cfg.DENEB_FORK_EPOCH != FAR_FUTURE_EPOCH:
    blobs = kvStore db.openKvStore("deneb_blobs").expectDb()
  block:
    var immutableValidatorsDb1 = DbSeq[ImmutableValidatorData].init(
      db, "immutable_validators", readOnly = true).expectDb()
    if immutableValidatorsDb.len() < immutableValidatorsDb1.len():
      while immutableValidatorsDb.len() < immutableValidatorsDb1.len():
        let val = immutableValidatorsDb1.get(immutableValidatorsDb.len())
        immutableValidatorsDb.add(ImmutableValidatorDataDb2(
          pubkey: val.pubkey.loadValid().toUncompressed(),
          withdrawal_credentials: val.withdrawal_credentials
        ))
    immutableValidatorsDb1.close()
    if not db.readOnly:
      discard db.exec("DROP TABLE IF EXISTS immutable_validators;")
  T(
    db: db,
    v0: BeaconChainDBV0.new(db, readOnly = true),
    genesisDeposits: genesisDepositsSeq,
    immutableValidatorsDb: immutableValidatorsDb,
    immutableValidators: loadImmutableValidators(immutableValidatorsDb),
    checkpoint: proc() = db.checkpoint(),
    keyValues: keyValues,
    blocks: blocks,
    blobs: blobs,
    stateRoots: stateRoots,
    statesNoVal: statesNoVal,
    stateDiffs: stateDiffs,
    summaries: summaries,
    finalizedBlocks: finalizedBlocks
  )
proc new*(T: type BeaconChainDB,
          dir: string,
          cfg: RuntimeConfig = defaultRuntimeConfig,
          inMemory = false,
          readOnly = false
    ): BeaconChainDB =
  let db =
    if inMemory:
      SqStoreRef.init("", "test", readOnly = readOnly, inMemory = true).expect(
        "working database (out of memory?)")
    else:
      if (let res = secureCreatePath(dir); res.isErr):
        quit 1
      SqStoreRef.init(
        dir, "nbc", readOnly = readOnly, manualCheckpoint = true).expectDb()
  BeaconChainDB.new(db, cfg)

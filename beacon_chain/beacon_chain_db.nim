# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[typetraits, tables],
  stew/[arrayops, assign2, byteutils, endians2, io2, objects, results],
  serialization, chronicles, snappy,
  eth/db/[kvstore, kvstore_sqlite3],
  ./networking/network_metadata, ./beacon_chain_db_immutable,
  ./spec/[deposit_snapshots,
          eth2_ssz_serialization,
          eth2_merkleization,
          forks,
          presets,
          state_transition],
  ./spec/datatypes/[phase0, altair, bellatrix],
  "."/[beacon_chain_db_light_client, filepath]

from ./spec/datatypes/capella import BeaconState
from ./spec/datatypes/deneb import TrustedSignedBeaconBlock

export
  phase0, altair, eth2_ssz_serialization, eth2_merkleization, kvstore,
  kvstore_sqlite3

logScope: topics = "bc_db"

type
  DbSeq*[T] = object
    insertStmt: SqliteStmt[openArray[byte], void]
    selectStmt: SqliteStmt[int64, openArray[byte]]
    recordCount: int64

  FinalizedBlocks* = object
    # A sparse version of DbSeq - can have holes but not duplicate entries
    insertStmt: SqliteStmt[(int64, array[32, byte]), void]
    selectStmt: SqliteStmt[int64, array[32, byte]]
    selectAllStmt: SqliteStmt[NoParams, (int64, array[32, byte])]

    low*: Opt[Slot]
    high*: Opt[Slot]

  DepositsSeq = DbSeq[DepositData]

  BeaconChainDBV0* = ref object
    ## BeaconChainDBV0 based on old kvstore table that sets the WITHOUT ROWID
    ## option which becomes unbearably slow with large blobs. It is used as a
    ## read-only store to support old versions - by freezing it at its current
    ## data set, downgrading remains possible since it's no longer touched -
    ## anyone downgrading will have to sync up whatever they missed.
    ##
    ## Newer versions read from the new tables first - if the data is not found,
    ## they turn to the old tables for reading. Writing is done only to the new
    ## tables.
    ##
    ## V0 stored most data in a single table, prefixing each key with a tag
    ## identifying the type of data.
    ##
    ## 1.1 introduced BeaconStateNoImmutableValidators storage where immutable
    ## validator data is stored in a separate table and only a partial
    ## BeaconState is written to kvstore
    ##
    ## 1.2 moved BeaconStateNoImmutableValidators to a separate table to
    ## alleviate some of the btree balancing issues - this doubled the speed but
    ## was still slow
    ##
    ## 1.3 creates `kvstore` with rowid, making it quite fast, but doesn't do
    ## anything about existing databases. Versions after that use a separate
    ## file instead (V1)
    ##
    ## Starting with bellatrix, we store blocks and states using snappy framed
    ## encoding so as to match the `Req`/`Resp` protocols and era files ("SZ").
    backend: KvStoreRef # kvstore
    stateStore: KvStoreRef # state_no_validators

  BeaconChainDB* = ref object
    ## Database storing resolved blocks and states - resolved blocks are such
    ## blocks that form a chain back to the tail block.
    ##
    ## We assume that the database backend is working / not corrupt - as such,
    ## we will raise a Defect any time there is an issue. This should be
    ## revisited in the future, when/if the calling code safely can handle
    ## corruption of this kind.
    ##
    ## The database follows an "mostly-consistent" model where it's possible
    ## that some data has been lost to crashes and restarts - for example,
    ## the state root table might contain entries that don't lead to a state
    ## etc - this makes it easier to defer certain operations such as pruning
    ## and cleanup, but also means that some amount of "junk" is left behind
    ## when the application is restarted or crashes in the wrong moment.
    ##
    ## Generally, sqlite performs a commit at the end of every write, meaning
    ## that data write order is respected - the strategy thus becomes to write
    ## bulk data first, then update pointers like the `head root` entry.
    db*: SqStoreRef

    v0: BeaconChainDBV0
    genesisDeposits*: DepositsSeq

    # immutableValidatorsDb only stores the total count; it's a proxy for SQL
    # queries. (v1.4.0+)
    immutableValidatorsDb*: DbSeq[ImmutableValidatorDataDb2]
    immutableValidators*: seq[ImmutableValidatorData2]

    checkpoint*: proc() {.gcsafe, raises: [].}

    keyValues: KvStoreRef # Random stuff using DbKeyKind - suitable for small values mainly!
    blocks: array[ConsensusFork, KvStoreRef] # BlockRoot -> TrustedSignedBeaconBlock

    blobs: KvStoreRef # (BlockRoot -> BlobSidecar)

    stateRoots: KvStoreRef # (Slot, BlockRoot) -> StateRoot

    statesNoVal: array[ConsensusFork, KvStoreRef] # StateRoot -> ForkBeaconStateNoImmutableValidators

    stateDiffs: KvStoreRef ##\
      ## StateRoot -> BeaconStateDiff
      ## Instead of storing full BeaconStates, one can store only the diff from
      ## a different state. As 75% of a typical BeaconState's serialized form's
      ## the validators, which are mostly immutable and append-only, just using
      ## a simple append-diff representation helps significantly. Various roots
      ## are stored in a mod-increment pattern across fixed-sized arrays, which
      ## addresses most of the rest of the BeaconState sizes.

    summaries: KvStoreRef
      ## BlockRoot -> BeaconBlockSummary - permits looking up basic block
      ## information via block root - contains only summaries that were valid
      ## at some point in history - it is however possible that entries exist
      ## that are no longer part of the finalized chain history, thus the
      ## cache should not be used to answer fork choice questions - see
      ## `getHeadBlock` and `finalizedBlocks` instead.
      ##
      ## May contain entries for blocks that are not stored in the database.
      ##
      ## See `finalizedBlocks` for an index in the other direction.

    finalizedBlocks*: FinalizedBlocks
      ## Blocks that are known to be finalized, per the latest head (v1.7.0+)
      ## Only blocks that have passed verification, either via state transition
      ## or backfilling are indexed here - thus, similar to `head`, it is part
      ## of the inner security ring and is used to answer security questions
      ## in the chaindag.
      ##
      ## May contain entries for blocks that are not stored in the database.
      ##
      ## See `summaries` for an index in the other direction.

    lcData: LightClientDataDB
      ## Persistent light client data to avoid expensive recomputations

  DbKeyKind* = enum
    # BEWARE. You should never remove entries from this enum.
    #         Only new items should be added to its end.
    kHashToState
    kHashToBlock
    kHeadBlock
      ## Pointer to the most recent block selected by the fork choice
    kTailBlock
      ## Pointer to the earliest finalized block - this is the genesis
      ## block when the chain starts, but might advance as the database
      ## gets pruned
      ## TODO: determine how aggressively the database should be pruned.
      ##       For a healthy network sync, we probably need to store blocks
      ##       at least past the weak subjectivity period.
    kBlockSlotStateRoot
      ## BlockSlot -> state_root mapping
    kGenesisBlock
      ## Immutable reference to the network genesis state
      ## (needed for satisfying requests to the beacon node API).
    kEth1PersistedTo # Obsolete
    kDepositsFinalizedByEth1 # Obsolete
    kOldDepositContractSnapshot
      ## Deprecated:
      ## This was the merkleizer checkpoint produced by processing the
      ## finalized deposits (similar to kDepositTreeSnapshot, but before
      ## the EIP-4881 support was introduced). Currently, we read from
      ## it during upgrades and we keep writing data to it as a measure
      ## allowing the users to downgrade to a previous version of Nimbus.
    kHashToBlockSummary # Block summaries for fast startup
    kSpeculativeDeposits
      ## Obsolete:
      ## This was a merkelizer checkpoint created on the basis of deposit
      ## events that we were not able to verify against a `deposit_root`
      ## served by the web3 provider. This was happening on Geth nodes
      ## that serve only recent contract state data (i.e. only recent
      ## `deposit_roots`).
    kHashToStateDiff # Obsolete
    kHashToStateOnlyMutableValidators
    kBackfillBlock # Obsolete, was in `unstable` for a while, but never released
    kDepositTreeSnapshot # EIP-4881-compatible deposit contract state snapshot

  BeaconBlockSummary* = object
    ## Cache of beacon block summaries - during startup when we construct the
    ## chain dag, loading full blocks takes a lot of time - the block
    ## summary contains a minimal snapshot of what's needed to instanciate
    ## the BlockRef tree.
    slot*: Slot
    parent_root*: Eth2Digest

# Subkeys essentially create "tables" within the key-value store by prefixing
# each entry with a table id

func subkey(kind: DbKeyKind): array[1, byte] =
  result[0] = byte ord(kind)

func subkey[N: static int](kind: DbKeyKind, key: array[N, byte]):
    array[N + 1, byte] =
  result[0] = byte ord(kind)
  result[1 .. ^1] = key

func subkey(kind: type phase0.BeaconState, key: Eth2Digest): auto =
  subkey(kHashToState, key.data)

func subkey(
    kind: type Phase0BeaconStateNoImmutableValidators, key: Eth2Digest): auto =
  subkey(kHashToStateOnlyMutableValidators, key.data)

func subkey(kind: type phase0.SignedBeaconBlock, key: Eth2Digest): auto =
  subkey(kHashToBlock, key.data)

func subkey(kind: type BeaconBlockSummary, key: Eth2Digest): auto =
  subkey(kHashToBlockSummary, key.data)

func subkey(root: Eth2Digest, slot: Slot): array[40, byte] =
  var ret: array[40, byte]
  # big endian to get a naturally ascending order on slots in sorted indices
  ret[0..<8] = toBytesBE(slot.uint64)
  # .. but 7 bytes should be enough for slots - in return, we get a nicely
  # rounded key length
  ret[0] = byte ord(kBlockSlotStateRoot)
  ret[8..<40] = root.data

  ret

func blobkey(root: Eth2Digest, index: BlobIndex) : array[40, byte] =
  var ret: array[40, byte]
  ret[0..<8] = toBytes(index)
  ret[8..<40] = root.data

  ret

template expectDb(x: auto): untyped =
  # There's no meaningful error handling implemented for a corrupt database or
  # full disk - this requires manual intervention, so we'll panic for now
  x.expect("working database (disk broken/full?)")

proc init*[T](
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

proc close*(s: var DbSeq) =
  s.insertStmt.dispose()
  s.selectStmt.dispose()

  reset(s)

proc add*[T](s: var DbSeq[T], val: T) =
  doAssert(distinctBase(s.insertStmt) != nil, "database closed or table not preset")
  let bytes = SSZ.encode(val)
  s.insertStmt.exec(bytes).expectDb()
  inc s.recordCount

template len*[T](s: DbSeq[T]): int64 =
  s.recordCount

proc get*[T](s: DbSeq[T], idx: int64): T =
  # This is used only locally
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

proc init*(T: type FinalizedBlocks, db: SqStoreRef, name: string,
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

proc close*(s: var FinalizedBlocks) =
  s.insertStmt.dispose()
  s.selectStmt.dispose()
  s.selectAllStmt.dispose()
  reset(s)

proc insert*(s: var FinalizedBlocks, slot: Slot, val: Eth2Digest) =
  doAssert slot.uint64 < int64.high.uint64, "Only reasonable slots supported"
  doAssert(distinctBase(s.insertStmt) != nil, "database closed or table not present")

  s.insertStmt.exec((slot.int64, val.data)).expectDb()
  s.low.ok(min(slot, s.low.get(slot)))
  s.high.ok(max(slot, s.high.get(slot)))

proc get*(s: FinalizedBlocks, idx: Slot): Opt[Eth2Digest] =
  if distinctBase(s.selectStmt) == nil: return Opt.none(Eth2Digest)
  var row: s.selectStmt.Result
  for rowRes in s.selectStmt.exec(int64(idx), row):
    expectDb rowRes
    return ok(Eth2Digest(data: row))

  return Opt.none(Eth2Digest)

iterator pairs*(s: FinalizedBlocks): (Slot, Eth2Digest) =
  if distinctBase(s.selectAllStmt) != nil:
    var row: s.selectAllStmt.Result
    for rowRes in s.selectAllStmt.exec(row):
      expectDb rowRes
      yield (Slot(row[0]), Eth2Digest(data: row[1]))

proc loadImmutableValidators(vals: DbSeq[ImmutableValidatorDataDb2]): seq[ImmutableValidatorData2] =
  result = newSeqOfCap[ImmutableValidatorData2](vals.len())
  for i in 0 ..< vals.len:
    let tmp = vals.get(i)
    result.add ImmutableValidatorData2(
      pubkey: tmp.pubkey.loadValid(),
      withdrawal_credentials: tmp.withdrawal_credentials)

template withManyWrites*(dbParam: BeaconChainDB, body: untyped) =
  let
    db = dbParam
    nested = isInsideTransaction(db.db)

  # We don't enforce strong ordering or atomicity requirements in the beacon
  # chain db in general, relying instead on readers to be able to deal with
  # minor inconsistencies - however, putting writes in a transaction is orders
  # of magnitude faster when doing many small writes, so we use this as an
  # optimization technique and the templace is named accordingly.
  if not nested:
    expectDb db.db.exec("BEGIN TRANSACTION;")
  var commit = false
  try:
      body
      commit = true
  finally:
    if not nested:
      if commit:
        expectDb db.db.exec("COMMIT TRANSACTION;")
      else:
        # https://www.sqlite.org/lang_transaction.html
        #
        # For all of these errors, SQLite attempts to undo just the one statement
        # it was working on and leave changes from prior statements within the same
        # transaction intact and continue with the transaction. However, depending
        # on the statement being evaluated and the point at which the error occurs,
        # it might be necessary for SQLite to rollback and cancel the entire transaction.
        # An application can tell which course of action SQLite took by using the
        # sqlite3_get_autocommit() C-language interface.
        #
        # It is recommended that applications respond to the errors listed above by
        # explicitly issuing a ROLLBACK command. If the transaction has already been
        # rolled back automatically by the error response, then the ROLLBACK command
        # will fail with an error, but no harm is caused by this.
        #
        if isInsideTransaction(db.db): # calls `sqlite3_get_autocommit`
          expectDb db.db.exec("ROLLBACK TRANSACTION;")

proc new*(T: type BeaconChainDBV0,
          db: SqStoreRef,
          readOnly = false
    ): BeaconChainDBV0 =
  var
    # V0 compatibility tables - these were created WITHOUT ROWID which is slow
    # for large blobs
    backendV0 = kvStore db.openKvStore(
      readOnly = db.readOnly or readOnly).expectDb()
    # state_no_validators is similar to state_no_validators2 but uses a
    # different key encoding and was created WITHOUT ROWID
    stateStoreV0 = kvStore db.openKvStore(
      "state_no_validators", readOnly = db.readOnly or readOnly).expectDb()

  BeaconChainDBV0(
      backend: backendV0,
      stateStore: stateStoreV0,
  )

proc new*(T: type BeaconChainDB,
          db: SqStoreRef,
          cfg: RuntimeConfig = defaultRuntimeConfig
    ): BeaconChainDB =
  if not db.readOnly:
    # Remove the deposits table we used before we switched
    # to storing only deposit contract checkpoints
    if db.exec("DROP TABLE IF EXISTS deposits;").isErr:
      debug "Failed to drop the deposits table"

    # An old pubkey->index mapping that hasn't been used on any mainnet release
    if db.exec("DROP TABLE IF EXISTS validatorIndexFromPubKey;").isErr:
      debug "Failed to drop the validatorIndexFromPubKey table"

  var
    genesisDepositsSeq =
      DbSeq[DepositData].init(db, "genesis_deposits").expectDb()
    immutableValidatorsDb =
      DbSeq[ImmutableValidatorDataDb2].init(db, "immutable_validators2").expectDb()

    # V1 - expected-to-be small rows get without rowid optimizations
    keyValues = kvStore db.openKvStore("key_values", true).expectDb()
    blocks = [
      kvStore db.openKvStore("blocks").expectDb(),
      kvStore db.openKvStore("altair_blocks").expectDb(),
      kvStore db.openKvStore("bellatrix_blocks").expectDb(),
      kvStore db.openKvStore("capella_blocks").expectDb(),
      kvStore db.openKvStore("deneb_blocks").expectDb()]

    stateRoots = kvStore db.openKvStore("state_roots", true).expectDb()

    statesNoVal = [
      kvStore db.openKvStore("state_no_validators2").expectDb(),
      kvStore db.openKvStore("altair_state_no_validators").expectDb(),
      kvStore db.openKvStore("bellatrix_state_no_validators").expectDb(),
      kvStore db.openKvStore("capella_state_no_validator_pubkeys").expectDb(),
      kvStore db.openKvStore("deneb_state_no_validator_pubkeys").expectDb()]

    stateDiffs = kvStore db.openKvStore("state_diffs").expectDb()
    summaries = kvStore db.openKvStore("beacon_block_summaries", true).expectDb()
    finalizedBlocks = FinalizedBlocks.init(db, "finalized_blocks").expectDb()

    lcData = db.initLightClientDataDB(LightClientDataDBNames(
      altairHeaders: "lc_altair_headers",
      capellaHeaders:
        if cfg.CAPELLA_FORK_EPOCH != FAR_FUTURE_EPOCH:
          "lc_capella_headers"
        else:
          "",
      denebHeaders:
        if cfg.DENEB_FORK_EPOCH != FAR_FUTURE_EPOCH:
          "lc_deneb_headers"
        else:
          "",
      altairCurrentBranches: "lc_altair_current_branches",
      altairSyncCommittees: "lc_altair_sync_committees",
      legacyAltairBestUpdates: "lc_altair_best_updates",
      bestUpdates: "lc_best_updates",
      sealedPeriods: "lc_sealed_periods")).expectDb()
  static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb

  var blobs : KvStoreRef
  if cfg.DENEB_FORK_EPOCH != FAR_FUTURE_EPOCH:
    blobs = kvStore db.openKvStore("deneb_blobs").expectDb()

  # Versions prior to 1.4.0 (altair) stored validators in `immutable_validators`
  # which stores validator keys in compressed format - this is
  # slow to load and has been superceded by `immutable_validators2` which uses
  # uncompressed keys instead. We still support upgrading a database from the
  # old format, but don't need to support downgrading, and therefore safely can
  # remove the keys
  block:
    var immutableValidatorsDb1 = DbSeq[ImmutableValidatorData].init(
      db, "immutable_validators", readOnly = true).expectDb()

    if immutableValidatorsDb.len() < immutableValidatorsDb1.len():
      notice "Migrating validator keys, this may take a minute",
        len = immutableValidatorsDb1.len()
      while immutableValidatorsDb.len() < immutableValidatorsDb1.len():
        let val = immutableValidatorsDb1.get(immutableValidatorsDb.len())
        immutableValidatorsDb.add(ImmutableValidatorDataDb2(
          pubkey: val.pubkey.loadValid().toUncompressed(),
          withdrawal_credentials: val.withdrawal_credentials
        ))
    immutableValidatorsDb1.close()

    if not db.readOnly:
      # Safe because nobody will be downgrading to pre-altair versions
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
    finalizedBlocks: finalizedBlocks,
    lcData: lcData
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
        fatal "Failed to create create database directory",
          path = dir, err = ioErrorMsg(res.error)
        quit 1

      SqStoreRef.init(
        dir, "nbc", readOnly = readOnly, manualCheckpoint = true).expectDb()
  BeaconChainDB.new(db, cfg)

template getLightClientDataDB*(db: BeaconChainDB): LightClientDataDB =
  db.lcData

proc decodeSSZ*[T](data: openArray[byte], output: var T): bool =
  try:
    readSszBytes(data, output, updateRoot = false)
    true
  except SerializationError as e:
    # If the data can't be deserialized, it could be because it's from a
    # version of the software that uses a different SSZ encoding
    warn "Unable to deserialize data, old database?",
      err = e.msg, typ = name(T), dataLen = data.len
    false

proc decodeSnappySSZ[T](data: openArray[byte], output: var T): bool =
  try:
    let decompressed = snappy.decode(data)
    readSszBytes(decompressed, output, updateRoot = false)
    true
  except SerializationError as e:
    # If the data can't be deserialized, it could be because it's from a
    # version of the software that uses a different SSZ encoding
    warn "Unable to deserialize data, old database?",
      err = e.msg, typ = name(T), dataLen = data.len
    false

proc decodeSZSSZ[T](data: openArray[byte], output: var T): bool =
  try:
    let decompressed = decodeFramed(data, checkIntegrity = false)
    readSszBytes(decompressed, output, updateRoot = false)
    true
  except CatchableError as e:
    # If the data can't be deserialized, it could be because it's from a
    # version of the software that uses a different SSZ encoding
    warn "Unable to deserialize data, old database?",
      err = e.msg, typ = name(T), dataLen = data.len
    false

func encodeSSZ*(v: auto): seq[byte] =
  try:
    SSZ.encode(v)
  except IOError as err:
    raiseAssert err.msg

func encodeSnappySSZ(v: auto): seq[byte] =
  try:
    snappy.encode(SSZ.encode(v))
  except CatchableError as err:
    # In-memory encode shouldn't fail!
    raiseAssert err.msg

func encodeSZSSZ(v: auto): seq[byte] =
  # https://github.com/google/snappy/blob/main/framing_format.txt
  try:
    encodeFramed(SSZ.encode(v))
  except CatchableError as err:
    # In-memory encode shouldn't fail!
    raiseAssert err.msg

proc getRaw(db: KvStoreRef, key: openArray[byte], T: type Eth2Digest): Opt[T] =
  var res: Opt[T]
  proc decode(data: openArray[byte]) =
    if data.len == sizeof(Eth2Digest):
      res.ok Eth2Digest(data: toArray(sizeof(Eth2Digest), data))
    else:
      # If the data can't be deserialized, it could be because it's from a
      # version of the software that uses a different SSZ encoding
      warn "Unable to deserialize data, old database?",
       typ = name(T), dataLen = data.len
      discard

  discard db.get(key, decode).expectDb()

  res

proc putRaw(db: KvStoreRef, key: openArray[byte], v: Eth2Digest) =
  db.put(key, v.data).expectDb()

type GetResult = enum
  found = "Found"
  notFound = "Not found"
  corrupted = "Corrupted"

proc getSSZ[T](db: KvStoreRef, key: openArray[byte], output: var T): GetResult =
  var status = GetResult.notFound

  let outputPtr = addr output # callback is local, ptr wont escape
  proc decode(data: openArray[byte]) =
    status =
      if decodeSSZ(data, outputPtr[]): GetResult.found
      else: GetResult.corrupted

  discard db.get(key, decode).expectDb()

  status

proc putSSZ(db: KvStoreRef, key: openArray[byte], v: auto) =
  db.put(key, encodeSSZ(v)).expectDb()

proc getSnappySSZ[T](db: KvStoreRef, key: openArray[byte], output: var T): GetResult =
  var status = GetResult.notFound

  let outputPtr = addr output # callback is local, ptr wont escape
  proc decode(data: openArray[byte]) =
    status =
      if decodeSnappySSZ(data, outputPtr[]): GetResult.found
      else: GetResult.corrupted

  discard db.get(key, decode).expectDb()

  status

proc putSnappySSZ(db: KvStoreRef, key: openArray[byte], v: auto) =
  db.put(key, encodeSnappySSZ(v)).expectDb()

proc getSZSSZ[T](db: KvStoreRef, key: openArray[byte], output: var T): GetResult =
  var status = GetResult.notFound

  let outputPtr = addr output # callback is local, ptr wont escape
  proc decode(data: openArray[byte]) =
    status =
      if decodeSZSSZ(data, outputPtr[]): GetResult.found
      else: GetResult.corrupted

  discard db.get(key, decode).expectDb()

  status

proc putSZSSZ(db: KvStoreRef, key: openArray[byte], v: auto) =
  db.put(key, encodeSZSSZ(v)).expectDb()

proc close*(db: BeaconChainDBV0) =
  discard db.stateStore.close()
  discard db.backend.close()

proc close*(db: BeaconChainDB) =
  if db.db == nil: return

  # Close things roughly in reverse order
  if not isNil(db.blobs):
    discard db.blobs.close()
  db.lcData.close()
  db.finalizedBlocks.close()
  discard db.summaries.close()
  discard db.stateDiffs.close()
  for kv in db.statesNoVal:
    discard kv.close()
  discard db.stateRoots.close()
  for kv in db.blocks:
    discard kv.close()
  discard db.keyValues.close()

  db.immutableValidatorsDb.close()
  db.genesisDeposits.close()
  db.v0.close()
  db.db.close()

  db.db = nil

func toBeaconBlockSummary*(v: SomeForkyBeaconBlock): BeaconBlockSummary =
  BeaconBlockSummary(
    slot: v.slot,
    parent_root: v.parent_root,
  )

proc putBeaconBlockSummary*(
    db: BeaconChainDB, root: Eth2Digest, value: BeaconBlockSummary) =
  # Summaries are too simple / small to compress, store them as plain SSZ
  db.summaries.putSSZ(root.data, value)

proc putBlock*(
    db: BeaconChainDB,
    value: phase0.TrustedSignedBeaconBlock | altair.TrustedSignedBeaconBlock) =
  db.withManyWrites:
    db.blocks[type(value).kind].putSnappySSZ(value.root.data, value)
    db.putBeaconBlockSummary(value.root, value.message.toBeaconBlockSummary())

proc putBlock*(
    db: BeaconChainDB,
    value: bellatrix.TrustedSignedBeaconBlock |
           capella.TrustedSignedBeaconBlock | deneb.TrustedSignedBeaconBlock) =
  db.withManyWrites:
    db.blocks[type(value).kind].putSZSSZ(value.root.data, value)
    db.putBeaconBlockSummary(value.root, value.message.toBeaconBlockSummary())

proc putBlobSidecar*(
    db: BeaconChainDB,
    value: BlobSidecar) =
  let block_root = hash_tree_root(value.signed_block_header.message)
  db.blobs.putSZSSZ(blobkey(block_root, value.index), value)

proc delBlobSidecar*(
    db: BeaconChainDB,
    root: Eth2Digest, index: BlobIndex): bool =
  db.blobs.del(blobkey(root, index)).expectDb()

proc updateImmutableValidators*(
    db: BeaconChainDB, validators: openArray[Validator]) =
  # Must be called before storing a state that references the new validators
  let numValidators = validators.len

  while db.immutableValidators.len() < numValidators:
    let immutableValidator =
      getImmutableValidatorData(validators[db.immutableValidators.len()])
    if not db.db.readOnly:
      db.immutableValidatorsDb.add ImmutableValidatorDataDb2(
        pubkey: immutableValidator.pubkey.toUncompressed(),
        withdrawal_credentials: immutableValidator.withdrawal_credentials)
    db.immutableValidators.add immutableValidator

template toBeaconStateNoImmutableValidators(state: phase0.BeaconState):
    Phase0BeaconStateNoImmutableValidators =
  isomorphicCast[Phase0BeaconStateNoImmutableValidators](state)

template toBeaconStateNoImmutableValidators(state: altair.BeaconState):
    AltairBeaconStateNoImmutableValidators =
  isomorphicCast[AltairBeaconStateNoImmutableValidators](state)

template toBeaconStateNoImmutableValidators(state: bellatrix.BeaconState):
    BellatrixBeaconStateNoImmutableValidators =
  isomorphicCast[BellatrixBeaconStateNoImmutableValidators](state)

template toBeaconStateNoImmutableValidators(state: capella.BeaconState):
    CapellaBeaconStateNoImmutableValidators =
  isomorphicCast[CapellaBeaconStateNoImmutableValidators](state)

template toBeaconStateNoImmutableValidators(state: deneb.BeaconState):
    DenebBeaconStateNoImmutableValidators =
  isomorphicCast[DenebBeaconStateNoImmutableValidators](state)

proc putState*(
    db: BeaconChainDB, key: Eth2Digest,
    value: phase0.BeaconState | altair.BeaconState) =
  db.updateImmutableValidators(value.validators.asSeq())
  db.statesNoVal[type(value).kind].putSnappySSZ(
    key.data, toBeaconStateNoImmutableValidators(value))

proc putState*(
    db: BeaconChainDB, key: Eth2Digest,
    value: bellatrix.BeaconState | capella.BeaconState | deneb.BeaconState) =
  db.updateImmutableValidators(value.validators.asSeq())
  db.statesNoVal[type(value).kind].putSZSSZ(
    key.data, toBeaconStateNoImmutableValidators(value))

proc putState*(db: BeaconChainDB, state: ForkyHashedBeaconState) =
  db.withManyWrites:
    db.putStateRoot(state.latest_block_root, state.data.slot, state.root)
    db.putState(state.root, state.data)

# For testing rollback
proc putCorruptState*(
    db: BeaconChainDB, fork: static ConsensusFork, key: Eth2Digest) =
  db.statesNoVal[fork].putSnappySSZ(key.data, Validator())

func stateRootKey(root: Eth2Digest, slot: Slot): array[40, byte] =
  var ret: array[40, byte]
  # big endian to get a naturally ascending order on slots in sorted indices
  ret[0..<8] = toBytesBE(slot.uint64)
  ret[8..<40] = root.data

  ret

proc putStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot,
    value: Eth2Digest) =
  db.stateRoots.putRaw(stateRootKey(root, slot), value)

proc putStateDiff*(db: BeaconChainDB, root: Eth2Digest, value: BeaconStateDiff) =
  db.stateDiffs.putSnappySSZ(root.data, value)

proc delBlock*(db: BeaconChainDB, fork: ConsensusFork, key: Eth2Digest): bool =
  var deleted = false
  db.withManyWrites:
    discard db.summaries.del(key.data).expectDb()
    deleted = db.blocks[fork].del(key.data).expectDb()
  deleted

proc delState*(db: BeaconChainDB, fork: ConsensusFork, key: Eth2Digest) =
  discard db.statesNoVal[fork].del(key.data).expectDb()

proc clearBlocks*(db: BeaconChainDB, fork: ConsensusFork): bool =
  db.blocks[fork].clear().expectDb()

proc clearStates*(db: BeaconChainDB, fork: ConsensusFork): bool =
  db.statesNoVal[fork].clear().expectDb()

proc delStateRoot*(db: BeaconChainDB, root: Eth2Digest, slot: Slot) =
  discard db.stateRoots.del(stateRootKey(root, slot)).expectDb()

proc delStateDiff*(db: BeaconChainDB, root: Eth2Digest) =
  discard db.stateDiffs.del(root.data).expectDb()

proc putHeadBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.keyValues.putRaw(subkey(kHeadBlock), key)

proc putTailBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.keyValues.putRaw(subkey(kTailBlock), key)

proc putGenesisBlock*(db: BeaconChainDB, key: Eth2Digest) =
  db.keyValues.putRaw(subkey(kGenesisBlock), key)

proc putDepositTreeSnapshot*(db: BeaconChainDB,
                             snapshot: DepositTreeSnapshot) =
  db.withManyWrites:
    db.keyValues.putSnappySSZ(subkey(kDepositTreeSnapshot),
                              snapshot)
    # TODO: We currently store this redundant old snapshot in order
    #       to allow the users to rollback to a previous version
    #       of Nimbus without problems. It would be reasonable
    #       to remove this in Nimbus 23.2
    db.keyValues.putSnappySSZ(subkey(kOldDepositContractSnapshot),
                              snapshot.toOldDepositContractSnapshot)

proc hasDepositTreeSnapshot*(db: BeaconChainDB): bool =
  expectDb(subkey(kDepositTreeSnapshot) in db.keyValues)

proc getDepositTreeSnapshot*(db: BeaconChainDB): Opt[DepositTreeSnapshot] =
  result.ok(default DepositTreeSnapshot)
  let r = db.keyValues.getSnappySSZ(subkey(kDepositTreeSnapshot), result.get)
  if r != GetResult.found: result.err()

proc getUpgradableDepositSnapshot*(db: BeaconChainDB): Option[OldDepositContractSnapshot] =
  var dcs: OldDepositContractSnapshot
  let oldKey = subkey(kOldDepositContractSnapshot)
  if db.keyValues.getSnappySSZ(oldKey, dcs) != GetResult.found:
    # Old record is not present in the current database.
    # We need to take a look in the v0 database as well.
    if db.v0.backend.getSnappySSZ(oldKey, dcs) != GetResult.found:
      return

  return some dcs

proc getPhase0Block(
    db: BeaconChainDBV0, key: Eth2Digest): Opt[phase0.TrustedSignedBeaconBlock] =
  # We only store blocks that we trust in the database
  result.ok(default(phase0.TrustedSignedBeaconBlock))
  if db.backend.getSnappySSZ(
      subkey(phase0.SignedBeaconBlock, key), result.get) != GetResult.found:
    result.err()
  else:
    # set root after deserializing (so it doesn't get zeroed)
    result.get().root = key

proc getBlock*(
    db: BeaconChainDB, key: Eth2Digest,
    T: type phase0.TrustedSignedBeaconBlock): Opt[T] =
  # We only store blocks that we trust in the database
  result.ok(default(T))
  if db.blocks[T.kind].getSnappySSZ(key.data, result.get) != GetResult.found:
    # During the initial releases phase0, we stored blocks in a different table
    result = db.v0.getPhase0Block(key)
  else:
    # set root after deserializing (so it doesn't get zeroed)
    result.get().root = key

proc getBlock*(
    db: BeaconChainDB, key: Eth2Digest,
    T: type altair.TrustedSignedBeaconBlock): Opt[T] =
  # We only store blocks that we trust in the database
  result.ok(default(T))
  if db.blocks[T.kind].getSnappySSZ(key.data, result.get) == GetResult.found:
    # set root after deserializing (so it doesn't get zeroed)
    result.get().root = key
  else:
    result.err()

proc getBlock*[
    X: bellatrix.TrustedSignedBeaconBlock | capella.TrustedSignedBeaconBlock |
       deneb.TrustedSignedBeaconBlock](
    db: BeaconChainDB, key: Eth2Digest,
    T: type X): Opt[T] =
  # We only store blocks that we trust in the database
  result.ok(default(T))
  if db.blocks[T.kind].getSZSSZ(key.data, result.get) == GetResult.found:
    # set root after deserializing (so it doesn't get zeroed)
    result.get().root = key
  else:
    result.err()

proc getPhase0BlockSSZ(
    db: BeaconChainDBV0, key: Eth2Digest, data: var seq[byte]): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = snappy.decode(data)
    success = dataPtr[].len > 0
  db.backend.get(subkey(phase0.SignedBeaconBlock, key), decode).expectDb() and
    success

proc getPhase0BlockSZ(
    db: BeaconChainDBV0, key: Eth2Digest, data: var seq[byte]): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = snappy.encodeFramed(snappy.decode(data))
    success = dataPtr[].len > 0
  db.backend.get(subkey(phase0.SignedBeaconBlock, key), decode).expectDb() and
    success

# SSZ implementations are separate so as to avoid unnecessary data copies
proc getBlockSSZ*(
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte],
    T: type phase0.TrustedSignedBeaconBlock): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = snappy.decode(data)
    success = dataPtr[].len > 0
  db.blocks[ConsensusFork.Phase0].get(key.data, decode).expectDb() and success or
    db.v0.getPhase0BlockSSZ(key, data)

proc getBlockSSZ*(
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte],
    T: type altair.TrustedSignedBeaconBlock): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = snappy.decode(data)
    success = dataPtr[].len > 0
  db.blocks[T.kind].get(key.data, decode).expectDb() and success

proc getBlockSSZ*[
    X: bellatrix.TrustedSignedBeaconBlock | capella.TrustedSignedBeaconBlock |
       deneb.TrustedSignedBeaconBlock](
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte], T: type X): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = decodeFramed(data, checkIntegrity = false)
    success = dataPtr[].len > 0
  db.blocks[T.kind].get(key.data, decode).expectDb() and success

proc getBlockSSZ*(
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte],
    fork: ConsensusFork): bool =
  withConsensusFork(fork):
    getBlockSSZ(db, key, data, consensusFork.TrustedSignedBeaconBlock)

proc getBlobSidecarSZ*(db: BeaconChainDB, root: Eth2Digest, index: BlobIndex,
                       data: var seq[byte]): bool =
  let dataPtr = addr data # Short-lived
  func decode(data: openArray[byte]) =
    assign(dataPtr[], data)
  db.blobs.get(blobkey(root, index), decode).expectDb()

proc getBlobSidecar*(db: BeaconChainDB, root: Eth2Digest, index: BlobIndex,
                     value: var BlobSidecar): bool =
  db.blobs.getSZSSZ(blobkey(root, index), value) == GetResult.found

proc getBlockSZ*(
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte],
    T: type phase0.TrustedSignedBeaconBlock): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = snappy.encodeFramed(snappy.decode(data))
    success = dataPtr[].len > 0
  db.blocks[ConsensusFork.Phase0].get(key.data, decode).expectDb() and success or
    db.v0.getPhase0BlockSZ(key, data)

proc getBlockSZ*(
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte],
    T: type altair.TrustedSignedBeaconBlock): bool =
  let dataPtr = addr data # Short-lived
  var success = true
  func decode(data: openArray[byte]) =
    dataPtr[] = snappy.encodeFramed(snappy.decode(data))
    success = dataPtr[].len > 0
  db.blocks[T.kind].get(key.data, decode).expectDb() and success

proc getBlockSZ*[
    X: bellatrix.TrustedSignedBeaconBlock | capella.TrustedSignedBeaconBlock |
       deneb.TrustedSignedBeaconBlock](
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte], T: type X): bool =
  let dataPtr = addr data # Short-lived
  func decode(data: openArray[byte]) =
    assign(dataPtr[], data)
  db.blocks[T.kind].get(key.data, decode).expectDb()

proc getBlockSZ*(
    db: BeaconChainDB, key: Eth2Digest, data: var seq[byte],
    fork: ConsensusFork): bool =
  withConsensusFork(fork):
    getBlockSZ(db, key, data, consensusFork.TrustedSignedBeaconBlock)

proc getStateOnlyMutableValidators(
    immutableValidators: openArray[ImmutableValidatorData2],
    store: KvStoreRef, key: openArray[byte],
    output: var (phase0.BeaconState | altair.BeaconState),
    rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  ## Rollback will be called only if output was partially written - if it was
  ## not found at all, rollback will not be called
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126

  let prevNumValidators = output.validators.len

  case store.getSnappySSZ(key, toBeaconStateNoImmutableValidators(output))
  of GetResult.found:
    let numValidators = output.validators.len
    doAssert immutableValidators.len >= numValidators

    for i in prevNumValidators ..< numValidators:
      let
        # Bypass hash cache invalidation
        dstValidator = addr output.validators.data[i]

      assign(
        dstValidator.pubkey,
        immutableValidators[i].pubkey.toPubKey())
      assign(
        dstValidator.withdrawal_credentials,
        immutableValidators[i].withdrawal_credentials)
      output.validators.clearCaches(i)

    true
  of GetResult.notFound:
    false
  of GetResult.corrupted:
    rollback()
    false

proc getStateOnlyMutableValidators(
    immutableValidators: openArray[ImmutableValidatorData2],
    store: KvStoreRef, key: openArray[byte],
    output: var bellatrix.BeaconState, rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  ## Rollback will be called only if output was partially written - if it was
  ## not found at all, rollback will not be called
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126

  let prevNumValidators = output.validators.len

  case store.getSZSSZ(key, toBeaconStateNoImmutableValidators(output))
  of GetResult.found:
    let numValidators = output.validators.len
    doAssert immutableValidators.len >= numValidators

    for i in prevNumValidators ..< numValidators:
      # Bypass hash cache invalidation
      let dstValidator = addr output.validators.data[i]

      assign(dstValidator.pubkey, immutableValidators[i].pubkey.toPubKey())
      assign(
        dstValidator.withdrawal_credentials,
        immutableValidators[i].withdrawal_credentials)
      output.validators.clearCaches(i)

    true
  of GetResult.notFound:
    false
  of GetResult.corrupted:
    rollback()
    false

proc getStateOnlyMutableValidators(
    immutableValidators: openArray[ImmutableValidatorData2],
    store: KvStoreRef, key: openArray[byte],
    output: var (capella.BeaconState | deneb.BeaconState),
    rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  ## Rollback will be called only if output was partially written - if it was
  ## not found at all, rollback will not be called
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126

  let prevNumValidators = output.validators.len

  case store.getSZSSZ(key, toBeaconStateNoImmutableValidators(output))
  of GetResult.found:
    let numValidators = output.validators.len
    doAssert immutableValidators.len >= numValidators

    for i in prevNumValidators ..< numValidators:
      # Bypass hash cache invalidation
      let dstValidator = addr output.validators.data[i]
      assign(dstValidator.pubkey, immutableValidators[i].pubkey.toPubKey())
      output.validators.clearCaches(i)

    true
  of GetResult.notFound:
    false
  of GetResult.corrupted:
    rollback()
    false

proc getState(
    db: BeaconChainDBV0,
    immutableValidators: openArray[ImmutableValidatorData2],
    key: Eth2Digest, output: var phase0.BeaconState,
    rollback: RollbackProc): bool =
  # Nimbus 1.0 reads and writes writes genesis BeaconState to `backend`
  # Nimbus 1.1 writes a genesis BeaconStateNoImmutableValidators to `backend` and
  # reads both BeaconState and BeaconStateNoImmutableValidators from `backend`
  # Nimbus 1.2 writes a genesis BeaconStateNoImmutableValidators to `stateStore`
  # and reads BeaconState from `backend` and BeaconStateNoImmutableValidators
  # from `stateStore`. We will try to read the state from all these locations.
  if getStateOnlyMutableValidators(
      immutableValidators, db.stateStore,
      subkey(Phase0BeaconStateNoImmutableValidators, key), output, rollback):
    return true
  if getStateOnlyMutableValidators(
      immutableValidators, db.backend,
      subkey(Phase0BeaconStateNoImmutableValidators, key), output, rollback):
    return true

  case db.backend.getSnappySSZ(subkey(phase0.BeaconState, key), output)
  of GetResult.found:
    true
  of GetResult.notFound:
    false
  of GetResult.corrupted:
    rollback()
    false

proc getState*(
    db: BeaconChainDB, key: Eth2Digest, output: var phase0.BeaconState,
    rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  ## Rollback will be called only if output was partially written - if it was
  ## not found at all, rollback will not be called
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126
  type T = type(output)

  if not getStateOnlyMutableValidators(
      db.immutableValidators, db.statesNoVal[T.kind], key.data, output, rollback):
    db.v0.getState(db.immutableValidators, key, output, rollback)
  else:
    true

proc getState*(
    db: BeaconChainDB, key: Eth2Digest,
    output: var (altair.BeaconState | bellatrix.BeaconState |
                 capella.BeaconState | deneb.BeaconState),
    rollback: RollbackProc): bool =
  ## Load state into `output` - BeaconState is large so we want to avoid
  ## re-allocating it if possible
  ## Return `true` iff the entry was found in the database and `output` was
  ## overwritten.
  ## Rollback will be called only if output was partially written - if it was
  ## not found at all, rollback will not be called
  # TODO rollback is needed to deal with bug - use `noRollback` to ignore:
  #      https://github.com/nim-lang/Nim/issues/14126
  type T = type(output)
  getStateOnlyMutableValidators(
    db.immutableValidators, db.statesNoVal[T.kind], key.data, output,
    rollback)

proc getState*(
    db: BeaconChainDB, fork: ConsensusFork, state_root: Eth2Digest,
    state: var ForkedHashedBeaconState, rollback: RollbackProc): bool =
  if state.kind != fork:
    # Avoid temporary (!)
    state = (ref ForkedHashedBeaconState)(kind: fork)[]

  withState(state):
    if not db.getState(state_root, forkyState.data, rollback):
      return false

    forkyState.root = state_root

  true

proc getStateRoot(db: BeaconChainDBV0,
                   root: Eth2Digest,
                   slot: Slot): Opt[Eth2Digest] =
  db.backend.getRaw(subkey(root, slot), Eth2Digest)

proc getStateRoot*(db: BeaconChainDB,
                   root: Eth2Digest,
                   slot: Slot): Opt[Eth2Digest] =
  db.stateRoots.getRaw(stateRootKey(root, slot), Eth2Digest) or
    db.v0.getStateRoot(root, slot)

proc getStateDiff*(db: BeaconChainDB,
                   root: Eth2Digest): Opt[BeaconStateDiff] =
  result.ok(BeaconStateDiff())
  if db.stateDiffs.getSnappySSZ(root.data, result.get) != GetResult.found:
    result.err

proc getHeadBlock(db: BeaconChainDBV0): Opt[Eth2Digest] =
  db.backend.getRaw(subkey(kHeadBlock), Eth2Digest)

proc getHeadBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.keyValues.getRaw(subkey(kHeadBlock), Eth2Digest) or
    db.v0.getHeadBlock()

proc getTailBlock(db: BeaconChainDBV0): Opt[Eth2Digest] =
  db.backend.getRaw(subkey(kTailBlock), Eth2Digest)

proc getTailBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.keyValues.getRaw(subkey(kTailBlock), Eth2Digest) or
    db.v0.getTailBlock()

proc getGenesisBlock(db: BeaconChainDBV0): Opt[Eth2Digest] =
  db.backend.getRaw(subkey(kGenesisBlock), Eth2Digest)

proc getGenesisBlock*(db: BeaconChainDB): Opt[Eth2Digest] =
  db.keyValues.getRaw(subkey(kGenesisBlock), Eth2Digest) or
    db.v0.getGenesisBlock()

proc containsBlock*(db: BeaconChainDBV0, key: Eth2Digest): bool =
  db.backend.contains(subkey(phase0.SignedBeaconBlock, key)).expectDb()

proc containsBlock*(
    db: BeaconChainDB, key: Eth2Digest,
    T: type phase0.TrustedSignedBeaconBlock): bool =
  db.blocks[T.kind].contains(key.data).expectDb() or
    db.v0.containsBlock(key)

proc containsBlock*[
    X: altair.TrustedSignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
       capella.TrustedSignedBeaconBlock | deneb.TrustedSignedBeaconBlock](
    db: BeaconChainDB, key: Eth2Digest, T: type X): bool =
  db.blocks[X.kind].contains(key.data).expectDb()

proc containsBlock*(db: BeaconChainDB, key: Eth2Digest, fork: ConsensusFork): bool =
  case fork
  of ConsensusFork.Phase0: containsBlock(db, key, phase0.TrustedSignedBeaconBlock)
  else: db.blocks[fork].contains(key.data).expectDb()

proc containsBlock*(db: BeaconChainDB, key: Eth2Digest): bool =
  for fork in countdown(ConsensusFork.high, ConsensusFork.low):
    if db.containsBlock(key, fork): return true

  false

proc containsState*(db: BeaconChainDBV0, key: Eth2Digest): bool =
  let sk = subkey(Phase0BeaconStateNoImmutableValidators, key)
  db.stateStore.contains(sk).expectDb() or
    db.backend.contains(sk).expectDb() or
    db.backend.contains(subkey(phase0.BeaconState, key)).expectDb()

proc containsState*(db: BeaconChainDB, fork: ConsensusFork, key: Eth2Digest,
    legacy: bool = true): bool =
  if db.statesNoVal[fork].contains(key.data).expectDb(): return true

  (legacy and fork == ConsensusFork.Phase0 and db.v0.containsState(key))

proc containsState*(db: BeaconChainDB, key: Eth2Digest, legacy: bool = true): bool =
  for fork in countdown(ConsensusFork.high, ConsensusFork.low):
    if db.statesNoVal[fork].contains(key.data).expectDb(): return true

  (legacy and db.v0.containsState(key))

proc getBeaconBlockSummary*(db: BeaconChainDB, root: Eth2Digest):
    Opt[BeaconBlockSummary] =
  var summary: BeaconBlockSummary
  if db.summaries.getSSZ(root.data, summary) == GetResult.found:
    ok(summary)
  else:
    err()

proc loadStateRoots*(db: BeaconChainDB): Table[(Slot, Eth2Digest), Eth2Digest] =
  ## Load all known state roots - just because we have a state root doesn't
  ## mean we also have a state (and vice versa)!
  var state_roots = initTable[(Slot, Eth2Digest), Eth2Digest](1024)

  discard db.stateRoots.find([], proc(k, v: openArray[byte]) =
    if k.len() == 40 and v.len() == 32:
      # For legacy reasons, the first byte of the slot is not part of the slot
      # but rather a subkey identifier - see subkey
      var tmp = toArray(8, k.toOpenArray(0, 7))
      tmp[0] = 0
      state_roots[
        (Slot(uint64.fromBytesBE(tmp)),
        Eth2Digest(data: toArray(sizeof(Eth2Digest), k.toOpenArray(8, 39))))] =
        Eth2Digest(data: toArray(sizeof(Eth2Digest), v))
    else:
      warn "Invalid state root in database", klen = k.len(), vlen = v.len()
  )

  state_roots

proc loadSummaries*(db: BeaconChainDB): Table[Eth2Digest, BeaconBlockSummary] =
  # Load summaries into table - there's no telling what order they're in so we
  # load them all - bugs in nim prevent this code from living in the iterator.
  var summaries = initTable[Eth2Digest, BeaconBlockSummary](1024*1024)

  discard db.summaries.find([], proc(k, v: openArray[byte]) =
    var output: BeaconBlockSummary

    if k.len() == sizeof(Eth2Digest) and decodeSSZ(v, output):
      summaries[Eth2Digest(data: toArray(sizeof(Eth2Digest), k))] = output
    else:
      warn "Invalid summary in database", klen = k.len(), vlen = v.len()
  )

  summaries

type RootedSummary = tuple[root: Eth2Digest, summary: BeaconBlockSummary]
iterator getAncestorSummaries*(db: BeaconChainDB, root: Eth2Digest):
    RootedSummary =
  ## Load a chain of ancestors for blck - iterates over the block starting from
  ## root and moving parent by parent
  ##
  ## The search will go on until an ancestor cannot be found.

  var
    res: RootedSummary
    newSummaries: seq[RootedSummary]

  res.root = root

  # Yield summaries in reverse chain order by walking the parent references.
  # If a summary is missing, try loading it from the older version or create one
  # from block data.

  const summariesQuery = """
  WITH RECURSIVE
    next(v) as (
      SELECT value FROM beacon_block_summaries
      WHERE `key` == ?

    UNION ALL
      SELECT value FROM beacon_block_summaries
      INNER JOIN next ON `key` == substr(v, 9, 32)
  )
  SELECT v FROM next;
  """
  let
    stmt = expectDb db.db.prepareStmt(
      summariesQuery, array[32, byte],
      array[sizeof(BeaconBlockSummary), byte],
      managed = false)

  defer: # in case iteration is stopped along the way
    # Write the newly found summaries in a single transaction - on first migration
    # from the old format, this brings down the write from minutes to seconds
    stmt.dispose()

    if not db.db.readOnly:
      if newSummaries.len() > 0:
        db.withManyWrites:
          for s in newSummaries:
            db.putBeaconBlockSummary(s.root, s.summary)

      if db.db.hasTable("kvstore").expectDb():
        # Clean up pre-altair summaries - by now, we will have moved them to the
        # new table
        db.db.exec(
          "DELETE FROM kvstore WHERE key >= ? and key < ?",
          ([byte ord(kHashToBlockSummary)], [byte ord(kHashToBlockSummary) + 1])).expectDb()

  var row: stmt.Result
  for rowRes in exec(stmt, root.data, row):
    expectDb rowRes
    if decodeSSZ(row, res.summary):
      yield res
      res.root = res.summary.parent_root

  # Backwards compat for reading old databases, or those that for whatever
  # reason lost a summary along the way..
  static: doAssert ConsensusFork.high == ConsensusFork.Deneb
  while true:
    if db.v0.backend.getSnappySSZ(
        subkey(BeaconBlockSummary, res.root), res.summary) == GetResult.found:
      discard # Just yield below
    elif (let blck = db.getBlock(res.root, phase0.TrustedSignedBeaconBlock); blck.isSome()):
      res.summary = blck.get().message.toBeaconBlockSummary()
    elif (let blck = db.getBlock(res.root, altair.TrustedSignedBeaconBlock); blck.isSome()):
      res.summary = blck.get().message.toBeaconBlockSummary()
    elif (let blck = db.getBlock(res.root, bellatrix.TrustedSignedBeaconBlock); blck.isSome()):
      res.summary = blck.get().message.toBeaconBlockSummary()
    elif (let blck = db.getBlock(res.root, capella.TrustedSignedBeaconBlock); blck.isSome()):
      res.summary = blck.get().message.toBeaconBlockSummary()
    elif (let blck = db.getBlock(res.root, deneb.TrustedSignedBeaconBlock); blck.isSome()):
      res.summary = blck.get().message.toBeaconBlockSummary()
    else:
      break

    yield res

    # Next time, load them from the right place
    newSummaries.add(res)

    res.root = res.summary.parent_root

# Test operations used to create broken and/or legacy database

proc putStateV0*(db: BeaconChainDBV0, key: Eth2Digest, value: phase0.BeaconState) =
  # Writes to KVStore, as done in 1.0.12 and earlier
  db.backend.putSnappySSZ(subkey(type value, key), value)

proc putBlockV0*(db: BeaconChainDBV0, value: phase0.TrustedSignedBeaconBlock) =
  # Write to KVStore, as done in 1.0.12 and earlier
  # In particular, no summary is written here - it should be recreated
  # automatically
  db.backend.putSnappySSZ(subkey(phase0.SignedBeaconBlock, value.root), value)

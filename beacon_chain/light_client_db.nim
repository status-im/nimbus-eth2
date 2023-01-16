# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  # Status libraries
  chronicles,
  eth/db/kvstore_sqlite3,
  # Beacon chain internals
  spec/datatypes/altair,
  spec/[eth2_ssz_serialization, helpers],
  ./db_limits

logScope: topics = "lcdb"

# `altair_lc_headers` holds the latest `LightClientStore.finalized_header`.
#
# `altair_sync_committees` holds finalized `SyncCommittee` by period, needed to
# continue an interrupted sync process without having to obtain bootstrap info.

template dbDataFork: LightClientDataFork = LightClientDataFork.Altair

type
  LightClientHeaderKind {.pure.} = enum  # Append only, used in DB data!
    Finalized = 1

  LightClientHeadersStore = object
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]

  SyncCommitteeStore = object
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  LightClientDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    headers: LightClientHeadersStore
      ## LightClientHeaderKind -> altair.LightClientHeader
      ## Stores the latest light client headers.

    syncCommittees: SyncCommitteeStore
      ## SyncCommitteePeriod -> altair.SyncCommittee
      ## Stores finalized `SyncCommittee` by sync committee period.

func initLightClientHeadersStore(
    backend: SqStoreRef,
    name: string): KvResult[LightClientHeadersStore] =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Altair
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `""" & name & """` (
      `kind` INTEGER PRIMARY KEY,  -- `LightClientHeaderKind`
      `header` BLOB                -- `altair.LightClientHeader` (SSZ)
    );
  """)

  let
    getStmt = backend.prepareStmt("""
      SELECT `header`
      FROM `""" & name & """`
      WHERE `kind` = ?;
    """, int64, seq[byte], managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `kind`, `header`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void, managed = false).expect("SQL query OK")

  ok LightClientHeadersStore(
    getStmt: getStmt,
    putStmt: putStmt)

func close(store: LightClientHeadersStore) =
  store.getStmt.dispose()
  store.putStmt.dispose()

proc getLatestFinalizedHeader*(
    db: LightClientDB): Opt[dbDataFork.LightClientHeader] =
  var header: seq[byte]
  for res in db.headers.getStmt.exec(
      LightClientHeaderKind.Finalized.int64, header):
    res.expect("SQL query OK")
    try:
      return ok SSZ.decode(header, dbDataFork.LightClientHeader)
    except SszError as exc:
      error "LC store corrupted", store = "headers",
        kind = "Finalized", exc = exc.msg
      return err()

func putLatestFinalizedHeader*(
    db: LightClientDB, header: dbDataFork.LightClientHeader) =
  block:
    let res = db.headers.putStmt.exec(
      (LightClientHeaderKind.Finalized.int64, SSZ.encode(header)))
    res.expect("SQL query OK")
  block:
    let period = header.beacon.slot.sync_committee_period
    doAssert period.isSupportedBySQLite
    let res = db.syncCommittees.keepFromStmt.exec(period.int64)
    res.expect("SQL query OK")

func initSyncCommitteesStore(
    backend: SqStoreRef,
    name: string): KvResult[SyncCommitteeStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `""" & name & """` (
      `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
      `sync_committee` BLOB          -- `altair.SyncCommittee` (SSZ)
    );
  """)

  let
    getStmt = backend.prepareStmt("""
      SELECT `sync_committee`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, seq[byte], managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `period`, `sync_committee`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok SyncCommitteeStore(
    getStmt: getStmt,
    putStmt: putStmt,
    keepFromStmt: keepFromStmt)

func close(store: SyncCommitteeStore) =
  store.getStmt.dispose()
  store.putStmt.dispose()
  store.keepFromStmt.dispose()

proc getSyncCommittee*(
    db: LightClientDB, period: SyncCommitteePeriod): Opt[altair.SyncCommittee] =
  doAssert period.isSupportedBySQLite
  var syncCommittee: seq[byte]
  for res in db.syncCommittees.getStmt.exec(period.int64, syncCommittee):
    res.expect("SQL query OK")
    try:
      return ok SSZ.decode(syncCommittee, altair.SyncCommittee)
    except SszError as exc:
      error "LC store corrupted", store = "syncCommittees",
        period, exc = exc.msg
      return err()

func putSyncCommittee*(
    db: LightClientDB, period: SyncCommitteePeriod,
    syncCommittee: altair.SyncCommittee) =
  doAssert period.isSupportedBySQLite
  let res = db.syncCommittees.putStmt.exec(
    (period.int64, SSZ.encode(syncCommittee)))
  res.expect("SQL query OK")

type LightClientDBNames* = object
  altairHeaders*: string
  altairSyncCommittees*: string

func initLightClientDB*(
    backend: SqStoreRef,
    names: LightClientDBNames): KvResult[LightClientDB] =
  let
    headers =
      ? backend.initLightClientHeadersStore(names.altairHeaders)
    syncCommittees =
      ? backend.initSyncCommitteesStore(names.altairSyncCommittees)

  ok LightClientDB(
    backend: backend,
    headers: headers,
    syncCommittees: syncCommittees)

func close*(db: LightClientDB) =
  if db.backend != nil:
    db.headers.close()
    db.syncCommittees.close()
    db[].reset()

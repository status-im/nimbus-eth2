# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Status libraries
  stew/base10,
  chronicles,
  eth/db/kvstore_sqlite3,
  # Beacon chain internals
  spec/datatypes/altair,
  spec/[eth2_ssz_serialization, helpers],
  ./db_limits

logScope: topics = "lcdb"

# `lc_headers` holds the latest `LightClientStore.finalized_header`.
#
# `altair_sync_committees` holds finalized `SyncCommittee` by period, needed to
# continue an interrupted sync process without having to obtain bootstrap info.

type
  LightClientHeaderKey {.pure.} = enum  # Append only, used in DB data!
    Finalized = 1  # Latest finalized header

  LegacyLightClientHeadersStore = object
    getStmt: SqliteStmt[int64, (int64, seq[byte])]
    putStmt: SqliteStmt[(int64, seq[byte]), void]

  LightClientHeadersStore = object
    getStmt: SqliteStmt[int64, (int64, seq[byte])]
    putStmt: SqliteStmt[(int64, int64, seq[byte]), void]

  SyncCommitteeStore = object
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  LightClientDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    legacyHeaders: LegacyLightClientHeadersStore
      ## LightClientHeaderKey -> altair.LightClientHeader
      ## Used through Bellatrix.

    headers: LightClientHeadersStore
      ## LightClientHeaderKey -> (LightClientDataFork, LightClientHeader)
      ## Stores the latest light client headers.

    syncCommittees: SyncCommitteeStore
      ## SyncCommitteePeriod -> altair.SyncCommittee
      ## Stores finalized `SyncCommittee` by sync committee period.

template disposeSafe(s: untyped): untyped =
  if distinctBase(s) != nil:
    s.dispose()
    s = nil

proc initLegacyLightClientHeadersStore(
    backend: SqStoreRef,
    name: string): KvResult[LegacyLightClientHeadersStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `kind` INTEGER PRIMARY KEY,  -- `LightClientHeaderKey`
        `header` BLOB                -- `altair.LightClientHeader` (SSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok LegacyLightClientHeadersStore()

  const legacyKind = Base10.toString(ord(LightClientDataFork.Altair).uint)
  let
    getStmt = backend.prepareStmt("""
      SELECT """ & legacyKind & """ AS `kind`, `header`
      FROM `""" & name & """`
      WHERE `""" & name & """`.`kind` = ?;
    """, int64, (int64, seq[byte]), managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `kind`, `header`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void, managed = false)
      .expect("SQL query OK")

  ok LegacyLightClientHeadersStore(
    getStmt: getStmt,
    putStmt: putStmt)

func close(store: var LegacyLightClientHeadersStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()

proc initLightClientHeadersStore(
    backend: SqStoreRef,
    name, legacyAltairName: string): KvResult[LightClientHeadersStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `key` INTEGER PRIMARY KEY,  -- `LightClientHeaderKey`
        `kind` INTEGER,             -- `LightClientDataFork`
        `header` BLOB               -- `LightClientHeader` (SSZ)
      );
    """)
    if ? backend.hasTable(legacyAltairName):
      # LightClientHeaderKey -> altair.LightClientHeader
      const legacyKind = Base10.toString(ord(LightClientDataFork.Altair).uint)
      ? backend.exec("""
        INSERT OR IGNORE INTO `""" & name & """` (
          `key`, `kind`, `header`
        )
        SELECT `kind` AS `key`, """ & legacyKind & """ AS `kind`, `header`
        FROM `""" & legacyAltairName & """`;
      """)
  if not ? backend.hasTable(name):
    return ok LightClientHeadersStore()

  let
    getStmt = backend.prepareStmt("""
      SELECT `kind`, `header`
      FROM `""" & name & """`
      WHERE `key` = ?;
    """, int64, (int64, seq[byte]), managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `key`, `kind`, `header`
      ) VALUES (?, ?, ?);
    """, (int64, int64, seq[byte]), void, managed = false)
      .expect("SQL query OK")

  ok LightClientHeadersStore(
    getStmt: getStmt,
    putStmt: putStmt)

func close(store: var LightClientHeadersStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()

proc getLatestFinalizedHeader*(
    db: LightClientDB): ForkedLightClientHeader =
  const key = LightClientHeaderKey.Finalized

  var header: (int64, seq[byte])
  proc processHeader(): ForkedLightClientHeader =
    try:
      withAll(LightClientDataFork):
        when lcDataFork > LightClientDataFork.None:
          if header[0] == ord(lcDataFork).int64:
            var obj = ForkedLightClientHeader(kind: lcDataFork)
            obj.forky(lcDataFork) = SSZ.decode(
              header[1], lcDataFork.LightClientHeader)
            return obj
      warn "Unsupported LC store kind", store = "headers",
        key, kind = header[0]
      return default(ForkedLightClientHeader)
    except SszError as exc:
      error "LC store corrupted", store = "headers",
        key, kind = header[0], exc = exc.msg
      return default(ForkedLightClientHeader)

  if distinctBase(db.headers.getStmt) != nil:
    for res in db.headers.getStmt.exec(key.int64, header):
      res.expect("SQL query OK")
      return processHeader()
  if distinctBase(db.legacyHeaders.getStmt) != nil:
    for res in db.legacyHeaders.getStmt.exec(key.int64, header):
      res.expect("SQL query OK")
      return processHeader()
  default(ForkedLightClientHeader)

func putLatestFinalizedHeader*(
    db: LightClientDB, header: ForkedLightClientHeader) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  withForkyHeader(header):
    when lcDataFork > LightClientDataFork.None:
      block:
        const key = LightClientHeaderKey.Finalized
        block:
          let res = db.headers.putStmt.exec(
            (key.int64, lcDataFork.int64, SSZ.encode(forkyHeader)))
          res.expect("SQL query OK")
        when lcDataFork == LightClientDataFork.Altair:
          let res = db.legacyHeaders.putStmt.exec(
            (key.int64, SSZ.encode(forkyHeader)))
          res.expect("SQL query OK")
        else:
          # Keep legacy table at best Altair header.
          discard
      block:
        let period = forkyHeader.beacon.slot.sync_committee_period
        doAssert period.isSupportedBySQLite
        let res = db.syncCommittees.keepFromStmt.exec(period.int64)
        res.expect("SQL query OK")
    else: raiseAssert "Cannot store empty `LightClientHeader`"

func initSyncCommitteesStore(
    backend: SqStoreRef,
    name: string): KvResult[SyncCommitteeStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
        `sync_committee` BLOB          -- `altair.SyncCommittee` (SSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok SyncCommitteeStore()

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

func close(store: var SyncCommitteeStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

proc getSyncCommittee*(
    db: LightClientDB, period: SyncCommitteePeriod): Opt[altair.SyncCommittee] =
  doAssert period.isSupportedBySQLite
  if distinctBase(db.syncCommittees.getStmt) == nil:
    return Opt.none(altair.SyncCommittee)
  var syncCommittee: seq[byte]
  for res in db.syncCommittees.getStmt.exec(period.int64, syncCommittee):
    res.expect("SQL query OK")
    try:
      return ok SSZ.decode(syncCommittee, altair.SyncCommittee)
    except SszError as exc:
      error "LC store corrupted", store = "syncCommittees",
        period, exc = exc.msg
      return Opt.none(altair.SyncCommittee)

func putSyncCommittee*(
    db: LightClientDB, period: SyncCommitteePeriod,
    syncCommittee: altair.SyncCommittee) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  doAssert period.isSupportedBySQLite
  let res = db.syncCommittees.putStmt.exec(
    (period.int64, SSZ.encode(syncCommittee)))
  res.expect("SQL query OK")

type LightClientDBNames* = object
  legacyAltairHeaders*: string
  headers*: string
  altairSyncCommittees*: string

proc initLightClientDB*(
    backend: SqStoreRef,
    names: LightClientDBNames): KvResult[LightClientDB] =
  let
    legacyHeaders =
      ? backend.initLegacyLightClientHeadersStore(names.legacyAltairHeaders)
    headers =
      ? backend.initLightClientHeadersStore(
        names.headers, names.legacyAltairHeaders)
    syncCommittees =
      ? backend.initSyncCommitteesStore(names.altairSyncCommittees)

  ok LightClientDB(
    backend: backend,
    legacyHeaders: legacyHeaders,
    headers: headers,
    syncCommittees: syncCommittees)

func close*(db: LightClientDB) =
  if db.backend != nil:
    db.legacyHeaders.close()
    db.headers.close()
    db.syncCommittees.close()
    db[].reset()

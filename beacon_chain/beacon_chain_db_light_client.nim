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

logScope: topics = "lcdata"

# `lc_xxxxx_headers` contains a copy of historic `LightClientHeader`.
# Data is only kept for blocks that are used in `LightClientBootstrap` objects.
# Caching is necessary to support longer retention for LC data than state data.
# SSZ because this data does not compress well, and because this data
# needs to be bundled together with other data to fulfill requests.
# Mainnet data size (all columns):
# - Altair: ~38 KB per `SyncCommitteePeriod` (~1.0 MB per month)
# - Capella: ~222 KB per `SyncCommitteePeriod` (~6.1 MB per month)
# - Deneb: ~230 KB per `SyncCommitteePeriod` (~6.3 MB per month)
#
# `lc_altair_current_branches` holds Merkle proofs needed to
# construct `LightClientBootstrap` objects.
# SSZ because this data does not compress well, and because this data
# needs to be bundled together with other data to fulfill requests.
# Mainnet data size (all columns):
# - Altair ... Deneb: ~42 KB per `SyncCommitteePeriod` (~1.1 MB per month)
#
# `lc_altair_sync_committees` contains a copy of finalized sync committees.
# They are initially populated from the main DAG (usually a fast state access).
# Caching is necessary to support longer retention for LC data than state data.
# SSZ because this data does not compress well, and because this data
# needs to be bundled together with other data to fulfill requests.
# Mainnet data size (all columns):
# - Altair ... Deneb: ~32 KB per `SyncCommitteePeriod` (~0.9 MB per month)
#
# `lc_best_updates` holds full `LightClientUpdate` objects in SSZ form.
# These objects are frequently queried in bulk, but there is only one per
# sync committee period, so storing the full sync committee is acceptable.
# This data could be stored as SZSSZ to avoid on-the-fly compression when a
# libp2p request is handled. However, the space savings are quite small.
# Furthermore, `LightClientUpdate` is consulted on each new block to attempt
# improving it. Continuously decompressing and recompressing seems inefficient.
# Finally, the libp2p context bytes depend on `attested_header.beacon.slot` for
# deriving the fork digest; the `kind` column is not sufficient to derive
# the fork digest, because the same storage format may be used across forks.
# SSZ storage selected due to the small size and reduced logic complexity.
# Mainnet data size (all columns):
# - Altair: ~33 KB per `SyncCommitteePeriod` (~0.9 MB per month)
# - Capella: ~34 KB per `SyncCommitteePeriod` (~0.9 MB per month)
# - Deneb: ~34 KB per `SyncCommitteePeriod` (~0.9 MB per month)
#
# `lc_sealed_periods` contains the sync committee periods for which
# full light client data was imported. Data for these periods may no longer
# improve regardless of further block processing. The listed periods are skipped
# when restarting the program.
# Mainnet data size (all columns):
# - All forks: 8 bytes per `SyncCommitteePeriod` (~0.0 MB per month)

type
  LightClientHeaderStore = object
    getStmt: SqliteStmt[array[32, byte], seq[byte]]
    putStmt: SqliteStmt[(array[32, byte], int64, seq[byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  CurrentSyncCommitteeBranchStore = object
    containsStmt: SqliteStmt[int64, int64]
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  SyncCommitteeStore = object
    containsStmt: SqliteStmt[int64, int64]
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  LegacyBestLightClientUpdateStore = object
    getStmt: SqliteStmt[int64, (int64, seq[byte])]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
    delStmt: SqliteStmt[int64, void]
    keepFromStmt: SqliteStmt[int64, void]

  BestLightClientUpdateStore = object
    getStmt: SqliteStmt[int64, (int64, seq[byte])]
    putStmt: SqliteStmt[(int64, int64, seq[byte]), void]
    delStmt: SqliteStmt[int64, void]
    keepFromStmt: SqliteStmt[int64, void]

  SealedSyncCommitteePeriodStore = object
    containsStmt: SqliteStmt[int64, int64]
    putStmt: SqliteStmt[int64, void]
    keepFromStmt: SqliteStmt[int64, void]

  LightClientDataDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    headers: array[LightClientDataFork, LightClientHeaderStore]
      ## Eth2Digest -> (Slot, LightClientHeader)
      ## Cached block headers to support longer retention than block storage.

    currentBranches: CurrentSyncCommitteeBranchStore
      ## Slot -> altair.CurrentSyncCommitteeBranch
      ## Cached data for creating future `LightClientBootstrap` instances.
      ## Key is the block slot of which the post state was used to get the data.
      ## Data stored for all finalized epoch boundary blocks.

    syncCommittees: SyncCommitteeStore
      ## SyncCommitteePeriod -> altair.SyncCommittee
      ## Cached sync committees to support longer retention than state storage.

    legacyBestUpdates: LegacyBestLightClientUpdateStore
      ## SyncCommitteePeriod -> altair.LightClientUpdate
      ## Used through Bellatrix.

    bestUpdates: BestLightClientUpdateStore
      ## SyncCommitteePeriod -> (LightClientDataFork, LightClientUpdate)
      ## Stores the `LightClientUpdate` with the most `sync_committee_bits` per
      ## `SyncCommitteePeriod`. Sync committee finality gives precedence.

    sealedPeriods: SealedSyncCommitteePeriodStore
      ## {SyncCommitteePeriod}
      ## Tracks the finalized sync committee periods for which complete data
      ## has been imported (from `dag.tail.slot`).

template disposeSafe(s: untyped): untyped =
  if distinctBase(s) != nil:
    s.dispose()
    s = typeof(s)(nil)

proc initHeadersStore(
    backend: SqStoreRef,
    name, typeName: string): KvResult[LightClientHeaderStore] =
  if name == "":
    return ok LightClientHeaderStore()
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `block_root` BLOB PRIMARY KEY,  -- `Eth2Digest`
        `slot` INTEGER,                 -- `Slot`
        `header` BLOB                   -- `""" & typeName & """` (SSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok LightClientHeaderStore()

  let
    getStmt = backend.prepareStmt("""
      SELECT `header`
      FROM `""" & name & """`
      WHERE `block_root` = ?;
    """, array[32, byte], seq[byte], managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `block_root`, `slot`, `header`
      ) VALUES (?, ?, ?);
    """, (array[32, byte], int64, seq[byte]), void, managed = false)
      .expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `slot` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok LightClientHeaderStore(
    getStmt: getStmt,
    putStmt: putStmt,
    keepFromStmt: keepFromStmt)

func close(store: var LightClientHeaderStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

proc getHeader*[T: ForkyLightClientHeader](
    db: LightClientDataDB, blockRoot: Eth2Digest): Opt[T] =
  if distinctBase(db.headers[T.kind].getStmt) == nil:
    return Opt.none(T)
  var header: seq[byte]
  for res in db.headers[T.kind].getStmt.exec(blockRoot.data, header):
    res.expect("SQL query OK")
    try:
      return ok SSZ.decode(header, T)
    except SerializationError as exc:
      error "LC data store corrupted", store = "headers", kind = T.kind,
        blockRoot, exc = exc.msg
      return Opt.none(T)

func putHeader*[T: ForkyLightClientHeader](
    db: LightClientDataDB, header: T) =
  doAssert not db.backend.readOnly and
    distinctBase(db.headers[T.kind].putStmt) != nil
  let
    blockRoot = hash_tree_root(header.beacon)
    slot = header.beacon.slot
    res = db.headers[T.kind].putStmt.exec(
      (blockRoot.data, slot.int64, SSZ.encode(header)))
  res.expect("SQL query OK")

proc initCurrentBranchesStore(
    backend: SqStoreRef,
    name: string): KvResult[CurrentSyncCommitteeBranchStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `slot` INTEGER PRIMARY KEY,  -- `Slot` (up through 2^63-1)
        `branch` BLOB                -- `altair.CurrentSyncCommitteeBranch` (SSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok CurrentSyncCommitteeBranchStore()

  let
    containsStmt = backend.prepareStmt("""
      SELECT 1 AS `exists`
      FROM `""" & name & """`
      WHERE `slot` = ?;
    """, int64, int64, managed = false).expect("SQL query OK")
    getStmt = backend.prepareStmt("""
      SELECT `branch`
      FROM `""" & name & """`
      WHERE `slot` = ?;
    """, int64, seq[byte], managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `slot`, `branch`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `slot` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok CurrentSyncCommitteeBranchStore(
    containsStmt: containsStmt,
    getStmt: getStmt,
    putStmt: putStmt,
    keepFromStmt: keepFromStmt)

func close(store: var CurrentSyncCommitteeBranchStore) =
  store.containsStmt.disposeSafe()
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

func hasCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot): bool =
  if not slot.isSupportedBySQLite or
      distinctBase(db.currentBranches.containsStmt) == nil:
    return false
  var exists: int64
  for res in db.currentBranches.containsStmt.exec(slot.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  false

proc getCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot): Opt[altair.CurrentSyncCommitteeBranch] =
  if not slot.isSupportedBySQLite or
      distinctBase(db.currentBranches.getStmt) == nil:
    return Opt.none(altair.CurrentSyncCommitteeBranch)
  var branch: seq[byte]
  for res in db.currentBranches.getStmt.exec(slot.int64, branch):
    res.expect("SQL query OK")
    try:
      return ok SSZ.decode(branch, altair.CurrentSyncCommitteeBranch)
    except SerializationError as exc:
      error "LC data store corrupted", store = "currentBranches",
        slot, exc = exc.msg
      return Opt.none(altair.CurrentSyncCommitteeBranch)

func putCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot,
    branch: altair.CurrentSyncCommitteeBranch) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  if not slot.isSupportedBySQLite:
    return
  let res = db.currentBranches.putStmt.exec((slot.int64, SSZ.encode(branch)))
  res.expect("SQL query OK")

proc initSyncCommitteesStore(
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
    containsStmt = backend.prepareStmt("""
      SELECT 1 AS `exists`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, int64, managed = false).expect("SQL query OK")
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
    containsStmt: containsStmt,
    getStmt: getStmt,
    putStmt: putStmt,
    keepFromStmt: keepFromStmt)

func close(store: var SyncCommitteeStore) =
  store.containsStmt.disposeSafe()
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

func hasSyncCommittee*(
    db: LightClientDataDB, period: SyncCommitteePeriod): bool =
  doAssert period.isSupportedBySQLite
  if distinctBase(db.syncCommittees.containsStmt) == nil:
    return false
  var exists: int64
  for res in db.syncCommittees.containsStmt.exec(period.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  false

proc getSyncCommittee*(
    db: LightClientDataDB, period: SyncCommitteePeriod
): Opt[altair.SyncCommittee] =
  doAssert period.isSupportedBySQLite
  if distinctBase(db.syncCommittees.getStmt) == nil:
    return Opt.none(altair.SyncCommittee)
  var branch: seq[byte]
  for res in db.syncCommittees.getStmt.exec(period.int64, branch):
    res.expect("SQL query OK")
    try:
      return ok SSZ.decode(branch, altair.SyncCommittee)
    except SerializationError as exc:
      error "LC data store corrupted", store = "syncCommittees",
        period, exc = exc.msg
      return Opt.none(altair.SyncCommittee)

func putSyncCommittee*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    syncCommittee: altair.SyncCommittee) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  doAssert period.isSupportedBySQLite
  let res = db.syncCommittees.putStmt.exec(
    (period.int64, SSZ.encode(syncCommittee)))
  res.expect("SQL query OK")

proc initLegacyBestUpdatesStore(
    backend: SqStoreRef,
    name: string,
): KvResult[LegacyBestLightClientUpdateStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
        `update` BLOB                  -- `altair.LightClientUpdate` (SSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok LegacyBestLightClientUpdateStore()

  const legacyKind = Base10.toString(ord(LightClientDataFork.Altair).uint)
  let
    getStmt = backend.prepareStmt("""
      SELECT """ & legacyKind & """ AS `kind`, `update`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, (int64, seq[byte]), managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `period`, `update`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void, managed = false).expect("SQL query OK")
    delStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok LegacyBestLightClientUpdateStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    keepFromStmt: keepFromStmt)

func close(store: var LegacyBestLightClientUpdateStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.delStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

proc initBestUpdatesStore(
    backend: SqStoreRef,
    name, legacyAltairName: string,
): KvResult[BestLightClientUpdateStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
        `kind` INTEGER,                -- `LightClientDataFork`
        `update` BLOB                  -- `LightClientUpdate` (SSZ)
      );
    """)
    if ? backend.hasTable(legacyAltairName):
      # SyncCommitteePeriod -> altair.LightClientUpdate
      const legacyKind = Base10.toString(ord(LightClientDataFork.Altair).uint)
      ? backend.exec("""
        INSERT OR IGNORE INTO `""" & name & """` (
          `period`, `kind`, `update`
        )
        SELECT `period`, """ & legacyKind & """ AS `kind`, `update`
        FROM `""" & legacyAltairName & """`;
      """)
  if not ? backend.hasTable(name):
    return ok BestLightClientUpdateStore()

  let
    getStmt = backend.prepareStmt("""
      SELECT `kind`, `update`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, (int64, seq[byte]), managed = false)
      .expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `period`, `kind`, `update`
      ) VALUES (?, ?, ?);
    """, (int64, int64, seq[byte]), void, managed = false)
      .expect("SQL query OK")
    delStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok BestLightClientUpdateStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    keepFromStmt: keepFromStmt)

func close(store: var BestLightClientUpdateStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.delStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

proc getBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod
): ForkedLightClientUpdate =
  doAssert period.isSupportedBySQLite

  var update: (int64, seq[byte])
  proc processUpdate(): ForkedLightClientUpdate =
    try:
      withAll(LightClientDataFork):
        when lcDataFork > LightClientDataFork.None:
          if update[0] == ord(lcDataFork).int64:
            return ForkedLightClientUpdate.init(SSZ.decode(
              update[1], lcDataFork.LightClientUpdate))
      warn "Unsupported LC data store kind", store = "bestUpdates",
        period, kind = update[0]
      return default(ForkedLightClientUpdate)
    except SerializationError as exc:
      error "LC data store corrupted", store = "bestUpdates",
        period, kind = update[0], exc = exc.msg
      return default(ForkedLightClientUpdate)

  if distinctBase(db.bestUpdates.getStmt) != nil:
    for res in db.bestUpdates.getStmt.exec(period.int64, update):
      res.expect("SQL query OK")
      return processUpdate()
  if distinctBase(db.legacyBestUpdates.getStmt) != nil:
    for res in db.legacyBestUpdates.getStmt.exec(period.int64, update):
      res.expect("SQL query OK")
      return processUpdate()
  default(ForkedLightClientUpdate)

func putBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    update: ForkedLightClientUpdate) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  doAssert period.isSupportedBySQLite
  withForkyUpdate(update):
    when lcDataFork > LightClientDataFork.None:
      let numParticipants = forkyUpdate.sync_aggregate.num_active_participants
      if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
        block:
          let res = db.bestUpdates.delStmt.exec(period.int64)
          res.expect("SQL query OK")
        block:
          let res = db.legacyBestUpdates.delStmt.exec(period.int64)
          res.expect("SQL query OK")
      else:
        block:
          let res = db.bestUpdates.putStmt.exec(
            (period.int64, lcDataFork.int64, SSZ.encode(forkyUpdate)))
          res.expect("SQL query OK")
        when lcDataFork == LightClientDataFork.Altair:
          let res = db.legacyBestUpdates.putStmt.exec(
            (period.int64, SSZ.encode(forkyUpdate)))
          res.expect("SQL query OK")
        else:
          # Keep legacy table at best Altair update.
          discard
    else:
      block:
        let res = db.bestUpdates.delStmt.exec(period.int64)
        res.expect("SQL query OK")
      block:
        let res = db.legacyBestUpdates.delStmt.exec(period.int64)
        res.expect("SQL query OK")

proc initSealedPeriodsStore(
    backend: SqStoreRef,
    name: string): KvResult[SealedSyncCommitteePeriodStore] =
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `period` INTEGER PRIMARY KEY  -- `SyncCommitteePeriod`
      );
    """)
  if not ? backend.hasTable(name):
    return ok SealedSyncCommitteePeriodStore()

  let
    containsStmt = backend.prepareStmt("""
      SELECT 1 AS `exists`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, int64, managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `period`
      ) VALUES (?);
    """, int64, void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok SealedSyncCommitteePeriodStore(
    containsStmt: containsStmt,
    putStmt: putStmt,
    keepFromStmt: keepFromStmt)

func close(store: var SealedSyncCommitteePeriodStore) =
  store.containsStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

func isPeriodSealed*(
    db: LightClientDataDB, period: SyncCommitteePeriod): bool =
  doAssert period.isSupportedBySQLite
  if distinctBase(db.sealedPeriods.containsStmt) == nil:
    return false
  var exists: int64
  for res in db.sealedPeriods.containsStmt.exec(period.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  false

func sealPeriod*(
    db: LightClientDataDB, period: SyncCommitteePeriod) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  doAssert period.isSupportedBySQLite
  let res = db.sealedPeriods.putStmt.exec(period.int64)
  res.expect("SQL query OK")

func keepPeriodsFrom*(
    db: LightClientDataDB, minPeriod: SyncCommitteePeriod) =
  doAssert not db.backend.readOnly  # All `stmt` are non-nil
  doAssert minPeriod.isSupportedBySQLite
  block:
    let res = db.sealedPeriods.keepFromStmt.exec(minPeriod.int64)
    res.expect("SQL query OK")
  block:
    let res = db.bestUpdates.keepFromStmt.exec(minPeriod.int64)
    res.expect("SQL query OK")
  block:
    let res = db.legacyBestUpdates.keepFromStmt.exec(minPeriod.int64)
    res.expect("SQL query OK")
  block:
    let res = db.syncCommittees.keepFromStmt.exec(minPeriod.int64)
    res.expect("SQL query OK")
  let minSlot = min(minPeriod.start_slot, int64.high.Slot)
  block:
    let res = db.currentBranches.keepFromStmt.exec(minSlot.int64)
    res.expect("SQL query OK")
  for lcDataFork, store in db.headers:
    if lcDataFork > LightClientDataFork.None and
        distinctBase(store.keepFromStmt) != nil:
      let res = store.keepFromStmt.exec(minSlot.int64)
      res.expect("SQL query OK")

type LightClientDataDBNames* = object
  altairHeaders*: string
  capellaHeaders*: string
  denebHeaders*: string
  altairCurrentBranches*: string
  altairSyncCommittees*: string
  legacyAltairBestUpdates*: string
  bestUpdates*: string
  sealedPeriods*: string

proc initLightClientDataDB*(
    backend: SqStoreRef,
    names: LightClientDataDBNames): KvResult[LightClientDataDB] =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
  let
    headers = [
      # LightClientDataFork.None
      LightClientHeaderStore(),
      # LightClientDataFork.Altair
      ? backend.initHeadersStore(
        names.altairHeaders, "altair.LightClientHeader"),
      # LightClientDataFork.Capella
      ? backend.initHeadersStore(
        names.capellaHeaders, "capella.LightClientHeader"),
      # LightClientDataFork.Deneb
      ? backend.initHeadersStore(
        names.denebHeaders, "deneb.LightClientHeader")
    ]
    currentBranches =
      ? backend.initCurrentBranchesStore(names.altairCurrentBranches)
    syncCommittees =
      ? backend.initSyncCommitteesStore(names.altairSyncCommittees)
    legacyBestUpdates =
      ? backend.initLegacyBestUpdatesStore(names.legacyAltairBestUpdates)
    bestUpdates =
      ? backend.initBestUpdatesStore(
        names.bestUpdates, names.legacyAltairBestUpdates)
    sealedPeriods =
      ? backend.initSealedPeriodsStore(names.sealedPeriods)

  ok LightClientDataDB(
    headers: headers,
    backend: backend,
    currentBranches: currentBranches,
    syncCommittees: syncCommittees,
    legacyBestUpdates: legacyBestUpdates,
    bestUpdates: bestUpdates,
    sealedPeriods: sealedPeriods)

proc close*(db: LightClientDataDB) =
  if db.backend != nil:
    for lcDataFork in LightClientDataFork:
      if lcDataFork > LightClientDataFork.None:
        db.headers[lcDataFork].close()
    db.currentBranches.close()
    db.syncCommittees.close()
    db.legacyBestUpdates.close()
    db.bestUpdates.close()
    db.sealedPeriods.close()
    db[].reset()

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
  stew/base10,
  chronicles,
  eth/db/kvstore_sqlite3,
  # Beacon chain internals
  spec/datatypes/altair,
  spec/[eth2_ssz_serialization, helpers],
  ./db_limits

logScope: topics = "lcdata"

# `lc_altair_current_branches` holds merkle proofs needed to
# construct `LightClientBootstrap` objects.
# SSZ because this data does not compress well, and because this data
# needs to be bundled together with other data to fulfill requests.
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
#
# `lc_sealed_periods` contains the sync committee periods for which
# full light client data was imported. Data for these periods may no longer
# improve regardless of further block processing. The listed periods are skipped
# when restarting the program.

type
  CurrentSyncCommitteeBranchStore = object
    containsStmt: SqliteStmt[int64, int64]
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  BestLightClientUpdateStore = object
    getStmt: SqliteStmt[int64, (int64, seq[byte])]
    putStmt: SqliteStmt[(int64, int64, seq[byte]), void]
    delStmt: SqliteStmt[int64, void]
    delFromStmt: SqliteStmt[int64, void]
    keepFromStmt: SqliteStmt[int64, void]

  SealedSyncCommitteePeriodStore = object
    containsStmt: SqliteStmt[int64, int64]
    putStmt: SqliteStmt[int64, void]
    delFromStmt: SqliteStmt[int64, void]
    keepFromStmt: SqliteStmt[int64, void]

  LightClientDataDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    currentBranches: CurrentSyncCommitteeBranchStore
      ## Slot -> altair.CurrentSyncCommitteeBranch
      ## Cached data for creating future `LightClientBootstrap` instances.
      ## Key is the block slot of which the post state was used to get the data.
      ## Data stored for all finalized epoch boundary blocks.

    bestUpdates: BestLightClientUpdateStore
      ## SyncCommitteePeriod -> (LightClientDataFork, LightClientUpdate)
      ## Stores the `LightClientUpdate` with the most `sync_committee_bits` per
      ## `SyncCommitteePeriod`. Sync committee finality gives precedence.

    sealedPeriods: SealedSyncCommitteePeriodStore
      ## {SyncCommitteePeriod}
      ## Tracks the finalized sync committee periods for which complete data
      ## has been imported (from `dag.tail.slot`).

proc initCurrentBranchesStore(
    backend: SqStoreRef,
    name: string): KvResult[CurrentSyncCommitteeBranchStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `""" & name & """` (
      `slot` INTEGER PRIMARY KEY,  -- `Slot` (up through 2^63-1)
      `branch` BLOB                -- `altair.CurrentSyncCommitteeBranch` (SSZ)
    );
  """)

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
      INSERT INTO `""" & name & """` (
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

func close(store: CurrentSyncCommitteeBranchStore) =
  store.containsStmt.dispose()
  store.getStmt.dispose()
  store.putStmt.dispose()
  store.keepFromStmt.dispose()

func hasCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot): bool =
  if not slot.isSupportedBySQLite:
    return false
  var exists: int64
  for res in db.currentBranches.containsStmt.exec(slot.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  false

proc getCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot): altair.CurrentSyncCommitteeBranch =
  if not slot.isSupportedBySQLite:
    return default(altair.CurrentSyncCommitteeBranch)
  var branch: seq[byte]
  for res in db.currentBranches.getStmt.exec(slot.int64, branch):
    res.expect("SQL query OK")
    try:
      return SSZ.decode(branch, altair.CurrentSyncCommitteeBranch)
    except SszError as exc:
      error "LC data store corrupted", store = "currentBranches",
        slot, exc = exc.msg
      return default(altair.CurrentSyncCommitteeBranch)

func putCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot,
    branch: altair.CurrentSyncCommitteeBranch) =
  if not slot.isSupportedBySQLite:
    return
  let res = db.currentBranches.putStmt.exec((slot.int64, SSZ.encode(branch)))
  res.expect("SQL query OK")

proc initBestUpdatesStore(
    backend: SqStoreRef,
    name, legacyAltairName: string,
): KvResult[BestLightClientUpdateStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `""" & name & """` (
      `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
      `kind` INTEGER,                -- `LightClientDataFork`
      `update` BLOB                  -- `LightClientUpdate` (SSZ)
    );
  """)
  if backend.hasTable(legacyAltairName).expect("SQL query OK"):
    info "Importing Altair light client data"
    # SyncCommitteePeriod -> altair.LightClientUpdate
    const legacyKind = Base10.toString(ord(LightClientDataFork.Altair).uint)
    ? backend.exec("""
      INSERT OR IGNORE INTO `""" & name & """` (
        `period`, `kind`, `update`
      )
      SELECT `period`, """ & legacyKind & """ AS `kind`, `update`
      FROM `""" & legacyAltairName & """`;
    """)
    ? backend.exec("""
      DROP TABLE `""" & legacyAltairName & """`;
    """)

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
    delFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` >= ?;
    """, int64, void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok BestLightClientUpdateStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    delFromStmt: delFromStmt,
    keepFromStmt: keepFromStmt)

func close(store: BestLightClientUpdateStore) =
  store.getStmt.dispose()
  store.putStmt.dispose()
  store.delStmt.dispose()
  store.delFromStmt.dispose()
  store.keepFromStmt.dispose()

proc getBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod
): ForkedLightClientUpdate =
  doAssert period.isSupportedBySQLite
  var update: (int64, seq[byte])
  for res in db.bestUpdates.getStmt.exec(period.int64, update):
    res.expect("SQL query OK")
    try:
      withAll(LightClientDataFork):
        when lcDataFork > LightClientDataFork.None:
          if update[0] == ord(lcDataFork).int64:
            var obj = ForkedLightClientUpdate(kind: lcDataFork)
            obj.forky(lcDataFork) = SSZ.decode(
              update[1], lcDataFork.LightClientUpdate)
            return obj
      warn "Unsupported LC data store kind", store = "bestUpdates",
        period, kind = update[0]
      return default(ForkedLightClientUpdate)
    except SszError as exc:
      error "LC data store corrupted", store = "bestUpdates",
        period, kind = update[0], exc = exc.msg
      return default(ForkedLightClientUpdate)

func putBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    update: ForkedLightClientUpdate) =
  doAssert period.isSupportedBySQLite
  withForkyUpdate(update):
    when lcDataFork > LightClientDataFork.None:
      let numParticipants = forkyUpdate.sync_aggregate.num_active_participants
      if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
        let res = db.bestUpdates.delStmt.exec(period.int64)
        res.expect("SQL query OK")
      else:
        let res = db.bestUpdates.putStmt.exec(
          (period.int64, lcDataFork.int64, SSZ.encode(forkyUpdate)))
        res.expect("SQL query OK")
    else:
      let res = db.bestUpdates.delStmt.exec(period.int64)
      res.expect("SQL query OK")

proc putUpdateIfBetter*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    update: ForkedLightClientUpdate) =
  let existing = db.getBestUpdate(period)
  if is_better_update(update, existing):
    db.putBestUpdate(period, update)

proc initSealedPeriodsStore(
    backend: SqStoreRef,
    name: string): KvResult[SealedSyncCommitteePeriodStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `""" & name & """` (
      `period` INTEGER PRIMARY KEY  -- `SyncCommitteePeriod`
    );
  """)

  let
    containsStmt = backend.prepareStmt("""
      SELECT 1 AS `exists`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, int64, managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      INSERT INTO `""" & name & """` (
        `period`
      ) VALUES (?);
    """, int64, void, managed = false).expect("SQL query OK")
    delFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` >= ?;
    """, int64, void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `period` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok SealedSyncCommitteePeriodStore(
    containsStmt: containsStmt,
    putStmt: putStmt,
    delFromStmt: delFromStmt,
    keepFromStmt: keepFromStmt)

func close(store: SealedSyncCommitteePeriodStore) =
  store.containsStmt.dispose()
  store.putStmt.dispose()
  store.delFromStmt.dispose()
  store.keepFromStmt.dispose()

func isPeriodSealed*(
    db: LightClientDataDB, period: SyncCommitteePeriod): bool =
  doAssert period.isSupportedBySQLite
  var exists: int64
  for res in db.sealedPeriods.containsStmt.exec(period.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  false

func sealPeriod*(
    db: LightClientDataDB, period: SyncCommitteePeriod) =
  doAssert period.isSupportedBySQLite
  let res = db.sealedPeriods.putStmt.exec(period.int64)
  res.expect("SQL query OK")

func delNonFinalizedPeriodsFrom*(
    db: LightClientDataDB, minPeriod: SyncCommitteePeriod) =
  doAssert minPeriod.isSupportedBySQLite
  let res1 = db.sealedPeriods.delFromStmt.exec(minPeriod.int64)
  res1.expect("SQL query OK")
  let res2 = db.bestUpdates.delFromStmt.exec(minPeriod.int64)
  res2.expect("SQL query OK")
  # `currentBranches` only has finalized data

func keepPeriodsFrom*(
    db: LightClientDataDB, minPeriod: SyncCommitteePeriod) =
  doAssert minPeriod.isSupportedBySQLite
  let res1 = db.sealedPeriods.keepFromStmt.exec(minPeriod.int64)
  res1.expect("SQL query OK")
  let res2 = db.bestUpdates.keepFromStmt.exec(minPeriod.int64)
  res2.expect("SQL query OK")
  let
    minSlot = min(minPeriod.start_slot, int64.high.Slot)
    res3 = db.currentBranches.keepFromStmt.exec(minSlot.int64)
  res3.expect("SQL query OK")

type LightClientDataDBNames* = object
  altairCurrentBranches*: string
  legacyAltairBestUpdates*: string
  bestUpdates*: string
  sealedPeriods*: string

proc initLightClientDataDB*(
    backend: SqStoreRef,
    names: LightClientDataDBNames): KvResult[LightClientDataDB] =
  let
    currentBranches =
      ? backend.initCurrentBranchesStore(names.altairCurrentBranches)
    bestUpdates =
      ? backend.initBestUpdatesStore(
        names.bestUpdates, names.legacyAltairBestUpdates)
    sealedPeriods =
      ? backend.initSealedPeriodsStore(names.sealedPeriods)

  ok LightClientDataDB(
    backend: backend,
    currentBranches: currentBranches,
    bestUpdates: bestUpdates,
    sealedPeriods: sealedPeriods)

proc close*(db: LightClientDataDB) =
  if db.backend != nil:
    db.currentBranches.close()
    db.bestUpdates.close()
    db.sealedPeriods.close()
    db[].reset()

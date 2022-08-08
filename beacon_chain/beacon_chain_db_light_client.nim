# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}


# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Status libraries
  chronicles,
  eth/db/kvstore_sqlite3,
  # Beacon chain internals
  spec/datatypes/altair,
  spec/[eth2_ssz_serialization, helpers]

logScope: topics = "lcdata"

# `altair_current_sync_committee_branches` holds merkle proofs needed to
# construct `LightClientBootstrap` objects. The sync committee needs to
# be computed from the main DAG on-demand (usually a fast state access).
# SSZ because this data does not compress well, and because this data
# needs to be bundled together with other data to fulfill requests.
#
# `altair_best_updates` holds full `LightClientUpdate` objects in SSZ form.
# These objects are frequently queried in bunk, but there is only one per
# sync committee period, so storing the full sync committee is acceptable.
# This data could be stored as SZSSZ to avoid on-the-fly compression when a
# libp2p request is handled. However, the space savings are quite small.
# Furthermore, `LightClientUpdate` is consulted on each new block to attempt
# improving it. Continuously decompressing and recompressing seems inefficient.
# Finally, the libp2p context bytes depend on `attested_header.slot` to derive
# the underlying fork digest. The table name is insufficient to determine this
# unless one is made for each fork, even if there was no structural change.
# SSZ storage selected due to the small size and reduced logic complexity.
#
# `sealed_sync_committee_periods` contains the sync committee periods for which
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
    getStmt: SqliteStmt[int64, seq[byte]]
    putStmt: SqliteStmt[(int64, seq[byte]), void]
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
      ## SyncCommitteePeriod -> altair.LightClientUpdate
      ## Stores the `LightClientUpdate` with the most `sync_committee_bits` per
      ## `SyncCommitteePeriod`. Sync committee finality gives precedence.

    sealedPeriods: SealedSyncCommitteePeriodStore
      ## {SyncCommitteePeriod}
      ## Tracks the finalized sync committee periods for which complete data
      ## has been imported (from `dag.tail.slot`).

# No `uint64` support in Sqlite
template isSupportedBySQLite(slot: Slot): bool =
  slot <= int64.high.Slot
template isSupportedBySQLite(period: SyncCommitteePeriod): bool =
  period <= int64.high.SyncCommitteePeriod

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
    except MalformedSszError, SszSizeMismatchError:
      error "LC store corrupted", store = "currentBranches", slot,
        exc = getCurrentException().name, err = getCurrentExceptionMsg()
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
    name: string): KvResult[BestLightClientUpdateStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `""" & name & """` (
      `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
      `update` BLOB                  -- `altair.LightClientUpdate` (SSZ)
    );
  """)

  let
    getStmt = backend.prepareStmt("""
      SELECT `update`
      FROM `""" & name & """`
      WHERE `period` = ?;
    """, int64, seq[byte], managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `period`, `update`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void, managed = false).expect("SQL query OK")
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
): altair.LightClientUpdate =
  doAssert period.isSupportedBySQLite
  var update: seq[byte]
  for res in db.bestUpdates.getStmt.exec(period.int64, update):
    res.expect("SQL query OK")
    try:
      return SSZ.decode(update, altair.LightClientUpdate)
    except MalformedSszError, SszSizeMismatchError:
      error "LC store corrupted", store = "bestUpdates", period,
        exc = getCurrentException().name, err = getCurrentExceptionMsg()
      return default(altair.LightClientUpdate)

func putBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    update: altair.LightClientUpdate) =
  doAssert period.isSupportedBySQLite
  let numParticipants = countOnes(update.sync_aggregate.sync_committee_bits)
  if numParticipants < MIN_SYNC_COMMITTEE_PARTICIPANTS:
    let res = db.bestUpdates.delStmt.exec(period.int64)
    res.expect("SQL query OK")
  else:
    let res = db.bestUpdates.putStmt.exec(
      (period.int64, SSZ.encode(update)))
    res.expect("SQL query OK")

proc putUpdateIfBetter*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    update: altair.LightClientUpdate) =
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

func delPeriodsFrom*(
    db: LightClientDataDB, minPeriod: SyncCommitteePeriod) =
  doAssert minPeriod.isSupportedBySQLite
  let res1 = db.sealedPeriods.delFromStmt.exec(minPeriod.int64)
  res1.expect("SQL query OK")
  let res2 = db.bestUpdates.delFromStmt.exec(minPeriod.int64)
  res2.expect("SQL query OK")

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
  altairBestUpdates*: string
  sealedPeriods*: string

proc initLightClientDataDB*(
    backend: SqStoreRef,
    names: LightClientDataDBNames): KvResult[LightClientDataDB] =
  let
    currentBranches =
      ? backend.initCurrentBranchesStore(names.altairCurrentBranches)
    bestUpdates =
      ? backend.initBestUpdatesStore(names.altairBestUpdates)
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

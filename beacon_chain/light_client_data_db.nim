# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Standard library
  std/os,
  # Status libraries
  chronicles,
  eth/db/kvstore_sqlite3,
  # Beacon chain internals
  spec/datatypes/altair,
  spec/[eth2_ssz_serialization, helpers],
  ./filepath

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
# Furthermore, the libp2p context bytes depend on `attested_header.slot`, so
# this would need to be stored separately to avoid having to decompress.
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

  LightClientDataDB* = object
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

proc initCurrentSyncCommitteeBranchStore(
    backend: SqStoreRef): KvResult[CurrentSyncCommitteeBranchStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `altair_current_sync_committee_branches` (
      `slot` INTEGER PRIMARY KEY,  -- `Slot` (up through 2^63-1)
      `branch` BLOB                -- `altair.CurrentSyncCommitteeBranch` (SSZ)
    );
  """)

  let
    containsStmt = ? backend.prepareStmt("""
      SELECT 1 AS `exists`
      FROM `altair_current_sync_committee_branches`
      WHERE `slot` = ?;
    """, int64, int64)
    getStmt = ? backend.prepareStmt("""
      SELECT `branch`
      FROM `altair_current_sync_committee_branches`
      WHERE `slot` = ?;
    """, int64, seq[byte])
    putStmt = ? backend.prepareStmt("""
      INSERT INTO `altair_current_sync_committee_branches` (
        `slot`, `branch`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void)
    keepFromStmt = ? backend.prepareStmt("""
      DELETE FROM `altair_current_sync_committee_branches`
      WHERE `slot` < ?;
    """, int64, void)

  ok CurrentSyncCommitteeBranchStore(
    containsStmt: containsStmt,
    getStmt: getStmt,
    putStmt: putStmt,
    keepFromStmt: keepFromStmt)

func hasCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot): bool =
  if slot > int64.high.Slot:
    return false  # No `uint64` support
  var exists: int64
  for res in db.currentBranches.containsStmt.exec(slot.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  return false

proc getCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot): altair.CurrentSyncCommitteeBranch =
  if slot > int64.high.Slot:
    return  # No `uint64` support
  var branch: seq[byte]
  for res in db.currentBranches.getStmt.exec(slot.int64, branch):
    res.expect("SQL query OK")
    try:
      return SSZ.decode(branch, altair.CurrentSyncCommitteeBranch)
    except MalformedSszError, SszSizeMismatchError:
      error "LC store corrupted", store = "currentBranches", slot,
        exc = getCurrentException().name, err = getCurrentExceptionMsg()
      return

func putCurrentSyncCommitteeBranch*(
    db: LightClientDataDB, slot: Slot,
    branch: altair.CurrentSyncCommitteeBranch) =
  if slot > int64.high.Slot:
    return  # No `uint64` support
  let res = db.currentBranches.putStmt.exec((slot.int64, SSZ.encode(branch)))
  res.expect("SQL query OK")

proc initBestUpdateStore(
    backend: SqStoreRef): KvResult[BestLightClientUpdateStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `altair_best_updates` (
      `period` INTEGER PRIMARY KEY,  -- `SyncCommitteePeriod`
      `update` BLOB                  -- `altair.LightClientUpdate` (SSZ)
    );
  """)

  let
    getStmt = ? backend.prepareStmt("""
      SELECT `update`
      FROM `altair_best_updates`
      WHERE `period` = ?;
    """, int64, seq[byte])
    putStmt = ? backend.prepareStmt("""
      REPLACE INTO `altair_best_updates` (
        `period`, `update`
      ) VALUES (?, ?);
    """, (int64, seq[byte]), void)
    delStmt = ? backend.prepareStmt("""
      DELETE FROM `altair_best_updates`
      WHERE `period` = ?;
    """, int64, void)
    delFromStmt = ? backend.prepareStmt("""
      DELETE FROM `altair_best_updates`
      WHERE `period` >= ?;
    """, int64, void)
    keepFromStmt = ? backend.prepareStmt("""
      DELETE FROM `altair_best_updates`
      WHERE `period` < ?;
    """, int64, void)

  ok BestLightClientUpdateStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    delFromStmt: delFromStmt,
    keepFromStmt: keepFromStmt)

proc getBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod
): altair.LightClientUpdate =
  doAssert period <= int64.high.SyncCommitteePeriod
  var update: seq[byte]
  for res in db.bestUpdates.getStmt.exec(period.int64, update):
    res.expect("SQL query OK")
    try:
      return SSZ.decode(update, altair.LightClientUpdate)
    except MalformedSszError, SszSizeMismatchError:
      error "LC store corrupted", store = "bestUpdates", period,
        exc = getCurrentException().name, err = getCurrentExceptionMsg()
      return

func putBestUpdate*(
    db: LightClientDataDB, period: SyncCommitteePeriod,
    update: altair.LightClientUpdate) =
  doAssert period <= int64.high.SyncCommitteePeriod
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

proc initSealedPeriodStore(
    backend: SqStoreRef): KvResult[SealedSyncCommitteePeriodStore] =
  ? backend.exec("""
    CREATE TABLE IF NOT EXISTS `sealed_sync_committee_periods` (
      `period` INTEGER PRIMARY KEY  -- `SyncCommitteePeriod`
    );
  """)

  let
    containsStmt = ? backend.prepareStmt("""
      SELECT 1 AS `exists`
      FROM `sealed_sync_committee_periods`
      WHERE `period` = ?;
    """, int64, int64)
    putStmt = ? backend.prepareStmt("""
      INSERT INTO `sealed_sync_committee_periods` (
        `period`
      ) VALUES (?);
    """, int64, void)
    delFromStmt = ? backend.prepareStmt("""
      DELETE FROM `sealed_sync_committee_periods`
      WHERE `period` >= ?;
    """, int64, void)
    keepFromStmt = ? backend.prepareStmt("""
      DELETE FROM `sealed_sync_committee_periods`
      WHERE `period` < ?;
    """, int64, void)

  ok SealedSyncCommitteePeriodStore(
    containsStmt: containsStmt,
    putStmt: putStmt,
    delFromStmt: delFromStmt,
    keepFromStmt: keepFromStmt)

func isPeriodSealed*(
    db: LightClientDataDB, period: SyncCommitteePeriod): bool =
  doAssert period <= int64.high.SyncCommitteePeriod
  var exists: int64
  for res in db.sealedPeriods.containsStmt.exec(period.int64, exists):
    res.expect("SQL query OK")
    doAssert exists == 1
    return true
  return false

func sealPeriod*(
    db: LightClientDataDB, period: SyncCommitteePeriod) =
  doAssert period <= int64.high.SyncCommitteePeriod
  let res = db.sealedPeriods.putStmt.exec(period.int64)
  res.expect("SQL query OK")

func delPeriodsFrom*(
    db: LightClientDataDB, minPeriod: SyncCommitteePeriod) =
  doAssert minPeriod <= int64.high.SyncCommitteePeriod
  let res1 = db.sealedPeriods.delFromStmt.exec(minPeriod.int64)
  res1.expect("SQL query OK")
  let res2 = db.bestUpdates.delFromStmt.exec(minPeriod.int64)
  res2.expect("SQL query OK")

func keepPeriodsFrom*(
    db: LightClientDataDB, minPeriod: SyncCommitteePeriod) =
  doAssert minPeriod <= int64.high.SyncCommitteePeriod
  let res1 = db.sealedPeriods.keepFromStmt.exec(minPeriod.int64)
  res1.expect("SQL query OK")
  let res2 = db.bestUpdates.keepFromStmt.exec(minPeriod.int64)
  res2.expect("SQL query OK")
  let
    minSlot = min(minPeriod.start_slot, int64.high.Slot)
    res3 = db.currentBranches.keepFromStmt.exec(minSlot.int64)
  res3.expect("SQL query OK")

proc initLightClientDataDB*(
    dir: string, inMemory = false): Opt[LightClientDataDB] =
  logScope:
    path = dir
    inMemory

  if not inMemory:
    let res = secureCreatePath(dir)
    if res.isErr:
      warn "Failed to create DB directory", err = ioErrorMsg(res.error)
      return err()

  const dbName = "lcdataV1"
  let
    backend = SqStoreRef.init(dir, dbName, inMemory = inMemory).valueOr:
      warn "Failed to create LC data DB", err = error
      return err()

    currentBranches = backend.initCurrentSyncCommitteeBranchStore().valueOr:
      warn "Failed to init LC store", store = "currentBranches", err = error
      backend.close()
      return err()
    bestUpdates = backend.initBestUpdateStore().valueOr:
      warn "Failed to init LC store", store = "bestUpdates", err = error
      backend.close()
      return err()
    sealedPeriods = backend.initSealedPeriodStore().valueOr:
      warn "Failed to init LC store", store = "sealedPeriods", err = error
      backend.close()
      return err()

  ok LightClientDataDB(
    backend: backend,
    currentBranches: currentBranches,
    bestUpdates: bestUpdates,
    sealedPeriods: sealedPeriods)

proc close*(db: var LightClientDataDB) =
  if db.backend != nil:
    db.backend.close()
    db.reset()

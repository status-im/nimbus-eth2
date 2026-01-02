# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Status libraries
  chronicles,
  eth/db/kvstore_sqlite3,
  # Beacon chain internals
  spec/helpers,
  ./db_utils

# Without this export compilation fails with error
# vendor\nim-chronicles\chronicles.nim(352, 21) Error: undeclared identifier: 'activeChroniclesStream'
# It actually is not needed, because chronicles is not used in this file,
# but because decodeSZSSZ() is generic and uses chronicles - generic expansion
# introduces this issue.
export chronicles

logScope: topics = "qudata"

type
  ForkyDataSidecar* = deneb.BlobSidecar | fulu.DataColumnSidecar |
                      gloas.DataColumnSidecar

  DataSidecarStore = object
    getStmt: SqliteStmt[array[32, byte], seq[byte]]
    putStmt: SqliteStmt[(array[32, byte], seq[byte]), void]
    delStmt: SqliteStmt[array[32, byte], void]
    countStmt: SqliteStmt[NoParams, int64]

  QuarantineDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    electraDataSidecar: DataSidecarStore
      ## Proposer signature verified data blob sidecars.
    fuluDataSidecar: DataSidecarStore
      ## Proposer signature verified data column sidecars.
    gloasDataSidecar: DataSidecarStore
      ## Proposer signature verified data column sidecars.

template tableName(sidecar: typedesc[ForkyDataSidecar]): string =
  when sidecar is deneb.BlobSidecar:
    "electra_sidecars_quarantine"
  elif sidecar is fulu.DataColumnSidecar:
    "fulu_sidecars_quarantine"
  elif sidecar is gloas.DataColumnSidecar:
    "gloas_sidecars_quarantine"
  else:
    static: raiseAssert "Sidecar's fork is not supported"

proc initDataSidecarStore(
    backend: SqStoreRef,
    name: string
): KvResult[DataSidecarStore] =
  if not(backend.readOnly):
    ? backend.exec("BEGIN TRANSACTION;")
    ? backend.exec("DROP INDEX IF EXISTS `" & name & "_iblock_root`;")
    ? backend.exec("DROP TABLE IF EXISTS `" & name & "`;")
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `block_root` BLOB,   -- `Eth2Digest`
        `data_sidecar` BLOB  -- `DataSidecar` (SZSSZ)
      );
    """)
    ? backend.exec("""
      CREATE INDEX IF NOT EXISTS `""" & name & """_iblock_root`
      ON `""" & name & """`(block_root);
    """)
    ? backend.exec("COMMIT;")

  if not ? backend.hasTable(name):
    return ok(DataSidecarStore())

  let
    getStmt = backend.prepareStmt("""
      SELECT `data_sidecar` FROM `""" & name & """`
      WHERE `block_root` = ?;
    """, array[32, byte], (seq[byte]), managed = false)
      .expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      INSERT INTO `""" & name & """` (
        `block_root`, `data_sidecar`
      ) VALUES (?, ?);
    """, (array[32, byte], seq[byte]), void, managed = false).expect("SQL query OK")
    delStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """` WHERE `block_root` == ?;
    """, array[32, byte], void, managed = false).expect("SQL query OK")
    countStmt = backend.prepareStmt("""
      SELECT COUNT(1) FROM `""" & name & """`;
    """, NoParams, int64, managed = false).expect("SQL query OK")

  ok(DataSidecarStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    countStmt: countStmt
  ))

func close(store: var DataSidecarStore) =
  if not(isNil(distinctBase(store.getStmt))): store.getStmt.disposeSafe()
  if not(isNil(distinctBase(store.putStmt))): store.putStmt.disposeSafe()
  if not(isNil(distinctBase(store.delStmt))): store.delStmt.disposeSafe()
  if not(isNil(distinctBase(store.countStmt))): store.countStmt.disposeSafe()

iterator sidecars*(
    db: QuarantineDB,
    T: typedesc[ForkyDataSidecar],
    blockRoot: Eth2Digest
): T =
  when T is deneb.BlobSidecar:
    template statement: untyped =
      db.electraDataSidecar.getStmt
    template storeName: untyped =
      "electraDataSidecar"
  elif T is fulu.DataColumnSidecar:
    template statement: untyped =
      db.fuluDataSidecar.getStmt
    template storeName: untyped =
      "fuluDataSidecar"
  elif T is gloas.DataColumnSidecar:
    template statement: untyped =
      db.gloasDataSidecar.getStmt
    template storeName: untyped =
      "gloasDataSidecar"
  else:
    static: raiseAssert "Sidecar's fork is not supported"

  if not(isNil(distinctBase(statement))):
    var row: statement.Result
    for rowRes in statement.exec(blockRoot.data, row):
      rowRes.expect("SQL query OK")
      var res: T
      if not(decodeSZSSZ(row, res)):
        error "Quarantine store corrupted", store = storeName,
              blockRoot
        break
      yield res

proc putDataSidecars*[T: ForkyDataSidecar](
    db: QuarantineDB,
    blockRoot: Eth2Digest,
    dataSidecars: openArray[ref T]
) =
  doAssert(not(db.backend.readOnly))

  when T is deneb.BlobSidecar:
    template statement: untyped =
      db.electraDataSidecar.putStmt
  elif T is fulu.DataColumnSidecar:
    template statement: untyped =
      db.fuluDataSidecar.putStmt
  elif T is gloas.DataColumnSidecar:
    template statement: untyped =
      db.gloasDataSidecar.putStmt
  else:
    static: raiseAssert "Sidecar's fork is not supported"

  if not(isNil(distinctBase(statement))):
    db.backend.exec("BEGIN TRANSACTION;").expect("SQL query OK")
    for sidecar in dataSidecars:
      let blob = encodeSZSSZ(sidecar[])
      statement.exec((blockRoot.data, blob)).
        expect("SQL query OK")
    db.backend.exec("COMMIT;").expect("SQL query OK")

proc removeDataSidecars*(
    db: QuarantineDB,
    T: typedesc[ForkyDataSidecar],
    blockRoot: Eth2Digest
) =
  doAssert not(db.backend.readOnly)

  when T is deneb.BlobSidecar:
    template statement: untyped =
      db.electraDataSidecar.delStmt
  elif T is fulu.DataColumnSidecar:
    template statement: untyped =
      db.fuluDataSidecar.delStmt
  elif T is gloas.DataColumnSidecar:
    template statement: untyped =
      db.gloasDataSidecar.delStmt
  else:
    static: raiseAssert "Sidecar's fork is not supported"

  if not(isNil(distinctBase(statement))):
    statement.exec(blockRoot.data).expect("SQL query OK")

proc sidecarsCount*(
    db: QuarantineDB,
    T: typedesc[ForkyDataSidecar],
): int64 =
  var recordCount = 0'i64

  when T is deneb.BlobSidecar:
    template statement: untyped =
      db.electraDataSidecar.countStmt
  elif T is fulu.DataColumnSidecar:
    template statement: untyped =
      db.fuluDataSidecar.countStmt
  elif T is gloas.DataColumnSidecar:
    template statement: untyped =
      db.gloasDataSidecar.countStmt
  else:
    static: raiseAssert "Sidecar's fork is not supported"

  if not(isNil(distinctBase(statement))):
    discard statement.exec do (res: int64):
      recordCount = res
  recordCount

proc initQuarantineDB*(
    backend: SqStoreRef,
): KvResult[QuarantineDB] =
  # Please note that all quarantine tables are temporary, each time the node is
  # restarted these tables will be wiped out completely.
  # Therefore there is no need to maintain forward or backward compatibility
  # guarantees.
  let
    electraDataSidecar =
      ? backend.initDataSidecarStore(tableName(deneb.BlobSidecar))
    fuluDataSidecar =
      ? backend.initDataSidecarStore(tableName(fulu.DataColumnSidecar))
    gloasDataSidecar =
      ? backend.initDataSidecarStore(tableName(gloas.DataColumnSidecar))

  ok QuarantineDB(
    backend: backend,
    electraDataSidecar: electraDataSidecar,
    fuluDataSidecar: fuluDataSidecar,
    gloasDataSidecar: gloasDataSidecar
  )

proc close*(db: QuarantineDB) =
  if not(isNil(db.backend)):
    db.electraDataSidecar.close()
    db.fuluDataSidecar.close()
    db.gloasDataSidecar.close()
    db[].reset()

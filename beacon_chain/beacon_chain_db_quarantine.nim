# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
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

logScope: topics = "qudata"

type
  ForkyDataSidecar* = deneb.BlobSidecar | fulu.DataColumnSidecar

  DataSidecarStore = object
    getStmt: SqliteStmt[array[32, byte], seq[byte]]
    putStmt: SqliteStmt[(array[32, byte], seq[byte]), void]
    delStmt: SqliteStmt[array[32, byte], int64]

  QuarantineDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    electraDataSidecar: DataSidecarStore
      ## Proposer signature verified data blob sidecars.
    fuluDataSidecar: DataSidecarStore
      ## Proposer signature verified data column sidecars.

template tableName(sidecar: typedesc[ForkyDataSidecar]): string =
  when sidecar is deneb.BlobSidecar:
    "electra_sidecars_quarantine"
  else:
    "fulu_sidecars_quarantine"

proc initDataSidecarStore(
    backend: SqStoreRef,
    name: string
): KvResult[DataSidecarStore] =
  if name == "":
    return ok(DataSidecarStore())

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
      DELETE FROM `""" & name & """` WHERE `block_root` == ? RETURNING ROWID;
    """, array[32, byte], (int64), managed = false).expect("SQL query OK")

  ok(DataSidecarStore(getStmt: getStmt, putStmt: putStmt, delStmt: delStmt))

func close(store: var DataSidecarStore) =
  if not(isNil(distinctBase(store.getStmt))): store.getStmt.disposeSafe()
  if not(isNil(distinctBase(store.putStmt))): store.putStmt.disposeSafe()
  if not(isNil(distinctBase(store.delStmt))): store.delStmt.disposeSafe()

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
  else:
    template statement: untyped =
      db.fuluDataSidecar.getStmt
    template storeName: untyped =
      "fuluDataSidecar"

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
  doAssert not(db.backend.readOnly)

  when T is deneb.BlobSidecar:
    template statement: untyped =
      db.electraDataSidecar.putStmt
  else:
    template statement: untyped =
      db.fuluDataSidecar.putStmt

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
): int =
  var res = 0
  doAssert not(db.backend.readOnly)

  when T is deneb.BlobSidecar:
    template statement: untyped =
      db.electraDataSidecar.delStmt
  else:
    template statement: untyped =
      db.fuluDataSidecar.delStmt

  if not(isNil(distinctBase(statement))):
    var row: statement.Result
    for rowRes in statement.exec(blockRoot.data, row):
      rowRes.expect("SQL query OK")
      inc(res)
  res

proc clearDataSidecars*(
    db: QuarantineDB,
    T: typedesc[ForkyDataSidecar],
) =
  doAssert not(db.backend.readOnly)
  db.backend.exec("DELETE FROM `" & tableName(T) & "`;").expect("SQL query OK")

proc initQuarantineDB*(
    backend: SqStoreRef,
): KvResult[QuarantineDB] =
  let
    electraDataSidecar =
      ? backend.initDataSidecarStore(tableName(deneb.BlobSidecar))
    fuluDataSidecar =
      ? backend.initDataSidecarStore(tableName(fulu.DataColumnSidecar))

  ok QuarantineDB(
    backend: backend,
    electraDataSidecar: electraDataSidecar,
    fuluDataSidecar: fuluDataSidecar
  )

proc close*(db: QuarantineDB) =
  if not(isNil(db.backend)):
    db.electraDataSidecar.close()
    db.fuluDataSidecar.close()
    db[].reset()

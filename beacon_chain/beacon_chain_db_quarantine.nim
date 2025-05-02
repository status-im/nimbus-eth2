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
  DataSidecarFork* {.pure.} = enum  # Append only, used in DB data!
    None = 0,  # only use non-0 in DB to detect accidentally uninitialized data
    Deneb,
    Fulu

  ForkyDataSidecar* =
    deneb.BlobSidecar |
    fulu.DataColumnSidecar

  DataSidecarStore = object
    getStmt: SqliteStmt[array[40, byte], (int64, seq[byte])]
    putStmt: SqliteStmt[(array[40, byte], int64, seq[byte]), void]
    delStmt: SqliteStmt[(array[40, byte], array[40, byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  QuarantineDB* = ref object
    forkEpochs: ForkEpochs

    backend: SqStoreRef
      ## SQLite backend

    dataSidecars: DataSidecarStore
      ## (Eth2Digest | index) -> (Slot, DataSidecar)
      ## Proposer signature verified data sidecars.

proc initDataSidecarStore(
    backend: SqStoreRef,
    name: string): KvResult[DataSidecarStore] =
  if name == "":
    return ok DataSidecarStore()
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `block_root_index` BLOB PRIMARY KEY,  -- `Eth2Digest | uint64 (BE)`
        `slot` INTEGER,                       -- `Slot`
        `data_sidecar` BLOB                   -- `DataSidecar` (SZSSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok DataSidecarStore()

  let
    getStmt = backend.prepareStmt("""
      SELECT `slot`, `data_sidecar`
      FROM `""" & name & """`
      WHERE `block_root_index` = ?;
    """, array[40, byte], (int64, seq[byte]), managed = false)
      .expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `block_root_index`, `slot`, `data_sidecar`
      ) VALUES (?, ?, ?);
    """, (array[40, byte], int64, seq[byte]),
      void, managed = false).expect("SQL query OK")
    delStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `block_root_index` >= ? and `block_root_index` <= ?;
    """, (array[40, byte], array[40, byte]),
      void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `slot` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok DataSidecarStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    keepFromStmt: keepFromStmt)

func close(store: var DataSidecarStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.delStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

template kind*(x: typedesc[deneb.BlobSidecar]): DataSidecarFork =
  DataSidecarFork.Deneb

template kind*(x: typedesc[fulu.DataColumnSidecar]): DataSidecarFork =
  DataSidecarFork.Fulu

template DataSidecar*(kind: static DataSidecarFork): auto =
  when kind == DataSidecarFork.Fulu:
    typedesc[fulu.DataColumnSidecar]
  elif kind == DataSidecarFork.Deneb:
    typedesc[deneb.BlobSidecar]
  else:
    {.error: "DataSidecar does not support " & $kind.}

template withAll*(x: typedesc[DataSidecarFork], body: untyped): untyped =
  static: doAssert DataSidecarFork.high == DataSidecarFork.Fulu
  block:
    const dataSidecarFork {.inject, used.} = DataSidecarFork.Fulu
    body
  block:
    const dataSidecarFork {.inject, used.} = DataSidecarFork.Deneb
    body
  block:
    const dataSidecarFork {.inject, used.} = DataSidecarFork.None
    body

func dataSidecarForkAtConsensusFork*(
    consensusFork: ConsensusFork): DataSidecarFork =
  static: doAssert DataSidecarFork.high == DataSidecarFork.Fulu
  if consensusFork >= ConsensusFork.Fulu:
    DataSidecarFork.Fulu
  elif consensusFork >= ConsensusFork.Deneb:
    DataSidecarFork.Deneb
  else:
    DataSidecarFork.None

func dataSidecarKey(blockRoot: Eth2Digest, index: uint64): array[40, byte] =
  var res: array[40, byte]
  res[0 ..< 32] = blockRoot.data
  res[32 ..< 40] = toBytesBE(index)
  res

proc getDataSidecar*[T: ForkyDataSidecar](
    db: QuarantineDB, blockRoot: Eth2Digest, index: uint64): Opt[T] =
  if distinctBase(db.dataSidecars.getStmt) == nil:
    return Opt.none(T)
  var dataSidecar: (int64, seq[byte])
  let blockRootIndex = blockRoot.dataSidecarKey(index)
  for res in db.dataSidecars.getStmt.exec(blockRootIndex, dataSidecar):
    res.expect("SQL query OK")
    let dataSidecarFork = dataSidecarForkAtConsensusFork(
      db.forkEpochs.consensusForkAtEpoch(dataSidecar[0].uint64.Slot.epoch))
    if dataSidecarFork != T.kind:
      warn "Unsupported quarantine store kind", store = "dataSidecars",
        blockRoot, slot = dataSidecar[0], kind = dataSidecarFork
      return Opt.none(T)
    var res: T
    if not decodeSZSSZ(dataSidecar[1], res):
      error "Quarantine store corrupted", store = "dataSidecars",
        blockRoot, slot = dataSidecar[0], kind = dataSidecarFork
      return Opt.none(T)
    return ok res

func putDataSidecar*[T: ForkyDataSidecar](
    db: QuarantineDB, dataSidecar: T, blockRoot = Opt.none(Eth2Digest)) =
  doAssert not db.backend.readOnly and
    distinctBase(db.dataSidecars.putStmt) != nil
  let
    slot = dataSidecar.signed_block_header.message.slot
    dataSidecarFork = dataSidecarForkAtConsensusFork(
      db.forkEpochs.consensusForkAtEpoch(slot.epoch))
  doAssert dataSidecarFork == T.kind, "Quarantine fork schedule misconfigured"
  let
    blockRoot = blockRoot.get(
      dataSidecar.signed_block_header.message.hash_tree_root())
    index = dataSidecar.index
    key = blockRoot.dataSidecarKey(index)
    res = db.dataSidecars.putStmt.exec(
      (key, slot.int64, encodeSZSSZ(dataSidecar)))
  res.expect("SQL query OK")

func delByBlockRoot*(
    db: QuarantineDB, blockRoot: Eth2Digest) =
  doAssert not db.backend.readOnly
  if distinctBase(db.dataSidecars.delStmt) != nil:
    let
      minKey = blockRoot.dataSidecarKey(uint64.low)
      maxKey = blockRoot.dataSidecarKey(uint64.high)
      res = db.dataSidecars.delStmt.exec((minKey, maxKey))
    res.expect("SQL query OK")

func keepEpochsFrom*(
    db: QuarantineDB, minEpoch: Epoch) =
  doAssert not db.backend.readOnly
  let minSlot = min(minEpoch.start_slot, int64.high.Slot)
  if distinctBase(db.dataSidecars.keepFromStmt) != nil:
    let res = db.dataSidecars.keepFromStmt.exec(minSlot.int64)
    res.expect("SQL query OK")

type QuarantineDBNames* = object
  dataSidecars*: string

proc initQuarantineDB*(
    backend: SqStoreRef,
    names: QuarantineDBNames,
    forkEpochs: ForkEpochs): KvResult[QuarantineDB] =
  let
    dataSidecars = ? backend.initDataSidecarStore(names.dataSidecars)

  ok QuarantineDB(
    forkEpochs: forkEpochs,
    backend: backend,
    dataSidecars: dataSidecars)

proc close*(db: QuarantineDB) =
  if db.backend != nil:
    db.dataSidecars.close()
    db[].reset()

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
  BlockStore = object
    getStmt: SqliteStmt[array[32, byte], seq[byte]]
    putStmt: SqliteStmt[(array[32, byte], int64, seq[byte]), void]
    delStmt: SqliteStmt[array[32, byte], void]
    keepFromStmt: SqliteStmt[int64, void]

  DataSidecarFork {.pure.} = enum
    None = 0,
    Deneb,
    Fulu

  ForkyDataSidecar* =
    deneb.BlobSidecar |
    fulu.DataColumnSidecar

  DataSidecarStore = object
    getStmt: SqliteStmt[array[40, byte], seq[byte]]
    putStmt: SqliteStmt[(array[40, byte], int64, seq[byte]), void]
    delStmt: SqliteStmt[(array[40, byte], array[40, byte]), void]
    keepFromStmt: SqliteStmt[int64, void]

  QuarantineDB* = ref object
    backend: SqStoreRef
      ## SQLite backend

    blocks: array[ConsensusFork, BlockStore]
      ## Eth2Digest -> (Slot, SignedBeaconBlock)
      ## Proposer signature verified blocks.

    dataSidecars: array[DataSidecarFork, DataSidecarStore]
      ## (Eth2Digest | index) -> (Slot, DataSidecar)
      ## Proposer signature verified data sidecars.

proc initBlockStore(
    backend: SqStoreRef,
    name, typeName: string): KvResult[BlockStore] =
  if name == "":
    return ok BlockStore()
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `block_root` BLOB PRIMARY KEY,  -- `Eth2Digest`
        `slot` INTEGER,                 -- `Slot`
        `signed_block` BLOB             -- `""" & typeName & """` (SZSSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok BlockStore()

  let
    getStmt = backend.prepareStmt("""
      SELECT `signed_block`
      FROM `""" & name & """`
      WHERE `block_root` = ?;
    """, array[32, byte], seq[byte], managed = false).expect("SQL query OK")
    putStmt = backend.prepareStmt("""
      REPLACE INTO `""" & name & """` (
        `block_root`, `slot`, `signed_block`
      ) VALUES (?, ?, ?);
    """, (array[32, byte], int64, seq[byte]),
      void, managed = false).expect("SQL query OK")
    delStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `block_root` = ?;
    """, array[32, byte], void, managed = false).expect("SQL query OK")
    keepFromStmt = backend.prepareStmt("""
      DELETE FROM `""" & name & """`
      WHERE `slot` < ?;
    """, int64, void, managed = false).expect("SQL query OK")

  ok BlockStore(
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    keepFromStmt: keepFromStmt)

func close(store: var BlockStore) =
  store.getStmt.disposeSafe()
  store.putStmt.disposeSafe()
  store.delStmt.disposeSafe()
  store.keepFromStmt.disposeSafe()

func getBlock*[T: ForkySignedBeaconBlock](
    db: QuarantineDB, blockRoot: Eth2Digest): Opt[T] =
  if distinctBase(db.blocks[T.kind].getStmt) == nil:
    return Opt.none(T)
  var blck: seq[byte]
  for res in db.blocks[T.kind].getStmt.exec(blockRoot.data, blck):
    res.expect("SQL query OK")
    var res: T
    if not decodeSZSSZ(blck, res):
      return Opt.none(T)
    return ok res

func putBlock*[T: ForkySignedBeaconBlock](
    db: QuarantineDB, blck: T) =
  doAssert not db.backend.readOnly and
    distinctBase(db.blocks[T.kind].putStmt) != nil
  let
    blockRoot = blck.root
    slot = blck.message.slot
    res = db.blocks[T.kind].putStmt.exec(
      (blockRoot.data, slot.int64, encodeSZSSZ(blck)))
  res.expect("SQL query OK")

proc initDataSidecarStore(
    backend: SqStoreRef,
    name, typeName: string): KvResult[DataSidecarStore] =
  if name == "":
    return ok DataSidecarStore()
  if not backend.readOnly:
    ? backend.exec("""
      CREATE TABLE IF NOT EXISTS `""" & name & """` (
        `block_root_index` BLOB PRIMARY KEY,  -- `Eth2Digest | uint64 (BE)`
        `slot` INTEGER,                       -- `Slot`
        `data_sidecar` BLOB                   -- `""" & typeName & """` (SZSSZ)
      );
    """)
  if not ? backend.hasTable(name):
    return ok DataSidecarStore()

  let
    getStmt = backend.prepareStmt("""
      SELECT `data_sidecar`
      FROM `""" & name & """`
      WHERE `block_root_index` = ?;
    """, array[40, byte], seq[byte], managed = false).expect("SQL query OK")
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

template kind(x: typedesc[deneb.BlobSidecar]): DataSidecarFork =
  DataSidecarFork.Deneb

template kind(x: typedesc[fulu.DataColumnSidecar]): DataSidecarFork =
  DataSidecarFork.Fulu

func dataSidecarKey(blockRoot: Eth2Digest, index: uint64): array[40, byte] =
  var res: array[40, byte]
  res[0 ..< 32] = blockRoot.data
  res[32 ..< 40] = toBytesBE(index)
  res

func getDataSidecar*[T: ForkyDataSidecar](
    db: QuarantineDB, blockRoot: Eth2Digest, index: uint64): Opt[T] =
  if distinctBase(db.dataSidecars[T.kind].getStmt) == nil:
    return Opt.none(T)
  var dataSidecar: seq[byte]
  let blockRootIndex = blockRoot.dataSidecarKey(index)
  for res in db.dataSidecars[T.kind].getStmt.exec(blockRootIndex, dataSidecar):
    res.expect("SQL query OK")
    var res: T
    if not decodeSZSSZ(dataSidecar, res):
      return Opt.none(T)
    return ok res

func putDataSidecar*[T: ForkyDataSidecar](
    db: QuarantineDB, dataSidecar: T, blockRoot = Opt.none(Eth2Digest)) =
  doAssert not db.backend.readOnly and
    distinctBase(db.dataSidecars[T.kind].putStmt) != nil
  let
    blockRoot = blockRoot.get(
      dataSidecar.signed_block_header.message.hash_tree_root())
    index = dataSidecar.index
    key = blockRoot.dataSidecarKey(index)
    slot = dataSidecar.signed_block_header.message.slot
    res = db.dataSidecars[T.kind].putStmt.exec(
      (key, slot.int64, encodeSZSSZ(dataSidecar)))
  res.expect("SQL query OK")

func delByBlockRoot*(
    db: QuarantineDB, blockRoot: Eth2Digest) =
  doAssert not db.backend.readOnly
  for dataSidecarFork, store in db.dataSidecars:
    if dataSidecarFork > DataSidecarFork.None and
        distinctBase(store.delStmt) != nil:
      let
        minKey = blockRoot.dataSidecarKey(uint64.low)
        maxKey = blockRoot.dataSidecarKey(uint64.high)
        res = store.delStmt.exec((minKey, maxKey))
      res.expect("SQL query OK")
  for consensusFork, store in db.blocks:
    if distinctBase(store.delStmt) != nil:
      let res = store.delStmt.exec(blockRoot.data)
      res.expect("SQL query OK")

func keepEpochsFrom*(
    db: QuarantineDB, minEpoch: Epoch) =
  doAssert not db.backend.readOnly
  let minSlot = min(minEpoch.start_slot, int64.high.Slot)
  for dataSidecarFork, store in db.dataSidecars:
    if dataSidecarFork > DataSidecarFork.None and
        distinctBase(store.keepFromStmt) != nil:
      let res = store.keepFromStmt.exec(minSlot.int64)
      res.expect("SQL query OK")
  for consensusFork, store in db.blocks:
    if distinctBase(store.keepFromStmt) != nil:
      let res = store.keepFromStmt.exec(minSlot.int64)
      res.expect("SQL query OK")

type QuarantineDBNames* = object
  phase0Blocks*: string
  altairBlocks*: string
  bellatrixBlocks*: string
  capellaBlocks*: string
  denebBlocks*: string
  electraBlocks*: string
  fuluBlocks*: string
  denebDataSidecars*: string
  fuluDataSidecars*: string

proc initQuarantineDB*(
    backend: SqStoreRef,
    names: QuarantineDBNames): KvResult[QuarantineDB] =
  static: doAssert ConsensusFork.high == ConsensusFork.Fulu
  let
    blocks = [
      # ConsensusFork.Phase0
      ? backend.initBlockStore(
        names.phase0Blocks, "phase0.SignedBeaconBlock"),
      # ConsensusFork.Altair
      ? backend.initBlockStore(
        names.altairBlocks, "altair.SignedBeaconBlock"),
      # ConsensusFork.Bellatrix
      ? backend.initBlockStore(
        names.bellatrixBlocks, "bellatrix.SignedBeaconBlock"),
      # ConsensusFork.Capella
      ? backend.initBlockStore(
        names.capellaBlocks, "capella.SignedBeaconBlock"),
      # ConsensusFork.Deneb
      ? backend.initBlockStore(
        names.denebBlocks, "deneb.SignedBeaconBlock"),
      # ConsensusFork.Electra
      ? backend.initBlockStore(
        names.electraBlocks, "electra.SignedBeaconBlock"),
      # ConsensusFork.Fulu
      ? backend.initBlockStore(
        names.fuluBlocks, "fulu.SignedBeaconBlock"),
    ]
    dataSidecars = [
      # DataSidecarFork.None
      DataSidecarStore(),
      # DataSidecarFork.Deneb
      ? backend.initDataSidecarStore(
        names.denebDataSidecars, "deneb.BlobSidecar"),
      # DataSidecarFork.Fulu
      ? backend.initDataSidecarStore(
        names.fuluDataSidecars, "fulu.DataColumnSidecar"),
    ]

  ok QuarantineDB(
    blocks: blocks,
    dataSidecars: dataSidecars)

proc close*(db: QuarantineDB) =
  if db.backend != nil:
    for consensusFork in ConsensusFork:
      db.blocks[consensusFork].close()
    for dataSidecarFork in DataSidecarFork:
      if dataSidecarFork > DataSidecarFork.None:
        db.dataSidecars[dataSidecarFork].close()
    db[].reset()

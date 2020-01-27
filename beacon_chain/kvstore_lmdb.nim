## Implementation of KVStore based on LMDB
## TODO: crashes on win32, investigate

import os

import ./kvstore

{.compile: "../vendor/lmdb/libraries/liblmdb/mdb.c".}
{.compile: "../vendor/lmdb/libraries/liblmdb/midl.c".}

const
  MDB_NOSUBDIR = 0x4000
  MDB_RDONLY   = 0x20000
  MDB_NOTFOUND = -30798

when defined(cpu64):
  const LMDB_MAP_SIZE = 1024'u * 1024'u * 1024'u * 10'u  # 10 GiB enough?
else:
  const LMDB_MAP_SIZE = 1024'u * 1024'u * 1024'u # 32bit limitation

type
  MDB_Env = distinct pointer
  MDB_Txn = distinct pointer
  MDB_Dbi = distinct cuint

  MDB_val = object
    mv_size: uint
    mv_data: pointer

  LmdbError* = object of CatchableError

# Used subset of the full LMDB API
proc mdb_env_create(env: var MDB_Env): cint {.importc, cdecl.}
proc mdb_env_open(env: MDB_Env, path: cstring, flags: cuint, mode: cint): cint {.importc, cdecl.}
proc mdb_txn_begin(env: MDB_Env, parent: MDB_Txn, flags: cuint, txn: var MDB_Txn): cint {.importc, cdecl.}
proc mdb_txn_commit(txn: MDB_Txn): cint {.importc, cdecl.}
proc mdb_txn_abort(txn: MDB_Txn) {.importc, cdecl.}
proc mdb_dbi_open(txn: MDB_Txn, name: cstring, flags: cuint, dbi: var MDB_Dbi): cint {.importc, cdecl.}
proc mdb_env_close(env: MDB_Env) {.importc, cdecl.}
proc mdb_strerror(err: cint): cstring {.importc, cdecl.}

proc mdb_get(txn: MDB_Txn, dbi: MDB_Dbi, key: var MDB_val, data: var MDB_val): cint {.importc, cdecl.}
proc mdb_del(txn: MDB_Txn, dbi: MDB_Dbi, key: var MDB_val, data: ptr MDB_val): cint {.importc, cdecl.}
proc mdb_put(txn: MDB_Txn, dbi: MDB_Dbi, key: var MDB_val, data: var MDB_val, flags: cuint): cint {.importc, cdecl.}

proc mdb_env_set_mapsize(env: MDB_Env, size: uint64): cint {.importc, cdecl.}

func raiseLmdbError(err: cint) {.noreturn.} =
  let tmp = mdb_strerror(err)
  raise (ref LmdbError)(msg: $tmp)

type
  LmdbStoreRef* = ref object of RootObj
    env: MDB_Env

template init(T: type MDB_Val, val: openArray[byte]): T =
  T(
    mv_size: val.len.uint,
    mv_data: unsafeAddr val[0]
  )

proc begin(db: LmdbStoreRef, flags: cuint): tuple[txn: MDB_Txn, dbi: MDB_Dbi] =
  var
    txn: MDB_Txn
    dbi: MDB_Dbi

  if (let x = mdb_txn_begin(db.env, nil, flags, txn); x != 0):
    raiseLmdbError(x)

  if (let x = mdb_dbi_open(txn, nil, 0, dbi); x != 0):
    mdb_txn_abort(txn)
    raiseLmdbError(x)

  (txn, dbi)

proc get*(db: LmdbStoreRef, key: openarray[byte], onData: DataProc): bool =
  if key.len == 0:
    return

  var
    (txn, dbi) = db.begin(MDB_RDONLY)
    dbKey = MDB_Val.init(key)
    dbVal: MDB_val

  # abort ok for read-only and easier for exception safety
  defer: mdb_txn_abort(txn)

  if (let x = mdb_get(txn, dbi, dbKey, dbVal); x != 0):
    if x == MDB_NOTFOUND:
      return false

    raiseLmdbError(x)

  if not onData.isNil:
    onData(toOpenArrayByte(cast[cstring](dbVal.mv_data), 0, dbVal.mv_size.int - 1))

  true

proc put*(db: LmdbStoreRef, key, value: openarray[byte]) =
  if key.len == 0: return

  var
    (txn, dbi) = db.begin(0)
    dbKey = MDB_Val.init(key)
    dbVal = MDB_Val.init(value)

  if (let x = mdb_put(txn, dbi, dbKey, dbVal, 0); x != 0):
    mdb_txn_abort(txn)
    raiseLmdbError(x)

  if (let x = mdb_txn_commit(txn); x != 0):
    raiseLmdbError(x)

proc contains*(db: LmdbStoreRef, key: openarray[byte]): bool =
  db.get(key, nil)

proc del*(db: LmdbStoreRef, key: openarray[byte]) =
  if key.len == 0: return

  var
    (txn, dbi) = db.begin(0)
    dbKey = MDB_Val.init(key)

  if (let x = mdb_del(txn, dbi, dbKey, nil); x != 0):
    mdb_txn_abort(txn)

    if x != MDB_NOTFOUND:
      raiseLmdbError(x)

    return

  if (let x = mdb_txn_commit(txn); x != 0):
    raiseLmdbError(x)

proc close*(db: LmdbStoreRef) =
  mdb_env_close(db.env)

proc init*(T: type LmdbStoreRef, basePath: string, readOnly = false): T =
  var
    env: MDB_Env

  if (let x = mdb_env_create(env); x != 0):
    raiseLmdbError(x)

  createDir(basePath)
  let dataDir = basePath / "nimbus.lmdb"

  if (let x = mdb_env_set_mapsize(env, LMDB_MAP_SIZE); x != 0):
    mdb_env_close(env)
    raiseLmdbError(x)

  var openFlags = MDB_NOSUBDIR
  if readOnly: openFlags = openFlags or MDB_RDONLY

  # file mode ignored on windows
  if (let x = mdb_env_open(env, dataDir, openFlags.cuint, 0o664.cint); x != 0):
    mdb_env_close(env)
    raiseLmdbError(x)

  T(env: env)

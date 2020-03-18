## Implementation of KVStore based on Sqlite3

import
  os,
  sqlite3_abi,
  ./kvstore

type
  SqliteStoreRef* = ref object of RootObj
    env: ptr sqlite3
    selectStmt, insertStmt, deleteStmt: ptr sqlite3_stmt

  SqliteError* = object of CatchableError

func raiseError(err: cint) {.noreturn.} =
  let tmp = sqlite3_errstr(err)
  raise (ref SqliteError)(msg: $tmp)

template checkErr(op, cleanup: untyped) =
  if (let v = (op); v != SQLITE_OK):
    cleanup
    raiseError(v)

template checkErr(op) =
  checkErr(op): discard

proc bindBlob(s: ptr sqlite3_stmt, n: int, blob: openarray[byte]): cint =
  sqlite3_bind_blob(s, n.cint, unsafeAddr blob[0], blob.len.cint, nil)

proc get*(db: SqliteStoreRef, key: openarray[byte], onData: DataProc): bool =
  checkErr sqlite3_reset(db.selectStmt)
  checkErr sqlite3_clear_bindings(db.selectStmt)
  checkErr bindBlob(db.selectStmt, 1, key)

  let v = sqlite3_step(db.selectStmt)
  case v
  of SQLITE_ROW:
    let
      p = cast[ptr UncheckedArray[byte]](sqlite3_column_blob(db.selectStmt, 0))
      l = sqlite3_column_bytes(db.selectStmt, 0)
    onData(toOpenArray(p, 0, l-1))
    true
  of SQLITE_DONE:
    false
  else:
    raiseError(v)

proc put*(db: SqliteStoreRef, key, value: openarray[byte]) =
  checkErr sqlite3_reset(db.insertStmt)
  checkErr sqlite3_clear_bindings(db.insertStmt)

  checkErr bindBlob(db.insertStmt, 1, key)
  checkErr bindBlob(db.insertStmt, 2, value)

  if (let v = sqlite3_step(db.insertStmt); v != SQLITE_DONE):
    raiseError(v)

proc contains*(db: SqliteStoreRef, key: openarray[byte]): bool =
  checkErr sqlite3_reset(db.selectStmt)
  checkErr sqlite3_clear_bindings(db.selectStmt)

  checkErr bindBlob(db.selectStmt, 1, key)

  let v = sqlite3_step(db.selectStmt)
  case v
  of SQLITE_ROW: result = true
  of SQLITE_DONE: result = false
  else: raiseError(v)

proc del*(db: SqliteStoreRef, key: openarray[byte]) =
  checkErr sqlite3_reset(db.deleteStmt)
  checkErr sqlite3_clear_bindings(db.deleteStmt)

  checkErr bindBlob(db.deleteStmt, 1, key)

  if (let v = sqlite3_step(db.deleteStmt); v != SQLITE_DONE):
    raiseError(v)

proc close*(db: SqliteStoreRef) =
  discard sqlite3_finalize(db.insertStmt)
  discard sqlite3_finalize(db.selectStmt)
  discard sqlite3_finalize(db.deleteStmt)
  discard sqlite3_close(db.env)

  db[] = SqliteStoreRef()[]

proc init*(
    T: type SqliteStoreRef,
    basePath: string,
    readOnly = false,
    inMemory = false): T =
  var
    env: ptr sqlite3

  let
    name =
      if inMemory: ":memory:"
      else: basepath / "nimbus.sqlite3"
    flags =
      if readOnly: SQLITE_OPEN_READONLY
      else: SQLITE_OPEN_READWRITE or SQLITE_OPEN_CREATE

  if not inMemory:
    createDir(basePath)

  checkErr sqlite3_open_v2(name, addr env, flags.cint, nil)

  template prepare(q: string, cleanup: untyped): ptr sqlite3_stmt =
    var s: ptr sqlite3_stmt
    checkErr sqlite3_prepare_v2(env, q, q.len.cint, addr s, nil):
      cleanup
      discard sqlite3_close(env)
    s

  template checkExec(q: string) =
    let s = prepare(q): discard

    if (let x = sqlite3_step(s); x != SQLITE_DONE):
      discard sqlite3_finalize(s)
      discard sqlite3_close(env)
      raiseError(x)

    if (let x = sqlite3_finalize(s); x != SQLITE_OK):
      discard sqlite3_close(env)
      raiseError(x)

  # TODO: check current version and implement schema versioning
  checkExec "PRAGMA user_version = 1;"

  checkExec """
    CREATE TABLE IF NOT EXISTS kvstore(
       key BLOB PRIMARY KEY,
       value BLOB
    ) WITHOUT ROWID;
  """

  let
    selectStmt = prepare "SELECT value FROM kvstore WHERE key = ?;":
      discard
    insertStmt = prepare "INSERT OR REPLACE INTO kvstore(key, value) VALUES (?, ?);":
      discard sqlite3_finalize(selectStmt)
    deleteStmt = prepare "DELETE FROM kvstore WHERE key = ?;":
      discard sqlite3_finalize(selectStmt)
      discard sqlite3_finalize(insertStmt)

  T(
    env: env,
    selectStmt: selectStmt,
    insertStmt: insertStmt,
    deleteStmt: deleteStmt
  )

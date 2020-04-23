## Implementation of KvStore based on sqlite3

{.push raises: [Defect].}

import
  os,
  sqlite3_abi,
  ./kvstore

export kvstore

type
  SqStoreRef* = ref object of RootObj
    env: ptr sqlite3
    selectStmt, insertStmt, deleteStmt: ptr sqlite3_stmt

template checkErr(op, cleanup: untyped) =
  if (let v = (op); v != SQLITE_OK):
    cleanup
    return err(sqlite3_errstr(v))

template checkErr(op) =
  checkErr(op): discard

proc bindBlob(s: ptr sqlite3_stmt, n: int, blob: openarray[byte]): cint =
  sqlite3_bind_blob(s, n.cint, unsafeAddr blob[0], blob.len.cint, nil)

proc get*(db: SqStoreRef, key: openarray[byte], onData: DataProc): KvResult[bool] =
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
    ok(true)
  of SQLITE_DONE:
    ok(false)
  else:
    err(sqlite3_errstr(v))

proc put*(db: SqStoreRef, key, value: openarray[byte]): KvResult[void] =
  checkErr sqlite3_reset(db.insertStmt)
  checkErr sqlite3_clear_bindings(db.insertStmt)

  checkErr bindBlob(db.insertStmt, 1, key)
  checkErr bindBlob(db.insertStmt, 2, value)

  if (let v = sqlite3_step(db.insertStmt); v != SQLITE_DONE):
    err(sqlite3_errstr(v))
  else:
    ok()

proc contains*(db: SqStoreRef, key: openarray[byte]): KvResult[bool] =
  checkErr sqlite3_reset(db.selectStmt)
  checkErr sqlite3_clear_bindings(db.selectStmt)

  checkErr bindBlob(db.selectStmt, 1, key)

  let v = sqlite3_step(db.selectStmt)
  case v
  of SQLITE_ROW: ok(true)
  of SQLITE_DONE: ok(false)
  else: err(sqlite3_errstr(v))

proc del*(db: SqStoreRef, key: openarray[byte]): KvResult[void] =
  checkErr sqlite3_reset(db.deleteStmt)
  checkErr sqlite3_clear_bindings(db.deleteStmt)

  checkErr bindBlob(db.deleteStmt, 1, key)

  if (let v = sqlite3_step(db.deleteStmt); v != SQLITE_DONE):
    err(sqlite3_errstr(v))
  else:
    ok()

proc close*(db: SqStoreRef) =
  discard sqlite3_finalize(db.insertStmt)
  discard sqlite3_finalize(db.selectStmt)
  discard sqlite3_finalize(db.deleteStmt)

  discard sqlite3_close(db.env)

  db[] = SqStoreRef()[]

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    readOnly = false,
    inMemory = false): KvResult[T] =
  var
    env: ptr sqlite3

  let
    name =
      if inMemory: ":memory:"
      else: basepath / name & ".sqlite3"
    flags =
      if readOnly: SQLITE_OPEN_READONLY
      else: SQLITE_OPEN_READWRITE or SQLITE_OPEN_CREATE

  if not inMemory:
    try:
      createDir(basePath)
    except OSError, IOError:
      return err("`sqlite: cannot create database directory")

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
      return err(sqlite3_errstr(x))

    if (let x = sqlite3_finalize(s); x != SQLITE_OK):
      discard sqlite3_close(env)
      return err(sqlite3_errstr(x))

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

  ok(SqStoreRef(
    env: env,
    selectStmt: selectStmt,
    insertStmt: insertStmt,
    deleteStmt: deleteStmt
  ))

# Simple Key-Value store database interface

import
  tables, hashes, sets

type
  MemoryStoreRef* = ref object of RootObj
    records: Table[seq[byte], seq[byte]]

  DataProc* = proc(val: openArray[byte])
  PutProc = proc (db: RootRef, key, val: openArray[byte]) {.gcsafe.}
  GetProc = proc (db: RootRef, key: openArray[byte], onData: DataProc): bool {.gcsafe.}
  DelProc = proc (db: RootRef, key: openArray[byte]) {.gcsafe.}
  ContainsProc = proc (db: RootRef, key: openArray[byte]): bool {.gcsafe.}

  KVStoreRef* = ref object
    ## Key-Value store virtual interface
    obj: RootRef
    putProc: PutProc
    getProc: GetProc
    delProc: DelProc
    containsProc: ContainsProc

template put*(db: KVStoreRef, key, val: openArray[byte]) =
  ## Store ``value`` at ``key`` - overwrites existing value if already present
  db.putProc(db.obj, key, val)

template get*(db: KVStoreRef, key: openArray[byte], onData: untyped): bool =
  ## Retrive value at ``key`` and call ``onData`` with the value. The data is
  ## valid for the duration of the callback.
  ## ``onData``: ``proc(data: openArray[byte])``
  ## returns true if found and false otherwise.
  db.getProc(db.obj, key, onData)

template del*(db: KVStoreRef, key: openArray[byte]) =
  ## Remove value at ``key`` from store - do nothing if the value is not present
  db.delProc(db.obj, key)

template contains*(db: KVStoreRef, key: openArray[byte]): bool =
  ## Return true iff ``key`` has a value in store
  db.containsProc(db.obj, key)

proc get*(db: MemoryStoreRef, key: openArray[byte], onData: DataProc): bool =
  let key = @key
  db.records.withValue(key, v):
    onData(v[])
    return true

proc del*(db: MemoryStoreRef, key: openArray[byte]) =
  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key
  db.records.del(key)

proc contains*(db: MemoryStoreRef, key: openArray[byte]): bool =
  db.records.contains(@key)

proc put*(db: MemoryStoreRef, key, val: openArray[byte]) =
  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key
  db.records[key] = @val

proc init*(T: type MemoryStoreRef): T =
  T(
    records: initTable[seq[byte], seq[byte]]()
  )

proc putImpl[T](db: RootRef, key, val: openArray[byte]) =
  mixin put
  put(T(db), key, val)

proc getImpl[T](db: RootRef, key: openArray[byte], onData: DataProc): bool =
  mixin get
  get(T(db), key, onData)

proc delImpl[T](db: RootRef, key: openArray[byte]) =
  mixin del
  del(T(db), key)

proc containsImpl[T](db: RootRef, key: openArray[byte]): bool =
  mixin contains
  contains(T(db), key)

func kvStore*[T: RootRef](x: T): KVStoreRef =
  mixin del, get, put, contains

  KVStoreRef(
    obj: x,
    putProc: putImpl[T],
    getProc: getImpl[T],
    delProc: delImpl[T],
    containsProc: containsImpl[T]
  )

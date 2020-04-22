# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Simple Key-Value store database interface that allows creating multiple
## tables within each store

{.push raises: [Defect].}

import
  stew/results,
  tables, hashes, sets

export results

type
  MemStoreRef* = ref object of RootObj
    records: Table[seq[byte], seq[byte]]

  KvResult*[T] = Result[T, cstring]

  DataProc* = proc(val: openArray[byte]) {.gcsafe, raises: [Defect].}

  PutProc = proc (db: RootRef, key, val: openArray[byte]): KvResult[void] {.nimcall, gcsafe, raises: [Defect].}
  GetProc = proc (db: RootRef, key: openArray[byte], onData: DataProc): KvResult[bool] {.nimcall, gcsafe, raises: [Defect].}
  DelProc = proc (db: RootRef, key: openArray[byte]): KvResult[void] {.nimcall, gcsafe, raises: [Defect].}
  ContainsProc = proc (db: RootRef, key: openArray[byte]): KvResult[bool] {.nimcall, gcsafe, raises: [Defect].}

  KvStoreRef* = ref object
    ## Key-Value store virtual interface
    obj: RootRef
    putProc: PutProc
    getProc: GetProc
    delProc: DelProc
    containsProc: ContainsProc

template put*(db: KvStoreRef, key, val: openArray[byte]): KvResult[void] =
  ## Store ``value`` at ``key`` - overwrites existing value if already present
  db.putProc(db.obj, key, val)

template get*(db: KvStoreRef, key: openArray[byte], onData: untyped): KvResult[bool] =
  ## Retrive value at ``key`` and call ``onData`` with the value. The data is
  ## valid for the duration of the callback.
  ## ``onData``: ``proc(data: openArray[byte])``
  ## returns true if found and false otherwise.
  db.getProc(db.obj, key, onData)

template del*(db: KvStoreRef, key: openArray[byte]): KvResult[void] =
  ## Remove value at ``key`` from store - do nothing if the value is not present
  db.delProc(db.obj, key)

template contains*(db: KvStoreRef, key: openArray[byte]): KvResult[bool] =
  ## Return true iff ``key`` has a value in store
  db.containsProc(db.obj, key)

proc putImpl[T](db: RootRef, key, val: openArray[byte]): KvResult[void] =
  mixin put
  put(T(db), key, val)

proc getImpl[T](db: RootRef, key: openArray[byte], onData: DataProc): KvResult[bool] =
  mixin get
  get(T(db), key, onData)

proc delImpl[T](db: RootRef, key: openArray[byte]): KvResult[void] =
  mixin del
  del(T(db), key)

proc containsImpl[T](db: RootRef, key: openArray[byte]): KvResult[bool] =
  mixin contains
  contains(T(db), key)

func kvStore*[T: RootRef](x: T): KvStoreRef =
  mixin del, get, put, contains

  KvStoreRef(
    obj: x,
    putProc: putImpl[T],
    getProc: getImpl[T],
    delProc: delImpl[T],
    containsProc: containsImpl[T]
  )

proc get*(db: MemStoreRef, key: openArray[byte], onData: DataProc): KvResult[bool] =
  let key = @key

  db.records.withValue(key, v):
    onData(v[])
    return ok(true)

  ok(false)

proc del*(db: MemStoreRef, key: openArray[byte]): KvResult[void] =
  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key
  db.records.del(key)
  ok()

proc contains*(db: MemStoreRef, key: openArray[byte]): KvResult[bool] =
  ok(db.records.contains(@key))

proc put*(db: MemStoreRef, key, val: openArray[byte]): KvResult[void] =
  # TODO: This is quite inefficient and it won't be necessary once
  # https://github.com/nim-lang/Nim/issues/7457 is developed.
  let key = @key
  db.records[key] = @val
  ok()

proc init*(T: type MemStoreRef): T =
  T(
    records: initTable[seq[byte], seq[byte]]()
  )

{.used.}

import
  unittest,
  ../beacon_chain/kvstore

const
  key = [0'u8, 1, 2, 3]
  value = [3'u8, 2, 1, 0]
  value2 = [5'u8, 2, 1, 0]

proc testKvStore*(db: KvStoreRef) =
  check:
    db != nil

    not db.get(key, proc(data: openArray[byte]) = discard)[]
    not db.contains(key)[]

  db.del(key)[] # does nothing

  db.put(key, value)[]

  var v: seq[byte]
  proc grab(data: openArray[byte]) =
    v = @data

  check:
    db.contains(key)[]
    db.get(key, grab)[]
    v == value

  db.put(key, value2)[] # overwrite old value
  check:
    db.contains(key)[]
    db.get(key, grab)[]
    v == value2

  db.del(key)[]
  check:
    not db.get(key, proc(data: openArray[byte]) = discard)[]
    not db.contains(key)[]

  db.del(key)[] # does nothing

suite "MemoryStoreRef":
  test "KvStore interface":
    testKvStore(kvStore MemStoreRef.init())

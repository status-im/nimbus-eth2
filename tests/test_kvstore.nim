{.used.}

import
  unittest,
  ../beacon_chain/kvstore

proc testKVStore*(db: KVStoreRef) =
  let
    key = [0'u8, 1, 2, 3]
    value = [3'u8, 2, 1, 0]
    value2 = [5'u8, 2, 1, 0]

  check:
    db != nil

    not db.get(key, proc(data: openArray[byte]) = discard)
    not db.contains(key)

  db.del(key) # does nothing

  db.put(key, value)

  check:
    db.contains(key)
    db.get(key, proc(data: openArray[byte]) =
      check data == value
    )

  db.put(key, value2) # overwrite old value
  check:
    db.contains(key)
    db.get(key, proc(data: openArray[byte]) =
      check data == value2
    )

  db.del(key)
  check:
    not db.get(key, proc(data: openArray[byte]) = discard)
    not db.contains(key)

  db.del(key) # does nothing

suite "MemoryStoreRef":
  test "KVStore interface":
    testKVStore(kvStore MemoryStoreRef.init())

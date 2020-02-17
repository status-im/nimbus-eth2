{.used.}

import
  os,
  unittest,
  ../beacon_chain/[kvstore, kvstore_sqlite3],
  ./test_kvstore

suite "Sqlite":
  test "KVStore interface":
    let db = SqliteStoreRef.init("", inMemory = true)
    defer: db.close()

    testKVStore(kvStore db)

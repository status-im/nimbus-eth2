{.used.}

import
  os,
  unittest,
  ../beacon_chain/[kvstore, kvstore_sqlite3],
  ./test_kvstore

suite "SqStoreRef":
  test "KvStore interface":
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()

    testKvStore(kvStore db)

{.used.}

import
  os,
  unittest,
  ../beacon_chain/[kvstore, kvstore_lmdb],
  ./test_kvstore

suite "LMDB":
  setup:
    let
      path = os.getTempDir() / "test_kvstore_lmdb"

    os.removeDir(path)
    os.createDir(path)

  teardown:
    os.removeDir(path)

  test "KVStore interface":
    let db = LmdbStoreRef.init(path)
    defer: db.close()

    testKVStore(kvStore db)

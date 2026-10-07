# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  eth/db/kvstore_sqlite3,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/spec/digest,
  ../beacon_chain/spec/presets,
  ../beacon_chain/validators/slashing_protection

from std/os import `/`, getTempDir, removeDir

template withTempDir(body: untyped): untyped =
  block:
    let dir {.inject.} = getTempDir() / "nimbus_test_db_locking"
    removeDir(dir)
    defer: removeDir(dir)
    body

suite "Exclusive database locking":
  test "a second beacon node cannot open the database":
    withTempDir:
      let db = BeaconChainDB.new(dir, defaultRuntimeConfig)
      defer: db.close()

      expect Defect:
        BeaconChainDB.new(dir, defaultRuntimeConfig).close()

  test "a second process cannot open the slashing protection database":
    withTempDir:
      let db = SlashingProtectionDB.init(
        ZERO_HASH, dir, "slashing_protection")
      defer: db.close()

      # `SlashingProtectionDB.init` quits the process when the open fails, so
      # the lock is observed through a plain second open of the same file
      check SqStoreRef.init(dir, "slashing_protection").isErr()

  test "the lock is released when the database is closed":
    withTempDir:
      BeaconChainDB.new(dir, defaultRuntimeConfig).close()
      let db = BeaconChainDB.new(dir, defaultRuntimeConfig)
      db.close()

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
  stew/bitops2,
  ../beacon_chain/spec/digest,
  ../beacon_chain/consensus_object_pools/quarantine_types

from sequtils import mapIt

suite "Missing Table":
  setup:
    let
      root1 = Eth2Digest.fromHex(
        "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0001")
      root2 = Eth2Digest.fromHex(
        "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0002")
      root3 = Eth2Digest.fromHex(
        "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0003")

  test "Add and delete missing":
    var mt = MissingTable.init(maxCapacity = 2)
    mt.add(root1)
    check:
      root1 in mt
      not mt.isFull()

    mt.add(root2)
    check:
      root2 in mt
      mt.isFull()

    mt.add(root3)
    check:
      root3 notin mt
      mt.isFull()

    mt.del(root1)
    check not mt.isFull()

  test "Check missing with exponential backoff":
    const maxRetries = 8
    var mt = MissingTable.init(maxCapacity = 3, maxRetries = maxRetries)

    # Simple retries
    mt.add(root1)
    mt.add(root2)
    var count = 0
    for i in 1'u64 ..< static(1'u64 shl maxRetries):
      if countOnes(i) == 1:
        check mt.checkMissing(32).mapIt(it.root) == @[root1, root2]
        inc count
      else:
        check mt.checkMissing(32).len() == 0
    check:
      mt.checkMissing(32).len() == 0
      count == maxRetries
      mt.len() == 0

    # Retries with root3 added in the middle
    var
      j = static(1'u64 shl (maxRetries - 3))
      count2 = 0
    reset(count)
    mt.add(root1)
    mt.add(root2)
    for i in 1'u64 ..< j:
      if countOnes(i) == 1:
        check mt.checkMissing(32).mapIt(it.root) == @[root1, root2]
        inc count
      else:
        check mt.checkMissing(32).len() == 0
    check count == maxRetries - 3

    mt.add(root3)
    for i in 1'u64 ..< static(1'u64 shl maxRetries):
      let
        jc = j < static(1'u64 shl maxRetries) and countOnes(j) == 1
        ic = countOnes(i) == 1

      if jc and ic:
        check mt.checkMissing(32).mapIt(it.root) == @[root1, root2, root3]
        inc count
        inc count2
      elif ic:
        check mt.checkMissing(32).mapIt(it.root) == @[root3]
        inc count2
      elif jc:
        check mt.checkMissing(32).mapIt(it.root) == @[root1, root2]
        inc count
      else:
        check mt.checkMissing(32).len() == 0
      inc j
    check:
      mt.checkMissing(32).len() == 0
      count == maxRetries
      count2 == maxRetries
      mt.len() == 0

# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  unittest,
  ../beacon_chain/[datatypes, hash_ssz]

suite "Tree hashing":
  # XXX Nothing but smoke tests for now..

  test "Hash ValidatorRecord":
    let vr = ValidatorRecord()
    check: hashSSZ(vr).len > 0

  test "Hash ShardAndCommittee":
    let sc = ShardAndCommittee()
    check: hashSSZ(sc).len > 0

  test "Hash integer":
    check: hashSSZ(0x01'u32) == [0'u8, 0, 0, 1] # big endian!

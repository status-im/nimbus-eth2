# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/datatypes/[phase0, altair],
  ../beacon_chain/spec/eth2_ssz_serialization

static:
  doAssert isFixedSize(Slot) == true

type
  Specific = object
    f1: Slot
    f2: Epoch

  Primitive = object # Same as above, but using primitive fields
    f1: uint64
    f2: uint64

suite "Specific field types":
  test "roundtrip":
    let encoded = SSZ.encode(Specific(f1: Slot(1), f2: Epoch(2)))
    check SSZ.decode(encoded, Primitive) == Primitive(f1: 1, f2: 2)

  test "root update":
    template testit(T: type) =
      var t: T
      t.root = hash_tree_root(t.message)
      let encoded = SSZ.encode(t)
      let decoded = SSZ.decode(encoded, T)
      check:
        t.message == decoded.message
        t.root == decoded.root

      t = default(type t)
      readSszBytes(encoded, t, false)
      check:
        t.root.isZero

    testit(phase0.SignedBeaconBlock)
    testit(phase0.TrustedSignedBeaconBlock)
    testit(altair.SignedBeaconBlock)
    testit(altair.TrustedSignedBeaconBlock)

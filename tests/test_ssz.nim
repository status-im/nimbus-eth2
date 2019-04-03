# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  unittest, sequtils, options,
  nimcrypto, eth/common, blscurve, serialization/testing/generic_suite,
  ../beacon_chain/ssz, ../beacon_chain/spec/[datatypes, digest]

func filled[N: static[int], T](typ: type array[N, T], value: T): array[N, T] =
  for val in result.mitems:
    val = value

func filled(T: type MDigest, value: byte): T =
  for val in result.data.mitems:
    val = value

suite "Simple serialization":
  # pending spec updates in
  #   - https://github.com/ethereum/eth2.0-specs
  type
    Foo = object
      f0: uint8
      f1: uint32
      f2: EthAddress
      f3: MDigest[256]
      f4: seq[byte]
      f5: ValidatorIndex

  let expected_deser = Foo(
      f0: 5,
      f1: 0'u32 - 3,
      f2: EthAddress.filled(byte 35),
      f3: MDigest[256].filled(byte 35),
      f4: @[byte 'c'.ord, 'o'.ord, 'w'.ord],
      f5: ValidatorIndex(79))

  var expected_ser = @[
      byte 67, 0, 0, 0, # length
      5,
      0xFD, 0xFF, 0xFF, 0xFF,
    ]
  expected_ser &= EthAddress.filled(byte 35)
  expected_ser &= MDigest[256].filled(byte 35).data
  expected_ser &= [byte 3, 0, 0, 0, 'c'.ord, 'o'.ord, 'w'.ord]
  expected_ser &= [byte 79, 0, 0]

  test "Object deserialization":
    let deser = SSZ.decode(expected_ser, Foo)
    check: expected_deser == deser

  test "Object serialization":
    let ser = SSZ.encode(expected_deser)
    check: expected_ser == ser

  test "Not enough data":
    expect SerializationError:
      let x = SSZ.decode(expected_ser[0..^2], Foo)

    expect SerializationError:
      let x = SSZ.decode(expected_ser[1..^1], Foo)

  test "ValidatorIndex roundtrip":
    # https://github.com/nim-lang/Nim/issues/10027
    let v = 79.ValidatorIndex
    let ser = SSZ.encode(v)
    check:
      ser.len() == 3
      SSZ.decode(ser, v.type) == v

  SSZ.roundripTest [1, 2, 3]
  SSZ.roundripTest @[1, 2, 3]
  SSZ.roundripTest SigKey.random().getKey()
  SSZ.roundripTest BeaconBlock(
    slot: 42.Slot, signature: sign(SigKey.random(), 0'u64, ""))
  SSZ.roundripTest BeaconState(slot: 42.Slot)

suite "Tree hashing":
  # TODO The test values are taken from an earlier version of SSZ and have
  #      nothing to do with upstream - needs verification and proper test suite

  test "Hash BeaconBlock":
    let vr = BeaconBlock()
    check:
      $hash_tree_root(vr) ==
        "1BD5D8577A7806CC524C367808C53AE2480F35A3C4BB11A90D6E1AC304E27201"

  test "Hash BeaconState":
    let vr = BeaconState()
    check:
      $hash_tree_root(vr) ==
        "DC751EF09987283D52483C75690234DDD75FFDAF1A844CD56FE1173465B5597A"

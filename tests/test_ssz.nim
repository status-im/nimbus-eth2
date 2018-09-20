# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  unittest, nimcrypto, eth_common, sequtils,
  ../beacon_chain/ssz

func filled[N: static[int], T](typ: type array[N, T], value: T): array[N, T] =
  for val in result.mitems:
    val = value

func filled(T: type MDigest, value: byte): T =
  for val in result.data.mitems:
    val = value

suite "Simple serialization":
  # pending spec updates in
  #   - https://github.com/ethereum/eth2.0-specs
  #   - https://github.com/ethereum/beacon_chain/blob/master/tests/ssz/test_deserialize.py
  #   - https://github.com/ethereum/beacon_chain/tree/master/ssz
  type
    Foo = object
      f0: uint8
      f1: uint32
      f2: EthAddress
      f3: MDigest[256]
      f4: seq[byte]

  let expected_deser = Foo(
      f0: 5,
      f1: 0'u32 - 3,
      f2: EthAddress.filled(byte 35),
      f3: MDigest[256].filled(byte 35),
      f4: @[byte 'c'.ord, 'o'.ord, 'w'.ord]
    )

  var expected_ser = @[
      byte 5,
      '\xFF'.ord, '\xFF'.ord, '\xFF'.ord, '\xFD'.ord,
    ]
  expected_ser &= EthAddress.filled(byte 35)
  expected_ser &= MDigest[256].filled(byte 35).data
  expected_ser &= [byte 0, 0, 0, 3, 'c'.ord, 'o'.ord, 'w'.ord]

  test "Deserialization":
    let deser = expected_ser.deserialize(Foo)
    check: expected_deser == deser

  test "Serialization":
    let ser = expected_deser.serialize()
    check: expected_ser == ser

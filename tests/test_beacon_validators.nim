# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import unittest2, results, chronos, stint
import ../beacon_chain/validators/beacon_validators,
       ../beacon_chain/spec/datatypes/base,
       ../beacon_chain/spec/eth2_apis/eth2_rest_serialization

suite "Beacon validators test suite":
  test "builderBetterBid(builderBoostFactor) test":
    const TestVectors =
      [
        (
          # zero comparison
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          0'u64,
          false
        ),
        (
          # less or equal
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          100'u64,
          true
        ),
        (
          # overflow #1
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          101'u64,
          true
        ),
        (
          # overflow #2
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          0xffffffffffffffff'u64,
          true
        ),
        (
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          0'u64,
          false
        ),
        (
          # less
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          100'u64,
          false
        ),
        (
          # overflow #1
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          101'u64,
          true
        ),
        (
          # overflow #2
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          0xffffffffffffffff'u64,
          true
        ),
        (
          # zeros
          "0",
          "0",
          0'u64,
          false
        ),
        (
          # 10 * (50 div 100) < 6
          "a",
          "6",
          50'u64,
          false
        ),
        (
          # 10 * (50 div 100) >= 5
          "a",
          "5",
          50'u64,
          true
        ),
        (
          # 5 * (150 div 100) < 8
          "5",
          "8",
          150'u64,
          false
        ),
        (
          # 5 * (150 div 100) >= 7
          "5",
          "7",
          150'u64,
          true
        ),
      ]

    for index, vector in TestVectors.pairs():
      let
        builderValue = strictParse(vector[0], UInt256, 16).get()
        engineValue = Wei(strictParse(vector[1], UInt256, 16).get())
      check builderBetterBid(vector[2], builderValue, engineValue) == vector[3]

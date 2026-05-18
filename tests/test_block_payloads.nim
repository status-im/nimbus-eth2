# beacon_chain
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
  ../beacon_chain/validators/block_payloads

from ../beacon_chain/spec/helpers import GWEI_TO_WEI

func gweiToWei(gwei: uint64): UInt256 =
  gwei.u256 * GWEI_TO_WEI.u256

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

  test "builderBetterBid(localBlockValueBoost) with Gwei-to-Wei conversion":
    # Simulates P2P bid selection: bid value is in Gwei, engine value in Wei
    # builder bid of 1 Gwei vs engine value of 0 Wei, bid wins (default 10% boost)
    check builderBetterBid(
      10'u8, gweiToWei(1), Wei(0.u256)) == true

    # builder bid of 100 Gwei vs engine value of 100 Gwei in Wei, bid loses (110 > 100)
    check builderBetterBid(
      10'u8, gweiToWei(100), gweiToWei(100)) == false

    # builder bid of 111 Gwei vs engine value of 100 Gwei, bid wins (111 > 110)
    check builderBetterBid(
      10'u8, gweiToWei(111), gweiToWei(100)) == true

    # builder bid of 109 Gwei vs engine value of 100 Gwei, bid loses (109 < 110)
    check builderBetterBid(
      10'u8, gweiToWei(109), gweiToWei(100)) == false

    # Zero boost, bid should exceed engine value
    check builderBetterBid(
      0'u8, gweiToWei(100), gweiToWei(100)) == false
    check builderBetterBid(
      0'u8, gweiToWei(101), gweiToWei(100)) == true

    # Max boost (255%), bid needs to be very high
    check builderBetterBid(
      255'u8, gweiToWei(100), gweiToWei(100)) == false
    check builderBetterBid(
      255'u8, gweiToWei(356), gweiToWei(100)) == true

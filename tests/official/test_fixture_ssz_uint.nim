# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  ospaths, strutils, unittest, sequtils,
  # Third parties
  stint, serialization,
  # Beacon chain internals
  ../../beacon_chain/ssz,
  ../../beacon_chain/spec/[datatypes, validator],
  # Test utilities
  ../testutil,
  ./fixtures_utils

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "fixtures" / "json_tests" / "ssz_generic" / "uint"

suite "Official - SSZ unsigned integer tests" & preset():
  test "Unsigned integer bounds" & preset():
    let uintBounds = parseTests(TestFolder / TestsPath / "uint_bounds.json", SSZUint)

    # We use Stint string -> uint parser + casting
    # as it's generic over all unsigned integer size
    # and not just BiggestUint
    for test in uintBounds.test_cases:
      if test.`type` == "uint8":
        if test.valid:
          let value: uint8 = test.value.parse(StUint[8]).data
          let serialized = SSZ.encode(value)
          check(serialized == test.ssz)
        else:
          if test.tags.anyIt(it == "uint_underflow"):
            # TODO: Stint throws RangeError for negative number parsing
            #       https://github.com/status-im/nim-stint/blob/ccf87daac1eef15238ff3d6d2edb138e22180d19/stint/io.nim#L130-L132
            expect RangeError, OverflowError:
              let value: uint8 = test.value.parse(StUint[8]).data

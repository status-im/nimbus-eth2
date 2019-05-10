# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard libs
  ospaths, strutils, json, unittest,
  # Third parties

  # Beacon chain internals
  ../../beacon_chain/spec/validator,
  # Test utilities
  ./fixtures_utils

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "fixtures" / "json_tests" / "shuffling" / "core" / "shuffling_full.json"

var shufflingTests: ShufflingTests

suite "Official - Shuffling tests":
  test "Parsing the official shuffling tests":
    shufflingTests = parseTests(TestFolder / TestsPath)

  test "Shuffling a sequence of N validators":
    for t in shufflingTests.test_cases:
      let implResult = get_shuffled_seq(t.seed, t.count)
      check: implResult == t.shuffled
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
  ../../beacon_chain/spec/crypto,
  # Test utilities
  ./fixtures_utils

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "fixtures" / "json_tests" / "bls" / "priv_to_pub" / "priv_to_pub.json"

var blsPrivToPubTests: Tests[BLSPrivToPub]

suite "Official - BLS tests":
  test "Parsing the official BLS priv_to_pub tests":
    blsPrivToPubTests = parseTestsBLSPrivToPub(TestFolder / TestsPath)

  test "Private to public key conversion":
    for t in blsPrivToPubTests.test_cases:
      let implResult = t.input.pubkey()
      check: implResult == t.output
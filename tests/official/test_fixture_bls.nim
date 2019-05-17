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
const TestsPath = "fixtures" / "json_tests" / "bls"
var
  blsPrivToPubTests: Tests[BLSPrivToPub]
  blsSignMsgTests: Tests[BLSSignMsg]

suite "Official - BLS tests":
  test "Parsing the official BLS tests":
    blsPrivToPubTests = parseTestsBLSPrivToPub(TestFolder / TestsPath / "priv_to_pub" / "priv_to_pub.json")
    blsSignMsgTests = parseTestsBLSSignMsg(TestFolder / TestsPath / "sign_msg" / "sign_msg.json")

  test "Private to public key conversion":
    for t in blsPrivToPubTests.test_cases:
      let implResult = t.input.pubkey()
      check: implResult == t.output

  test "Message signing":
    for t in blsSignMsgTests.test_cases:
      let implResult = t.input.privkey.bls_sign(
        t.input.message,
        uint64(t.input.domain)
        )
      check: implResult == t.output
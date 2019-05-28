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
  blsAggSigTests: Tests[BLSAggSig]
  blsAggPubKeyTests: Tests[BLSAggPubKey]

suite "Official - BLS tests":
  test "Parsing the official BLS tests":
    blsPrivToPubTests = parseTests(TestFolder / TestsPath / "priv_to_pub" / "priv_to_pub.json", BLSPrivToPub)
    blsSignMsgTests = parseTests(TestFolder / TestsPath / "sign_msg" / "sign_msg.json", BLSSignMsg)
    blsAggSigTests = parseTests(TestFolder / TestsPath / "aggregate_sigs" / "aggregate_sigs.json", BLSAggSig)
    blsAggPubKeyTests = parseTests(TestFolder / TestsPath / "aggregate_pubkeys" / "aggregate_pubkeys.json", BLSAggPubKey)

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

  test "Aggregating signatures":
    for t in blsAggSigTests.test_cases:
      let implResult = t.input.combine()
      check: implResult == t.output

  test "Aggregating public keys":
    for t in blsAggPubKeyTests.test_cases:
      let implResult = t.input.combine()
      check: implResult == t.output

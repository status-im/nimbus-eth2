# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard libs
  ospaths, strutils, unittest, endians,
  # Status libs
  blscurve, stew/byteutils,
  # Beacon chain internals
  ../../beacon_chain/spec/crypto,
  # Test utilities
  ./fixtures_utils

type
  # # TODO - but already tested in nim-blscurve
  # BLSUncompressedG2 = object
  #   input*: tuple[
  #     message: seq[byte],
  #     domain: array[1, byte]
  #     ]
  #   output*: ECP2_BLS381

  # # TODO - but already tested in nim-blscurve
  # BLSCompressedG2 = object
  #   input*: tuple[
  #     message: seq[byte],
  #     domain: array[1, byte]
  #     ]
  #   output*: ECP2_BLS381

  Domain = distinct uint64
    ## Domains have custom hex serialization

  BLSPrivToPub* = object
    input*: ValidatorPrivKey
    output*: ValidatorPubKey

  BLSSignMsgInput = object
    privkey*: ValidatorPrivKey
    message*: seq[byte]
    domain*: Domain

  BLSSignMsg* = object
    input*: BLSSignMsgInput
    output*: Signature

  BLSAggSig* = object
    input*: seq[Signature]
    output*: Signature

  BLSAggPubKey* = object
    input*: seq[ValidatorPubKey]
    output*: ValidatorPubKey

proc readValue*(r: var JsonReader, a: var Domain) {.inline.} =
  ## Custom deserializer for Domain
  ## They are uint64 stored in hex values
  # Furthermore Nim parseHex doesn't support uint
  # until https://github.com/nim-lang/Nim/pull/11067
  # (0.20)
  let be_uint = hexToPaddedByteArray[8](r.readValue(string))
  bigEndian64(a.addr, be_uint.unsafeAddr)

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

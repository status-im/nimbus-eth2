# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard libs
  os,
  # Status libs
  unittest2,
  blscurve, stew/byteutils,
  # Beacon chain internals
  ../../beacon_chain/spec/crypto,
  # Test utilities
  ./fixtures_utils

type
  BLSPrivToPub = object
    input: ValidatorPrivKey
    output: ValidatorPubKey

  BLSSignMsgInput = object
    privkey: ValidatorPrivKey
    message: seq[byte]
    domain: Eth2Domain

  BLSSignMsg = object
    input: BLSSignMsgInput
    output: Signature

  BLSAggSig = object
    input: seq[Signature]
    output: Signature

  BLSAggPubKey = object
    input: seq[ValidatorPubKey]
    output: ValidatorPubKey

func readValue(r: var JsonReader, a: var Eth2Domain) =
  ## Custom deserializer for Eth2Domain
  # Furthermore Nim parseHex doesn't support uint
  # until https://github.com/nim-lang/Nim/pull/11067
  # (0.20)
  a = hexToPaddedByteArray[8](r.readValue(string))

# TODO: json tests were removed
const BLSDir = JsonTestsDir/"general"/"phase0"/"bls"

suite "Official - BLS tests":
  test "Private to public key conversion":
    for file in walkDirRec(BLSDir/"priv_to_pub", checkDir = true):
      let t = parseTest(file, Json, BLSPrivToPub)
      let implResult = t.input.pubkey()
      check: implResult == t.output

  test "Message signing":
    for file in walkDirRec(BLSDir/"sign_msg", checkDir = true):
      let t = parseTest(file, Json, BLSSignMsg)
      let implResult = t.input.privkey.bls_sign(
        t.input.message,
        t.input.domain
      )
      check: implResult == t.output

  test "Aggregating signatures":
    for file in walkDirRec(BLSDir/"aggregate_sigs", checkDir = true):
      let t = parseTest(file, Json, BLSAggSig)
      let implResult = t.input.combine()
      check: implResult == t.output

  test "Aggregating public keys":
    for file in walkDirRec(BLSDir/"aggregate_pubkeys", checkDir = true):
      let t = parseTest(file, Json, BLSAggPubKey)
      let implResult = t.input.combine()
      check: implResult == t.output

  # TODO: msg_hash_compressed and uncompressed

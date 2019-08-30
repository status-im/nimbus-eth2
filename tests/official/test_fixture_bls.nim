# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard libs
  os, unittest, endians,
  # Status libs
  blscurve, stew/byteutils,
  # Beacon chain internals
  ../../beacon_chain/spec/crypto,
  # Test utilities
  ./fixtures_utils

type
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

const BLSDir = JsonTestsDir/"general"/"phase0"/"bls"

suite "Official - BLS tests":
  test "Private to public key conversion":
    for file in walkDirRec(BLSDir/"priv_to_pub"):
      let t = parseTest(file, Json, BLSPrivToPub)
      let implResult = t.input.pubkey()
      check: implResult == t.output

  test "Message signing":
    for file in walkDirRec(BLSDir/"sign_msg"):
      let t = parseTest(file, Json, BLSSignMsg)
      let implResult = t.input.privkey.bls_sign(
        t.input.message,
        uint64(t.input.domain)
      )
      check: implResult == t.output

  test "Aggregating signatures":
    for file in walkDirRec(BLSDir/"aggregate_sigs"):
      let t = parseTest(file, Json, BLSAggSig)
      let implResult = t.input.combine()
      check: implResult == t.output

  test "Aggregating public keys":
    for file in walkDirRec(BLSDir/"aggregate_pubkeys"):
      let t = parseTest(file, Json, BLSAggPubKey)
      let implResult = t.input.combine()
      check: implResult == t.output

  # TODO: msg_hash_compressed and uncompressed

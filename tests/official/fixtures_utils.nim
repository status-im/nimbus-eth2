# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard lib
  json, streams, strutils,
  # Dependencies
  yaml.tojson,
  blscurve, nimcrypto,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, crypto, digest]

export nimcrypto.toHex

proc yamlToJson*(file: string): seq[JsonNode] =
  try:
    let fs = openFileStream(file)
    defer: fs.close()
    result = fs.loadToJson()
  except IOError:
    echo "Exception when reading file: " & file
    raise

proc default*(T: typedesc): T = discard

# TODO: use nim-serialization

proc toPubkey*(node: JsonNode): ValidatorPubKey =
  let rawStr = node.getStr
  doAssert rawStr[0..<2] == "0x", "Hexadecimal input is expected to be prefixed with 0x"
  let ok = result.init(rawStr[2 .. rawStr.high])
  doAssert ok, "Validator public key parsing failure"

proc toDigest*(node: JsonNode): Eth2Digest =
  let rawStr = node.getStr
  doAssert rawStr[0..<2] == "0x", "Hexadecimal input is expected to be prefixed with 0x"
  rawStr[2 .. rawStr.high].hexToBytes(result.data)

proc toUint64*(node: JsonNode): uint64 =
  case node.kind:
  of JInt:
    result = node.num.uint64
  of JString:
    result = node.str.parseBiggestUInt
  else:
    raise newException(ValueError, "This JSON node cannot hold a uint64")
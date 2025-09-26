# beacon_chain
# Copyright (c) 2021-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/strutils,
  unittest2,
  stew/byteutils,
  json_serialization/std/tables,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]

const denebSignedContents = staticRead(sourceDir & "/test_files/denebSignedContents.json")

# Examples from:
# https://github.com/ethereum/remote-signing-api/blob/87a392deb4e43209ca896dde6b4ec40bef7ee02c/signing/paths/sign.yaml
# via https://jsonformatter.org/yaml-to-json with pre-bellatrix removed
const Web3SignerExamples = staticRead(sourceDir & "/test_files/web3signer.examples.json")

# Can't be in same namespace as some other KZG-related fromHex overloads due to
# https://github.com/nim-lang/Nim/issues/22861
func fromHex(T: typedesc[KzgCommitment], s: string): T {.
     raises: [ValueError].} =
  var res: T
  hexToByteArray(s, res.bytes)
  res

suite "REST encoding and decoding":
  test "DenebSignedBlockContents decoding":
    let blck = RestJson.decode(denebSignedContents, DenebSignedBlockContents)
    check:
      hash_tree_root(blck.signed_block.message) == Eth2Digest.fromHex(
        "0xc67166e600d76d9d129244d10e4f35279d75d800fb39a5ce35e98328d53939da")
      blck.signed_block.root == Eth2Digest.fromHex(
        "0xc67166e600d76d9d129244d10e4f35279d75d800fb39a5ce35e98328d53939da")
      blck.signed_block.signature == ValidatorSig.fromHex(
        "0x8e2cd6cf4457825818eb380f1ea74f2fc99665041194ab5bcbdbf96f2e22bad4376d2a94f69d762c999ffd500e2525ab0561b01a79158456c83cf5bf0f2104e26f7b0d22f41dcc8f49a0e1cc29bb09aee1c548903fa04bdfcd20603c400d948d")[]
      blck.kzg_proofs.len == 0
      blck.blobs.len == 0
      blck == RestJson.decode(RestJson.encode(blck), DenebSignedBlockContents)
      # SSZ encoding is also used in rest!
      blck == SSZ.decode(SSZ.encode(blck), DenebSignedBlockContents)

  test "KzgCommitment":
    let
      zeroString =
        "\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""
      randString =
        "\"0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb\""
      zeroKzgCommitment = KzgCommitment.fromHex(
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
      randKzgCommitment = KzgCommitment.fromHex(
        "0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb")

    check:
      RestJson.decode(zeroString, KzgCommitment) == zeroKzgCommitment
      RestJson.decode(zeroString, KzgCommitment) != randKzgCommitment
      RestJson.decode(randString, KzgCommitment) != zeroKzgCommitment
      RestJson.decode(randString, KzgCommitment) == randKzgCommitment

      RestJson.encode(zeroKzgCommitment) == zeroString
      RestJson.encode(zeroKzgCommitment) != randString
      RestJson.encode(randKzgCommitment) != zeroString
      RestJson.encode(randKzgCommitment) == randString

  test "KzgProof":
    let
      zeroString =
        "\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""
      randString =
        "\"0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb\""
      zeroKzgProof = KzgProof.fromHex(
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
      randKzgProof = KzgProof.fromHex(
        "0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb")

    check:
      RestJson.decode(zeroString, KzgProof) == zeroKzgProof
      RestJson.decode(zeroString, KzgProof) != randKzgProof
      RestJson.decode(randString, KzgProof) != zeroKzgProof
      RestJson.decode(randString, KzgProof) == randKzgProof

      RestJson.encode(zeroKzgProof) == zeroString
      RestJson.encode(zeroKzgProof) != randString
      RestJson.encode(randKzgProof) != zeroString
      RestJson.encode(randKzgProof) == randString

  test "Blob":
    let
      zeroBlob = new Blob
      nonzeroBlob = new Blob
      blobLen = distinctBase(nonzeroBlob[]).lenu64

    for i in 0 ..< blobLen:
      nonzeroBlob[i] = 17.byte

    let
      zeroString = newClone(RestJson.encode(zeroBlob[]))
      nonzeroString = newClone(RestJson.encode(nonzeroBlob[]))

    let
      zeroBlobRoundTrip =
        newClone(RestJson.decode(zeroString[], Blob))
      nonzeroBlobRoundTrip =
        newClone(RestJson.decode(nonzeroString[], Blob))

    check:
      zeroString[].startsWith "\"0x0000000000000000000000000000000000000000000000000"
      nonzeroString[].startsWith "\"0x111111111111111111111111111111111111111111111111"
      zeroString[].endsWith "0000000000000000000000000000000000000000000000\""
      nonzeroString[].endsWith "1111111111111111111111111111111111111111111111\""
      zeroString[].lenu64 == 2*blobLen + 4   # quotation marks and 0x prefix
      nonzeroString[].lenu64 == 2*blobLen + 4   # quotation marks and 0x prefix
      zeroBlob[] == zeroBlobRoundTrip[]
      nonzeroBlob[] == nonzeroBlobRoundTrip[]
      zeroBlob[] != nonzeroBlob[]

  test "Validator pubkey hack":

    let
      encoded = """
      {
        "pubkey": "0x933ad9491b62059dd065b560d256d8957a8c402cc6e8d8ee7290ae11e8f7329267a8811c397529dac52ae1342ba58c95",
        "withdrawal_credentials": "0x00f50428677c60f997aadeab24aabf7fceaef491c96a52b463ae91f95611cf71",
        "effective_balance": "32000000000",
        "slashed": false,
        "activation_eligibility_epoch": "0",
        "activation_epoch": "0",
        "exit_epoch": "18446744073709551615",
        "withdrawable_epoch": "18446744073709551615"
      }"""

    let validator = RestJson.decode(encoded, Validator)
    check:
      validator.pubkey == ValidatorPubKey.fromHex(
        "0x933ad9491b62059dd065b560d256d8957a8c402cc6e8d8ee7290ae11e8f7329267a8811c397529dac52ae1342ba58c95")[]
      validator.exit_epoch == FAR_FUTURE_EPOCH

  test "RestErrorMessage parser tests":
    const GoodTestVectors = [
      (
        """{"code": 500, "message": "block not found"}""",
        RestErrorMessage.init(500, "block not found")
      ),
      (
        """{"code": "600", "message": "block not found"}""",
        RestErrorMessage.init(600, "block not found")
      ),
      (
        """{"code": "700", "message": "block not found",
            "data": "data", "custom": "field"}""",
        RestErrorMessage.init(700, "block not found")
      ),
      (
        """{"code":"701", "message": "block not found",
            "data": "data", "custom": 300}""",
        RestErrorMessage.init(701, "block not found")
      ),
      (
        """{"code": "702", "message": "block not found",
            "data": "data", "custom": {"field1": "value1"}}""",
        RestErrorMessage.init(702, "block not found")
      ),
      (
        """{"code": 800, "message": "block not found",
            "custom": "data", "stacktraces": []}""",
        RestErrorMessage.init(800, "block not found", [])
      ),
      (
        """{"code": 801, "message": "block not found",
            "custom": 100, "stacktraces": []}""",
        RestErrorMessage.init(801, "block not found", [])
      ),
      (
        """{"code": 802, "message": "block not found",
            "custom": {"field1": "value1"}, "stacktraces": []}""",
        RestErrorMessage.init(802, "block not found", [])
      ),
      (
        """{"code": "900", "message": "block not found",
            "stacktraces": ["line1", "line2", "line3"], "custom": "data"}""",
        RestErrorMessage.init(900, "block not found",
                              ["line1", "line2", "line3"])
      ),
      (
        """{"code": "901", "message": "block not found",
            "stacktraces": ["line1", "line2", "line3"], "custom": 2000}""",
        RestErrorMessage.init(901, "block not found",
                              ["line1", "line2", "line3"])
      ),
      (
        """{"code": "902", "message": "block not found",
            "stacktraces": ["line1", "line2", "line3"],
            "custom": {"field1": "value1"}}""",
        RestErrorMessage.init(902, "block not found",
                              ["line1", "line2", "line3"])
      )
    ]

    const FailureTestVectors = [
      # `code` has negative value.
      """{"code":-1, "message": "block not found"}""",
      # `code` has negative value encoded as string.
      """{"code": "-1", "message": "block not found"}""",
      # `code` field as an object.
      """{"code":{"object": "value"}, "message": "block not found"}""",
      # `message` field as number.
      """{"code": "400", "message": 100}""",
      # `message` field as an object.
      """{"code": "400", "message": {"object": "value"}}""",
      # `stacktraces` field as an object.
      """{"code": "400", "message": "block not found",
          "stacktraces":{"object": "value"}}""",
      # Field `stacktraces` mixed array values.
      """{"code": "400", "message": "block not found",
          "stacktraces":["object", 1]""",
      # missing required field `code` and `message`.
      "",
      # missing required field `message`.
      """{"code":"400"}""",
      # missing required field `code`.
      """{"message": "block not found"}"""
    ]

    let contentType = getContentType("application/json").get()

    for test in GoodTestVectors:
      let res = decodeBytes(
        RestErrorMessage, test[0].toOpenArrayByte(0, len(test[0]) - 1),
        Opt.some(contentType))
      check res.isOk()
      let response = res.get()
      check:
        response.code == test[1].code
        response.message == test[1].message
      if response.stacktraces.isNone():
        check test[1].stacktraces.isNone()
      else:
        check:
          test[1].stacktraces.isSome()
          test[1].stacktraces.get() == response.stacktraces.get()

    for test in FailureTestVectors:
      let res = decodeBytes(
        RestErrorMessage, test.toOpenArrayByte(0, len(test) - 1),
        Opt.some(contentType))
      checkpoint test
      check res.isErr()

  test "RestErrorMessage writer tests":
    proc `==`(a: RestApiResponse, b: string): bool =
      case a.kind
      of RestApiResponseKind.Content:
        string.fromBytes(a.content.data) == b
      of RestApiResponseKind.Error:
        a.errobj.message == b
      else:
        raiseAssert "Unsupported RestApiResponse kind"
    check:
      jsonMsgResponse(RestApiResponse, "data") ==
          """{"code":200,"message":"data"}"""
      jsonError(RestApiResponse, Http202, "data") ==
        """{"code":202,"message":"data"}"""
      jsonError(RestApiResponse, Http400, "data", "") ==
        """{"code":400,"message":"data"}"""
      jsonError(RestApiResponse, Http404, "data", "stacktrace") ==
        """{"code":404,"message":"data","stacktraces":["stacktrace"]}"""
      jsonError(RestApiResponse, Http500, "data", ["s1", "s2"]) ==
        """{"code":500,"message":"data","stacktraces":["s1","s2"]}"""
      jsonErrorList(RestApiResponse, Http408, "data", ["s1", "s2"]) ==
        """{"code":408,"message":"data","failures":["s1","s2"]}"""

  test "strictParse(Stuint) tests":
    const
      GoodVectors16 = [
        ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
           "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ("0x123456789ABCDEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
           "123456789abcdefffffffffffffffffffffffffffffffffffffffffffffffff"),
        ("123456789ABCDEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
         "123456789abcdefffffffffffffffffffffffffffffffffffffffffffffffff")
      ]
      GoodVectors10 = [
        ("115792089237316195423570985008687907853269984665640564039457584007913129639935",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ("0", "0"),
      ]
      GoodVectors8 = [
        ("0o17777777777777777777777777777777777777777777777777777777777777777777777777777777777777",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
      ]
      GoodVectors2 = [
        ("0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
      ]
      OverflowVectors16 = [
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0",
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
      ]
      OverflowVectors10 = [
        "1157920892373161954235709850086879078532699846656405640394575840079131296399350",
        "1157920892373161954235709850086879078532699846656405640394575840079131296399351"
      ]
      OverflowVectors8 = [
        "0o177777777777777777777777777777777777777777777777777777777777777777777777777777777777770",
        "0o177777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
      ]
      OverflowVectors2 = [
        "0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110",
        "0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
      ]
      InvalidCharsVectors16 = [
        "GFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0xGFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0x0123456789ABCDEFZFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "0123456789ABCDEFXFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      ]
      InvalidCharsVectors10 = [
        "11579208923731619542357098500868790785326998466564056403945758400791312963993A",
        "K"
      ]
      InvalidCharsVectors8 = [
        "0o17777777777777777777777777777777777777777777777777777777777777777777777777777777777778"
      ]
      InvalidCharsVectors2 = [
        "0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111112"
      ]

    for vector in GoodVectors16:
      let res = strictParse(vector[0], UInt256, 16)
      check:
        res.isOk()
        res.get().toHex() == vector[1]

    for vector in GoodVectors10:
      let res = strictParse(vector[0], UInt256, 10)
      check:
        res.isOk()
        res.get().toHex() == vector[1]

    for vector in GoodVectors8:
      let res = strictParse(vector[0], UInt256, 8)
      check:
        res.isOk()
        res.get().toHex() == vector[1]

    for vector in GoodVectors2:
      let res = strictParse(vector[0], UInt256, 2)
      check:
        res.isOk()
        res.get().toHex() == vector[1]

    for vector in OverflowVectors16:
      let res = strictParse(vector, UInt256, 16)
      check:
        res.isErr()
        res.error == "Overflow error"

    for vector in OverflowVectors10:
      let res = strictParse(vector, UInt256, 10)
      check:
        res.isErr()
        res.error == "Overflow error"

    for vector in OverflowVectors8:
      let res = strictParse(vector, UInt256, 8)
      check:
        res.isErr()
        res.error == "Overflow error"

    for vector in OverflowVectors2:
      let res = strictParse(vector, UInt256, 2)
      check:
        res.isErr()
        res.error == "Overflow error"

    for vector in InvalidCharsVectors16:
      let res = strictParse(vector, UInt256, 16)
      check res.isErr()

    for vector in InvalidCharsVectors10:
      let res = strictParse(vector, UInt256, 10)
      check res.isErr()

    for vector in InvalidCharsVectors8:
      let res = strictParse(vector, UInt256, 8)
      check res.isErr()

    for vector in InvalidCharsVectors2:
      let res = strictParse(vector, UInt256, 2)
      check res.isErr()

  let examples = Json.decode(Web3SignerExamples, Table[string, Table[string, JsonString]])

  for name, example in examples:
    test "remote signing example " & name:
      let
        decoded = RestJson.decode(string(example["value"]), Web3SignerRequest)
        encoded = RestJson.encode(decoded)
        recoded = RestJson.encode(RestJson.decode(encoded, Web3SignerRequest))

      check:
        encoded == recoded

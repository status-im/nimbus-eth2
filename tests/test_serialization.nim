# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  stew/results, presto/client,
  testutils/unittests, chronicles,
  ../beacon_chain/spec/eth2_apis/[eth2_rest_serialization, rest_types],
  ./testutil

suite "Serialization/deserialization test suite":
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
        a.content.data.bytesToString() == b
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

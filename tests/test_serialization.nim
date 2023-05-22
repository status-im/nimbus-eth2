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
    proc init(t: typedesc[RestErrorMessage], status: int,
              message: string): RestErrorMessage =
      RestErrorMessage(
        code: status, message: message,
        stacktraces: none[seq[string]]()
      )
    proc init(t: typedesc[RestErrorMessage], status: int,
              message: string,
              stacktraces: openArray[string]): RestErrorMessage =
      RestErrorMessage(
        code: status, message: message,
        stacktraces: some(@stacktraces)
      )

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

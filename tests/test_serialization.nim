# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/options,
  stew/results, presto/client,
  testutils/unittests, chronicles,
  ../beacon_chain/spec/eth2_apis/[eth2_rest_serialization, rest_types],
  ./testutil

suite "Serialization/deserialization test suite":
  test "RestGenericError tests":
    proc init(t: typedesc[RestGenericError], status: int,
              message: string): RestGenericError =
      RestGenericError(
        code: uint64(status), message: message,
        stacktraces: none[seq[string]]()
      )
    proc init(t: typedesc[RestGenericError], status: int,
              message: string,
              stacktraces: openArray[string]): RestGenericError =
      RestGenericError(
        code: uint64(status), message: message,
        stacktraces: some(@stacktraces)
      )

    const GoodTestVectors = [
      (
        "{\"code\":500,\"message\":\"block not found\"}",
        RestGenericError.init(500, "block not found")
      ),
      (
        "{\"code\":\"600\",\"message\":\"block not found\"}",
        RestGenericError.init(600, "block not found")
      ),
      (
        "{\"code\":\"700\",\"message\":\"block not found\", " &
        "\"data\": \"data\", \"custom\": \"field\"}",
        RestGenericError.init(700, "block not found")
      ),
      (
        "{\"code\":\"701\",\"message\":\"block not found\", " &
        "\"data\": \"data\", \"custom\": 300}",
        RestGenericError.init(701, "block not found")
      ),
      (
        "{\"code\":\"702\",\"message\":\"block not found\", " &
        "\"data\": \"data\", \"custom\": {\"field1\": \"value1\"}}",
        RestGenericError.init(702, "block not found")
      ),
      (
        "{\"code\":800,\"message\":\"block not found\", " &
        "\"custom\": \"data\", \"stacktraces\": []}",
        RestGenericError.init(800, "block not found", [])
      ),
      (
        "{\"code\":801,\"message\":\"block not found\", " &
        "\"custom\": 100, \"stacktraces\": []}",
        RestGenericError.init(801, "block not found", [])
      ),
      (
        "{\"code\":802,\"message\":\"block not found\", " &
        "\"custom\": {\"field1\": \"value1\"}, \"stacktraces\": []}",
        RestGenericError.init(802, "block not found", [])
      ),
      (
        "{\"code\":\"900\",\"message\":\"block not found\", " &
        "\"stacktraces\": [\"line1\", \"line2\", \"line3\"], " &
        "\"custom\": \"data\"}",
        RestGenericError.init(900, "block not found",
                              ["line1", "line2", "line3"])
      ),
      (
        "{\"code\":\"901\",\"message\":\"block not found\", " &
        "\"stacktraces\": [\"line1\", \"line2\", \"line3\"], " &
        "\"custom\": 2000}",
        RestGenericError.init(901, "block not found",
                              ["line1", "line2", "line3"])
      ),
      (
        "{\"code\":\"902\",\"message\":\"block not found\", " &
        "\"stacktraces\": [\"line1\", \"line2\", \"line3\"], " &
        "\"custom\": {\"field1\": \"value1\"}}",
        RestGenericError.init(902, "block not found",
                              ["line1", "line2", "line3"])
      )
    ]

    const FailureTestVectors = [
      "{\"code\":-1, \"message\":\"block not found\"}",
      "{\"code\":\"-1\", \"message\":\"block not found\"}",
      "{\"code\":{\"object\": \"value\"}, \"message\":\"block not found\"}",
      "{\"code\":\"400\", \"message\":100}",
      "{\"code\":\"400\", \"message\":{\"object\": \"value\"}}",
      "{\"code\":\"400\", \"message\":\"block not found\", " &
        "\"stacktraces\":{\"object\": \"value\"}}",
      "{\"code\":\"400\", \"message\":\"block not found\", " &
        "\"stacktraces\":[\"object\", 1]}",
      "{\"code\":\"400\", \"message\":\"block not found\", " &
        "\"stacktraces\":[\"object\", 1]",
      "",
      "{\"code\":\"400\"}",
      "{\"message\":\"block not found\"}"
    ]

    let contentType = getContentType("application/json").get()

    for test in GoodTestVectors:
      let res = decodeBytes(
        RestGenericError, test[0].toOpenArrayByte(0, len(test[0]) - 1),
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
        RestGenericError, test.toOpenArrayByte(0, len(test) - 1),
        Opt.some(contentType))
      check res.isErr()

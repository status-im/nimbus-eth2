# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronos, presto/client, "."/[rest_types, eth2_rest_serialization]

from std/times import Time, DateTime, toTime, fromUnix, now, utc, `-`, inNanoseconds

export chronos, client, rest_types, eth2_rest_serialization

proc raiseGenericError*(resp: RestPlainResponse) {.noreturn, raises: [RestError].} =
  let error = block:
    let res = decodeBytes(RestErrorMessage, resp.data, resp.contentType)
    if res.isErr():
      let msg =
        "Incorrect response error format (" & $resp.status & ") [" & $res.error() & "]"
      raise newException(RestError, msg)
    res.get()
  let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
  raise newException(RestError, msg)

proc raiseUnknownStatusError*(
    resp: RestPlainResponse
) {.noreturn, raises: [RestError].} =
  let msg = "Unknown response status error (" & $resp.status & ")"
  raise newException(RestError, msg)

proc getBodyBytesWithCap*(
    response: HttpClientResponseRef, maxBytes: int
): Future[Opt[seq[byte]]] {.async.} =
  var reader = response.getBodyReader()
  try:
    let
      data = await reader.read(maxBytes)
      isComplete = reader.atEof()
    await reader.closeWait()
    reader = nil
    await response.finish()
    if not isComplete:
      return err()
    return ok data
  except CancelledError as exc:
    if not (isNil(reader)):
      await reader.closeWait()
    raise exc
  except AsyncStreamError:
    if not (isNil(reader)):
      await reader.closeWait()
    raise newHttpReadError("Could not read response")

proc getTimestamp*(): uint64 =
  uint64((toTime(now().utc) - fromUnix(0)).inNanoseconds())

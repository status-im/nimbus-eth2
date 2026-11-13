# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronos, presto/client,
  ./[rest_types, eth2_rest_serialization]

from std/times import Time, DateTime, toTime, fromUnix, now, utc, `-`,
                      inNanoseconds

export chronos, client, rest_types, eth2_rest_serialization

proc raiseGenericError*(resp: RestPlainResponse) {.
     noreturn, raises: [RestError].} =
  let error =
    block:
      let res = decodeBytes(RestErrorMessage, resp.data, resp.contentType)
      if res.isErr():
        let msg = "Incorrect response error format (" & $resp.status &
                  ") [" & $res.error() & "]"
        raise newException(RestError, msg)
      res.get()
  let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
  raise newException(RestError, msg)

func raiseUnknownStatusError*(resp: RestPlainResponse) {.
     noreturn, raises: [RestError].} =
  let msg = "Unknown response status error (" & $resp.status & ")"
  raise newException(RestError, msg)

proc getBodyBytesWithCap*(
    response: HttpClientResponseRef,
    maxBytes: int): Future[Opt[seq[byte]]] {.async.} =
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
    if not(isNil(reader)):
      await reader.closeWait()
    raise exc
  except AsyncStreamError:
    if not(isNil(reader)):
      await reader.closeWait()
    raise newHttpReadError("Could not read response")

type
  ProgressFunc* =
    proc (current, total: uint64, finish: bool) {.gcsafe, raises: [].}

proc getBodyInChunks*(
    response: HttpClientResponseRef,
    chunkSize: int = 1_048_576,
    maxBytes: int,
    timeout: Duration,
    cbproc: ProgressFunc
): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
  var
    res: seq[byte]
    reader =
      try:
        response.getBodyReader()
      except HttpUseClosedError:
        return Result[seq[byte], string].err("Remote peer disconnected")
  try:
    if not(isNil(cbproc)):
      cbproc(lenu64(res), response.contentLength, false)
    while not(reader.atEof()):
      let
        waitFut = sleepAsync(timeout)
        readFut = reader.read(chunkSize)
      discard await race(readFut, waitFut)
      if not(readFut.finished()):
        # timeout error
        await readFut.cancelAndWait()
        return Result[seq[byte], string].err("Read operation timed out")
      else:
        await waitFut.cancelAndWait()
      let data = await readFut
      if len(data) + len(res) >= maxBytes:
        return Result[seq[byte], string].err("Response too long")
      res = res & data
      if not(isNil(cbproc)):
        cbproc(lenu64(res), response.contentLength, false)
    if not(isNil(cbproc)):
      cbproc(lenu64(res), response.contentLength, true)
    Result[seq[byte], string].ok(res)
  except CancelledError as exc:
    if not(isNil(cbproc)):
      cbproc(lenu64(res), response.contentLength, true)
    raise exc
  except AsyncStreamError:
    if not(isNil(cbproc)):
      cbproc(lenu64(res), response.contentLength, true)
    return Result[seq[byte], string].err("Remote peer disconnected")
  finally:
    await reader.closeWait()
    try:
      await response.finish()
    except HttpUseClosedError:
      discard

proc getTimestamp*(): uint64 =
  uint64((toTime(now().utc) - fromUnix(0)).inNanoseconds())

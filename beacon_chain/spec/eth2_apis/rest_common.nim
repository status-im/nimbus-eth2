# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, presto/client,
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc raiseGenericError*(resp: RestPlainResponse) {.
     noreturn, raises: [RestError, Defect].} =
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

proc raiseUnknownStatusError*(resp: RestPlainResponse) {.
     noreturn, raises: [RestError, Defect].} =
  let msg = "Unknown response status error (" & $resp.status & ")"
  raise newException(RestError, msg)

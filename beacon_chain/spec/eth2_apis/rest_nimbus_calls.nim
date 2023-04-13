# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client,
  "."/[rest_types, eth2_rest_serialization, rest_common]

proc getValidatorsActivity*(epoch: Epoch,
                            body: seq[ValidatorIndex]
                           ): RestPlainResponse {.
     rest, endpoint: "/nimbus/v1/validator/activity/{epoch}",
     meth: MethodPost.}

proc getTimesyncInifo*(body: RestNimbusTimestamp1): RestPlainResponse {.
     rest, endpoint: "/nimbus/v1/timesync", meth: MethodPost.}

proc getTimeOffset*(client: RestClientRef): Future[int64] {.async.} =
  let
    timestamp1 = getTimestamp()
    data = RestNimbusTimestamp1(timestamp1: timestamp1)
    resp = await client.getTimesyncInifo(data)

  return
    case resp.status
    of 200:
      if resp.contentType.isNone() or
         isWildCard(resp.contentType.get().mediaType) or
         resp.contentType.get().mediaType != ApplicationJsonMediaType:
        raise newException(RestError, "Missing or incorrect Content-Type")

      let stamps = decodeBytes(RestNimbusTimestamp2, resp.data,
                               resp.contentType).valueOr:
        raise newException(RestError, $error)

      let offset = (int64(stamps.timestamp2) - int64(timestamp1)) +
                   (int64(stamps.timestamp3) - int64(getTimestamp()))
      offset
    of 400:
      let error = decodeBytes(RestErrorMessage, resp.data,
                              resp.contentType).valueOr:
        let msg = "Incorrect response error format (" & $resp.status &
                  ") [" & $error & "]"
        raise (ref RestResponseError)(msg: msg, status: resp.status)
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise (ref RestResponseError)(
        msg: msg, status: error.code, message: error.message)
    else:
      raiseRestResponseError(resp)

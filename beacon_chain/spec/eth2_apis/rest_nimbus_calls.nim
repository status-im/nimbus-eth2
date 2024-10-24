# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, presto/client,
  "."/[rest_types, eth2_rest_serialization, rest_common]

proc getValidatorsActivity*(epoch: Epoch,
                            body: seq[ValidatorIndex]
                           ): RestPlainResponse {.
     rest, endpoint: "/nimbus/v1/validator/activity/{epoch}",
     meth: MethodPost.}

proc getTimesyncInifo*(body: RestNimbusTimestamp1): RestPlainResponse {.
     rest, endpoint: "/nimbus/v1/timesync", meth: MethodPost.}

proc getTimeOffset*(client: RestClientRef,
                    delay: Duration): Future[int64] {.
     async: (raises: [RestError, RestResponseError, CancelledError]).} =
  let
    timestamp1 = getTimestamp()
    data = RestNimbusTimestamp1(timestamp1: timestamp1)
    resp = await client.getTimesyncInifo(data)
    timestamp4 = getTimestamp()

  case resp.status
  of 200:
    if resp.contentType.isNone() or
       isWildCard(resp.contentType.get().mediaType) or
       resp.contentType.get().mediaType != ApplicationJsonMediaType:
      raise newException(RestError, "Missing or incorrect Content-Type")

    let stamps = decodeBytes(RestNimbusTimestamp2, resp.data,
                             resp.contentType).valueOr:
      raise newException(RestError, $error)

    trace "Time offset data",
          timestamp1 = timestamp1,
          timestamp2 = stamps.timestamp2,
          timestamp3 = stamps.timestamp3,
          timestamp4 = timestamp4,
          delay14 = delay.nanoseconds,
          delay23 = stamps.delay

    # t1 - time when we sent request.
    # t2 - time when remote server received request.
    # t3 - time when remote server sent response.
    # t4 - time when we received response.
    # delay14 = validator client processing delay.
    # delay23 = beacon node processing delay.
    #
    # Round-trip network delay `delta` = (t4 - t1) - (t3 - t2)
    # but with delays this will be:
    # `delta` = (t4 - t1 + delay14) - (t3 - t2 + delay23)
    # Estimated server time is t3 + (delta div 2)
    # Estimated clock skew `theta` = t3 + (delta div 2) - t4
    let
      delay14 = delay.nanoseconds
      delay23 = int64(stamps.delay)
      offset = (int64(stamps.timestamp2) - int64(timestamp1) +
                int64(stamps.timestamp3) - int64(timestamp4) +
                delay14 - delay23) div 2
    offset
  else:
    let error = decodeBytes(RestErrorMessage, resp.data,
                            resp.contentType).valueOr:
      let msg = "Incorrect response error format (" & $resp.status &
                ") [" & $error & "]"
      raise (ref RestResponseError)(msg: msg, status: resp.status)
    let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
    raise (ref RestResponseError)(
      msg: msg, status: error.code, message: error.message)

proc getHistoricalSummariesV1Plain*(
  state_id: StateIdent
): RestPlainResponse {.
  rest,
  endpoint: "/nimbus/v1/debug/beacon/states/{state_id}/historical_summaries",
  accept: preferSSZ,
  meth: MethodGet
.}

proc getHistoricalSummariesV1*(
    client: RestClientRef, state_id: StateIdent, cfg: RuntimeConfig, restAccept = ""
): Future[Option[GetHistoricalSummariesV1Response]] {.
    async: (
      raises: [
        CancelledError, RestEncodingError, RestDnsResolveError, RestCommunicationError,
        RestDecodingError, RestResponseError,
      ]
    )
.} =
  let resp =
    if len(restAccept) > 0:
      await client.getHistoricalSummariesV1Plain(state_id, restAcceptType = restAccept)
    else:
      await client.getHistoricalSummariesV1Plain(state_id)

  return
    case resp.status
    of 200:
      if resp.contentType.isNone() or isWildCard(resp.contentType.get().mediaType):
        raise newException(RestDecodingError, "Missing or incorrect Content-Type")
      else:
        let mediaType = resp.contentType.get().mediaType
        if mediaType == ApplicationJsonMediaType:
          let summaries = decodeBytes(
            GetHistoricalSummariesV1Response, resp.data, resp.contentType
          ).valueOr:
            raise newException(RestDecodingError, $error)
          some(summaries)
        elif mediaType == OctetStreamMediaType:
          let summaries =
            try:
              SSZ.decode(resp.data, GetHistoricalSummariesV1Response)
            except SerializationError as exc:
              raise newException(RestDecodingError, exc.msg)
          some(summaries)
        else:
          raise newException(RestDecodingError, "Unsupported Content-Type")
    of 404:
      none(GetHistoricalSummariesV1Response)
    of 400, 500:
      let error = decodeBytes(RestErrorMessage, resp.data, resp.contentType).valueOr:
        let msg =
          "Incorrect response error format (" & $resp.status & ") [" & $error & "]"
        raise (ref RestResponseError)(msg: msg, status: resp.status)
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise
        (ref RestResponseError)(msg: msg, status: error.code, message: error.message)
    else:
      raiseRestResponseError(resp)

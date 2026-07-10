# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, presto/client,
  "."/[rest_types, eth2_rest_serialization, rest_common]

proc getValidatorsActivity*(epoch: Epoch,
                            body: seq[ValidatorIndex]
                           ): RestPlainResponse {.
     rest, endpoint: "/nimbus/v1/validator/activity/{epoch}",
     meth: MethodPost.}

func decodeSszResponse(
    T: type ForkedHistoricalSummariesWithProof,
    data: openArray[byte],
    historicalSummariesFork: HistoricalSummariesFork,
    cfg: RuntimeConfig,
): T {.raises: [RestDecodingError].} =
  case historicalSummariesFork
  of HistoricalSummariesFork.Electra:
    let summaries =
      try:
        SSZ.decode(data, GetHistoricalSummariesV1ResponseElectra)
      except SerializationError as exc:
        raise newException(RestDecodingError, exc.msg)
    ForkedHistoricalSummariesWithProof.init(summaries)
  of HistoricalSummariesFork.Capella:
    let summaries =
      try:
        SSZ.decode(data, GetHistoricalSummariesV1Response)
      except SerializationError as exc:
        raise newException(RestDecodingError, exc.msg)
    ForkedHistoricalSummariesWithProof.init(summaries)

proc decodeJsonResponse(
    T: type ForkedHistoricalSummariesWithProof,
    data: openArray[byte],
    historicalSummariesFork: HistoricalSummariesFork,
    cfg: RuntimeConfig,
): T {.raises: [RestDecodingError].} =
  case historicalSummariesFork
  of HistoricalSummariesFork.Electra:
    let summaries = decodeBytes(
      GetHistoricalSummariesV1ResponseElectra, data, Opt.none(ContentTypeData)
    ).valueOr:
      raise newException(RestDecodingError, $error)
    ForkedHistoricalSummariesWithProof.init(summaries)
  of HistoricalSummariesFork.Capella:
    let summaries = decodeBytes(
      GetHistoricalSummariesV1Response, data, Opt.none(ContentTypeData)
    ).valueOr:
      raise newException(RestDecodingError, $error)
    ForkedHistoricalSummariesWithProof.init(summaries)

proc decodeHttpResponse(
    T: type ForkedHistoricalSummariesWithProof,
    data: openArray[byte],
    mediaType: MediaType,
    consensusFork: ConsensusFork,
    cfg: RuntimeConfig,
): T {.raises: [RestDecodingError].} =
  let historicalSummariesFork = historicalSummariesForkAtConsensusFork(consensusFork).valueOr:
    raiseRestDecodingBytesError(cstring("Unsupported fork: " & $consensusFork))

  if mediaType == OctetStreamMediaType:
    ForkedHistoricalSummariesWithProof.decodeSszResponse(data, historicalSummariesFork, cfg)
  elif mediaType == ApplicationJsonMediaType:
    ForkedHistoricalSummariesWithProof.decodeJsonResponse(data, historicalSummariesFork, cfg)
  else:
    raise newException(RestDecodingError, "Unsupported content-type")

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
): Future[Opt[ForkedHistoricalSummariesWithProof]] {.
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
        let
          consensusFork = ConsensusFork.decodeString(
            resp.headers.getString("eth-consensus-version")
          ).valueOr:
            raiseRestDecodingBytesError(error)
          mediaType = resp.contentType.value().mediaType

        Opt.some(
          ForkedHistoricalSummariesWithProof.decodeHttpResponse(
            resp.data, mediaType, consensusFork, cfg
          )
        )
    of 404:
      Opt.none(ForkedHistoricalSummariesWithProof)
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

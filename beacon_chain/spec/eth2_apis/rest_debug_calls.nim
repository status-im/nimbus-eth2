# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, presto/client,
  ".."/[helpers, forks], ".."/datatypes/[phase0, altair],
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getDebugChainHeads*(): RestResponse[GetDebugChainHeadsResponse] {.
     rest, endpoint: "/eth/v1/debug/beacon/heads",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getDebugChainHeads

proc getStateV2Plain*(state_id: StateIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v2/debug/beacon/states/{state_id}",
     accept: preferSSZ,
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2

proc getStateV2*(client: RestClientRef, state_id: StateIdent,
                 cfg: RuntimeConfig, restAccept = ""
                ): Future[ref ForkedHashedBeaconState] {.async.} =
  # nil is returned if the state is not found due to a 404 - `ref` is needed
  # to manage stack usage
  let resp =
    if len(restAccept) > 0:
      await client.getStateV2Plain(state_id, restAcceptType = restAccept)
    else:
      await client.getStateV2Plain(state_id)
  return
    case resp.status
    of 200:
      if resp.contentType.isNone() or
         isWildCard(resp.contentType.get().mediaType):
        raise newException(RestError, "Missing or incorrect Content-Type")
      else:
        let mediaType = resp.contentType.get().mediaType
        if mediaType == ApplicationJsonMediaType:
          let state =
            block:
              let res = newClone(decodeBytes(GetStateV2Response, resp.data,
                                    resp.contentType))
              if res[].isErr():
                raise newException(RestError, $res[].error())
              newClone(res[].get())
          state
        elif mediaType == OctetStreamMediaType:
          try:
            newClone(readSszForkedHashedBeaconState(cfg, resp.data))
          except CatchableError as exc:
            raise newException(RestError, exc.msg)
        else:
          raise newException(RestError, "Unsupported content-type")
    of 404:
      nil
    of 400, 500:
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

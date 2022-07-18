# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronos, presto/client,
  ".."/[helpers, forks], ".."/datatypes/[phase0, altair],
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getStatePlain*(state_id: StateIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v1/debug/beacon/states/{state_id}",
     accept: preferSSZ,
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getState

proc getState*(client: RestClientRef, state_id: StateIdent,
               restAccept = ""): Future[phase0.BeaconState] {.async.} =
  let resp =
    if len(restAccept) > 0:
      await client.getStatePlain(state_id, restAcceptType = restAccept)
    else:
      await client.getStatePlain(state_id)
  let data =
    case resp.status
    of 200:
      case resp.contentType
      of "application/json":
        let state =
          block:
            let res = decodeBytes(GetStateResponse, resp.data,
                                  resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            res.get()
        state.data
      of "application/octet-stream":
        let state =
          block:
            let res = decodeBytes(GetPhase0StateSszResponse, resp.data,
                                  resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            res.get()
        state
      else:
        raise newException(RestError, "Unsupported content-type")
    of 400, 404, 500:
      let error =
        block:
          let res = decodeBytes(RestGenericError, resp.data, resp.contentType)
          if res.isErr():
            let msg = "Incorrect response error format (" & $resp.status &
                      ") [" & $res.error() & "]"
            raise newException(RestError, msg)
          res.get()
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise newException(RestError, msg)
    else:
      let msg = "Unknown response status error (" & $resp.status & ")"
      raise newException(RestError, msg)
  return data

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
  let data =
    case resp.status
    of 200:
      case resp.contentType
      of "application/json":
        let state =
          block:
            let res = newClone(decodeBytes(GetStateV2Response, resp.data,
                                  resp.contentType))
            if res[].isErr():
              raise newException(RestError, $res[].error())
            newClone(res[].get())
        state
      of "application/octet-stream":
        try:
          newClone(readSszForkedHashedBeaconState(cfg, resp.data))
        except CatchableError as exc:
          raise newException(RestError, exc.msg)
      else:
        raise newException(RestError, "Unsupported content-type")
    of 404:
      nil
    of 400, 500:
      let error =
        block:
          let res = decodeBytes(RestGenericError, resp.data, resp.contentType)
          if res.isErr():
            let msg = "Incorrect response error format (" & $resp.status &
                      ") [" & $res.error() & "]"
            raise newException(RestError, msg)
          res.get()
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise newException(RestError, msg)
    else:
      let msg = "Unknown response status error (" & $resp.status & ")"
      raise newException(RestError, msg)
  return data

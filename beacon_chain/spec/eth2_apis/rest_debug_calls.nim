# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client,
  ".."/[helpers, forks], ".."/datatypes/[phase0, altair, merge],
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getStatePlain*(state_id: StateIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v1/debug/beacon/states/{state_id}",
     accept: "application/octet-stream,application-json;q=0.9",
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
     accept: "application/octet-stream,application-json;q=0.9",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2

proc getStateV2*(client: RestClientRef, state_id: StateIdent,
                 forks: array[2, Fork],
                 restAccept = ""): Future[ForkedHashedBeaconState] {.async.} =
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
            let res = decodeBytes(GetStateV2Response, resp.data,
                                  resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            res.get()
        state
      of "application/octet-stream":
        let header =
          block:
            let res = decodeBytes(GetStateV2Header, resp.data, resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            res.get()
        if header.slot.epoch() < forks[1].epoch:
          let state = newClone(
            block:
              let res = newClone(decodeBytes(
                GetPhase0StateSszResponse, resp.data, resp.contentType))
              if res[].isErr():
                raise newException(RestError, $res[].error())
              res[].get())
          ForkedHashedBeaconState.init(phase0.HashedBeaconState(
            data: state[], root: hash_tree_root(state[])))
        else:
          let state = newClone(
            block:
              let res = newClone(decodeBytes(
                GetAltairStateSszResponse, resp.data, resp.contentType))
              if res[].isErr():
                raise newException(RestError, $res[].error())
              res[].get())
          ForkedHashedBeaconState.init(altair.HashedBeaconState(
            data: state[], root: hash_tree_root(state[])))
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

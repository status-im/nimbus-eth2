# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/strformat,
  chronos, presto/client,
  ../[helpers, forks],
  ./[rest_common, rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getDebugChainHeadsV2*(): RestResponse[GetDebugChainHeadsV2Response] {.
     rest, endpoint: "/eth/v2/debug/beacon/heads",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getDebugChainHeadsV2

proc getStateV2Plain(state_id: StateIdent): RestHttpResponseRef {.
     rest, endpoint: "/eth/v2/debug/beacon/states/{state_id}",
     accept: preferSSZ,
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2

proc getStateV2*(
    client: RestClientRef, state_id: StateIdent, cfg: RuntimeConfig,
    restAccept = ""): Future[ref ForkedHashedBeaconState] {.async.} =
  # nil is returned if the state is not found due to a 404 - `ref` is needed
  # to manage stack usage
  let resp =
    if len(restAccept) > 0:
      await client.getStateV2Plain(state_id, restAcceptType = restAccept)
    else:
      await client.getStateV2Plain(state_id)

  case resp.status
  of 200:
    if resp.contentType.isNone():
      raise newException(RestError, "Missing Content-Type")

    const maxBodyBytes = 3 * 1024 * 1024 * 1024
    let
      data = (await resp.getBodyBytesWithCap(maxBodyBytes)).valueOr:
        raise newException(RestError, "Response too long")
      mediaType = resp.contentType.get().mediaType
      state =
        if mediaType == ApplicationJsonMediaType:
          decodeBytes(GetStateV2Response, data, resp.contentType).valueOr:
            raise newException(RestError, $error)
        elif mediaType == OctetStreamMediaType:
          try:
            newClone(readSszForkedHashedBeaconState(cfg, data))
          except CatchableError as exc:
            raise newException(RestError, exc.msg)
        else:
          raise newException(RestError, "Unsupported content-type")

    case state_id.kind
    of StateQueryKind.Slot:
      if state[].slot != state_id.slot:
        raise newException(RestError, "Wrong slot in received state")
    of StateQueryKind.Root:
      if state[].root != state_id.root:
        raise newException(RestError, "Wrong root in received state")
    of StateQueryKind.Named:
      case state_id.value
      of StateIdentType.Genesis:
        if state[].slot != GENESIS_SLOT:
          raise newException(RestError, "Wrong slot in received state")
      else:
        discard # can't trivially check these

    state
  of 404:
    nil
  of 400, 500:
    const maxBodyBytes = 128 * 1024
    let
      data = (await resp.getBodyBytesWithCap(maxBodyBytes)).valueOr:
        let msg = &"Error response too long ({resp.status})"
        raise (ref RestResponseError)(msg: msg, status: resp.status)
      error = decodeBytes(RestErrorMessage, data, resp.contentType).valueOr:
        let msg = &"Incorrect response error format ({resp.status}) [{error}]"
        raise (ref RestResponseError)(msg: msg, status: resp.status)
    let msg = &"Error response ({resp.status}) [{error.message}]"
    raise (ref RestResponseError)(
      msg: msg, status: error.code, message: error.message)
  else:
    raiseRestResponseError(RestPlainResponse(
      status: resp.status,
      contentType: resp.contentType))

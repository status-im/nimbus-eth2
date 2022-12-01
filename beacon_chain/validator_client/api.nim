# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import chronicles
import ../spec/eth2_apis/eth2_rest_serialization,
       ../spec/datatypes/[phase0, altair]
import common, fallback_service

export eth2_rest_serialization, common

const
  ResponseSuccess = "Received successful response"
  ResponseInvalidError = "Received invalid request response"
  ResponseInternalError = "Received internal error response"
  ResponseUnexpectedError = "Received unexpected error response"
  ResponseNotFoundError = "Received resource missing error response"
  ResponseNoSyncError = "Received nosync error response"

type
  ApiResponse*[T] = Result[T, string]
  ApiOperation = enum
    Success, Timeout, Failure, Interrupt

  ApiStrategyKind* {.pure.} = enum
    Priority, Best, First

  ApiNodeResponse*[T] = object
    node*: BeaconNodeServerRef
    data*: ApiResponse[T]

  ApiResponseSeq*[T] = object
    status*: ApiOperation
    data*: seq[ApiNodeResponse[T]]

proc `$`*(strategy: ApiStrategyKind): string =
  case strategy
  of ApiStrategyKind.First:
    "first"
  of ApiStrategyKind.Best:
    "best"
  of ApiStrategyKind.Priority:
    "priority"

proc lazyWaiter(node: BeaconNodeServerRef, request: FutureBase) {.async.} =
  try:
    await allFutures(request)
    if request.failed():
      node.status = RestBeaconNodeStatus.Offline
  except CancelledError as exc:
    node.status = RestBeaconNodeStatus.Offline
    await cancelAndWait(request)

proc lazyWait(nodes: seq[BeaconNodeServerRef], requests: seq[FutureBase],
              timerFut: Future[void]) {.async.} =
  doAssert(len(nodes) == len(requests))
  if len(nodes) == 0:
    return

  var futures: seq[Future[void]]
  for index in 0 ..< len(requests):
    futures.add(lazyWaiter(nodes[index], requests[index]))

  if not(isNil(timerFut)):
    await allFutures(futures) or timerFut
    if timerFut.finished():
      var pending: seq[Future[void]]
      for future in futures:
        if not(future.finished()):
          pending.add(future.cancelAndWait())
      await allFutures(pending)
    else:
      await cancelAndWait(timerFut)
  else:
    await allFutures(futures)

template firstSuccessParallel*(
           vc: ValidatorClientRef,
           responseType: typedesc,
           timeout: Duration,
           roles: set[BeaconNodeRole],
           body1, body2: untyped
         ): ApiResponse[responseType] =
  var it {.inject.}: RestClientRef

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  var retRes: ApiResponse[responseType]
  while true:
    var resultReady = false
    let onlineNodes =
      try:
        if not isNil(timerFut):
          await vc.waitOnlineNodes(timerFut, roles)
        vc.onlineNodes(roles)
      except CancelledError as exc:
        if not(isNil(timerFut)) and not(timerFut.finished()):
          await timerFut.cancelAndWait()
        raise exc
      except CatchableError as exc:
        # This case could not be happened.
        error "Unexpected exception while waiting for beacon nodes",
              err_name = $exc.name, err_msg = $exc.msg
        var default: seq[BeaconNodeServerRef]
        default

    if len(onlineNodes) == 0:
      retRes = ApiResponse[responseType].err("Operation timeout exceeded")
      resultReady = true
    else:
      var (pendingRequests, pendingNodes) =
        block:
          var requests: seq[FutureBase]
          var nodes: seq[BeaconNodeServerRef]
          for node {.inject.} in onlineNodes:
            it = node.client
            let fut = FutureBase(body1)
            requests.add(fut)
            nodes.add(node)
          (requests, nodes)

      var raceFut: Future[FutureBase]
      while true:
        try:
          if len(pendingRequests) == 0:
            if not(isNil(timerFut)) and not(timerFut.finished()):
              await timerFut.cancelAndWait()
            retRes = ApiResponse[responseType].err(
              "Beacon node(s) unable to satisfy request")
            resultReady = true
          else:
            raceFut = race(pendingRequests)

            if isNil(timerFut):
              await raceFut or timerFut
            else:
              await allFutures(raceFut)

            if raceFut.finished():
              # One of the requests in the race completed.
              let index = pendingRequests.find(raceFut.read())
              doAssert(index >= 0)

              let
                requestFut = pendingRequests[index]
                beaconNode = pendingNodes[index]

              # Remove completed future from pending list.
              pendingRequests.del(index)
              pendingNodes.del(index)

              let
                node {.inject.} = beaconNode
                apiResponse {.inject.} =
                  if requestFut.failed():
                    let exc = Future[responseType](requestFut).readError()
                    ApiResponse[responseType].err("[" & $exc.name & "] " &
                                                  $exc.msg)
                  else:
                    ApiResponse[responseType].ok(
                      Future[responseType](requestFut).read())
                status =
                  try:
                    body2
                  except CancelledError as exc:
                    raise exc
                  except CatchableError:
                    raiseAssert("Response handler must not raise exceptions")

              node.status = status
              if apiResponse.isOk() and (status == RestBeaconNodeStatus.Online):
                retRes = apiResponse
                resultReady = true
                asyncSpawn lazyWait(pendingNodes, pendingRequests, timerFut)
                break
            else:
              # Timeout exceeded first.
              var pendingCancel: seq[Future[void]]
              pendingCancel.add(raceFut.cancelAndWait())
              for index, future in pendingRequests.pairs():
                if not(future.finished()):
                  pendingNodes[index].status = RestBeaconNodeStatus.Offline
                  pendingCancel.add(future.cancelAndWait())
              await allFutures(pendingCancel)
              retRes = ApiResponse[responseType].err(
                "Beacon nodes unable to satisfy request in time")
              resultReady = true
        except CancelledError as exc:
          var pendingCancel: seq[Future[void]]
          if not(isNil(raceFut)) and not(raceFut.finished()):
            pendingCancel.add(raceFut.cancelAndWait())
          if not(isNil(timerFut)) and not(timerFut.finished()):
            pendingCancel.add(timerFut.cancelAndWait())
          for index, future in pendingRequests.pairs():
            if not(future.finished()):
              pendingNodes[index].status = RestBeaconNodeStatus.Offline
              pendingCancel.add(future.cancelAndWait())
          await allFutures(pendingCancel)
          raise exc
        except CatchableError as exc:
          # This should not be happened, because allFutures() and race() did not
          # raise any exceptions.
          error "Unexpected exception while processing request",
                err_name = $exc.name, err_msg = $exc.msg
          retRes = ApiResponse[responseType].err("Unexpected error")
          resultReady = true
        if resultReady:
          break
    if resultReady:
      break
  retRes

template bestSuccess*(vc: ValidatorClientRef, responseType: typedesc,
                      timeout: Duration, bodyRequest,
                      bodyScore: untyped): ApiResponse[responseType] =
  var it {.inject.}: RestClientRef
  type BodyType = typeof(bodyRequest)

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  let onlineNodes =
    try:
      if not isNil(timerFut):
        await vc.waitOnlineNodes(timerFut)
      vc.onlineNodes()
    except CancelledError as exc:
      if not(isNil(timerFut)) and not(timerFut.finished()):
        await timerFut.cancelAndWait()
      raise exc
    except CatchableError as exc:
      # This case could not be happened.
      error "Unexpected exception while waiting for beacon nodes",
            err_name = $exc.name, err_msg = $exc.msg
      var default: seq[BeaconNodeServerRef]
      default

  if len(onlineNodes) == 0:
    ApiResponse[responseType].err("No beacon nodes available")
  else:
    let
      (pendingRequests, pendingNodes) =
        block:
          var requests: seq[BodyType]
          var nodes: seq[BeaconNodeServerRef]
          for node {.inject.} in onlineNodes:
            it = node.client
            let fut = bodyRequest
            requests.add(fut)
            nodes.add(node)
          (requests, nodes)

      status =
        try:
          if isNil(timerFut):
            await allFutures(pendingRequests)
            ApiOperation.Success
          else:
            let waitFut = allFutures(pendingRequests)
            discard await race(waitFut, timerFut)
            if not(waitFut.finished()):
              await waitFut.cancelAndWait()
              ApiOperation.Timeout
            else:
              if not(timerFut.finished()):
                await timerFut.cancelAndWait()
              ApiOperation.Success
        except CancelledError as exc:
          # We should cancel all the pending requests and timer before we return
          # result.
          var pendingCancel: seq[Future[void]]
          for future in pendingRequests:
            if not(fut.finished()):
              pendingCancel.add(fut.cancelAndWait())
          if not(isNil(timerFut)) and not(timerFut.finished()):
            pendingCancel.add(timerFut.cancelAndWait())
          await allFutures(pendingCancel)
          raise exc
        except CatchableError:
          # This should not be happened, because allFutures() and race() did not
          # raise any exceptions.
          ApiOperation.Failure

      apiResponses {.inject.} =
        block:
          var res: seq[ApiNodeResponse[responseType]]
          for requestFut, pnode in pendingRequests.pairs():
            let beaconNode = pendingNodes[index]
            if requestFut.finished():
              if requestFut.failed():
                let exc = requestFut.readError()
                debug "One of operation requests has been failed",
                      node = beaconNode, err_name = $exc.name,
                      err_msg = $exc.msg
                beaconNode.status = RestBeaconNodeStatus.Offline
              elif future.cancelled():
                debug "One of operation requests has been interrupted",
                      node = beaconNode
              else:
                res.add(
                  ApiNodeResponse(
                    node: beaconNode,
                    data: ApiResponse[responseType].ok(future.read())
                  )
                )
            else:
              case status
              of ApiOperation.Timeout:
                debug "One of operation requests has been timed out",
                      node = beaconNode
                pendingNodes[index].status = RestBeaconNodeStatus.Offline
              of ApiOperation.Success, ApiOperation.Failure,
                 ApiOperation.Interrupt:
                 # This should not be happened, because all Futures should be
                 # finished.
                debug "One of operation requests failed unexpectedly",
                      node = beaconNode
                pendingNodes[index].status = RestBeaconNodeStatus.Offline
          res

    if len(apiResponses) == 0:
      ApiResponse[responseType].err("No successful responses available")
    else:
      let index = bestScore
      if index >= 0:
        debug "Operation request result was selected",
              node = apiResponses[index].node
        apiResponses[index].data
      else:
        ApiResponse[responseType].err("Unable to get best response")

template onceToAll*(vc: ValidatorClientRef, responseType: typedesc,
                    timeout: Duration, roles: set[BeaconNodeRole],
                    body: untyped): ApiResponseSeq[responseType] =
  var it {.inject.}: RestClientRef
  type BodyType = typeof(body)

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  let onlineNodes =
    try:
      if not isNil(timerFut):
        await vc.waitOnlineNodes(timerFut, roles)
      vc.onlineNodes(roles)
    except CancelledError as exc:
      if not(isNil(timerFut)) and not(timerFut.finished()):
        await timerFut.cancelAndWait()
      raise exc
    except CatchableError as exc:
      # This case could not be happened.
      error "Unexpected exception while waiting for beacon nodes",
            err_name = $exc.name, err_msg = $exc.msg
      var default: seq[BeaconNodeServerRef]
      default

  if len(onlineNodes) == 0:
    # Timeout exceeded or operation was cancelled
    ApiResponseSeq[responseType](status: ApiOperation.Timeout)
  else:
    let (pendingRequests, pendingNodes) =
      block:
        var requests: seq[BodyType]
        var nodes: seq[BeaconNodeServerRef]
        for node {.inject.} in onlineNodes:
          it = node.client
          let fut = body
          requests.add(fut)
          nodes.add(node)
        (requests, nodes)

    let status =
      try:
        if isNil(timerFut):
          await allFutures(pendingRequests)
          ApiOperation.Success
        else:
          let waitFut = allFutures(pendingRequests)
          discard await race(waitFut, timerFut)
          if not(waitFut.finished()):
            await waitFut.cancelAndWait()
            ApiOperation.Timeout
          else:
            if not(timerFut.finished()):
              await timerFut.cancelAndWait()
            ApiOperation.Success
      except CancelledError as exc:
        # We should cancel all the pending requests and timer before we return
        # result.
        var pendingCancel: seq[Future[void]]
        for fut in pendingRequests:
          if not(fut.finished()):
            pendingCancel.add(fut.cancelAndWait())
        if not(isNil(timerFut)) and not(timerFut.finished()):
          pendingCancel.add(timerFut.cancelAndWait())
        await allFutures(pendingCancel)
        raise exc
      except CatchableError:
        # This should not be happened, because allFutures() and race() did not
        # raise any exceptions.
        ApiOperation.Failure

    let responses =
      block:
        var res: seq[ApiNodeResponse[responseType]]
        for idx, pnode in pendingNodes.pairs():
          let apiResponse =
            block:
              let fut = pendingRequests[idx]
              if fut.finished():
                if fut.failed() or fut.cancelled():
                  let exc = fut.readError()
                  ApiNodeResponse[responseType](
                    node: pnode,
                    data: ApiResponse[responseType].err("[" & $exc.name & "] " &
                                                        $exc.msg)
                  )
                else:
                  ApiNodeResponse[responseType](
                    node: pnode,
                    data: ApiResponse[responseType].ok(fut.read())
                  )
              else:
                case status
                of ApiOperation.Interrupt:
                  ApiNodeResponse[responseType](
                    node: pnode,
                    data: ApiResponse[responseType].err("Operation interrupted")
                  )
                of ApiOperation.Timeout:
                  pendingNodes[idx].status = RestBeaconNodeStatus.Offline
                  ApiNodeResponse[responseType](
                    node: pnode,
                    data: ApiResponse[responseType].err(
                            "Operation timeout exceeded")
                  )
                of ApiOperation.Success, ApiOperation.Failure:
                  # This should not be happened, because all Futures should be
                  # finished, and `Failure` processed when Future is finished.
                  ApiNodeResponse[responseType](
                    node: pnode,
                    data: ApiResponse[responseType].err("Unexpected error")
                  )
          res.add(apiResponse)
        res

    ApiResponseSeq[responseType](status: status, data: responses)

template firstSuccessSequential*(vc: ValidatorClientRef, respType: typedesc,
                                 timeout: Duration,
                                 roles: set[BeaconNodeRole], body: untyped,
                                 handlers: untyped): untyped =
  doAssert(timeout != ZeroDuration)
  var it {.inject.}: RestClientRef

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  var iterationsCount = 0

  while true:
    let onlineNodes =
      try:
        await vc.waitOnlineNodes(timerFut, roles)
        vc.onlineNodes(roles)
      except CancelledError as exc:
        # waitOnlineNodes do not cancel `timoutFuture`.
        if not(isNil(timerFut)) and not(timerFut.finished()):
          await timerFut.cancelAndWait()
        raise exc
      except CatchableError:
        # This case could not be happened.
        var default: seq[BeaconNodeServerRef]
        default

    if len(onlineNodes) == 0:
      # `onlineNodes` sequence is empty only if operation timeout exceeded.
      break

    if iterationsCount != 0:
      debug "Request got failed", iterations_count = iterationsCount

    var exitNow = false

    for node {.inject.} in onlineNodes:
      it = node.client
      var bodyFut = body

      let resOp =
        block:
          if isNil(timerFut):
            try:
              # We use `allFutures()` to keep result in `bodyFut`, but still
              # be able to check errors.
              await allFutures(bodyFut)
              ApiOperation.Success
            except CancelledError as exc:
              # `allFutures()` could not cancel Futures.
              if not(bodyFut.finished()):
                await bodyFut.cancelAndWait()
              raise exc
            except CatchableError as exc:
              # This case could not be happened.
              ApiOperation.Failure
          else:
            try:
              discard await race(bodyFut, timerFut)
              if bodyFut.finished():
                ApiOperation.Success
              else:
                await bodyFut.cancelAndWait()
                ApiOperation.Timeout
            except CancelledError as exc:
              # `race()` could not cancel Futures.
              var pending: seq[Future[void]]
              if not(bodyFut.finished()):
                pending.add(bodyFut.cancelAndWait())
              if not(isNil(timerFut)) and not(timerFut.finished()):
                pending.add(timerFut.cancelAndWait())
              await allFutures(pending)
              raise exc
            except CatchableError as exc:
              # This case should not happen.
              ApiOperation.Failure

      block:
        let apiResponse {.inject.} =
          block:
            if bodyFut.finished():
              if bodyFut.failed() or bodyFut.cancelled():
                let exc = bodyFut.readError()
                ApiResponse[respType].err("[" & $exc.name & "] " & $exc.msg)
              else:
                ApiResponse[respType].ok(bodyFut.read())
            else:
              case resOp
              of ApiOperation.Interrupt:
                ApiResponse[respType].err("Operation was interrupted")
              of ApiOperation.Timeout:
                ApiResponse[respType].err("Operation timeout exceeded")
              of ApiOperation.Success, ApiOperation.Failure:
                # This should not be happened, because all Futures should be
                # finished, and `Failure` processed when Future is finished.
                ApiResponse[respType].err("Unexpected error")

        let status =
          try:
            handlers
          except CatchableError:
            raiseAssert("Response handler must not raise exceptions")

        node.status = status

      if resOp == ApiOperation.Success:
        if node.status == RestBeaconNodeStatus.Online:
          exitNow = true
          break
      else:
        exitNow = true
        break

    if exitNow:
      break

proc getIndexedErrorMessage(response: RestPlainResponse): string =
  let res = decodeBytes(RestIndexedErrorMessage, response.data,
                        response.contentType)
  if res.isOk():
    let errorObj = res.get()
    let failures = errorObj.failures.mapIt($it.index & ": " & it.message)
    errorObj.message & ": [" & failures.join(", ") & "]"
  else:
    "Unable to decode error response: [" & $res.error() & "]"

proc getErrorMessage(response: RestPlainResponse): string =
  let res = decodeBytes(RestErrorMessage, response.data,
                        response.contentType)
  if res.isOk():
    let errorObj = res.get()
    if errorObj.stacktraces.isSome():
      errorObj.message & ": [" & errorObj.stacktraces.get().join("; ") & "]"
    else:
      errorObj.message
  else:
    "Unable to decode error response: [" & $res.error() & "]"

proc getProposerDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       strategy: ApiStrategyKind
     ): Future[GetProposerDutiesResponse] {.async.} =
  logScope:
    request = "getProposerDuties"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve proposer duties"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestResponse[GetProposerDutiesResponse],
                                      SlotDuration, {BeaconNodeRole.Duties},
                                      getProposerDuties(it, epoch)):
      if apiResponse.isErr():
        trace ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestResponse[GetProposerDutiesResponse],
                              SlotDuration, {BeaconNodeRole.Duties},
                              getProposerDuties(it, epoch)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node,  error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc getAttesterDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       validators: seq[ValidatorIndex],
       strategy: ApiStrategyKind
     ): Future[GetAttesterDutiesResponse] {.async.} =
  logScope:
    request = "getAttesterDuties"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve attester duties"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestResponse[GetAttesterDutiesResponse],
                                      SlotDuration, {BeaconNodeRole.Duties},
                                      getAttesterDuties(it, epoch, validators)):
      if apiResponse.isErr():
        trace ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestResponse[GetAttesterDutiesResponse],
                              SlotDuration, {BeaconNodeRole.Duties},
                              getAttesterDuties(it, epoch, validators)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node,
              error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    raise newException(ValidatorApiError, ErrorMessage)

proc getSyncCommitteeDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       validators: seq[ValidatorIndex],
       strategy: ApiStrategyKind
     ): Future[GetSyncCommitteeDutiesResponse] {.async.} =
  logScope:
    request = "getSyncCommitteeDuties"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve sync committee duties"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestResponse[GetSyncCommitteeDutiesResponse], SlotDuration,
      {BeaconNodeRole.Duties}, getSyncCommitteeDuties(it, epoch, validators)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestResponse[GetSyncCommitteeDutiesResponse],
                              SlotDuration, {BeaconNodeRole.Duties},
                              getSyncCommitteeDuties(it, epoch, validators)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc getForkSchedule*(
       vc: ValidatorClientRef,
       strategy: ApiStrategyKind
     ): Future[seq[Fork]] {.async.} =
  logScope:
    request = "getForkSchedule"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve fork schedule"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestResponse[GetForkScheduleResponse],
                                      SlotDuration, {BeaconNodeRole.Duties},
                                      getForkSchedule(it)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data.data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestResponse[GetForkScheduleResponse],
                              SlotDuration, {BeaconNodeRole.Duties},
                              getForkSchedule(it)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data.data
        of 500:
          debug ResponseInternalError,
                response_code = response.status, endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError,
                response_code = response.status, endpoint = node
          RestBeaconNodeStatus.Offline
    raise newException(ValidatorApiError, ErrorMessage)

proc getHeadBlockRoot*(
       vc: ValidatorClientRef,
       strategy: ApiStrategyKind
     ): Future[RestRoot] {.async.} =
  logScope:
    request = "getHeadBlockRoot"
    strategy = $strategy

  let blockIdent = BlockIdent.init(BlockIdentType.Head)

  const ErrorMessage = "Unable to retrieve head block's root"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestResponse[GetBlockRootResponse],
                                      SlotDuration,
                                      {BeaconNodeRole.SyncCommitteeData},
                                      getBlockRoot(it, blockIdent)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 404:
          debug ResponseNotFoundError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data.data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestResponse[GetBlockRootResponse], SlotDuration,
                              {BeaconNodeRole.SyncCommitteeData},
                              getBlockRoot(it, blockIdent)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 404:
          debug ResponseNotFoundError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    raise newException(ValidatorApiError, ErrorMessage)

proc getValidators*(
       vc: ValidatorClientRef,
       id: seq[ValidatorIdent],
       strategy: ApiStrategyKind
     ): Future[seq[RestValidator]] {.async.} =
  logScope:
    request = "getStateValidators"
    strategy = $strategy

  let stateIdent = StateIdent.init(StateIdentType.Head)

  const ErrorMessage = "Unable to retrieve head state's validator information"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestResponse[GetStateValidatorsResponse],
                                      SlotDuration, {BeaconNodeRole.Duties},
                                      getStateValidators(it, stateIdent, id)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 404:
          debug ResponseNotFoundError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data.data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestResponse[GetStateValidatorsResponse],
                              SlotDuration, {BeaconNodeRole.Duties},
                              getStateValidators(it, stateIdent, id)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data.data
        of 400:
          debug ResponseInvalidError,
                response_code = response.status, endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 404:
          debug ResponseNotFoundError,
                response_code = response.status, endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError,
                response_code = response.status, endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError,
                response_code = response.status, endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc produceAttestationData*(
       vc: ValidatorClientRef,
       slot: Slot,
       committee_index: CommitteeIndex,
       strategy: ApiStrategyKind
     ): Future[AttestationData] {.async.} =
  logScope:
    request = "produceAttestationData"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve attestation data"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestResponse[ProduceAttestationDataResponse],
      OneThirdDuration, {BeaconNodeRole.AttestationData},
      produceAttestationData(it, slot, committee_index)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data.data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestResponse[ProduceAttestationDataResponse],
      OneThirdDuration, {BeaconNodeRole.AttestationData},
      produceAttestationData(it, slot, committee_index)):

      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc submitPoolAttestations*(
       vc: ValidatorClientRef,
       data: seq[Attestation],
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  logScope:
    request = "submitPoolAttestations"
    strategy = $strategy

  const
    ErrorMessage = "Unable to submit attestation"
    NoErrorMessage = "Attestation was sucessfully published"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse, SlotDuration,
                                      {BeaconNodeRole.AttestationPublish},
                                      submitPoolAttestations(it, data)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace NoErrorMessage, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return true

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.AttestationPublish},
                              submitPoolAttestations(it, data)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace NoErrorMessage, endpoint = node
          return true
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc submitPoolSyncCommitteeSignature*(
       vc: ValidatorClientRef,
       data: SyncCommitteeMessage,
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  logScope:
    request = "submitPoolSyncCommitteeSignatures"
    strategy = $strategy

  let restData = RestSyncCommitteeMessage.init(
    data.slot,
    data.beacon_block_root,
    data.validator_index,
    data.signature
  )

  const
    ErrorMessage = "Unable to submit sync committee message"
    NoErrorMessage = "Sync committee message was successfully published"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res =  vc.firstSuccessParallel(
      RestPlainResponse, SlotDuration, {BeaconNodeRole.SyncCommitteePublish},
      submitPoolSyncCommitteeSignatures(it, @[restData])):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace NoErrorMessage, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return true

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse, SlotDuration, {BeaconNodeRole.SyncCommitteePublish},
      submitPoolSyncCommitteeSignatures(it, @[restData])):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          trace NoErrorMessage, endpoint = node
          return true
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node, response_error = response.getIndexedErrorMessage()
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc getAggregatedAttestation*(
       vc: ValidatorClientRef,
       slot: Slot,
       root: Eth2Digest,
       strategy: ApiStrategyKind
     ): Future[Attestation] {.async.} =
  logScope:
    request = "getAggregatedAttestation"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve aggregated attestation data"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestResponse[GetAggregatedAttestationResponse],
      OneThirdDuration, {BeaconNodeRole.AggregatedData},
      getAggregatedAttestation(it, root, slot)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data.data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestResponse[GetAggregatedAttestationResponse],
      OneThirdDuration, {BeaconNodeRole.AggregatedData},
      getAggregatedAttestation(it, root, slot)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc produceSyncCommitteeContribution*(
       vc: ValidatorClientRef,
       slot: Slot,
       subcommitteeIndex: SyncSubcommitteeIndex,
       root: Eth2Digest,
       strategy: ApiStrategyKind
     ): Future[SyncCommitteeContribution] {.async.} =
  logScope:
    request = "produceSyncCommitteeContribution"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve sync committee contribution data"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestResponse[ProduceSyncCommitteeContributionResponse], OneThirdDuration,
      {BeaconNodeRole.SyncCommitteeData},
      produceSyncCommitteeContribution(it, slot, subcommitteeIndex, root)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data.data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestResponse[ProduceSyncCommitteeContributionResponse], OneThirdDuration,
      {BeaconNodeRole.SyncCommitteeData},
      produceSyncCommitteeContribution(it, slot, subcommitteeIndex, root)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc publishAggregateAndProofs*(
       vc: ValidatorClientRef,
       data: seq[SignedAggregateAndProof],
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  logScope:
    request = "publishAggregateAndProofs"
    strategy = $strategy

  const
    ErrorMessage = "Unable to publish aggregate and proofs"
    NoErrorMessage = "Aggregate and proofs was sucessfully published"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse, SlotDuration,
                                      {BeaconNodeRole.AggregatedPublish},
                                      publishAggregateAndProofs(it, data)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace NoErrorMessage, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return true

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.AggregatedPublish},
                              publishAggregateAndProofs(it, data)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace NoErrorMessage, endpoint = node
          return true
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc publishContributionAndProofs*(
       vc: ValidatorClientRef,
       data: seq[RestSignedContributionAndProof],
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  logScope:
    request = "publishContributionAndProofs"
    strategy = $strategy

  const
    ErrorMessage = "Unable to publish contribution and proofs"
    NoErrorMessage = "Contribution and proofs were successfully published"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse, SlotDuration,
                                      {BeaconNodeRole.SyncCommitteePublish},
                                      publishContributionAndProofs(it, data)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace NoErrorMessage, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline

    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return true

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.SyncCommitteePublish},
                              publishContributionAndProofs(it, data)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace NoErrorMessage, endpoint = node
          return true
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
    raise newException(ValidatorApiError, ErrorMessage)

proc produceBlockV2*(
       vc: ValidatorClientRef,
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       strategy: ApiStrategyKind
     ): Future[ProduceBlockResponseV2] {.async.} =
  logScope:
    request = "produceBlockV2"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve block data"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestResponse[ProduceBlockResponseV2],
      SlotDuration, {BeaconNodeRole.BlockProposalData},
      produceBlockV2(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestResponse[ProduceBlockResponseV2],
      SlotDuration, {BeaconNodeRole.BlockProposalData},
      produceBlockV2(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc publishBlock*(
       vc: ValidatorClientRef,
       data: ForkedSignedBeaconBlock,
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  logScope:
    request = "publishBlock"
    strategy = $strategy

  const
    BlockPublished = "Block was successfully published"
    BlockBroadcasted = "Block not passed validation, but still published"
    ErrorMessage = "Unable to publish block"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = block:
      vc.firstSuccessParallel(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.BlockProposalPublish}):
        case data.kind
        of BeaconBlockFork.Phase0:
          publishBlock(it, data.phase0Data)
        of BeaconBlockFork.Altair:
          publishBlock(it, data.altairData)
        of BeaconBlockFork.Bellatrix:
          publishBlock(it, data.bellatrixData)
        of BeaconBlockFork.Capella:
          publishBlock(it, data.capellaData)
      do:
        if apiResponse.isErr():
          debug ErrorMessage, endpoint = node, error = apiResponse.error()
          RestBeaconNodeStatus.Offline
        else:
          let response = apiResponse.get()
          case response.status:
          of 200:
            trace BlockPublished, endpoint = node
            RestBeaconNodeStatus.Online
          of 202:
            debug BlockBroadcasted, endpoint = node
            RestBeaconNodeStatus.Online
          of 400:
            debug ResponseInvalidError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.Incompatible
          of 500:
            debug ResponseInternalError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.Offline
          of 503:
            debug ResponseNoSyncError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.NotSynced
          else:
            debug ResponseUnexpectedError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return true

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.BlockProposalPublish}):
      case data.kind
      of BeaconBlockFork.Phase0:
        publishBlock(it, data.phase0Data)
      of BeaconBlockFork.Altair:
        publishBlock(it, data.altairData)
      of BeaconBlockFork.Bellatrix:
        publishBlock(it, data.bellatrixData)
      of BeaconBlockFork.Capella:
        publishBlock(it, data.capellaData)
    do:
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace BlockPublished, endpoint = node
          return true
        of 202:
          debug BlockBroadcasted, endpoint = node
          return true
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc produceBlindedBlock*(
       vc: ValidatorClientRef,
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       strategy: ApiStrategyKind
     ): Future[ProduceBlindedBlockResponse] {.async.} =
  logScope:
    request = "produceBlindedBlock"
    strategy = $strategy

  const ErrorMessage = "Unable to retrieve block data"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestResponse[ProduceBlindedBlockResponse],
      SlotDuration, {BeaconNodeRole.BlockProposalData},
      produceBlindedBlock(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          RestBeaconNodeStatus.Online
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestResponse[ProduceBlindedBlockResponse],
      SlotDuration, {BeaconNodeRole.BlockProposalData},
      produceBlindedBlock(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace ResponseSuccess, endpoint = node
          return response.data
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc publishBlindedBlock*(
       vc: ValidatorClientRef,
       data: ForkedSignedBlindedBeaconBlock,
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  logScope:
    request = "publishBlindedBlock"
    strategy = $strategy

  const
    BlockPublished = "Block was successfully published"
    BlockBroadcasted = "Block not passed validation, but still published"
    ErrorMessage = "Unable to publish block"

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = block:
      vc.firstSuccessParallel(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.BlockProposalPublish}):
        case data.kind
        of BeaconBlockFork.Phase0:
          publishBlindedBlock(it, data.phase0Data)
        of BeaconBlockFork.Altair:
          publishBlindedBlock(it, data.altairData)
        of BeaconBlockFork.Bellatrix:
          publishBlindedBlock(it, data.bellatrixData)
        of BeaconBlockFork.Capella:
          publishBlindedBlock(it, data.capellaData)
      do:
        if apiResponse.isErr():
          debug ErrorMessage, endpoint = node, error = apiResponse.error()
          RestBeaconNodeStatus.Offline
        else:
          let response = apiResponse.get()
          case response.status:
          of 200:
            trace BlockPublished, endpoint = node
            RestBeaconNodeStatus.Online
          of 202:
            debug BlockBroadcasted, endpoint = node
            RestBeaconNodeStatus.Online
          of 400:
            debug ResponseInvalidError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.Incompatible
          of 500:
            debug ResponseInternalError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.Offline
          of 503:
            debug ResponseNoSyncError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.NotSynced
          else:
            debug ResponseUnexpectedError, response_code = response.status,
                  endpoint = node,
                  response_error = response.getErrorMessage()
            RestBeaconNodeStatus.Offline
    if res.isErr():
      raise newException(ValidatorApiError, res.error())
    return true

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                              {BeaconNodeRole.BlockProposalPublish}):
      case data.kind
      of BeaconBlockFork.Phase0:
        publishBlindedBlock(it, data.phase0Data)
      of BeaconBlockFork.Altair:
        publishBlindedBlock(it, data.altairData)
      of BeaconBlockFork.Bellatrix:
        publishBlindedBlock(it, data.bellatrixData)
      of BeaconBlockFork.Capella:
        publishBlindedBlock(it, data.capellaData)
    do:
      if apiResponse.isErr():
        debug ErrorMessage, endpoint = node, error = apiResponse.error()
        RestBeaconNodeStatus.Offline
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          trace BlockPublished, endpoint = node
          return true
        of 202:
          debug BlockBroadcasted, endpoint = node
          return true
        of 400:
          debug ResponseInvalidError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Incompatible
        of 500:
          debug ResponseInternalError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline
        of 503:
          debug ResponseNoSyncError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.NotSynced
        else:
          debug ResponseUnexpectedError, response_code = response.status,
                endpoint = node,
                response_error = response.getErrorMessage()
          RestBeaconNodeStatus.Offline

    raise newException(ValidatorApiError, ErrorMessage)

proc prepareBeaconCommitteeSubnet*(
       vc: ValidatorClientRef,
       data: seq[RestCommitteeSubscription],
     ): Future[int] {.async.} =
  logScope: request = "prepareBeaconCommitteeSubnet"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
                          {BeaconNodeRole.AggregatedData},
                          prepareBeaconCommitteeSubnet(it, data))
  if len(resp.data) == 0:
    # We did not get any response from beacon nodes.
    case resp.status
    of ApiOperation.Success:
      # This should not be happened, there should be present at least one
      # successfull response.
      return 0
    of ApiOperation.Timeout:
      debug "Unable to subscribe to beacon committee subnets in time",
            timeout = SlotDuration
      return 0
    of ApiOperation.Interrupt:
      debug "Beacon committee subscription request was interrupted"
      return 0
    of ApiOperation.Failure:
      debug "Unexpected error happened while subscribing to beacon committee " &
            "subnets"
      return 0
  else:
    var count = 0
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to subscribe to beacon committee subnets",
              endpoint = apiResponse.node, error = apiResponse.data.error()
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Subscription to beacon commitee subnets failed",
                 status = response.status, endpoint = apiResponse.node,
                 message = response.getErrorMessage()
    return count

proc prepareSyncCommitteeSubnets*(
       vc: ValidatorClientRef,
       data: seq[RestSyncCommitteeSubscription],
     ): Future[int] {.async.} =
  logScope: request = "prepareSyncCommitteeSubnet"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
                          {BeaconNodeRole.SyncCommitteeData},
                          prepareSyncCommitteeSubnets(it, data))
  if len(resp.data) == 0:
    # We did not get any response from beacon nodes.
    case resp.status
    of ApiOperation.Success:
      # This should not be happened, there should be present at least one
      # successfull response.
      return 0
    of ApiOperation.Timeout:
      debug "Unable to prepare sync committee subnets in time",
            timeout = SlotDuration
      return 0
    of ApiOperation.Interrupt:
      debug "Sync committee subnets preparation request was interrupted"
      return 0
    of ApiOperation.Failure:
      debug "Unexpected error happened while preparing sync committee subnets"
      return 0
  else:
    var count = 0
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to prepare sync committee subnets",
              endpoint = apiResponse.node, error = apiResponse.data.error()
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Sync committee subnets preparation failed",
                 status = response.status, endpoint = apiResponse.node,
                 message = response.getErrorMessage()
    return count

proc getValidatorsActivity*(
       vc: ValidatorClientRef, epoch: Epoch,
       validators: seq[ValidatorIndex]
     ): Future[GetValidatorsActivityResponse] {.async.} =
  logScope: request = "getValidatorsActivity"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
                          {BeaconNodeRole.Duties},
                          getValidatorsActivity(it, epoch, validators))
  case resp.status
  of ApiOperation.Timeout:
    debug "Unable to perform validator's activity request in time",
          timeout = SlotDuration
    return GetValidatorsActivityResponse()
  of ApiOperation.Interrupt:
    debug "Validator's activity request was interrupted"
    return GetValidatorsActivityResponse()
  of ApiOperation.Failure:
    debug "Unexpected error happened while receiving validator's activity"
    return GetValidatorsActivityResponse()
  of ApiOperation.Success:
    var activities: seq[RestActivityItem]
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to retrieve validators activity data",
              endpoint = apiResponse.node, error = apiResponse.data.error()
      else:
        let
          response = apiResponse.data.get()
          activity =
            block:
              var default: seq[RestActivityItem]
              case response.status
              of 200:
                let res = decodeBytes(GetValidatorsActivityResponse,
                                      response.data, response.contentType)
                if res.isOk():
                  let list = res.get().data
                  if len(list) != len(validators):
                    debug "Received incomplete validators activity response",
                          endpoint = apiResponse.node,
                          validators_count = len(validators),
                          activities_count = len(list)
                    default
                  else:
                    let isOrdered =
                      block:
                        var res = true
                        for index in 0 ..< len(validators):
                          if list[index].index != validators[index]:
                            res = false
                            break
                        res
                    if not(isOrdered):
                      debug "Received unordered validators activity response",
                          endpoint = apiResponse.node,
                          validators_count = len(validators),
                          activities_count = len(list)
                      default
                    else:
                      debug "Received validators activity response",
                            endpoint = apiResponse.node,
                            validators_count = len(validators),
                            activities_count = len(list)
                      list
                else:
                  debug "Received invalid/incomplete response",
                        endpoint = apiResponse.node, error_message = res.error()
                  apiResponse.node.status = RestBeaconNodeStatus.Incompatible
                  default
              of 400:
                debug "Server reports invalid request",
                      response_code = response.status,
                      endpoint = apiResponse.node,
                      response_error = response.getErrorMessage()
                apiResponse.node.status = RestBeaconNodeStatus.Incompatible
                default
              of 500:
                debug "Server reports internal error",
                      response_code = response.status,
                      endpoint = apiResponse.node,
                      response_error = response.getErrorMessage()
                apiResponse.node.status = RestBeaconNodeStatus.Offline
                default
              else:
                debug "Server reports unexpected error code",
                      response_code = response.status,
                      endpoint = apiResponse.node,
                      response_error = response.getErrorMessage()
                apiResponse.node.status = RestBeaconNodeStatus.Offline
                default

        if len(activity) > 0:
          if len(activities) == 0:
            activities = activity
          else:
            # If single node returns `active` it means that validator's
            # activity was seen by this node, so result would be `active`.
            for index in 0 ..< len(activities):
              if activity[index].active:
                activities[index].active = true
    return GetValidatorsActivityResponse(data: activities)

proc prepareBeaconProposer*(
       vc: ValidatorClientRef,
       data: seq[PrepareBeaconProposer]
     ): Future[int] {.async.} =
  logScope: request = "prepareBeaconProposer"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
                          {BeaconNodeRole.BlockProposalPublish},
                          prepareBeaconProposer(it, data))
  if len(resp.data) == 0:
    # We did not get any response from beacon nodes.
    case resp.status
    of ApiOperation.Success:
      # This should not be happened, there should be present at least one
      # successfull response.
      return 0
    of ApiOperation.Timeout:
      debug "Unable to perform beacon proposer preparation request in time",
            timeout = SlotDuration
      return 0
    of ApiOperation.Interrupt:
      debug "Beacon proposer's preparation request was interrupted"
      return 0
    of ApiOperation.Failure:
      debug "Unexpected error happened while preparing beacon proposers"
      return 0
  else:
    var count = 0
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to perform beacon proposer preparation request",
              endpoint = apiResponse.node, error = apiResponse.data.error()
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Beacon proposer preparation failed", status = response.status,
                endpoint = apiResponse.node,
                message = response.getErrorMessage()
    return count

proc registerValidator*(
       vc: ValidatorClientRef,
       data: seq[SignedValidatorRegistrationV1]
     ): Future[int] {.async.} =
  logScope: request = "registerValidators"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
                          {BeaconNodeRole.BlockProposalPublish},
                          registerValidator(it, data))
  if len(resp.data) == 0:
    # We did not get any response from beacon nodes.
    case resp.status
    of ApiOperation.Success:
      # This should not be happened, there should be present at least one
      # successfull response.
      return 0
    of ApiOperation.Timeout:
      debug "Unable to register validators in time",
            timeout = SlotDuration
      return 0
    of ApiOperation.Interrupt:
      debug "Validator registration was interrupted"
      return 00
    of ApiOperation.Failure:
      debug "Unexpected error happened while registering validators"
      return 0
  else:
    var count = 0
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to register validator with beacon node",
              endpoint = apiResponse.node, error = apiResponse.data.error()
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Unable to register validators with beacon node",
                status = response.status, endpoint = apiResponse.node,
                message = response.getErrorMessage()
    return count

proc getValidatorsLiveness*(
       vc: ValidatorClientRef, epoch: Epoch,
       validators: seq[ValidatorIndex]
     ): Future[GetValidatorsLivenessResponse] {.async.} =
  logScope: request = "getValidatorsActivity"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
                          {BeaconNodeRole.Duties},
                          getValidatorsLiveness(it, epoch, validators))
  case resp.status
  of ApiOperation.Timeout:
    debug "Unable to perform validator's liveness request in time",
          timeout = SlotDuration
    return GetValidatorsLivenessResponse()
  of ApiOperation.Interrupt:
    debug "Validator's liveness request was interrupted"
    return GetValidatorsLivenessResponse()
  of ApiOperation.Failure:
    debug "Unexpected error happened while receiving validator's liveness"
    return GetValidatorsLivenessResponse()
  of ApiOperation.Success:
    let defaultLiveness = RestLivenessItem(index: ValidatorIndex(high(uint32)))
    var activities: Table[ValidatorIndex, RestLivenessItem]
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to retrieve validators liveness data",
              endpoint = apiResponse.node, error = apiResponse.data.error()
      else:
        let response = apiResponse.data.get()
        case response.status
        of 200:
          let res = decodeBytes(GetValidatorsLivenessResponse,
                                response.data, response.contentType)
          if res.isOk():
            let list = res.get().data
            if len(list) != len(validators):
              debug "Received incomplete validators liveness response",
                    endpoint = apiResponse.node,
                    validators_count = len(validators),
                    activities_count = len(list)
              continue
            else:
              var updated = 0
              for item in list:
                activities.withValue(item.index, stored):
                  if item.is_live:
                    stored[].is_live = true
                    inc(updated)
                do:
                  activities[item.index] = item
                  inc(updated)
              debug "Received validators liveness response",
                    endpoint = apiResponse.node,
                    validators_count = len(validators),
                    activities_count = len(list),
                    updated_count = updated
          else:
            debug "Received invalid/incomplete response",
                  endpoint = apiResponse.node, error_message = res.error()
            apiResponse.node.status = RestBeaconNodeStatus.Incompatible
            continue
        of 400:
          debug "Server reports invalid request",
                response_code = response.status,
                endpoint = apiResponse.node,
                response_error = response.getErrorMessage()
          apiResponse.node.status = RestBeaconNodeStatus.Incompatible
          continue
        of 500:
          debug "Server reports internal error",
                response_code = response.status,
                endpoint = apiResponse.node,
                response_error = response.getErrorMessage()
          apiResponse.node.status = RestBeaconNodeStatus.Offline
          continue
        of 503:
          debug "Server reports that it not in sync",
                response_code = response.status,
                endpoint = apiResponse.node,
                response_error = response.getErrorMessage()
          apiResponse.node.status = RestBeaconNodeStatus.NotSynced
          continue
        else:
          debug "Server reports unexpected error code",
                response_code = response.status,
                endpoint = apiResponse.node,
                response_error = response.getErrorMessage()
          apiResponse.node.status = RestBeaconNodeStatus.Offline
          continue

    var response =
      block:
        var res: seq[RestLivenessItem]
        for vindex in validators:
          let item = activities.getOrDefault(vindex, defaultLiveness)
          if item == defaultLiveness:
            debug "Validator is missing in response",
                  validator_index = vindex
            return GetValidatorsLivenessResponse()
          else:
            res.add(item)
        res

    return GetValidatorsLivenessResponse(data: response)

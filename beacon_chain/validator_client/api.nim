# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
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
  ResponseDecodeError = "Received response could not be decoded"
  ResponseECNotInSyncError* = "Execution client not in sync"

type
  ApiResponse*[T] = Result[T, string]
  ApiOperation = enum
    Success, Timeout, Failure, Interrupt

  ApiNodeResponse*[T] = object
    node*: BeaconNodeServerRef
    data*: ApiResponse[T]

  ApiResponseSeq*[T] = object
    status*: ApiOperation
    data*: seq[ApiNodeResponse[T]]

const
  ViableNodeStatus = {RestBeaconNodeStatus.Compatible,
                      RestBeaconNodeStatus.NotSynced,
                      RestBeaconNodeStatus.OptSynced,
                      RestBeaconNodeStatus.Synced}

proc `$`*(strategy: ApiStrategyKind): string =
  case strategy
  of ApiStrategyKind.First:
    "first"
  of ApiStrategyKind.Best:
    "best"
  of ApiStrategyKind.Priority:
    "priority"

proc lazyWaiter(node: BeaconNodeServerRef, request: FutureBase,
                requestName: string, strategy: ApiStrategyKind) {.async.} =
  try:
    await allFutures(request)
    if request.failed():
      let failure = ApiNodeFailure.init(
        ApiFailure.Communication, requestName, strategy, node,
        $request.error.msg)
      node.updateStatus(RestBeaconNodeStatus.Offline, failure)
  except CancelledError as exc:
    await cancelAndWait(request)

proc lazyWait(nodes: seq[BeaconNodeServerRef], requests: seq[FutureBase],
              timerFut: Future[void], requestName: string,
              strategy: ApiStrategyKind) {.async.} =
  doAssert(len(nodes) == len(requests))
  if len(nodes) == 0:
    return

  var futures: seq[Future[void]]
  for index in 0 ..< len(requests):
    futures.add(lazyWaiter(nodes[index], requests[index], requestName,
                           strategy))

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
           handlerType: typedesc,
           timeout: Duration,
           statuses: set[RestBeaconNodeStatus],
           roles: set[BeaconNodeRole],
           body1, body2: untyped
         ): ApiResponse[handlerType] =
  var
    it {.inject.}: RestClientRef
    iterations = 0

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  var retRes: ApiResponse[handlerType]
  while true:
    var resultReady = false
    let onlineNodes =
      try:
        if iterations == 0:
          # We are not going to wait for BNs if there some available.
          await vc.waitNodes(timerFut, statuses, roles, false)
        else:
          # We get here only, if all the requests are failed. To avoid requests
          # spam we going to wait for changes in BNs statuses.
          await vc.waitNodes(timerFut, statuses, roles, true)
        vc.filterNodes(statuses, roles)
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
      retRes = ApiResponse[handlerType].err("No online beacon node(s)")
      resultReady = true
    else:
      var
        (pendingRequests, pendingNodes) =
          block:
            var requests: seq[FutureBase]
            var nodes: seq[BeaconNodeServerRef]
            for node {.inject.} in onlineNodes:
              it = node.client
              let fut = FutureBase(body1)
              requests.add(fut)
              nodes.add(node)
            (requests, nodes)
        raceFut: Future[FutureBase]
        requestsCancelled = false

      while true:
        try:
          if len(pendingRequests) == 0:
            if not(isNil(timerFut)) and not(timerFut.finished()):
              await timerFut.cancelAndWait()
            retRes = ApiResponse[handlerType].err(
              "Beacon node(s) unable to satisfy request")
            resultReady = true
            break
          else:
            raceFut = race(pendingRequests)

            if isNil(timerFut):
              await raceFut or timerFut
            else:
              await allFutures(raceFut)

            let
              index =
                if not(isNil(timerFut)) and timerFut.finished():
                  # Timeout exceeded first.
                  if not(requestsCancelled):
                    var pending: seq[Future[void]]
                    pending.add(raceFut.cancelAndWait())
                    for future in pendingRequests.items():
                      if not(future.finished()):
                        pending.add(future.cancelAndWait())
                    await allFutures(pending)
                    requestsCancelled = true
                  0
                else:
                  let res = pendingRequests.find(raceFut.read())
                  doAssert(res >= 0)
                  res
              requestFut = pendingRequests[index]
              beaconNode = pendingNodes[index]

            # Remove completed future from pending list.
            pendingRequests.del(index)
            pendingNodes.del(index)

            let
              node {.inject.} = beaconNode
              apiResponse {.inject.} =
                if timerFut.finished():
                  ApiResponse[responseType].err(
                    "Timeout exceeded while awaiting for the response")
                else:
                  if requestFut.failed():
                    ApiResponse[responseType].err($requestFut.error.msg)
                  else:
                    ApiResponse[responseType].ok(
                      Future[responseType](requestFut).read())
              handlerResponse =
                try:
                  body2
                except CancelledError as exc:
                  raise exc
                except CatchableError:
                  raiseAssert("Response handler must not raise exceptions")

            if apiResponse.isOk() and handlerResponse.isOk():
              retRes = handlerResponse
              resultReady = true
              asyncSpawn lazyWait(pendingNodes, pendingRequests, timerFut,
                                  RequestName, strategy)
              break

        except CancelledError as exc:
          var pendingCancel: seq[Future[void]]
          if not(isNil(raceFut)) and not(raceFut.finished()):
            pendingCancel.add(raceFut.cancelAndWait())
          if not(isNil(timerFut)) and not(timerFut.finished()):
            pendingCancel.add(timerFut.cancelAndWait())
          for index, future in pendingRequests.pairs():
            if not(future.finished()):
              pendingCancel.add(future.cancelAndWait())
          await allFutures(pendingCancel)
          raise exc
        except CatchableError as exc:
          # This should not be happened, because allFutures() and race() did not
          # raise any exceptions.
          error "Unexpected exception while processing request",
                err_name = $exc.name, err_msg = $exc.msg
          retRes = ApiResponse[handlerType].err("Unexpected error")
          resultReady = true
        if resultReady:
          break
    if resultReady:
      break

    inc(iterations)
  retRes

template bestSuccess*(
           vc: ValidatorClientRef,
           responseType: typedesc,
           timeout: Duration,
           statuses: set[RestBeaconNodeStatus],
           roles: set[BeaconNodeRole],
           bodyRequest,
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
      await vc.waitNodes(timerFut, statuses, roles, false)
      vc.filterNodes(statuses, roles)
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
    ApiResponse[responseType].err("No online beacon node(s)")
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
                beaconNode.status.updateStatus(RestBeaconNodeStatus.Offline)
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

template onceToAll*(
           vc: ValidatorClientRef,
           responseType: typedesc,
           timeout: Duration,
           statuses: set[RestBeaconNodeStatus],
           roles: set[BeaconNodeRole],
           body: untyped
         ): ApiResponseSeq[responseType] =
  var it {.inject.}: RestClientRef
  type BodyType = typeof(body)

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  let onlineNodes =
    try:
      await vc.waitNodes(timerFut, statuses, roles, false)
      vc.filterNodes(statuses, roles)
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

template firstSuccessSequential*(
           vc: ValidatorClientRef,
           responseType: typedesc,
           timeout: Duration,
           statuses: set[RestBeaconNodeStatus],
           roles: set[BeaconNodeRole],
           body: untyped,
           handlers: untyped
         ): untyped =
  doAssert(timeout != ZeroDuration)
  var
    it {.inject.}: RestClientRef
    iterations = 0

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  while true:
    let onlineNodes =
      try:
        if iterations == 0:
          # We are not going to wait for BNs if there some available.
          await vc.waitNodes(timerFut, statuses, roles, false)
        else:
          # We get here only, if all the requests are failed. To avoid requests
          # spam we going to wait for changes in BNs statuses.
          await vc.waitNodes(timerFut, statuses, roles, true)
        vc.filterNodes(statuses, roles)
      except CancelledError as exc:
        # waitNodes do not cancel `timoutFuture`.
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

    if iterations != 0:
      debug "Request got failed", iterations_count = iterations

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

      var handlerStatus = false
      block:
        let apiResponse {.inject.} =
          block:
            if bodyFut.finished():
              if bodyFut.failed() or bodyFut.cancelled():
                let exc = bodyFut.readError()
                ApiResponse[responseType].err("[" & $exc.name & "] " & $exc.msg)
              else:
                ApiResponse[responseType].ok(bodyFut.read())
            else:
              case resOp
              of ApiOperation.Interrupt:
                ApiResponse[responseType].err("Operation was interrupted")
              of ApiOperation.Timeout:
                ApiResponse[responseType].err("Operation timeout exceeded")
              of ApiOperation.Success, ApiOperation.Failure:
                # This should not be happened, because all Futures should be
                # finished, and `Failure` processed when Future is finished.
                ApiResponse[responseType].err("Unexpected error")

        handlerStatus =
          try:
            handlers
          except CatchableError:
            raiseAssert("Response handler must not raise exceptions")

      if resOp == ApiOperation.Success:
        if handlerStatus:
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
    "Unable to decode error response: [" & $res.error & "]"

proc getErrorMessage*(response: RestPlainResponse): string =
  let res = decodeBytes(RestErrorMessage, response.data,
                        response.contentType)
  if res.isOk():
    let errorObj = res.get()
    if errorObj.stacktraces.isSome():
      errorObj.message & ": [" & errorObj.stacktraces.get().join("; ") & "]"
    else:
      errorObj.message
  else:
    "Unable to decode error response: [" & $res.error & "]"

template handleCommunicationError(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.Communication, RequestName,
    strategy, node, apiResponse.error)
  node.updateStatus(RestBeaconNodeStatus.Offline, failure)
  failures.add(failure)

template handleUnexpectedCode(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.UnexpectedCode, RequestName,
    strategy, node, response.status, response.getErrorMessage())
  node.updateStatus(RestBeaconNodeStatus.UnexpectedCode, failure)
  failures.add(failure)

template handleUnexpectedData(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.UnexpectedResponse, RequestName,
    strategy, node, response.status, $res.error)
  node.updateStatus(RestBeaconNodeStatus.UnexpectedResponse, failure)
  failures.add(failure)

template handleOptimistic(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.OptSynced, RequestName,
    strategy, node, response.status,
    "Response was sent by optimistically synced node")
  node.updateStatus(RestBeaconNodeStatus.OptSynced, failure)

template handle400(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.Invalid, RequestName,
    strategy, node, response.status, response.getErrorMessage())
  node.updateStatus(RestBeaconNodeStatus.Incompatible, failure)
  failures.add(failure)

template handle404(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.NotFound, RequestName,
    strategy, node, response.status, response.getErrorMessage())
  node.updateStatus(RestBeaconNodeStatus.Incompatible, failure)
  failures.add(failure)

template handle500(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.Internal, RequestName,
    strategy, node, response.status, response.getErrorMessage())
  node.updateStatus(RestBeaconNodeStatus.InternalError, failure)
  failures.add(failure)

template handle503(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.NotSynced, RequestName,
    strategy, node, response.status, response.getErrorMessage())
  node.updateStatus(RestBeaconNodeStatus.NotSynced, failure)
  failures.add(failure)

proc getProposerDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       strategy: ApiStrategyKind
     ): Future[GetProposerDutiesResponse] {.async.} =
  const RequestName = "getProposerDuties"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      GetProposerDutiesResponse,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.Duties},
                                      getProposerDutiesPlain(it, epoch)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetProposerDutiesResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetProposerDutiesResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetProposerDutiesResponse].err($res.error)
          else:
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            ApiResponse[GetProposerDutiesResponse].ok(data)
        of 400:
          handle400()
          ApiResponse[GetProposerDutiesResponse].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[GetProposerDutiesResponse].err(ResponseInternalError)
        of 503:
          handle503()
          ApiResponse[GetProposerDutiesResponse].err(ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetProposerDutiesResponse].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.Duties},
                              getProposerDutiesPlain(it, epoch)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetProposerDutiesResponse, response.data,
                                response.contentType)
          if res.isOk():
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            return data
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get proposer duties", data: failures)

proc getAttesterDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       validators: seq[ValidatorIndex],
       strategy: ApiStrategyKind
     ): Future[GetAttesterDutiesResponse] {.async.} =
  const RequestName = "getAttesterDuties"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      GetAttesterDutiesResponse,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.Duties},
                                      getAttesterDutiesPlain(it, epoch,
                                                             validators)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetAttesterDutiesResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetAttesterDutiesResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetAttesterDutiesResponse].err($res.error)
          else:
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            ApiResponse[GetAttesterDutiesResponse].ok(data)
        of 400:
          handle400()
          ApiResponse[GetAttesterDutiesResponse].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[GetAttesterDutiesResponse].err(ResponseInternalError)
        of 503:
          handle503()
          ApiResponse[GetAttesterDutiesResponse].err(ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetAttesterDutiesResponse].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.Duties},
                              getAttesterDutiesPlain(it, epoch, validators)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetAttesterDutiesResponse, response.data,
                                response.contentType)
          if res.isOk():
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            return data
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get attester duties", data: failures)

proc getSyncCommitteeDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       validators: seq[ValidatorIndex],
       strategy: ApiStrategyKind
     ): Future[GetSyncCommitteeDutiesResponse] {.async.} =
  const RequestName = "getSyncCommitteeDuties"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      GetSyncCommitteeDutiesResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.Duties},
      getSyncCommitteeDutiesPlain(it, epoch, validators)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetSyncCommitteeDutiesResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetSyncCommitteeDutiesResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetSyncCommitteeDutiesResponse].err($res.error)
          else:
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            ApiResponse[GetSyncCommitteeDutiesResponse].ok(data)
        of 400:
          handle400()
          ApiResponse[GetSyncCommitteeDutiesResponse].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[GetSyncCommitteeDutiesResponse].err(ResponseInternalError)
        of 503:
          handle503()
          ApiResponse[GetSyncCommitteeDutiesResponse].err(ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetSyncCommitteeDutiesResponse].err(
            ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.Duties},
      getSyncCommitteeDutiesPlain(it, epoch, validators)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetSyncCommitteeDutiesResponse, response.data,
                                response.contentType)
          if res.isOk():
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            return data
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get sync committee duties", data: failures)

proc getForkSchedule*(
       vc: ValidatorClientRef,
       strategy: ApiStrategyKind
     ): Future[seq[Fork]] {.async.} =
  const RequestName = "getForkSchedule"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      GetForkScheduleResponse,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.Duties},
                                      getForkSchedulePlain(it)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetForkScheduleResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetForkScheduleResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetForkScheduleResponse].err($res.error)
          else:
            ApiResponse[GetForkScheduleResponse].ok(res.get())
        of 500:
          handle500()
          ApiResponse[GetForkScheduleResponse].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetForkScheduleResponse].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.Duties},
                              getForkSchedulePlain(it)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetForkScheduleResponse, response.data,
                                response.contentType)
          if res.isOk(): return res.get().data

          handleUnexpectedData()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get fork schedule", data: failures)

proc getHeadBlockRoot*(
       vc: ValidatorClientRef,
       strategy: ApiStrategyKind
     ): Future[DataOptimisticObject[RestRoot]] {.async.} =
  const RequestName = "getHeadBlockRoot"

  var failures: seq[ApiNodeFailure]

  let blockIdent = BlockIdent.init(BlockIdentType.Head)

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      GetBlockRootResponse,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.SyncCommitteeData},
                                      getBlockRootPlain(it, blockIdent)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetBlockRootResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetBlockRootResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetBlockRootResponse].err($res.error)
          else:
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
              failures.add(failure)
              ApiResponse[GetBlockRootResponse].err(ResponseECNotInSyncError)
            else:
              ApiResponse[GetBlockRootResponse].ok(data)
        of 400:
          handle400()
          ApiResponse[GetBlockRootResponse].err(ResponseInvalidError)
        of 404:
          handle404()
          ApiResponse[GetBlockRootResponse].err(ResponseNotFoundError)
        of 500:
          handle500()
          ApiResponse[GetBlockRootResponse].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetBlockRootResponse].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse, #RestResponse[GetBlockRootResponse],
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.SyncCommitteeData},
                              getBlockRootPlain(it, blockIdent)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetBlockRootResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            false
          else:
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
              failures.add(failure)
              false
            else:
              return data
        of 400:
          handle400()
          false
        of 404:
          handle404()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get head block root", data: failures)

proc getValidators*(
       vc: ValidatorClientRef,
       id: seq[ValidatorIdent],
       strategy: ApiStrategyKind
     ): Future[seq[RestValidator]] {.async.} =
  const RequestName = "getStateValidators"

  let stateIdent = StateIdent.init(StateIdentType.Head)

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      GetStateValidatorsResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.Duties},
      getStateValidatorsPlain(it, stateIdent, id)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetStateValidatorsResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetStateValidatorsResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetStateValidatorsResponse].err($res.error)
          else:
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            ApiResponse[GetStateValidatorsResponse].ok(data)
        of 400:
          handle400()
          ApiResponse[GetStateValidatorsResponse].err(ResponseInvalidError)
        of 404:
          handle404()
          ApiResponse[GetStateValidatorsResponse].err(ResponseNotFoundError)
        of 500:
          handle500()
          ApiResponse[GetStateValidatorsResponse].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetStateValidatorsResponse].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.Duties},
                              getStateValidatorsPlain(it, stateIdent, id)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(GetStateValidatorsResponse, response.data,
                                response.contentType)
          if res.isOk():
            let data = res.get()
            if data.execution_optimistic.get(false):
              handleOptimistic()
            return data.data
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 404:
          handle404()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get state's validators", data: failures)

proc produceAttestationData*(
       vc: ValidatorClientRef,
       slot: Slot,
       committee_index: CommitteeIndex,
       strategy: ApiStrategyKind
     ): Future[AttestationData] {.async.} =
  const RequestName = "produceAttestationData"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      ProduceAttestationDataResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.AttestationData},
      produceAttestationDataPlain(it, slot, committee_index)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[ProduceAttestationDataResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(ProduceAttestationDataResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[ProduceAttestationDataResponse].err($res.error)
          else:
            ApiResponse[ProduceAttestationDataResponse].ok(res.get())
        of 400:
          handle400()
          ApiResponse[ProduceAttestationDataResponse].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[ProduceAttestationDataResponse].err(ResponseInternalError)
        of 503:
          handle503()
          ApiResponse[ProduceAttestationDataResponse].err(
            ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[ProduceAttestationDataResponse].err(
            ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.AttestationData},
      produceAttestationDataPlain(it, slot, committee_index)):

      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(ProduceAttestationDataResponse, response.data,
                                response.contentType)
          if res.isOk(): return res.get().data

          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to produce attestation data", data: failures)

proc submitPoolAttestations*(
       vc: ValidatorClientRef,
       data: seq[Attestation],
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  const
    RequestName = "submitPoolAttestations"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      bool,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.AttestationPublish},
                                      submitPoolAttestations(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[bool].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          ApiResponse[bool].ok(true)
        of 400:
          handle400()
          ApiResponse[bool].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[bool].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[bool].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.AttestationPublish},
                              submitPoolAttestations(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          return true
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to submit attestations", data: failures)

proc submitPoolSyncCommitteeSignature*(
       vc: ValidatorClientRef,
       data: SyncCommitteeMessage,
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  const
    RequestName = "submitPoolSyncCommitteeSignatures"

  let restData = RestSyncCommitteeMessage.init(
    data.slot,
    data.beacon_block_root,
    data.validator_index,
    data.signature
  )

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res =  vc.firstSuccessParallel(
      RestPlainResponse,
      bool,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.SyncCommitteePublish},
      submitPoolSyncCommitteeSignatures(it, @[restData])):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[bool].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          ApiResponse[bool].ok(true)
        of 400:
          handle400()
          ApiResponse[bool].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[bool].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[bool].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.SyncCommitteePublish},
      submitPoolSyncCommitteeSignatures(it, @[restData])):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          return true
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to submit sync committee message", data: failures)

proc getAggregatedAttestation*(
       vc: ValidatorClientRef,
       slot: Slot,
       root: Eth2Digest,
       strategy: ApiStrategyKind
     ): Future[Attestation] {.async.} =
  const
    RequestName = "getAggregatedAttestation"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      GetAggregatedAttestationResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.AggregatedData},
      getAggregatedAttestationPlain(it, root, slot)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[GetAggregatedAttestationResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(GetAggregatedAttestationResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[GetAggregatedAttestationResponse].err($res.error)
          else:
            ApiResponse[GetAggregatedAttestationResponse].ok(res.get())
        of 400:
          handle400()
          ApiResponse[GetAggregatedAttestationResponse].err(
            ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[GetAggregatedAttestationResponse].err(
            ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[GetAggregatedAttestationResponse].err(
            ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.AggregatedData},
      getAggregatedAttestationPlain(it, root, slot)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(GetAggregatedAttestationResponse, response.data,
                                response.contentType)
          if res.isOk(): return res.get().data
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to get aggregated attestation", data: failures)

proc produceSyncCommitteeContribution*(
       vc: ValidatorClientRef,
       slot: Slot,
       subcommitteeIndex: SyncSubcommitteeIndex,
       root: Eth2Digest,
       strategy: ApiStrategyKind
     ): Future[SyncCommitteeContribution] {.async.} =
  const
    RequestName = "produceSyncCommitteeContribution"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      ProduceSyncCommitteeContributionResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.SyncCommitteeData},
      produceSyncCommitteeContributionPlain(it, slot, subcommitteeIndex, root)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[ProduceSyncCommitteeContributionResponse].err(
          apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(ProduceSyncCommitteeContributionResponse,
                                response.data, response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[ProduceSyncCommitteeContributionResponse].err(
              $res.error)
          else:
            ApiResponse[ProduceSyncCommitteeContributionResponse].ok(res.get())
        of 400:
          handle400()
          ApiResponse[ProduceSyncCommitteeContributionResponse].err(
            ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[ProduceSyncCommitteeContributionResponse].err(
            ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[ProduceSyncCommitteeContributionResponse].err(
            ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get().data

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.SyncCommitteeData},
      produceSyncCommitteeContributionPlain(it, slot, subcommitteeIndex, root)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(ProduceSyncCommitteeContributionResponse,
                                response.data, response.contentType)
          if res.isOk(): return res.get().data
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to produce sync committee contribution", data: failures)

proc publishAggregateAndProofs*(
       vc: ValidatorClientRef,
       data: seq[SignedAggregateAndProof],
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  const
    RequestName = "publishAggregateAndProofs"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      bool,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.AggregatedPublish},
                                      publishAggregateAndProofs(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[bool].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          ApiResponse[bool].ok(true)
        of 400:
          handle400()
          ApiResponse[bool].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[bool].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[bool].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.AggregatedPublish},
                              publishAggregateAndProofs(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          return true
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to publish aggregated attestation", data: failures)

proc publishContributionAndProofs*(
       vc: ValidatorClientRef,
       data: seq[RestSignedContributionAndProof],
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  const
    RequestName = "publishContributionAndProofs"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(RestPlainResponse,
                                      bool,
                                      SlotDuration,
                                      ViableNodeStatus,
                                      {BeaconNodeRole.SyncCommitteePublish},
                                      publishContributionAndProofs(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[bool].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          ApiResponse[bool].ok(true)
        of 400:
          handle400()
          ApiResponse[bool].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[bool].err(ResponseInternalError)
        else:
          handleUnexpectedCode()
          ApiResponse[bool].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.SyncCommitteePublish},
                              publishContributionAndProofs(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          return true
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to publish sync committee contribution", data: failures)

proc produceBlockV2*(
       vc: ValidatorClientRef,
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       strategy: ApiStrategyKind
     ): Future[ProduceBlockResponseV2] {.async.} =
  const
    RequestName = "produceBlockV2"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      ProduceBlockResponseV2,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.BlockProposalData},
      produceBlockV2Plain(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[ProduceBlockResponseV2].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(ProduceBlockResponseV2, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[ProduceBlockResponseV2].err($res.error)
          else:
            ApiResponse[ProduceBlockResponseV2].ok(res.get())
        of 400:
          handle400()
          ApiResponse[ProduceBlockResponseV2].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[ProduceBlockResponseV2].err(ResponseInternalError)
        of 503:
          handle503()
          ApiResponse[ProduceBlockResponseV2].err(ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[ProduceBlockResponseV2].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.BlockProposalData},
      produceBlockV2Plain(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(ProduceBlockResponseV2, response.data,
                                response.contentType)
          if res.isOk(): return res.get()
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to produce block", data: failures)

proc publishBlock*(
       vc: ValidatorClientRef,
       data: ForkedSignedBeaconBlock,
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  const
    RequestName = "publishBlock"
    BlockBroadcasted = "Block not passed validation, but still published"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = block:
      vc.firstSuccessParallel(RestPlainResponse,
                              bool,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.BlockProposalPublish}):
        case data.kind
        of ConsensusFork.Phase0:
          publishBlock(it, data.phase0Data)
        of ConsensusFork.Altair:
          publishBlock(it, data.altairData)
        of ConsensusFork.Bellatrix:
          publishBlock(it, data.bellatrixData)
        of ConsensusFork.Capella:
          publishBlock(it, data.capellaData)
        of ConsensusFork.Deneb:
          debugRaiseAssert $denebImplementationMissing &
                           ": validator_client/api.nim:publishBlock (1)"
          let f = newFuture[RestPlainResponse]("")
          f.fail(new RestError)
          f

      do:
        if apiResponse.isErr():
          handleCommunicationError()
          ApiResponse[bool].err(apiResponse.error)
        else:
          let response = apiResponse.get()
          case response.status:
          of 200:
            ApiResponse[bool].ok(true)
          of 202:
            debug BlockBroadcasted, node = node, blck = shortLog(data)
            ApiResponse[bool].ok(true)
          of 400:
            handle400()
            ApiResponse[bool].err(ResponseInvalidError)
          of 500:
            handle500()
            ApiResponse[bool].err(ResponseInternalError)
          of 503:
            handle503()
            ApiResponse[bool].err(ResponseNoSyncError)
          else:
            handleUnexpectedCode()
            ApiResponse[bool].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.BlockProposalPublish}):
      case data.kind
      of ConsensusFork.Phase0:
        publishBlock(it, data.phase0Data)
      of ConsensusFork.Altair:
        publishBlock(it, data.altairData)
      of ConsensusFork.Bellatrix:
        publishBlock(it, data.bellatrixData)
      of ConsensusFork.Capella:
        publishBlock(it, data.capellaData)
      of ConsensusFork.Deneb:
        debugRaiseAssert $denebImplementationMissing &
                         ": validator_client/api.nim:publishBlock (2)"
        let f = newFuture[RestPlainResponse]("")
        f.fail(new RestError)
        f
    do:
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          return true
        of 202:
          debug BlockBroadcasted, node = node, blck = shortLog(data)
          return true
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to publish block", data: failures)

proc produceBlindedBlock*(
       vc: ValidatorClientRef,
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes,
       strategy: ApiStrategyKind
     ): Future[ProduceBlindedBlockResponse] {.async.} =
  const
    RequestName = "produceBlindedBlock"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = vc.firstSuccessParallel(
      RestPlainResponse,
      ProduceBlindedBlockResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.BlockProposalData},
      produceBlindedBlockPlain(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[ProduceBlindedBlockResponse].err(apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(ProduceBlindedBlockResponse, response.data,
                                response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[ProduceBlindedBlockResponse].err($res.error)
          else:
            ApiResponse[ProduceBlindedBlockResponse].ok(res.get())
        of 400:
          # TODO(cheatfate): We not going to update BN status for this handler,
          # because BN reports 400 for any type of error that does not mean
          # that BN is incompatible.
          let failure = ApiNodeFailure.init(ApiFailure.Invalid, RequestName,
            strategy, node, response.status, response.getErrorMessage())
          failures.add(failure)
          ApiResponse[ProduceBlindedBlockResponse].err(ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[ProduceBlindedBlockResponse].err(ResponseInternalError)
        of 503:
          handle503()
          ApiResponse[ProduceBlindedBlockResponse].err(ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[ProduceBlindedBlockResponse].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(
      RestPlainResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.BlockProposalData},
      produceBlindedBlockPlain(it, slot, randao_reveal, graffiti)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          let res = decodeBytes(ProduceBlindedBlockResponse, response.data,
                                response.contentType)
          if res.isOk(): return res.get()
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to produce blinded block", data: failures)

proc publishBlindedBlock*(
       vc: ValidatorClientRef,
       data: ForkedSignedBlindedBeaconBlock,
       strategy: ApiStrategyKind
     ): Future[bool] {.async.} =
  const
    RequestName = "publishBlindedBlock"
    BlockBroadcasted = "Block not passed validation, but still published"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res = block:
      vc.firstSuccessParallel(RestPlainResponse,
                              bool,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.BlockProposalPublish}):
        case data.kind
        of ConsensusFork.Phase0:
          publishBlindedBlock(it, data.phase0Data)
        of ConsensusFork.Altair:
          publishBlindedBlock(it, data.altairData)
        of ConsensusFork.Bellatrix:
          publishBlindedBlock(it, data.bellatrixData)
        of ConsensusFork.Capella:
          publishBlindedBlock(it, data.capellaData)
        of ConsensusFork.Deneb:
          debugRaiseAssert $denebImplementationMissing &
                           ": validator_client/api.nim:publishBlindedBlock (1)"
          let f = newFuture[RestPlainResponse]("")
          f.fail(new RestError)
          f
      do:
        if apiResponse.isErr():
          handleCommunicationError()
          ApiResponse[bool].err(apiResponse.error)
        else:
          let response = apiResponse.get()
          case response.status:
          of 200:
            ApiResponse[bool].ok(true)
          of 202:
            debug BlockBroadcasted, node = node, blck = shortLog(data)
            ApiResponse[bool].ok(true)
          of 400:
            handle400()
            ApiResponse[bool].err(ResponseInvalidError)
          of 500:
            handle500()
            ApiResponse[bool].err(ResponseInternalError)
          of 503:
            handle503()
            ApiResponse[bool].err(ResponseNoSyncError)
          else:
            handleUnexpectedCode()
            ApiResponse[bool].err(ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.BlockProposalPublish}):
      case data.kind
      of ConsensusFork.Phase0:
        publishBlindedBlock(it, data.phase0Data)
      of ConsensusFork.Altair:
        publishBlindedBlock(it, data.altairData)
      of ConsensusFork.Bellatrix:
        publishBlindedBlock(it, data.bellatrixData)
      of ConsensusFork.Capella:
        publishBlindedBlock(it, data.capellaData)
      of ConsensusFork.Deneb:
        debugRaiseAssert $denebImplementationMissing &
                         ": validator_client/api.nim:publishBlindedBlock (2)"
        let f = newFuture[RestPlainResponse]("")
        f.fail(new RestError)
        f
    do:
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status:
        of 200:
          return true
        of 202:
          debug BlockBroadcasted, node = node, blck = shortLog(data)
          return true
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to publish blinded block", data: failures)

proc prepareBeaconCommitteeSubnet*(
       vc: ValidatorClientRef,
       data: seq[RestCommitteeSubscription],
     ): Future[int] {.async.} =
  logScope: request = "prepareBeaconCommitteeSubnet"
  let resp = vc.onceToAll(RestPlainResponse,
                          SlotDuration,
                          ViableNodeStatus,
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
              endpoint = apiResponse.node, error = apiResponse.data.error
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Subscription to beacon commitee subnets failed",
                 status = response.status, endpoint = apiResponse.node,
                 reason = response.getErrorMessage()
    return count

proc prepareSyncCommitteeSubnets*(
       vc: ValidatorClientRef,
       data: seq[RestSyncCommitteeSubscription],
     ): Future[int] {.async.} =
  logScope: request = "prepareSyncCommitteeSubnet"
  let resp = vc.onceToAll(RestPlainResponse,
                          SlotDuration,
                          ViableNodeStatus,
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
              endpoint = apiResponse.node, error = apiResponse.data.error
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Sync committee subnets preparation failed",
                 status = response.status, endpoint = apiResponse.node,
                 message = response.getErrorMessage()
    return count

proc prepareBeaconProposer*(
       vc: ValidatorClientRef,
       data: seq[PrepareBeaconProposer]
     ): Future[int] {.async.} =
  logScope: request = "prepareBeaconProposer"
  let resp = vc.onceToAll(RestPlainResponse,
                          SlotDuration,
                          ViableNodeStatus,
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
              endpoint = apiResponse.node, error = apiResponse.data.error
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Beacon proposer preparation failed", status = response.status,
                endpoint = apiResponse.node, reason = response.getErrorMessage()
    return count

proc registerValidator*(
       vc: ValidatorClientRef,
       data: seq[SignedValidatorRegistrationV1]
     ): Future[int] {.async.} =
  logScope: request = "registerValidators"
  let resp = vc.onceToAll(RestPlainResponse,
                          SlotDuration,
                          ViableNodeStatus,
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
      return 0
    of ApiOperation.Failure:
      debug "Unexpected error happened while registering validators"
      return 0
  else:
    var count = 0
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to register validator with beacon node",
              endpoint = apiResponse.node, error = apiResponse.data.error
      else:
        let response = apiResponse.data.get()
        if response.status == 200:
          inc(count)
        else:
          debug "Unable to register validators with beacon node",
                status = response.status, endpoint = apiResponse.node,
                reason = response.getErrorMessage()
    return count

proc getValidatorsLiveness*(
       vc: ValidatorClientRef, epoch: Epoch,
       validators: seq[ValidatorIndex]
     ): Future[GetValidatorsLivenessResponse] {.async.} =
  const
    RequestName = "getValidatorsActivity"
  let resp = vc.onceToAll(RestPlainResponse,
                          SlotDuration,
                          ViableNodeStatus,
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
              endpoint = apiResponse.node, error = apiResponse.data.error
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
            let failure = ApiNodeFailure.init(
              ApiFailure.UnexpectedResponse, RequestName,
              apiResponse.node, response.status, $res.error)
            apiResponse.node.updateStatus(
              RestBeaconNodeStatus.UnexpectedResponse, failure)
            continue
        of 400:
          let failure = ApiNodeFailure.init(
            ApiFailure.Invalid, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          apiResponse.node.updateStatus(
            RestBeaconNodeStatus.Incompatible, failure)
          continue
        of 500:
          let failure = ApiNodeFailure.init(
            ApiFailure.Internal, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          apiResponse.node.updateStatus(
            RestBeaconNodeStatus.InternalError, failure)
          continue
        of 503:
          let failure = ApiNodeFailure.init(
            ApiFailure.NotSynced, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          apiResponse.node.updateStatus(
            RestBeaconNodeStatus.NotSynced, failure)
          continue
        else:
          let failure = ApiNodeFailure.init(
            ApiFailure.UnexpectedCode, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          apiResponse.node.updateStatus(
            RestBeaconNodeStatus.UnexpectedCode, failure)
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

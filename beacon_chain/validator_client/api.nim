# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/strutils
import chronicles, stew/base10
import ".."/spec/eth2_apis/eth2_rest_serialization,
       ".."/spec/datatypes/[phase0, altair]
import "."/[common, fallback_service, scoring]

export eth2_rest_serialization, common

const
  ResponseInvalidError = "Received invalid request response"
  ResponseInternalError = "Received internal error response"
  ResponseUnexpectedError = "Received unexpected error response"
  ResponseNotFoundError = "Received resource missing error response"
  ResponseNoSyncError = "Received nosync error response"
  ResponseDecodeError = "Received response could not be decoded"
  ResponseECNotInSyncError* = "Execution client not in sync"
  ResponseNotImplementedError =
    "Received endpoint not implemented error response"

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

  ApiScore* = object
    index*: int
    score*: Opt[float64]

  BestNodeResponse*[T] = object
    node*: BeaconNodeServerRef
    data*: ApiResponse[T]
    score*: float64

const
  ViableNodeStatus = {RestBeaconNodeStatus.Compatible,
                      RestBeaconNodeStatus.NotSynced,
                      RestBeaconNodeStatus.OptSynced,
                      RestBeaconNodeStatus.Synced}

proc `$`*(s: ApiScore): string =
  var res = Base10.toString(uint64(s.index))
  res.add(": ")
  if s.score.isSome():
    res.add(shortScore(s.score.get()))
  else:
    res.add("<n/a>")
  res

proc `$`*(ss: openArray[ApiScore]): string =
  "[" & ss.mapIt($it).join(",") & "]"

chronicles.formatIt(seq[ApiScore]):
  $it

func init*(t: typedesc[ApiScore], node: BeaconNodeServerRef,
           score: float64): ApiScore =
  ApiScore(index: node.index, score: Opt.some(score))

func init*(t: typedesc[ApiScore], node: BeaconNodeServerRef): ApiScore =
  ApiScore(index: node.index, score: Opt.none(float64))

func init*[T](t: typedesc[BestNodeResponse], node: BeaconNodeServerRef,
              data: ApiResponse[T], score: float64): BestNodeResponse[T] =
  BestNodeResponse[T](node: node, data: data, score: score)

proc lazyWaiter(node: BeaconNodeServerRef, request: FutureBase,
                requestName: string, strategy: ApiStrategyKind) {.async.} =
  try:
    await allFutures(request)
    if request.failed():
      let failure = ApiNodeFailure.init(
        ApiFailure.Communication, requestName, strategy, node,
        $request.error.msg)
      node.updateStatus(RestBeaconNodeStatus.Offline, failure)
  except CancelledError:
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

proc apiResponseOr[T](future: FutureBase, timerFut: Future[void],
                      message: string): ApiResponse[T] =
  if future.finished() and not(future.cancelled()):
    if future.failed():
      ApiResponse[T].err($future.error.msg)
    else:
      ApiResponse[T].ok(Future[T](future).read())
  else:
    if timerFut.finished():
      ApiResponse[T].err(message)
    else:
      ApiResponse[T].err("Interrupted by the caller")

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
        default(seq[BeaconNodeServerRef])

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

            if not(isNil(timerFut)):
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
                apiResponseOr[responseType](requestFut, timerFut,
                  "Timeout exceeded while awaiting for the response")
              handlerResponse =
                try:
                  body2
                except CancelledError as exc:
                  raise exc
                except CatchableError:
                  raiseAssert("Response handler must not raise exceptions")

            if handlerResponse.isOk():
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
          for future in pendingRequests.items():
            if not(future.finished()):
              pendingCancel.add(future.cancelAndWait())
          await noCancel allFutures(pendingCancel)
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
           handlerType: typedesc,
           timeout: Duration,
           statuses: set[RestBeaconNodeStatus],
           roles: set[BeaconNodeRole],
           bodyRequest,
           bodyScore,
           bodyHandler: untyped): ApiResponse[handlerType] =
  var
    it {.inject.}: RestClientRef
    iterations = 0

  var timerFut =
    if timeout != InfiniteDuration:
      sleepAsync(timeout)
    else:
      nil

  var
    retRes: ApiResponse[handlerType]
    scores: seq[ApiScore]
    bestResponse: Opt[BestNodeResponse[handlerType]]

  block mainLoop:
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
          if not(isNil(timerFut)) and not(timerFut.finished()):
            await timerFut.cancelAndWait()
          raise exc
        except CatchableError as exc:
          # This case could not be happened.
          error "Unexpected exception while waiting for beacon nodes",
                err_name = $exc.name, err_msg = $exc.msg
          default(seq[BeaconNodeServerRef])

      if len(onlineNodes) == 0:
        retRes = ApiResponse[handlerType].err("No online beacon node(s)")
        break mainLoop
      else:
        var
          (pendingRequests, pendingNodes) =
            block:
              var requests: seq[FutureBase]
              var nodes: seq[BeaconNodeServerRef]
              for node {.inject.} in onlineNodes:
                it = node.client
                let fut = FutureBase(bodyRequest)
                requests.add(fut)
                nodes.add(node)
              (requests, nodes)
          perfectScoreFound = false

        block innerLoop:
          while len(pendingRequests) > 0:
            var
              finishedRequests: seq[FutureBase]
              finishedNodes: seq[BeaconNodeServerRef]
              raceFut: Future[FutureBase]
            try:
              raceFut = race(pendingRequests)

              if not(isNil(timerFut)):
                await raceFut or timerFut
              else:
                await allFutures(raceFut)

              for index, future in pendingRequests.pairs():
                if future.finished() or
                   (not(isNil(timerFut)) and timerFut.finished()):
                  finishedRequests.add(future)
                  finishedNodes.add(pendingNodes[index])
                  let
                    node {.inject.} = pendingNodes[index]
                    apiResponse {.inject.} =
                      apiResponseOr[responseType](future, timerFut,
                        "Timeout exceeded while awaiting for the response")
                    handlerResponse =
                      try:
                        bodyHandler
                      except CancelledError as exc:
                        raise exc
                      except CatchableError:
                        raiseAssert(
                          "Response handler must not raise exceptions")

                  if handlerResponse.isOk():
                    let
                      itresponse {.inject.} = handlerResponse.get()
                      score =
                        try:
                          bodyScore
                        except CancelledError as exc:
                          raise exc
                        except CatchableError:
                          raiseAssert("Score handler must not raise exceptions")
                    scores.add(ApiScore.init(node, score))
                    if bestResponse.isNone() or
                      (score > bestResponse.get().score):
                      bestResponse = Opt.some(
                        BestNodeResponse.init(node, handlerResponse, score))
                      if perfectScore(score):
                        perfectScoreFound = true
                        break
                  else:
                    scores.add(ApiScore.init(node))

              if perfectScoreFound:
                # lazyWait will cancel `pendingRequests` on timeout.
                asyncSpawn lazyWait(pendingNodes, pendingRequests, timerFut,
                                    RequestName, strategy)
                break innerLoop

              if not(isNil(timerFut)) and timerFut.finished():
                # If timeout is exceeded we need to cancel all the tasks which
                # are still running.
                var pendingCancel: seq[Future[void]]
                for future in pendingRequests.items():
                  if not(future.finished()):
                    pendingCancel.add(future.cancelAndWait())
                await allFutures(pendingCancel)
                break innerLoop

              pendingRequests.keepItIf(it notin finishedRequests)
              pendingNodes.keepItIf(it notin finishedNodes)

            except CancelledError as exc:
              var pendingCancel: seq[Future[void]]
              # `or` operation does not cancelling Futures passed as arguments.
              if not(isNil(raceFut)) and not(raceFut.finished()):
                pendingCancel.add(raceFut.cancelAndWait())
              if not(isNil(timerFut)) and not(timerFut.finished()):
                pendingCancel.add(timerFut.cancelAndWait())
              # We should cancel all the requests which are still pending.
              for future in pendingRequests.items():
                if not(future.finished()):
                  pendingCancel.add(future.cancelAndWait())
              # Awaiting cancellations.
              await noCancel allFutures(pendingCancel)
              raise exc
            except CatchableError as exc:
              # This should not be happened, because allFutures() and race()
              # did not raise any exceptions.
              error "Unexpected exception while processing request",
                    err_name = $exc.name, err_msg = $exc.msg
              retRes = ApiResponse[handlerType].err("Unexpected error")
              break mainLoop

        if bestResponse.isSome():
          retRes = bestResponse.get().data
          break mainLoop
        else:
          if timerFut.finished():
            retRes = ApiResponse[handlerType].err(
                       "Timeout exceeded while awaiting for responses")
            break mainLoop
          else:
            # When all requests failed
            discard

      inc(iterations)

  if retRes.isOk():
    debug "Best score result selected",
          request = RequestName, available_scores = scores,
          best_score = shortScore(bestResponse.get().score),
          best_node = bestResponse.get().node

  retRes

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
        await noCancel allFutures(pendingCancel)
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
            except CatchableError:
              # This case should not happen.
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
              await noCancel allFutures(pending)
              raise exc
            except CatchableError:
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

template handle501(): untyped {.dirty.} =
  let failure = ApiNodeFailure.init(ApiFailure.NotImplemented, RequestName,
    strategy, node, response.status, response.getErrorMessage())
  node.updateStatus(RestBeaconNodeStatus.Incompatible, failure)
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
  of ApiStrategyKind.First:
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

  of ApiStrategyKind.Best:
    let res = vc.bestSuccess(
      RestPlainResponse,
      GetBlockRootResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.SyncCommitteeData},
      getBlockRootPlain(it, blockIdent),
      getSyncCommitteeMessageDataScore(vc, itresponse)):
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
  of ApiStrategyKind.First:
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

  of ApiStrategyKind.Best:
    let res = vc.bestSuccess(
      RestPlainResponse,
      ProduceAttestationDataResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.AttestationData},
      produceAttestationDataPlain(it, slot, committee_index),
      getAttestationDataScore(vc, itresponse)):
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
  of ApiStrategyKind.First:
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

  of ApiStrategyKind.Best:
    let res = vc.bestSuccess(
      RestPlainResponse,
      GetAggregatedAttestationResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.AggregatedData},
      getAggregatedAttestationPlain(it, root, slot),
      getAggregatedAttestationDataScore(itresponse)):
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
  of ApiStrategyKind.First:
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

  of ApiStrategyKind.Best:
    let res = vc.bestSuccess(
      RestPlainResponse,
      ProduceSyncCommitteeContributionResponse,
      OneThirdDuration,
      ViableNodeStatus,
      {BeaconNodeRole.SyncCommitteeData},
      produceSyncCommitteeContributionPlain(it, slot, subcommitteeIndex, root),
      getSyncCommitteeContributionDataScore(itresponse)):
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
          let
            version = response.headers.getString("eth-consensus-version")
            res = decodeBytes(ProduceBlockResponseV2, response.data,
                              response.contentType, version)
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
          let
            version = response.headers.getString("eth-consensus-version")
            res = decodeBytes(ProduceBlockResponseV2, response.data,
                              response.contentType, version)
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
       data: RestPublishedSignedBlockContents,
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
          publishBlock(it, data.denebData)
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
            debug BlockBroadcasted, node = node,
             blck = shortLog(ForkedSignedBeaconBlock.init(data))
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
        publishBlock(it, data.denebData)

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
          debug BlockBroadcasted, node = node,
           blck = shortLog(ForkedSignedBeaconBlock.init(data))
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
          let
            version = response.headers.getString("eth-consensus-version")
            res = decodeBytes(ProduceBlindedBlockResponse, response.data,
                              response.contentType, version)
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
          let
            version = response.headers.getString("eth-consensus-version")
            res = decodeBytes(ProduceBlindedBlockResponse, response.data,
                              response.contentType, version)
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
          publishBlindedBlock(it, data.denebData)
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
        publishBlindedBlock(it, data.denebData)
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
    RequestName = "getLiveness"
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
            discard ApiNodeFailure.init(
              ApiFailure.UnexpectedResponse, RequestName,
              apiResponse.node, response.status, $res.error)
            # We do not update beacon node's status anymore because of
            # issue #5377.
            continue
        of 400:
          discard ApiNodeFailure.init(
            ApiFailure.Invalid, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          continue
        of 500:
          discard ApiNodeFailure.init(
            ApiFailure.Internal, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          continue
        of 503:
          discard ApiNodeFailure.init(
            ApiFailure.NotSynced, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          continue
        else:
          discard ApiNodeFailure.init(
            ApiFailure.UnexpectedCode, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
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

proc getFinalizedBlockHeader*(
       vc: ValidatorClientRef,
     ): Future[Opt[GetBlockHeaderResponse]] {.async.} =
  const RequestName = "getFinalizedBlockHeader"

  let
    blockIdent = BlockIdent.init(BlockIdentType.Finalized)
    resp = vc.onceToAll(RestPlainResponse,
                        SlotDuration,
                        ViableNodeStatus,
                        {BeaconNodeRole.Duties},
                        getBlockHeaderPlain(it, blockIdent))
  case resp.status
  of ApiOperation.Timeout:
    debug "Unable to obtain finalized block header in time",
          timeout = SlotDuration
    return Opt.none(GetBlockHeaderResponse)
  of ApiOperation.Interrupt:
    debug "Finalized block header request was interrupted"
    return Opt.none(GetBlockHeaderResponse)
  of ApiOperation.Failure:
    debug "Unexpected error happened while trying to get finalized block header"
    return Opt.none(GetBlockHeaderResponse)
  of ApiOperation.Success:
    var oldestBlockHeader: GetBlockHeaderResponse
    var oldestEpoch: Opt[Epoch]
    for apiResponse in resp.data:
      if apiResponse.data.isErr():
        debug "Unable to get finalized block header",
              endpoint = apiResponse.node, error = apiResponse.data.error
      else:
        let response = apiResponse.data.get()
        case response.status
        of 200:
          let res = decodeBytes(GetBlockHeaderResponse,
                                response.data, response.contentType)
          if res.isOk():
            let
              rdata = res.get()
              epoch = rdata.data.header.message.slot.epoch()
            if oldestEpoch.get(FAR_FUTURE_EPOCH) > epoch:
              oldestEpoch = Opt.some(epoch)
              oldestBlockHeader = rdata
          else:
            let failure = ApiNodeFailure.init(
              ApiFailure.UnexpectedResponse, RequestName,
              apiResponse.node, response.status, $res.error)
            # We do not update beacon node's status anymore because of
            # issue #5377.
            debug ResponseDecodeError, reason = getFailureReason(failure)
            continue
        of 400:
          let failure = ApiNodeFailure.init(
            ApiFailure.Invalid, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          debug ResponseInvalidError, reason = getFailureReason(failure)
          continue
        of 404:
          let failure = ApiNodeFailure.init(
            ApiFailure.NotFound, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          debug ResponseNotFoundError, reason = getFailureReason(failure)
          continue
        of 500:
          let failure = ApiNodeFailure.init(
            ApiFailure.Internal, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          debug ResponseInternalError, reason = getFailureReason(failure)
          continue
        else:
          let failure = ApiNodeFailure.init(
            ApiFailure.UnexpectedCode, RequestName,
            apiResponse.node, response.status, response.getErrorMessage())
          # We do not update beacon node's status anymore because of
          # issue #5377.
          debug ResponseUnexpectedError, reason = getFailureReason(failure)
          continue

    if oldestEpoch.isSome():
      return Opt.some(oldestBlockHeader)
    else:
      return Opt.none(GetBlockHeaderResponse)

proc submitBeaconCommitteeSelections*(
       vc: ValidatorClientRef,
       data: seq[RestBeaconCommitteeSelection],
       strategy: ApiStrategyKind
     ): Future[SubmitBeaconCommitteeSelectionsResponse] {.async.} =
  const
    RequestName = "submitBeaconCommitteeSelections"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res =  vc.firstSuccessParallel(
      RestPlainResponse,
      SubmitBeaconCommitteeSelectionsResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.Duties},
      submitBeaconCommitteeSelectionsPlain(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err(
          apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(SubmitBeaconCommitteeSelectionsResponse,
                                response.data, response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err($res.error)
          else:
            ApiResponse[SubmitBeaconCommitteeSelectionsResponse].ok(res.get())
        of 400:
          handle400()
          ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err(
            ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err(
            ResponseInternalError)
        of 501:
          handle501()
          ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err(
            ResponseNotImplementedError)
        of 503:
          handle503()
          ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err(
            ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[SubmitBeaconCommitteeSelectionsResponse].err(
            ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.Duties},
                              submitBeaconCommitteeSelectionsPlain(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(SubmitBeaconCommitteeSelectionsResponse,
                                response.data, response.contentType)
          if res.isOk(): return res.get()
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 501:
          handle501()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to submit beacon committee selections", data: failures)

proc submitSyncCommitteeSelections*(
       vc: ValidatorClientRef,
       data: seq[RestSyncCommitteeSelection],
       strategy: ApiStrategyKind
     ): Future[SubmitSyncCommitteeSelectionsResponse] {.async.} =
  const
    RequestName = "submitBeaconCommitteeSelections"

  var failures: seq[ApiNodeFailure]

  case strategy
  of ApiStrategyKind.First, ApiStrategyKind.Best:
    let res =  vc.firstSuccessParallel(
      RestPlainResponse,
      SubmitSyncCommitteeSelectionsResponse,
      SlotDuration,
      ViableNodeStatus,
      {BeaconNodeRole.Duties},
      submitSyncCommitteeSelectionsPlain(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        ApiResponse[SubmitSyncCommitteeSelectionsResponse].err(
          apiResponse.error)
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(SubmitSyncCommitteeSelectionsResponse,
                                response.data, response.contentType)
          if res.isErr():
            handleUnexpectedData()
            ApiResponse[SubmitSyncCommitteeSelectionsResponse].err($res.error)
          else:
            ApiResponse[SubmitSyncCommitteeSelectionsResponse].ok(res.get())
        of 400:
          handle400()
          ApiResponse[SubmitSyncCommitteeSelectionsResponse].err(
            ResponseInvalidError)
        of 500:
          handle500()
          ApiResponse[SubmitSyncCommitteeSelectionsResponse].err(
            ResponseInternalError)
        of 501:
          handle501()
          ApiResponse[SubmitSyncCommitteeSelectionsResponse].err(
            ResponseNotImplementedError)
        of 503:
          handle503()
          ApiResponse[SubmitSyncCommitteeSelectionsResponse].err(
            ResponseNoSyncError)
        else:
          handleUnexpectedCode()
          ApiResponse[SubmitSyncCommitteeSelectionsResponse].err(
            ResponseUnexpectedError)

    if res.isErr():
      raise (ref ValidatorApiError)(msg: res.error, data: failures)
    return res.get()

  of ApiStrategyKind.Priority:
    vc.firstSuccessSequential(RestPlainResponse,
                              SlotDuration,
                              ViableNodeStatus,
                              {BeaconNodeRole.Duties},
                              submitSyncCommitteeSelectionsPlain(it, data)):
      if apiResponse.isErr():
        handleCommunicationError()
        false
      else:
        let response = apiResponse.get()
        case response.status
        of 200:
          let res = decodeBytes(SubmitSyncCommitteeSelectionsResponse,
                                response.data, response.contentType)
          if res.isOk(): return res.get()
          handleUnexpectedData()
          false
        of 400:
          handle400()
          false
        of 500:
          handle500()
          false
        of 501:
          handle501()
          false
        of 503:
          handle503()
          false
        else:
          handleUnexpectedCode()
          false

    raise (ref ValidatorApiError)(
      msg: "Failed to submit sync committee selections", data: failures)

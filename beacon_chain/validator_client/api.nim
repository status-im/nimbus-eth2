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

type
  ApiResponse*[T] = Result[T, string]
  ApiOperation = enum
    Success, Timeout, Failure, Interrupt

  ApiStrategyKind* {.pure.} = enum
    Priority, Best, First

  ApiNodeResponse*[T] = object
    node*: BeaconNodeServerRef
    data*: ApiResponse[T]

  ApiScoreFunction*[T] = proc(vc: ValidatorClientRef,
                              data: openArray[ApiNodeResponse[T]]): int {.
                           raises: [Defect], gcsafe.}

  ApiResponseSeq*[T] = object
    status*: ApiOperation
    data*: seq[ApiNodeResponse[T]]

proc lazyWait(futures: seq[FutureBase], timerFut: Future[void]) {.async.} =
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

template firstSuccessParallel*(vc: ValidatorClientRef, responseType: typedesc,
                               timeout: Duration, body1,
                               body2: untyped): ApiResponse[responseType] =
  var it {.inject.}: RestClientRef

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
      var default: seq[BeaconNodeServerRef]
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
    ApiResponse[responseType].err("Operation timeout exceeded")
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

    var retRes: ApiResponse[responseType]
    var raceFut: Future[FutureBase]
    while true:
      try:
        if len(pendingRequests) == 0:
          if not(isNil(timerFut)) and not(timerFut.finished()):
            await timerFut.cancelAndWait()
          retRes = ApiResponse[responseType].err(
            "Beacon node(s) unable to satisfy request")
          break
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

            if requestFut.failed():
              let exc = Future[responseType](requestFut).readError()
              debug "One of operation requests has been failed",
                    node = beaconNode, err_name = $exc.name, err_msg = $exc.msg
              beaconNode.status = RestBeaconNodeStatus.Offline
            elif requestFut.cancelled():
              debug "One of operation requests has been interrupted",
                    node = beaconNode
            else:
              let
                apiNode {.inject.} = beaconNode
                apiResponse {.inject.} = Future[responseType](requestFut).read()
                res = body2
              if res.isOk():
                asyncSpawn lazyWait(pendingRequests, timerFut)
                retRes = res
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
            break
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
      var default: seq[BeaconNodeServerRef]
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
                    node: beaconNode
                    data: ApiResponse[responseType].ok(future.read()))
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
                    timeout: Duration,
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
        await vc.waitOnlineNodes(timerFut)
      vc.onlineNodes()
    except CancelledError as exc:
      var default: seq[BeaconNodeServerRef]
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
                                 timeout: Duration, body: untyped,
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
        await vc.waitOnlineNodes(timerFut)
        vc.onlineNodes()
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

proc getDutyErrorMessage(response: RestPlainResponse): string =
  let res = decodeBytes(RestDutyError, response.data,
                        response.contentType)
  if res.isOk():
    let errorObj = res.get()
    let failures = errorObj.failures.mapIt(Base10.toString(it.index) & ": " &
                                           it.message)
    errorObj.message & ": [" & failures.join(", ") & "]"
  else:
    "Unable to decode error response: [" & $res.error() & "]"

proc getGenericErrorMessage(response: RestPlainResponse): string =
  let res = decodeBytes(RestGenericError, response.data,
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
       epoch: Epoch
     ): Future[GetProposerDutiesResponse] {.async.} =
  logScope: request = "getProposerDuties"
  vc.firstSuccessSequential(RestResponse[GetProposerDutiesResponse],
                            SlotDuration, getProposerDuties(it, epoch)):
    if apiResponse.isErr():
      debug "Unable to retrieve proposer duties", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = 503, endpoint = node
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to retrieve proposer duties")

proc getAttesterDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       validators: seq[ValidatorIndex]
     ): Future[GetAttesterDutiesResponse] {.async.} =
  logScope: request = "getAttesterDuties"
  vc.firstSuccessSequential(RestResponse[GetAttesterDutiesResponse],
                            SlotDuration,
                            getAttesterDuties(it, epoch, validators)):
    if apiResponse.isErr():
      debug "Unable to retrieve attester duties", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to retrieve attester duties")

proc getSyncCommitteeDuties*(
       vc: ValidatorClientRef,
       epoch: Epoch,
       validators: seq[ValidatorIndex]
     ): Future[GetSyncCommitteeDutiesResponse] {.async.} =
  logScope: request = "getSyncCommitteeDuties"
  vc.firstSuccessSequential(RestResponse[GetSyncCommitteeDutiesResponse],
                            SlotDuration,
                            getSyncCommitteeDuties(it, epoch, validators)):
    if apiResponse.isErr():
      debug "Unable to retrieve sync committee duties", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to retrieve sync committee duties")

proc getForkSchedule*(
       vc: ValidatorClientRef
     ): Future[seq[Fork]] {.async.} =
  logScope: request = "getForkSchedule"
  let res = vc.firstParallelSuccess(RestResponse[GetForkScheduleResponse],
                                    SlotDuration, getForkSchedule(it)):
    case apiResponse.status
    of 200:
      trace "Received successful response", endpoint = apiNode
      ApiResponse[RestResponse[GetForkScheduleResponse]].ok(apiResponse)
    of 500:
      debug "Received internal error response",
            response_code = apiResponse.status, endpoint = apiNode
      ApiResponse[RestResponse[GetForkScheduleResponse]].err("")
    else:
      const error = "Received unexpected error response"
      debug error, response_code = apiResponse.status, endpoint = apiNode
      ApiResponse[RestResponse[GetForkScheduleResponse]].err(error)

  if res.isOk():
    return res.get().data.data
  else:
    raise newException(ValidatorApiError, res.error())

proc getHeadStateFork*(
       vc: ValidatorClientRef
     ): Future[Fork] {.async.} =
  logScope: request = "getHeadStateFork"
  let stateIdent = StateIdent.init(StateIdentType.Head)
  vc.firstSuccessSequential(RestResponse[GetStateForkResponse], SlotDuration,
                            getStateFork(it, stateIdent)):
    if apiResponse.isErr():
      debug "Unable to retrieve head state's fork", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data.data
      of 400, 404:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to retrieve head state's fork")

proc getHeadBlockRoot*(
       vc: ValidatorClientRef
     ): Future[RestRoot] {.async.} =
  logScope: request = "getHeadBlockRoot"
  let blockIdent = BlockIdent.init(BlockIdentType.Head)
  vc.firstSuccessSequential(RestResponse[GetBlockRootResponse], SlotDuration,
                            getBlockRoot(it, blockIdent)):
    if apiResponse.isErr():
      debug "Unable to retrieve head block's root", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data.data
      of 400, 404:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to retrieve head block's root")

proc getValidators*(
       vc: ValidatorClientRef,
       id: seq[ValidatorIdent]
     ): Future[seq[RestValidator]] {.async.} =
  logScope: request = "getStateValidators"
  let stateIdent = StateIdent.init(StateIdentType.Head)
  vc.firstSuccessSequential(RestResponse[GetStateValidatorsResponse],
                            SlotDuration,
                            getStateValidators(it, stateIdent, id)):
    if apiResponse.isErr():
      debug "Unable to retrieve head state's validator information",
            endpoint = node, error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data.data
      of 400, 404:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to retrieve head state's validator information")

proc produceAttestationData*(
       vc: ValidatorClientRef,
       slot: Slot,
       committee_index: CommitteeIndex
     ): Future[AttestationData] {.async.} =
  logScope: request = "produceAttestationData"
  vc.firstSuccessSequential(RestResponse[ProduceAttestationDataResponse],
                            OneThirdDuration,
                            produceAttestationData(it, slot, committee_index)):
    if apiResponse.isErr():
      debug "Unable to retrieve attestation data", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Received successful response", endpoint = node
        return response.data.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to retrieve attestation data")

proc submitPoolAttestations*(
       vc: ValidatorClientRef,
       data: seq[Attestation]
     ): Future[bool] {.async.} =
  logScope: request = "submitPoolAttestations"
  vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                            submitPoolAttestations(it, data)):
    if apiResponse.isErr():
      debug "Unable to submit attestation", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Attestation was sucessfully published", endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getDutyErrorMessage()
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getDutyErrorMessage()
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getDutyErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to submit attestation")

proc submitPoolSyncCommitteeSignature*(
       vc: ValidatorClientRef,
       data: SyncCommitteeMessage
     ): Future[bool] {.async.} =
  logScope: request = "submitPoolSyncCommitteeSignatures"
  let restData = RestSyncCommitteeMessage.init(
    data.slot,
    data.beacon_block_root,
    data.validator_index,
    data.signature
  )
  vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                            submitPoolSyncCommitteeSignatures(it, @[restData])):
    if apiResponse.isErr():
      debug "Unable to submit sync committee message", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Sync committee message was successfully published",
              endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getDutyErrorMessage()
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getDutyErrorMessage()
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getDutyErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to submit sync committee message")

proc getAggregatedAttestation*(
       vc: ValidatorClientRef,
       slot: Slot,
       root: Eth2Digest
     ): Future[Attestation] {.async.} =
  logScope: request = "getAggregatedAttestation"
  vc.firstSuccessSequential(RestResponse[GetAggregatedAttestationResponse],
                            OneThirdDuration,
                            getAggregatedAttestation(it, root, slot)):
    if apiResponse.isErr():
      debug "Unable to retrieve aggregated attestation data", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status:
      of 200:
        debug "Received successful response", endpoint = node
        return response.data.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to retrieve aggregated attestation data")

proc produceSyncCommitteeContribution*(
       vc: ValidatorClientRef,
       slot: Slot,
       subcommitteeIndex: SyncSubcommitteeIndex,
       root: Eth2Digest
     ): Future[SyncCommitteeContribution] {.async.} =
  logScope: request = "produceSyncCommitteeContribution"
  vc.firstSuccessSequential(
    RestResponse[ProduceSyncCommitteeContributionResponse], OneThirdDuration,
    produceSyncCommitteeContribution(it, slot, subcommitteeIndex, root)):
    if apiResponse.isErr():
      debug "Unable to retrieve sync committee contribution data",
            endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status:
      of 200:
        debug "Received successful response", endpoint = node
        return response.data.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to retrieve sync committee contribution data")

proc publishAggregateAndProofs*(
       vc: ValidatorClientRef,
       data: seq[SignedAggregateAndProof]
     ): Future[bool] {.async.} =
  logScope: request = "publishAggregateAndProofs"
  vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                            publishAggregateAndProofs(it, data)):
    if apiResponse.isErr():
      debug "Unable to publish aggregate and proofs", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status:
      of 200:
        debug "Aggregate and proofs was sucessfully published", endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to publish aggregate and proofs")

proc publishContributionAndProofs*(
       vc: ValidatorClientRef,
       data: seq[RestSignedContributionAndProof]
     ): Future[bool] {.async.} =
  logScope: request = "publishContributionAndProofs"
  vc.firstSuccessSequential(RestPlainResponse, SlotDuration,
                            publishContributionAndProofs(it, data)):
    if apiResponse.isErr():
      debug "Unable to publish contribution and proofs", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status:
      of 200:
        debug "Contribution and proofs were successfully published",
              endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to publish contribution and proofs")

proc produceBlockV2*(
       vc: ValidatorClientRef,
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes
     ): Future[ProduceBlockResponseV2] {.async.} =
  logScope: request = "produceBlockV2"
  vc.firstSuccessSequential(RestResponse[ProduceBlockResponseV2],
                            SlotDuration,
                            produceBlockV2(it, slot, randao_reveal, graffiti)):
    if apiResponse.isErr():
      debug "Unable to retrieve block data", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status:
      of 200:
        debug "Received successful response", endpoint = node
        return response.data
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to retrieve block data")

proc publishBlock*(
       vc: ValidatorClientRef,
       data: ForkedSignedBeaconBlock
     ): Future[bool] {.async.} =
  logScope: request = "publishBlock"
  vc.firstSuccessSequential(RestPlainResponse, SlotDuration):
    case data.kind
    of BeaconBlockFork.Phase0:
      publishBlock(it, data.phase0Data)
    of BeaconBlockFork.Altair:
      publishBlock(it, data.altairData)
    of BeaconBlockFork.Bellatrix:
      publishBlock(it, data.bellatrixData)
  do:
    if apiResponse.isErr():
      debug "Unable to publish block", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status:
      of 200:
        debug "Block was successfully published", endpoint = node
        return true
      of 202:
        debug "Block not passed validation, but still published",
              endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Incompatible
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to publish block")

proc prepareBeaconCommitteeSubnet*(
       vc: ValidatorClientRef,
       data: seq[RestCommitteeSubscription]
     ): Future[bool] {.async.} =
  logScope: request = "prepareBeaconCommitteeSubnet"
  vc.firstSuccessSequential(RestPlainResponse, OneThirdDuration,
                            prepareBeaconCommitteeSubnet(it, data)):
    if apiResponse.isErr():
      debug "Unable to prepare committee subnet", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Commitee subnet was successfully prepared", endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        return false
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError, "Unable to prepare committee subnet")

proc prepareSyncCommitteeSubnets*(
       vc: ValidatorClientRef,
       data: seq[RestSyncCommitteeSubscription]
     ): Future[bool] {.async.} =
  logScope: request = "prepareSyncCommitteeSubnet"
  vc.firstSuccessSequential(RestPlainResponse, OneThirdDuration,
                            prepareSyncCommitteeSubnets(it, data)):
    if apiResponse.isErr():
      debug "Unable to prepare sync committee subnet", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Sync committee subnet was successfully prepared",
              endpoint = node
        return true
      of 400:
        debug "Received invalid request response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        return false
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline
      of 503:
        debug "Received not synced error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.NotSynced
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node,
              response_error = response.getGenericErrorMessage()
        RestBeaconNodeStatus.Offline

  raise newException(ValidatorApiError,
                     "Unable to prepare sync committee subnet")

proc getValidatorsActivity*(
       vc: ValidatorClientRef, epoch: Epoch,
       validators: seq[ValidatorIndex]
     ): Future[GetValidatorsActivityResponse] {.async.} =
  logScope: request = "getValidatorsActivity"
  let resp = vc.onceToAll(RestPlainResponse, SlotDuration,
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
                      response_error = response.getGenericErrorMessage()
                apiResponse.node.status = RestBeaconNodeStatus.Incompatible
                default
              of 500:
                debug "Server reports internal error",
                      response_code = response.status,
                      endpoint = apiResponse.node,
                      response_error = response.getGenericErrorMessage()
                apiResponse.node.status = RestBeaconNodeStatus.Offline
                default
              else:
                debug "Server reports unexpected error code",
                      response_code = response.status,
                      endpoint = apiResponse.node,
                      response_error = response.getGenericErrorMessage()
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

import chronicles
import ../spec/eth2_apis/eth2_rest_serialization,
       ../spec/datatypes/[phase0, altair]
import common, fallback_service

export eth2_rest_serialization, common

type
  ApiResponse*[T] = Result[T, string]
  ApiOperation = enum
    Success, Timeout, Failure, Interrupt

template firstSuccessTimeout*(vc: ValidatorClientRef, respType: typedesc,
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
    let onlineNodes = vc.onlineNodes()

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
            except CancelledError:
              # `allFutures()` could not cancel Futures.
              await bodyFut.cancelAndWait()
              ApiOperation.Interrupt
            except CatchableError as exc:
              # This only could happened if `allFutures()` start raise
              # exceptions.
              ApiOperation.Failure
          else:
            try:
              discard await race(bodyFut, timerFut)
              if bodyFut.finished():
                ApiOperation.Success
              else:
                await bodyFut.cancelAndWait()
                ApiOperation.Timeout
            except CancelledError:
              # `race()` could not cancel Futures.
              if not(bodyFut.finished()):
                if not(timerFut.finished()):
                  timerFut.cancel()
                await allFutures(bodyFut.cancelAndWait(), timerFut)
              else:
                await cancelAndWait(timerFut)
              ApiOperation.Interrupt
            except CatchableError as exc:
              # This only could happened if `race()` start raise exceptions.
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

    await vc.waitOnlineNodes()

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
  vc.firstSuccessTimeout(RestResponse[GetProposerDutiesResponse], SlotDuration,
                         getProposerDuties(it, epoch)):
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
  vc.firstSuccessTimeout(RestResponse[GetAttesterDutiesResponse], SlotDuration,
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
  vc.firstSuccessTimeout(RestResponse[GetSyncCommitteeDutiesResponse], SlotDuration,
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
  vc.firstSuccessTimeout(RestResponse[GetForkScheduleResponse], SlotDuration,
                         getForkSchedule(it)):
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
      of 500:
        debug "Received internal error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
      else:
        debug "Received unexpected error response",
              response_code = response.status, endpoint = node
        RestBeaconNodeStatus.Offline
  raise newException(ValidatorApiError, "Unable to retrieve fork schedule")

proc getHeadStateFork*(
       vc: ValidatorClientRef
     ): Future[Fork] {.async.} =
  logScope: request = "getHeadStateFork"
  let stateIdent = StateIdent.init(StateIdentType.Head)
  vc.firstSuccessTimeout(RestResponse[GetStateForkResponse], SlotDuration,
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
  vc.firstSuccessTimeout(RestResponse[GetBlockRootResponse], SlotDuration,
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
  vc.firstSuccessTimeout(RestResponse[GetStateValidatorsResponse], SlotDuration,
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
  vc.firstSuccessTimeout(RestResponse[ProduceAttestationDataResponse],
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
  vc.firstSuccessTimeout(RestPlainResponse, SlotDuration,
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
  vc.firstSuccessTimeout(RestPlainResponse, SlotDuration,
                         submitPoolSyncCommitteeSignatures(it, @[restData])):
    if apiResponse.isErr():
      debug "Unable to submit sync committee message", endpoint = node,
            error = apiResponse.error()
      RestBeaconNodeStatus.Offline
    else:
      let response = apiResponse.get()
      case response.status
      of 200:
        debug "Sync committee message was successfully published", endpoint = node
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

  raise newException(ValidatorApiError, "Unable to submit sync committee message")

proc getAggregatedAttestation*(
       vc: ValidatorClientRef,
       slot: Slot,
       root: Eth2Digest
     ): Future[Attestation] {.async.} =
  logScope: request = "getAggregatedAttestation"
  vc.firstSuccessTimeout(RestResponse[GetAggregatedAttestationResponse],
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
  vc.firstSuccessTimeout(RestResponse[ProduceSyncCommitteeContributionResponse],
                         OneThirdDuration,
                         produceSyncCommitteeContribution(it,
                                                          slot,
                                                          subcommitteeIndex,
                                                          root)):
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
  vc.firstSuccessTimeout(RestPlainResponse, SlotDuration,
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
  vc.firstSuccessTimeout(RestPlainResponse, SlotDuration,
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
  vc.firstSuccessTimeout(RestResponse[ProduceBlockResponseV2],
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
  vc.firstSuccessTimeout(RestPlainResponse, SlotDuration):
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
  vc.firstSuccessTimeout(RestPlainResponse, OneThirdDuration,
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
  vc.firstSuccessTimeout(RestPlainResponse, OneThirdDuration,
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

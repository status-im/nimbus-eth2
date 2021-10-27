# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  stew/results,
  chronicles,
  ./rest_utils,
  ../beacon_node

export rest_utils

logScope: topics = "rest_eventapi"

proc validateEventTopics(events: seq[EventTopic]): Result[EventTopics,
                                                          cstring] =
  const NonUniqueError = cstring("Event topics must be unique")
  var res: set[EventTopic]
  for item in events:
    case item
    of EventTopic.Head:
      if EventTopic.Head in res:
        return err(NonUniqueError)
      res.incl(EventTopic.Head)
    of EventTopic.Block:
      if EventTopic.Block in res:
        return err(NonUniqueError)
      res.incl(EventTopic.Block)
    of EventTopic.Attestation:
      if EventTopic.Attestation in res:
        return err(NonUniqueError)
      res.incl(EventTopic.Attestation)
    of EventTopic.VoluntaryExit:
      if EventTopic.VoluntaryExit in res:
        return err(NonUniqueError)
      res.incl(EventTopic.VoluntaryExit)
    of EventTopic.FinalizedCheckpoint:
      if EventTopic.FinalizedCheckpoint in res:
        return err(NonUniqueError)
      res.incl(EventTopic.FinalizedCheckpoint)
    of EventTopic.ChainReorg:
      if EventTopic.ChainReorg in res:
        return err(NonUniqueError)
      res.incl(EventTopic.ChainReorg)
    of EventTopic.ContributionAndProof:
      if EventTopic.ContributionAndProof in res:
        return err(NonUniqueError)
      res.incl(EventTopic.ContributionAndProof)
  if res == {}:
    err("Empty topics list")
  else:
    ok(res)

proc eventHandler*(response: HttpResponseRef, node: BeaconNode,
                   T: typedesc, event: string,
                   serverEvent: string) {.async.} =
  var fut = node.eventBus.waitEvent(T, event)
  while true:
    let jsonRes =
      try:
        let res = await fut
        when T is ForkedTrustedSignedBeaconBlock:
          let blockInfo = RestBlockInfo.init(res)
          some(RestApiResponse.prepareJsonStringResponse(blockInfo))
        else:
          some(RestApiResponse.prepareJsonStringResponse(res))
      except CancelledError:
        none[string]()
    if jsonRes.isNone() or (response.state != HttpResponseState.Sending):
      # Cancellation happened or connection with remote peer has been lost.
      break
    # Initiating new event waiting to avoid race conditions and event misses.
    fut = node.eventBus.waitEvent(T, event)
    # Sending event and payload over wire.
    let exitLoop =
      try:
        await response.sendEvent(serverEvent, jsonRes.get())
        false
      except CancelledError:
        true
      except HttpError as exc:
        debug "Unable to deliver event to remote peer", error_name = $exc.name,
              error_msg = $exc.msg
        true
      except CatchableError as exc:
        debug "Unexpected error encountered", error_name = $exc.name,
              error_msg = $exc.msg
        true
    if exitLoop:
      if not(fut.finished()):
        await fut.cancelAndWait()
      break

proc installEventApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Events/eventstream
  router.api(MethodGet, "/api/eth/v1/events") do (
    topics: seq[EventTopic]) -> RestApiResponse:
    let eventTopics =
      block:
        if topics.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid topics value",
                                           $topics.error())
        let res = validateEventTopics(topics.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid topics value",
                                           $res.error())
        res.get()

    let res = preferredContentType("text/event-stream")
    if res.isErr():
      return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
    if res.get() != "text/event-stream":
      return RestApiResponse.jsonError(Http500, InvalidAcceptError)

    var response = request.getResponse()
    response.keepAlive = false
    try:
      await response.prepareSSE()
    except HttpError:
      # It means that server failed to send HTTP response to the remote client
      # so there no need to respond with HTTP error response.
      return

    let handlers =
      block:
        var res: seq[Future[void]]
        if EventTopic.Head in eventTopics:
          let handler = response.eventHandler(node, HeadChangeInfoObject,
                                              "head-change", "head")
          res.add(handler)
        if EventTopic.Block in eventTopics:
          let handler = response.eventHandler(node,
                                              ForkedTrustedSignedBeaconBlock,
                                              "signed-beacon-block", "block")
          res.add(handler)
        if EventTopic.Attestation in eventTopics:
          let handler = response.eventHandler(node, Attestation,
                                              "attestation-received",
                                              "attestation")
          res.add(handler)
        if EventTopic.VoluntaryExit in eventTopics:
          let handler = response.eventHandler(node, SignedVoluntaryExit,
                                              "voluntary-exit",
                                              "voluntary_exit")
          res.add(handler)
        if EventTopic.FinalizedCheckpoint in eventTopics:
          let handler = response.eventHandler(node, FinalizationInfoObject,
                                              "finalization",
                                              "finalized_checkpoint")
          res.add(handler)
        if EventTopic.ChainReorg in eventTopics:
          let handler = response.eventHandler(node, ReorgInfoObject,
                                              "chain-reorg", "chain_reorg")
          res.add(handler)
        if EventTopic.ContributionAndProof in eventTopics:
          let handler = response.eventHandler(node, SignedContributionAndProof,
                                              "sync-contribution-and-proof",
                                              "contribution_and_proof")
          res.add(handler)
        res

    discard await one(handlers)
    # One of the handlers finished, it means that connection has been droped, so
    # we cancelling all other handlers.
    let pending =
      block:
        var res: seq[Future[void]]
        for fut in handlers:
          if not(fut.finished()):
            fut.cancel()
            res.add(fut)
        res
    await allFutures(pending)
    return

  router.redirect(
    MethodGet,
    "/eth/v1/events",
    "/api/eth/v1/events"
  )

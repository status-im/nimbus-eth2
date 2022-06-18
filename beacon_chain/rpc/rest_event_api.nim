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

proc eventHandler*[T](response: HttpResponseRef,
                      eventQueue: AsyncEventQueue[T],
                      serverEvent: string) {.async.} =
  var empty: seq[T]
  let key = eventQueue.register()

  while true:
    var exitLoop = false

    let events =
      try:
        let res = await eventQueue.waitEvents(key)
        res
      except CancelledError:
        empty

    for event in events:
      let jsonRes =
        when T is ForkedTrustedSignedBeaconBlock:
          let blockInfo = RestBlockInfo.init(event)
          RestApiResponse.prepareJsonStringResponse(blockInfo)
        else:
          RestApiResponse.prepareJsonStringResponse(event)

      exitLoop =
        if response.state != HttpResponseState.Sending:
          true
        else:
          try:
            await response.sendEvent(serverEvent, jsonRes)
            false
          except CancelledError:
            true
          except HttpError as exc:
            debug "Unable to deliver event to remote peer",
                  error_name = $exc.name, error_msg = $exc.msg
            true
          except CatchableError as exc:
            debug "Unexpected error encountered, while trying to deliver event",
                  error_name = $exc.name, error_msg = $exc.msg
            true

      if exitLoop:
        break

    if exitLoop or len(events) == 0:
      break

  eventQueue.unregister(key)

proc installEventApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Events/eventstream
  router.api(MethodGet, "/eth/v1/events") do (
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

    let res = preferredContentType(textEventStreamMediaType)
    if res.isErr():
      return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
    if res.get() != textEventStreamMediaType:
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
          let handler = response.eventHandler(node.eventBus.headQueue,
                                              "head")
          res.add(handler)
        if EventTopic.Block in eventTopics:
          let handler = response.eventHandler(node.eventBus.blocksQueue,
                                              "block")
          res.add(handler)
        if EventTopic.Attestation in eventTopics:
          let handler = response.eventHandler(node.eventBus.attestQueue,
                                              "attestation")
          res.add(handler)
        if EventTopic.VoluntaryExit in eventTopics:
          let handler = response.eventHandler(node.eventBus.exitQueue,
                                              "voluntary_exit")
          res.add(handler)
        if EventTopic.FinalizedCheckpoint in eventTopics:
          let handler = response.eventHandler(node.eventBus.finalQueue,
                                              "finalized_checkpoint")
          res.add(handler)
        if EventTopic.ChainReorg in eventTopics:
          let handler = response.eventHandler(node.eventBus.reorgQueue,
                                              "chain_reorg")
          res.add(handler)
        if EventTopic.ContributionAndProof in eventTopics:
          let handler = response.eventHandler(node.eventBus.contribQueue,
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

  # Legacy URLS - Nimbus <= 1.5.5 used to expose the REST API with an additional
  # `/api` path component
  router.redirect(
    MethodGet,
    "/api/eth/v1/events",
    "/eth/v1/events"
  )

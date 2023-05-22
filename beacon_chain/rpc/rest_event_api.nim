# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/results,
  chronicles,
  ./rest_utils,
  ../beacon_node

export rest_utils

logScope: topics = "rest_eventapi"

proc validateEventTopics(events: seq[EventTopic],
                         withLightClient: bool): Result[EventTopics, cstring] =
  const NonUniqueError = cstring("Event topics must be unique")
  const UnsupportedError = cstring("Unsupported event topic value")
  var res: set[EventTopic]
  for item in events:
    if item in res:
      return err(NonUniqueError)
    if not withLightClient and item in [
        EventTopic.LightClientFinalityUpdate,
        EventTopic.LightClientOptimisticUpdate]:
      return err(UnsupportedError)
    res.incl(item)

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
      let jsonRes =  RestApiResponse.prepareJsonStringResponse(event)

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
        let res = validateEventTopics(topics.get(),
                                      node.dag.lcDataStore.serve)
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
        if EventTopic.LightClientFinalityUpdate in eventTopics:
          doAssert node.dag.lcDataStore.serve
          let handler = response.eventHandler(node.eventBus.finUpdateQueue,
                                              "light_client_finality_update")
          res.add(handler)
        if EventTopic.LightClientOptimisticUpdate in eventTopics:
          doAssert node.dag.lcDataStore.serve
          let handler = response.eventHandler(node.eventBus.optUpdateQueue,
                                              "light_client_optimistic_update")
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

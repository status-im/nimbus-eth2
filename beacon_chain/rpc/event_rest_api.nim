# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  stew/results,
  chronicles,
  presto,
  ./eth2_json_rest_serialization, ./rest_utils,
  ../beacon_node_common

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
  if res == {}:
    err("Empty topics list")
  else:
    ok(res)

proc installEventApiHandlers*(router: var RestRouter, node: BeaconNode) =
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

    return RestApiResponse.jsonError(Http500, "Not implemented yet")

# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}


import std/[strutils, sequtils, algorithm]
import stew/base10, chronos, chronicles, results
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, forks_light_client],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../[beacon_clock, beacon_node]

proc startHybridSync*(node: BeaconNode): Future[void] {.
     async: (raises: [CancelledError]).} =
  let
    eventKey = node.eventBus.optUpdateQueue.register()
    events =
      try:
        await node.eventBus.optUpdateQueue.waitEvents(eventKey)
      except AsyncEventQueueFullError:
        raiseAssert "AsyncEventQueueFullError should not be happened"
    beaconHeader =
      withForkyOptimisticUpdate(events[^1].data):
        when lcDataFork > LightClientDataFork.None:
          forkyOptimisticUpdate.attested_header.beacon
        else:
          raiseAssert "Should not be happened"
  debug "Received beacon block header", beacon_header = shortLog(beaconHeader),
        events_count = len(events)

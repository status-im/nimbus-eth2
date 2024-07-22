# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[strutils, sequtils, algorithm]
import stew/base10, chronos, chronicles, results, nimcrypto/utils
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, forks_light_client],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../[beacon_clock, beacon_node],
  ./sync_types

export sync_types

proc getLatestBeaconHeader*(
    overseer: SyncOverseerRef
): Future[BeaconBlockHeader] {.async: (raises: [CancelledError]).} =
  let eventKey = overseer.eventQueue.register()

  defer:
    overseer.eventQueue.unregister(eventKey)

  let events =
    try:
      await overseer.eventQueue.waitEvents(eventKey)
    except CancelledError as exc:
      raise exc
    except AsyncEventQueueFullError:
      raiseAssert "AsyncEventQueueFullError should not be happened!"

  withForkyHeader(events[^1]):
    when lcDataFork > LightClientDataFork.None:
      forkyHeader.beacon
    else:
      raiseAssert "Should not be happened"

proc isBackfillEmpty(backfill: BeaconBlockSummary): bool =
  (backfill.slot == GENESIS_SLOT) and isFullZero(backfill.parent_root.data)

proc mainLoop*(
    overseer: SyncOverseerRef
): Future[void] {.async: (raises: []).} =
  if not(isBackfillEmpty(overseer.dag.backfill)):
    # Backfill is already running.
    return

  overseer.statusMsg = Opt.some("awaiting block header")
  let blockHeader =
    try:
      await overseer.getLatestBeaconHeader()
    except CancelledError:
      return
  overseer.statusMsg = Opt.none(string)

  notice "Received beacon block header",
         backfill = shortLog(overseer.dag.backfill),
         beacon_header = shortLog(blockHeader),
         current_slot = overseer.beaconClock.now().slotOrZero()

  overseer.dag.backfill =
    BeaconBlockSummary(slot: blockHeader.slot,
                       parent_root: blockHeader.parent_root)

proc start*(overseer: SyncOverseerRef) =
  overseer.loopFuture = overseer.mainLoop()

proc stop*(overseer: SyncOverseerRef) {.async: (raises: []).} =
  doAssert(not(isNil(overseer.loopFuture)),
           "SyncOverseer was not started yet")
  if not(overseer.loopFuture.finished()):
    await cancelAndWait(overseer.loopFuture)

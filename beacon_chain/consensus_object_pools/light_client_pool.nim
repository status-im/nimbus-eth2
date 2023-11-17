# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Status libraries
  chronos,
  # Beacon chain internals
  ../spec/datatypes/base

type
  LightClientPool* = object
    latestForwardedFinalitySlot*: Slot
      ## Latest finality update that was forwarded on libp2p gossip.
      ## Tracks `finality_update.finalized_header.beacon.slot`.

    latestForwardedFinalityHasSupermajority*: bool
      ## Whether or not the latest finality update that was forwarded on
      ## libp2p gossip had supermajority (> 2/3) sync committee participation.

    latestForwardedOptimisticSlot*: Slot
      ## Latest optimistic update that was forwarded on libp2p gossip.
      ## Tracks `optimistic_update.attested_header.beacon.slot`.

    latestBroadcastedSlot*: Slot
      ## Latest slot for which updates were broadcasted on libp2p gossip.
      ## Tracks `update.signature_slot`.

    broadcastGossipFut*: Future[void]
      ## Task to broadcast libp2p gossip. Started when a sync committee message
      ## is sent. Tracked separately from `handleValidatorDuties` to catch the
      ## case where `node.attachedValidators[].count == 0` at function start,
      ## and then a sync committee message gets sent from a remote VC via REST.

# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import ../datatypes/base
export base

type
  RpcNodePeer* = tuple
    peer_id: string
    enr: string
    last_seen_p2p_address: string
    state: string
    direction: string
    agent: string # This is not part of specification
    proto: string # This is not part of specification

  RpcSyncInfo* = tuple
    head_slot: Slot
    sync_distance: uint64
    is_syncing: bool

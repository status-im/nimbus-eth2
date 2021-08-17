# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  presto/client,
  "."/[rest_types, eth2_rest_serialization]

export client, rest_types, eth2_rest_serialization

proc getNetworkIdentity*(): RestResponse[GetNetworkIdentityResponse] {.
     rest, endpoint: "/eth/v1/node/identity",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getNetworkIdentity

proc getPeers*(
    state: seq[PeerStateKind],
    direction: seq[PeerDirectKind]): RestResponse[GetPeersResponse] {.
     rest, endpoint: "/eth/v1/node/peers",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getPeers

proc getPeer*(peer_id: PeerId): RestResponse[GetPeerResponse] {.
     rest, endpoint: "/eth/v1/node/peers/{peer_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getPeer

proc getPeerCount*(): RestResponse[GetPeerCountResponse] {.
     rest, endpoint: "/eth/v1/node/peer_count",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getPeerCount

proc getNodeVersion*(): RestResponse[GetVersionResponse] {.
     rest, endpoint: "/eth/v1/node/version",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getNodeVersion

proc getSyncingStatus*(): RestResponse[GetSyncingStatusResponse] {.
     rest, endpoint: "/eth/v1/node/syncing",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getSyncingStatus

proc getHealth*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/node/health",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Node/getHealth

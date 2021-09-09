# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/[options, sequtils],
  chronicles,
  json_rpc/servers/httpserver,
  eth/p2p/discoveryv5/enr,
  libp2p/[multiaddress, multicodec, peerstore],
  nimcrypto/utils as ncrutils,
  ../beacon_node_common, ../version,
  ../networking/[eth2_network, peer_pool],
  ../sync/sync_manager,
  ../spec/datatypes/base,
  ./rpc_utils

logScope: topics = "nodeapi"

type
  RpcServer = RpcHttpServer

proc validateState(state: Option[seq[string]]): Option[set[ConnectionState]] =
  var res: set[ConnectionState]
  if state.isSome():
    let states = state.get()
    for item in states:
      case item
      of "disconnected":
        if ConnectionState.Disconnected notin res:
          res.incl(ConnectionState.Disconnected)
        else:
          # `state` values should be unique
          return none(set[ConnectionState])
      of "connecting":
        if ConnectionState.Disconnected notin res:
          res.incl(ConnectionState.Connecting)
        else:
          # `state` values should be unique
          return none(set[ConnectionState])
      of "connected":
        if ConnectionState.Connected notin res:
          res.incl(ConnectionState.Connected)
        else:
          # `state` values should be unique
          return none(set[ConnectionState])
      of "disconnecting":
        if ConnectionState.Disconnecting notin res:
          res.incl(ConnectionState.Disconnecting)
        else:
          # `state` values should be unique
          return none(set[ConnectionState])
      else:
        # Found incorrect `state` string value
        return none(set[ConnectionState])

  if res == {}:
    res = {ConnectionState.Connecting, ConnectionState.Connected,
           ConnectionState.Disconnecting, ConnectionState.Disconnected}
  some(res)

proc validateDirection(direction: Option[seq[string]]): Option[set[PeerType]] =
  var res: set[PeerType]
  if direction.isSome():
    let directions = direction.get()
    for item in directions:
      case item
      of "inbound":
        if PeerType.Incoming notin res:
          res.incl(PeerType.Incoming)
        else:
          # `direction` values should be unique
          return none(set[PeerType])
      of "outbound":
        if PeerType.Outgoing notin res:
          res.incl(PeerType.Outgoing)
        else:
          # `direction` values should be unique
          return none(set[PeerType])
      else:
        # Found incorrect `direction` string value
        return none(set[PeerType])

  if res == {}:
    res = {PeerType.Incoming, PeerType.Outgoing}
  some(res)

proc toString(state: ConnectionState): string =
  case state
  of ConnectionState.Disconnected:
    "disconnected"
  of ConnectionState.Connecting:
    "connecting"
  of ConnectionState.Connected:
    "connected"
  of ConnectionState.Disconnecting:
    "disconnecting"
  else:
    ""

proc toString(direction: PeerType): string =
  case direction:
  of PeerType.Incoming:
    "inbound"
  of PeerType.Outgoing:
    "outbound"

proc getLastSeenAddress(node: BeaconNode, id: PeerId): string =
  # TODO (cheatfate): We need to provide filter here, which will be able to
  # filter such multiaddresses like `/ip4/0.0.0.0` or local addresses or
  # addresses with peer ids.
  let addrs = node.network.switch.peerStore.addressBook.get(id).toSeq()
  if len(addrs) > 0:
    $addrs[len(addrs) - 1]
  else:
    ""

proc getDiscoveryAddresses(node: BeaconNode): Option[seq[string]] =
  let restr = node.network.enrRecord().toTypedRecord()
  if restr.isErr():
    return none[seq[string]]()
  let respa = restr.get().toPeerAddr(udpProtocol)
  if respa.isErr():
    return none[seq[string]]()
  let pa = respa.get()
  let mpa = MultiAddress.init(multicodec("p2p"), pa.peerId)
  if mpa.isErr():
    return none[seq[string]]()
  var addresses = newSeqOfCap[string](len(pa.addrs))
  for item in pa.addrs:
    let resa = concat(item, mpa.get())
    if resa.isOk():
      addresses.add($(resa.get()))
  return some(addresses)

proc getP2PAddresses(node: BeaconNode): Option[seq[string]] =
  let pinfo = node.network.switch.peerInfo
  let mpa = MultiAddress.init(multicodec("p2p"), pinfo.peerId)
  if mpa.isErr():
    return none[seq[string]]()
  var addresses = newSeqOfCap[string](len(pinfo.addrs))
  for item in pinfo.addrs:
    let resa = concat(item, mpa.get())
    if resa.isOk():
      addresses.add($(resa.get()))
  return some(addresses)

proc installNodeApiHandlers*(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Defect, CatchableError].} =
  rpcServer.rpc("get_v1_node_identity") do () -> RpcNodeIdentity:
    let discoveryAddresses =
      block:
        let res = node.getDiscoveryAddresses()
        if res.isSome():
          res.get()
        else:
          newSeq[string](0)

    let p2pAddresses =
      block:
        let res = node.getP2PAddresses()
        if res.isSome():
          res.get()
        else:
          newSeq[string]()

    return (
      peer_id: $node.network.peerId(),
      enr: node.network.enrRecord().toUri(),
      p2p_addresses: p2pAddresses,
      discovery_addresses: discoveryAddresses,
      metadata: (node.network.metadata.seq_number,
                 "0x" & ncrutils.toHex(node.network.metadata.attnets.bytes))
    )

  rpcServer.rpc("get_v1_node_peers") do (state: Option[seq[string]],
                          direction: Option[seq[string]]) -> seq[RpcNodePeer]:
    var res = newSeq[RpcNodePeer]()
    let rstates = validateState(state)
    if rstates.isNone():
      raise newException(CatchableError, "Incorrect state parameter")
    let rdirs = validateDirection(direction)
    if rdirs.isNone():
      raise newException(CatchableError, "Incorrect direction parameter")
    let states = rstates.get()
    let dirs = rdirs.get()
    for peer in node.network.peers.values():
      if (peer.connectionState in states) and (peer.direction in dirs):
        let resPeer = (
          peer_id: $peer.peerId,
          enr: if peer.enr.isSome(): peer.enr.get().toUri() else: "",
          last_seen_p2p_address: getLastSeenAddress(node, peer.peerId),
          state: peer.connectionState.toString(),
          direction: peer.direction.toString(),
          agent: node.network.switch.peerStore.agentBook.get(peer.peerId),       # Fields `agent` and `proto` are not
          proto: node.network.switch.peerStore.protoVersionBook.get(peer.peerId) # part of specification
        )
        res.add(resPeer)
    return res

  rpcServer.rpc("get_v1_node_peer_count") do () -> RpcNodePeerCount:
    var res: RpcNodePeerCount
    for item in node.network.peers.values():
      case item.connectionState
      of ConnectionState.Connecting:
        inc(res.connecting)
      of ConnectionState.Connected:
        inc(res.connected)
      of ConnectionState.Disconnecting:
        inc(res.disconnecting)
      of ConnectionState.Disconnected:
        inc(res.disconnected)
      of ConnectionState.None:
        discard
    return res

  rpcServer.rpc("get_v1_node_peers_peerId") do (
    peer_id: string) -> RpcNodePeer:
    let pres = PeerID.init(peer_id)
    if pres.isErr():
      raise newException(CatchableError,
                         "The peer ID supplied could not be parsed")
    let pid = pres.get()
    let peer = node.network.peers.getOrDefault(pid)
    if isNil(peer):
      raise newException(CatchableError, "Peer not found")

    return (
      peer_id: $peer.peerId,
      enr: if peer.enr.isSome(): peer.enr.get().toUri() else: "",
      last_seen_p2p_address: getLastSeenAddress(node, peer.peerId),
      state: peer.connectionState.toString(),
      direction: peer.direction.toString(),
      agent: node.network.switch.peerStore.agentBook.get(peer.peerId),       # Fields `agent` and `proto` are not
      proto: node.network.switch.peerStore.protoVersionBook.get(peer.peerId) # part of specification
    )

  rpcServer.rpc("get_v1_node_version") do () -> JsonNode:
    return %*{"version": "Nimbus/" & fullVersionStr}

  rpcServer.rpc("get_v1_node_syncing") do () -> RpcSyncInfo:
    return node.syncManager.getInfo()

  rpcServer.rpc("get_v1_node_health") do () -> JsonNode:
    # TODO: There currently no way to situation when we node has issues, so
    # its impossible to return HTTP ERROR 503 according to specification.
    if node.syncManager.inProgress:
      # We need to return HTTP ERROR 206 according to specification
      return %*{"health": 206}
    else:
      return %*{"health": 200}

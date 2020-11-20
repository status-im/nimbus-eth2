import std/options,
  chronicles,
  json_rpc/[rpcserver, jsonmarshal],
  eth/p2p/discoveryv5/enr,
  ../beacon_node_common, ../eth2_network,
  ../peer_pool, ../version,
  ../spec/[datatypes, digest, presets],
  ../spec/eth2_apis/callsigs_types

logScope: topics = "nodeapi"

type
  RpcServer = RpcHttpServer

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

type
  RpcPeer* = object
    peer_id*: string
    enr*: string
    last_seen_p2p_address*: string
    state*: string
    direction*: string

proc validatePeerState(state: Option[seq[string]]): Option[set[ConnectionState]] =
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

proc installNodeApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("get_v1_node_identity") do () -> NodeIdentityTuple:
    return (
      peer_id: node.network.peerId(),
      enr: node.network.enrRecord(),
      # TODO rest of fields
      p2p_addresses: newSeq[MultiAddress](0),
      discovery_addresses: newSeq[MultiAddress](0),
      metadata: (0'u64, "")
    )

  rpcServer.rpc("get_v1_node_peers") do (state: Option[seq[string]],
                                direction: Option[seq[string]]) -> seq[RpcPeer]:
    var res = newSeq[RpcPeer]()
    let rstates = validatePeerState(state)
    if rstates.isNone():
      raise newException(CatchableError, "Incorrect state parameter")
    let rdirs = validateDirection(direction)
    if rdirs.isNone():
      raise newException(CatchableError, "Incorrect direction parameter")
    let states = rstates.get()
    let dirs = rdirs.get()
    for item in node.network.peers.values():
      if (item.connectionState in states) and (item.direction in dirs):
        let address =
          if len(item.info.addrs) > 0:
            $item.info.addrs[0]
          else:
            ""
        let rpeer = RpcPeer(
          peer_id: $item.info.peerId,
          enr: if item.enr.isSome(): item.enr.get().toUri() else: "",
          last_seen_p2p_address: address,
          state: item.connectionState.toString(),
          direction: item.direction.toString()
        )
        res.add(rpeer)
    return res

  rpcServer.rpc("get_v1_node_peers_peerId") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_node_version") do () -> JsonNode:
    return %{
      "version": "Nimbus/" & fullVersionStr
    }

  rpcServer.rpc("get_v1_node_syncing") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_node_health") do () -> JsonNode:
    unimplemented()

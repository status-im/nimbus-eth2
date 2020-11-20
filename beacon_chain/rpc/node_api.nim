import std/options,
  chronicles,
  json_rpc/[rpcserver, jsonmarshal],

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

proc validatePeerState(state: seq[string]): Option[set[ConnectionState]] =
  var res: set[ConnectionState]
  for item in state:
    case item
    of "disconnected":
      if ConnectionState.Disconnected notin res:
        res.incl(ConnectionState.Disconnected)
      else:
        return none(set[ConnectionState])
    of "connecting":
      if ConnectionState.Disconnected notin res:
        res.incl(ConnectionState.Connecting)
      else:
        return none(set[ConnectionState])
    of "connected":
      if ConnectionState.Connected notin res:
        res.incl(ConnectionState.Connected)
      else:
        return none(set[ConnectionState])
    of "disconnecting":
      if ConnectionState.Disconnecting notin res:
        res.incl(ConnectionState.Disconnecting)
      else:
        return none(set[ConnectionState])
    else:
      return none(set[ConnectionState])

  if res == {}:
    res = {ConnectionState.Connecting, ConnectionState.Connected,
           ConnectionState.Disconnecting, ConnectionState.Disconnected}
  some(res)

proc toString*(state: ConnectionState): string =
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

  rpcServer.rpc("get_v1_node_peers") do () -> seq[RpcPeer]:
    unimplemented()

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

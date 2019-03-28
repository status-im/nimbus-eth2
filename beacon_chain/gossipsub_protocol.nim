import
  tables, sets, macros, base64,
  chronos, nimcrypto/sysrand, chronicles, json_serialization,
  eth/[p2p, rlp, async_utils], eth/p2p/[rlpx, peer_pool],
  spec/[datatypes, crypto],
  tracing/stacktraces

type
  TopicMsgHandler = proc (msg: string)

  GossipSubPeer* = ref object
    sentMessages: HashSet[string]
    subscribedFor: HashSet[string]

  GossipSubNetwork* = ref object
    topicSubscribers: Table[string, TopicMsgHandler]
    handledMessages: HashSet[string]

proc initProtocolState*(network: GossipSubNetwork, _: EthereumNode) =
  network.topicSubscribers = initTable[string, TopicMsgHandler]()
  network.handledMessages = initSet[string]()

proc initProtocolState*(peer: GossipSubPeer, _: Peer) =
  peer.sentMessages = initSet[string]()
  peer.subscribedFor = initSet[string]()

proc trySubscribing(peer: Peer, topic: string) {.gcsafe.}
proc tryEmitting(peer: Peer, topic: string,
                 msgId: string, msg: string): Future[void] {.gcsafe.}

p2pProtocol GossipSub(version = 1,
                      shortName = "gss",
                      peerState = GossipSubPeer,
                      networkState = GossipSubNetwork):
  # This is a very barebones emulation of the GossipSub protocol
  # available in LibP2P:

  onPeerConnected do (peer: Peer):
    info "GossipSub Peer connected", peer
    let gossipNet = peer.networkState
    for topic, _ in gossipNet.topicSubscribers:
      peer.trySubscribing(topic)

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason):
    info "GossipSub Peer disconnected", peer, reason

  proc subscribeFor(peer: Peer, topic: string) =
    peer.state.subscribedFor.incl topic

  proc emit(peer: Peer, topic: string, msgId: string, msg: string) =
    if msgId in peer.networkState.handledMessages:
      trace "Ignored previously handled message", msgId
      return

    peer.networkState.handledMessages.incl msgId

    for p in peer.network.peers(GossipSub):
      if msgId notin p.state.sentMessages and topic in p.state.subscribedFor:
        p.state.sentMessages.incl msgId
        traceAsyncErrors p.tryEmitting(topic, msgId, msg)

    {.gcsafe.}:
      let handler = peer.networkState.topicSubscribers.getOrDefault(topic)
      if handler != nil:
        handler(msg)

proc trySubscribing(peer: Peer, topic: string) =
  var fut = peer.subscribeFor(topic)
  fut.addCallback do (arg: pointer):
    if fut.failed:
      debug "Failed to subscribe to topic with GossipSub peer", topic, peer

proc tryEmitting(peer: Peer, topic: string,
                 msgId: string, msg: string): Future[void] =
  var fut = peer.emit(topic, msgId, msg)
  fut.addCallback do (arg: pointer):
    if fut.failed:
      debug "GossipSub message not delivered to Peer", peer
  return fut

proc subscribe*[MsgType](node: EthereumNode,
                         topic: string,
                         userHandler: proc(msg: MsgType)) {.async.}=
  var gossipNet = node.protocolState(GossipSub)
  gossipNet.topicSubscribers[topic] = proc (msg: string) =
    userHandler Json.decode(msg, MsgType)

  for peer in node.peers(GossipSub):
    peer.trySubscribing(topic)

proc broadcast*(node: EthereumNode, topic: string, msg: auto) =
  var randBytes: array[10, byte];
  if randomBytes(randBytes) != 10:
    warn "Failed to generate random message id"

  let msg = Json.encode(msg)
  let msgId = base64.encode(randBytes)
  trace "Sending GossipSub message", msgId

  for peer in node.peers(GossipSub):
    if topic in peer.state(GossipSub).subscribedFor:
      traceAsyncErrors peer.tryEmitting(topic, msgId, msg)


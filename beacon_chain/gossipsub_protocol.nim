import
  tables, sets, macros, base64,
  asyncdispatch2, nimcrypto/sysrand, chronicles, rlp, eth_p2p, eth_p2p/rlpx

type
  TopicMsgHandler = proc(data: seq[byte]): Future[void]

  GossibSubPeer = ref object
    sentMessages: HashSet[string]
    subscribedFor: HashSet[string]

  GossipSubNetwork = ref object
    topicSubscribers: Table[string, TopicMsgHandler]

proc initProtocolState*(network: GossipSubNetwork, node: EthereumNode) =
  network.topicSubscribers = initTable[string, TopicMsgHandler]()

proc initProtocolState*(peer: GossibSubPeer, node: EthereumNode) =
  peer.sentMessages = initSet[string]()
  peer.subscribedFor = initSet[string]()

p2pProtocol GossipSub(version = 1,
                      shortName = "gss",
                      peerState = GossibSubPeer,
                      networkState = GossipSubNetwork):
  # This is a very barebones emulation of the GossipSub protocol
  # available in LibP2P:

  proc subscribeFor(peer: Peer, topic: string) =
    peer.state.subscribedFor.incl topic

  proc emit(peer: Peer, topic: string, msgId: string, data: openarray[byte]) =
    for p in peer.network.peers(GossipSub):
      if msgId notin p.state.sentMessages and topic in p.state.subscribedFor:
        asyncCheck p.emit(topic, msgId, data)

    let handler = peer.networkState.topicSubscribers.getOrDefault(topic)
    if handler != nil:
      await handler(data)

proc subscribeImpl(node: EthereumNode,
                   topic: string,
                   subscriber: TopicMsgHandler) =
  var gossipNet = node.protocolState(GossipSub)
  gossipNet.topicSubscribers[topic] = subscriber
  for peer in node.peers(GossipSub): discard peer.subscribeFor(topic)

proc broadcastImpl(node: EthereumNode, topic: string, msgBytes: seq[byte]): seq[Future[void]] {.gcsafe.} =
  var randBytes: array[10, byte];
  if randomBytes(randBytes) != 10:
    warn "Failed to generate random message id"
  let msgId = base64.encode(randBytes)

  for peer in node.peers(GossipSub):
    if topic in peer.state(GossipSub).subscribedFor:
      result.add peer.emit(topic, msgId, msgBytes)

proc makeMessageHandler[MsgType](userHandler: proc(msg: MsgType): Future[void]): TopicMsgHandler =
  result = proc (data: seq[byte]): Future[void] =
    userHandler rlp.decode(data, MsgType)

macro subscribe*(node: EthereumNode, topic: string, handler: untyped): untyped =
  handler.addPragma ident"async"
  result = newCall(bindSym"subscribeImpl",
                   node, topic, newCall(bindSym"makeMessageHandler", handler))

proc broadcast*(node: EthereumNode, topic: string, data: auto) {.async.} =
  await all(node.broadcastImpl(topic, rlp.encode(data)))


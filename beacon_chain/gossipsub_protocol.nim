import
  tables, sets,
  asyncdispatch2, chronicles, rlp, eth_p2p, eth_p2p/rlpx

type
  TopicMsgHandler = proc(data: seq[byte]): Future[void]

  GossibSubPeer = ref object
    sentMessages: HashSet[string]

  GossipSubNetwork = ref object
    deliveredMessages: Table[Peer, HashSet[string]]
    topicSubscribers: Table[string, seq[TopicMsgHandler]]

p2pProtocol GossipSub(version = 1,
                      shortName = "gss",
                      peerState = GossibSubPeer,
                      networkState = GossipSubNetwork):
  # This is a very barebones emulation of the GossipSub protocol
  # available in LibP2P:

  proc interestedIn(peer: Peer, topic: string)
  proc emit(peer: Peer, topic: string, msgId: string, data: openarray[byte])

proc subscribeImpl(node: EthereumNode,
                   topic: string,
                   subscriber: TopicMsgHandler) =
  discard

proc broadcastImpl(node: EthereumNode, topic: string, data: seq[byte]) =
  discard

macro subscribe*(node: EthereumNode, topic: string, handler: untyped): untyped =
  discard

proc broadcast*(node: EthereumNode, topic: string, data: auto) {.async.} =
  discard


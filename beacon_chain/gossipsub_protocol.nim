import
  tables, sets,
  eth_p2p, eth_p2p/rlpx

type
  TopicMsgHandler = proc(data: seq[byte]): Future[void]

  GossipSubNetwork = type
    deliveredMessages: Table[Peer, HashSet[string]]
    topicSubscribers: Table[string, seq[TopicMsgHandler]]

protocol GossipSub(version = 1):
  # This is a very barebones emulation of the GossipSub protocol
  # available in LibP2P:

  proc interestedIn(topic: string)
  proc emit(topic: string, msgId: string, data: openarray[byte])

proc subscribeImpl(node: EthereumNode,
                   topic: string,
                   subscriber: TopicMsgHandler) =
  discard

proc broadcastImpl(node: EthereumNode, topic: string, data: seq[byte]) =
  discard

macro subscribe*(node: EthereumNode, topic: string, handler: body): untyped =
  discard

proc broadcast*(node: EthereumNode, topic: string, data: auto) =
  discard


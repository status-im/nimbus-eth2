# included from libp2p_backend

proc `$`*(peer: Peer): string = $peer.id

proc init*(T: type Peer, network: Eth2Node, id: PeerID): Peer {.gcsafe.}

proc getPeer*(node: Eth2Node, peerId: PeerID): Peer {.gcsafe.} =
  result = node.peers.getOrDefault(peerId)
  if result == nil:
    result = Peer.init(node, peerId)
    node.peers[peerId] = result

proc peerFromStream(daemon: DaemonAPI, stream: P2PStream): Peer {.gcsafe.} =
  Eth2Node(daemon.userData).getPeer(stream.peer)

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.daemon.disconnect(peer.id)
    peer.connectionState = Disconnected
    peer.network.peers.del(peer.id)

template raisePeerDisconnected(msg: string, r: DisconnectionReason) =
  var e = newException(PeerDisconnected, msg)
  e.reason = r
  raise e

proc disconnectAndRaise(peer: Peer,
                        reason: DisconnectionReason,
                        msg: string) {.async.} =
  let r = reason
  await peer.disconnect(r)
  raisePeerDisconnected(msg, r)

template reraiseAsPeerDisconnected(peer: Peer, errMsgExpr: static string,
                                   reason = FaultOrError): auto =
  const errMsg = errMsgExpr
  debug errMsg, err = getCurrentExceptionMsg()
  disconnectAndRaise(peer, reason, errMsg)

proc getCompressedMsgId*(MsgType: type): CompressedMsgId =
  mixin msgId, msgProtocol, protocolInfo
  (protocolIdx: MsgType.msgProtocol.protocolInfo.index,
   methodId: MsgType.msgId)

proc nextMsg*(peer: Peer, MsgType: type): Future[MsgType] =
  ## This procs awaits a specific P2P message.
  ## Any messages received while waiting will be dispatched to their
  ## respective handlers. The designated message handler will also run
  ## to completion before the future returned by `nextMsg` is resolved.
  let awaitedMsgId = getCompressedMsgId(MsgType)
  let f = getOrDefault(peer.awaitedMessages, awaitedMsgId)
  if not f.isNil:
    return Future[MsgType](f)

  initFuture result
  peer.awaitedMessages[awaitedMsgId] = result


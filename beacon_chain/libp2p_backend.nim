import
  algorithm, typetraits,
  stew/[varints,base58], stew/shims/[macros, tables], chronos, chronicles,
  faststreams/output_stream, serialization,
  json_serialization/std/options, eth/p2p/p2p_protocol_dsl,
  # TODO: create simpler to use libp2p modules that use re-exports
  libp2p/[switch, multistream, connection,
          multiaddress, peerinfo, peer,
          crypto/crypto, protocols/identify, protocols/protocol],
  libp2p/muxers/mplex/[mplex, types],
  libp2p/protocols/secure/[secure, secio],
  libp2p/protocols/pubsub/[pubsub, floodsub],
  libp2p/transports/[transport, tcptransport],
  libp2p_json_serialization, ssz

export
  p2pProtocol, libp2p_json_serialization, ssz

type
  P2PStream = Connection

  # TODO Is this really needed?
  Eth2Node* = ref object of RootObj
    switch*: Switch
    peers*: Table[PeerID, Peer]
    protocolStates*: seq[RootRef]
    libp2pTransportLoops*: seq[Future[void]]

  EthereumNode = Eth2Node # needed for the definitions in p2p_backends_helpers

  Peer* = ref object
    network*: Eth2Node
    info*: PeerInfo
    wasDialed*: bool
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    maxInactivityAllowed*: Duration

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  UntypedResponder = object
    peer*: Peer
    stream*: P2PStream

  Responder*[MsgType] = distinct UntypedResponder

  MessageInfo* = object
    name*: string

    # Private fields:
    libp2pCodecName: string
    protocolMounter*: MounterProc
    printer*: MessageContentPrinter
    nextMsgResolver*: NextMsgResolver

  ProtocolInfoObj* = object
    name*: string
    messages*: seq[MessageInfo]
    index*: int # the position of the protocol in the
                # ordered list of supported protocols

    # Private fields:
    peerStateInitializer*: PeerStateInitializer
    networkStateInitializer*: NetworkStateInitializer
    handshake*: HandshakeStep
    disconnectHandler*: DisconnectionHandler

  ProtocolInfo* = ptr ProtocolInfoObj

  PeerStateInitializer* = proc(peer: Peer): RootRef {.gcsafe.}
  NetworkStateInitializer* = proc(network: EthereumNode): RootRef {.gcsafe.}
  HandshakeStep* = proc(peer: Peer, stream: P2PStream): Future[void] {.gcsafe.}
  DisconnectionHandler* = proc(peer: Peer): Future[void] {.gcsafe.}
  ThunkProc* = LPProtoHandler
  MounterProc* = proc(network: Eth2Node) {.gcsafe.}
  MessageContentPrinter* = proc(msg: pointer): string {.gcsafe.}
  NextMsgResolver* = proc(msgData: SszReader, future: FutureBase) {.gcsafe.}

  DisconnectionReason* = enum
    ClientShutDown
    IrrelevantNetwork
    FaultOrError

  PeerDisconnected* = object of CatchableError
    reason*: DisconnectionReason

  TransmissionError* = object of CatchableError

template `$`*(peer: Peer): string = id(peer.info)
chronicles.formatIt(Peer): $it

# TODO: This exists only as a compatibility layer between the daemon
# APIs and the native LibP2P ones. It won't be necessary once the
# daemon is removed.
#
template writeAllBytes(stream: P2PStream, bytes: seq[byte]): untyped =
  write(stream, bytes)

template openStream(node: Eth2Node, peer: Peer, protocolId: string): untyped =
  dial(node.switch, peer.info, protocolId)

proc peer(stream: P2PStream): PeerID =
  # TODO: Can this be `none`?
  stream.peerInfo.get.peerId
#
# End of compatibility layer

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer {.gcsafe.}

proc getPeer*(node: Eth2Node, peerInfo: PeerInfo): Peer {.gcsafe.} =
  let peerId = peerInfo.peerId
  result = node.peers.getOrDefault(peerId)
  if result == nil:
    result = Peer.init(node, peerInfo)
    node.peers[peerId] = result

proc peerFromStream(network: Eth2Node, stream: P2PStream): Peer {.gcsafe.} =
  # TODO: Can this be `none`?
  return network.getPeer(stream.peerInfo.get)

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.async.} =
  # TODO: How should we notify the other peer?
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    await peer.network.switch.disconnect(peer.info)
    peer.connectionState = Disconnected
    peer.network.peers.del(peer.info.peerId)

proc safeClose(stream: P2PStream) {.async.} =
  if not stream.closed:
    await close(stream)

include eth/p2p/p2p_backends_helpers
include eth/p2p/p2p_tracing
include libp2p_backends_common

proc init*(T: type Eth2Node, switch: Switch): T =
  new result
  result.switch = switch
  result.peers = initTable[PeerID, Peer]()

  newSeq result.protocolStates, allProtocols.len
  for proto in allProtocols:
    if proto.networkStateInitializer != nil:
      result.protocolStates[proto.index] = proto.networkStateInitializer(result)

    for msg in proto.messages:
      if msg.protocolMounter != nil:
        msg.protocolMounter result

proc start*(node: Eth2Node) {.async.} =
  node.libp2pTransportLoops = await node.switch.start()

proc init*(T: type Peer, network: Eth2Node, info: PeerInfo): Peer =
  new result
  result.info = info
  result.network = network
  result.connectionState = Connected
  result.maxInactivityAllowed = 15.minutes # TODO: Read this from the config
  newSeq result.protocolStates, allProtocols.len
  for i in 0 ..< allProtocols.len:
    let proto = allProtocols[i]
    if proto.peerStateInitializer != nil:
      result.protocolStates[i] = proto.peerStateInitializer(result)

proc registerMsg(protocol: ProtocolInfo,
                 name: string,
                 mounter: MounterProc,
                 libp2pCodecName: string,
                 printer: MessageContentPrinter) =
  protocol.messages.add MessageInfo(name: name,
                                    protocolMounter: mounter,
                                    libp2pCodecName: libp2pCodecName,
                                    printer: printer)

proc p2pProtocolBackendImpl*(p: P2PProtocol): Backend =
  var
    Format = ident "SSZ"
    Responder = bindSym "Responder"
    P2PStream = bindSym "P2PStream"
    OutputStream = bindSym "OutputStream"
    Peer = bindSym "Peer"
    Eth2Node = bindSym "Eth2Node"
    messagePrinter = bindSym "messagePrinter"
    milliseconds = bindSym "milliseconds"
    registerMsg = bindSym "registerMsg"
    initProtocol = bindSym "initProtocol"
    bindSymOp = bindSym "bindSym"
    errVar = ident "err"
    msgVar = ident "msg"
    msgBytesVar = ident "msgBytes"
    networkVar = ident "network"
    await = ident "await"
    callUserHandler = ident "callUserHandler"

  p.useRequestIds = false
  p.useSingleRecordInlining = true

  new result

  result.PeerType = Peer
  result.NetworkType = Eth2Node
  result.registerProtocol = bindSym "registerProtocol"
  result.setEventHandlers = bindSym "setEventHandlers"
  result.SerializationFormat = Format
  result.ResponderType = Responder

  result.afterProtocolInit = proc (p: P2PProtocol) =
    p.onPeerConnected.params.add newIdentDefs(streamVar, P2PStream)

  result.implementMsg = proc (msg: Message) =
    let
      protocol = msg.protocol
      msgName = $msg.ident
      msgNameLit = newLit msgName
      MsgRecName = msg.recName
      codecNameLit = getRequestProtoName(msg.procDef)

    if msg.procDef.body.kind != nnkEmpty and msg.kind == msgRequest:
      # Request procs need an extra param - the stream where the response
      # should be written:
      msg.userHandler.params.insert(2, newIdentDefs(streamVar, P2PStream))
      msg.initResponderCall.add streamVar

    ##
    ## Implement the Thunk:
    ##
    ## The protocol handlers in nim-libp2p receive only a `P2PStream`
    ## parameter and there is no way to access the wider context (such
    ## as the current `Switch`). In our handlers, we may need to list all
    ## peers in the current network, so we must keep a reference to the
    ## network object in the closure environment of the installed handlers.
    ##
    ## For this reason, we define a `protocol mounter` proc that will
    ## initialize the network object by creating handlers bound to the
    ## specific network.
    ##
    let
      protocolMounterName = ident(msgName & "_mounter")
      userHandlerCall = msg.genUserHandlerCall(msgVar, [peerVar, streamVar])

    var mounter: NimNode
    if msg.userHandler != nil:
      protocol.outRecvProcs.add quote do:
        template `callUserHandler`(`peerVar`: `Peer`,
                                   `streamVar`: `P2PStream`,
                                   `msgVar`: `MsgRecName`): untyped =
          `userHandlerCall`

        proc `protocolMounterName`(`networkVar`: `Eth2Node`) =
          proc thunk(`streamVar`: `P2PStream`,
                      proto: string): Future[void] {.gcsafe.} =
            return handleIncomingStream(`networkVar`, `streamVar`,
                                        `MsgRecName`, `Format`)

          mount `networkVar`.switch,
                LPProtocol(codec: `codecNameLit`, handler: thunk)

      mounter = protocolMounterName
    else:
      mounter = newNilLit()

    ##
    ## Implement Senders and Handshake
    ##
    if msg.kind == msgHandshake:
      macros.error "Handshake messages are not supported in LibP2P protocols"
    else:
      var sendProc = msg.createSendProc()
      implementSendProcBody sendProc

    protocol.outProcRegistrations.add(
      newCall(registerMsg,
              protocol.protocolInfoVar,
              msgNameLit,
              mounter,
              codecNameLit,
              newTree(nnkBracketExpr, messagePrinter, MsgRecName)))

  result.implementProtocolInit = proc (p: P2PProtocol): NimNode =
    return newCall(initProtocol, newLit(p.name), p.peerInit, p.netInit)


import
  options, tables,
  chronos, json_serialization, strutils, chronicles, metrics, eth/net/nat,
  version, conf

const
  clientId* = "Nimbus beacon node v" & fullVersionStr

export
  version

let
  globalListeningAddr = parseIpAddress("0.0.0.0")

# Metrics for tracking attestation and beacon block loss
declareCounter gossip_messages_sent,
  "Number of gossip messages sent by this peer"

declareCounter gossip_messages_received,
  "Number of gossip messages received by this peer"

proc setupNat(conf: BeaconNodeConf): tuple[ip: IpAddress,
                                           tcpPort: Port,
                                           udpPort: Port] =
  # defaults
  result.ip = globalListeningAddr
  result.tcpPort = Port(conf.tcpPort)
  result.udpPort = Port(conf.udpPort)

  var nat: NatStrategy
  case conf.nat.toLowerAscii:
    of "any":
      nat = NatAny
    of "none":
      nat = NatNone
    of "upnp":
      nat = NatUpnp
    of "pmp":
      nat = NatPmp
    else:
      if conf.nat.startsWith("extip:") and isIpAddress(conf.nat[6..^1]):
        # any required port redirection is assumed to be done by hand
        result.ip = parseIpAddress(conf.nat[6..^1])
        nat = NatNone
      else:
        error "not a valid NAT mechanism, nor a valid IP address", value = conf.nat
        quit(QuitFailure)

  if nat != NatNone:
    let extIP = getExternalIP(nat)
    if extIP.isSome:
      result.ip = extIP.get()
      let extPorts = redirectPorts(tcpPort = result.tcpPort,
                                   udpPort = result.udpPort,
                                   description = clientId)
      if extPorts.isSome:
        (result.tcpPort, result.udpPort) = extPorts.get()

when networkBackend == rlpxBackend:
  import
    os,
    eth/[rlp, p2p, keys], gossipsub_protocol,
    eth/p2p/peer_pool # for log on connected peers

  export
    p2p, rlp, gossipsub_protocol

  const
    netBackendName* = "rlpx"
    IrrelevantNetwork* = UselessPeer

  type
    Eth2Node* = EthereumNode
    Eth2NodeIdentity* = KeyPair
    BootstrapAddr* = ENode

  proc getPersistentNetIdentity*(conf: BeaconNodeConf): Eth2NodeIdentity =
    let privateKeyFile = conf.dataDir / "network.privkey"
    var privKey: PrivateKey
    if not fileExists(privateKeyFile):
      privKey = newPrivateKey()
      createDir conf.dataDir.string
      writeFile(privateKeyFile, $privKey)
    else:
      privKey = initPrivateKey(readFile(privateKeyFile).string)

    KeyPair(seckey: privKey, pubkey: privKey.getPublicKey())

  proc getPersistenBootstrapAddr*(conf: BeaconNodeConf,
                                  ip: IpAddress, port: Port): BootstrapAddr =
    let
      identity = getPersistentNetIdentity(conf)
      address = Address(ip: ip, tcpPort: port, udpPort: port)

    initENode(identity.pubKey, address)

  proc isSameNode*(bootstrapNode: BootstrapAddr, id: Eth2NodeIdentity): bool =
    bootstrapNode.pubKey == id.pubKey

  proc shortForm*(id: Eth2NodeIdentity): string =
    ($id.pubKey)[0..5]

  proc writeValue*(writer: var JsonWriter, value: BootstrapAddr) {.inline.} =
    writer.writeValue $value

  proc readValue*(reader: var JsonReader, value: var BootstrapAddr) {.inline.} =
    value = initENode reader.readValue(string)

  proc createEth2Node*(conf: BeaconNodeConf,
                       bootstrapNodes: seq[BootstrapAddr]): Future[EthereumNode] {.async.} =
    let
      keys = getPersistentNetIdentity(conf)
      (ip, tcpPort, udpPort) = setupNat(conf)
      address = Address(ip: ip,
                        tcpPort: tcpPort,
                        udpPort: udpPort)

    # TODO there are more networking options to add here: local bind ip, ipv6
    #      etc.
    return newEthereumNode(keys, address, 0,
                           nil, clientId)

  proc saveConnectionAddressFile*(node: Eth2Node, filename: string) =
    writeFile(filename, $node.listeningAddress)

  proc initAddress*(T: type BootstrapAddr, str: string): T =
    initENode(str)

  func peersCount*(node: Eth2Node): int =
    node.peerPool.len

else:
  import
    os, random,
    stew/io, eth/async_utils, libp2p/crypto/crypto,
    ssz

  when networkBackend == libp2pBackend:
    import
      libp2p_backend

    export
      libp2p_backend

  else:
    import
      libp2p/daemon/daemonapi, libp2p/multiaddress, libp2p_daemon_backend

    export
      libp2p_daemon_backend

  const
    netBackendName* = "libp2p"
    networkKeyFilename = "privkey.protobuf"

  type
    BootstrapAddr* = MultiAddress
    Eth2NodeIdentity* = KeyPair

  proc initAddress*(T: type BootstrapAddr, str: string): T =
    let address = MultiAddress.init(str)
    if IPFS.match(address) and matchPartial(multiaddress.TCP, address):
      result = address
    else:
      raise newException(MultiAddressError,
                         "Invalid bootstrap node multi-address")

  proc ensureNetworkIdFile(conf: BeaconNodeConf): string =
    result = conf.dataDir / networkKeyFilename
    if not fileExists(result):
      createDir conf.dataDir.string
      let pk = PrivateKey.random(Secp256k1)
      writeFile(result, pk.getBytes)

  proc getPersistentNetIdentity*(conf: BeaconNodeConf): Eth2NodeIdentity =
    let privateKeyFile = conf.dataDir / networkKeyFilename
    var privKey: PrivateKey
    if not fileExists(privateKeyFile):
      createDir conf.dataDir.string
      privKey = PrivateKey.random(Secp256k1)
      writeFile(privateKeyFile, privKey.getBytes())
    else:
      let strdata = readFile(privateKeyFile)
      privKey = PrivateKey.init(cast[seq[byte]](strdata))

    result = KeyPair(seckey: privKey, pubkey: privKey.getKey())

  template tcpEndPoint(address, port): auto =
    MultiAddress.init(address, Protocol.IPPROTO_TCP, port)

  var mainDaemon: DaemonAPI

  proc allMultiAddresses(nodes: seq[BootstrapAddr]): seq[string] =
    for node in nodes:
      result.add $node

  proc createEth2Node*(conf: BeaconNodeConf,
                       bootstrapNodes: seq[BootstrapAddr]): Future[Eth2Node] {.async.} =
    var
      (extIp, extTcpPort, extUdpPort) = setupNat(conf)
      hostAddress = tcpEndPoint(globalListeningAddr, Port conf.tcpPort)
      announcedAddresses = if extIp == globalListeningAddr: @[]
                           else: @[tcpEndPoint(extIp, extTcpPort)]
      keyFile = conf.ensureNetworkIdFile

    info "Starting the LibP2P daemon", hostAddress, announcedAddresses,
                                       keyFile, bootstrapNodes

    var daemonFut = if bootstrapNodes.len == 0:
      newDaemonApi({PSNoSign, DHTFull, PSFloodSub},
                   id = keyFile,
                   hostAddresses = @[hostAddress],
                   announcedAddresses = announcedAddresses)
    else:
      newDaemonApi({PSNoSign, DHTFull, PSFloodSub, WaitBootstrap},
                   id = keyFile,
                   hostAddresses = @[hostAddress],
                   announcedAddresses = announcedAddresses,
                   bootstrapNodes = allMultiAddresses(bootstrapNodes),
                   peersRequired = 1)

    mainDaemon = await daemonFut
    var identity = await mainDaemon.identity()

    info "LibP2P daemon started", peer = identity.peer.pretty(),
                                  addresses = identity.addresses

    proc closeDaemon() {.noconv.} =
      info "Shutting down the LibP2P daemon"
      waitFor mainDaemon.close()
    addQuitProc(closeDaemon)

    return await Eth2Node.init(mainDaemon)

  proc getPersistenBootstrapAddr*(conf: BeaconNodeConf,
                                  ip: IpAddress, port: Port): BootstrapAddr =
    let pair = getPersistentNetIdentity(conf)
    let pidma = MultiAddress.init(multiCodec("p2p"), PeerID.init(pair.pubkey))
    result = tcpEndPoint(ip, port) & pidma

  proc isSameNode*(bootstrapNode: BootstrapAddr, id: Eth2NodeIdentity): bool =
    if IPFS.match(bootstrapNode):
      let pid1 = PeerID.init(bootstrapNode[2].protoAddress())
      let pid2 = PeerID.init(id.pubkey)
      result = (pid1 == pid2)

  proc shortForm*(id: Eth2NodeIdentity): string =
    $PeerID.init(id.pubkey)

  proc connectToNetwork*(node: Eth2Node,
                         bootstrapNodes: seq[MultiAddress]) {.async.} =
    # TODO: perhaps we should do these in parallel
    var connected = false
    for bootstrapNode in bootstrapNodes:
      try:
        if IPFS.match(bootstrapNode):
          let pid = PeerID.init(bootstrapNode[2].protoAddress())
          await node.daemon.connect(pid, @[bootstrapNode[0] & bootstrapNode[1]])
          var peer = node.getPeer(pid)
          peer.wasDialed = true
          await initializeConnection(peer)
          connected = true
        else:
          raise newException(CatchableError, "Incorrect bootstrap address")
      except CatchableError as err:
        error "Failed to connect to bootstrap node",
               node = bootstrapNode, err = err.msg

    if bootstrapNodes.len > 0 and connected == false:
      fatal "Failed to connect to any bootstrap node. Quitting."
      quit 1

  proc saveConnectionAddressFile*(node: Eth2Node, filename: string) =
    let id = waitFor node.daemon.identity()
    Json.saveFile(filename, id, pretty = false)

  proc loadConnectionAddressFile*(filename: string): PeerInfo =
    Json.loadFile(filename, PeerInfo)

  func peersCount*(node: Eth2Node): int =
    node.peers.len

  proc makeMessageHandler[MsgType](msgHandler: proc(msg: MsgType) {.gcsafe.}): P2PPubSubCallback =
    result = proc(api: DaemonAPI,
                  ticket: PubsubTicket,
                  msg: PubSubMessage): Future[bool] {.async, gcsafe.} =
      inc gossip_messages_received
      trace "Incoming gossip bytes",
        peer = msg.peer, len = msg.data.len, tops = msg.topics
      msgHandler SSZ.decode(msg.data, MsgType)
      return true

  proc subscribe*[MsgType](node: Eth2Node,
                           topic: string,
                           msgHandler: proc(msg: MsgType) {.gcsafe.} ) {.async, gcsafe.} =
    discard await node.daemon.pubsubSubscribe(topic, makeMessageHandler(msgHandler))

  proc broadcast*(node: Eth2Node, topic: string, msg: auto) =
    inc gossip_messages_sent
    traceAsyncErrors node.daemon.pubsubPublish(topic, SSZ.encode(msg))

  # TODO:
  # At the moment, this is just a compatiblity shim for the existing RLPx functionality.
  # The filtering is not implemented properly yet.
  iterator randomPeers*(node: Eth2Node, maxPeers: int, Protocol: type): Peer =
    var peers = newSeq[Peer]()
    for _, peer in pairs(node.peers): peers.add peer
    shuffle peers
    if peers.len > maxPeers: peers.setLen(maxPeers)
    for p in peers: yield p

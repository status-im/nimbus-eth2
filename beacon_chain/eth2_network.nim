import
  options, tables,
  chronos, json_serialization, strutils, chronicles, eth/net/nat,
  spec/digest, version, conf

const
  clientId = "Nimbus beacon node v" & fullVersionStr()

export
  version

let
  globalListeningAddr = parseIpAddress("0.0.0.0")

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

  proc init*(T: type BootstrapAddr, str: string): T =
    initENode(str)

  func peersCount*(node: Eth2Node): int =
    node.peerPool.len

else:
  import
    os, random, stew/io,
    libp2p/crypto/crypto, libp2p/daemon/daemonapi, eth/async_utils,
    ssz, libp2p_backend

  export
    libp2p_backend

  const
    netBackendName* = "libp2p"
    networkKeyFilename = "privkey.protobuf"

  type
    BootstrapAddr* = PeerInfo
    Eth2NodeIdentity* = PeerInfo

  proc init*(T: type BootstrapAddr, str: string): T =
    Json.decode(str, PeerInfo)

  proc ensureNetworkIdFile(conf: BeaconNodeConf): string =
    result = conf.dataDir / networkKeyFilename
    if not fileExists(result):
      createDir conf.dataDir.string
      let pk = PrivateKey.random(Secp256k1)
      writeFile(result, pk.getBytes)

  proc getPersistentNetIdentity*(conf: BeaconNodeConf): Eth2NodeIdentity =
    # Using waitFor here is reasonable, because this proc is needed only
    # prior to connecting to the network. The RLPx alternative reads from
    # file and it's much easier to use if it's not async.
    # TODO: revisit in the future when we have our own Lib2P2 implementation.
    let daemon = waitFor newDaemonApi(id = conf.ensureNetworkIdFile)
    result = waitFor daemon.identity()
    waitFor daemon.close()

  template tcpEndPoint(address, port): auto =
    MultiAddress.init(address, Protocol.IPPROTO_TCP, port)

  var mainDaemon: DaemonAPI

  proc allMultiAddresses(nodes: seq[BootstrapAddr]): seq[string] =
    for node in nodes:
      for a in node.addresses:
        result.add $a & "/ipfs/" & node.peer.pretty()

  proc createEth2Node*(conf: BeaconNodeConf,
                       bootstrapNodes: seq[BootstrapAddr]): Future[Eth2Node] {.async.} =
    var
      (extIp, extTcpPort, extUdpPort) = setupNat(conf)
      hostAddress = tcpEndPoint(globalListeningAddr, Port conf.tcpPort)
      announcedAddresses = if extIp != globalListeningAddr: @[]
                           else: @[tcpEndPoint(extIp, extTcpPort)]
      keyFile = conf.ensureNetworkIdFile

    info "Starting the LibP2P daemon", hostAddress, announcedAddresses,
                                       keyFile, bootstrapNodes

    var daemonFut = if bootstrapNodes.len == 0:
      newDaemonApi({PSNoSign, DHTFull, PSGossipSub},
                   id = keyFile,
                   hostAddresses = @[hostAddress],
                   announcedAddresses = announcedAddresses)
    else:
      newDaemonApi({PSNoSign, DHTFull, PSGossipSub, WaitBootstrap},
                   id = keyFile,
                   hostAddresses = @[hostAddress],
                   announcedAddresses = announcedAddresses,
                   bootstrapNodes = allMultiAddresses(bootstrapNodes),
                   peersRequired = 1)

    info "Deamon started"

    mainDaemon = await daemonFut

    proc closeDaemon() {.noconv.} =
      info "Shutting down the LibP2P daemon"
      waitFor mainDaemon.close()
    addQuitProc(closeDaemon)

    return await Eth2Node.init(mainDaemon)

  proc getPersistenBootstrapAddr*(conf: BeaconNodeConf,
                                  ip: IpAddress, port: Port): BootstrapAddr =
    result = getPersistentNetIdentity(conf)
    result.addresses = @[tcpEndPoint(ip, port)]

  proc isSameNode*(bootstrapNode: BootstrapAddr, id: Eth2NodeIdentity): bool =
    bootstrapNode.peer == id.peer

  proc shortForm*(id: Eth2NodeIdentity): string =
    # TODO: Make this shorter
    $id

  proc connectToNetwork*(node: Eth2Node, bootstrapNodes: seq[PeerInfo]) {.async.} =
    # TODO: perhaps we should do these in parallel
    var connected = false
    for bootstrapNode in bootstrapNodes:
      try:
        await node.daemon.connect(bootstrapNode.peer, bootstrapNode.addresses)
        var peer = node.getPeer(bootstrapNode.peer)
        peer.wasDialed = true
        await initializeConnection(peer)
        connected = true
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

  proc makeMessageHandler[MsgType](msgHandler: proc(msg: MsgType)): P2PPubSubCallback =
    result = proc(api: DaemonAPI,
                  ticket: PubsubTicket,
                  msg: PubSubMessage): Future[bool] {.async.} =
      msgHandler SSZ.decode(msg.data, MsgType)
      return true

  proc subscribe*[MsgType](node: Eth2Node,
                           topic: string,
                           msgHandler: proc(msg: MsgType)) {.async.} =
    discard await node.daemon.pubsubSubscribe(topic, makeMessageHandler(msgHandler))

  proc broadcast*(node: Eth2Node, topic: string, msg: auto) =
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

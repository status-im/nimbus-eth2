const
  useDEVP2P = not defined(withLibP2P)

import
  options, chronos, version

const
  clientId = "Nimbus beacon node v" & versionAsStr

when useDEVP2P:
  import
    eth/[rlp, p2p, keys], gossipsub_protocol

  export
    p2p, rlp, gossipsub_protocol

  type
    Eth2Node* = EthereumNode
    BootstrapAddr* = ENode

  template libp2pProtocol*(name, version: string) {.pragma.}

  proc createEth2Node*(tcpPort, udpPort: Port): Future[Eth2Node] {.async.} =
    let
      keys = newKeyPair()
      address = Address(ip: parseIpAddress("127.0.0.1"),
                        tcpPort: tcpPort,
                        udpPort: udpPort)

    newEthereumNode(keys, address, 0,
                    nil, clientId, minPeers = 1)

  proc saveConnectionAddressFile*(node: Eth2Node, filename: string) =
    writeFile(filename, $node.listeningAddress)

  proc init*(T: type BootstrapAddr, str: string): T =
    initENode(str)

else:
  import
    libp2p/daemon/daemonapi, json_serialization, chronicles,
    libp2p_backend

  export
    libp2p_backend

  type
    BootstrapAddr* = PeerInfo

  proc writeValue*(writer: var JsonWriter, value: PeerID) {.inline.} =
    writer.writeValue value.pretty

  proc readValue*(reader: var JsonReader, value: var PeerID) {.inline.} =
    value = PeerID.init reader.readValue(string)

  proc writeValue*(writer: var JsonWriter, value: MultiAddress) {.inline.} =
    writer.writeValue $value

  proc readValue*(reader: var JsonReader, value: var MultiAddress) {.inline.} =
    value = MultiAddress.init reader.readValue(string)

  proc init*(T: type BootstrapAddr, str: string): T =
    Json.decode(str, PeerInfo)

  proc createEth2Node*(tcpPort, udpPort: Port): Future[Eth2Node] {.async.} =
    var node = new Eth2Node
    await node.init()
    return node

  proc connectToNetwork*(node: Eth2Node, bootstrapNodes: seq[PeerInfo]) {.async.} =
    # TODO: perhaps we should do these in parallel
    for bootstrapNode in bootstrapNodes:
      try:
        await node.daemon.connect(bootstrapNode.peer, bootstrapNode.addresses)
        await node.getPeer(bootstrapNode.peer).performProtocolHandshakes()
      except PeerDisconnected:
        error "Failed to connect to bootstrap node", node = bootstrapNode

  proc saveConnectionAddressFile*(node: Eth2Node, filename: string) =
    let id = waitFor node.daemon.identity()
    Json.saveFile(filename, id, pretty = false)

  proc loadConnectionAddressFile*(filename: string): PeerInfo =
    Json.loadFile(filename, PeerInfo)


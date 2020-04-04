import
  os, net, strutils, strformat, parseutils,
  chronicles, stew/[result, objects], eth/keys, eth/trie/db, eth/p2p/enode,
  eth/p2p/discoveryv5/[enr, protocol, discovery_db, types],
  libp2p/[multiaddress, peer],
  libp2p/crypto/crypto as libp2pCrypto,
  conf

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId
  PublicKey = keys.PublicKey

export
  Eth2DiscoveryProtocol, open, start, close, result

proc toENode*(a: MultiAddress): Result[ENode, cstring] =
  if not IPFS.match(a):
    return err "Unsupported MultiAddress"

  try:
    # TODO. This code is quite messy with so much string handling.
    # MultiAddress can offer a more type-safe API?
    var
      peerId = PeerID.init(a[2].protoAddress())
      addressFragments = split($a[0], "/")
      portFragments = split($a[1], "/")
      tcpPort: int

    if addressFragments.len != 3 or
       addressFragments[1] != "ip4" or
       portFragments.len != 3 or
       portFragments[1] notin ["tcp", "udp"] or
       parseInt(portFragments[2], tcpPort) == 0:
      return err "Only IPv4 MultiAddresses are supported"

    let
      ipAddress = parseIpAddress(addressFragments[2])

      # TODO. The multiaddress will have either a TCP or a UDP value, but
      # is it reasonable to assume that a client will use the same ports?
      # Probably not, but how can we bootstrap then?
      udpPort = tcpPort

    var pubkey: libp2pCrypto.PublicKey
    if peerId.extractPublicKey(pubkey):
      if pubkey.scheme == Secp256k1:
        return ok ENode(pubkey: PublicKey(pubkey.skkey),
                        address: Address(ip: ipAddress,
                                         tcpPort: Port tcpPort,
                                         udpPort: Port udpPort))

  except CatchableError:
    # This will reach the error exit path below
    discard

  return err "Invalid MultiAddress"

proc toMultiAddressStr*(enode: ENode): string =
  var peerId = PeerID.init(libp2pCrypto.PublicKey(
    scheme: Secp256k1, skkey: SkPublicKey(enode.pubkey)))
  &"/ip4/{enode.address.ip}/tcp/{enode.address.tcpPort}/p2p/{peerId.pretty}"

proc toENode*(enrRec: enr.Record): Result[ENode, cstring] =
  try:
    # TODO: handle IPv6
    let ipBytes = enrRec.get("ip", seq[byte])
    if ipBytes.len != 4:
      return err "Malformed ENR IP address"
    let
      ip = IpAddress(family: IpAddressFamily.IPv4,
                     address_v4: toArray(4, ipBytes))
      tcpPort = Port enrRec.get("tcp", uint16)
      udpPort = Port enrRec.get("udp", uint16)
    var pubKey: PublicKey
    if not enrRec.get(pubKey):
      return err "Failed to read public key from ENR record"
    return ok ENode(pubkey: pubkey,
                    address: Address(ip: ip,
                                     tcpPort: tcpPort,
                                     udpPort: udpPort))
  except CatchableError:
    return err "Invalid ENR record"

# TODO
# This will be resoted to its more generalized form (returning ENode)
# once we refactor the discv5 code to be more easily bootstrapped with
# trusted, but non-signed bootstrap addresses.
proc parseBootstrapAddress*(address: TaintedString): Result[enr.Record, cstring] =
  if address.len == 0:
    return err "an empty string is not a valid bootstrap node"

  logScope:
    address = string(address)

  if address[0] == '/':
    return err "MultiAddress bootstrap addresses are not supported"
    #[
    try:
      let ma = MultiAddress.init(address)
      return toENode(ma)
    except CatchableError:
      return err "Invalid bootstrap multiaddress"
    ]#
  else:
    let lowerCaseAddress = toLowerAscii(string address)
    if lowerCaseAddress.startsWith("enr:"):
      var enrRec: enr.Record
      if enrRec.fromURI(string address):
        return ok enrRec
      return err "Invalid ENR bootstrap record"
    elif lowerCaseAddress.startsWith("enode:"):
      return err "ENode bootstrap addresses are not supported"
      #[
      try:
        return ok initEnode(string address)
      except CatchableError as err:
        return err "Ignoring invalid enode bootstrap address"
      ]#
    else:
      return err "Ignoring unrecognized bootstrap address type"

proc addBootstrapNode*(bootstrapAddr: string,
                       bootNodes: var seq[ENode],
                       bootEnrs: var seq[enr.Record],
                       localPubKey: PublicKey) =
  let enrRes = parseBootstrapAddress(bootstrapAddr)
  if enrRes.isOk:
    let enodeRes = enrRes.value.toENode
    if enodeRes.isOk:
      if enodeRes.value.pubKey != localPubKey:
        bootEnrs.add enrRes.value
  else:
    warn "Ignoring invalid bootstrap address",
          bootstrapAddr, reason = enrRes.error

proc loadBootstrapFile*(bootstrapFile: string,
                        bootNodes: var seq[ENode],
                        bootEnrs: var seq[enr.Record],
                        localPubKey: PublicKey) =
  if bootstrapFile.len == 0: return
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0:
    for ln in lines(bootstrapFile):
      addBootstrapNode(ln, bootNodes, bootEnrs, localPubKey)
  elif cmpIgnoreCase(ext, ".yaml") == 0:
    # TODO. This is very ugly, but let's try to negotiate the
    # removal of YAML metadata.
    for ln in lines(bootstrapFile):
      addBootstrapNode(string(ln[3..^2]), bootNodes, bootEnrs, localPubKey)
  else:
    error "Unknown bootstrap file format", ext
    quit 1

proc new*(T: type Eth2DiscoveryProtocol,
          conf: BeaconNodeConf,
          ip: Option[IpAddress], tcpPort, udpPort: Port,
          rawPrivKeyBytes: openarray[byte]): T =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  var
    pk = PrivateKey.fromRaw(rawPrivKeyBytes).tryGet()
    ourPubKey = pk.toPublicKey().tryGet()
    db = DiscoveryDB.init(newMemoryDB())

  var bootNodes: seq[ENode]
  var bootEnrs: seq[enr.Record]
  for node in conf.bootstrapNodes:
    addBootstrapNode(node, bootNodes, bootEnrs, ourPubKey)
  loadBootstrapFile(string conf.bootstrapNodesFile, bootNodes, bootEnrs, ourPubKey)

  let persistentBootstrapFile = conf.dataDir / "bootstrap_nodes.txt"
  if fileExists(persistentBootstrapFile):
    loadBootstrapFile(persistentBootstrapFile, bootNodes, bootEnrs, ourPubKey)

  newProtocol(pk, db, ip, tcpPort, udpPort, bootEnrs)

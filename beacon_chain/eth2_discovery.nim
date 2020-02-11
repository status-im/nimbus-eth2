import
  os, net, strutils, strformat, parseutils,
  chronicles, stew/[result, objects], eth/keys, eth/trie/db, eth/p2p/enode,
  eth/p2p/discoveryv5/[enr, protocol, node, discovery_db, types],
  libp2p/[multiaddress, multicodec, peer],
  libp2p/crypto/crypto as libp2pCrypto,
  conf

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId

export
  Eth2DiscoveryProtocol, open, start, close, result

proc new*(T: type Eth2DiscoveryProtocol,
          conf: BeaconNodeConf,
          rawPrivKeyBytes: openarray[byte]): T =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  var
    pk = initPrivateKey(rawPrivKeyBytes)
    db = DiscoveryDB.init(newMemoryDB())

  newProtocol(pk, db, Port conf.udpPort)

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
        return ok ENode(pubkey: pubkey.skkey,
                        address: Address(ip: ipAddress,
                                         tcpPort: Port tcpPort,
                                         udpPort: Port udpPort))

  except CatchableError:
    # This will reach the error exit path below
    discard

  return err "Invalid MultiAddress"

proc toMultiAddressStr*(enode: ENode): string =
  var peerId = PeerID.init(libp2pCrypto.PublicKey(scheme: Secp256k1,
                                                  skkey: enode.pubkey))
  &"/ip4/{enode.address.ip}/tcp/{enode.address.tcpPort}/p2p/{peerId.pretty}"

proc parseBootstrapAddress*(address: TaintedString): Result[ENode, cstring] =
  if address.len == 0:
    return err "an empty string is not a valid bootstrap node"

  logScope:
    address = string(address)

  if address[0] == '/':
    try:
      let ma = MultiAddress.init(address)

      return toENode(ma)
    except CatchableError:
      return err "Invalid bootstrap multiaddress"
  else:
    let lowerCaseAddress = toLowerAscii(string address)
    if lowerCaseAddress.startsWith("enr:"):
      var enrRec: enr.Record
      if enrRec.fromURI(string address):
        try:
          # TODO: handle IPv6
          let ipBytes = enrRec.get("ip", seq[byte])
          if ipBytes.len != 4:
            return err "Malformed ENR IP address"
          let
            ip = IpAddress(family: IpAddressFamily.IPv4,
                           address_v4: toArray(4, ipBytes))
            udpPort = Port enrRec.get("udp", uint16)
          var pubKey: keys.PublicKey
          if not enrRec.get(pubKey):
            return err "Failed to read public key from ENR record"
          return ok ENode(pubkey: pubkey,
                          address: Address(ip: ip, udpPort: udpPort))
        except CatchableError:
          # This will continue to the failure path below
          discard
      return err "Invalid ENR bootstrap record"
    elif lowerCaseAddress.startsWith("enode:"):
      try:
        return ok initEnode(string address)
      except CatchableError as err:
        return err "Ignoring invalid enode bootstrap address"
    else:
      return err "Ignoring unrecognized bootstrap address type"

proc addBootstrapNode*(bootNodes: var seq[ENode],
                       bootstrapAddr: string) =
  let enodeRes = parseBootstrapAddress(bootstrapAddr)
  if enodeRes.isOk:
    bootNodes.add enodeRes.value
  else:
    warn "Ignoring invalid bootstrap address",
          bootstrapAddr, reason = enodeRes.error

proc loadBootstrapFile*(bootNodes: var seq[ENode],
                        bootstrapFile: string) =
  if bootstrapFile.len == 0: return
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0:
    for ln in lines(bootstrapFile):
      bootNodes.addBootstrapNode(ln)
  elif cmpIgnoreCase(ext, ".yaml") == 0:
    # TODO. This is very ugly, but let's try to negotiate the
    # removal of YAML metadata.
    for ln in lines(bootstrapFile):
      bootNodes.addBootstrapNode(string(ln[3..^2]))
  else:
    error "Unknown bootstrap file format", ext
    quit 1


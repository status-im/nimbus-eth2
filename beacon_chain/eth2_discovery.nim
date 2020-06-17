{.push raises: [Defect].}

import
  os, sequtils, strutils,
  chronicles, stew/shims/net, stew/results, eth/keys, eth/trie/db,
  eth/p2p/discoveryv5/[enr, protocol, discovery_db, node],
  conf

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId
  PublicKey = keys.PublicKey

export
  Eth2DiscoveryProtocol, open, start, close, closeWait, randomNodes, results

proc parseBootstrapAddress*(address: TaintedString):
    Result[enr.Record, cstring] =
  if address.len == 0:
    return err "an empty string is not a valid bootstrap node"

  logScope:
    address = string(address)

  if address[0] == '/':
    return err "MultiAddress bootstrap addresses are not supported"
  else:
    let lowerCaseAddress = toLowerAscii(string address)
    if lowerCaseAddress.startsWith("enr:"):
      var enrRec: enr.Record
      if enrRec.fromURI(string address):
        return ok enrRec
      return err "Invalid ENR bootstrap record"
    elif lowerCaseAddress.startsWith("enode:"):
      return err "ENode bootstrap addresses are not supported"
    else:
      return err "Ignoring unrecognized bootstrap address type"

proc addBootstrapNode*(bootstrapAddr: string,
                       bootstrapEnrs: var seq[enr.Record],
                       localPubKey: PublicKey) =
  let enrRes = parseBootstrapAddress(bootstrapAddr)
  if enrRes.isOk:
    bootstrapEnrs.add enrRes.value
  else:
    warn "Ignoring invalid bootstrap address",
          bootstrapAddr, reason = enrRes.error

proc loadBootstrapFile*(bootstrapFile: string,
                        bootstrapEnrs: var seq[enr.Record],
                        localPubKey: PublicKey) =
  if bootstrapFile.len == 0: return
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0:
    try:
      for ln in lines(bootstrapFile):
        addBootstrapNode(ln, bootstrapEnrs, localPubKey)
    except IOError as e:
      error "Could not read bootstrap file", msg = e.msg
      quit 1

  elif cmpIgnoreCase(ext, ".yaml") == 0:
    # TODO. This is very ugly, but let's try to negotiate the
    # removal of YAML metadata.
    try:
      for ln in lines(bootstrapFile):
        addBootstrapNode(string(ln[3..^2]), bootstrapEnrs, localPubKey)
    except IOError as e:
      error "Could not read bootstrap file", msg = e.msg
      quit 1
  else:
    error "Unknown bootstrap file format", ext
    quit 1

proc new*(T: type Eth2DiscoveryProtocol,
          conf: BeaconNodeConf,
          ip: Option[ValidIpAddress], tcpPort, udpPort: Port,
          rawPrivKeyBytes: openarray[byte],
          enrFields: openarray[(string, seq[byte])]):
          T {.raises: [Exception, Defect].} =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  let
    pk = PrivateKey.fromRaw(rawPrivKeyBytes).expect("Valid private key")
    ourPubKey = pk.toPublicKey().expect("Public key from valid private key")
    # TODO: `newMemoryDB()` causes raises: [Exception]
    db = DiscoveryDB.init(newMemoryDB())

  var bootstrapEnrs: seq[enr.Record]
  for node in conf.bootstrapNodes:
    addBootstrapNode(node, bootstrapEnrs, ourPubKey)
  loadBootstrapFile(string conf.bootstrapNodesFile, bootstrapEnrs, ourPubKey)

  let persistentBootstrapFile = conf.dataDir / "bootstrap_nodes.txt"
  if fileExists(persistentBootstrapFile):
    loadBootstrapFile(persistentBootstrapFile, bootstrapEnrs, ourPubKey)

  let enrFieldPairs = mapIt(enrFields, toFieldPair(it[0], it[1]))
  newProtocol(pk, db, ip, tcpPort, udpPort, enrFieldPairs, bootstrapEnrs)

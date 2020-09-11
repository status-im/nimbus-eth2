{.push raises: [Defect].}

import
  std/[os, strutils],
  chronicles, stew/shims/net, stew/results, bearssl,
  eth/keys, eth/p2p/discoveryv5/[enr, protocol, node],
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
                       bootstrapEnrs: var seq[enr.Record]) =
  let enrRes = parseBootstrapAddress(bootstrapAddr)
  if enrRes.isOk:
    bootstrapEnrs.add enrRes.value
  else:
    warn "Ignoring invalid bootstrap address",
          bootstrapAddr, reason = enrRes.error

proc loadBootstrapFile*(bootstrapFile: string,
                        bootstrapEnrs: var seq[enr.Record]) =
  if bootstrapFile.len == 0: return
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0 or cmpIgnoreCase(ext, ".enr") == 0 :
    try:
      for ln in lines(bootstrapFile):
        addBootstrapNode(ln, bootstrapEnrs)
    except IOError as e:
      error "Could not read bootstrap file", msg = e.msg
      quit 1

  elif cmpIgnoreCase(ext, ".yaml") == 0:
    # TODO. This is very ugly, but let's try to negotiate the
    # removal of YAML metadata.
    try:
      for ln in lines(bootstrapFile):
        addBootstrapNode(string(ln.strip()[3..^2]), bootstrapEnrs)
    except IOError as e:
      error "Could not read bootstrap file", msg = e.msg
      quit 1
  else:
    error "Unknown bootstrap file format", ext
    quit 1

proc new*(T: type Eth2DiscoveryProtocol,
          conf: BeaconNodeConf,
          ip: Option[ValidIpAddress], tcpPort, udpPort: Port,
          pk: PrivateKey,
          enrFields: openarray[(string, seq[byte])], rng: ref BrHmacDrbgContext):
          T {.raises: [Exception, Defect].} =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  var bootstrapEnrs: seq[enr.Record]
  for node in conf.bootstrapNodes:
    addBootstrapNode(node, bootstrapEnrs)
  loadBootstrapFile(string conf.bootstrapNodesFile, bootstrapEnrs)

  let persistentBootstrapFile = conf.dataDir / "bootstrap_nodes.txt"
  if fileExists(persistentBootstrapFile):
    loadBootstrapFile(persistentBootstrapFile, bootstrapEnrs)

  newProtocol(
    pk, ip, tcpPort, udpPort, enrFields, bootstrapEnrs, rng = rng)

{.push raises: [Defect].}

import
  std/[os, strutils],
  chronicles, stew/shims/net, stew/results, bearssl,
  eth/keys, eth/p2p/discoveryv5/[enr, protocol, node],
  conf

export protocol, keys

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId
  PublicKey = keys.PublicKey

export
  Eth2DiscoveryProtocol, open, start, close, closeWait, queryRandom,
    updateRecord, results

proc parseBootstrapAddress*(address: TaintedString):
    Result[enr.Record, cstring] =
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

iterator strippedLines(filename: string): string {.raises: [ref IOError].} =
  for line in lines(filename):
    let stripped = strip(line)
    if stripped.startsWith('#'): # Comments
      continue

    if stripped.len > 0:
      yield stripped

proc addBootstrapNode*(bootstrapAddr: string,
                       bootstrapEnrs: var seq[enr.Record]) =
  # Ignore empty lines or lines starting with #
  if bootstrapAddr.len == 0 or bootstrapAddr[0] == '#':
    return

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
      for ln in strippedLines(bootstrapFile):
        addBootstrapNode(ln, bootstrapEnrs)
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
          enrFields: openArray[(string, seq[byte])], rng: ref BrHmacDrbgContext):
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

  newProtocol(pk, ip, tcpPort, udpPort, enrFields, bootstrapEnrs,
    bindIp = conf.listenAddress, rng = rng)

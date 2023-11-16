# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, stew/shims/net, stew/results,
  eth/p2p/discoveryv5/[enr, protocol, node],
  ".."/[conf, conf_light_client]

from std/os import splitFile
from std/strutils import cmpIgnoreCase, split, startsWith, strip, toLowerAscii

export protocol

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId

export
  Eth2DiscoveryProtocol, open, start, close, closeWait, queryRandom,
    updateRecord, results

func parseBootstrapAddress*(address: string):
    Result[enr.Record, cstring] =
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

  # Ignore comments in
  # https://github.com/eth-clients/eth2-networks/blob/063f826a03676c33c95a66306916f18b690d35eb/shared/mainnet/bootstrap_nodes.txt
  let enrRes = parseBootstrapAddress(bootstrapAddr.split(" # ")[0])
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
          config: BeaconNodeConf | LightClientConf,
          enrIp: Option[IpAddress], enrTcpPort, enrUdpPort: Option[Port],
          pk: PrivateKey,
          enrFields: openArray[(string, seq[byte])], rng: ref HmacDrbgContext):
          T =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  var bootstrapEnrs: seq[enr.Record]
  for node in config.bootstrapNodes:
    addBootstrapNode(node, bootstrapEnrs)
  loadBootstrapFile(string config.bootstrapNodesFile, bootstrapEnrs)

  when config is BeaconNodeConf:
    let persistentBootstrapFile = config.dataDir / "bootstrap_nodes.txt"
    if fileExists(persistentBootstrapFile):
      loadBootstrapFile(persistentBootstrapFile, bootstrapEnrs)

  newProtocol(pk, enrIp, enrTcpPort, enrUdpPort, enrFields, bootstrapEnrs,
    bindPort = config.udpPort, bindIp = config.listenAddress,
    enrAutoUpdate = config.enrAutoUpdate, rng = rng)

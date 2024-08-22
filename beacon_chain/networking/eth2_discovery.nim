# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[algorithm, sequtils],
  chronos, chronicles, stew/results,
  eth/p2p/discoveryv5/[enr, protocol, node, random2],
  ../spec/datatypes/[altair, eip7594],
  ../spec/eth2_ssz_serialization,
  ".."/[conf, conf_light_client]

from std/os import splitFile
from std/strutils import cmpIgnoreCase, split, startsWith, strip, toLowerAscii

export protocol, node

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId

func parseBootstrapAddress*(address: string):
    Result[enr.Record, cstring] =
  let lowerCaseAddress = toLowerAscii(address)
  if lowerCaseAddress.startsWith("enr:"):
    var enrRec: enr.Record
    if enrRec.fromURI(address):
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

  let listenAddress =
    if config.listenAddress.isSome():
      Opt.some(config.listenAddress.get())
    else:
      Opt.none(IpAddress)

  newProtocol(pk, enrIp, enrTcpPort, enrUdpPort, enrFields, bootstrapEnrs,
    bindPort = config.udpPort, bindIp = listenAddress,
    enrAutoUpdate = config.enrAutoUpdate, rng = rng)

func isCompatibleForkId*(discoveryForkId: ENRForkID, peerForkId: ENRForkID): bool =
  if discoveryForkId.fork_digest == peerForkId.fork_digest:
    if discoveryForkId.next_fork_version < peerForkId.next_fork_version:
      # Peer knows about a fork and we don't
      true
    elif discoveryForkId.next_fork_version == peerForkId.next_fork_version:
      # We should have the same next_fork_epoch
      discoveryForkId.next_fork_epoch == peerForkId.next_fork_epoch

    else:
      # Our next fork version is bigger than the peer's one
      false
  else:
    # Wrong fork digest
    false

proc queryRandom*(
    d: Eth2DiscoveryProtocol,
    forkId: ENRForkID,
    wantedAttnets: AttnetBits,
    wantedSyncnets: SyncnetBits,
    wantedCscnets: CscCount,
    minScore: int): Future[seq[Node]] {.async.} =
  ## Perform a discovery query for a random target
  ## (forkId) and matching at least one of the attestation subnets.

  let nodes = await d.queryRandom()

  var filtered: seq[(int, Node)]
  for n in nodes:
    var score: int = 0

    let
      eth2FieldBytes = n.record.get(enrForkIdField, seq[byte]).valueOr:
        continue
      peerForkId =
        try:
          SSZ.decode(eth2FieldBytes, ENRForkID)
        except SszError as e:
          debug "Could not decode the eth2 field of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

    if not forkId.isCompatibleForkId(peerForkId):
      continue

    let cscnetsBytes = n.record.get(enrCustodySubnetCountField, seq[byte])
    if cscnetsBytes.isOk():
      let cscnetsNode =
        try:
          SSZ.decode(cscnetsBytes.get(), CscCount)
        except SszError as e:
          debug "Could not decode the csc count ENR bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

    let attnetsBytes = n.record.get(enrAttestationSubnetsField, seq[byte])
    if attnetsBytes.isOk():
      let attnetsNode =
        try:
          SSZ.decode(attnetsBytes.get(), AttnetBits)
        except SszError as e:
          debug "Could not decode the attnets ERN bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      for i in 0..<ATTESTATION_SUBNET_COUNT:
        if wantedAttnets[i] and attnetsNode[i]:
          score += 1

    let syncnetsBytes = n.record.get(enrSyncSubnetsField, seq[byte])
    if syncnetsBytes.isOk():
      let syncnetsNode =
        try:
          SSZ.decode(syncnetsBytes.get(), SyncnetBits)
        except SszError as e:
          debug "Could not decode the syncnets ENR bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      for i in SyncSubcommitteeIndex:
        if wantedSyncnets[i] and syncnetsNode[i]:
          score += 10 # connecting to the right syncnet is urgent

    if score >= minScore:
      filtered.add((score, n))

  d.rng[].shuffle(filtered)
  return filtered.sortedByIt(-it[0]).mapIt(it[1])

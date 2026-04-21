# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[algorithm, sequtils],
  chronos, chronicles,
  eth/p2p/discoveryv5/[protocol, node, random2],
  ../spec/datatypes/[altair, fulu],
  ../spec/[eth2_ssz_serialization, peerdas_helpers, column_map],
  ".."/[conf, conf_light_client]

from std/os import splitFile
from std/strutils import cmpIgnoreCase, split, startsWith, strip, toLowerAscii

export protocol, node

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId
  QueryScore* = array[3, int]

const
  AttesttationNetScore* = 0
  SyncNetScore* = 1
  ColumnNetScore* = 2

func parseBootstrapAddress*(address: string):
    Result[enr.Record, string] =
  let lowerCaseAddress = toLowerAscii(address)
  if lowerCaseAddress.startsWith("enr:"):
    let res = enr.Record.fromURI(address)
    if res.isOk():
      return ok res.value
    return err "Invalid bootstrap ENR: " & $res.error
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
  # https://github.com/eth-clients/mainnet/blob/main/metadata/bootstrap_nodes.txt
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
          enrIp: Opt[IpAddress], enrTcpPort, enrUdpPort: Opt[Port],
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
    cfg: RuntimeConfig,
    forkId: ENRForkID,
    wantedAttnets: AttnetBits,
    wantedSyncnets: SyncnetBits,
    localMap: ColumnMap,
    minScore: QueryScore
): Future[seq[Node]] {.async: (raises: [CancelledError]).} =
  ## Perform a discovery query for a random target
  ## (forkId) and matching at least one of the attestation subnets.

  let nodes = await d.queryRandom()

  var filtered: seq[(int, Node)]
  for n in nodes:
    var score: QueryScore

    let
      eth2FieldBytes = n.record.get(enrForkIdField, seq[byte]).valueOr:
        continue
      peerForkId =
        try:
          SSZ.decode(eth2FieldBytes, ENRForkID)
        except SerializationError as e:
          debug "Could not decode the eth2 field of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

    if not forkId.isCompatibleForkId(peerForkId):
      continue

    let cgcCountBytes = n.record.get(enrCustodyGroupCountField, seq[byte])
    if cgcCountBytes.isOk():
      let cgcCountNode =
        try:
          SSZ.decode(cgcCountBytes.get(), uint8)
        except SerializationError as e:
          debug "Could not decode the cgc ENR field of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      let peerMap =
        cfg.resolve_column_map_from_custody_groups(
          n.id, CustodyIndex(cgcCountNode))

      score[ColumnNetScore] = 100 * len(peerMap and localMap)

    let attnetsBytes = n.record.get(enrAttestationSubnetsField, seq[byte])
    if attnetsBytes.isOk():
      let attnetsNode =
        try:
          SSZ.decode(attnetsBytes.get(), AttnetBits)
        except SerializationError as e:
          debug "Could not decode the attnets ENR bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      for i in 0..<ATTESTATION_SUBNET_COUNT:
        if wantedAttnets[i] and attnetsNode[i]:
          score[AttesttationNetScore] += 1

    let syncnetsBytes = n.record.get(enrSyncSubnetsField, seq[byte])
    if syncnetsBytes.isOk():
      let syncnetsNode =
        try:
          SSZ.decode(syncnetsBytes.get(), SyncnetBits)
        except SerializationError as e:
          debug "Could not decode the syncnets ENR bitfield of peer",
            peer = n.record.toURI(), exception = e.name, msg = e.msg
          continue

      for i in SyncSubcommitteeIndex:
        if wantedSyncnets[i] and syncnetsNode[i]:
          score[SyncNetScore] += 10 # connecting to the right syncnet is urgent

    if (score[0] >= minScore[0]) and (score[1] >= minScore[1]) and
       (score[2] >= minScore[2]):
      filtered.add((score[0] + score[1] + score[2], n))

  d.rng[].shuffle(filtered)
  return filtered.sortedByIt(-it[0]).mapIt(it[1])

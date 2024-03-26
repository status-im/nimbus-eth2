# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  stew/[byteutils, results, endians2],
  chronicles,
  chronos, chronos/transports/[osnet, ipnet],
  eth/p2p/discoveryv5/enr,
  libp2p/[multiaddress, multicodec, peerstore],
  ../version, ../beacon_node, ../sync/sync_manager,
  ../networking/[eth2_network, peer_pool],
  ../spec/datatypes/base,
  ./rest_utils

export rest_utils

logScope: topics = "rest_node"

type
  ConnectionStateSet* = set[ConnectionState]
  PeerTypeSet* = set[PeerType]

  RestNodePeerCount* = object
    disconnected*: uint64
    connecting*: uint64
    connected*: uint64
    disconnecting*: uint64

RestJson.useDefaultSerializationFor(
  RestNodePeerCount,
)

proc validateState(states: seq[PeerStateKind]): Result[ConnectionStateSet,
                                                       cstring] =
  var res: set[ConnectionState]
  for item in states:
    case item
    of PeerStateKind.Disconnected:
      if ConnectionState.Disconnected in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Disconnected)
    of PeerStateKind.Connecting:
      if ConnectionState.Connecting in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Connecting)
    of PeerStateKind.Connected:
      if ConnectionState.Connected in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Connected)
    of PeerStateKind.Disconnecting:
      if ConnectionState.Disconnecting in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Disconnecting)
  if res == {}:
    res = {ConnectionState.Connecting, ConnectionState.Connected,
           ConnectionState.Disconnecting, ConnectionState.Disconnected}
  ok(res)

proc validateDirection(directions: seq[PeerDirectKind]): Result[PeerTypeSet,
                                                                cstring] =
  var res: set[PeerType]
  for item in directions:
    case item
    of PeerDirectKind.Inbound:
      if PeerType.Incoming in res:
        return err("Peer direction states must be unique")
      res.incl(PeerType.Incoming)
    of PeerDirectKind.Outbound:
      if PeerType.Outgoing in res:
        return err("Peer direction states must be unique")
      res.incl(PeerType.Outgoing)
  if res == {}:
    res = {PeerType.Incoming, PeerType.Outgoing}
  ok(res)

proc toString(state: ConnectionState): string =
  case state
  of ConnectionState.Disconnected:
    "disconnected"
  of ConnectionState.Connecting:
    "connecting"
  of ConnectionState.Connected:
    "connected"
  of ConnectionState.Disconnecting:
    "disconnecting"
  else:
    ""

proc toString(direction: PeerType): string =
  case direction:
  of PeerType.Incoming:
    "inbound"
  of PeerType.Outgoing:
    "outbound"

proc getLastSeenAddress(node: BeaconNode, id: PeerId): string =
  # TODO (cheatfate): We need to provide filter here, which will be able to
  # filter such multiaddresses like `/ip4/0.0.0.0` or local addresses or
  # addresses with peer ids.
  let addrs = node.network.switch.peerStore[AddressBook][id]
  if len(addrs) > 0:
    $addrs[len(addrs) - 1]
  else:
    ""
proc getDiscoveryAddresses(node: BeaconNode): Opt[seq[string]] =
  let restr = node.network.enrRecord().toTypedRecord()
  if restr.isErr():
    return Opt.none(seq[string])
  let respa = restr.get().toPeerAddr(udpProtocol)
  if respa.isErr():
    return Opt.none(seq[string])
  let pa = respa.get()
  let mpa = MultiAddress.init(multiCodec("p2p"), pa.peerId)
  if mpa.isErr():
    return Opt.none(seq[string])
  var addresses = newSeqOfCap[string](len(pa.addrs))
  for item in pa.addrs:
    let resa = concat(item, mpa.get())
    if resa.isOk():
      addresses.add($(resa.get()))
  return Opt.some(addresses)

proc getProtocolArgument(ma: MultiAddress,
                         codec: MultiCodec): MaResult[seq[byte]] =
  var buffer: seq[byte]
  for item in ma:
    let
      ritem = ? item
      code = ? ritem.protoCode()
    if code == codec:
      let arg = ? ritem.protoAddress()
      return ok(arg)

  err("Multiaddress codec has not been found")

proc checkInterface(iface: NetworkInterface): bool =
  if (iface.ifType == IfSoftwareLoopback) or (iface.state == StatusUp):
    true
  else:
    false

proc init(t: typedesc[MultiAddress], family: AddressFamily,
          iface: NetworkInterface,
          port: Port, suffix: MultiAddress): MaResult[seq[MultiAddress]] =
  var res: seq[MultiAddress]
  if not(iface.checkInterface()):
    return err("Unsupported interface")
  for ifaddr in iface.addresses:
    if ifaddr.host.family != family:
      continue
    var address = ifaddr.host
    address.port = port
    let
      maddress = ? MultiAddress.init(address)
      suffixed = ? maddress.concat(suffix)
    res.add(suffixed)
  ok(res)

proc getP2PAddresses(node: BeaconNode): Opt[seq[string]] =
  let
    interfaces = getInterfaces()
    pinfo = node.network.switch.peerInfo
    suffix = MultiAddress.init(multiCodec("p2p"), pinfo.peerId).valueOr:
      return Opt.none(seq[string])

  # In this loop we expand bounded addresses like `0.0.0.0` and `::` to list of
  # interface addresses.
  var addresses = newSeq[string]()
  for maddress in pinfo.addrs:
    if TCP_IP.matchPartial(maddress):
      let
        portArg = maddress.getProtocolArgument(multiCodec("tcp")).valueOr:
          continue
        port =
          block:
            if len(portArg) != sizeof(uint16):
              continue
            Port(uint16.fromBytesLE(portArg))
      if IP4.matchPartial(maddress):
        let address4 = maddress.getProtocolArgument(multiCodec("ip4")).valueOr:
          continue
        if address4 != AnyAddress.address_v4:
          let suffixed = maddress.concat(suffix).valueOr:
            continue
          addresses.add($suffixed)
          continue
        for iface in interfaces:
          let iaddrs = MultiAddress.init(AddressFamily.IPv4, iface, port,
                                         suffix).valueOr:
            continue
          for item in iaddrs:
            addresses.add($item)
      elif IP6.matchPartial(maddress):
        let address6 = maddress.getProtocolArgument(multiCodec("ip6")).valueOr:
          continue
        if address6 != AnyAddress6.address_v6:
          let suffixed = maddress.concat(suffix).valueOr:
            continue
          addresses.add($suffixed)
          continue
        for iface in interfaces:
          let iaddrs = MultiAddress.init(AddressFamily.IPv6, iface, port,
                                         suffix).valueOr:
            continue
          for item in iaddrs:
            addresses.add($item)
      else:
        let suffixed = maddress.concat(suffix).valueOr:
          continue
        addresses.add($suffixed)
    else:
      let suffixed = maddress.concat(suffix).valueOr:
        continue
      addresses.add($suffixed)

  # We assume that an address that appears more then once in list of observed
  # addresses by libp2p identify protocol, can be used as address which can
  # be dialled (out public address in case when we are behind NAT). All
  # other addresses can be our outgoing addresses, so remote peer will be unable
  # to connect using this address.
  var addrCounts = initCountTable[TransportAddress]()
  let observed = node.network.switch.peerStore.getMostObservedProtosAndPorts()
  for maddress in observed:
    if TCP_IP.matchPartial(maddress):
      let
        portArg = maddress.getProtocolArgument(multiCodec("tcp")).valueOr:
          continue
        port =
          block:
            if len(portArg) != sizeof(uint16):
              continue
            Port(uint16.fromBytesLE(portArg))

      if IP4.matchPartial(maddress):
        let
          address4 = maddress.getProtocolArgument(multiCodec("ip4")).valueOr:
            continue
        var ta4 = TransportAddress(family: AddressFamily.IPv4, port: port)
        ta4.address_v4[0 .. 3] = address4[0 .. 3]
        addrCounts.inc(ta4)
      elif IP6.matchPartial(maddress):
        let
          address6 = maddress.getProtocolArgument(multiCodec("ip6")).valueOr:
            continue
        var ta6 = TransportAddress(family: AddressFamily.IPv6, port: port)
        ta6.address_v6[0 .. 15] = address6[0 .. 15]
        addrCounts.inc(ta6)
      else:
        discard

  for taddr, count in addrCounts.pairs():
    if count > 1:
      let
        maddr = MultiAddress.init(taddr).valueOr:
          continue
        suffixed = maddr.concat(suffix).valueOr:
          continue
      addresses.add($suffixed)

  return Opt.some(addresses)

proc installNodeApiHandlers*(router: var RestRouter, node: BeaconNode) =
  let
    cachedVersion =
      RestApiResponse.prepareJsonResponse((version: "Nimbus/" & fullVersionStr))

  # https://ethereum.github.io/beacon-APIs/#/Node/getNetworkIdentity
  router.api2(MethodGet, "/eth/v1/node/identity") do () -> RestApiResponse:
    let
      discoveryAddresses = node.getDiscoveryAddresses().valueOr:
        default(seq[string])
      p2pAddresses = node.getP2PAddresses().valueOr:
        default(seq[string])

    RestApiResponse.jsonResponse(
      (
        peer_id: $node.network.peerId(),
        enr: node.network.enrRecord().toURI(),
        p2p_addresses: p2pAddresses,
        discovery_addresses: discoveryAddresses,
        metadata: (
          seq_number: node.network.metadata.seq_number,
          syncnets: to0xHex(node.network.metadata.syncnets.bytes),
          attnets: to0xHex(node.network.metadata.attnets.bytes)
        )
      )
    )

  # https://ethereum.github.io/beacon-APIs/#/Node/getPeers
  router.api2(MethodGet, "/eth/v1/node/peers") do (
    state: seq[PeerStateKind],
    direction: seq[PeerDirectKind]) -> RestApiResponse:
    let connectionMask =
      block:
        if state.isErr():
          return RestApiResponse.jsonError(Http400, InvalidPeerStateValueError,
                                           $state.error())
        validateState(state.get()).valueOr:
          return RestApiResponse.jsonError(Http400, InvalidPeerStateValueError,
                                           $error)
    let directionMask =
      block:
        if direction.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidPeerDirectionValueError,
                                           $direction.error())
        validateDirection(direction.get()).valueOr:
          return RestApiResponse.jsonError(Http400,
                                           InvalidPeerDirectionValueError,
                                           $error)
    var res: seq[RestNodePeer]
    for peer in node.network.peers.values():
      if (peer.connectionState in connectionMask) and
         (peer.direction in directionMask):
        let peer = RestNodePeer(
          peer_id: $peer.peerId,
          enr: if peer.enr.isSome(): peer.enr.get().toURI() else: "",
          last_seen_p2p_address: getLastSeenAddress(node, peer.peerId),
          state: peer.connectionState.toString(),
          direction: peer.direction.toString(),
          # Fields `agent` and `proto` are not part of specification
          agent: node.network.switch.peerStore[AgentBook][peer.peerId],
          proto: node.network.switch.peerStore[ProtoVersionBook][peer.peerId]
        )
        res.add(peer)
    RestApiResponse.jsonResponseWMeta(res, (count: RestNumeric(len(res))))

  # https://ethereum.github.io/beacon-APIs/#/Node/getPeerCount
  router.api2(MethodGet, "/eth/v1/node/peer_count") do () -> RestApiResponse:
    var res: RestNodePeerCount
    for item in node.network.peers.values():
      case item.connectionState
      of ConnectionState.Connecting:
        inc(res.connecting)
      of ConnectionState.Connected:
        inc(res.connected)
      of ConnectionState.Disconnecting:
        inc(res.disconnecting)
      of ConnectionState.Disconnected:
        inc(res.disconnected)
      of ConnectionState.None:
        discard
    RestApiResponse.jsonResponse(res)

  # https://ethereum.github.io/beacon-APIs/#/Node/getPeer
  router.api2(MethodGet, "/eth/v1/node/peers/{peer_id}") do (
    peer_id: PeerId) -> RestApiResponse:
    let peer =
      block:
        if peer_id.isErr():
          return RestApiResponse.jsonError(Http400, InvalidPeerIdValueError,
                                           $peer_id.error())
        let res = node.network.peers.getOrDefault(peer_id.get())
        if isNil(res):
          return RestApiResponse.jsonError(Http404, PeerNotFoundError)
        res
    RestApiResponse.jsonResponse(
      (
        peer_id: $peer.peerId,
        enr: if peer.enr.isSome(): peer.enr.get().toURI() else: "",
        last_seen_p2p_address: getLastSeenAddress(node, peer.peerId),
        state: peer.connectionState.toString(),
        direction: peer.direction.toString(),
        agent: node.network.switch.peerStore[AgentBook][peer.peerId],
          # Fields `agent` and `proto` are not part of specification
        proto: node.network.switch.peerStore[ProtoVersionBook][peer.peerId]
          # Fields `agent` and `proto` are not part of specification
      )
    )

  # https://ethereum.github.io/beacon-APIs/#/Node/getNodeVersion
  router.api2(MethodGet, "/eth/v1/node/version") do () -> RestApiResponse:
    RestApiResponse.response(cachedVersion, Http200, "application/json")

  # https://ethereum.github.io/beacon-APIs/#/Node/getSyncingStatus
  router.api2(MethodGet, "/eth/v1/node/syncing") do () -> RestApiResponse:
    let
      wallSlot = node.beaconClock.now().slotOrZero()
      headSlot = node.dag.head.slot
      distance = wallSlot - headSlot
      isSyncing =
        if isNil(node.syncManager):
          false
        else:
          node.syncManager.inProgress
      isOptimistic =
        if node.currentSlot().epoch() >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
          some(not node.dag.head.executionValid)
        else:
          none[bool]()
      elOffline =
        if node.currentSlot().epoch() >= node.dag.cfg.CAPELLA_FORK_EPOCH:
          some(not node.elManager.hasAnyWorkingConnection)
        else:
          none[bool]()  # Added with ethereum/beacon-APIs v2.4.0

      info = RestSyncInfo(
        head_slot: headSlot, sync_distance: distance,
        is_syncing: isSyncing, is_optimistic: isOptimistic,
        el_offline: elOffline
      )
    RestApiResponse.jsonResponse(info)

  # https://ethereum.github.io/beacon-APIs/#/Node/getHealth
  router.api2(MethodGet, "/eth/v1/node/health") do () -> RestApiResponse:
    # TODO: Add ability to detect node's issues and return 503 error according
    # to specification.
    let status =
      if node.syncManager.inProgress:
        Http206
      else:
        Http200
    RestApiResponse.response("", status, contentType = "")

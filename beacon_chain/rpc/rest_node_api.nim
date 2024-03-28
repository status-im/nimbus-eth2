# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[sequtils, tables],
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

proc getWildcardMultiAddresses(
  interfaces: openArray[NetworkInterface],
  families: set[AddressFamily],
  protocol: IpTransportProtocol,
  port: Port,
  suffix: MultiAddress
): seq[MultiAddress] =
  var addresses: seq[MultiAddress]
  if len(families) > 0:
    for iface in interfaces:
      if not(iface.checkInterface()):
        # We support only addresses which are currently UP.
        continue
      for ifaddr in iface.addresses:
        if ifaddr.host.family notin families:
          continue
        var address = ifaddr.host
        address.port = port
        let
          maddress =
            case protocol
            of IpTransportProtocol.udpProtocol:
              MultiAddress.init(address, IPPROTO_UDP).valueOr:
                continue
            of IpTransportProtocol.tcpProtocol:
              MultiAddress.init(address, IPPROTO_TCP).valueOr:
                continue
          suffixed = maddress.concat(suffix).valueOr:
            continue
        addresses.add(suffixed)
  addresses

proc getDiscoveryV5Addresses(node: BeaconNode): seq[MultiAddress] =
  var addresses: seq[MultiAddress]
  let
    typedRecord = node.network.enrRecord().toTypedRecord().valueOr:
      return default(seq[MultiAddress])
    peerAddress = typedRecord.toPeerAddr(udpProtocol).valueOr:
      return default(seq[MultiAddress])
    suffix = MultiAddress.init(multiCodec("p2p"), peerAddress.peerId).valueOr:
      return default(seq[MultiAddress])
  for item in peerAddress.addrs:
    let res = concat(item, suffix).valueOr:
      continue
    addresses.add(res)
  addresses

proc getExternalAddresses(node: BeaconNode,
                          protocol: IpTransportProtocol): seq[MultiAddress] =
  var addresses: seq[MultiAddress]
  let suffix = MultiAddress.init(multiCodec("p2p"),
                                 node.network.peerIdent).valueOr:
    return default(seq[MultiAddress])

  for eaddress in node.network.externalAddresses:
    let
      maddress =
        case protocol
        of IpTransportProtocol.tcpProtocol:
          if eaddress.address.isNone() or eaddress.tcp.isNone():
            continue
          MultiAddress.init(eaddress.address.get(), protocol,
                            eaddress.tcp.get())
        of IpTransportProtocol.udpProtocol:
          if eaddress.address.isNone() or eaddress.udp.isNone():
            continue
          MultiAddress.init(eaddress.address.get(), protocol,
                            eaddress.udp.get())
      suffixed = maddress.concat(suffix).valueOr:
        continue
    addresses.add(suffixed)
  addresses

proc getObservedAddresses(node: BeaconNode): seq[MultiAddress] =
  # Following functionality depends on working `Identify/IdentifyPush` protocol
  # inside `nim-libp2p` (currently disabled).
  #
  # We assume that an address that appears more then once in list of observed
  # addresses by libp2p identify protocol, can be used as address which can
  # be dialled (out public address in case when we are behind NAT). All
  # other addresses can be our outgoing addresses, so remote peer will be unable
  # to connect using this address.
  var
    addresses: seq[MultiAddress]
    addrCounts = initCountTable[TransportAddress]()

  let
    peerId = node.network.peerIdent
    suffix = MultiAddress.init(multiCodec("p2p"), peerId).valueOr:
      return default(seq[MultiAddress])
    observed = node.network.switch.peerStore.getMostObservedProtosAndPorts()

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
      addresses.add(suffixed)
  addresses

proc getLibp2pPeerInfoAddresses(
    node: BeaconNode,
    interfaces: openArray[NetworkInterface]
): seq[MultiAddress] =
  var addresses: seq[MultiAddress]
  let
    peerId = node.network.peerIdent
    pinfo = node.network.switch.peerInfo
    suffix = MultiAddress.init(multiCodec("p2p"), peerId).valueOr:
      return default(seq[MultiAddress])

  # In this loop we expand bounded addresses like `0.0.0.0` and `::` to list of
  # interface addresses.
  for maddress in pinfo.addrs:
    if TCP_IP.matchPartial(maddress):
      let
        portArg = maddress.getProtocolArgument(multiCodec("tcp")).valueOr:
          continue
        port =
          block:
            if len(portArg) != sizeof(uint16):
              continue
            Port(uint16.fromBytesBE(portArg))
      if IP4.matchPartial(maddress):
        let address4 =
          maddress.getProtocolArgument(multiCodec("ip4")).valueOr:
            continue
        if address4 != AnyAddress.address_v4:
          let suffixed = maddress.concat(suffix).valueOr:
            continue
          addresses.add(suffixed)
          continue
        let wildcardAddresses =
          interfaces.getWildcardMultiAddresses(
            {AddressFamily.IPv4}, IpTransportProtocol.tcpProtocol, port, suffix)
        addresses.add(wildcardAddresses)
      elif IP6.matchPartial(maddress):
        let address6 =
          maddress.getProtocolArgument(multiCodec("ip6")).valueOr:
            continue
        if address6 != AnyAddress6.address_v6:
          let suffixed = maddress.concat(suffix).valueOr:
            continue
          addresses.add(suffixed)
          continue
        let wildcardAddresses =
          interfaces.getWildcardMultiAddresses(
            {AddressFamily.IPv6}, IpTransportProtocol.tcpProtocol, port, suffix)
        addresses.add(wildcardAddresses)
      else:
        let suffixed = maddress.concat(suffix).valueOr:
          continue
        addresses.add(suffixed)
    else:
      let suffixed = maddress.concat(suffix).valueOr:
        continue
      addresses.add(suffixed)
  addresses

proc getDiscoveryAddresses(
    node: BeaconNode,
    interfaces: openArray[NetworkInterface]
): seq[string] =
  var addresses: HashSet[string]
  let
    peerId = node.network.peerIdent
    suffix = MultiAddress.init(multiCodec("p2p"), peerId).valueOr:
      return default(seq[string])
    families =
      block:
        var res: set[AddressFamily]
        case node.config.listenAddress.family
        of IpAddressFamily.IPv4:
          res.incl(AddressFamily.IPv4)
        of IpAddressFamily.IPv6:
          # TODO (cheatfate): Wildcard addresses (dualstack) will be handled
          # later.
          res.incl(AddressFamily.IPv6)
        res
    port = node.config.udpPort
  # Add known external addresses.
  let externalAddresses =
    node.getExternalAddresses(IpTransportProtocol.udpProtocol)
  for address in externalAddresses:
    let saddress = $address
    if saddress notin addresses:
      addresses.incl(saddress)
  # Add local interface addresses.
  let wildcardAddresses =
    interfaces.getWildcardMultiAddresses(
      families, IpTransportProtocol.udpProtocol, port, suffix)
  for address in wildcardAddresses:
    let saddress = $address
    if saddress notin addresses:
      addresses.incl(saddress)
  # Add public addresses discovered by DiscoveryV5.
  let peerAddresses = node.getDiscoveryV5Addresses()
  for address in peerAddresses:
    let saddress = $address
    if saddress notin addresses:
      addresses.incl(saddress)
  addresses.toSeq()

proc getP2PAddresses(
    node: BeaconNode,
    interfaces: openArray[NetworkInterface]
): seq[string] =
  var addresses: HashSet[string]
  # Add known external addresses.
  let externalAddresses =
    node.getExternalAddresses(IpTransportProtocol.tcpProtocol)
  for address in externalAddresses:
    let saddress = $address
    if saddress notin addresses:
      addresses.incl(saddress)
  # Add local interface addresses.
  let wildcardAddresses = node.getLibp2pPeerInfoAddresses(interfaces)
  for address in wildcardAddresses:
    let saddress = $address
    if saddress notin addresses:
      addresses.incl(saddress)
  # Add public addresses discovered Libp2p identify protocol.
  let observedAddresses = node.getObservedAddresses()
  for address in observedAddresses:
    let saddress = $address
    if saddress notin addresses:
      addresses.incl(saddress)
  addresses.toSeq()

proc installNodeApiHandlers*(router: var RestRouter, node: BeaconNode) =
  let
    cachedVersion =
      RestApiResponse.prepareJsonResponse((version: "Nimbus/" & fullVersionStr))

  # https://ethereum.github.io/beacon-APIs/#/Node/getNetworkIdentity
  router.api2(MethodGet, "/eth/v1/node/identity") do () -> RestApiResponse:
    let
      interfaces = getInterfaces()
      discoveryAddresses = node.getDiscoveryAddresses(interfaces)
      p2pAddresses = node.getP2PAddresses(interfaces)

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

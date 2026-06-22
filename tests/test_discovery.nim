# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos/unittest2/asynctests,
  chronos, eth/enr/enr,
  ../beacon_chain/spec/[presets, forks, network, column_map, peerdas_helpers],
  ../beacon_chain/networking/[eth2_network, eth2_discovery],
  ./testutil

proc new(T: type Eth2DiscoveryProtocol,
    pk: keys.PrivateKey,
    enrIp: Opt[IpAddress], enrTcpPort, enrUdpPort: Opt[Port],
    bindPort: Port, bindIp: IpAddress,
    enrFields: openArray[(string, seq[byte])] = [],
    rng: ref HmacDrbgContext): T =
  newProtocol(pk, enrIp, enrTcpPort, enrUdpPort, enrFields,
    bindPort = bindPort, bindIp = bindIp, rng = rng)

proc generateNode(rng: ref HmacDrbgContext, port: Port,
    enrFields: openArray[(string, seq[byte])] = []): Eth2DiscoveryProtocol =
  let ip =
    try:
      parseIpAddress("127.0.0.1")
    except ValueError:
      raiseAssert "Argument is a valid IP address"
  Eth2DiscoveryProtocol.new(keys.PrivateKey.random(rng[]),
        Opt.some(ip), Opt.some(port), Opt.some(port), port, ip, enrFields, rng = rng)

proc generateIntersectMap(map: ColumnMap, intersection, total: int): ColumnMap =
  doAssert(total <= NUMBER_OF_COLUMNS)
  doAssert(intersection <= total)
  doAssert(len(map) >= intersection)

  var res: ColumnMap
  for i in map:
    if len(res) == intersection:
      break
    res.incl(i)

  for i in 0 ..< NUMBER_OF_COLUMNS:
    if ColumnIndex(i) notin map:
      if len(res) == total:
        break
      res.incl(ColumnIndex(i))

  res

const
  noAttnetsPreference = AttnetBits()
  noSyncnetsPreference = SyncnetBits()
  noCgcnetsPreference = ColumnMap()

suite "Eth2 specific discovery tests":
  setup:
    let
      rng = HmacDrbgContext.new()
      enrForkId = ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0))

  asyncTest "Attestation subnet query":
    var attnets: AttnetBits
    attnets.setBit(34)

    let
      node1 = generateNode(rng, Port(5000))
      node2 = generateNode(rng, Port(5001), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(attnets)
      })

    node1.open()
    node2.open()

    # ping in one direction to add node2 to routing table of node1
    check (await node2.ping(node1.localNode)).isOk()

    var attnetsSelected: AttnetBits
    attnetsSelected.setBit(42)
    attnetsSelected.setBit(34)

    let discovered = await node1.queryRandom(
      defaultRuntimeConfig,
      enrForkId, attnetsSelected, noSyncnetsPreference,
      noCgcnetsPreference, [1, 0, 0])
    check discovered.len == 1

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Sync subnet query":
    var syncnets: SyncnetBits
    syncnets.setBit(1)

    let
      node1 = generateNode(rng, Port(5000))
      node2 = generateNode(rng, Port(5001), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrSyncSubnetsField: SSZ.encode(syncnets)
      })

    node1.open()
    node2.open()

    # ping in one direction to add node2 to routing table of node1
    check (await node2.ping(node1.localNode)).isOk()

    var syncnetsSelected: SyncnetBits
    syncnetsSelected.setBit(1)
    syncnetsSelected.setBit(2)

    let discovered = await node1.queryRandom(
      defaultRuntimeConfig,
      enrForkId, noAttnetsPreference, syncnetsSelected,
      noCgcnetsPreference, [0, 10, 0])
    check discovered.len == 1

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Columns subcustody query":
    let cgcCountNode = CustodyIndex(8)
    let
      node1 = generateNode(rng, Port(5000))
      node2 = generateNode(rng, Port(5001), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrCustodyGroupCountField: SSZ.encode(cgcCountNode)
      })

    node1.open()
    node2.open()

    # ping in one direction to add node2 to routing table of node1
    check (await node2.ping(node1.localNode)).isOk()

    let node2map =
      defaultRuntimeConfig.resolve_column_map_from_custody_groups(
        node2.localNode.id, cgcCountNode)

    check len(node2map) == int(cgcCountNode)


    for i in 1 ..< int(cgcCountNode):
      # create local map just with cgcCountNode columns and where `i` columns
      # intersects with columns in `note2map`.
      let
        localMap = generateIntersectMap(node2map, i, 8)
        discovered = await node1.queryRandom(
          defaultRuntimeConfig,
          enrForkId, noAttnetsPreference, noSyncnetsPreference,
          localMap, [0, 0, 100])
      check discovered.len == 1

    let
      localMap = generateIntersectMap(node2map, 0, 8)
      discovered = await node1.queryRandom(
        defaultRuntimeConfig,
        enrForkId, noAttnetsPreference, noSyncnetsPreference,
        localMap, [0, 0, 100])
    check discovered.len == 0

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Combination subnet query":
    var
      syncnets: SyncnetBits
      attnets: AttnetBits

    attnets.setBit(34)
    syncnets.setBit(1)

    let cgcCountNode = CustodyIndex(8)
    let
      node1 = generateNode(rng, Port(5000))
      node2 = generateNode(rng, Port(5001), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(attnets),
        enrSyncSubnetsField: SSZ.encode(syncnets),
        enrCustodyGroupCountField: SSZ.encode(cgcCountNode)
      })

    node1.open()
    node2.open()

    # ping in one direction to add node2 to routing table of node1
    check (await node2.ping(node1.localNode)).isOk()

    let node2map =
      defaultRuntimeConfig.resolve_column_map_from_custody_groups(
        node2.localNode.id, cgcCountNode)

    check len(node2map) == int(cgcCountNode)

    var syncnetsSelected: SyncnetBits
    syncnetsSelected.setBit(1)
    syncnetsSelected.setBit(2)

    var attnetsSelected: AttnetBits
    attnetsSelected.setBit(42)
    attnetsSelected.setBit(34)

    let
      localMap = generateIntersectMap(node2map, 2, 8)

    let discovered = await node1.queryRandom(
      defaultRuntimeConfig,
      enrForkId, attnetsSelected, syncnetsSelected,
      localMap, [1, 10, 200])

    check discovered.len == 1

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Invalid attnets field":
    var invalidAttnets: BitArray[ATTESTATION_SUBNET_COUNT.int div 2]
    invalidAttnets.setBit(15)
    # TODO: This doesn't fail actually.
    # var invalidAttnets2: BitArray[ATTESTATION_SUBNET_COUNT.int * 2]
    # invalidAttnets2.setBit(15)
    var attnets: AttnetBits
    attnets.setBit(15)

    let
      node1 = generateNode(rng, Port(5000))
      node2 = generateNode(rng, Port(5001), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(invalidAttnets)
      })
      node3 = generateNode(rng, Port(5002), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(attnets)
      })

    node1.open()
    node2.open()
    node3.open()

    check (await node2.ping(node1.localNode)).isOk()
    check (await node3.ping(node1.localNode)).isOk()

    var attnetsSelected: AttnetBits
    attnetsSelected.setBit(15)
    attnetsSelected.setBit(42)

    let discovered = await node1.queryRandom(
      defaultRuntimeConfig,
      enrForkId, attnetsSelected, noSyncnetsPreference,
      noCgcnetsPreference, [1, 0, 0])
    check discovered.len == 1

    await node1.closeWait()
    await node2.closeWait()
    await node3.closeWait()

  asyncTest "Subnet query after ENR update":
    var attnets: AttnetBits
    attnets.setBit(1)

    let
      node1 = generateNode(rng, Port(5000))
      node2 = generateNode(rng, Port(5001), {
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(attnets)
      })

    node1.open()
    node2.open()

    check (await node2.ping(node1.localNode)).isOk()

    var attnetsSelected: AttnetBits
    attnetsSelected.setBit(2)

    block:
      let discovered = await node1.queryRandom(
        defaultRuntimeConfig,
        enrForkId, attnetsSelected, noSyncnetsPreference,
        noCgcnetsPreference, [1, 0, 0])
      check discovered.len == 0

    block:
      attnets.setBit(2)
      check node2.updateRecord({
        enrForkIdField: SSZ.encode(enrForkId),
        enrAttestationSubnetsField: SSZ.encode(attnets)
      }).isOk()

      let nodes = await node1.findNode(node2.localNode, @[0'u16])
      check nodes.isOk() and nodes[].len > 0
      discard node1.addNode(nodes[][0])

      let discovered = await node1.queryRandom(
        defaultRuntimeConfig,
        enrForkId, attnetsSelected, noSyncnetsPreference,
        noCgcnetsPreference, [1, 0, 0])
      check discovered.len == 1

    await node1.closeWait()
    await node2.closeWait()

suite "Fork id compatibility test":
  test "Digest check":
    check false == isCompatibleForkId(
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)),
      ENRForkID(
        fork_digest: ForkDigest([byte 9, 9, 9, 9]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)))

    check true == isCompatibleForkId(
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)),
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)))

  test "Fork check":
    # Future fork should work
    check true == isCompatibleForkId(
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)),
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 2, 2, 2, 2]),
        next_fork_epoch: Epoch(2)))

    # Past fork should fail
    check false == isCompatibleForkId(
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 1]),
        next_fork_epoch: Epoch(0)),
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)))

  test "Next fork epoch check":
    # Same fork should check next_fork_epoch
    check false == isCompatibleForkId(
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(0)),
      ENRForkID(
        fork_digest: ForkDigest([byte 0, 1, 2, 3]),
        next_fork_version: Version([byte 0, 0, 0, 0]),
        next_fork_epoch: Epoch(2)))

suite "Discovery fork ID":
  test "Expected fork IDs":
    let genesis_validators_root = ZERO_HASH
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = 5.Epoch
    cfg.BELLATRIX_FORK_EPOCH = 10.Epoch

    let
      # Phase 0
      phase0ForkId = block:
        let
          current_fork_version = cfg.GENESIS_FORK_VERSION
          next_fork_version = current_fork_version
          fork_digest = compute_fork_digest(
            current_fork_version, genesis_validators_root)
          forkId = ENRForkID(
            fork_digest: fork_digest,
            next_fork_version: next_fork_version,
            next_fork_epoch: cfg.ALTAIR_FORK_EPOCH)
        for epoch in GENESIS_EPOCH ..< cfg.ALTAIR_FORK_EPOCH - 1:
          check cfg.getDiscoveryForkID(epoch, genesis_validators_root) == forkId
        forkId

      # Altair should become visible 1 epoch before the fork
      phase0AltairForkId = block:
        let
          current_fork_version = cfg.GENESIS_FORK_VERSION
          next_fork_version = cfg.ALTAIR_FORK_VERSION
          fork_digest = compute_fork_digest(
            current_fork_version, genesis_validators_root)
          forkId = ENRForkID(
            fork_digest: fork_digest,
            next_fork_version: next_fork_version,
            next_fork_epoch: cfg.ALTAIR_FORK_EPOCH)
        for epoch in cfg.ALTAIR_FORK_EPOCH - 1 ..< cfg.ALTAIR_FORK_EPOCH:
          check cfg.getDiscoveryForkID(epoch, genesis_validators_root) == forkId
        forkId

      # Altair
      altairForkId = block:
        let
          current_fork_version = cfg.ALTAIR_FORK_VERSION
          next_fork_version = current_fork_version
          fork_digest = compute_fork_digest(
            current_fork_version, genesis_validators_root)
          forkId = ENRForkID(
            fork_digest: fork_digest,
            next_fork_version: next_fork_version,
            next_fork_epoch: cfg.BELLATRIX_FORK_EPOCH)
        for epoch in cfg.ALTAIR_FORK_EPOCH ..< cfg.BELLATRIX_FORK_EPOCH - 1:
          check cfg.getDiscoveryForkID(epoch, genesis_validators_root) == forkId
        forkId

      # Bellatrix should become visible 1 epoch before the fork
      altairBellatrixForkId = block:
        let
          current_fork_version = cfg.ALTAIR_FORK_VERSION
          next_fork_version = cfg.BELLATRIX_FORK_VERSION
          fork_digest = compute_fork_digest(
            current_fork_version, genesis_validators_root)
          forkId = ENRForkID(
            fork_digest: fork_digest,
            next_fork_version: next_fork_version,
            next_fork_epoch: cfg.BELLATRIX_FORK_EPOCH)
        for epoch in cfg.BELLATRIX_FORK_EPOCH - 1 ..< cfg.BELLATRIX_FORK_EPOCH:
          check cfg.getDiscoveryForkID(epoch, genesis_validators_root) == forkId
        forkId

      # Bellatrix
      bellatrixForkId = block:
        let
          current_fork_version = cfg.BELLATRIX_FORK_VERSION
          next_fork_version = current_fork_version
          fork_digest = compute_fork_digest(
            current_fork_version, genesis_validators_root)
          forkId = ENRForkID(
            fork_digest: fork_digest,
            next_fork_version: next_fork_version,
            next_fork_epoch: FAR_FUTURE_EPOCH)
        for epoch in cfg.BELLATRIX_FORK_EPOCH ..< cfg.BELLATRIX_FORK_EPOCH + 5:
          check cfg.getDiscoveryForkID(epoch, genesis_validators_root) == forkId
        forkId

    check:  # isCompatibleForkId(ourForkId, peerForkId)
      isCompatibleForkId(phase0ForkId, phase0ForkId)
      isCompatibleForkId(phase0ForkId, phase0AltairForkId)
      not isCompatibleForkId(phase0ForkId, altairForkId)
      not isCompatibleForkId(phase0ForkId, altairBellatrixForkId)
      not isCompatibleForkId(phase0ForkId, bellatrixForkId)

      not isCompatibleForkId(phase0AltairForkId, phase0ForkId)  # fork -1 epoch
      isCompatibleForkId(phase0AltairForkId, phase0AltairForkId)
      not isCompatibleForkId(phase0AltairForkId, altairForkId)
      not isCompatibleForkId(phase0AltairForkId, altairBellatrixForkId)
      not isCompatibleForkId(phase0AltairForkId, bellatrixForkId)

      not isCompatibleForkId(altairForkId, phase0ForkId)
      not isCompatibleForkId(altairForkId, phase0AltairForkId)
      isCompatibleForkId(altairForkId, altairForkId)
      isCompatibleForkId(altairForkId, altairBellatrixForkId)
      not isCompatibleForkId(altairForkId, bellatrixForkId)

      not isCompatibleForkId(altairBellatrixForkId, phase0ForkId)
      not isCompatibleForkId(altairBellatrixForkId, phase0AltairForkId)
      not isCompatibleForkId(altairBellatrixForkId, altairForkId)  # fork -1 ep
      isCompatibleForkId(altairBellatrixForkId, altairBellatrixForkId)
      not isCompatibleForkId(altairBellatrixForkId, bellatrixForkId)

      not isCompatibleForkId(bellatrixForkId, phase0ForkId)
      not isCompatibleForkId(bellatrixForkId, phase0AltairForkId)
      not isCompatibleForkId(bellatrixForkId, altairForkId)
      not isCompatibleForkId(bellatrixForkId, altairBellatrixForkId)
      isCompatibleForkId(bellatrixForkId, bellatrixForkId)

# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  testutils/unittests,
  chronos, stew/shims/net, eth/keys, eth/p2p/discoveryv5/enr,
  ../beacon_chain/spec/[forks, network],
  ../beacon_chain/networking/[eth2_network, eth2_discovery],
  ./testutil

proc new(T: type Eth2DiscoveryProtocol,
    pk: keys.PrivateKey,
    enrIp: Option[ValidIpAddress], enrTcpPort, enrUdpPort: Option[Port],
    bindPort: Port, bindIp: ValidIpAddress,
    enrFields: openArray[(string, seq[byte])] = [],
    rng: ref HmacDrbgContext):
    T {.raises: [CatchableError, Defect].} =

  newProtocol(pk, enrIp, enrTcpPort, enrUdpPort, enrFields,
    bindPort = bindPort, bindIp = bindIp, rng = rng)

proc generateNode(rng: ref HmacDrbgContext, port: Port,
    enrFields: openArray[(string, seq[byte])] = []): Eth2DiscoveryProtocol =
  let ip = ValidIpAddress.init("127.0.0.1")
  Eth2DiscoveryProtocol.new(keys.PrivateKey.random(rng[]),
        some(ip), some(port), some(port), port, ip, enrFields, rng = rng)

# TODO: Add tests with a syncnets preference
const noSyncnetsPreference = SyncnetBits()

procSuite "Eth2 specific discovery tests":
  let
    rng = keys.newRng()
    enrForkId = ENRForkID(
      fork_digest: ForkDigest([byte 0, 1, 2, 3]),
      next_fork_version: Version([byte 0, 0, 0, 0]),
      next_fork_epoch: Epoch(0))

  asyncTest "Subnet query":
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
      enrForkId, attnetsSelected, noSyncnetsPreference, 1)
    check discovered.len == 1

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Invalid attnets field":
    var invalidAttnets: BitArray[ATTESTATION_SUBNET_COUNT div 2]
    invalidAttnets.setBit(15)
    # TODO: This doesn't fail actually.
    # var invalidAttnets2: BitArray[ATTESTATION_SUBNET_COUNT * 2]
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
      enrForkId, attnetsSelected, noSyncnetsPreference, 1)
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
        enrForkId, attnetsSelected, noSyncnetsPreference, 1)
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
        enrForkId, attnetsSelected, noSyncnetsPreference, 1)
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

    # Phase 0
    for epoch in GENESIS_EPOCH ..< cfg.ALTAIR_FORK_EPOCH - 1:
      let
        current_fork_version = cfg.GENESIS_FORK_VERSION
        next_fork_version = current_fork_version
        fork_digest = compute_fork_digest(
          current_fork_version, genesis_validators_root)

      check cfg.getDiscoveryForkID(epoch, genesis_validators_root) ==
        ENRForkID(
          fork_digest: fork_digest,
          next_fork_version: next_fork_version,
          next_fork_epoch: FAR_FUTURE_EPOCH)

    # Altair should become visible 1 epoch before the fork
    for epoch in cfg.ALTAIR_FORK_EPOCH - 1 ..< cfg.ALTAIR_FORK_EPOCH:
      let
        current_fork_version = cfg.GENESIS_FORK_VERSION
        next_fork_version = cfg.ALTAIR_FORK_VERSION
        fork_digest = compute_fork_digest(
          current_fork_version, genesis_validators_root)

      check cfg.getDiscoveryForkID(epoch, genesis_validators_root) ==
        ENRForkID(
          fork_digest: fork_digest,
          next_fork_version: next_fork_version,
          next_fork_epoch: cfg.ALTAIR_FORK_EPOCH)

    # Altair
    for epoch in cfg.ALTAIR_FORK_EPOCH ..< cfg.BELLATRIX_FORK_EPOCH - 1:
      let
        current_fork_version = cfg.ALTAIR_FORK_VERSION
        next_fork_version = current_fork_version
        fork_digest = compute_fork_digest(
          current_fork_version, genesis_validators_root)

      check cfg.getDiscoveryForkID(epoch, genesis_validators_root) ==
        ENRForkID(
          fork_digest: fork_digest,
          next_fork_version: next_fork_version,
          next_fork_epoch: FAR_FUTURE_EPOCH)

    # Bellatrix should become visible 1 epoch before the fork
    for epoch in cfg.BELLATRIX_FORK_EPOCH - 1 ..< cfg.BELLATRIX_FORK_EPOCH:
      let
        current_fork_version = cfg.ALTAIR_FORK_VERSION
        next_fork_version = cfg.BELLATRIX_FORK_VERSION
        fork_digest = compute_fork_digest(
          current_fork_version, genesis_validators_root)

      check cfg.getDiscoveryForkID(epoch, genesis_validators_root) ==
        ENRForkID(
          fork_digest: fork_digest,
          next_fork_version: next_fork_version,
          next_fork_epoch: cfg.BELLATRIX_FORK_EPOCH)

    # Bellatrix
    for epoch in cfg.BELLATRIX_FORK_EPOCH ..< cfg.BELLATRIX_FORK_EPOCH + 5:
      let
        current_fork_version = cfg.BELLATRIX_FORK_VERSION
        next_fork_version = current_fork_version
        fork_digest = compute_fork_digest(
          current_fork_version, genesis_validators_root)

      check cfg.getDiscoveryForkID(epoch, genesis_validators_root) ==
        ENRForkID(
          fork_digest: fork_digest,
          next_fork_version: next_fork_version,
          next_fork_epoch: FAR_FUTURE_EPOCH)

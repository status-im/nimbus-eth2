# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  std/os,
  chronicles, chronos,
  eth/keys,
  ./spec/beaconstate,
  "."/[light_client, nimbus_binary_common, version]

proc onFinalizedHeader(lightClient: LightClient) =
  notice "New LC finalized header",
    finalized_header = shortLog(lightClient.finalizedHeader.get)

proc onOptimisticHeader(lightClient: LightClient) =
  notice "New LC optimistic header",
    optimistic_header = shortLog(lightClient.optimisticHeader.get)

proc onSecond(
    lightClient: LightClient,
    config: LightClientConf,
    getBeaconTime: GetBeaconTimeFn) =
  ## This procedure will be called once per second.
  let wallSlot = getBeaconTime().slotOrZero()
  if checkIfShouldStopAtEpoch(wallSlot, config.stopAtEpoch):
    quit(0)

  lightClient.updateGossipStatus(wallSlot + 1)

proc runOnSecondLoop(
    lightClient: LightClient,
    config: LightClientConf,
    getBeaconTime: GetBeaconTimeFn) {.async.} =
  while true:
    onSecond(lightClient, config, getBeaconTime)
    await chronos.sleepAsync(chronos.seconds(1))

programMain:
  var config = makeBannerAndConfig(
    "Nimbus light client " & fullVersionStr, LightClientConf)
  setupLogging(config.logLevel, config.logStdout, config.logFile)

  notice "Launching light client",
    version = fullVersionStr, cmdParams = commandLineParams(), config

  let metadata = loadEth2Network(config.eth2Network)
  for node in metadata.bootstrapNodes:
    config.bootstrapNodes.add node
  template cfg(): auto = metadata.cfg

  let
    genesisState =
      try:
        template genesisData(): auto = metadata.genesisData
        newClone(readSszForkedHashedBeaconState(
          cfg, genesisData.toOpenArrayByte(genesisData.low, genesisData.high)))
      except CatchableError as err:
        raiseAssert "Invalid baked-in state: " & err.msg

    beaconClock = BeaconClock.init(
      getStateField(genesisState[], genesis_time))
    getBeaconTime = beaconClock.getBeaconTimeFn()

    genesis_validators_root =
      getStateField(genesisState[], genesis_validators_root)
    forkDigests = newClone ForkDigests.init(cfg, genesis_validators_root)

    genesisBlockRoot = get_initial_beacon_block(genesisState[]).root

    rng = keys.newRng()
    netKeys = optimisticgetRandomNetKeys(rng[])
    network = createEth2Node(
      rng, config, netKeys, cfg,
      forkDigests, getBeaconTime, genesis_validators_root)

    lightClient = createLightClient(
      network, rng, config, cfg,
      forkDigests, getBeaconTime, genesis_validators_root)

  info "Listening to incoming network requests"
  network.initBeaconSync(cfg, forkDigests, genesisBlockRoot, getBeaconTime)
  lightClient.installMessageValidators()
  waitFor network.startListening()
  waitFor network.start()

  lightClient.onFinalizedHeader = onFinalizedHeader
  lightClient.onOptimisticHeader = onOptimisticHeader
  lightClient.trustedBlockRoot = some config.trustedBlockRoot
  lightClient.start()

  asyncSpawn runOnSecondLoop(lightClient, config, getBeaconTime)
  while true:
    poll()

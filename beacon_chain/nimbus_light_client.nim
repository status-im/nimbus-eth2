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
  chronicles, chronicles/chronos_tools, chronos,
  eth/keys,
  ./eth1/eth1_monitor,
  ./spec/beaconstate,
  ./sync/optimistic_sync_light_client,
  "."/[light_client, nimbus_binary_common, version]

from ./gossip_processing/block_processor import newExecutionPayload
from ./gossip_processing/consensus_manager import runForkchoiceUpdated

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

    eth1Monitor =
      if config.web3Urls.len > 0:
        Eth1Monitor.init(
          cfg, db = nil, getBeaconTime, config.web3Urls,
          none(DepositContractSnapshot), metadata.eth1Network,
          forcePolling = false,
          rng[].loadJwtSecret(config, allowCreate = false))
      else:
        nil

    optimisticProcessor = proc(signedBlock: ForkedMsgTrustedSignedBeaconBlock):
        Future[void] {.async.} =
      debug "New LC optimistic block",
        opt = signedBlock.toBlockId(),
        wallSlot = getBeaconTime().slotOrZero
      withBlck(signedBlock):
        when stateFork >= BeaconStateFork.Bellatrix:
          if blck.message.is_execution_block:
            await eth1Monitor.ensureDataProvider()

            # engine_newPayloadV1
            template payload(): auto = blck.message.body.execution_payload
            discard await eth1Monitor.newExecutionPayload(payload)

            # engine_forkchoiceUpdatedV1
            discard await eth1Monitor.runForkchoiceUpdated(
              headBlockRoot = payload.block_hash,
              finalizedBlockRoot = ZERO_HASH)
        else: discard
      return
    optSync = initLCOptimisticSync(
      network, getBeaconTime, optimisticProcessor,
      config.safeSlotsToImportOptimistically)

    lightClient = createLightClient(
      network, rng, config, cfg,
      forkDigests, getBeaconTime, genesis_validators_root)

  info "Listening to incoming network requests"
  network.initBeaconSync(cfg, forkDigests, genesisBlockRoot, getBeaconTime)
  lightClient.installMessageValidators()
  waitFor network.startListening()
  waitFor network.start()

  proc shouldSyncOptimistically(slot: Slot): bool =
    const
      # Maximum age of light client optimistic header to use optimistic sync
      maxAge = 2 * SLOTS_PER_EPOCH

    if eth1Monitor == nil:
      false
    elif getBeaconTime().slotOrZero > slot + maxAge:
      false
    else:
      true

  proc onFinalizedHeader(lightClient: LightClient) =
    notice "New LC finalized header",
      finalized_header = shortLog(lightClient.finalizedHeader.get)
    let optimisticHeader = lightClient.optimisticHeader.valueOr:
      return
    if not shouldSyncOptimistically(optimisticHeader.slot):
      return
    let finalizedHeader = lightClient.finalizedHeader.valueOr:
      return
    optSync.setOptimisticHeader(optimisticHeader)
    optSync.setFinalizedHeader(finalizedHeader)

  proc onOptimisticHeader(lightClient: LightClient) =
    notice "New LC optimistic header",
      optimistic_header = shortLog(lightClient.optimisticHeader.get)
    let optimisticHeader = lightClient.optimisticHeader.valueOr:
      return
    if not shouldSyncOptimistically(optimisticHeader.slot):
      return
    optSync.setOptimisticHeader(optimisticHeader)

  lightClient.onFinalizedHeader = onFinalizedHeader
  lightClient.onOptimisticHeader = onOptimisticHeader
  lightClient.trustedBlockRoot = some config.trustedBlockRoot

  var nextExchangeTransitionConfTime: Moment

  proc onSecond(time: Moment) =
    # engine_exchangeTransitionConfigurationV1
    if time > nextExchangeTransitionConfTime and eth1Monitor != nil:
      nextExchangeTransitionConfTime = time + chronos.minutes(1)
      traceAsyncErrors eth1Monitor.exchangeTransitionConfiguration()

    let wallSlot = getBeaconTime().slotOrZero()
    checkIfShouldStopAtEpoch(wallSlot, config.stopAtEpoch)

    lightClient.updateGossipStatus(wallSlot + 1)

  proc runOnSecondLoop() {.async.} =
    let sleepTime = chronos.seconds(1)
    while true:
      let start = chronos.now(chronos.Moment)
      await chronos.sleepAsync(sleepTime)
      let afterSleep = chronos.now(chronos.Moment)
      let sleepTime = afterSleep - start
      onSecond(start)
      let finished = chronos.now(chronos.Moment)
      let processingTime = finished - afterSleep
      trace "onSecond task completed", sleepTime, processingTime

  onSecond(Moment.now())
  optSync.start()
  lightClient.start()

  asyncSpawn runOnSecondLoop()
  while true:
    poll()

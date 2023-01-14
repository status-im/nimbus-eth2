# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronicles,
  eth/keys,
  ./gossip_processing/light_client_processor,
  ./networking/[eth2_network, topic_params],
  ./spec/datatypes/altair,
  ./spec/helpers,
  ./sync/light_client_manager,
  "."/[beacon_clock, conf_light_client]

export LightClientFinalizationMode, eth2_network, conf_light_client

logScope: topics = "lightcl"

template storeDataFork: LightClientDataFork = LightClientProcessor.storeDataFork

type
  LightClientHeaderCallback* =
    proc(lightClient: LightClient, header: storeDataFork.LightClientHeader) {.
      gcsafe, raises: [Defect].}

  LightClientValueObserver[V] =
    proc(lightClient: LightClient, v: V) {.gcsafe, raises: [Defect].}
  LightClientBootstrapObserver* =
    LightClientValueObserver[ForkedLightClientBootstrap]
  LightClientUpdateObserver* =
    LightClientValueObserver[ForkedLightClientUpdate]
  LightClientFinalityUpdateObserver* =
    LightClientValueObserver[ForkedLightClientFinalityUpdate]
  LightClientOptimisticUpdateObserver* =
    LightClientValueObserver[ForkedLightClientOptimisticUpdate]

  LightClient* = ref object
    network: Eth2Node
    cfg: RuntimeConfig
    forkDigests: ref ForkDigests
    getBeaconTime: GetBeaconTimeFn
    store: ref Option[storeDataFork.LightClientStore]
    processor: ref LightClientProcessor
    manager: LightClientManager
    gossipState: GossipState
    onFinalizedHeader*, onOptimisticHeader*: LightClientHeaderCallback
    bootstrapObserver*: LightClientBootstrapObserver
    updateObserver*: LightClientUpdateObserver
    finalityUpdateObserver*: LightClientFinalityUpdateObserver
    optimisticUpdateObserver*: LightClientOptimisticUpdateObserver
    trustedBlockRoot*: Option[Eth2Digest]

func storeDataFork*(x: typedesc[LightClient]): LightClientDataFork =
  storeDataFork

func finalizedHeader*(
    lightClient: LightClient): Opt[storeDataFork.LightClientHeader] =
  if lightClient.store[].isSome:
    ok lightClient.store[].get.finalized_header
  else:
    err()

func optimisticHeader*(
    lightClient: LightClient): Opt[storeDataFork.LightClientHeader] =
  if lightClient.store[].isSome:
    ok lightClient.store[].get.optimistic_header
  else:
    err()

func finalizedSyncCommittee*(
    lightClient: LightClient): Opt[altair.SyncCommittee] =
  if lightClient.store[].isSome:
    ok lightClient.store[].get.current_sync_committee
  else:
    err()

proc createLightClient(
    network: Eth2Node,
    rng: ref HmacDrbgContext,
    dumpEnabled: bool,
    dumpDirInvalid, dumpDirIncoming: string,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest,
    finalizationMode: LightClientFinalizationMode
): LightClient =
  let lightClient = LightClient(
    network: network,
    cfg: cfg,
    forkDigests: forkDigests,
    getBeaconTime: getBeaconTime,
    store: (ref Option[storeDataFork.LightClientStore])())

  func getTrustedBlockRoot(): Option[Eth2Digest] =
    lightClient.trustedBlockRoot

  proc onStoreInitialized() =
    discard

  proc onFinalizedHeader() =
    if lightClient.onFinalizedHeader != nil:
      lightClient.onFinalizedHeader(
        lightClient, lightClient.finalizedHeader.get)

  proc onOptimisticHeader() =
    if lightClient.onOptimisticHeader != nil:
      lightClient.onOptimisticHeader(
        lightClient, lightClient.optimisticHeader.get)

  proc bootstrapObserver(obj: ForkedLightClientBootstrap) =
    if lightClient.bootstrapObserver != nil:
      lightClient.bootstrapObserver(lightClient, obj)

  proc updateObserver(obj: ForkedLightClientUpdate) =
    if lightClient.updateObserver != nil:
      lightClient.updateObserver(lightClient, obj)

  proc finalityObserver(obj: ForkedLightClientFinalityUpdate) =
    if lightClient.finalityUpdateObserver != nil:
      lightClient.finalityUpdateObserver(lightClient, obj)

  proc optimisticObserver(obj: ForkedLightClientOptimisticUpdate) =
    if lightClient.optimisticUpdateObserver != nil:
      lightClient.optimisticUpdateObserver(lightClient, obj)

  lightClient.processor = LightClientProcessor.new(
    dumpEnabled, dumpDirInvalid, dumpDirIncoming,
    cfg, genesis_validators_root, finalizationMode,
    lightClient.store, getBeaconTime, getTrustedBlockRoot,
    onStoreInitialized, onFinalizedHeader, onOptimisticHeader,
    bootstrapObserver, updateObserver, finalityObserver, optimisticObserver)

  proc lightClientVerifier(obj: SomeForkedLightClientObject):
      Future[Result[void, VerifierError]] =
    let resfut = newFuture[Result[void, VerifierError]]("lightClientVerifier")
    lightClient.processor[].addObject(MsgSource.gossip, obj, resfut)
    resfut
  proc bootstrapVerifier(obj: ForkedLightClientBootstrap): auto =
    lightClientVerifier(obj)
  proc updateVerifier(obj: ForkedLightClientUpdate): auto =
    lightClientVerifier(obj)
  proc finalityVerifier(obj: ForkedLightClientFinalityUpdate): auto =
    lightClientVerifier(obj)
  proc optimisticVerifier(obj: ForkedLightClientOptimisticUpdate): auto =
    lightClientVerifier(obj)

  func isLightClientStoreInitialized(): bool =
    lightClient.store[].isSome

  func isNextSyncCommitteeKnown(): bool =
    if lightClient.store[].isSome:
      lightClient.store[].get.is_next_sync_committee_known
    else:
      false

  func getFinalizedPeriod(): SyncCommitteePeriod =
    if lightClient.store[].isSome:
      lightClient.store[].get.finalized_header
        .beacon.slot.sync_committee_period
    else:
      GENESIS_SLOT.sync_committee_period

  func getOptimisticPeriod(): SyncCommitteePeriod =
    if lightClient.store[].isSome:
      lightClient.store[].get.optimistic_header
        .beacon.slot.sync_committee_period
    else:
      GENESIS_SLOT.sync_committee_period

  lightClient.manager = LightClientManager.init(
    lightClient.network, rng, getTrustedBlockRoot,
    bootstrapVerifier, updateVerifier, finalityVerifier, optimisticVerifier,
    isLightClientStoreInitialized, isNextSyncCommitteeKnown,
    getFinalizedPeriod, getOptimisticPeriod, getBeaconTime)

  lightClient.gossipState = {}

  lightClient

proc createLightClient*(
    network: Eth2Node,
    rng: ref HmacDrbgContext,
    config: BeaconNodeConf,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest,
    finalizationMode: LightClientFinalizationMode
): LightClient =
  createLightClient(
    network, rng,
    config.dumpEnabled, config.dumpDirInvalid, config.dumpDirIncoming,
    cfg, forkDigests, getBeaconTime, genesis_validators_root, finalizationMode)

proc createLightClient*(
    network: Eth2Node,
    rng: ref HmacDrbgContext,
    config: LightClientConf,
    cfg: RuntimeConfig,
    forkDigests: ref ForkDigests,
    getBeaconTime: GetBeaconTimeFn,
    genesis_validators_root: Eth2Digest,
    finalizationMode: LightClientFinalizationMode
): LightClient =
  createLightClient(
    network, rng,
    dumpEnabled = false, dumpDirInvalid = ".", dumpDirIncoming = ".",
    cfg, forkDigests, getBeaconTime, genesis_validators_root, finalizationMode)

proc start*(lightClient: LightClient) =
  notice "Starting light client",
    trusted_block_root = lightClient.trustedBlockRoot
  lightClient.manager.start()

proc resetToFinalizedHeader*(
    lightClient: LightClient,
    header: storeDataFork.LightClientHeader,
    current_sync_committee: SyncCommittee) =
  lightClient.processor[].resetToFinalizedHeader(header, current_sync_committee)

import metrics

from
  ./gossip_processing/eth2_processor
import
  processLightClientFinalityUpdate, processLightClientOptimisticUpdate

declareCounter beacon_light_client_finality_updates_received,
  "Number of valid LC finality updates processed by this node"
declareCounter beacon_light_client_finality_updates_dropped,
  "Number of invalid LC finality updates dropped by this node", labels = ["reason"]
declareCounter beacon_light_client_optimistic_updates_received,
  "Number of valid LC optimistic updates processed by this node"
declareCounter beacon_light_client_optimistic_updates_dropped,
  "Number of invalid LC optimistic updates dropped by this node", labels = ["reason"]

template logReceived(
    msg: ForkyLightClientFinalityUpdate) =
  debug "LC finality update received", finality_update = msg

template logValidated(
    msg: ForkyLightClientFinalityUpdate) =
  trace "LC finality update validated", finality_update = msg
  beacon_light_client_finality_updates_received.inc()

proc logDropped(
    msg: ForkyLightClientFinalityUpdate, es: varargs[ValidationError]) =
  for e in es:
    debug "Dropping LC finality update", finality_update = msg, error = e
  beacon_light_client_finality_updates_dropped.inc(1, [$es[0][0]])

template logReceived(
    msg: ForkyLightClientOptimisticUpdate) =
  debug "LC optimistic update received", optimistic_update = msg

template logValidated(
    msg: ForkyLightClientOptimisticUpdate) =
  trace "LC optimistic update validated", optimistic_update = msg
  beacon_light_client_optimistic_updates_received.inc()

proc logDropped(
    msg: ForkyLightClientOptimisticUpdate, es: varargs[ValidationError]) =
  for e in es:
    debug "Dropping LC optimistic update", optimistic_update = msg, error = e
  beacon_light_client_optimistic_updates_dropped.inc(1, [$es[0][0]])

proc installMessageValidators*(
    lightClient: LightClient, eth2Processor: ref Eth2Processor = nil) =
  # When registering multiple message validators, IGNORE results take precedence
  # over ACCEPT results. However, because the opposite behaviour is needed here,
  # we handle both full node and light client validation in this module
  template getLocalWallPeriod(): auto =
    lightClient.getBeaconTime().slotOrZero().sync_committee_period

  template validate[T: SomeForkyLightClientObject](
      msg: T,
      contextFork: BeaconStateFork,
      validatorProcName: untyped): ValidationResult =
    msg.logReceived()

    if contextFork != lightClient.cfg.stateForkAtEpoch(msg.contextEpoch):
      msg.logDropped(
        (ValidationResult.Reject, cstring "Invalid context fork"))
      return ValidationResult.Reject

    const lcDataFork = T.kind
    var obj = T.Forked(kind: lcDataFork)
    obj.forky(lcDataFork) = msg

    var
      ignoreErrors {.noinit.}: array[2, ValidationError]
      numIgnoreErrors = 0

    let res1 =
      if eth2Processor != nil:
        let
          v = eth2Processor[].`validatorProcName`(MsgSource.gossip, obj)
          res = v.toValidationResult()
        if res == ValidationResult.Reject:
          msg.logDropped(v.error)
          return res
        if res == ValidationResult.Ignore:
          ignoreErrors[numIgnoreErrors] = v.error
          inc numIgnoreErrors
        res
      else:
        ValidationResult.Ignore

    let res2 =
      if lightClient.manager.isGossipSupported(getLocalWallPeriod()):
        let
          v = lightClient.processor[].`validatorProcName`(MsgSource.gossip, obj)
          res = v.toValidationResult()
        if res == ValidationResult.Reject:
          msg.logDropped(v.error)
          return res
        if res == ValidationResult.Ignore:
          ignoreErrors[numIgnoreErrors] = v.error
          inc numIgnoreErrors
        res
      else:
        ValidationResult.Ignore

    if res1 == ValidationResult.Accept or res2 == ValidationResult.Accept:
      msg.logValidated()
      return ValidationResult.Accept

    doAssert res1 == ValidationResult.Ignore and res2 == ValidationResult.Ignore
    if numIgnoreErrors == 0:
      ignoreErrors[numIgnoreErrors] = static:
        (ValidationResult.Ignore, cstring T.name & ": irrelevant")
      inc numIgnoreErrors
    msg.logDropped(ignoreErrors.toOpenArray(0, numIgnoreErrors - 1))
    ValidationResult.Ignore

  let forkDigests = lightClient.forkDigests
  for stateFork in BeaconStateFork:
    if stateFork >= BeaconStateFork.Capella:
      # Format is still in development, do not use Gossip at this time.
      continue

    withLcDataFork(lcDataForkAtStateFork(stateFork)):
      when lcDataFork > LightClientDataFork.None:
        let digest = forkDigests[].atStateFork(stateFork)

        lightClient.network.addValidator(
          getLightClientFinalityUpdateTopic(digest),
          proc(msg: lcDataFork.LightClientFinalityUpdate): ValidationResult =
            validate(msg, stateFork, processLightClientFinalityUpdate))

        lightClient.network.addValidator(
          getLightClientOptimisticUpdateTopic(digest),
          proc(msg: lcDataFork.LightClientOptimisticUpdate): ValidationResult =
            validate(msg, stateFork, processLightClientOptimisticUpdate))

proc updateGossipStatus*(
    lightClient: LightClient, slot: Slot, dagIsBehind = default(Option[bool])) =
  template cfg(): auto = lightClient.cfg

  let
    epoch = slot.epoch

    lcBehind =
      not lightClient.manager.isGossipSupported(slot.sync_committee_period)
    dagBehind =
      # While separate message validators can be installed for both
      # full node and light client (both are called unless one rejects msg),
      # only a single subscription is supported per topic.
      # The full node subscription is also handled in this module, even though
      # it does not directly relate to the client side of the LC sync protocol
      dagIsBehind.get(true)
    isBehind = lcBehind and dagBehind

    currentEpochTargetGossipState = getTargetGossipState(
      epoch, cfg.ALTAIR_FORK_EPOCH, cfg.BELLATRIX_FORK_EPOCH,
      cfg.CAPELLA_FORK_EPOCH, cfg.EIP4844_FORK_EPOCH, isBehind)
    targetGossipState =
      if lcBehind or epoch < 1:
        currentEpochTargetGossipState
      else:
        # The fork digest for light client topics depends on the attested slot,
        # which is in the past relative to the signature slot (current slot).
        # Therefore, LC topic subscriptions are kept for 1 extra epoch.
        let previousEpochTargetGossipState = getTargetGossipState(
          epoch - 1, cfg.ALTAIR_FORK_EPOCH, cfg.BELLATRIX_FORK_EPOCH,
          cfg.CAPELLA_FORK_EPOCH, cfg.EIP4844_FORK_EPOCH, isBehind)
        currentEpochTargetGossipState + previousEpochTargetGossipState

  template currentGossipState(): auto = lightClient.gossipState
  if currentGossipState == targetGossipState:
    return

  if currentGossipState.card == 0 and targetGossipState.card > 0:
    debug "Enabling LC topic subscriptions",
      wallSlot = slot, targetGossipState
  elif currentGossipState.card > 0 and targetGossipState.card == 0:
    debug "Disabling LC topic subscriptions",
      wallSlot = slot
  else:
    # Individual forks added / removed
    discard

  let
    newGossipForks = targetGossipState - currentGossipState
    oldGossipForks = currentGossipState - targetGossipState

  for gossipFork in oldGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      if gossipFork >= BeaconStateFork.Capella:
        # Format is still in development, do not use Gossip at this time.
        continue
      let forkDigest = lightClient.forkDigests[].atStateFork(gossipFork)
      lightClient.network.unsubscribe(
        getLightClientFinalityUpdateTopic(forkDigest))
      lightClient.network.unsubscribe(
        getLightClientOptimisticUpdateTopic(forkDigest))

  for gossipFork in newGossipForks:
    if gossipFork >= BeaconStateFork.Altair:
      if gossipFork >= BeaconStateFork.Capella:
        # Format is still in development, do not use Gossip at this time.
        continue
      let forkDigest = lightClient.forkDigests[].atStateFork(gossipFork)
      lightClient.network.subscribe(
        getLightClientFinalityUpdateTopic(forkDigest),
        basicParams)
      lightClient.network.subscribe(
        getLightClientOptimisticUpdateTopic(forkDigest),
        basicParams)

  lightClient.gossipState = targetGossipState

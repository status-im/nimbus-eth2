# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, metrics,
  ../spec/light_client_sync,
  ../consensus_object_pools/block_pools_types,
  ".."/[beacon_clock, sszdump],
  "."/[eth2_processor, gossip_validation]

export sszdump, eth2_processor, gossip_validation

logScope: topics = "gossip_lc"

# Light Client Processor
# ------------------------------------------------------------------------------
# The light client processor handles received light client objects

declareHistogram light_client_store_object_duration_seconds,
  "storeObject() duration", buckets = [0.25, 0.5, 1, 2, 4, 8, Inf]

type
  Nothing = object

  GetTrustedBlockRootCallback* =
    proc(): Option[Eth2Digest] {.gcsafe, raises: [].}
  VoidCallback* =
    proc() {.gcsafe, raises: [].}

  ValueObserver[V] =
    proc(v: V) {.gcsafe, raises: [].}
  BootstrapObserver* =
    ValueObserver[ForkedLightClientBootstrap]
  UpdateObserver* =
    ValueObserver[ForkedLightClientUpdate]
  FinalityUpdateObserver* =
    ValueObserver[ForkedLightClientFinalityUpdate]
  OptimisticUpdateObserver* =
    ValueObserver[ForkedLightClientOptimisticUpdate]

  LightClientFinalizationMode* {.pure.} = enum
    Strict
      ## Only finalize light client data that:
      ## - has been signed by a supermajority (2/3) of the sync committee
      ## - has a valid finality proof
      ##
      ## Optimizes for security, but may become stuck if there is any of:
      ## - non-finality for an entire sync committee period
      ## - low sync committee participation for an entire sync committee period
      ## Such periods need to be covered by an out-of-band syncing mechanism.
      ##
      ## Note that a compromised supermajority of the sync committee is able to
      ## sign arbitrary light client data, even after being slashed. The light
      ## client cannot validate the slashing status of sync committee members.
      ## Likewise, voluntarily exited validators may sign bad light client data
      ## for the sync committee periods in which they used to be selected.

    Optimistic
      ## Attempt to finalize light client data not satisfying strict conditions
      ## if there is no progress for an extended period of time and if there are
      ## repeated messages indicating that it is the best available data on the
      ## network for the affected time period.
      ##
      ## Optimizes for availability of recent data, but may end up on incorrect
      ## forks if run in a hostile network environment (no honest peers), or if
      ## the low sync committee participation is being exploited by bad actors.

  LightClientProcessor* = object
    ## This manages the processing of received light client objects
    ##
    ## from:
    ## - Gossip:
    ##   - `LightClientFinalityUpdate`
    ##   - `LightClientOptimisticUpdate`
    ## - `LightClientManager`:
    ##   - `GetLightClientBootstrap`
    ##   - `LightClientUpdatesByRange`
    ##   - `GetLightClientFinalityUpdate`
    ##   - `GetLightClientOptimisticUpdate`
    ##
    ## are then verified and added to:
    ## - `LightClientStore`

    # Config
    # ----------------------------------------------------------------
    dumpEnabled: bool
    dumpDirInvalid: string
    dumpDirIncoming: string
    strictVerification: bool

    # Consumer
    # ----------------------------------------------------------------
    store: ref ForkedLightClientStore
    getBeaconTime: GetBeaconTimeFn
    getTrustedBlockRoot: GetTrustedBlockRootCallback
    onStoreInitialized, onFinalizedHeader, onOptimisticHeader: VoidCallback
    bootstrapObserver: BootstrapObserver
    updateObserver: UpdateObserver
    finalityUpdateObserver: FinalityUpdateObserver
    optimisticUpdateObserver: OptimisticUpdateObserver

    cfg: RuntimeConfig
    genesis_validators_root: Eth2Digest

    case finalizationMode: LightClientFinalizationMode
    of LightClientFinalizationMode.Strict:
      discard
    of LightClientFinalizationMode.Optimistic:
      lastProgressTick: BeaconTime # Moment when last update made progress
      lastDuplicateTick: BeaconTime # Moment when last duplicate update received
      numDupsSinceProgress: int # Number of duplicates since last progress

    latestFinalityUpdate: ForkedLightClientOptimisticUpdate

const
  # These constants have been chosen empirically and are not backed by spec
  duplicateRateLimit = chronos.seconds(5) # Rate limit for counting duplicates
  duplicateCountDelay = chronos.minutes(15) # Delay to start counting duplicates
  minForceUpdateDelay = chronos.minutes(30) # Minimum delay until forced-update
  minForceUpdateDuplicates = 100 # Minimum duplicates until forced-update

# Initialization
# ------------------------------------------------------------------------------

proc new*(
    T: type LightClientProcessor,
    dumpEnabled: bool,
    dumpDirInvalid, dumpDirIncoming: string,
    cfg: RuntimeConfig,
    genesis_validators_root: Eth2Digest,
    finalizationMode: LightClientFinalizationMode,
    store: ref ForkedLightClientStore,
    getBeaconTime: GetBeaconTimeFn,
    getTrustedBlockRoot: GetTrustedBlockRootCallback,
    onStoreInitialized: VoidCallback = nil,
    onFinalizedHeader: VoidCallback = nil,
    onOptimisticHeader: VoidCallback = nil,
    bootstrapObserver: BootstrapObserver = nil,
    updateObserver: UpdateObserver = nil,
    finalityUpdateObserver: FinalityUpdateObserver = nil,
    optimisticUpdateObserver: OptimisticUpdateObserver = nil,
    strictVerification = false
): ref LightClientProcessor =
  (ref LightClientProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    strictVerification: strictVerification,
    store: store,
    getBeaconTime: getBeaconTime,
    getTrustedBlockRoot: getTrustedBlockRoot,
    onStoreInitialized: onStoreInitialized,
    onFinalizedHeader: onFinalizedHeader,
    onOptimisticHeader: onOptimisticHeader,
    bootstrapObserver: bootstrapObserver,
    updateObserver: updateObserver,
    finalityUpdateObserver: finalityUpdateObserver,
    optimisticUpdateObserver: optimisticUpdateObserver,
    cfg: cfg,
    genesis_validators_root: genesis_validators_root,
    finalizationMode: finalizationMode)

# Storage
# ------------------------------------------------------------------------------

proc dumpInvalidObject(
    self: LightClientProcessor,
    obj: SomeForkyLightClientObject) =
  if self.dumpEnabled:
    dump(self.dumpDirInvalid, obj)

proc dumpObject[T](
    self: LightClientProcessor,
    obj: SomeForkyLightClientObject,
    res: Result[T, VerifierError]) =
  if self.dumpEnabled and res.isErr:
    case res.error
    of VerifierError.Invalid:
      self.dumpInvalidObject(obj)
    of VerifierError.MissingParent:
      dump(self.dumpDirIncoming, obj)
    else:
      discard

proc tryForceUpdate(
    self: var LightClientProcessor,
    wallTime: BeaconTime) =
  ## Try to force-update to the next sync committee period.
  let wallSlot = wallTime.slotOrZero()
  doAssert self.finalizationMode == LightClientFinalizationMode.Optimistic

  withForkyStore(self.store[]):
    when lcDataFork > LightClientDataFork.None:
      case forkyStore.process_light_client_store_force_update(wallSlot)
      of NoUpdate:
        discard
      of DidUpdateWithoutSupermajority:
        warn "Light client force-updated without supermajority",
          finalizedSlot = forkyStore.finalized_header.beacon.slot,
          optimisticSlot = forkyStore.optimistic_header.beacon.slot
      of DidUpdateWithoutFinality:
        warn "Light client force-updated without finality proof",
          finalizedSlot = forkyStore.finalized_header.beacon.slot,
          optimisticSlot = forkyStore.optimistic_header.beacon.slot

proc processObject(
    self: var LightClientProcessor,
    obj: SomeForkedLightClientObject,
    wallTime: BeaconTime): Result[void, VerifierError] =
  let
    res = withForkyObject(obj):
      when lcDataFork > LightClientDataFork.None:
        when forkyObject is ForkyLightClientBootstrap:
          if self.store[].kind > LightClientDataFork.None:
            err(VerifierError.Duplicate)
          else:
            let trustedBlockRoot = self.getTrustedBlockRoot()
            if trustedBlockRoot.isNone:
              err(VerifierError.MissingParent)
            else:
              let initRes = initialize_light_client_store(
                trustedBlockRoot.get, forkyObject, self.cfg)
              if initRes.isErr:
                err(initRes.error)
              else:
                self.store[] = ForkedLightClientStore.init(initRes.get)
                ok()
        elif forkyObject is SomeForkyLightClientUpdate:
          if self.store[].kind == LightClientDataFork.None:
            err(VerifierError.MissingParent)
          else:
            if lcDataFork > self.store[].kind:
              info "Upgrading light client",
                oldFork = self.store[].kind, newFork = lcDataFork
              self.store[].migrateToDataFork(lcDataFork)
            withForkyStore(self.store[]):
              when lcDataFork > LightClientDataFork.None:
                let
                  wallSlot = wallTime.slotOrZero()
                  upgradedObject = obj.migratingToDataFork(lcDataFork)
                process_light_client_update(
                  forkyStore, upgradedObject.forky(lcDataFork), wallSlot,
                  self.cfg, self.genesis_validators_root)
              else: raiseAssert "Unreachable"
      else:
        err(VerifierError.Invalid)

  withForkyObject(obj):
    when lcDataFork > LightClientDataFork.None:
      self.dumpObject(forkyObject, res)

  if res.isErr:
    when obj is ForkedLightClientUpdate:
      if self.finalizationMode == LightClientFinalizationMode.Optimistic and
          obj.kind <= self.store[].kind:
        withForkyStore(self.store[]):
          when lcDataFork > LightClientDataFork.None:
            if forkyStore.best_valid_update.isSome:
              # `best_valid_update` is set when supermajority / finality proof
              # is unavailable. In that case, we will wait for a better update.
              # If none is made available within reasonable time, light client
              # is force-updated with best known data to ensure sync progress.
              case res.error
              of VerifierError.Duplicate:
                if wallTime >= self.lastDuplicateTick + duplicateRateLimit:
                  if self.numDupsSinceProgress < minForceUpdateDuplicates:
                    let upgradedObj = obj.migratingToDataFork(lcDataFork)
                    if upgradedObj.forky(lcDataFork).matches(
                        forkyStore.best_valid_update.get):
                      self.lastDuplicateTick = wallTime
                      inc self.numDupsSinceProgress
                  if self.numDupsSinceProgress >= minForceUpdateDuplicates and
                      wallTime >= self.lastProgressTick + minForceUpdateDelay:
                    self.tryForceUpdate(wallTime)
                    self.lastProgressTick = wallTime
                    self.lastDuplicateTick = wallTime + duplicateCountDelay
                    self.numDupsSinceProgress = 0
              else: discard

    return res

  when obj is ForkedLightClientBootstrap | ForkedLightClientUpdate:
    if self.finalizationMode == LightClientFinalizationMode.Optimistic:
      self.lastProgressTick = wallTime
      self.lastDuplicateTick = wallTime + duplicateCountDelay
      self.numDupsSinceProgress = 0

  res

template withReportedProgress(
    obj: SomeForkedLightClientObject | Nothing, body: untyped): bool =
  block:
    let
      oldIsInitialized = self.store[].kind > LightClientDataFork.None
      oldNextCommitteeKnown = withForkyStore(self.store[]):
        when lcDataFork > LightClientDataFork.None:
          forkyStore.is_next_sync_committee_known
        else:
          false
    var
      oldFinalized = withForkyStore(self.store[]):
        when lcDataFork > LightClientDataFork.None:
          ForkedLightClientHeader.init(forkyStore.finalized_header)
        else:
          default(ForkedLightClientHeader)
      oldOptimistic = withForkyStore(self.store[]):
        when lcDataFork > LightClientDataFork.None:
          ForkedLightClientHeader.init(forkyStore.optimistic_header)
        else:
          default(ForkedLightClientHeader)

    body

    var
      didProgress = false
      didSignificantProgress = false

    let newIsInitialized = self.store[].kind > LightClientDataFork.None
    if newIsInitialized > oldIsInitialized:
      didProgress = true
      didSignificantProgress = true
      if self.onStoreInitialized != nil:
        self.onStoreInitialized()
        self.onStoreInitialized = nil

    withForkyStore(self.store[]):
      when lcDataFork > LightClientDataFork.None:
        if oldOptimistic.kind <= lcDataFork:
          oldOptimistic.migrateToDataFork(lcDataFork)
          if forkyStore.optimistic_header != oldOptimistic.forky(lcDataFork):
            didProgress = true
            when obj isnot SomeForkedLightClientUpdateWithFinality:
              didSignificantProgress = true
            if self.onOptimisticHeader != nil:
              self.onOptimisticHeader()

        if oldFinalized.kind <= lcDataFork:
          oldFinalized.migrateToDataFork(lcDataFork)
          if forkyStore.finalized_header != oldFinalized.forky(lcDataFork):
            didProgress = true
            didSignificantProgress = true
            if self.onFinalizedHeader != nil:
              self.onFinalizedHeader()

        if forkyStore.is_next_sync_committee_known != oldNextCommitteeKnown:
          didProgress = true

    if didProgress:
      when obj is Nothing:
        discard
      elif obj is ForkedLightClientBootstrap:
        if self.bootstrapObserver != nil:
          self.bootstrapObserver(obj)
      elif obj is ForkedLightClientUpdate:
        if self.updateObserver != nil:
          self.updateObserver(obj)
      elif obj is ForkedLightClientFinalityUpdate:
        if self.finalityUpdateObserver != nil:
          self.finalityUpdateObserver(obj)
      elif obj is ForkedLightClientOptimisticUpdate:
        if self.optimisticUpdateObserver != nil:
          self.optimisticUpdateObserver(obj)
      else: raiseAssert "Unreachable"

    didSignificantProgress

template withReportedProgress(body: untyped): bool =
  withReportedProgress(Nothing(), body)

proc storeObject*(
    self: var LightClientProcessor,
    src: MsgSource, wallTime: BeaconTime,
    obj: SomeForkedLightClientObject): Result[bool, VerifierError] =
  ## storeObject is the main entry point for unvalidated light client objects -
  ## all untrusted objects pass through here. When storing an object, we will
  ## update the `LightClientStore` accordingly
  let
    startTick = Moment.now()
    didSignificantProgress =
      withReportedProgress(obj):
        ? self.processObject(obj, wallTime)

        let
          storeObjectTick = Moment.now()
          storeObjectDur = storeObjectTick - startTick

        light_client_store_object_duration_seconds.observe(
          storeObjectDur.toFloatSeconds())

        let objSlot = withForkyObject(obj):
          when lcDataFork > LightClientDataFork.None:
            when forkyObject is ForkyLightClientBootstrap:
              forkyObject.header.beacon.slot
            elif forkyObject is SomeForkyLightClientUpdateWithFinality:
              forkyObject.finalized_header.beacon.slot
            else:
              forkyObject.attested_header.beacon.slot
          else:
            GENESIS_SLOT
        withForkyStore(self.store[]):
          when lcDataFork > LightClientDataFork.None:
            debug "LC object processed",
              finalizedSlot = forkyStore.finalized_header.beacon.slot,
              optimisticSlot = forkyStore.optimistic_header.beacon.slot,
              kind = typeof(obj).name,
              objectSlot = objSlot,
              storeObjectDur
  ok didSignificantProgress

proc resetToFinalizedHeader*(
    self: var LightClientProcessor,
    header: ForkedLightClientHeader,
    current_sync_committee: SyncCommittee) =
  discard withReportedProgress:
    withForkyHeader(header):
      when lcDataFork > LightClientDataFork.None:
        self.store[] = ForkedLightClientStore.init(lcDataFork.LightClientStore(
          finalized_header: forkyHeader,
          current_sync_committee: current_sync_committee,
          optimistic_header: forkyHeader))
        template forkyStore: untyped = self.store[].forky(lcDataFork)
        debug "LC reset to finalized header",
          finalizedSlot = forkyStore.finalized_header.beacon.slot,
          optimisticSlot = forkyStore.optimistic_header.beacon.slot
      else:
        self.store[].reset()
        debug "LC reset"

# Enqueue
# ------------------------------------------------------------------------------

proc addObject*(
    self: var LightClientProcessor,
    src: MsgSource,
    obj: SomeForkedLightClientObject,
    resfut: Future[Result[void, VerifierError]] = nil) =
  ## Enqueue a Gossip-validated light client object for verification
  # Backpressure:
  #   Only one object is validated at any time -
  #   Light client objects are always "fast" to process
  # Producers:
  # - Gossip:
  #   - `LightClientFinalityUpdate`
  #   - `LightClientOptimisticUpdate`
  # - `LightClientManager`:
  #   - `GetLightClientBootstrap`
  #   - `LightClientUpdatesByRange`
  #   - `GetLightClientFinalityUpdate`
  #   - `GetLightClientOptimisticUpdate`

  let
    wallTime = self.getBeaconTime()
    (afterGenesis, _) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing LC object before genesis, clock turned back?"
    quit 1

  let res = self.storeObject(src, wallTime, obj)

  if resfut != nil:
    if res.isOk:
      resfut.complete(Result[void, VerifierError].ok())
    else:
      resfut.complete(Result[void, VerifierError].err(res.error))

# Message validators
# ------------------------------------------------------------------------------

func toValidationError(
    self: var LightClientProcessor,
    r: Result[bool, VerifierError],
    wallTime: BeaconTime,
    obj: SomeForkedLightClientObject): Result[void, ValidationError] =
  if r.isOk:
    let didSignificantProgress = r.get
    if didSignificantProgress:
      let
        signature_slot = withForkyObject(obj):
          when lcDataFork > LightClientDataFork.None:
            forkyObject.signature_slot
          else:
            GENESIS_SLOT
        currentTime = wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY
        forwardTime = signature_slot.light_client_finality_update_time
      if currentTime < forwardTime:
        # [IGNORE] The `finality_update` is received after the block
        # at `signature_slot` was given enough time to propagate through
        # the network.
        # [IGNORE] The `optimistic_update` is received after the block
        # at `signature_slot` was given enough time to propagate through
        # the network.
        return errIgnore(typeof(obj).name & ": received too early")
      ok()
    else:
      when obj is ForkedLightClientOptimisticUpdate:
        # [IGNORE] The `optimistic_update` either matches corresponding fields
        # of the most recently forwarded `LightClientFinalityUpdate` (if any),
        # or it advances the `optimistic_header` of the local `LightClientStore`
        if obj.matches(self.latestFinalityUpdate):
          return ok()
      # [IGNORE] The `finality_update` advances the `finalized_header` of the
      # local `LightClientStore`.
      errIgnore(typeof(obj).name & ": no significant progress")
  else:
    case r.error
    of VerifierError.Invalid:
      # [REJECT] The `finality_update` is valid.
      # [REJECT] The `optimistic_update` is valid.
      errReject($r.error)
    of VerifierError.MissingParent,
        VerifierError.UnviableFork,
        VerifierError.Duplicate:
      # [IGNORE] The `finalized_header.beacon.slot` is greater than that of
      # all previously forwarded `finality_update`s
      # [IGNORE] The `attested_header.beacon.slot` is greater than that of all
      # previously forwarded `optimistic_update`s
      errIgnore($r.error)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#process_light_client_finality_update
proc processLightClientFinalityUpdate*(
    self: var LightClientProcessor, src: MsgSource,
    finality_update: ForkedLightClientFinalityUpdate
): Result[void, ValidationError] =
  let
    wallTime = self.getBeaconTime()
    r = self.storeObject(src, wallTime, finality_update)
    v = self.toValidationError(r, wallTime, finality_update)
  if v.isErr:
    return checkedResult(v.error, self.strictVerification)

  self.latestFinalityUpdate = finality_update.toOptimistic
  v

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#process_light_client_finality_update
proc processLightClientOptimisticUpdate*(
    self: var LightClientProcessor, src: MsgSource,
    optimistic_update: ForkedLightClientOptimisticUpdate
): Result[void, ValidationError] =
  let
    wallTime = self.getBeaconTime()
    r = self.storeObject(src, wallTime, optimistic_update)
    v = self.toValidationError(r, wallTime, optimistic_update)
  if v.isErr:
    return checkedResult(v.error, self.strictVerification)

  let
    latestFinalitySlot = withForkyOptimisticUpdate(self.latestFinalityUpdate):
      when lcDataFork > LightClientDataFork.None:
        forkyOptimisticUpdate.attested_header.beacon.slot
      else:
        GENESIS_SLOT
    attestedSlot = withForkyOptimisticUpdate(optimistic_update):
      when lcDataFork > LightClientDataFork.None:
        forkyOptimisticUpdate.attested_header.beacon.slot
      else:
        GENESIS_SLOT
  if attestedSlot >= latestFinalitySlot:
    self.latestFinalityUpdate.reset()  # Only forward once
  v

# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  stew/objects,
  chronos, metrics,
  ../spec/datatypes/altair,
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
  GetTrustedBlockRootCallback* =
    proc(): Option[Eth2Digest] {.gcsafe, raises: [Defect].}
  VoidCallback* =
    proc() {.gcsafe, raises: [Defect].}

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
    ##
    ## The processor will also attempt to force-update the light client state
    ## if no update seems to be available on the network, that is both signed by
    ## a supermajority of sync committee members and also improves finality.
    ## This logic is triggered if there is no progress for an extended period
    ## of time, and there are repeated messages indicating that this is the best
    ## available data on the network during that time period.

    # Config
    # ----------------------------------------------------------------
    dumpEnabled: bool
    dumpDirInvalid: string
    dumpDirIncoming: string

    # Consumer
    # ----------------------------------------------------------------
    store: ref Option[LightClientStore]
    getBeaconTime: GetBeaconTimeFn
    getTrustedBlockRoot: GetTrustedBlockRootCallback
    onStoreInitialized, onFinalizedHeader, onOptimisticHeader: VoidCallback

    cfg: RuntimeConfig
    genesis_validators_root: Eth2Digest

    lastProgressTick: BeaconTime # Moment when last update made progress
    lastDuplicateTick: BeaconTime # Moment when last duplicate update received
    numDuplicatesSinceProgress: int # Number of duplicates since last progress

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
    store: ref Option[LightClientStore],
    getBeaconTime: GetBeaconTimeFn,
    getTrustedBlockRoot: GetTrustedBlockRootCallback,
    onStoreInitialized: VoidCallback = nil,
    onFinalizedHeader: VoidCallback = nil,
    onOptimisticHeader: VoidCallback = nil
): ref LightClientProcessor =
  (ref LightClientProcessor)(
    dumpEnabled: dumpEnabled,
    dumpDirInvalid: dumpDirInvalid,
    dumpDirIncoming: dumpDirIncoming,
    store: store,
    getBeaconTime: getBeaconTime,
    getTrustedBlockRoot: getTrustedBlockRoot,
    onStoreInitialized: onStoreInitialized,
    onFinalizedHeader: onFinalizedHeader,
    onOptimisticHeader: onOptimisticHeader,
    cfg: cfg,
    genesis_validators_root: genesis_validators_root
  )

# Storage
# ------------------------------------------------------------------------------

proc dumpInvalidObject(
    self: LightClientProcessor,
    obj: SomeLightClientObject) =
  if self.dumpEnabled:
    dump(self.dumpDirInvalid, obj)

proc dumpObject[T](
    self: LightClientProcessor,
    obj: SomeLightClientObject,
    res: Result[T, BlockError]) =
  if self.dumpEnabled and res.isErr:
    case res.error
    of BlockError.Invalid:
      self.dumpInvalidObject(obj)
    of BlockError.MissingParent:
      dump(self.dumpDirIncoming, obj)
    else:
      discard

proc tryForceUpdate(
    self: var LightClientProcessor,
    wallTime: BeaconTime) =
  ## Try to force-update to the next sync committee period.
  let
    wallSlot = wallTime.slotOrZero()
    store = self.store

  if store[].isSome:
    case store[].get.try_light_client_store_force_update(wallSlot)
    of NoUpdate:
      discard
    of DidUpdateWithoutSupermajority:
      warn "Light client force-updated without supermajority",
        finalizedSlot = store[].get.finalized_header.slot,
        optimisticSlot = store[].get.optimistic_header.slot
    of DidUpdateWithoutFinality:
      warn "Light client force-updated without finality proof",
        finalizedSlot = store[].get.finalized_header.slot,
        optimisticSlot = store[].get.optimistic_header.slot

proc processObject(
    self: var LightClientProcessor,
    obj: SomeLightClientObject,
    wallTime: BeaconTime): Result[void, BlockError] =
  let
    wallSlot = wallTime.slotOrZero()
    store = self.store
    res =
      when obj is altair.LightClientBootstrap:
        if store[].isSome:
          err(BlockError.Duplicate)
        else:
          let trustedBlockRoot = self.getTrustedBlockRoot()
          if trustedBlockRoot.isNone:
            err(BlockError.MissingParent)
          else:
            let initRes =
              initialize_light_client_store(trustedBlockRoot.get, obj)
            if initRes.isErr:
              err(initRes.error)
            else:
              store[] = some(initRes.get)
              ok()
      elif obj is SomeLightClientUpdate:
        if store[].isNone:
          err(BlockError.MissingParent)
        else:
          store[].get.process_light_client_update(
            obj, wallSlot, self.cfg, self.genesis_validators_root)

  self.dumpObject(obj, res)

  if res.isErr:
    when obj is altair.LightClientUpdate:
      if store[].isSome and store[].get.best_valid_update.isSome:
        # `best_valid_update` gets set when no supermajority / improved finality
        # is available. In that case, we will wait for a better update that once
        # again fulfills those conditions. If none is received within reasonable
        # time, the light client store is force-updated to `best_valid_update`.
        case res.error
        of BlockError.Duplicate:
          if wallTime >= self.lastDuplicateTick + duplicateRateLimit:
            if self.numDuplicatesSinceProgress < minForceUpdateDuplicates:
              if obj.matches(store[].get.best_valid_update.get):
                self.lastDuplicateTick = wallTime
                inc self.numDuplicatesSinceProgress
            if self.numDuplicatesSinceProgress >= minForceUpdateDuplicates and
                wallTime >= self.lastProgressTick + minForceUpdateDelay:
              self.tryForceUpdate(wallTime)
              self.lastProgressTick = wallTime
              self.lastDuplicateTick = wallTime + duplicateCountDelay
              self.numDuplicatesSinceProgress = 0
        else: discard

    return res

  when obj is altair.LightClientBootstrap | altair.LightClientUpdate:
    self.lastProgressTick = wallTime
    self.lastDuplicateTick = wallTime + duplicateCountDelay
    self.numDuplicatesSinceProgress = 0

  res

template withReportedProgress(expectFinalityUpdate: bool, body: untyped): bool =
  block:
    let
      previousWasInitialized = store[].isSome
      previousFinalized =
        if store[].isSome:
          store[].get.finalized_header
        else:
          BeaconBlockHeader()
      previousOptimistic =
        if store[].isSome:
          store[].get.optimistic_header
        else:
          BeaconBlockHeader()

    body

    var didProgress = false

    if store[].isSome != previousWasInitialized:
      didProgress = true
      if self.onStoreInitialized != nil:
        self.onStoreInitialized()
        self.onStoreInitialized = nil

    if store[].get.optimistic_header != previousOptimistic:
      when not expectFinalityUpdate:
        didProgress = true
      if self.onOptimisticHeader != nil:
        self.onOptimisticHeader()

    if store[].get.finalized_header != previousFinalized:
      didProgress = true
      if self.onFinalizedHeader != nil:
        self.onFinalizedHeader()

    didProgress

template withReportedProgress(body: untyped): bool =
  withReportedProgress(false, body)

proc storeObject*(
    self: var LightClientProcessor,
    src: MsgSource, wallTime: BeaconTime,
    obj: SomeLightClientObject): Result[bool, BlockError] =
  ## storeObject is the main entry point for unvalidated light client objects -
  ## all untrusted objects pass through here. When storing an object, we will
  ## update the `LightClientStore` accordingly
  let
    startTick = Moment.now()
    store = self.store

    didProgress =
      withReportedProgress(obj is SomeLightClientUpdateWithFinality):
        ? self.processObject(obj, wallTime)

        let
          storeObjectTick = Moment.now()
          storeObjectDur = storeObjectTick - startTick

        light_client_store_object_duration_seconds.observe(
          storeObjectDur.toFloatSeconds())

        let objSlot =
          when obj is altair.LightClientBootstrap:
            obj.header.slot
          elif obj is SomeLightClientUpdateWithFinality:
            obj.finalized_header.slot
          else:
            obj.attested_header.slot
        debug "LC object processed",
          finalizedSlot = store[].get.finalized_header.slot,
          optimisticSlot = store[].get.optimistic_header.slot,
          kind = typeof(obj).name,
          objectSlot = objSlot,
          storeObjectDur
  ok didProgress

proc resetToFinalizedHeader*(
    self: var LightClientProcessor,
    header: BeaconBlockHeader,
    current_sync_committee: SyncCommittee) =
  let store = self.store

  discard withReportedProgress:
    store[] = some LightClientStore(
      finalized_header: header,
      current_sync_committee: current_sync_committee,
      optimistic_header: header)

    debug "LC reset to finalized header",
      finalizedSlot = store[].get.finalized_header.slot,
      optimisticSlot = store[].get.optimistic_header.slot

# Enqueue
# ------------------------------------------------------------------------------

proc addObject*(
    self: var LightClientProcessor,
    src: MsgSource,
    obj: SomeLightClientObject,
    resfut: Future[Result[void, BlockError]] = nil) =
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
    (afterGenesis, wallSlot) = wallTime.toSlot()

  if not afterGenesis:
    error "Processing LC object before genesis, clock turned back?"
    quit 1

  let res = self.storeObject(src, wallTime, obj)

  if resfut != nil:
    if res.isOk:
      resfut.complete(Result[void, BlockError].ok())
    else:
      resfut.complete(Result[void, BlockError].err(res.error))

# Message validators
# ------------------------------------------------------------------------------

func toValidationError(
    v: Result[bool, BlockError],
    wallTime: BeaconTime): Result[void, ValidationError] =
  if v.isOk:
    let didProgress = v.get
    if didProgress:
      when v is SomeLightClientUpdate:
        let
          signature_slot = v.signature_slot
          currentTime = wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY
          forwardTime = signature_slot.light_client_optimistic_update_time
        if currentTime < forwardTime:
          # [IGNORE] The `finality_update` / `optimistic_update` is received
          # after the block at `signature_slot` was given enough time to
          # propagate through the network.
          return errIgnore(typeof(v).name & ": received too early")
      ok()
    else:
      # [IGNORE] The `finality_update` / `optimistic_update`
      # advances the `finalized_header` / `optimistic_header`
      # of the local `LightClientStore`.
      errIgnore(typeof(v).name & ": no significant progress")
  else:
    case v.error
    of BlockError.Invalid:
      # [REJECT] The `finality_update` / `optimistic_update` is valid.
      errReject($v.error)
    of BlockError.MissingParent, BlockError.UnviableFork, BlockError.Duplicate:
      # [IGNORE] No other `finality_update` with a lower or equal
      # `finalized_header.slot` / `attested_header.slot` was already
      # forwarded on the network.
      errIgnore($v.error)

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#light_client_finality_update
proc lightClientFinalityUpdateValidator*(
    self: var LightClientProcessor, src: MsgSource,
    finality_update: altair.LightClientFinalityUpdate
): Result[void, ValidationError] =
  let
    wallTime = self.getBeaconTime()
    r = self.storeObject(src, wallTime, finality_update)
    v = r.toValidationError(wallTime)
  v

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#light_client_optimistic_update
proc lightClientOptimisticUpdateValidator*(
    self: var LightClientProcessor, src: MsgSource,
    optimistic_update: altair.LightClientOptimisticUpdate
): Result[void, ValidationError] =
  let
    wallTime = self.getBeaconTime()
    r = self.storeObject(src, wallTime, optimistic_update)
    v = r.toValidationError(wallTime)
  v

# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  eth/p2p/discoveryv5/random2,
  ../spec/eth2_apis/[eth2_rest_serialization, rest_light_client_calls],
  ../spec/[helpers, light_client_sync],
  ../sync/light_client_sync_helpers,
  ../beacon_clock

{.pragma: exported, cdecl, exportc, dynlib, raises: [].}
{.pragma: exportedConst, exportc, dynlib.}

proc destroy(x: auto) =
  x[].reset()
  x.dealloc()

proc ETHRandomNumberCreate(): ptr ref HmacDrbgContext {.exported.} =
  ## Creates a new cryptographically secure random number generator.
  ##
  ## * The cryptographically secure random number generator must be destroyed
  ##   with `ETHRandomNumberDestroy` once no longer needed, to release memory.
  ##
  ## Returns:
  ## * Pointer to an initialized cryptographically secure random number
  ##   generator context - If successful.
  ## * `NULL` - If an error occurred.
  let rng = (ref HmacDrbgContext).create()
  rng[] = HmacDrbgContext.new()
  rng

proc ETHRandomNumberDestroy(rng: ptr ref HmacDrbgContext) {.exported.} =
  ## Destroys a cryptographically secure random number generator.
  ##
  ## * The cryptographically secure random number generator
  ##   must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `rng` - Cryptographically secure random number generator.
  rng.destroy()

proc ETHConsensusConfigCreateFromYaml(
    configFileContent: cstring): ptr RuntimeConfig {.exported.} =
  ## Creates a new Ethereum Consensus Layer network configuration
  ## based on the given `config.yaml` file content from an
  ## Ethereum network definition.
  ##
  ## * The Ethereum Consensus Layer network configuration must be destroyed with
  ##   `ETHConsensusConfigDestroy` once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `configFileContent` - `config.yaml` file content. NULL-terminated.
  ##
  ## Returns:
  ## * Pointer to an initialized Ethereum Consensus Layer network configuration
  ##   based on the given `config.yaml` file content - If successful.
  ## * `NULL` - If the given `config.yaml` is malformed or incompatible.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/configs/README.md
  let cfg = RuntimeConfig.create()
  try:
    cfg[] = readRuntimeConfig($configFileContent, "config.yaml")[0]
    cfg
  except IOError, PresetFileError, PresetIncompatibleError:
    cfg.destroy()
    nil

proc ETHConsensusConfigDestroy(cfg: ptr RuntimeConfig) {.exported.} =
  ## Destroys an Ethereum Consensus Layer network configuration.
  ##
  ## * The Ethereum Consensus Layer network configuration
  ##   must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  cfg.destroy()

func ETHConsensusConfigGetConsensusVersionAtEpoch(
    cfg: ptr RuntimeConfig, epoch: cint): cstring {.exported.} =
  ## Returns the expected `Eth-Consensus-Version` for a given `epoch`.
  ##
  ## * The returned `Eth-Consensus-Version` is statically allocated.
  ##   It must neither be released nor written to.
  ##
  ## Parameters:
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `epoch` - Epoch number for which to obtain `Eth-Consensus-Version`
  ##
  ## Returns:
  ## * Expected `Eth-Consensus-Version` for the given `epoch`. NULL-terminated.
  ##
  ## See:
  ## * https://github.com/ethereum/beacon-APIs/blob/v2.4.1/beacon-node-oapi.yaml#L419
  withConsensusFork(cfg[].consensusForkAtEpoch(epoch.Epoch)):
    const consensusVersion: cstring = consensusFork.toString()
    consensusVersion

proc ETHBeaconStateCreateFromSsz(
    cfg: ptr RuntimeConfig,
    consensusVersion: cstring,
    sszBytes: ptr UncheckedArray[byte],
    numSszBytes: cint): ptr ForkedHashedBeaconState {.exported.} =
  ## Creates a new beacon state based on its SSZ encoded representation.
  ##
  ## * The beacon state must be destroyed with `ETHBeaconStateDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## * When loading a `genesis.ssz` file from an Ethereum network definition,
  ##   use `ETHConsensusConfigGetConsensusVersionAtEpoch` with `epoch = 0`
  ##   to determine the correct `consensusVersion`.
  ##
  ## Parameters:
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `consensusVersion` - `Eth-Consensus-Version` for the given `sszBytes`.
  ## * `sszBytes` - Buffer with SSZ encoded beacon state representation.
  ## * `numSszBytes` - Length of buffer.
  ##
  ## Returns:
  ## * Pointer to an initialized beacon state based on the given SSZ encoded
  ##   representation - If successful.
  ## * `NULL` - If the given `sszBytes` is malformed.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/bellatrix/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/capella/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/configs/README.md
  let
    consensusFork = decodeEthConsensusVersion($consensusVersion).valueOr:
      return nil
    state = ForkedHashedBeaconState.create()
  try:
    state[] = consensusFork.readSszForkedHashedBeaconState(
      sszBytes.toOpenArray(0, numSszBytes - 1))
    withState(state[]):
      if cfg[].consensusForkAtEpoch(forkyState.data.slot.epoch) == state.kind:
        state
      else:
        state.destroy()
        nil
  except SszError:
    state.destroy()
    nil

proc ETHBeaconStateDestroy(state: ptr ForkedHashedBeaconState) {.exported.} =
  ## Destroys a beacon state.
  ##
  ## * The beacon state must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `state` - Beacon state.
  state.destroy()

proc ETHBeaconStateCopyGenesisValidatorsRoot(
    state: ptr ForkedHashedBeaconState): ptr Eth2Digest {.exported.} =
  ## Copies the `genesis_validators_root` field from a beacon state.
  ##
  ## * The genesis validators root must be destroyed with `ETHRootDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `state` - Beacon state.
  ##
  ## Returns:
  ## * Pointer to a copy of the given beacon state's genesis validators root.
  let genesisValRoot = Eth2Digest.create()
  genesisValRoot[] = getStateField(state[], genesis_validators_root)
  genesisValRoot

proc ETHRootDestroy(root: ptr Eth2Digest) {.exported.} =
  ## Destroys a Merkle root.
  ##
  ## * The Merkle root must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `root` - Merkle root.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#custom-types
  root.destroy()

proc ETHForkDigestsCreateFromState(
    cfg: ptr RuntimeConfig,
    state: ptr ForkedHashedBeaconState): ptr ref ForkDigests {.exported.} =
  ## Creates a fork digests cache for a given beacon state.
  ##
  ## * The fork digests cache must be destroyed with `ETHForkDigestsDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `state` - Beacon state.
  ##
  ## Returns:
  ## * Pointer to an initialized fork digests cache based on the beacon state.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#compute_fork_digest
  let forkDigests = (ref ForkDigests).create()
  forkDigests[] = newClone ForkDigests.init(
    cfg[], getStateField(state[], genesis_validators_root))
  forkDigests

proc ETHForkDigestsDestroy(forkDigests: ptr ref ForkDigests) {.exported.} =
  ## Destroys a fork digests cache.
  ##
  ## * The fork digests cache must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `forkDigests` - Fork digests cache.
  forkDigests.destroy()

proc ETHBeaconClockCreateFromState(
    state: ptr ForkedHashedBeaconState): ptr BeaconClock {.exported.} =
  ## Creates a beacon clock for a given beacon state's `genesis_time` field.
  ##
  ## * The beacon clock must be destroyed with `ETHBeaconClockDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `state` - Beacon state.
  ##
  ## Returns:
  ## * Pointer to an initialized beacon clock based on the beacon state.
  let beaconClock = BeaconClock.create()
  beaconClock[] = BeaconClock.init(getStateField(state[], genesis_time))
  beaconClock

proc ETHBeaconClockDestroy(beaconClock: ptr BeaconClock) {.exported.} =
  ## Destroys a beacon clock.
  ##
  ## * The beacon clock must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `beaconClock` - Beacon clock.
  beaconClock.destroy()

proc ETHBeaconClockGetSlot(beaconClock: ptr BeaconClock): cint {.exported.} =
  ## Indicates the slot number for the current wall clock time.
  ##
  ## Parameters:
  ## * `beaconClock` - Beacon clock.
  ##
  ## Returns:
  ## * Slot number for the current wall clock time - If genesis has occurred.
  ## * `0` - If genesis is still pending.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#custom-types
  beaconClock[].now().slotOrZero().cint

const lcDataFork = LightClientDataFork.high

proc ETHLightClientStoreCreateFromBootstrap(
    cfg: ptr RuntimeConfig,
    trustedBlockRoot: ptr Eth2Digest,
    mediaType: cstring,
    consensusVersion: cstring,
    bootstrapBytes: ptr UncheckedArray[byte],
    numBootstrapBytes: cint
): ptr lcDataFork.LightClientStore {.exported.} =
  ## Creates a light client store from light client bootstrap data.
  ## The light client store is the primary object for syncing with
  ## an Ethereum network.
  ##
  ## * To create a light client store, the Ethereum network definition
  ##   including the fork schedule, `genesis_time` and `genesis_validators_root`
  ##   must be known. Furthermore, a beacon block root must be assumed trusted.
  ##   The trusted block root should be within the weak subjectivity period,
  ##   and its root should be from a finalized `Checkpoint`.
  ##
  ## * The REST `/eth/v1/beacon/light_client/bootstrap/{block_root}` beacon API
  ##   may be used to obtain light client bootstrap data for a given
  ##   trusted block root. Setting the `Accept: application/octet-stream`
  ##   HTTP header in the request selects the more compact SSZ representation.
  ##
  ## * After creating a light client store, `ETHLightClientStoreGetNextSyncTask`
  ##   may be used to determine what further REST beacon API requests to perform
  ##   for keeping the light client store in sync with the Ethereum network.
  ##
  ## * Once synced the REST `/eth/v1/events?topics=light_client_finality_update`
  ##   `&topics=light_client_optimistic_update` beacon API provides the most
  ##   recent light client data. Data from this endpoint is always JSON encoded
  ##   and may be processed with `ETHLightClientStoreProcessFinalityUpdate` and
  ##   `ETHLightClientStoreProcessOptimisticUpdate`.
  ##
  ## * The light client store must be destroyed with
  ##   `ETHLightClientStoreDestroy` once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `trustedBlockRoot` - Trusted block root.
  ## * `mediaType` - HTTP `Content-Type` associated with `bootstrapBytes`;
  ##   `application/json` for JSON, `application/octet-stream` for SSZ.
  ## * `consensusVersion` - HTTP `Eth-Consensus-Version` response header
  ##   associated with `bootstrapBytes`.
  ## * `bootstrapBytes` - Buffer with encoded light client bootstrap data.
  ## * `numBootstrapBytes` - Length of buffer.
  ##
  ## Returns:
  ## * Pointer to an initialized light client store based on the given
  ##   light client bootstrap data - If successful.
  ## * `NULL` - If the given `bootstrapBytes` is malformed or incompatible.
  ##
  ## See:
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientBootstrap
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/light-client.md
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/weak-subjectivity.md#weak-subjectivity-period
  let
    mediaType = MediaType.init($mediaType)
    consensusFork = decodeEthConsensusVersion($consensusVersion).valueOr:
      return nil
  var bootstrap =
    try:
      ForkedLightClientBootstrap.decodeHttpLightClientObject(
        bootstrapBytes.toOpenArray(0, numBootstrapBytes - 1),
        mediaType, consensusFork, cfg[])
    except RestError:
      return nil
  doAssert bootstrap.kind > LightClientDataFork.None
  bootstrap.migrateToDataFork(lcDataFork)

  let store = lcDataFork.LightClientStore.create()
  store[] = initialize_light_client_store(
      trustedBlockRoot[], bootstrap.forky(lcDataFork), cfg[]).valueOr:
    store.destroy()
    return nil
  store

proc ETHLightClientStoreDestroy(
    store: ptr lcDataFork.LightClientStore) {.exported.} =
  ## Destroys a light client store.
  ##
  ## * The light client store must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  store.destroy()

let
  ## Sync task to fulfill using `/eth/v1/beacon/light_client/updates`.
  kETHLcSyncKind_UpdatesByRange {.exportedConst.} =
    LcSyncKind.UpdatesByRange.cint

  ## Sync task to fulfill using `/eth/v1/beacon/light_client/finality_update`.
  kETHLcSyncKind_FinalityUpdate {.exportedConst.} =
    LcSyncKind.FinalityUpdate.cint

  ## Sync task to fulfill using `/eth/v1/beacon/light_client/optimistic_update`.
  kETHLcSyncKind_OptimisticUpdate {.exportedConst.} =
    LcSyncKind.OptimisticUpdate.cint

proc ETHLightClientStoreGetNextSyncTask(
    store: ptr lcDataFork.LightClientStore,
    beaconClock: ptr BeaconClock,
    startPeriod #[out]#: ptr cint,
    count #[out]#: ptr cint): cint {.exported.} =
  ## Obtains the next task for keeping a light client store in sync
  ## with the Ethereum network.
  ##
  ## * When using the REST beacon API to fulfill a sync task, setting the
  ##   `Accept: application/octet-stream` HTTP header in the request
  ##   selects the more compact SSZ representation.
  ##
  ## * After fetching the requested light client data and processing it with the
  ##   appropriate handler, `ETHLightClientStoreGetMillisecondsToNextSyncTask`
  ##   may be used to obtain a delay until a new sync task becomes available.
  ##   Once the delay is reached, call `ETHLightClientStoreGetNextSyncTask`
  ##   again to obtain the next sync task.
  ##
  ## * Once synced the REST `/eth/v1/events?topics=light_client_finality_update`
  ##   `&topics=light_client_optimistic_update` beacon API provides the most
  ##   recent light client data. Data from this endpoint is always JSON encoded
  ##   and may be processed with `ETHLightClientStoreProcessFinalityUpdate` and
  ##   `ETHLightClientStoreProcessOptimisticUpdate`. Events may be processed at
  ##   any time and do not require re-computing the delay until next sync task
  ##   with `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ## * `beaconClock` - Beacon clock.
  ## * `startPeriod` [out] - `start_period` query parameter, if applicable.
  ## * `count` [out] - `count` query parameter, if applicable.
  ##
  ## Returns:
  ## * `kETHLcSyncKind_UpdatesByRange` - If the next sync task is fulfillable
  ##   using REST `/eth/v1/beacon/light_client/updates` beacon API.
  ##   The `startPeriod` and `count` parameters are filled, and to be passed to
  ##   `/eth/v1/beacon/light_client/updates?start_period={startPeriod}`
  ##   `&count={count}`.
  ##   Process the response with `ETHLightClientStoreProcessUpdatesByRange`.
  ## * `kETHLcSyncKind_FinalityUpdate` - If the next sync task is fulfillable
  ##   using REST `/eth/v1/beacon/light_client/finality_update` beacon API.
  ##   Process the response with `ETHLightClientStoreProcessFinalityUpdate`.
  ##   The `startPeriod` and `count` parameters are unused for this sync task.
  ## * `kETHLcSyncKind_OptimisticUpdate` - If the next sync task is fulfillable
  ##   using REST `/eth/v1/beacon/light_client/optimistic_update` beacon API.
  ##   Process the response with `ETHLightClientStoreProcessOptimisticUpdate`.
  ##   The `startPeriod` and `count` parameters are unused for this sync task.
  ##
  ## See:
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientUpdatesByRange
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientFinalityUpdate
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientOptimisticUpdate
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
  let syncTask = nextLightClientSyncTask(
    current = beaconClock[].now().slotOrZero().sync_committee_period,
    finalized = store[].finalized_header.beacon.slot.sync_committee_period,
    optimistic = store[].optimistic_header.beacon.slot.sync_committee_period,
    isNextSyncCommitteeKnown = store[].is_next_sync_committee_known)
  case syncTask.kind
  of LcSyncKind.UpdatesByRange:
    startPeriod[] = syncTask.startPeriod.cint
    count[] = syncTask.count.cint
  of LcSyncKind.FinalityUpdate:
    startPeriod[] = 0
    count[] = 0
  of LcSyncKind.OptimisticUpdate:
    startPeriod[] = 0
    count[] = 0
  syncTask.kind.cint

proc ETHLightClientStoreGetMillisecondsToNextSyncTask(
    store: ptr lcDataFork.LightClientStore,
    rng: ptr ref HmacDrbgContext,
    beaconClock: ptr BeaconClock,
    latestProcessResult: cint): cint {.exported.} =
  ## Indicates the delay until a new light client sync task becomes available.
  ## Once the delay is reached, call `ETHLightClientStoreGetNextSyncTask`
  ## to obtain the next sync task.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ## * `rng` - Cryptographically secure random number generator.
  ## * `beaconClock` - Beacon clock.
  ## * `latestProcessResult` - Latest sync task processing result, i.e.,
  ##   the return value of `ETHLightClientStoreProcessUpdatesByRange`,
  ##   `ETHLightClientStoreProcessFinalityUpdate`, or
  ##   `ETHLightClientStoreProcessOptimisticUpdate`, for latest task.
  ##   If the data for the sync task could not be fetched, set to `1`.
  ##
  ## Returns:
  ## * Number of milliseconds until `ETHLightClientStoreGetNextSyncTask`
  ##   should be called again to obtain the next light client sync task.
  rng[].nextLcSyncTaskDelay(
    wallTime = beaconClock[].now(),
    finalized = store[].finalized_header.beacon.slot.sync_committee_period,
    optimistic = store[].optimistic_header.beacon.slot.sync_committee_period,
    isNextSyncCommitteeKnown = store[].is_next_sync_committee_known,
    didLatestSyncTaskProgress = (latestProcessResult == 0)).milliseconds.cint

proc ETHLightClientStoreProcessUpdatesByRange(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ref ForkDigests,
    genesisValRoot: ptr Eth2Digest,
    beaconClock: ptr BeaconClock,
    startPeriod: cint,
    count: cint,
    mediaType: cstring,
    updatesBytes: ptr UncheckedArray[byte],
    numUpdatesBytes: cint): cint {.exported.} =
  ## Processes light client update data.
  ##
  ## * This processes the response data for a sync task of kind
  ##   `kETHLcSyncKind_UpdatesByRange`, as indicated by
  ##   `ETHLightClientStoreGetNextSyncTask`. After processing, call
  ##   `ETHLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
  ##   until a new sync task becomes available.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `forkDigests` - Fork digests cache.
  ## * `genesisValRoot` - Genesis validators root.
  ## * `beaconClock` - Beacon clock.
  ## * `startPeriod` - `startPeriod` parameter associated with the sync task.
  ## * `count` - `count` parameter associated with the sync task.
  ## * `mediaType` - HTTP `Content-Type` associated with `updatesBytes`;
  ##   `application/json` for JSON, `application/octet-stream` for SSZ.
  ## * `updatesBytes` - Buffer with encoded light client update data.
  ## * `numUpdatesBytes` - Length of buffer.
  ##
  ## Returns:
  ## * `0` - If the given `updatesBytes` is valid and sync did progress.
  ## * `1` - If the given `updatesBytes` is malformed or incompatible.
  ## * `2` - If the given `updatesBytes` did not advance sync progress.
  ##
  ## See:
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientUpdatesByRange
  let
    wallTime = beaconClock[].now()
    currentSlot = wallTime.slotOrZero()
    mediaType = MediaType.init($mediaType)
  var updates =
    try:
      seq[ForkedLightClientUpdate].decodeHttpLightClientObjects(
        updatesBytes.toOpenArray(0, numUpdatesBytes - 1),
        mediaType, cfg[], forkDigests[])
    except RestError:
      return 1
  let e = updates.checkLightClientUpdates(
    startPeriod.SyncCommitteePeriod, count.uint64)
  if e.isErr:
    return 1
  var didProgress = false
  for i in 0 ..< updates.len:
    doAssert updates[i].kind > LightClientDataFork.None
    updates[i].migrateToDataFork(lcDataFork)
    let res = process_light_client_update(
      store[], updates[i].forky(lcDataFork),
      currentSlot, cfg[], genesisValRoot[])
    if res.isOk:
      didProgress = true
    else:
      case res.error
      of VerifierError.MissingParent:
        break
      of VerifierError.Duplicate:
        discard
      of VerifierError.UnviableFork:
        break
      of VerifierError.Invalid:
        return 1
  if not didProgress:
    return 2
  0

proc ETHLightClientStoreProcessFinalityUpdate(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ref ForkDigests,
    genesisValRoot: ptr Eth2Digest,
    beaconClock: ptr BeaconClock,
    mediaType: cstring,
    consensusVersion #[optional]#: cstring,
    finUpdateBytes: ptr UncheckedArray[byte],
    numFinUpdateBytes: cint): cint {.exported.} =
  ## Processes light client finality update data.
  ##
  ## * This processes the response data for a sync task of kind
  ##   `kETHLcSyncKind_FinalityUpdate`, as indicated by
  ##   `ETHLightClientStoreGetNextSyncTask`. After processing, call
  ##   `ETHLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
  ##   until a new sync task becomes available.
  ##
  ## * This also processes event data from the REST
  ##   `/eth/v1/events?topics=light_client_finality_update` beacon API.
  ##   Set `mediaType` to `application/json`, and `consensusVersion` to `NULL`.
  ##   Events may be processed at any time, it is not necessary to call
  ##   `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `forkDigests` - Fork digests cache.
  ## * `genesisValRoot` - Genesis validators root.
  ## * `beaconClock` - Beacon clock.
  ## * `mediaType` - HTTP `Content-Type` associated with `finUpdateBytes`;
  ##   `application/json` for JSON, `application/octet-stream` for SSZ.
  ## * `consensusVersion` - HTTP `Eth-Consensus-Version` response header
  ##   associated with `finUpdateBytes`. `NULL` when processing event.
  ## * `finUpdateBytes` - Buffer with encoded finality update data.
  ## * `numFinUpdateBytes` - Length of buffer.
  ##
  ## Returns:
  ## * `0` - If the given `finUpdateBytes` is valid and sync did progress.
  ## * `1` - If the given `finUpdateBytes` is malformed or incompatible.
  ## * `2` - If the given `finUpdateBytes` did not advance sync progress.
  ##
  ## See:
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientFinalityUpdate
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
  let
    wallTime = beaconClock[].now()
    currentSlot = wallTime.slotOrZero()
    mediaType = MediaType.init($mediaType)
  var finalityUpdate =
    try:
      if consensusVersion == nil:
        if mediaType != ApplicationJsonMediaType:
          return 1
        ForkedLightClientFinalityUpdate.decodeJsonLightClientObject(
          finUpdateBytes.toOpenArray(0, numFinUpdateBytes - 1),
          Opt.none(ConsensusFork), cfg[])
      else:
        let consensusFork = decodeEthConsensusVersion(
            $consensusVersion).valueOr:
          return 1
        ForkedLightClientFinalityUpdate.decodeHttpLightClientObject(
          finUpdateBytes.toOpenArray(0, numFinUpdateBytes - 1),
          mediaType, consensusFork, cfg[])
    except RestError:
      return 1
  doAssert finalityUpdate.kind > LightClientDataFork.None
  finalityUpdate.migrateToDataFork(lcDataFork)
  let res = process_light_client_update(
    store[], finalityUpdate.forky(lcDataFork),
    currentSlot, cfg[], genesisValRoot[])
  return
    if res.isOk:
      0
    else:
      case res.error
      of VerifierError.MissingParent:
        2
      of VerifierError.Duplicate:
        2
      of VerifierError.UnviableFork:
        2
      of VerifierError.Invalid:
        1

proc ETHLightClientStoreProcessOptimisticUpdate(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ref ForkDigests,
    genesisValRoot: ptr Eth2Digest,
    beaconClock: ptr BeaconClock,
    mediaType: cstring,
    consensusVersion #[optional]#: cstring,
    optUpdateBytes: ptr UncheckedArray[byte],
    numOptUpdateBytes: cint): cint {.exported.} =
  ## Processes light client optimistic update data.
  ##
  ## * This processes the response data for a sync task of kind
  ##   `kETHLcSyncKind_OptimisticUpdate`, as indicated by
  ##   `ETHLightClientStoreGetNextSyncTask`. After processing, call
  ##   `ETHLightClientStoreGetMillisecondsToNextSyncTask` to obtain a delay
  ##   until a new sync task becomes available.
  ##
  ## * This also processes event data from the REST
  ##   `/eth/v1/events?topics=light_client_optimistic_update` beacon API.
  ##   Set `mediaType` to `application/json`, and `consensusVersion` to `NULL`.
  ##   Events may be processed at any time, it is not necessary to call
  ##   `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ## * `forkDigests` - Fork digests cache.
  ## * `genesisValRoot` - Genesis validators root.
  ## * `beaconClock` - Beacon clock.
  ## * `mediaType` - HTTP `Content-Type` associated with `optUpdateBytes`;
  ##   `application/json` for JSON, `application/octet-stream` for SSZ.
  ## * `consensusVersion` - HTTP `Eth-Consensus-Version` response header
  ##   associated with `optUpdateBytes`. `NULL` when processing event.
  ## * `optUpdateBytes` - Buffer with encoded optimistic update data.
  ## * `numOptUpdateBytes` - Length of buffer.
  ##
  ## Returns:
  ## * `0` - If the given `optUpdateBytes` is valid and sync did progress.
  ## * `1` - If the given `optUpdateBytes` is malformed or incompatible.
  ## * `2` - If the given `optUpdateBytes` did not advance sync progress.
  ##
  ## See:
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Beacon/getLightClientOptimisticUpdate
  ## * https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.1#/Events/eventstream
  let
    wallTime = beaconClock[].now()
    currentSlot = wallTime.slotOrZero()
    mediaType = MediaType.init($mediaType)
  var optimisticUpdate =
    try:
      if consensusVersion == nil:
        if mediaType != ApplicationJsonMediaType:
          return 1
        ForkedLightClientOptimisticUpdate.decodeJsonLightClientObject(
          optUpdateBytes.toOpenArray(0, numOptUpdateBytes - 1),
          Opt.none(ConsensusFork), cfg[])
      else:
        let consensusFork = decodeEthConsensusVersion(
            $consensusVersion).valueOr:
          return 1
        ForkedLightClientOptimisticUpdate.decodeHttpLightClientObject(
          optUpdateBytes.toOpenArray(0, numOptUpdateBytes - 1),
          mediaType, consensusFork, cfg[])
    except RestError:
      return 1
  doAssert optimisticUpdate.kind > LightClientDataFork.None
  optimisticUpdate.migrateToDataFork(lcDataFork)
  let res = process_light_client_update(
    store[], optimisticUpdate.forky(lcDataFork),
    currentSlot, cfg[], genesisValRoot[])
  return
    if res.isOk:
      0
    else:
      case res.error
      of VerifierError.MissingParent:
        2
      of VerifierError.Duplicate:
        2
      of VerifierError.UnviableFork:
        2
      of VerifierError.Invalid:
        1

func ETHLightClientStoreGetFinalizedHeader(
    store: ptr lcDataFork.LightClientStore
): ptr lcDataFork.LightClientHeader {.exported.} =
  ## Obtains the latest finalized header of a given light client store.
  ##
  ## * The returned value is allocated in the given light client store.
  ##   It must neither be released nor written to, and the light client store
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ##
  ## Returns:
  ## * Latest finalized header.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
  addr store[].finalized_header

func ETHLightClientStoreIsNextSyncCommitteeKnown(
    store: ptr lcDataFork.LightClientStore): bool {.exported.} =
  ## Indicates whether or not the next sync committee is currently known.
  ##
  ## * The light client sync process ensures that the next sync committee
  ##   is obtained in time, before it starts signing light client data.
  ##   To stay in sync, use `ETHLightClientStoreGetNextSyncTask` and
  ##   `ETHLightClientStoreGetMillisecondsToNextSyncTask`.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ##
  ## Returns:
  ## * Whether or not the next sync committee is currently known.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/sync-protocol.md#is_next_sync_committee_known
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/light-client.md
  store[].is_next_sync_committee_known

func ETHLightClientStoreGetOptimisticHeader(
    store: ptr lcDataFork.LightClientStore
): ptr lcDataFork.LightClientHeader {.exported.} =
  ## Obtains the latest optimistic header of a given light client store.
  ##
  ## * The returned value is allocated in the given light client store.
  ##   It must neither be released nor written to, and the light client store
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ##
  ## Returns:
  ## * Latest optimistic header.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
  addr store[].optimistic_header

func ETHLightClientStoreGetSafetyThreshold(
    store: ptr lcDataFork.LightClientStore): cint {.exported.} =
  ## Calculates the safety threshold for a given light client store.
  ##
  ## * Light client data can only update the optimistic header if it is signed
  ##   by more sync committee participants than the safety threshold indicates.
  ##
  ## * The finalized header is not affected by the safety threshold;
  ##   light client data can only update the finalized header if it is signed
  ##   by a supermajority of the sync committee, regardless of safety threshold.
  ##
  ## Parameters:
  ## * `store` - Light client store.
  ##
  ## Returns:
  ## * Light client store safety threshold.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/altair/light-client/sync-protocol.md#get_safety_threshold
  store[].get_safety_threshold.cint

proc ETHLightClientHeaderCreateCopy(
    header: ptr lcDataFork.LightClientHeader
): ptr lcDataFork.LightClientHeader {.exported.} =
  ## Creates a shallow copy of a given light client header.
  ##
  ## * The copy must be destroyed with `ETHLightClientHeaderDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `header` - Light client header.
  ##
  ## Returns:
  ## * Pointer to a shallow copy of the given header.
  let copy = lcDataFork.LightClientHeader.create()
  copy[] = header[]
  copy

proc ETHLightClientHeaderDestroy(
    header: ptr lcDataFork.LightClientHeader) {.exported.} =
  ## Destroys a light client header.
  ##
  ## * The light client header must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `header` - Light client header.
  header.destroy()

proc ETHLightClientHeaderCopyBeaconRoot(
    header: ptr lcDataFork.LightClientHeader,
    cfg: ptr RuntimeConfig): ptr Eth2Digest {.exported.} =
  ## Computes the beacon block Merkle root for a given light client header.
  ##
  ## * The Merkle root must be destroyed with `ETHRootDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `header` - Light client header.
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ##
  ## Returns:
  ## * Pointer to a copy of the given header's beacon block root.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#hash_tree_root
  discard cfg  # Future-proof against new fields, see `get_lc_execution_root`.
  let root = Eth2Digest.create()
  root[] = header[].beacon.hash_tree_root()
  root

func ETHLightClientHeaderGetBeacon(
    header: ptr lcDataFork.LightClientHeader
): ptr BeaconBlockHeader {.exported.} =
  ## Obtains the beacon block header of a given light client header.
  ##
  ## * The returned value is allocated in the given light client header.
  ##   It must neither be released nor written to, and the light client header
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `header` - Light client header.
  ##
  ## Returns:
  ## * Beacon block header.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/phase0/beacon-chain.md#beaconblockheader
  addr header[].beacon

func ETHBeaconBlockHeaderGetSlot(
    beacon: ptr BeaconBlockHeader): cint {.exported.} =
  ## Obtains the slot number of a given beacon block header.
  ##
  ## Parameters:
  ## * `beacon` - Beacon block header.
  ##
  ## Returns:
  ## * Slot number.
  beacon[].slot.cint

func ETHBeaconBlockHeaderGetProposerIndex(
    beacon: ptr BeaconBlockHeader): cint {.exported.} =
  ## Obtains the proposer validator registry index
  ## of a given beacon block header.
  ##
  ## Parameters:
  ## * `beacon` - Beacon block header.
  ##
  ## Returns:
  ## * Proposer validator registry index.
  beacon[].proposer_index.cint

func ETHBeaconBlockHeaderGetParentRoot(
    beacon: ptr BeaconBlockHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the parent beacon block Merkle root of a given beacon block header.
  ##
  ## * The returned value is allocated in the given beacon block header.
  ##   It must neither be released nor written to, and the beacon block header
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `beacon` - Beacon block header.
  ##
  ## Returns:
  ## * Parent beacon block root.
  addr beacon[].parent_root

func ETHBeaconBlockHeaderGetStateRoot(
    beacon: ptr BeaconBlockHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the beacon state Merkle root of a given beacon block header.
  ##
  ## * The returned value is allocated in the given beacon block header.
  ##   It must neither be released nor written to, and the beacon block header
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `beacon` - Beacon block header.
  ##
  ## Returns:
  ## * Beacon state root.
  addr beacon[].state_root

func ETHBeaconBlockHeaderGetBodyRoot(
    beacon: ptr BeaconBlockHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the beacon block body Merkle root of a given beacon block header.
  ##
  ## * The returned value is allocated in the given beacon block header.
  ##   It must neither be released nor written to, and the beacon block header
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `beacon` - Beacon block header.
  ##
  ## Returns:
  ## * Beacon block body root.
  addr beacon[].body_root

proc ETHLightClientHeaderCopyExecutionHash(
    header: ptr lcDataFork.LightClientHeader,
    cfg: ptr RuntimeConfig
): ptr Eth2Digest {.exported.} =
  ## Computes the execution block hash for a given light client header.
  ##
  ## * The hash must be destroyed with `ETHRootDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `header` - Light client header.
  ## * `cfg` - Ethereum Consensus Layer network configuration.
  ##
  ## Returns:
  ## * Pointer to a copy of the given header's execution block hash.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/deneb/beacon-chain.md#executionpayloadheader
  discard cfg  # Future-proof against SSZ execution block header, EIP-6404ff.
  let root = Eth2Digest.create()
  root[] = header[].execution.block_hash
  root

type ExecutionPayloadHeader =
  typeof(default(lcDataFork.LightClientHeader).execution)

func ETHLightClientHeaderGetExecution(
    header: ptr lcDataFork.LightClientHeader
): ptr ExecutionPayloadHeader {.exported.} =
  ## Obtains the execution payload header of a given light client header.
  ##
  ## * The returned value is allocated in the given light client header.
  ##   It must neither be released nor written to, and the light client header
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `header` - Light client header.
  ##
  ## Returns:
  ## * Execution payload header.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.0/specs/deneb/beacon-chain.md#executionpayloadheader
  addr header[].execution

func ETHExecutionPayloadHeaderGetParentHash(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the parent execution block hash of a given
  ## execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Parent execution block hash.
  addr execution[].parent_hash

func ETHExecutionPayloadHeaderGetFeeRecipient(
    execution: ptr ExecutionPayloadHeader): ptr ExecutionAddress {.exported.} =
  ## Obtains the fee recipient address of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Fee recipient execution address.
  addr execution[].fee_recipient

func ETHExecutionPayloadHeaderGetStateRoot(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the state MPT root of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Execution state root.
  addr execution[].state_root

func ETHExecutionPayloadHeaderGetReceiptsRoot(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the receipts MPT root of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Execution receipts root.
  addr execution[].receipts_root

func ETHExecutionPayloadHeaderGetLogsBloom(
    execution: ptr ExecutionPayloadHeader): ptr BloomLogs {.exported.} =
  ## Obtains the logs bloom of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Execution logs bloom.
  addr execution[].logs_bloom

func ETHExecutionPayloadHeaderGetPrevRandao(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exported.} =
  ## Obtains the previous randao mix of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Previous randao mix.
  addr execution[].prev_randao

func ETHExecutionPayloadHeaderGetBlockNumber(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the execution block number of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Execution block number.
  execution[].block_number.cint

func ETHExecutionPayloadHeaderGetGasLimit(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the gas limit of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Gas limit.
  execution[].gas_limit.cint

func ETHExecutionPayloadHeaderGetGasUsed(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the gas used of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Gas used.
  execution[].gas_used.cint

func ETHExecutionPayloadHeaderGetTimestamp(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the timestamp of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Execution block timestamp.
  execution[].timestamp.cint

func ETHExecutionPayloadHeaderGetExtraDataBytes(
    execution: ptr ExecutionPayloadHeader
): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the extra data buffer of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## * Use `ETHExecutionPayloadHeaderGetNumExtraDataBytes`
  ##   to obtain the length of the buffer.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Buffer with execution block extra data.
  cast[ptr UncheckedArray[byte]](addr execution[].extra_data[0])

func ETHExecutionPayloadHeaderGetNumExtraDataBytes(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the extra data buffer's length of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Length of execution block extra data.
  execution[].extra_data.len.cint

func ETHExecutionPayloadHeaderGetBaseFeePerGas(
    execution: ptr ExecutionPayloadHeader): ptr UInt256 {.exported.} =
  ## Obtains the base fee per gas of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Base fee per gas.
  addr execution[].base_fee_per_gas

func ETHExecutionPayloadHeaderGetDataGasUsed(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the data gas used of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Data gas used.
  execution[].data_gas_used.cint

func ETHExecutionPayloadHeaderGetExcessDataGas(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the excess data gas of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Excess data gas.
  execution[].excess_data_gas.cint

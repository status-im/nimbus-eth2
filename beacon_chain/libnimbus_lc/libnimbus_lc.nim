# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[json, sequtils, times],
  stew/saturation_arith,
  eth/common/[eth_types_rlp, transaction],
  eth/keys,
  eth/p2p/discoveryv5/random2,
  eth/rlp,
  eth/trie/[db, hexary],
  json_rpc/jsonmarshal,
  secp256k1,
  web3/eth_api_types,
  ../el/el_manager,
  ../spec/eth2_apis/[eth2_rest_serialization, rest_light_client_calls],
  ../spec/[helpers, light_client_sync],
  ../sync/light_client_sync_helpers,
  ../beacon_clock

{.pragma: exported, cdecl, exportc, dynlib, raises: [].}
{.pragma: exportedConst, exportc, dynlib.}

proc toUnmanagedPtr[T](x: ref T): ptr T =
  GC_ref(x)
  addr x[]

func asRef[T](x: ptr T): ref T =
  cast[ref T](x)

proc destroy[T](x: ptr T) =
  x[].reset()
  GC_unref(asRef(x))

proc ETHRandomNumberCreate(): ptr HmacDrbgContext {.exported.} =
  ## Creates a new cryptographically secure random number generator.
  ##
  ## * The cryptographically secure random number generator must be destroyed
  ##   with `ETHRandomNumberDestroy` once no longer needed, to release memory.
  ##
  ## Returns:
  ## * Pointer to an initialized cryptographically secure random number
  ##   generator context - If successful.
  ## * `NULL` - If an error occurred.
  HmacDrbgContext.new().toUnmanagedPtr()

proc ETHRandomNumberDestroy(rng: ptr HmacDrbgContext) {.exported.} =
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/configs/README.md
  let cfg = RuntimeConfig.new()
  try:
    cfg[] = readRuntimeConfig($configFileContent, "config.yaml")[0]
  except IOError, PresetFileError, PresetIncompatibleError:
    return nil
  cfg.toUnmanagedPtr()

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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/bellatrix/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#beaconstate
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/configs/README.md
  let
    consensusFork = ConsensusFork.decodeString($consensusVersion).valueOr:
      return nil
    state = ForkedHashedBeaconState.new()
  try:
    state[] = consensusFork.readSszForkedHashedBeaconState(
      sszBytes.toOpenArray(0, numSszBytes - 1))
  except SszError:
    return nil
  withState(state[]):
    if cfg[].consensusForkAtEpoch(forkyState.data.slot.epoch) != state.kind:
      return nil
  state.toUnmanagedPtr()

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
  let genesisValRoot = Eth2Digest.new()
  genesisValRoot[] = getStateField(state[], genesis_validators_root)
  genesisValRoot.toUnmanagedPtr()

proc ETHRootDestroy(root: ptr Eth2Digest) {.exported.} =
  ## Destroys a Merkle root.
  ##
  ## * The Merkle root must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `root` - Merkle root.
  ##
  ## See:
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#custom-types
  root.destroy()

proc ETHForkDigestsCreateFromState(
    cfg: ptr RuntimeConfig,
    state: ptr ForkedHashedBeaconState): ptr ForkDigests {.exported.} =
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_fork_digest
  let forkDigests = ForkDigests.new()
  forkDigests[] = ForkDigests.init(
    cfg[], getStateField(state[], genesis_validators_root))
  forkDigests.toUnmanagedPtr()

proc ETHForkDigestsDestroy(forkDigests: ptr ForkDigests) {.exported.} =
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
  let beaconClock = BeaconClock.new()
  beaconClock[] = BeaconClock.init(getStateField(state[], genesis_time))
  beaconClock.toUnmanagedPtr()

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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#custom-types
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/light-client.md
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/weak-subjectivity.md#weak-subjectivity-period
  let
    mediaType = MediaType.init($mediaType)
    consensusFork = ConsensusFork.decodeString($consensusVersion).valueOr:
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

  let store = lcDataFork.LightClientStore.new()
  store[] = initialize_light_client_store(
      trustedBlockRoot[], bootstrap.forky(lcDataFork), cfg[]).valueOr:
    return nil
  store.toUnmanagedPtr()

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
    rng: ptr HmacDrbgContext,
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
  asRef(rng).nextLcSyncTaskDelay(
    wallTime = beaconClock[].now(),
    finalized = store[].finalized_header.beacon.slot.sync_committee_period,
    optimistic = store[].optimistic_header.beacon.slot.sync_committee_period,
    isNextSyncCommitteeKnown = store[].is_next_sync_committee_known,
    didLatestSyncTaskProgress = (latestProcessResult == 0)).milliseconds.cint

proc ETHLightClientStoreProcessUpdatesByRange(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ForkDigests,
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
        mediaType, cfg[], asRef(forkDigests))
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
    forkDigests: ptr ForkDigests,
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
        let consensusFork = ConsensusFork.decodeString(
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
    forkDigests: ptr ForkDigests,
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
        let consensusFork = ConsensusFork.decodeString(
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#is_next_sync_committee_known
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/light-client.md
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/light-client/sync-protocol.md#modified-lightclientheader
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#get_safety_threshold
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
  let copy = lcDataFork.LightClientHeader.new()
  copy[] = header[]
  copy.toUnmanagedPtr()

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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#hash_tree_root
  discard cfg  # Future-proof against new fields, see `get_lc_execution_root`.
  let root = Eth2Digest.new()
  root[] = header[].beacon.hash_tree_root()
  root.toUnmanagedPtr()

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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beaconblockheader
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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/deneb/beacon-chain.md#executionpayloadheader
  discard cfg  # Future-proof against SSZ execution block header, EIP-6404ff.
  let root = Eth2Digest.new()
  root[] = header[].execution.block_hash
  root.toUnmanagedPtr()

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
  ## * https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/beacon-chain.md#executionpayloadheader
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
  ## Obtains the logs Bloom of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Execution logs Bloom.
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
    execution: ptr ExecutionPayloadHeader,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the extra data buffer of a given execution payload header.
  ##
  ## * The returned value is allocated in the given execution payload header.
  ##   It must neither be released nor written to, and the execution payload
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with execution block extra data.
  numBytes[] = execution[].extra_data.len.cint
  if execution[].extra_data.len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultExtraData: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultExtraData)
  cast[ptr UncheckedArray[byte]](addr execution[].extra_data[0])

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

func ETHExecutionPayloadHeaderGetBlobGasUsed(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the blob gas used of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Blob gas used.
  execution[].blob_gas_used.cint

func ETHExecutionPayloadHeaderGetExcessBlobGas(
    execution: ptr ExecutionPayloadHeader): cint {.exported.} =
  ## Obtains the excess blob gas of a given execution payload header.
  ##
  ## Parameters:
  ## * `execution` - Execution payload header.
  ##
  ## Returns:
  ## * Excess blob gas.
  execution[].excess_blob_gas.cint

type
  ETHWithdrawal = object
    index: uint64
    validatorIndex: uint64
    address: ExecutionAddress
    amount: uint64
    bytes: seq[byte]

  ETHExecutionBlockHeader = object
    transactionsRoot: Eth2Digest
    withdrawalsRoot: Eth2Digest
    withdrawals: seq[ETHWithdrawal]

proc ETHExecutionBlockHeaderCreateFromJson(
    executionHash: ptr Eth2Digest,
    blockHeaderJson: cstring): ptr ETHExecutionBlockHeader {.exported.} =
  ## Verifies that a JSON execution block header is valid and that it matches
  ## the given `executionHash`.
  ##
  ## * The JSON-RPC `eth_getBlockByHash` with params `[executionHash, false]`
  ##   may be used to obtain execution block header data for a given execution
  ##   block hash. Pass the response's `result` property as `blockHeaderJson`.
  ##
  ## * The execution block header must be destroyed with
  ##   `ETHExecutionBlockHeaderDestroy` once no longer needed,
  ##   to release memory.
  ##
  ## Parameters:
  ## * `executionHash` - Execution block hash.
  ## * `blockHeaderJson` - Buffer with JSON encoded header. NULL-terminated.
  ##
  ## Returns:
  ## * Pointer to an initialized execution block header - If successful.
  ## * `NULL` - If the given `blockHeaderJson` is malformed or incompatible.
  ##
  ## See:
  ## * https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbyhash
  let node =
    try:
      parseJson($blockHeaderJson)
    except Exception:
      return nil
  var data: BlockObject
  try:
    fromJson(node, argName = "", data)
  except KeyError, ValueError:
    return nil
  if data == nil:
    return nil

  # Sanity check
  if data.hash.asEth2Digest != executionHash[]:
    return nil

  # Check fork consistency
  static: doAssert totalSerializedFields(BlockObject) == 26,
    "Only update this number once code is adjusted to check new fields!"
  if data.baseFeePerGas.isNone and (
      data.withdrawals.isSome or data.withdrawalsRoot.isSome or
      data.blobGasUsed.isSome or data.excessBlobGas.isSome):
    return nil
  if data.withdrawalsRoot.isNone and (
      data.blobGasUsed.isSome or data.excessBlobGas.isSome):
    return nil
  if data.withdrawals.isSome != data.withdrawalsRoot.isSome:
    return nil
  if data.blobGasUsed.isSome != data.excessBlobGas.isSome:
    return nil

  # Construct block header
  static:  # `GasInt` is signed. We only use it for hashing.
    doAssert sizeof(int64) == sizeof(data.gasLimit)
    doAssert sizeof(int64) == sizeof(data.gasUsed)
  if distinctBase(data.timestamp) > int64.high.uint64:
    return nil
  if data.nonce.isNone:
    return nil
  let blockHeader = ExecutionBlockHeader(
    parentHash: data.parentHash.asEth2Digest,
    ommersHash: data.sha3Uncles.asEth2Digest,
    coinbase: distinctBase(data.miner),
    stateRoot: data.stateRoot.asEth2Digest,
    txRoot: data.transactionsRoot.asEth2Digest,
    receiptRoot: data.receiptsRoot.asEth2Digest,
    bloom: distinctBase(data.logsBloom),
    difficulty: data.difficulty,
    blockNumber: distinctBase(data.number).u256,
    gasLimit: cast[int64](data.gasLimit),
    gasUsed: cast[int64](data.gasUsed),
    timestamp: EthTime(int64.saturate distinctBase(data.timestamp)),
    extraData: distinctBase(data.extraData),
    mixDigest: data.mixHash.asEth2Digest,
    nonce: distinctBase(data.nonce.get),
    fee: data.baseFeePerGas,
    withdrawalsRoot:
      if data.withdrawalsRoot.isSome:
        some(data.withdrawalsRoot.get.asEth2Digest)
      else:
        none(ExecutionHash256),
    blobGasUsed:
      if data.blobGasUsed.isSome:
        some distinctBase(data.blobGasUsed.get)
      else:
        none(uint64),
    excessBlobGas:
      if data.excessBlobGas.isSome:
        some distinctBase(data.excessBlobGas.get)
      else:
        none(uint64),
    parentBeaconBlockRoot:
      if data.parentBeaconBlockRoot.isSome:
        some distinctBase(data.parentBeaconBlockRoot.get.asEth2Digest)
      else:
        none(ExecutionHash256))
  if rlpHash(blockHeader) != executionHash[]:
    return nil

  # Construct withdrawals
  var wds: seq[ETHWithdrawal]
  if data.withdrawals.isSome:
    doAssert data.withdrawalsRoot.isSome  # Checked above

    wds = newSeqOfCap[ETHWithdrawal](data.withdrawals.get.len)
    for data in data.withdrawals.get:
      # Check fork consistency
      static: doAssert totalSerializedFields(WithdrawalObject) == 4,
        "Only update this number once code is adjusted to check new fields!"

      # Construct withdrawal
      let
        wd = ExecutionWithdrawal(
          index: distinctBase(data.index),
          validatorIndex: distinctBase(data.validatorIndex),
          address: distinctBase(data.address),
          amount: distinctBase(data.amount))
        rlpBytes =
          try:
            rlp.encode(wd)
          except RlpError:
            raiseAssert "Unreachable"

      wds.add ETHWithdrawal(
        index: wd.index,
        validatorIndex: wd.validatorIndex,
        address: ExecutionAddress(data: wd.address),
        amount: wd.amount,
        bytes: rlpBytes)

    var tr = initHexaryTrie(newMemoryDB())
    for i, wd in wds:
      try:
        tr.put(rlp.encode(i), wd.bytes)
      except RlpError:
        raiseAssert "Unreachable"
    if tr.rootHash() != data.withdrawalsRoot.get.asEth2Digest:
      return nil

  let executionBlockHeader = ETHExecutionBlockHeader.new()
  executionBlockHeader[] = ETHExecutionBlockHeader(
    transactionsRoot: blockHeader.txRoot,
    withdrawalsRoot: blockHeader.withdrawalsRoot.get(ZERO_HASH),
    withdrawals: wds)
  executionBlockHeader.toUnmanagedPtr()

proc ETHExecutionBlockHeaderDestroy(
    executionBlockHeader: ptr ETHExecutionBlockHeader) {.exported.} =
  ## Destroys an execution block header.
  ##
  ## * The execution block header must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `executionBlockHeader` - Execution block header.
  executionBlockHeader.destroy()

func ETHExecutionBlockHeaderGetTransactionsRoot(
    executionBlockHeader: ptr ETHExecutionBlockHeader
): ptr Eth2Digest {.exported.} =
  ## Obtains the transactions MPT root of a given execution block header.
  ##
  ## * The returned value is allocated in the given execution block header.
  ##   It must neither be released nor written to, and the execution block
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `executionBlockHeader` - Execution block header.
  ##
  ## Returns:
  ## * Execution transactions root.
  addr executionBlockHeader[].transactionsRoot

func ETHExecutionBlockHeaderGetWithdrawalsRoot(
    executionBlockHeader: ptr ETHExecutionBlockHeader
): ptr Eth2Digest {.exported.} =
  ## Obtains the withdrawals MPT root of a given execution block header.
  ##
  ## * The returned value is allocated in the given execution block header.
  ##   It must neither be released nor written to, and the execution block
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `executionBlockHeader` - Execution block header.
  ##
  ## Returns:
  ## * Execution withdrawals root.
  addr executionBlockHeader[].withdrawalsRoot

func ETHExecutionBlockHeaderGetWithdrawals(
    executionBlockHeader: ptr ETHExecutionBlockHeader
): ptr seq[ETHWithdrawal] {.exported.} =
  ## Obtains the withdrawal sequence of a given execution block header.
  ##
  ## * The returned value is allocated in the given execution block header.
  ##   It must neither be released nor written to, and the execution block
  ##   header must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `executionBlockHeader` - Execution block header.
  ##
  ## Returns:
  ## * Withdrawal sequence.
  addr executionBlockHeader[].withdrawals

type
  ETHAccessTuple = object
    address: ExecutionAddress
    storageKeys: seq[Eth2Digest]

  DestinationType {.pure.} = enum
    Regular,
    Create

  ETHTransaction = object
    hash: Eth2Digest
    chainId: UInt256
    `from`: ExecutionAddress
    nonce: uint64
    maxPriorityFeePerGas: uint64
    maxFeePerGas: uint64
    gas: uint64
    destinationType: DestinationType
    to: ExecutionAddress
    value: UInt256
    input: seq[byte]
    accessList: seq[ETHAccessTuple]
    maxFeePerBlobGas: UInt256
    blobVersionedHashes: seq[Eth2Digest]
    signature: seq[byte]
    bytes: TypedTransaction

proc ETHTransactionsCreateFromJson(
    transactionsRoot: ptr Eth2Digest,
    transactionsJson: cstring): ptr seq[ETHTransaction] {.exported.} =
  ## Verifies that JSON transactions data is valid and that it matches
  ## the given `transactionsRoot`.
  ##
  ## * The JSON-RPC `eth_getBlockByHash` with params `[executionHash, true]`
  ##   may be used to obtain transactions data for a given execution
  ##   block hash. Pass `result.transactions` as `transactionsJson`.
  ##
  ## * The transaction sequence must be destroyed with
  ##   `ETHTransactionsDestroy` once no longer needed,
  ##   to release memory.
  ##
  ## Parameters:
  ## * `transactionsRoot` - Execution transactions root.
  ## * `transactionsJson` - Buffer with JSON transactions list. NULL-terminated.
  ##
  ## Returns:
  ## * Pointer to an initialized transaction sequence - If successful.
  ## * `NULL` - If the given `transactionsJson` is malformed or incompatible.
  ##
  ## See:
  ## * https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbyhash
  let node =
    try:
      parseJson($transactionsJson)
    except Exception:
      return nil
  var datas: seq[TransactionObject]
  try:
    fromJson(node, argName = "", datas)
  except KeyError, ValueError:
    return nil

  var txs = newSeqOfCap[ETHTransaction](datas.len)
  for i, data in datas:
    # Sanity check
    if data.transactionIndex.isNone:
      return nil
    if distinctBase(data.transactionIndex.get) != i.uint64:
      return nil

    # Check fork consistency
    static: doAssert totalSerializedFields(TransactionObject) == 21,
      "Only update this number once code is adjusted to check new fields!"
    let txType =
      case data.`type`.get(0.Quantity):
      of 0.Quantity:
        if data.accessList.isSome or
            data.maxFeePerGas.isSome or data.maxPriorityFeePerGas.isSome or
            data.maxFeePerBlobGas.isSome or data.blobVersionedHashes.isSome:
          return nil
        TxLegacy
      of 1.Quantity:
        if data.chainId.isNone or data.accessList.isNone:
          return nil
        if data.maxFeePerGas.isSome or data.maxPriorityFeePerGas.isSome or
            data.maxFeePerBlobGas.isSome or data.blobVersionedHashes.isSome:
          return nil
        TxEip2930
      of 2.Quantity:
        if data.chainId.isNone or data.accessList.isNone or
            data.maxFeePerGas.isNone or data.maxPriorityFeePerGas.isNone:
          return nil
        if data.maxFeePerBlobGas.isSome or data.blobVersionedHashes.isSome:
          return nil
        TxEip1559
      of 3.Quantity:
        if data.to.isNone or data.chainId.isNone or data.accessList.isNone or
            data.maxFeePerGas.isNone or data.maxPriorityFeePerGas.isNone or
            data.maxFeePerBlobGas.isNone or data.blobVersionedHashes.isNone:
          return nil
        TxEip4844
      else:
        return nil

    # Construct transaction
    static:
      doAssert sizeof(uint64) == sizeof(ChainId)
      doAssert sizeof(int64) == sizeof(data.gasPrice)
      doAssert sizeof(int64) == sizeof(data.maxPriorityFeePerGas.get)
      doAssert sizeof(UInt256) == sizeof(data.maxFeePerBlobGas.get)
    if distinctBase(data.chainId.get(0.Quantity)) > distinctBase(ChainId.high):
      return nil
    if distinctBase(data.gasPrice) > int64.high.uint64:
      return nil
    if distinctBase(data.maxFeePerGas.get(0.Quantity)) > int64.high.uint64:
      return nil
    if distinctBase(data.maxPriorityFeePerGas.get(0.Quantity)) >
        int64.high.uint64:
      return nil
    if data.maxFeePerBlobGas.get(0.u256) >
        uint64.high.u256:
      return nil
    if distinctBase(data.gas) > int64.high.uint64:
      return nil
    if data.v.uint64 > int64.high.uint64:
      return nil
    let
      tx = ExecutionTransaction(
        txType: txType,
        chainId: data.chainId.get(0.Quantity).ChainId,
        nonce: distinctBase(data.nonce),
        gasPrice: data.gasPrice.GasInt,
        maxPriorityFee:
          distinctBase(data.maxPriorityFeePerGas.get(data.gasPrice)).GasInt,
        maxFee: distinctBase(data.maxFeePerGas.get(data.gasPrice)).GasInt,
        gasLimit: distinctBase(data.gas).GasInt,
        to:
          if data.to.isSome:
            some(distinctBase(data.to.get))
          else:
            none(EthAddress),
        value: data.value,
        payload: data.input,
        accessList:
          if data.accessList.isSome:
            data.accessList.get.mapIt(AccessPair(
              address: distinctBase(it.address),
              storageKeys: it.storageKeys.mapIt(distinctBase(it))))
          else:
            @[],
        maxFeePerBlobGas:
          data.maxFeePerBlobGas.get(0.u256),
        versionedHashes:
          if data.blobVersionedHashes.isSome:
            data.blobVersionedHashes.get.mapIt(
              ExecutionHash256(data: distinctBase(it)))
          else:
            @[],
        V: data.v.int64,
        R: data.r,
        S: data.s)
      rlpBytes =
        try:
          rlp.encode(tx)
        except RlpError:
          raiseAssert "Unreachable"
      hash = keccakHash(rlpBytes)
    if data.hash.asEth2Digest != hash:
      return nil

    template isEven(x: int64): bool =
      (x and 1) == 0

    # Compute from execution address
    var rawSig {.noinit.}: array[65, byte]
    rawSig[0 ..< 32] = tx.R.toBytesBE()
    rawSig[32 ..< 64] = tx.S.toBytesBE()
    rawSig[64] =
      if txType != TxLegacy:
        tx.V.uint8
      elif tx.V.isEven:
        1
      else:
        0
    let
      sig = SkRecoverableSignature.fromRaw(rawSig).valueOr:
        return nil
      sigHash = SkMessage.fromBytes(tx.txHashNoSignature().data).valueOr:
        return nil
      fromPubkey = sig.recover(sigHash).valueOr:
        return nil
      fromAddress = keys.PublicKey(fromPubkey).toCanonicalAddress()
    if distinctBase(data.`from`) != fromAddress:
      return nil

    # Compute to execution address
    let
      destinationType =
        if tx.to.isSome:
          DestinationType.Regular
        else:
          DestinationType.Create
      toAddress =
        case destinationType
        of DestinationType.Regular:
          tx.to.get
        of DestinationType.Create:
          var res {.noinit.}: array[20, byte]
          res[0 ..< 20] = keccakHash(rlp.encodeList(fromAddress, tx.nonce))
            .data.toOpenArray(12, 31)
          res

    txs.add ETHTransaction(
      hash: keccakHash(rlpBytes),
      chainId: distinctBase(tx.chainId).u256,
      `from`: ExecutionAddress(data: fromAddress),
      nonce: tx.nonce,
      maxPriorityFeePerGas: tx.maxPriorityFee.uint64,
      maxFeePerGas: tx.maxFee.uint64,
      gas: tx.gasLimit.uint64,
      destinationType: destinationType,
      to: ExecutionAddress(data: toAddress),
      value: tx.value,
      input: tx.payload,
      accessList: tx.accessList.mapIt(ETHAccessTuple(
        address: ExecutionAddress(data: it.address),
        storageKeys: it.storageKeys.mapIt(Eth2Digest(data: it)))),
      maxFeePerBlobGas: tx.maxFeePerBlobGas,
      blobVersionedHashes: tx.versionedHashes,
      signature: @rawSig,
      bytes: rlpBytes.TypedTransaction)

  var tr = initHexaryTrie(newMemoryDB())
  for i, transaction in txs:
    try:
      tr.put(rlp.encode(i), distinctBase(transaction.bytes))
    except RlpError:
      raiseAssert "Unreachable"
  if tr.rootHash() != transactionsRoot[]:
    return nil

  let transactions = seq[ETHTransaction].new()
  transactions[] = txs
  transactions.toUnmanagedPtr()

proc ETHTransactionsDestroy(
    transactions: ptr seq[ETHTransaction]) {.exported.} =
  ## Destroys a transaction sequence.
  ##
  ## * The transaction sequence must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `transactions` - Transaction sequence.
  transactions.destroy()

func ETHTransactionsGetCount(
    transactions: ptr seq[ETHTransaction]): cint {.exported.} =
  ## Indicates the total number of transactions in a transaction sequence.
  ##
  ## * Individual transactions may be inspected using `ETHTransactionsGet`.
  ##
  ## Parameters:
  ## * `transactions` - Transaction sequence.
  ##
  ## Returns:
  ## * Number of available transactions.
  transactions[].len.cint

func ETHTransactionsGet(
    transactions: ptr seq[ETHTransaction],
    transactionIndex: cint): ptr ETHTransaction {.exported.} =
  ## Obtains an individual transaction by sequential index
  ## in a transaction sequence.
  ##
  ## * The returned value is allocated in the given transaction sequence.
  ##   It must neither be released nor written to, and the transaction
  ##   sequence must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transactions` - Transaction sequence.
  ## * `transactionIndex` - Sequential transaction index.
  ##
  ## Returns:
  ## * Transaction.
  addr transactions[][transactionIndex.int]

func ETHTransactionGetHash(
    transaction: ptr ETHTransaction): ptr Eth2Digest {.exported.} =
  ## Obtains the transaction hash of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Transaction hash.
  addr transaction[].hash

func ETHTransactionGetChainId(
    transaction: ptr ETHTransaction): ptr UInt256 {.exported.} =
  ## Obtains the chain ID of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Chain ID.
  addr transaction[].chainId

func ETHTransactionGetFrom(
    transaction: ptr ETHTransaction): ptr ExecutionAddress {.exported.} =
  ## Obtains the from address of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * From execution address.
  addr transaction[].`from`

func ETHTransactionGetNonce(
    transaction: ptr ETHTransaction): ptr uint64 {.exported.} =
  ## Obtains the nonce of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Nonce.
  addr transaction[].nonce

func ETHTransactionGetMaxPriorityFeePerGas(
    transaction: ptr ETHTransaction): ptr uint64 {.exported.} =
  ## Obtains the max priority fee per gas of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Max priority fee per gas.
  addr transaction[].maxPriorityFeePerGas

func ETHTransactionGetMaxFeePerGas(
    transaction: ptr ETHTransaction): ptr uint64 {.exported.} =
  ## Obtains the max fee per gas of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Max fee per gas.
  addr transaction[].maxFeePerGas

func ETHTransactionGetGas(
    transaction: ptr ETHTransaction): ptr uint64 {.exported.} =
  ## Obtains the gas of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Gas.
  addr transaction[].gas

func ETHTransactionIsCreatingContract(
    transaction: ptr ETHTransaction): bool {.exported.} =
  ## Indicates whether or not a transaction is creating a contract.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Whether or not the transaction is creating a contract.
  case transaction[].destinationType
  of DestinationType.Regular:
    false
  of DestinationType.Create:
    true

func ETHTransactionGetTo(
    transaction: ptr ETHTransaction): ptr ExecutionAddress {.exported.} =
  ## Obtains the to address of a transaction.
  ##
  ## * If the transaction is creating a contract, this function returns
  ##   the address of the new contract.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * To execution address.
  addr transaction[].to

func ETHTransactionGetValue(
    transaction: ptr ETHTransaction): ptr UInt256 {.exported.} =
  ## Obtains the value of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Value.
  addr transaction[].value

func ETHTransactionGetInputBytes(
    transaction: ptr ETHTransaction,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the input of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with input.
  numBytes[] = transaction[].input.len.cint
  if transaction[].input.len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultInput: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultInput)
  cast[ptr UncheckedArray[byte]](addr transaction[].input[0])

func ETHTransactionGetAccessList(
    transaction: ptr ETHTransaction): ptr seq[ETHAccessTuple] {.exported.} =
  ## Obtains the access list of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Transaction access list.
  addr transaction[].accessList

func ETHAccessListGetCount(
    accessList: ptr seq[ETHAccessTuple]): cint {.exported.} =
  ## Indicates the total number of access tuples in a transaction access list.
  ##
  ## * Individual access tuples may be inspected using `ETHAccessListGet`.
  ##
  ## Parameters:
  ## * `accessList` - Transaction access list.
  ##
  ## Returns:
  ## * Number of available access tuples.
  accessList[].len.cint

func ETHAccessListGet(
    accessList: ptr seq[ETHAccessTuple],
    accessTupleIndex: cint): ptr ETHAccessTuple {.exported.} =
  ## Obtains an individual access tuple by sequential index
  ## in a transaction access list.
  ##
  ## * The returned value is allocated in the given transaction access list.
  ##   It must neither be released nor written to, and the transaction
  ##   access list must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `accessList` - Transaction access list.
  ## * `accessTupleIndex` - Sequential access tuple index.
  ##
  ## Returns:
  ## * Access tuple.
  addr accessList[][accessTupleIndex.int]

func ETHAccessTupleGetAddress(
    accessTuple: ptr ETHAccessTuple): ptr ExecutionAddress {.exported.} =
  ## Obtains the address of an access tuple.
  ##
  ## * The returned value is allocated in the given access tuple.
  ##   It must neither be released nor written to, and the access tuple
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `accessTuple` - Access tuple.
  ##
  ## Returns:
  ## * Address.
  addr accessTuple[].address

func ETHAccessTupleGetNumStorageKeys(
    accessTuple: ptr ETHAccessTuple): cint {.exported.} =
  ## Indicates the total number of storage keys in an access tuple.
  ##
  ## * Individual storage keys may be inspected using
  ##   `ETHAccessTupleGetStorageKey`.
  ##
  ## Parameters:
  ## * `accessTuple` - Access tuple.
  ##
  ## Returns:
  ## * Number of available storage keys.
  accessTuple[].storageKeys.len.cint

func ETHAccessTupleGetStorageKey(
    accessTuple: ptr ETHAccessTuple,
    storageKeyIndex: cint): ptr Eth2Digest {.exported.} =
  ## Obtains an individual storage key by sequential index
  ## in an access tuple.
  ##
  ## * The returned value is allocated in the given transaction access tuple.
  ##   It must neither be released nor written to, and the transaction
  ##   access tuple must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `accessTuple` - Access tuple.
  ## * `storageKeyIndex` - Sequential storage key index.
  ##
  ## Returns:
  ## * Storage key.
  addr accessTuple[].storageKeys[storageKeyIndex.int]

func ETHTransactionGetMaxFeePerBlobGas(
    transaction: ptr ETHTransaction): ptr UInt256 {.exported.} =
  ## Obtains the max fee per blob gas of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Max fee per blob gas.
  addr transaction[].maxFeePerBlobGas

func ETHTransactionGetNumBlobVersionedHashes(
    transaction: ptr ETHTransaction): cint {.exported.} =
  ## Indicates the total number of blob versioned hashes of a transaction.
  ##
  ## * Individual blob versioned hashes may be inspected using
  ##   `ETHTransactionGetBlobVersionedHash`.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ##
  ## Returns:
  ## * Number of available blob versioned hashes.
  transaction[].blobVersionedHashes.len.cint

func ETHTransactionGetBlobVersionedHash(
    transaction: ptr ETHTransaction,
    versionedHashIndex: cint): ptr Eth2Digest {.exported.} =
  ## Obtains an individual blob versioned hash by sequential index
  ## in a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ## * `versionedHashIndex` - Sequential blob versioned hash index.
  ##
  ## Returns:
  ## * Blob versioned hash.
  addr transaction[].blobVersionedHashes[versionedHashIndex.int]

func ETHTransactionGetSignatureBytes(
    transaction: ptr ETHTransaction,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the signature of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with signature.
  numBytes[] = distinctBase(transaction[].signature).len.cint
  if distinctBase(transaction[].signature).len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultBytes: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultBytes)
  cast[ptr UncheckedArray[byte]](addr distinctBase(transaction[].signature)[0])

func ETHTransactionGetBytes(
    transaction: ptr ETHTransaction,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the raw byte representation of a transaction.
  ##
  ## * The returned value is allocated in the given transaction.
  ##   It must neither be released nor written to, and the transaction
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `transaction` - Transaction.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with raw transaction data.
  numBytes[] = distinctBase(transaction[].bytes).len.cint
  if distinctBase(transaction[].bytes).len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultBytes: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultBytes)
  cast[ptr UncheckedArray[byte]](addr distinctBase(transaction[].bytes)[0])

type
  ETHLog = object
    address: ExecutionAddress
    topics: seq[Eth2Digest]
    data: seq[byte]

  ReceiptStatusType {.pure.} = enum
    Root,
    Status  # EIP-658

  ETHReceipt = object
    statusType: ReceiptStatusType
    root: Eth2Digest
    status: bool
    gasUsed: uint64
    logsBloom: BloomLogs
    logs: seq[ETHLog]
    bytes: seq[byte]

proc ETHReceiptsCreateFromJson(
    receiptsRoot: ptr Eth2Digest,
    receiptsJson: cstring,
    transactions: ptr seq[ETHTransaction]): ptr seq[ETHReceipt] {.exported.} =
  ## Verifies that JSON receipts data is valid and that it matches
  ## the given `receiptsRoot`.
  ##
  ## * The JSON-RPC `eth_getTransactionReceipt` may be used to obtain
  ##   receipts data for a given transaction hash. For verification, it is
  ##   necessary to obtain the receipt for _all_ transactions within a block.
  ##   Pass a JSON array containing _all_ receipt's `result` as `receiptsJson`.
  ##   The receipts need to be in the same order as the `transactions`.
  ##
  ## * The receipt sequence must be destroyed with `ETHReceiptsDestroy`
  ##   once no longer needed, to release memory.
  ##
  ## Parameters:
  ## * `receiptsRoot` - Execution receipts root.
  ## * `receiptsJson` - Buffer with JSON receipts list. NULL-terminated.
  ## * `transactions` - Transaction sequence.
  ##
  ## Returns:
  ## * Pointer to an initialized receipt sequence - If successful.
  ## * `NULL` - If the given `receiptsJson` is malformed or incompatible.
  ##
  ## See:
  ## * https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
  let node =
    try:
      parseJson($receiptsJson)
    except Exception:
      return nil
  var datas: seq[ReceiptObject]
  try:
    fromJson(node, argName = "", datas)
  except KeyError, ValueError:
    return nil
  if datas.len != ETHTransactionsGetCount(transactions):
    return nil

  var
    recs = newSeqOfCap[ETHReceipt](datas.len)
    cumulativeGasUsed = 0'u64
    logIndex = uint64.high
  for i, data in datas:
    # Sanity check
    if distinctBase(data.transactionIndex) != i.uint64:
      return nil

    # Check fork consistency
    static: doAssert totalSerializedFields(ReceiptObject) == 17,
      "Only update this number once code is adjusted to check new fields!"
    static: doAssert totalSerializedFields(LogObject) == 9,
      "Only update this number once code is adjusted to check new fields!"
    let txType =
      case data.`type`.get(0.Quantity):
      of 0.Quantity:
        TxLegacy
      of 1.Quantity:
        TxEip2930
      of 2.Quantity:
        TxEip1559
      of 3.Quantity:
        TxEip4844
      else:
        return nil
    if data.root.isNone and data.status.isNone or
        data.root.isSome and data.status.isSome:
      return nil
    if data.status.isSome and distinctBase(data.status.get) > 1:
      return nil
    if distinctBase(data.cumulativeGasUsed) !=
        cumulativeGasUsed + distinctBase(data.gasUsed):
      return nil
    cumulativeGasUsed = distinctBase(data.cumulativeGasUsed)
    for log in data.logs:
      if log.removed:
        return nil
      if log.logIndex.isNone:
        return nil
      if distinctBase(log.logIndex.get) != logIndex + 1:
        return nil
      logIndex = distinctBase(log.logIndex.get)
      if log.transactionIndex.isNone:
        return nil
      if log.transactionIndex.get != data.transactionIndex:
        return nil
      if log.transactionHash.isNone:
        return nil
      if log.transactionHash.get != data.transactionHash:
        return nil
      if log.blockHash.isNone:
        return nil
      if log.blockHash.get != data.blockHash:
        return nil
      if log.blockNumber.isNone:
        return nil
      if log.blockNumber.get != data.blockNumber:
        return nil
      if log.data.len mod 32 != 0:
        return nil
      if log.topics.len > 4:
        return nil

    # Construct receipt
    static:
      doAssert sizeof(int64) == sizeof(data.cumulativeGasUsed)
    if distinctBase(data.cumulativeGasUsed) > int64.high.uint64:
      return nil
    let
      rec = ExecutionReceipt(
        receiptType: txType,
        isHash: data.root.isSome,
        status: distinctBase(data.status.get(1.Quantity)) != 0'u64,
        hash:
          if data.root.isSome:
            ExecutionHash256(data: distinctBase(data.root.get))
          else:
            default(ExecutionHash256),
        cumulativeGasUsed: distinctBase(data.cumulativeGasUsed).GasInt,
        bloom: distinctBase(data.logsBloom),
        logs: data.logs.mapIt(Log(
          address: distinctBase(it.address),
          topics: it.topics.mapIt(distinctBase(it)),
          data: it.data)))
      rlpBytes =
        try:
          rlp.encode(rec)
        except RlpError:
          raiseAssert "Unreachable"

    recs.add ETHReceipt(
      statusType:
        if rec.isHash:
          ReceiptStatusType.Root
        else:
          ReceiptStatusType.Status,
      root: rec.hash,
      status: rec.status,
      gasUsed: distinctBase(data.gasUsed),  # Validated during sanity checks.
      logsBloom: BloomLogs(data: rec.bloom),
      logs: rec.logs.mapIt(ETHLog(
        address: ExecutionAddress(data: it.address),
        topics: it.topics.mapIt(Eth2Digest(data: it)),
        data: it.data)),
      bytes: rlpBytes)

  var tr = initHexaryTrie(newMemoryDB())
  for i, rec in recs:
    try:
      tr.put(rlp.encode(i), rec.bytes)
    except RlpError:
      raiseAssert "Unreachable"
  if tr.rootHash() != receiptsRoot[]:
    return nil

  let receipts = seq[ETHReceipt].new()
  receipts[] = recs
  receipts.toUnmanagedPtr()

proc ETHReceiptsDestroy(
    receipts: ptr seq[ETHReceipt]) {.exported.} =
  ## Destroys a receipt sequence.
  ##
  ## * The receipt sequence must no longer be used after destruction.
  ##
  ## Parameters:
  ## * `receipts` - Receipt sequence.
  receipts.destroy()

func ETHReceiptsGetCount(
    receipts: ptr seq[ETHReceipt]): cint {.exported.} =
  ## Indicates the total number of receipts in a receipt sequence.
  ##
  ## * Individual receipts may be inspected using `ETHReceiptsGet`.
  ##
  ## Parameters:
  ## * `receipts` - Receipt sequence.
  ##
  ## Returns:
  ## * Number of available receipts.
  receipts[].len.cint

func ETHReceiptsGet(
    receipts: ptr seq[ETHReceipt],
    receiptIndex: cint): ptr ETHReceipt {.exported.} =
  ## Obtains an individual receipt by sequential index
  ## in a receipt sequence.
  ##
  ## * The returned value is allocated in the given receipt sequence.
  ##   It must neither be released nor written to, and the receipt
  ##   sequence must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `receipts` - Receipt sequence.
  ## * `receiptIndex` - Sequential receipt index.
  ##
  ## Returns:
  ## * Receipt.
  addr receipts[][receiptIndex.int]

func ETHReceiptHasStatus(
    receipt: ptr ETHReceipt): bool {.exported.} =
  ## Indicates whether or not a receipt has a status code.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ##
  ## Returns:
  ## * Whether or not the receipt has a status code.
  ##
  ## See:
  ## * https://eips.ethereum.org/EIPS/eip-658
  case receipt[].statusType
  of ReceiptStatusType.Root:
    false
  of ReceiptStatusType.Status:
    true

func ETHReceiptGetRoot(
    receipt: ptr ETHReceipt): ptr Eth2Digest {.exported.} =
  ## Obtains the intermediate post-state root of a receipt with no status code.
  ##
  ## * If the receipt has a status code, this function returns a zero hash.
  ##
  ## * The returned value is allocated in the given receipt.
  ##   It must neither be released nor written to, and the receipt
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ##
  ## Returns:
  ## * Intermediate post-state root.
  addr receipt[].root

func ETHReceiptGetStatus(
    receipt: ptr ETHReceipt): bool {.exported.} =
  ## Obtains the status code of a receipt with a status code.
  ##
  ## * If the receipt has no status code, this function returns true.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ##
  ## Returns:
  ## * Status code.
  ##
  ## See:
  ## * https://eips.ethereum.org/EIPS/eip-658
  receipt[].status

func ETHReceiptGetGasUsed(
    receipt: ptr ETHReceipt): ptr uint64 {.exported.} =
  ## Obtains the gas used of a receipt.
  ##
  ## * The returned value is allocated in the given receipt.
  ##   It must neither be released nor written to, and the receipt
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ##
  ## Returns:
  ## * Gas used.
  addr receipt[].gasUsed

func ETHReceiptGetLogsBloom(
    receipt: ptr ETHReceipt): ptr BloomLogs {.exported.} =
  ## Obtains the logs Bloom of a receipt.
  ##
  ## * The returned value is allocated in the given receipt.
  ##   It must neither be released nor written to, and the receipt
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ##
  ## Returns:
  ## * Logs Bloom.
  addr receipt[].logsBloom

func ETHReceiptGetLogs(
    receipt: ptr ETHReceipt): ptr seq[ETHLog] {.exported.} =
  ## Obtains the logs of a receipt.
  ##
  ## * The returned value is allocated in the given receipt.
  ##   It must neither be released nor written to, and the receipt
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ##
  ## Returns:
  ## * Log sequence.
  addr receipt[].logs

func ETHLogsGetCount(
    logs: ptr seq[ETHLog]): cint {.exported.} =
  ## Indicates the total number of logs in a log sequence.
  ##
  ## * Individual logs may be inspected using `ETHLogsGet`.
  ##
  ## Parameters:
  ## * `logs` - Log sequence.
  ##
  ## Returns:
  ## * Number of available logs.
  logs[].len.cint

func ETHLogsGet(
    logs: ptr seq[ETHLog],
    logIndex: cint): ptr ETHLog {.exported.} =
  ## Obtains an individual log by sequential index in a log sequence.
  ##
  ## * The returned value is allocated in the given log sequence.
  ##   It must neither be released nor written to, and the log sequence
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `logs` - Log sequence.
  ## * `logIndex` - Sequential log index.
  ##
  ## Returns:
  ## * Log.
  addr logs[][logIndex.int]

func ETHLogGetAddress(
    log: ptr ETHLog): ptr ExecutionAddress {.exported.} =
  ## Obtains the address of a log.
  ##
  ## * The returned value is allocated in the given log.
  ##   It must neither be released nor written to, and the log
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `log` - Log.
  ##
  ## Returns:
  ## * Address.
  addr log[].address

func ETHLogGetNumTopics(
    log: ptr ETHLog): cint {.exported.} =
  ## Indicates the total number of topics in a log.
  ##
  ## * Individual topics may be inspected using `ETHLogGetTopic`.
  ##
  ## Parameters:
  ## * `log` - Log.
  ##
  ## Returns:
  ## * Number of available topics.
  log[].topics.len.cint

func ETHLogGetTopic(
    log: ptr ETHLog,
    topicIndex: cint): ptr Eth2Digest {.exported.} =
  ## Obtains an individual topic by sequential index in a log.
  ##
  ## * The returned value is allocated in the given log.
  ##   It must neither be released nor written to, and the log
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `log` - Log.
  ## * `topicIndex` - Sequential topic index.
  ##
  ## Returns:
  ## * Topic.
  addr log[].topics[topicIndex.int]

func ETHLogGetDataBytes(
    log: ptr ETHLog,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the data of a log.
  ##
  ## * The returned value is allocated in the given log.
  ##   It must neither be released nor written to, and the log
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `log` - Log.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with data.
  numBytes[] = log[].data.len.cint
  if log[].data.len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultData: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultData)
  cast[ptr UncheckedArray[byte]](addr log[].data[0])

func ETHReceiptGetBytes(
    receipt: ptr ETHReceipt,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the raw byte representation of a receipt.
  ##
  ## * The returned value is allocated in the given receipt.
  ##   It must neither be released nor written to, and the receipt
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `receipt` - Receipt.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with raw receipt data.
  numBytes[] = distinctBase(receipt[].bytes).len.cint
  if distinctBase(receipt[].bytes).len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultBytes: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultBytes)
  cast[ptr UncheckedArray[byte]](addr distinctBase(receipt[].bytes)[0])

func ETHWithdrawalsGetCount(
    withdrawals: ptr seq[ETHWithdrawal]): cint {.exported.} =
  ## Indicates the total number of withdrawals in a withdrawal sequence.
  ##
  ## * Individual withdrawals may be inspected using `ETHWithdrawalsGet`.
  ##
  ## Parameters:
  ## * `withdrawals` - Withdrawal sequence.
  ##
  ## Returns:
  ## * Number of available withdrawals.
  withdrawals[].len.cint

func ETHWithdrawalsGet(
    withdrawals: ptr seq[ETHWithdrawal],
    withdrawalIndex: cint): ptr ETHWithdrawal {.exported.} =
  ## Obtains an individual withdrawal by sequential index
  ## in a withdrawal sequence.
  ##
  ## * The returned value is allocated in the given withdrawal sequence.
  ##   It must neither be released nor written to, and the withdrawal
  ##   sequence must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `withdrawals` - Withdrawal sequence.
  ## * `withdrawalIndex` - Sequential withdrawal index.
  ##
  ## Returns:
  ## * Withdrawal.
  addr withdrawals[][withdrawalIndex.int]

func ETHWithdrawalGetIndex(
    withdrawal: ptr ETHWithdrawal): ptr uint64 {.exported.} =
  ## Obtains the index of a withdrawal.
  ##
  ## * The returned value is allocated in the given withdrawal.
  ##   It must neither be released nor written to, and the withdrawal
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `withdrawal` - Withdrawal.
  ##
  ## Returns:
  ## * Index.
  addr withdrawal[].index

func ETHWithdrawalGetValidatorIndex(
    withdrawal: ptr ETHWithdrawal): ptr uint64 {.exported.} =
  ## Obtains the validator index of a withdrawal.
  ##
  ## * The returned value is allocated in the given withdrawal.
  ##   It must neither be released nor written to, and the withdrawal
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `withdrawal` - Withdrawal.
  ##
  ## Returns:
  ## * Validator index.
  addr withdrawal[].validatorIndex

func ETHWithdrawalGetAddress(
    withdrawal: ptr ETHWithdrawal): ptr ExecutionAddress {.exported.} =
  ## Obtains the address of a withdrawal.
  ##
  ## * The returned value is allocated in the given withdrawal.
  ##   It must neither be released nor written to, and the withdrawal
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `withdrawal` - Withdrawal.
  ##
  ## Returns:
  ## * Address.
  addr withdrawal[].address

func ETHWithdrawalGetAmount(
    withdrawal: ptr ETHWithdrawal): ptr uint64 {.exported.} =
  ## Obtains the amount of a withdrawal.
  ##
  ## * The returned value is allocated in the given withdrawal.
  ##   It must neither be released nor written to, and the withdrawal
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `withdrawal` - Withdrawal.
  ##
  ## Returns:
  ## * Amount.
  addr withdrawal[].amount

func ETHWithdrawalGetBytes(
    withdrawal: ptr ETHWithdrawal,
    numBytes #[out]#: ptr cint): ptr UncheckedArray[byte] {.exported.} =
  ## Obtains the raw byte representation of a withdrawal.
  ##
  ## * The returned value is allocated in the given withdrawal.
  ##   It must neither be released nor written to, and the withdrawal
  ##   must not be released while the returned value is in use.
  ##
  ## Parameters:
  ## * `withdrawal` - Withdrawal.
  ## * `numBytes` [out] - Length of buffer.
  ##
  ## Returns:
  ## * Buffer with raw withdrawal data.
  numBytes[] = distinctBase(withdrawal[].bytes).len.cint
  if distinctBase(withdrawal[].bytes).len == 0:
    # https://github.com/nim-lang/Nim/issues/22389
    const defaultBytes: cstring = ""
    return cast[ptr UncheckedArray[byte]](defaultBytes)
  cast[ptr UncheckedArray[byte]](addr distinctBase(withdrawal[].bytes)[0])

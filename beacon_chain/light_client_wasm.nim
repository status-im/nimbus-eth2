# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  eth/p2p/discoveryv5/random2,
  spec/eth2_apis/[eth2_rest_serialization, rest_light_client_calls],
  spec/[helpers, light_client_sync],
  sync/light_client_sync_helpers,
  ./beacon_clock

proc destroy(x: auto) =
  x[].reset()
  x.dealloc()

proc ETHRandomNumberCreate(): ptr ref SecureRngContext {.exportc.} =
  let rng = (ref SecureRngContext).create()
  rng[] = SecureRngContext.new()
  rng

proc ETHRandomNumberDestroy(rng: ptr ref SecureRngContext) {.exportc.} =
  rng.destroy()

proc ETHRuntimeConfigCreateFromYaml(
    fileContent: cstring): ptr RuntimeConfig {.exportc.} =
  let cfg = RuntimeConfig.create()
  try:
    cfg[] = readRuntimeConfig($fileContent, "config.yaml")[0]
    cfg
  except IOError, PresetFileError, PresetIncompatibleError:
    cfg.destroy()
    nil

proc ETHRuntimeConfigDestroy(cfg: ptr RuntimeConfig) {.exportc.} =
  cfg.destroy()

func ETHRuntimeConfigGetConsensusForkAtEpoch(
    cfg: ptr RuntimeConfig, epoch: cint): cstring {.exportc.} =
  withConsensusFork(cfg[].consensusForkAtEpoch(epoch.Epoch)):
    const ethConsensusVersion: cstring = consensusFork.toString()
    ethConsensusVersion

proc ETHBeaconStateCreateFromSsz(
    cfg: ptr RuntimeConfig,
    ethConsensusVersion: cstring,
    sszBytes: ptr UncheckedArray[byte],
    numSszBytes: cint): ptr ForkedHashedBeaconState {.exportc.} =
  let
    consensusFork = decodeEthConsensusVersion($ethConsensusVersion).valueOr:
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

proc ETHBeaconStateDestroy(state: ptr ForkedHashedBeaconState) {.exportc.} =
  state.destroy()

proc ETHBeaconStateCopyGenesisValidatorsRoot(
    state: ptr ForkedHashedBeaconState): ptr Eth2Digest {.exportc.} =
  let genesisValidatorsRoot = Eth2Digest.create()
  genesisValidatorsRoot[] = getStateField(state[], genesis_validators_root)
  genesisValidatorsRoot

proc ETHRootDestroy(root: ptr Eth2Digest) {.exportc.} =
  root.destroy()

proc ETHForkDigestsCreateFromState(
    cfg: ptr RuntimeConfig,
    state: ptr ForkedHashedBeaconState): ptr ref ForkDigests {.exportc.} =
  let forkDigests = (ref ForkDigests).create()
  forkDigests[] = newClone ForkDigests.init(
    cfg[], getStateField(state[], genesis_validators_root))
  forkDigests

proc ETHForkDigestsDestroy(forkDigests: ptr ref ForkDigests) {.exportc.} =
  forkDigests.destroy()

proc ETHBeaconClockCreateFromState(
    state: ptr ForkedHashedBeaconState): ptr BeaconClock {.exportc.} =
  let beaconClock = BeaconClock.create()
  beaconClock[] = BeaconClock.init(getStateField(state[], genesis_time))
  beaconClock

proc ETHBeaconClockDestroy(beaconClock: ptr BeaconClock) {.exportc.} =
  beaconClock.destroy()

proc ETHBeaconClockGetSlot(beaconClock: ptr BeaconClock): cint {.exportc.} =
  beaconClock[].now().slotOrZero().cint

const lcDataFork = LightClientDataFork.high

proc ETHLightClientStoreCreateFromBootstrap(
    cfg: ptr RuntimeConfig,
    trustedBlockRoot: ptr Eth2Digest,
    mediaType: cstring,
    ethConsensusVersion: cstring,
    bootstrapBytes: ptr UncheckedArray[byte],
    numBootstrapBytes: cint
): ptr lcDataFork.LightClientStore {.exportc.} =
  let
    mediaType = MediaType.init($mediaType)
    consensusFork = decodeEthConsensusVersion($ethConsensusVersion).valueOr:
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
    store: ptr lcDataFork.LightClientStore) {.exportc.} =
  store.destroy()

proc ETHLightClientStoreProcessUpdatesByRange(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ref ForkDigests,
    genesisValidatorsRoot: ptr Eth2Digest,
    beaconClock: ptr BeaconClock,
    startPeriod: cint,
    count: cint,
    mediaType: cstring,
    updatesByRangeBytes: ptr UncheckedArray[byte],
    numUpdatesByRangeBytes: cint,
    didProgress: ptr cint): cint {.exportc.} =
  didProgress[] = 0
  let
    wallTime = beaconClock[].now()
    currentSlot = wallTime.slotOrZero()
    mediaType = MediaType.init($mediaType)
  var updates =
    try:
      seq[ForkedLightClientUpdate].decodeHttpLightClientObjects(
        updatesByRangeBytes.toOpenArray(0, numUpdatesByRangeBytes - 1),
        mediaType, cfg[], forkDigests[])
    except RestError:
      return 1
  let e = updates.checkLightClientUpdates(
    startPeriod.SyncCommitteePeriod, count.uint64)
  if e.isErr:
    return 1
  for i in 0 ..< updates.len:
    doAssert updates[i].kind > LightClientDataFork.None
    updates[i].migrateToDataFork(lcDataFork)
    let res = process_light_client_update(
      store[], updates[i].forky(lcDataFork),
      currentSlot, cfg[], genesisValidatorsRoot[])
    if res.isOk:
      didProgress[] = 1
    else:
      case res.error
      of VerifierError.MissingParent:
        return 0
      of VerifierError.Duplicate:
        discard
      of VerifierError.UnviableFork:
        return 0
      of VerifierError.Invalid:
        return 1
  0

proc ETHLightClientStoreProcessFinalityUpdate(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ref ForkDigests,
    genesisValidatorsRoot: ptr Eth2Digest,
    beaconClock: ptr BeaconClock,
    mediaType: cstring,
    ethConsensusVersion: cstring,
    finalityUpdateBytes: ptr UncheckedArray[byte],
    numFinalityUpdateBytes: cint,
    didProgress: ptr cint): cint {.exportc.} =
  didProgress[] = 0
  let
    wallTime = beaconClock[].now()
    currentSlot = wallTime.slotOrZero()
    mediaType = MediaType.init($mediaType)
  var finalityUpdate =
    try:
      if ethConsensusVersion == nil:
        if mediaType != ApplicationJsonMediaType:
          return 1
        ForkedLightClientFinalityUpdate.decodeJsonLightClientObject(
          finalityUpdateBytes.toOpenArray(0, numFinalityUpdateBytes - 1),
          Opt.none(ConsensusFork), cfg[])
      else:
        let consensusFork = decodeEthConsensusVersion(
            $ethConsensusVersion).valueOr:
          return 1
        ForkedLightClientFinalityUpdate.decodeHttpLightClientObject(
          finalityUpdateBytes.toOpenArray(0, numFinalityUpdateBytes - 1),
          mediaType, consensusFork, cfg[])
    except RestError:
      return 1
  doAssert finalityUpdate.kind > LightClientDataFork.None
  finalityUpdate.migrateToDataFork(lcDataFork)
  let res = process_light_client_update(
    store[], finalityUpdate.forky(lcDataFork),
    currentSlot, cfg[], genesisValidatorsRoot[])
  if res.isOk:
    didProgress[] = 1
  else:
    case res.error
    of VerifierError.MissingParent:
      return 0
    of VerifierError.Duplicate:
      discard
    of VerifierError.UnviableFork:
      return 0
    of VerifierError.Invalid:
      return 1
  0

proc ETHLightClientStoreProcessOptimisticUpdate(
    store: ptr lcDataFork.LightClientStore,
    cfg: ptr RuntimeConfig,
    forkDigests: ptr ref ForkDigests,
    genesisValidatorsRoot: ptr Eth2Digest,
    beaconClock: ptr BeaconClock,
    mediaType: cstring,
    ethConsensusVersion: cstring,
    optimisticUpdateBytes: ptr UncheckedArray[byte],
    numOptimisticUpdateBytes: cint,
    didProgress: ptr cint): cint {.exportc.} =
  didProgress[] = 0
  let
    wallTime = beaconClock[].now()
    currentSlot = wallTime.slotOrZero()
    mediaType = MediaType.init($mediaType)
  var optimisticUpdate =
    try:
      if ethConsensusVersion == nil:
        if mediaType != ApplicationJsonMediaType:
          return 1
        ForkedLightClientOptimisticUpdate.decodeJsonLightClientObject(
          optimisticUpdateBytes.toOpenArray(0, numOptimisticUpdateBytes - 1),
          Opt.none(ConsensusFork), cfg[])
      else:
        let consensusFork = decodeEthConsensusVersion(
            $ethConsensusVersion).valueOr:
          return 1
        ForkedLightClientOptimisticUpdate.decodeHttpLightClientObject(
          optimisticUpdateBytes.toOpenArray(0, numOptimisticUpdateBytes - 1),
          mediaType, consensusFork, cfg[])
    except RestError:
      return 1
  doAssert optimisticUpdate.kind > LightClientDataFork.None
  optimisticUpdate.migrateToDataFork(lcDataFork)
  let res = process_light_client_update(
    store[], optimisticUpdate.forky(lcDataFork),
    currentSlot, cfg[], genesisValidatorsRoot[])
  if res.isOk:
    didProgress[] = 1
  else:
    case res.error
    of VerifierError.MissingParent:
      return 0
    of VerifierError.Duplicate:
      discard
    of VerifierError.UnviableFork:
      return 0
    of VerifierError.Invalid:
      return 1
  0

let
  kETHLCSyncKind_UpdatesByRange {.exportc.} = LCSyncKind.UpdatesByRange.cint
  kETHLCSyncKind_FinalityUpdate {.exportc.} = LCSyncKind.FinalityUpdate.cint
  kETHLCSyncKind_OptimisticUpdate {.exportc.} = LCSyncKind.OptimisticUpdate.cint

proc ETHLightClientStoreGetNextSyncTask(
    store: ptr lcDataFork.LightClientStore,
    beaconClock: ptr BeaconClock,
    startPeriod: ptr cint,
    count: ptr cint): cint {.exportc.} =
  let syncTask = nextLightClientSyncTask(
    finalized = store[].finalized_header.beacon.slot.sync_committee_period,
    optimistic = store[].optimistic_header.beacon.slot.sync_committee_period,
    current = beaconClock[].now().slotOrZero().sync_committee_period,
    isNextSyncCommitteeKnown = store[].is_next_sync_committee_known)
  case syncTask.kind
  of LCSyncKind.UpdatesByRange:
    startPeriod[] = syncTask.startPeriod.cint
    count[] = syncTask.count.cint
    syncTask.kind.cint
  of LCSyncKind.FinalityUpdate:
    startPeriod[] = 0
    count[] = 0
    syncTask.kind.cint
  of LCSyncKind.OptimisticUpdate:
    startPeriod[] = 0
    count[] = 0
    syncTask.kind.cint

proc ETHLightClientStoreGetMillisecondsToNextFetch(
    store: ptr lcDataFork.LightClientStore,
    rng: ptr ref SecureRngContext,
    beaconClock: ptr BeaconClock,
    wasLatestOptimistic: bool): cint {.exportc.} =
  let
    wallTime = beaconClock[].now()
    current = wallTime.slotOrZero().sync_committee_period
    finalized = store[].finalized_header.beacon.slot.sync_committee_period
    isNextSyncCommitteeKnown = store[].is_next_sync_committee_known

    schedulingMode =
      if not current.isGossipSupported(finalized, isNextSyncCommitteeKnown):
        SchedulingMode.Soon
      elif not wasLatestOptimistic:
        SchedulingMode.CurrentPeriod
      else:
        SchedulingMode.NextPeriod
    nextFetchTime = rng[].nextLightClientFetchTime(wallTime, schedulingMode)
  timer.nanoseconds((nextFetchTime - wallTime).nanoseconds).milliseconds.cint

func ETHLightClientStoreGetFinalizedHeader(
    store: ptr lcDataFork.LightClientStore
): ptr lcDataFork.LightClientHeader {.exportc.} =
  addr store[].finalized_header

func ETHLightClientStoreGetOptimisticHeader(
    store: ptr lcDataFork.LightClientStore
): ptr lcDataFork.LightClientHeader {.exportc.} =
  addr store[].optimistic_header

func ETHLightClientHeaderGetBeacon(
    header: ptr lcDataFork.LightClientHeader
): ptr BeaconBlockHeader {.exportc.} =
  addr header[].beacon

func ETHBeaconBlockHeaderGetRoot(
    beacon: ptr BeaconBlockHeader, root: ptr Eth2Digest) {.exportc.} =
  root[] = beacon[].hash_tree_root()

func ETHBeaconBlockHeaderGetSlot(
    beacon: ptr BeaconBlockHeader): cint {.exportc.} =
  beacon[].slot.cint

func ETHBeaconBlockHeaderGetProposerIndex(
    beacon: ptr BeaconBlockHeader): cint {.exportc.} =
  beacon[].proposer_index.cint

func ETHBeaconBlockHeaderGetParentRoot(
    beacon: ptr BeaconBlockHeader): ptr Eth2Digest {.exportc.} =
  addr beacon[].parent_root

func ETHBeaconBlockHeaderGetStateRoot(
    beacon: ptr BeaconBlockHeader): ptr Eth2Digest {.exportc.} =
  addr beacon[].state_root

func ETHBeaconBlockHeaderGetBodyRoot(
    beacon: ptr BeaconBlockHeader): ptr Eth2Digest {.exportc.} =
  addr beacon[].body_root

type ExecutionPayloadHeader =
  typeof(default(lcDataFork.LightClientHeader).execution)

func ETHLightClientHeaderGetExecution(
    header: ptr lcDataFork.LightClientHeader
): ptr ExecutionPayloadHeader {.exportc.} =
  addr header[].execution

func ETHExecutionPayloadHeaderGetParentHash(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].parent_hash

func ETHExecutionPayloadHeaderGetFeeRecipient(
    execution: ptr ExecutionPayloadHeader): ptr ExecutionAddress {.exportc.} =
  addr execution[].fee_recipient

func ETHExecutionPayloadHeaderGetStateRoot(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].state_root

func ETHExecutionPayloadHeaderGetReceiptsRoot(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].receipts_root

func ETHExecutionPayloadHeaderGetLogsBloom(
    execution: ptr ExecutionPayloadHeader): ptr BloomLogs {.exportc.} =
  addr execution[].logs_bloom

func ETHExecutionPayloadHeaderGetPrevRandao(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].prev_randao

func ETHExecutionPayloadHeaderGetBlockNumber(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].block_number.cint

func ETHExecutionPayloadHeaderGetGasLimit(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].gas_limit.cint

func ETHExecutionPayloadHeaderGetGasUsed(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].gas_used.cint

func ETHExecutionPayloadHeaderGetTimestamp(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].timestamp.cint

func ETHExecutionPayloadHeaderGetNumExtraDataBytes(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].extra_data.len.cint

func ETHExecutionPayloadHeaderGetExtraDataBytes(
    execution: ptr ExecutionPayloadHeader
): ptr UncheckedArray[byte] {.exportc.} =
  cast[ptr UncheckedArray[byte]](addr execution[].extra_data[0])

func ETHExecutionPayloadHeaderGetBaseFeePerGas(
    execution: ptr ExecutionPayloadHeader): ptr UInt256 {.exportc.} =
  addr execution[].base_fee_per_gas

func ETHExecutionPayloadHeaderGetBlockHash(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].block_hash

func ETHExecutionPayloadHeaderGetTransactionsRoot(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].transactions_root

func ETHExecutionPayloadHeaderGetWithdrawalsRoot(
    execution: ptr ExecutionPayloadHeader): ptr Eth2Digest {.exportc.} =
  addr execution[].withdrawals_root

func ETHExecutionPayloadHeaderGetDataGasUsed(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].data_gas_used.cint

func ETHExecutionPayloadHeaderGetExcessDataGas(
    execution: ptr ExecutionPayloadHeader): cint {.exportc.} =
  execution[].excess_data_gas.cint

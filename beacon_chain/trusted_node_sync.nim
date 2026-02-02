# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  stew/base10,
  chronicles, chronos, eth/async_utils,
  ./sync/[light_client_sync_helpers, sync_manager],
  ./consensus_object_pools/[block_clearance, blockchain_dag],
  ./spec/eth2_apis/rest_beacon_client,
  ./spec/[beaconstate, eth2_merkleization, forks, light_client_sync,
          network, presets, state_transition],
  ./process_state

from presto import RestDecodingError
from "."/beacon_clock import
  BeaconClock, fromFloatSeconds, currentSlot, init

const
  largeRequestsTimeout = 6.minutes  # Downloading large items such as states.
  smallRequestsTimeout = 30.seconds # Downloading smaller items such as blocks and deposit snapshots.

from ./spec/datatypes/deneb import asSigVerified, shortLog

type
  TrustedNodeSyncKind* {.pure.} = enum
    TrustedBlockRoot,
    StateId

  TrustedNodeSyncTarget* = object
    case kind*: TrustedNodeSyncKind
    of TrustedNodeSyncKind.TrustedBlockRoot:
      trustedBlockRoot*: Eth2Digest
    of TrustedNodeSyncKind.StateId:
      stateId*: string

func shortLog*(v: TrustedNodeSyncTarget): auto =
  case v.kind
  of TrustedNodeSyncKind.TrustedBlockRoot:
    "trustedBlockRoot(" & $v.trustedBlockRoot & ")"
  of TrustedNodeSyncKind.StateId:
    v.stateId

chronicles.formatIt(TrustedNodeSyncTarget): shortLog(it)

proc fromTrustedBlockRoot*(T: type TrustedNodeSyncTarget, v: Eth2Digest): T =
  T(kind: TrustedNodeSyncKind.TrustedBlockRoot, trustedBlockRoot: v)

proc fromStateId*(T: type TrustedNodeSyncTarget, v: string): T =
  T(kind: TrustedNodeSyncKind.StateId, stateId: v)

proc createNewRestClient(url: string): Result[RestClientRef, cstring] =
  let
    flags = {RestClientFlag.CommaSeparatedArray,
             RestClientFlag.ResolveAlways}
    socketFlags = {SocketFlags.TcpNoDelay}
  RestClientRef.new(url, flags = flags, socketFlags = socketFlags)

proc fetchCheckpointState(
    cfg: RuntimeConfig,
    client: RestClientRef,
    syncTarget: TrustedNodeSyncTarget,
    genesisState: ref ForkedHashedBeaconState,
): Future[ref ForkedHashedBeaconState] {.async: (raises: [CancelledError]).} =
  var stateRoot: Opt[Eth2Digest]
  let stateId =
    case syncTarget.kind
    of TrustedNodeSyncKind.TrustedBlockRoot:
      # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/altair/light-client/light-client.md#light-client-sync-process
      const lcDataFork = LightClientDataFork.high
      var bestViableCheckpoint: Opt[tuple[slot: Slot, state_root: Eth2Digest]]
      func trackBestViableCheckpoint(store: lcDataFork.LightClientStore) =
        if store.finalized_header.beacon.slot.is_epoch:
          bestViableCheckpoint.ok(
            (
              slot: store.finalized_header.beacon.slot,
              state_root: store.finalized_header.beacon.state_root,
            )
          )

      doAssert genesisState != nil, "Already checked for `TrustedBlockRoot`"
      let
        genesisTime = genesisState[].genesis_time
        beaconClock = BeaconClock.init(cfg.timeParams, genesisTime).valueOr:
          error "Invalid genesis time in state", genesisTime
          quit 1

        genesis_validators_root = genesisState[].genesis_validators_root
        forkDigests = newClone ForkDigests.init(cfg, genesis_validators_root)

        trustedBlockRoot = syncTarget.trustedBlockRoot

      notice "Downloading state verification light client data", trustedBlockRoot

      var bootstrap =
        try:
          info "Downloading LC bootstrap", trustedBlockRoot
          awaitWithTimeout(
            client.getLightClientBootstrap(trustedBlockRoot, cfg, forkDigests),
            smallRequestsTimeout,
          ):
            error "Attempt to download LC bootstrap timed out"
            return nil
        except CatchableError as exc:
          error "Unable to download LC bootstrap", error = exc.msg
          return nil
      if bootstrap.kind == LightClientDataFork.None:
        error "LC bootstrap unavailable on server"
        return nil
      bootstrap.migrateToDataFork(lcDataFork)

      var store = initialize_light_client_store(
        trustedBlockRoot, bootstrap.forky(lcDataFork), cfg
      ).valueOr:
        error "`initialize_light_client_store` failed", err = error
        quit 1
      store.trackBestViableCheckpoint()

      while true:
        let
          finalized = store.finalized_header.beacon.slot.sync_committee_period
          optimistic = store.optimistic_header.beacon.slot.sync_committee_period
          current = beaconClock.currentSlot.sync_committee_period
          isNextSyncCommitteeKnown = store.is_next_sync_committee_known
          periods: Slice[SyncCommitteePeriod] =
            if finalized == optimistic and not isNextSyncCommitteeKnown:
              if finalized >= current:
                finalized .. finalized
              else:
                finalized ..< current
            elif finalized + 1 < current:
              finalized + 1 ..< current
            else:
              break
          startPeriod = periods.a
          count = min(periods.len, MAX_REQUEST_LIGHT_CLIENT_UPDATES).uint64

        var updates =
          try:
            info "Downloading LC updates", startPeriod, count
            awaitWithTimeout(
              client.getLightClientUpdatesByRange(startPeriod, count, cfg, forkDigests),
              smallRequestsTimeout,
            ):
              error "Attempt to download LC updates timed out"
              return nil
          except CatchableError as exc:
            error "Unable to download LC updates", error = exc.msg
            return nil
        updates.checkLightClientUpdates(startPeriod, count).isOkOr:
          error "Malformed LC updates response", error
          quit 1
        if updates.len == 0:
          warn "Server does not appear to be fully synced"
          break

        for i in 0 ..< updates.len:
          doAssert updates[i].kind > LightClientDataFork.None
          updates[i].migrateToDataFork(lcDataFork)
          store.process_light_client_update(
            updates[i].forky(lcDataFork),
            beaconClock.currentSlot,
            cfg,
            genesis_validators_root,
          ).isOkOr:
            error "`process_light_client_update` failed", error
            quit 1
          store.trackBestViableCheckpoint()

      var finalityUpdate =
        try:
          info "Downloading LC finality update"
          awaitWithTimeout(
            client.getLightClientFinalityUpdate(cfg, forkDigests), smallRequestsTimeout
          ):
            error "Attempt to download LC finality update timed out"
            return nil
        except CatchableError as exc:
          error "Unable to download LC finality update", err = exc.msg
          return nil
      if bootstrap.kind == LightClientDataFork.None:
        error "LC finality update unavailable on server"
        return nil

      finalityUpdate.migrateToDataFork(lcDataFork)

      store.process_light_client_update(
        finalityUpdate.forky(lcDataFork),
        beaconClock.currentSlot,
        cfg,
        genesis_validators_root,
      ).isOkOr:
        error "`process_light_client_update` failed", error
        quit 1
      store.trackBestViableCheckpoint()

      if bestViableCheckpoint.isErr:
        error "CP not on epoch boundary. Retry later",
          latestCheckpointSlot = store.finalized_header.beacon.slot
        return nil
      if not store.finalized_header.beacon.slot.is_epoch:
        warn "CP not on epoch boundary. Using older one",
          latestCheckpointSlot = store.finalized_header.beacon.slot,
          bestViableCheckpointSlot = bestViableCheckpoint.get.slot

      stateRoot.ok bestViableCheckpoint.get.state_root
      Base10.toString(distinctBase(bestViableCheckpoint.get.slot))
    of TrustedNodeSyncKind.StateId:
      syncTarget.stateId

  logScope:
    stateId

  notice "Downloading checkpoint state"

  let state =
    try:
      let id = block:
        let tmp = StateIdent.decodeString(stateId).valueOr:
          error "Cannot decode checkpoint state id, must be a slot, hash, 'finalized' or 'head'"
          return nil
        if tmp.kind == StateQueryKind.Slot and not tmp.slot.is_epoch():
          notice "Rounding given slot to epoch"
          StateIdent.init(tmp.slot.epoch().start_slot)
        else:
          tmp
      awaitWithTimeout(client.getStateV2(id, cfg), largeRequestsTimeout):
        error "Attempt to download checkpoint state timed out; https://nimbus.guide/trusted-node-sync.html#sync-from-checkpoint-files provides an alternative approach"
        return nil
    except CatchableError as exc:
      error "Unable to download checkpoint state", error = exc.msg
      return nil

  if state == nil:
    error "No state found a given checkpoint"
    return nil

  if stateRoot.isSome:
    if state[].root != stateRoot.get:
      error "Checkpoint state has incorrect root!",
        expectedStateRoot = stateRoot.get, actualStateRoot = state[].root
      return nil

    notice "Checkpoint state validated against light client data",
      stateRoot = stateRoot.get

  if not state[].slot.is_epoch():
    error "State slot must fall on an epoch boundary",
      slot = state[].slot,
      offset = state[].slot - state[].slot.epoch.start_slot
    return nil

  state

proc fetchCheckpointState*(
  cfg: RuntimeConfig,
  restUrl: string,
  syncTarget: TrustedNodeSyncTarget,
  genesisState: ref ForkedHashedBeaconState,
): Future[ref ForkedHashedBeaconState] {.async: (raises: [CancelledError]).} =
  var
    client = createNewRestClient(restUrl).valueOr:
      error "Cannot connect to server", url = restUrl, reason = error
      quit 1
  defer:
    await client.closeWait()

  await fetchCheckpointState(cfg, client, syncTarget, genesisState)

proc doTrustedNodeSync*(
    db: BeaconChainDB,
    cfg: RuntimeConfig,
    databaseDir: string,
    eraDir: string,
    restUrl: string,
    syncTarget: TrustedNodeSyncTarget,
    backfill: bool,
    reindex: bool,
    genesisState: ref ForkedHashedBeaconState = nil,
) {.async: (raises: [CancelledError]).} =
  logScope:
    restUrl
    syncTarget

  notice "Starting trusted node sync",
    databaseDir, backfill, reindex

  var
    client = createNewRestClient(restUrl).valueOr:
      error "Cannot connect to server", url = restUrl, reason = error
      quit 1
  defer:
    await client.closeWait()

  # If possible, we'll store the genesis state in the database - this is not
  # strictly necessary but renders the resulting database compatible with
  # versions prior to 22.11 and makes reindexing possible
  let genesisState =
    if (let genesisRoot = db.getGenesisBlock(); genesisRoot.isSome()):
      let
        genesisBlock = db.getForkedBlock(genesisRoot.get()).valueOr:
          error "Cannot load genesis block from database",
            genesisRoot = genesisRoot.get()
          quit 1
        genesisStateRoot = genesisBlock.state_root
        consensusFork = cfg.consensusForkAtEpoch(GENESIS_EPOCH)

        tmp = (ref ForkedHashedBeaconState)(kind: consensusFork)
      if not db.getState(consensusFork, genesisStateRoot, tmp[], noRollback):
        error "Cannot load genesis state from database",
          genesisStateRoot
        quit 1

      if (genesisState != nil) and (tmp[].root != genesisState[].root):
        error "Unexpected genesis state in database, is this the same network?",
          databaseRoot = tmp[].root,
          genesisRoot = genesisState[].root
        quit 1
      tmp
    else:
      let tmp = if genesisState != nil:
        genesisState
      else:
        case syncTarget.kind
        of TrustedNodeSyncKind.TrustedBlockRoot:
          error "Genesis state is required when using `trustedBlockRoot`",
            missingNetworkMetadataFile = "genesis.ssz"
          # `genesis_time` and `genesis_validators_root` are required to check
          # light client data signatures. They are not part of `config.yaml`.
          # We could download the initial state based on `LightClientBootstrap`
          # `state_root`, but that state is unlikely to be readily available and
          # can be much larger than the genesis state. Furthermore, the major
          # known networks bundle the `genesis.ssz` file with network metadata,
          # so adding this complexity doesn't solve a practical usecase. Users
          # on private networks may obtain a trusted `genesis.ssz` file and mark
          # it as trusted by moving it into the network metadata folder.
          #
          # Note that `historical_roots` / `historical_summaries` may be used to
          # prove correctness of a particular genesis state. However, there is
          # currently no endpoint to obtain proofs, and they change for every
          # slot, making it tricky to actually provide them.
          quit 1
        of TrustedNodeSyncKind.StateId:
          notice "Downloading genesis state", restUrl
          try:
            awaitWithTimeout(
                client.getStateV2(StateIdent.init(StateIdentType.Genesis), cfg),
                largeRequestsTimeout):
              info "Attempt to download genesis state timed out"
              # https://github.com/nim-lang/Nim/issues/22180
              (ref ForkedHashedBeaconState)(nil)
          except CatchableError as exc:
            info "Unable to download genesis state",
              error = exc.msg, restUrl
            nil

      if isNil(tmp):
        notice "Server is missing genesis state, node will not be able to reindex history",
          restUrl
      tmp

  let
    dbHead = db.getHeadBlock()
    head = if dbHead.isSome():
      let
        bid = db.getBlockId(dbHead.get()).valueOr:
          error "Database missing head block summary - database too old or corrupt",
            headRoot = dbHead.get()
          quit 1

      Opt.some bid
    else:
      # When we don't have a head, we'll use the given checkpoint as head
      Opt.none(BlockId)

  if head.isNone:
    let state = await fetchCheckpointState(cfg, client, syncTarget, genesisState)

    if state == nil:
      error "No state found a given checkpoint"
      quit 1

    if genesisState != nil:
      if state[].genesis_time != genesisState[].genesis_time:
        error "Checkpoint state does not match genesis",
          timeInCheckpoint = state[].genesis_time,
          timeInGenesis = genesisState[].genesis_time
        quit 1
      if state[].genesis_validators_root != genesisState[].genesis_validators_root:
        error "Checkpoint state does not match genesis",
          rootInCheckpoint = state[].genesis_validators_root,
          rootInGenesis = genesisState[].genesis_validators_root
        quit 1

      ChainDAGRef.preInit(db, genesisState[])

      if genesisState[].slot != state[].slot:
        ChainDAGRef.preInit(db, state[])
    else:
      ChainDAGRef.preInit(db, state[])

  else:
    notice "Skipping checkpoint download, database already exists (remove db directory to get a fresh snapshot)",
      databaseDir, head = shortLog(head.get())

  # Coming this far, we've done what ChainDAGRef.preInit would normally do -
  # we can now load a ChainDAG to start backfilling it
  let
    validatorMonitor = newClone(
      ValidatorMonitor.init(cfg, false, false))
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {}, eraPath = eraDir)
    backfillSlot = max(dag.backfill.slot, 1.Slot) - 1
    horizon = max(dag.horizon, dag.frontfill.valueOr(BlockId()).slot)

  let canReindex = if backfillSlot <= horizon:
    info "Database backfilled", backfill = dag.backfill, horizon
    true
  elif backfill:
    # +1 because we need to download the frontfill slot for the frontfill match
    # detection to kick in, in addBackfillBlock
    let missingSlots = dag.backfill.slot - horizon + 1

    notice "Downloading historical blocks - you can interrupt this process at any time and it will automatically be completed when you start the beacon node",
      backfillSlot, horizon, missingSlots

    var # Same averaging as SyncManager
      syncCount = 0
      processed = 0'u64
      avgSyncSpeed = 0.0
      stamp = SyncMoment.now(0)

    proc downloadBlock(slot: Slot):
        Future[Option[ref ForkedSignedBeaconBlock]] {.async.} =
      # Download block at given slot, retrying a few times,
      var lastError: ref CatchableError
      for i in 0..<3:
        try:
          return awaitWithTimeout(client.getBlockV2(BlockIdent.init(slot), cfg),
                                  smallRequestsTimeout):
            raise newException(CatchableError, "Request timed out")
        except RestResponseError as exc:
          lastError = exc
          notice "Server does not support block downloads / backfilling - blocks will be downloaded later",
            msg = exc.msg
          break
        except CatchableError as exc:
          # We'll assume this may be a connectivity error or something similar
          lastError = exc

          warn "Retrying download of block", slot, err = exc.msg
          client = createNewRestClient(restUrl).valueOr:
            error "Cannot connect to server", url = restUrl, reason = error
            quit 1

      raise lastError

    # Download several blocks in parallel but process them serially
    proc processBlock(blck: Option[ref ForkedSignedBeaconBlock]) =
      let newStamp = SyncMoment.now(processed)
      if newStamp.stamp - stamp.stamp > 12.seconds:
        syncCount += 1

        let
          remaining = dag.backfill.slot - horizon
          slotsPerSec = speed(stamp, newStamp)
        avgSyncSpeed = avgSyncSpeed + (slotsPerSec - avgSyncSpeed) / float(syncCount)

        info "Backfilling",
          timeleft = toTimeLeftString(
            if avgSyncSpeed >= 0.001:
              Duration.fromFloatSeconds(remaining.float / avgSyncSpeed)
            else: InfiniteDuration),
          slotsPerSecond = avgSyncSpeed,
          remainingSlots = remaining
        stamp = newStamp

      processed += 1
      if blck.isSome():
        let
          data = blck.get()

        withBlck(data[]):
          let res =
            case syncTarget.kind
            of TrustedNodeSyncKind.TrustedBlockRoot:
              # Trust-minimized sync: the server is only trusted for
              # data availability, responses must be verified
              dag.addBackfillBlock(forkyBlck)
            of TrustedNodeSyncKind.StateId:
              # The server is fully trusted to provide accurate data;
              # it could have provided a malicious state
              dag.addBackfillBlock(forkyBlck.asSigVerified())
          if res.isErr():
            case res.error()
            of VerifierError.Invalid,
                VerifierError.MissingParent,
                VerifierError.UnviableFork:
              error "Got invalid block from trusted node - is it on the right network?",
                blck = shortLog(forkyBlck), err = res.error()
              quit 1
            of VerifierError.Duplicate, VerifierError.MissingSidecars:
              discard

    # Download blocks backwards from the backfill slot, ie the first slot for
    # which we don't have a block, when walking backwards from the head
    try:
      var
        gets: array[16, Future[Option[ref ForkedSignedBeaconBlock]]]

      for i in 0.uint64..missingSlots + gets.lenu64:
        if i >= gets.lenu64():
          let
            fut = gets[int(i mod gets.lenu64)]

          processBlock(await fut)

        if i <= backfillSlot:
          let slot = backfillSlot - i
          gets[int(i mod gets.lenu64)] = downloadBlock(slot)

        if i mod 1024 == 0:
          db.checkpoint() # Transfer stuff from wal periodically
      true
    except CatchableError as exc: # Block download failed
      notice "Backfilling incomplete - blocks will be downloaded when starting the node", msg = exc.msg
      false
  else:
    let missingSlots = dag.backfill.slot - horizon
    notice "Database initialized, historical blocks will be backfilled when starting the node",
      missingSlots, backfill = dag.backfill, horizon

    false

  if reindex and canReindex:
    notice "Reindexing historical state lookup tables (you can interrupt this process at any time)"

    # Build a DAG
    dag.rebuildIndex(
      proc(): bool =
        ProcessState.stopIt(notice("Shutting down", reason = it))
    )

  notice "Done, your beacon node is ready to serve you! Don't forget to check that you're on the canonical chain by comparing the checkpoint root with other online sources. See https://nimbus.guide/trusted-node-sync.html for more information.",
    checkpoint = dag.head

when isMainModule:
  import
    std/os,
    networking/network_metadata

  let
    cfg = getRuntimeConfig(some os.paramStr(1))
    databaseDir = os.paramStr(2)
    syncTarget = TrustedNodeSyncTarget.fromStateId(os.paramStr(5))
    backfill = os.paramCount() > 5 and os.paramStr(6) == "true"
    db = BeaconChainDB.new(databaseDir, cfg, inMemory = false)
  waitFor db.doTrustedNodeSync(
    cfg, databaseDir, os.paramStr(3),
    os.paramStr(4), syncTarget, backfill, false)
  db.close()

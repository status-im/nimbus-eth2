# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/[base10, results],
  chronicles, chronos, eth/async_utils,
  ./sync/sync_manager,
  ./consensus_object_pools/[block_clearance, blockchain_dag],
  ./spec/eth2_apis/rest_beacon_client,
  ./spec/[beaconstate, eth2_merkleization, forks, presets,
          state_transition, deposit_snapshots],
  "."/[beacon_clock, beacon_chain_db, era_db]

from presto import RestDecodingError

const
  largeRequestsTimeout = 60.seconds # Downloading large items such as states.
  smallRequestsTimeout = 30.seconds # Downloading smaller items such as blocks and deposit snapshots.

proc fetchDepositSnapshot(client: RestClientRef):
                          Future[Result[DepositTreeSnapshot, string]] {.async.} =
  let resp = try:
    awaitWithTimeout(client.getDepositSnapshot(), smallRequestsTimeout):
      return err "Fetching /eth/v1/beacon/deposit_snapshot timed out"
  except CatchableError as e:
    return err("The trusted node likely does not support the /eth/v1/beacon/deposit_snapshot end-point:" & e.msg)

  let data = resp.data.data
  let snapshot = DepositTreeSnapshot(
    eth1Block: data.execution_block_hash,
    depositContractState: DepositContractState(
      branch: data.finalized,
      deposit_count: depositCountBytes(data.deposit_count)),
    blockHeight: data.execution_block_height)

  if not snapshot.isValid(data.deposit_root):
    return err "The obtained deposit snapshot contains self-contradictory data"

  return ok snapshot

from ./spec/datatypes/deneb import asSigVerified, shortLog

proc doTrustedNodeSync*(
    cfg: RuntimeConfig,
    databaseDir: string,
    eraDir: string,
    restUrl: string,
    stateId: string,
    backfill: bool,
    reindex: bool,
    downloadDepositSnapshot: bool,
    genesisState: ref ForkedHashedBeaconState = nil) {.async.} =
  logScope:
    restUrl
    stateId

  notice "Starting trusted node sync",
    databaseDir, backfill, reindex

  var
    client = RestClientRef.new(restUrl).valueOr:
      error "Cannot connect to server", error = error
      quit 1

  let
    db = BeaconChainDB.new(databaseDir, cfg, inMemory = false)
  defer:
    db.close()

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
        genesisStateRoot = getForkedBlockField(genesisBlock, state_root)
        consensusFork = cfg.consensusForkAtEpoch(GENESIS_EPOCH)

        tmp = (ref ForkedHashedBeaconState)(kind: consensusFork)
      if not db.getState(consensusFork, genesisStateRoot, tmp[], noRollback):
        error "Cannot load genesis state from database",
          genesisStateRoot
        quit 1

      if (genesisState != nil) and
          (getStateRoot(tmp[]) != getStateRoot(genesisState[])):
        error "Unexpected genesis state in database, is this the same network?",
          databaseRoot = getStateRoot(tmp[]),
          genesisRoot = getStateRoot(genesisState[])
        quit 1
      tmp
    else:
      let tmp = if genesisState != nil:
        genesisState
      else:
        notice "Downloading genesis state", restUrl
        try:
          awaitWithTimeout(
              client.getStateV2(StateIdent.init(StateIdentType.Genesis), cfg),
              largeRequestsTimeout):
            info "Attempt to download genesis state timed out"
            nil
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
    notice "Downloading checkpoint state"

    let
      state = try:
        let id = block:
          let tmp = StateIdent.decodeString(stateId).valueOr:
            error "Cannot decode checkpoint state id, must be a slot, hash, 'finalized' or 'head'"
            quit 1
          if tmp.kind == StateQueryKind.Slot and not tmp.slot.is_epoch():
            notice "Rounding given slot to epoch"
            StateIdent.init(tmp.slot.epoch().start_slot)
          else:
            tmp
        awaitWithTimeout(client.getStateV2(id, cfg), largeRequestsTimeout):
          error "Attempt to download checkpoint state timed out"
          quit 1
      except CatchableError as exc:
        error "Unable to download checkpoint state",
          error = exc.msg
        quit 1

    if state == nil:
      error "No state found a given checkpoint",
        stateId
      quit 1

    if not getStateField(state[], slot).is_epoch():
      error "State slot must fall on an epoch boundary",
        slot = getStateField(state[], slot),
        offset = getStateField(state[], slot) -
          getStateField(state[], slot).epoch.start_slot
      quit 1

    if genesisState != nil:
      if getStateField(state[], genesis_validators_root) !=
          getStateField(genesisState[], genesis_validators_root):
        error "Checkpoint state does not match genesis",
          rootInCheckpoint = getStateField(state[], genesis_validators_root),
          rootInGenesis = getStateField(genesisState[], genesis_validators_root)
        quit 1

      ChainDAGRef.preInit(db, genesisState[])

      if getStateField(genesisState[], slot) != getStateField(state[], slot):
        ChainDAGRef.preInit(db, state[])
    else:
      ChainDAGRef.preInit(db, state[])

    if downloadDepositSnapshot:
      # Fetch deposit snapshot.  This API endpoint is still optional.
      let depositSnapshot = await fetchDepositSnapshot(client)
      if depositSnapshot.isOk:
        if depositSnapshot.get.matches(getStateField(state[], eth1_data)):
          info "Writing deposit contracts snapshot",
               depositRoot = depositSnapshot.get.getDepositRoot(),
               depositCount = depositSnapshot.get.getDepositCountU64
          db.putDepositTreeSnapshot(depositSnapshot.get)
        else:
          warn "The downloaded deposit snapshot does not agree with the downloaded state"
      else:
        warn "Deposit tree snapshot was not imported", reason = depositSnapshot.error

  else:
    notice "Skipping checkpoint download, database already exists (remove db directory to get a fresh snapshot)",
      databaseDir, head = shortLog(head.get())

  # Coming this far, we've done what ChainDAGRef.preInit would normally do -
  # we can now load a ChainDAG to start backfilling it
  let
    validatorMonitor = newClone(ValidatorMonitor.init(false, false))
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {}, eraPath = eraDir)
    backfillSlot = dag.backfill.slot
    horizon = max(dag.horizon, dag.frontfill.valueOr(BlockId()).slot)

  let canReindex = if backfillSlot <= horizon:
    info "Database backfilled", backfill = dag.backfill, horizon
    true
  elif backfill:
    # +1 because we need to download the frontfill slot for the frontfill match
    # detection to kick in, in addBackfillBlock
    let missingSlots = dag.backfill.slot - horizon + 1

    notice "Downloading historical blocks - you can interrupt this process at any time and it automatically be completed when you start the beacon node",
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
          client = RestClientRef.new(restUrl).valueOr:
            error "Cannot connect to server", url = restUrl, error = error
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
          if (let res = dag.addBackfillBlock(blck.asSigVerified()); res.isErr()):
            case res.error()
            of VerifierError.Invalid,
                VerifierError.MissingParent,
                VerifierError.UnviableFork:
              error "Got invalid block from trusted node - is it on the right network?",
                blck = shortLog(blck), err = res.error()
              quit 1
            of VerifierError.Duplicate:
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
    dag.rebuildIndex()

  notice "Done, your beacon node is ready to serve you! Don't forget to check that you're on the canonical chain by comparing the checkpoint root with other online sources. See https://nimbus.guide/trusted-node-sync.html for more information.",
    checkpoint = dag.head

when isMainModule:
  import
    std/[os],
    networking/network_metadata

  let backfill = os.paramCount() > 5 and os.paramStr(6) == "true"

  waitFor doTrustedNodeSync(
    getRuntimeConfig(some os.paramStr(1)), os.paramStr(2), os.paramStr(3),
    os.paramStr(4), os.paramStr(5), backfill, false, true)

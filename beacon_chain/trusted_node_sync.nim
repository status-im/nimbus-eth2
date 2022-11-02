# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  stew/base10,
  chronicles, chronos,
  ./sync/sync_manager,
  ./consensus_object_pools/blockchain_dag,
  ./spec/eth2_apis/rest_beacon_client,
  ./spec/[beaconstate, eth2_merkleization, forks, presets, state_transition],
  "."/[beacon_clock, beacon_chain_db]

type
  DbCache = object
    summaries: Table[Eth2Digest, BeaconBlockSummary]
    slots: seq[Option[Eth2Digest]]

proc updateSlots(cache: var DbCache, slot: Slot) =
  if cache.slots.lenu64() < slot:
    cache.slots.setLen(slot.int + 1)

proc updateSlots(cache: var DbCache, root: Eth2Digest, slot: Slot) =
  # The slots mapping stores one linear block history - we construct it by
  # starting from a given root/slot and walking the known parents as far back
  # as possible which ensures that all blocks belong to the same history

  cache.updateSlots(slot)

  var
    root = root
    lastSlot = slot

  while true:
    cache.summaries.withValue(root, v) do:
      let slot = v[].slot

      for i in slot.int + 1..<lastSlot.int: # Avoid re-querying known gaps
        cache.slots[i] = some(ZERO_HASH)

      cache.slots[slot.int] = some(root)

      if slot == 0:
        return

      root = v[].parent_root
      lastSlot = slot
    do:
      return

proc update(cache: var DbCache, blck: ForkySignedBeaconBlock) =
  if blck.root notin cache.summaries:
    cache.summaries[blck.root] = blck.message.toBeaconBlockSummary()

  cache.updateSlots(blck.root, blck.message.slot)

proc isKnown(cache: DbCache, slot: Slot): bool =
  slot < cache.slots.lenu64 and cache.slots[slot.int].isSome()

proc doTrustedNodeSync*(
    cfg: RuntimeConfig, databaseDir: string, restUrl: string,
    stateId: string, backfill: bool, reindex: bool,
    genesisState: ref ForkedHashedBeaconState = nil) {.async.} =
  logScope:
    restUrl
    stateId

  notice "Starting trusted node sync",
    databaseDir, backfill, reindex

  let
    db = BeaconChainDB.new(databaseDir, inMemory = false)
  defer:
    db.close()

  var
    dbCache = DbCache(summaries: db.loadSummaries())

  let
    dbHead = db.getHeadBlock()
    headSlot = if dbHead.isSome():
      if dbHead.get() notin dbCache.summaries:
        # This can happen with pre-blocksummary database - it's better to start
        # over in this case
        error "Database missing head block summary - database too old or corrupt"
        quit 1

      let slot = dbCache.summaries[dbHead.get()].slot
      dbCache.updateSlots(dbHead.get(), slot)
      slot
    else:
      # When we don't have a head, we'll use the given checkpoint as head
      FAR_FUTURE_SLOT

  var client = RestClientRef.new(restUrl).valueOr:
    error "Cannot connect to server", error = error
    quit 1

  proc downloadBlock(slot: Slot):
      Future[Option[ref ForkedSignedBeaconBlock]] {.async.} =
    # Download block at given slot, retrying a few times,
    var lastError: ref CatchableError
    for i in 0..<3:
      try:
        return await client.getBlockV2(BlockIdent.init(slot), cfg)
      except RestResponseError as exc:
        lastError = exc
        notice "Server does not support block downloads / backfilling",
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
        stateFork = cfg.stateForkAtEpoch(GENESIS_EPOCH)

        tmp = (ref ForkedHashedBeaconState)(kind: stateFork)
      if not db.getState(stateFork, genesisStateRoot, tmp[], noRollback):
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
          await client.getStateV2(
            StateIdent.init(StateIdentType.Genesis), cfg)
        except CatchableError as exc:
          info "Unable to download genesis state",
            error = exc.msg, restUrl
          nil

      if isNil(tmp):
        notice "Server is missing genesis state, node will not be able to reindex history",
          restUrl
      tmp

  let (checkpointSlot, checkpointRoot) = if dbHead.isNone:
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
        await client.getStateV2(id, cfg)
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

      withState(genesisState[]):
        let blck = get_initial_beacon_block(forkyState)
        dbCache.update(blck.asSigned())

      ChainDAGRef.preInit(db, genesisState[])

      if getStateField(genesisState[], slot) != getStateField(state[], slot):
        ChainDAGRef.preInit(db, state[])
    else:
      ChainDAGRef.preInit(db, state[])

    let latest_bid = state[].latest_block_id()

    (latest_bid.slot, latest_bid.root)
  else:
    notice "Skipping checkpoint download, database already exists (remove db directory to get a fresh snapshot)",
      databaseDir, head = shortLog(dbHead.get())
    (headSlot, dbHead.get())

  # Coming this far, we've done what ChainDAGRef.preInit would normally do -
  # Let's do a sanity check and start backfilling blocks from the trusted node
  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    error "Database not initialized after checkpoint sync, report bug",
      err = v.error()
    quit 1

  dbCache.updateSlots(checkpointSlot)

  let
    missingSlots = block:
      var total = 0
      for slot in Slot(0)..<checkpointSlot:
        if not dbCache.isKnown(slot):
          total += 1
      total

  let canReindex = if missingSlots == 0:
    info "Database backfilled"
    true
  elif backfill:
    notice "Downloading historical blocks - you can interrupt this process at any time and it automatically be completed when you start the beacon node",
      checkpointSlot, missingSlots

    var # Same averaging as SyncManager
      syncCount = 0
      processed = 0'u64
      avgSyncSpeed = 0.0
      stamp = SyncMoment.now(0)

    # Download several blocks in parallel but process them serially
    var gets: array[16, Future[Option[ref ForkedSignedBeaconBlock]]]
    proc processBlock(
        fut: Future[Option[ref ForkedSignedBeaconBlock]], slot: Slot) {.async.} =
      processed += 1
      var blck = await fut
      if blck.isNone():
        dbCache.slots[slot.int] = some ZERO_HASH
        return

      let data = blck.get()
      withBlck(data[]):
        debug "Processing",
          blck = shortLog(blck.message),
          blockRoot = shortLog(blck.root)

        if blck.message.slot == checkpointSlot:
          if blck.root != checkpointRoot:
            error "Downloaded block does not match checkpoint history",
              blck = shortLog(blck),
              expectedRoot = shortLog(checkpointRoot)

            quit 1
        else:
          var childSlot = blck.message.slot + 1
          while true:
            if childSlot >= dbCache.slots.lenu64():
              error "Downloaded block does not match checkpoint history"
              quit 1

            if not dbCache.slots[childSlot.int].isSome():
              # Should never happen - we download slots backwards
              error "Downloaded block does not match checkpoint history"
              quit 1

            let knownRoot = dbCache.slots[childSlot.int].get()
            if knownRoot == ZERO_HASH:
              childSlot += 1
              continue

            dbCache.summaries.withValue(knownRoot, summary):
              if summary[].parent_root != blck.root:
                error "Downloaded block does not match checkpoint history",
                  blockRoot = shortLog(blck.root),
                  expectedRoot = shortLog(summary[].parent_root)
                quit 1

              break

            # This shouldn't happen - we should have downloaded the child and
            # updated knownBlocks before here
            error "Expected child block not found in checkpoint history"
            quit 1

        if blck.root notin dbCache.summaries:
          db.putBlock(blck.asTrusted())

        dbCache.update(blck)

        let newStamp = SyncMoment.now(processed)
        if newStamp.stamp - stamp.stamp > 12.seconds:
          syncCount += 1

          let
            remaining = blck.message.slot.int
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

    # Download blocks backwards from the checkpoint slot, skipping the ones we
    # already have in the database. We'll do a few downloads in parallel which
    # risks having some redundant downloads going on, but speeds things up
    try:
      for i in 0'u64..<(checkpointSlot.uint64 + gets.lenu64()):
        if not isNil(gets[int(i mod gets.lenu64)]):
          await processBlock(
            gets[int(i mod gets.lenu64)],
            checkpointSlot + gets.lenu64() - uint64(i))
          gets[int(i mod gets.lenu64)] = nil

        if i < checkpointSlot:
          let slot = checkpointSlot - i
          if dbCache.isKnown(slot):
            continue

          gets[int(i mod gets.lenu64)] = downloadBlock(slot)

        if i mod 1024 == 0:
          db.checkpoint() # Transfer stuff from wal periodically
      true
    except CatchableError as exc: # Block download failed
      notice "Backfilling incomplete - blocks will be downloaded when starting the node", msg = exc.msg
      false
  else:
    notice "Database initialized, historical blocks will be backfilled when starting the node",
      missingSlots

    false

  if reindex and canReindex:
    notice "Reindexing historical state lookup tables (you can interrupt this process at any time)"

    # Build a DAG
    let
      validatorMonitor = newClone(ValidatorMonitor.init(false, false))
      dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})

    dag.rebuildIndex()

  notice "Done, your beacon node is ready to serve you! Don't forget to check that you're on the canonical chain by comparing the checkpoint root with other online sources. See https://nimbus.guide/trusted-node-sync.html for more information.",
    checkpointRoot

when isMainModule:
  import
    std/[os],
    networking/network_metadata

  let backfill = os.paramCount() > 4 and os.paramStr(5) == "true"

  waitFor doTrustedNodeSync(
    getRuntimeConfig(some os.paramStr(1)), os.paramStr(2), os.paramStr(3),
    os.paramStr(4), backfill, false)

import
  os, stats, strformat, tables,
  chronicles, confutils, stew/byteutils, eth/db/kvstore_sqlite3,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/[beacon_chain_db, extras],
  ../beacon_chain/consensus_object_pools/[blockchain_dag, statedata_helpers],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers,
                        state_transition, presets, validator],
  ../beacon_chain/ssz, ../beacon_chain/ssz/sszdump,
  ../research/simutils, ./e2store

type Timers = enum
  tInit = "Initialize DB"
  tLoadBlock = "Load block from database"
  tLoadState = "Load state from database"
  tAdvanceSlot = "Advance slot, non-epoch"
  tAdvanceEpoch = "Advance slot, epoch"
  tApplyBlock = "Apply block, no slot processing"
  tDbLoad = "Database load"
  tDbStore = "Database store"

type
  DbCmd* = enum
    bench
    dumpState
    dumpBlock
    pruneDatabase
    rewindState
    exportEra
    validatorPerf

  # TODO:
  # This should probably allow specifying a run-time preset
  DbConf = object
    databaseDir* {.
        defaultValue: ""
        desc: "Directory where `nbc.sqlite` is stored"
        name: "db" }: InputDir

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    case cmd* {.
      command
      desc: ""
      .}: DbCmd

    of bench:
      benchSlot* {.
        defaultValue: 0
        name: "start-slot"
        desc: "Starting slot, negative = backwards from head".}: int64
      benchSlots* {.
        defaultValue: 50000
        name: "slots"
        desc: "Number of slots to run benchmark for, 0 = all the way to head".}: uint64
      storeBlocks* {.
        defaultValue: false
        desc: "Store each read block back into a separate database".}: bool
      storeStates* {.
        defaultValue: false
        desc: "Store a state each epoch into a separate database".}: bool
      printTimes* {.
        defaultValue: true
        desc: "Print csv of block processing time".}: bool
      resetCache* {.
        defaultValue: false
        desc: "Process each block with a fresh cache".}: bool

    of dumpState:
      stateRoot* {.
        argument
        desc: "State roots to save".}: seq[string]

    of dumpBlock:
      blockRootx* {.
        argument
        desc: "Block roots to save".}: seq[string]

    of pruneDatabase:
      dryRun* {.
        defaultValue: false
        desc: "Don't write to the database copy; only simulate actions; default false".}: bool
      keepOldStates* {.
        defaultValue: true
        desc: "Keep pre-finalization states; default true".}: bool
      verbose* {.
        defaultValue: false
        desc: "Enables verbose output; default false".}: bool

    of rewindState:
      blockRoot* {.
        argument
        desc: "Block root".}: string

      slot* {.
        argument
        desc: "Slot".}: uint64

    of exportEra:
      era* {.
        defaultValue: 0
        desc: "The era number to write".}: uint64
      eraCount* {.
        defaultValue: 1
        desc: "Number of eras to write".}: uint64

    of validatorPerf:
      perfSlot* {.
        defaultValue: -128 * SLOTS_PER_EPOCH.int64
        name: "start-slot"
        desc: "Starting slot, negative = backwards from head".}: int64
      perfSlots* {.
        defaultValue: 0
        name: "slots"
        desc: "Number of slots to run benchmark for, 0 = all the way to head".}: uint64

proc getBlockRange(dag: ChainDAGRef, startSlot: int64, count: uint64): seq[BlockRef] =
  # Range of block in reverse order
  let
    start =
      if startSlot >= 0: Slot(startSlot)
      elif uint64(-startSlot) >= dag.head.slot: Slot(0)
      else: Slot(dag.head.slot - uint64(-startSlot))
    ends =
      if count == 0: dag.head.slot + 1
      else: start + count
  var
     blockRefs: seq[BlockRef]
     cur = dag.head

  while cur != nil:
    if cur.slot < ends:
      if cur.slot < start or cur.slot == 0: # skip genesis
        break
      else:
        blockRefs.add cur
    cur = cur.parent
  blockRefs

proc cmdBench(conf: DbConf, runtimePreset: RuntimePreset) =
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.new(
      runtimePreset, conf.databaseDir.string,)
    dbBenchmark = BeaconChainDB.new(runtimePreset, "benchmark")
  defer:
    db.close()
    dbBenchmark.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let dag = withTimerRet(timers[tInit]):
    ChainDAGRef.init(runtimePreset, db, {})

  var
    blockRefs = dag.getBlockRange(conf.benchSlot, conf.benchSlots)
    blocks: seq[TrustedSignedBeaconBlock]

  echo &"Loaded {dag.blocks.len} blocks, head slot {dag.head.slot}, selected {blockRefs.len} blocks"
  doAssert blockRefs.len() > 0, "Must select at least one block"

  for b in 0..<blockRefs.len:
    withTimer(timers[tLoadBlock]):
      blocks.add db.getBlock(blockRefs[blockRefs.len - b - 1].root).get()

  let state = newClone(dag.headState)

  var
    cache = StateCache()
    rewards = RewardInfo()
    loadedState = new BeaconState

  withTimer(timers[tLoadState]):
    dag.updateStateData(
      state[], blockRefs[^1].atSlot(blockRefs[^1].slot - 1), false, cache)

  for b in blocks.mitems():
    while getStateField(state[], slot) < b.message.slot:
      let isEpoch = (getStateField(state[], slot) + 1).isEpoch()
      withTimer(timers[if isEpoch: tAdvanceEpoch else: tAdvanceSlot]):
        let ok = process_slots(
          state[].data, getStateField(state[], slot) + 1, cache, rewards, {})
        doAssert ok, "Slot processing can't fail with correct inputs"

    var start = Moment.now()
    withTimer(timers[tApplyBlock]):
      if conf.resetCache:
        cache = StateCache()
      if not state_transition(
          runtimePreset, state[].data, b, cache, rewards, {slotProcessed}, noRollback):
        dump("./", b)
        echo "State transition failed (!)"
        quit 1
    if conf.printTimes:
      echo b.message.slot, ",", toHex(b.root.data), ",", nanoseconds(Moment.now() - start)
    if conf.storeBlocks:
      withTimer(timers[tDbStore]):
        dbBenchmark.putBlock(b)

    if getStateField(state[], slot).isEpoch and conf.storeStates:
      if getStateField(state[], slot).epoch < 2:
        dbBenchmark.putState(state[].data.root, state[].data.data)
        dbBenchmark.checkpoint()
      else:
        withTimer(timers[tDbStore]):
          dbBenchmark.putState(state[].data.root, state[].data.data)
          dbBenchmark.checkpoint()

        withTimer(timers[tDbLoad]):
          doAssert dbBenchmark.getState(state[].data.root, loadedState[], noRollback)

        if getStateField(state[], slot).epoch mod 16 == 0:
          doAssert hash_tree_root(state[].data.data) == hash_tree_root(loadedState[])

  printTimers(false, timers)

proc cmdDumpState(conf: DbConf, preset: RuntimePreset) =
  let db = BeaconChainDB.new(preset, conf.databaseDir.string)
  defer: db.close()

  for stateRoot in conf.stateRoot:
    try:
      let root = Eth2Digest(data: hexToByteArray[32](stateRoot))
      var state = (ref HashedBeaconState)(root: root)
      if not db.getState(root, state.data, noRollback):
        echo "Couldn't load ", root
      else:
        dump("./", state[])
    except CatchableError as e:
      echo "Couldn't load ", stateRoot, ": ", e.msg

proc cmdDumpBlock(conf: DbConf, preset: RuntimePreset) =
  let db = BeaconChainDB.new(preset, conf.databaseDir.string)
  defer: db.close()

  for blockRoot in conf.blockRootx:
    try:
      let root = Eth2Digest(data: hexToByteArray[32](blockRoot))
      if (let blck = db.getBlock(root); blck.isSome):
        dump("./", blck.get())
      else:
        echo "Couldn't load ", root
    except CatchableError as e:
      echo "Couldn't load ", blockRoot, ": ", e.msg

proc copyPrunedDatabase(
    db: BeaconChainDB, copyDb: BeaconChainDB,
    dryRun, verbose, keepOldStates: bool) =
  ## Create a pruned copy of the beacon chain database

  let
    headBlock = db.getHeadBlock()
    tailBlock = db.getTailBlock()

  doAssert headBlock.isOk and tailBlock.isOk
  doAssert db.getBlock(headBlock.get).isOk
  doAssert db.getBlock(tailBlock.get).isOk

  var
    beaconState: ref BeaconState
    finalizedEpoch: Epoch  # default value of 0 is conservative/safe
    prevBlockSlot = db.getBlock(db.getHeadBlock().get).get.message.slot

  beaconState = new BeaconState
  let headEpoch = db.getBlock(headBlock.get).get.message.slot.epoch

  # Tail states are specially addressed; no stateroot intermediary
  if not db.getState(
      db.getBlock(tailBlock.get).get.message.state_root, beaconState[],
      noRollback):
    doAssert false, "could not load tail state"
  if not dry_run:
    copyDb.putState(beaconState[])

  for signedBlock in getAncestors(db, headBlock.get):
    if not dry_run:
      copyDb.putBlock(signedBlock)
      copyDb.checkpoint()
    if verbose:
      echo "copied block at slot ", signedBlock.message.slot

    for slot in countdown(prevBlockSlot, signedBlock.message.slot + 1):
      if slot mod SLOTS_PER_EPOCH != 0 or
          ((not keepOldStates) and slot.epoch < finalizedEpoch):
        continue

      # Could also only copy these states, head and finalized, plus tail state
      let stateRequired = slot.epoch in [finalizedEpoch, headEpoch]

      let sr = db.getStateRoot(signedBlock.root, slot)
      if sr.isErr:
        if stateRequired:
          echo "skipping state root required for slot ",
            slot, " with root ", signedBlock.root
        continue

      if not db.getState(sr.get, beaconState[], noRollback):
        # Don't copy dangling stateroot pointers
        if stateRequired:
          doAssert false, "state root and state required"
        continue

      finalizedEpoch = max(
        finalizedEpoch, beaconState.finalized_checkpoint.epoch)

      if not dry_run:
        copyDb.putStateRoot(signedBlock.root, slot, sr.get)
        copyDb.putState(beaconState[])
      if verbose:
        echo "copied state at slot ", slot, " from block at ", shortLog(signedBlock.message.slot)

    prevBlockSlot = signedBlock.message.slot

  if not dry_run:
    copyDb.putHeadBlock(headBlock.get)
    copyDb.putTailBlock(tailBlock.get)

proc cmdPrune(conf: DbConf, preset: RuntimePreset) =
  let
    db = BeaconChainDB.new(preset, conf.databaseDir.string)
    # TODO: add the destination as CLI paramter
    copyDb = BeaconChainDB.new(preset, "pruned_db")

  defer:
    db.close()
    copyDb.close()

  db.copyPrunedDatabase(copyDb, conf.dryRun, conf.verbose, conf.keepOldStates)

proc cmdRewindState(conf: DbConf, preset: RuntimePreset) =
  echo "Opening database..."
  let db = BeaconChainDB.new(preset, conf.databaseDir.string)
  defer: db.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let dag = init(ChainDAGRef, preset, db)

  let blckRef = dag.getRef(fromHex(Eth2Digest, conf.blockRoot))
  if blckRef == nil:
    echo "Block not found in database"
    return

  let tmpState = assignClone(dag.headState)
  dag.withState(tmpState[], blckRef.atSlot(Slot(conf.slot))):
    echo "Writing state..."
    dump("./", hashedState, blck)

proc atCanonicalSlot(blck: BlockRef, slot: Slot): BlockSlot =
  if slot == 0:
    blck.atSlot(slot)
  else:
    blck.atSlot(slot - 1).blck.atSlot(slot)

proc cmdExportEra(conf: DbConf, preset: RuntimePreset) =
  let db = BeaconChainDB.new(preset, conf.databaseDir.string)
  defer: db.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let
    dag = init(ChainDAGRef, preset, db)

  let tmpState = assignClone(dag.headState)

  for era in conf.era..<conf.era + conf.eraCount:
    let
      firstSlot = if era == 0: Slot(0) else: Slot((era - 1) * SLOTS_PER_HISTORICAL_ROOT)
      endSlot = Slot(era * SLOTS_PER_HISTORICAL_ROOT)
      slotCount = endSlot - firstSlot
      name = &"ethereum2-mainnet-{era.int:08x}-{1:08x}"
      canonical = dag.head.atCanonicalSlot(endSlot)

    if endSlot > dag.head.slot:
      echo "Written all complete eras"
      break

    var e2s = E2Store.open(".", name, firstSlot).get()
    defer: e2s.close()

    dag.withState(tmpState[], canonical):
      e2s.appendRecord(state).get()

    var
      ancestors: seq[BlockRef]
      cur = canonical.blck
    if era != 0:
      while cur != nil and cur.slot >= firstSlot:
        ancestors.add(cur)
        cur = cur.parent

      for i in 0..<ancestors.len():
        let
          ancestor = ancestors[ancestors.len - 1 - i]
        e2s.appendRecord(db.getBlock(ancestor.root).get()).get()

type
  # Validator performance metrics tool based on
  # https://github.com/paulhauner/lighthouse/blob/etl/lcli/src/etl/validator_performance.rs
  # Credits to Paul Hauner
  ValidatorPerformance = object
    attestation_hits: uint64
    attestation_misses: uint64
    head_attestation_hits: uint64
    head_attestation_misses: uint64
    target_attestation_hits: uint64
    target_attestation_misses: uint64
    first_slot_head_attester_when_first_slot_empty: uint64
    first_slot_head_attester_when_first_slot_not_empty: uint64
    delays: Table[uint64, uint64]

proc cmdValidatorPerf(conf: DbConf, runtimePreset: RuntimePreset) =
  echo "Opening database..."
  let
    db = BeaconChainDB.new(
      runtimePreset, conf.databaseDir.string,)
  defer:
    db.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "# Initializing block pool..."
  let dag = ChainDAGRef.init(runtimePreset, db, {})

  var
    blockRefs = dag.getBlockRange(conf.perfSlot, conf.perfSlots)
    perfs = newSeq[ValidatorPerformance](
      getStateField(dag.headState, validators).len())
    cache = StateCache()
    rewards = RewardInfo()
    blck: TrustedSignedBeaconBlock

  doAssert blockRefs.len() > 0, "Must select at least one block"

  echo "# Analyzing performance for epochs ",
    blockRefs[^1].slot.epoch, " - ", blockRefs[0].slot.epoch

  let state = newClone(dag.headState)
  dag.updateStateData(
    state[], blockRefs[^1].atSlot(blockRefs[^1].slot - 1), false, cache)

  proc processEpoch() =
    let
      prev_epoch_target_slot =
        state[].get_previous_epoch().compute_start_slot_at_epoch()
      penultimate_epoch_end_slot =
        if prev_epoch_target_slot == 0: Slot(0)
        else: prev_epoch_target_slot - 1
      first_slot_empty =
        state[].data.data.get_block_root_at_slot(prev_epoch_target_slot) ==
        state[].data.data.get_block_root_at_slot(penultimate_epoch_end_slot)

    let first_slot_attesters = block:
      let committee_count = state[].data.data.get_committee_count_per_slot(
        prev_epoch_target_slot, cache)
      var indices = HashSet[ValidatorIndex]()
      for committee_index in 0..<committee_count:
        for validator_index in state[].data.data.get_beacon_committee(
            prev_epoch_target_slot, committee_index.CommitteeIndex, cache):
          indices.incl(validator_index)
      indices

    for i, s in rewards.statuses.pairs():
      let perf = addr perfs[i]
      if RewardFlags.isActiveInPreviousEpoch in s.flags:
        if s.is_previous_epoch_attester.isSome():
          perf.attestation_hits += 1;

          if RewardFlags.isPreviousEpochHeadAttester in s.flags:
            perf.head_attestation_hits += 1
          else:
            perf.head_attestation_misses += 1

          if RewardFlags.isPreviousEpochTargetAttester in s.flags:
            perf.target_attestation_hits += 1
          else:
            perf.target_attestation_misses += 1

          if i.ValidatorIndex in first_slot_attesters:
            if first_slot_empty:
              perf.first_slot_head_attester_when_first_slot_empty += 1
            else:
              perf.first_slot_head_attester_when_first_slot_not_empty += 1

          if s.inclusion_info.isSome():
            perf.delays.mGetOrPut(s.inclusion_info.get().delay, 0'u64) += 1

        else:
          perf.attestation_misses += 1;


  for bi in 0..<blockRefs.len:
    blck = db.getBlock(blockRefs[blockRefs.len - bi - 1].root).get()
    while getStateField(state[], slot) < blck.message.slot:
      let ok = process_slots(
        state[].data, getStateField(state[], slot) + 1, cache, rewards, {})
      doAssert ok, "Slot processing can't fail with correct inputs"

      if getStateField(state[], slot).isEpoch():
        processEpoch()

    if not state_transition(
        runtimePreset, state[].data, blck, cache, rewards, {slotProcessed}, noRollback):
      echo "State transition failed (!)"
      quit 1

  # Capture rewards from the epoch leading up to the last block
  let nextEpochStart = (blck.message.slot.epoch + 1).compute_start_slot_at_epoch
  doAssert  process_slots(state[].data, nextEpochStart, cache, rewards, {})
  processEpoch()

  echo "validator_index,attestation_hits,attestation_misses,head_attestation_hits,head_attestation_misses,target_attestation_hits,target_attestation_misses,delay_avg,first_slot_head_attester_when_first_slot_empty,first_slot_head_attester_when_first_slot_not_empty"

  for (i, perf) in perfs.pairs:
    var
      count = 0'u64
      sum = 0'u64
    for delay, n in perf.delays:
        count += n
        sum += delay * n
    echo i,",",
      perf.attestation_hits,",",
      perf.attestation_misses,",",
      perf.head_attestation_hits,",",
      perf.head_attestation_misses,",",
      perf.target_attestation_hits,",",
      perf.target_attestation_misses,",",
      if count == 0: 0.0
      else: sum.float / count.float,",",
      perf.first_slot_head_attester_when_first_slot_empty,",",
      perf.first_slot_head_attester_when_first_slot_not_empty

when isMainModule:
  var
    conf = DbConf.load()
    runtimePreset = getRuntimePresetForNetwork(conf.eth2Network)

  case conf.cmd
  of bench:
    cmdBench(conf, runtimePreset)
  of dumpState:
    cmdDumpState(conf, runtimePreset)
  of dumpBlock:
    cmdDumpBlock(conf, runtimePreset)
  of pruneDatabase:
    cmdPrune(conf, runtimePreset)
  of rewindState:
    cmdRewindState(conf, runtimePreset)
  of exportEra:
    cmdExportEra(conf, runtimePreset)
  of validatorPerf:
    cmdValidatorPerf(conf, runtimePreset)

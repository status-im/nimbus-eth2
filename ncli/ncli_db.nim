import
  os, stats, strformat, tables, snappy,
  chronicles, confutils, stew/[byteutils, io2], eth/db/kvstore_sqlite3,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/[beacon_chain_db],
  ../beacon_chain/consensus_object_pools/[blockchain_dag],
  ../beacon_chain/spec/datatypes/[phase0, altair, bellatrix],
  ../beacon_chain/spec/[
    beaconstate, helpers, state_transition, state_transition_epoch, validator,
    ssz_codec],
  ../beacon_chain/sszdump,
  ../research/simutils,
  ./e2store, ./ncli_common

when defined(posix):
  import system/ansi_c

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
  DbCmd* {.pure.} = enum
    bench = "Run a replay benchmark for block and epoch processing"
    dumpState = "Extract a state from the database as-is - only works for states that have been explicitly stored"
    putState = "Store a given BeaconState in the database"
    dumpBlock = "Extract a (trusted) SignedBeaconBlock from the database"
    putBlock = "Store a given SignedBeaconBlock in the database, potentially updating some of the pointers"
    pruneDatabase
    rewindState = "Extract any state from the database based on a given block and slot, replaying if needed"
    exportEra = "Write an experimental era file"
    validatorPerf
    validatorDb = "Create or update attestation performance database"

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

    of DbCmd.bench:
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

    of DbCmd.dumpState:
      stateRoot* {.
        argument
        desc: "State roots to save".}: seq[string]

    of DbCmd.putState:
      stateFile {.
        argument
        name: "file"
        desc: "Files to import".}: seq[string]

    of DbCmd.dumpBlock:
      blockRootx* {.
        argument
        desc: "Block roots to save".}: seq[string]

    of DbCmd.putBlock:
      blckFile {.
        argument
        name: "file"
        desc: "Files to import".}: seq[string]
      setHead {.
        defaultValue: false
        name: "set-head"
        desc: "Update head to this block"}: bool
      setTail {.
        defaultValue: false
        name: "set-tail"
        desc: "Update tail to this block"}: bool
      setGenesis {.
        defaultValue: false
        name: "set-genesis"
        desc: "Update genesis to this block"}: bool

    of DbCmd.pruneDatabase:
      dryRun* {.
        defaultValue: false
        desc: "Don't write to the database copy; only simulate actions; default false".}: bool
      keepOldStates* {.
        defaultValue: true
        desc: "Keep pre-finalization states; default true".}: bool
      verbose* {.
        defaultValue: false
        desc: "Enables verbose output; default false".}: bool

    of DbCmd.rewindState:
      blockRoot* {.
        argument
        desc: "Block root".}: string

      slot* {.
        argument
        desc: "Slot".}: uint64

    of DbCmd.exportEra:
      era* {.
        defaultValue: 0
        desc: "The era number to write".}: uint64
      eraCount* {.
        defaultValue: 1
        desc: "Number of eras to write".}: uint64

    of DbCmd.validatorPerf:
      perfSlot* {.
        defaultValue: -128 * SLOTS_PER_EPOCH.int64
        name: "start-slot"
        desc: "Starting slot, negative = backwards from head".}: int64
      perfSlots* {.
        defaultValue: 0
        name: "slots"
        desc: "Number of slots to run benchmark for, 0 = all the way to head".}: uint64
    of DbCmd.validatorDb:
      outDir* {.
        name: "out-dir"
        abbr: "o"
        desc: "Output directory".}: string
      startEpoch* {.
        name: "start-epoch"
        abbr: "s"
        desc: "Epoch from which to start recording statistics." &
              "By default one past the last epoch in the output directory".}: Option[uint]
      endEpoch* {.
        name: "end-epoch"
        abbr: "e"
        desc: "The last for which to record statistics." &
              "By default the last epoch in the input database".}: Option[uint]

var shouldShutDown = false

proc putState(db: BeaconChainDB, state: ForkedHashedBeaconState) =
  withState(state):
    db.putStateRoot(state.latest_block_root(), state.data.slot, state.root)
    db.putState(state.root, state.data)

func getSlotRange(dag: ChainDAGRef, startSlot: int64, count: uint64): (Slot, Slot) =
  let
    start =
      if startSlot >= 0: Slot(startSlot)
      elif uint64(-startSlot) >= dag.head.slot: Slot(0)
      else: Slot(dag.head.slot - uint64(-startSlot))
    ends =
      if count == 0: dag.head.slot + 1
      else: start + count
  (start, ends)

proc cmdBench(conf: DbConf, cfg: RuntimeConfig) =
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.new(conf.databaseDir.string,)
    dbBenchmark = BeaconChainDB.new("benchmark")
  defer:
    db.close()
    dbBenchmark.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized: ", v.error()
    quit 1

  echo "Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = withTimerRet(timers[tInit]):
      ChainDAGRef.init(cfg, db, validatorMonitor, {})

  var
    (start, ends) = dag.getSlotRange(conf.benchSlot, conf.benchSlots)
    blockRefs = dag.getBlockRange(start, ends)
    blocks: (
      seq[phase0.TrustedSignedBeaconBlock],
      seq[altair.TrustedSignedBeaconBlock],
      seq[bellatrix.TrustedSignedBeaconBlock])

  echo &"Loaded {dag.blocks.len} blocks, head slot {dag.head.slot}, selected {blockRefs.len} blocks"
  doAssert blockRefs.len() > 0, "Must select at least one block"

  for b in 0 ..< blockRefs.len:
    let blck = blockRefs[blockRefs.len - b - 1]
    withTimer(timers[tLoadBlock]):
      case cfg.blockForkAtEpoch(blck.slot.epoch)
      of BeaconBlockFork.Phase0:
        blocks[0].add dag.db.getPhase0Block(blck.root).get()
      of BeaconBlockFork.Altair:
        blocks[1].add dag.db.getAltairBlock(blck.root).get()
      of BeaconBlockFork.Bellatrix:
        blocks[2].add dag.db.getMergeBlock(blck.root).get()

  let stateData = newClone(dag.headState)

  var
    cache = StateCache()
    info = ForkedEpochInfo()
    loadedState = (
      (ref phase0.HashedBeaconState)(),
      (ref altair.HashedBeaconState)(),
      (ref bellatrix.HashedBeaconState)())

  withTimer(timers[tLoadState]):
    doAssert dag.updateStateData(
      stateData[], blockRefs[^1].atSlot(blockRefs[^1].slot - 1), false, cache)

  template processBlocks(blocks: auto) =
    for b in blocks.mitems():
      if shouldShutDown: quit QuitSuccess
      while getStateField(stateData[].data, slot) < b.message.slot:
        let isEpoch = (getStateField(stateData[].data, slot) + 1).is_epoch()
        withTimer(timers[if isEpoch: tAdvanceEpoch else: tAdvanceSlot]):
          process_slots(
            dag.cfg, stateData[].data, getStateField(stateData[].data, slot) + 1, cache,
            info, {}).expect("Slot processing can't fail with correct inputs")

      var start = Moment.now()
      withTimer(timers[tApplyBlock]):
        if conf.resetCache:
          cache = StateCache()
        let res = state_transition_block(
            dag.cfg, stateData[].data, b, cache, {}, noRollback)
        if res.isErr():
          dump("./", b)
          echo "State transition failed (!) ", res.error()
          quit 1
      if conf.printTimes:
        echo b.message.slot, ",", toHex(b.root.data), ",", nanoseconds(Moment.now() - start)
      if conf.storeBlocks:
        withTimer(timers[tDbStore]):
          dbBenchmark.putBlock(b)

      withState(stateData[].data):
        if state.data.slot.is_epoch and conf.storeStates:
          if state.data.slot.epoch < 2:
            dbBenchmark.putState(state.root, state.data)
            dbBenchmark.checkpoint()
          else:
            withTimer(timers[tDbStore]):
              dbBenchmark.putState(state.root, state.data)
              dbBenchmark.checkpoint()

            withTimer(timers[tDbLoad]):
              case stateFork
              of BeaconStateFork.Phase0:
                doAssert dbBenchmark.getState(
                  state.root, loadedState[0][].data, noRollback)
              of BeaconStateFork.Altair:
                doAssert dbBenchmark.getState(
                  state.root, loadedState[1][].data, noRollback)
              of BeaconStateFork.Bellatrix:
                doAssert dbBenchmark.getState(
                  state.root, loadedState[2][].data, noRollback)

            if state.data.slot.epoch mod 16 == 0:
              let loadedRoot = case stateFork
                of BeaconStateFork.Phase0:    hash_tree_root(loadedState[0][].data)
                of BeaconStateFork.Altair:    hash_tree_root(loadedState[1][].data)
                of BeaconStateFork.Bellatrix: hash_tree_root(loadedState[2][].data)
              doAssert hash_tree_root(state.data) == loadedRoot

  processBlocks(blocks[0])
  processBlocks(blocks[1])
  processBlocks(blocks[2])

  printTimers(false, timers)

proc cmdDumpState(conf: DbConf) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  let
    phase0State    = (ref phase0.HashedBeaconState)()
    altairState    = (ref altair.HashedBeaconState)()
    bellatrixState = (ref bellatrix.HashedBeaconState)()

  for stateRoot in conf.stateRoot:
    if shouldShutDown: quit QuitSuccess
    template doit(state: untyped) =
      try:
        state.root = Eth2Digest.fromHex(stateRoot)

        if db.getState(state.root, state.data, noRollback):
          dump("./", state)
          continue
      except CatchableError as e:
        echo "Couldn't load ", state.root, ": ", e.msg

    doit(phase0State[])
    doit(altairState[])
    doit(bellatrixState[])

    echo "Couldn't load ", stateRoot

proc cmdPutState(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  for file in conf.stateFile:
    if shouldShutDown: quit QuitSuccess
    let state = newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(file).tryGet()))
    db.putState(state[])

proc cmdDumpBlock(conf: DbConf) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  for blockRoot in conf.blockRootx:
    if shouldShutDown: quit QuitSuccess
    try:
      let root = Eth2Digest.fromHex(blockRoot)
      if (let blck = db.getPhase0Block(root); blck.isSome):
        dump("./", blck.get())
      elif (let blck = db.getAltairBlock(root); blck.isSome):
        dump("./", blck.get())
      elif (let blck = db.getMergeBlock(root); blck.isSome):
        dump("./", blck.get())
      else:
        echo "Couldn't load ", blockRoot
    except CatchableError as e:
      echo "Couldn't load ", blockRoot, ": ", e.msg

proc cmdPutBlock(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  for file in conf.blckFile:
    if shouldShutDown: quit QuitSuccess

    let blck = readSszForkedSignedBeaconBlock(
        cfg, readAllBytes(file).tryGet())

    withBlck(blck.asTrusted()):
      db.putBlock(blck)
      if conf.setHead:
        db.putHeadBlock(blck.root)
      if conf.setTail:
        db.putTailBlock(blck.root)
      if conf.setGenesis:
        db.putGenesisBlock(blck.root)

proc copyPrunedDatabase(
    db: BeaconChainDB, copyDb: BeaconChainDB,
    dryRun, verbose, keepOldStates: bool) =
  ## Create a pruned copy of the beacon chain database

  let
    headBlock = db.getHeadBlock()
    tailBlock = db.getTailBlock()
    genesisBlock = db.getGenesisBlock()

  doAssert db.getPhase0Block(headBlock.get).isOk
  doAssert db.getPhase0Block(tailBlock.get).isOk
  doAssert db.getPhase0Block(genesisBlock.get).isOk

  var
    beaconState = (ref phase0.HashedBeaconState)()
    finalizedEpoch: Epoch  # default value of 0 is conservative/safe
    prevBlockSlot = db.getPhase0Block(db.getHeadBlock().get).get.message.slot

  let
    headEpoch = db.getPhase0Block(headBlock.get).get.message.slot.epoch
    tailStateRoot = db.getPhase0Block(tailBlock.get).get.message.state_root

  # Tail states are specially addressed; no stateroot intermediary
  if not db.getState(tailStateRoot, beaconState[].data, noRollback):
    doAssert false, "could not load tail state"
  beaconState[].root = tailStateRoot

  if not dry_run:
    copyDb.putStateRoot(
      beaconState[].latest_block_root(), beaconState[].data.slot,
      beaconState[].root)
    copyDb.putState(beaconState[].root, beaconState[].data)
    copyDb.putBlock(db.getPhase0Block(genesisBlock.get).get)

  for signedBlock in getAncestors(db, headBlock.get):
    if shouldShutDown: quit QuitSuccess
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

      if not db.getState(sr.get, beaconState[].data, noRollback):
        # Don't copy dangling stateroot pointers
        if stateRequired:
          doAssert false, "state root and state required"
        continue
      beaconState[].root = sr.get()

      finalizedEpoch = max(
        finalizedEpoch, beaconState[].data.finalized_checkpoint.epoch)

      if not dry_run:
        copyDb.putStateRoot(
          beaconState[].latest_block_root(), beaconState[].data.slot,
          beaconState[].root)
        copyDb.putState(beaconState[].root, beaconState[].data)
      if verbose:
        echo "copied state at slot ", slot, " from block at ", shortLog(signedBlock.message.slot)

    prevBlockSlot = signedBlock.message.slot

  if not dry_run:
    copyDb.putHeadBlock(headBlock.get)
    copyDb.putTailBlock(tailBlock.get)
    copyDb.putGenesisBlock(genesisBlock.get)

proc cmdPrune(conf: DbConf) =
  let
    db = BeaconChainDB.new(conf.databaseDir.string)
    # TODO: add the destination as CLI paramter
    copyDb = BeaconChainDB.new("pruned_db")

  defer:
    db.close()
    copyDb.close()

  db.copyPrunedDatabase(copyDb, conf.dryRun, conf.verbose, conf.keepOldStates)

proc cmdRewindState(conf: DbConf, cfg: RuntimeConfig) =
  echo "Opening database..."
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized: ", v.error()
    quit 1

  echo "Initializing block pool..."

  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

  let blckRef = dag.getBlockRef(fromHex(Eth2Digest, conf.blockRoot)).valueOr:
    echo "Block not found in database"
    return

  let tmpState = assignClone(dag.headState)
  dag.withUpdatedState(tmpState[], blckRef.atSlot(Slot(conf.slot))) do:
    echo "Writing state..."
    withState(stateData.data):
      dump("./", state)
  do: raiseAssert "withUpdatedState failed"

func atCanonicalSlot(blck: BlockRef, slot: Slot): BlockSlot =
  if slot == 0:
    blck.atSlot(slot)
  else:
    blck.atSlot(slot - 1).blck.atSlot(slot)

proc cmdExportEra(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized: ", v.error()
    quit 1

  type Timers = enum
    tState
    tBlocks

  echo "Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

  let tmpState = assignClone(dag.headState)
  var
    tmp: seq[byte]
    timers: array[Timers, RunningStat]

  for era in conf.era ..< conf.era + conf.eraCount:
    if shouldShutDown: quit QuitSuccess
    let
      firstSlot =
        if era == 0: none(Slot)
        else: some(Slot((era - 1) * SLOTS_PER_HISTORICAL_ROOT))
      endSlot = Slot(era * SLOTS_PER_HISTORICAL_ROOT)
      canonical = dag.head.atCanonicalSlot(endSlot)

    if endSlot > dag.head.slot:
      echo "Written all complete eras"
      break

    let name = withState(dag.headState.data): eraFileName(cfg, state.data, era)
    echo "Writing ", name

    let e2 = openFile(name, {OpenFlags.Write, OpenFlags.Create}).get()
    defer: discard closeFile(e2)

    var group = EraGroup.init(e2, firstSlot).get()
    if firstSlot.isSome():
      withTimer(timers[tBlocks]):
        var blocks: array[SLOTS_PER_HISTORICAL_ROOT.int, BlockId]
        for i in dag.getBlockRange(firstSlot.get(), 1, blocks)..<blocks.len:
          if dag.getBlockSSZ(blocks[i], tmp):
            group.update(e2, blocks[i].slot, tmp).get()

    withTimer(timers[tState]):
      dag.withUpdatedState(tmpState[], canonical) do:
        withState(stateData.data):
          group.finish(e2, state.data).get()
      do: raiseAssert "withUpdatedState failed"

  printTimers(true, timers)

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

proc cmdValidatorPerf(conf: DbConf, cfg: RuntimeConfig) =
  echo "Opening database..."
  let
    db = BeaconChainDB.new(conf.databaseDir.string,)
  defer:
    db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized: ", v.error()
    quit 1

  echo "# Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})

  var
    (start, ends) = dag.getSlotRange(conf.perfSlot, conf.perfSlots)
    blockRefs = dag.getBlockRange(start, ends)
    perfs = newSeq[ValidatorPerformance](
      getStateField(dag.headState.data, validators).len())
    cache = StateCache()
    info = ForkedEpochInfo()
    blck: phase0.TrustedSignedBeaconBlock

  doAssert blockRefs.len() > 0, "Must select at least one block"

  echo "# Analyzing performance for epochs ",
    blockRefs[^1].slot.epoch, " - ", blockRefs[0].slot.epoch

  let state = newClone(dag.headState)
  doAssert dag.updateStateData(
    state[], blockRefs[^1].atSlot(blockRefs[^1].slot - 1), false, cache)

  proc processEpoch() =
    let
      prev_epoch_target_slot =
        state[].data.get_previous_epoch().start_slot()
      penultimate_epoch_end_slot =
        if prev_epoch_target_slot == 0: Slot(0)
        else: prev_epoch_target_slot - 1
      first_slot_empty =
        state[].data.get_block_root_at_slot(prev_epoch_target_slot) ==
        state[].data.get_block_root_at_slot(penultimate_epoch_end_slot)

    let first_slot_attesters = block:
      let committees_per_slot = state[].data.get_committee_count_per_slot(
        prev_epoch_target_slot.epoch, cache)
      var indices = HashSet[ValidatorIndex]()
      for committee_index in get_committee_indices(committees_per_slot):
        for validator_index in state[].data.get_beacon_committee(
            prev_epoch_target_slot, committee_index, cache):
          indices.incl(validator_index)
      indices
    case info.kind
    of EpochInfoFork.Phase0:
      template info: untyped = info.phase0Data
      for i, s in info.validators.pairs():
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

            if s.is_previous_epoch_attester.isSome():
              perf.delays.mgetOrPut(
                s.is_previous_epoch_attester.get().delay, 0'u64) += 1

          else:
            perf.attestation_misses += 1;
    of EpochInfoFork.Altair:
      echo "TODO altair"

    if shouldShutDown: quit QuitSuccess

  for bi in 0 ..< blockRefs.len:
    blck = db.getPhase0Block(blockRefs[blockRefs.len - bi - 1].root).get()
    while getStateField(state[].data, slot) < blck.message.slot:
      let
        nextSlot = getStateField(state[].data, slot) + 1
        flags =
          if nextSlot == blck.message.slot: {skipLastStateRootCalculation}
          else: {}
      process_slots(
        dag.cfg, state[].data, nextSlot, cache, info, flags).expect(
          "Slot processing can't fail with correct inputs")

      if getStateField(state[].data, slot).is_epoch():
        processEpoch()

    let res = state_transition_block(
        dag.cfg, state[].data, blck, cache, {}, noRollback)
    if res.isErr:
      echo "State transition failed (!) ", res.error()
      quit 1

  # Capture rewards of empty slots as well
  while getStateField(state[].data, slot) < ends:
    process_slots(
      dag.cfg, state[].data, getStateField(state[].data, slot) + 1, cache,
      info, {}).expect("Slot processing can't fail with correct inputs")

    if getStateField(state[].data, slot).is_epoch():
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

proc createValidatorsRawTable(db: SqStoreRef) =
  db.exec("""
    CREATE TABLE IF NOT EXISTS validators_raw(
      validator_index INTEGER PRIMARY KEY,
      pubkey BLOB NOT NULL UNIQUE
    );
  """).expect("DB")

proc createValidatorsView(db: SqStoreRef) =
  db.exec("""
    CREATE VIEW IF NOT EXISTS validators AS
    SELECT
      validator_index,
      '0x' || lower(hex(pubkey)) as pubkey
    FROM validators_raw;
  """).expect("DB")

proc createInsertValidatorProc(db: SqStoreRef): auto =
  db.prepareStmt("""
    INSERT OR IGNORE INTO validators_raw(
      validator_index,
      pubkey)
    VALUES(?, ?);""",
    (int64, array[48, byte]), void).expect("DB")

proc collectBalances(balances: var seq[uint64], forkedState: ForkedHashedBeaconState) =
  withState(forkedState):
    balances = seq[uint64](state.data.balances.data)

proc calculateDelta(info: RewardsAndPenalties): int64 =
  info.source_outcome +
  info.target_outcome +
  info.head_outcome +
  info.inclusion_delay_outcome +
  info.sync_committee_outcome +
  info.proposer_outcome +
  info.slashing_outcome -
  info.inactivity_penalty.int64 +
  info.deposits.int64

proc printComponents(info: RewardsAndPenalties) =
  echo "Components:"
  echo "Source outcome: ", info.source_outcome
  echo "Target outcome: ", info.target_outcome
  echo "Head outcome: ", info.head_outcome
  echo "Inclusion delay outcome: ", info.inclusion_delay_outcome
  echo "Sync committee outcome: ", info.sync_committee_outcome
  echo "Proposer outcome: ", info.proposer_outcome
  echo "Slashing outcome: ", info.slashing_outcome
  echo "Inactivity penalty: ", info.inactivity_penalty
  echo "Deposits: ", info.deposits

proc checkBalance(validatorIndex: int64,
                  validator: RewardStatus | ParticipationInfo,
                  currentEpochBalance, previousEpochBalance: Gwei,
                  validatorInfo: RewardsAndPenalties) =
  let delta = validatorInfo.calculateDelta
  if currentEpochBalance.int64 == previousEpochBalance.int64 + delta:
    return
  echo "Validator: ", validatorIndex
  echo "Is eligible: ", is_eligible_validator(validator)
  echo "Current epoch balance: ", currentEpochBalance
  echo "Previous epoch balance: ", previousEpochBalance
  echo "State delta: ", currentEpochBalance - previousEpochBalance
  echo "Computed delta: ", delta
  printComponents(validatorInfo)
  raiseAssert("Validator's previous epoch balance plus computed validator's " &
              "delta is not equal to the validator's current epoch balance.")

proc getDbValidatorsCount(db: SqStoreRef): int64 =
  var res: int64
  discard db.exec("SELECT count(*) FROM validators", ()) do (r: int64):
    res = r
  return res

template inTransaction(db: SqStoreRef, dbName: string, body: untyped) =
  try:
    db.exec("BEGIN TRANSACTION;").expect(dbName)
    body
  finally:
    db.exec("END TRANSACTION;").expect(dbName)

proc insertValidators(db: SqStoreRef, state: ForkedHashedBeaconState,
                      startIndex, endIndex: int64) =
  var insertValidator {.global.}: SqliteStmt[
    (int64, array[48, byte]), void]
  once: insertValidator = db.createInsertValidatorProc
  withState(state):
    db.inTransaction("DB"):
      for i in startIndex ..< endIndex:
        insertValidator.exec(
          (i, state.data.validators[i].pubkey.toRaw)).expect("DB")

proc cmdValidatorDb(conf: DbConf, cfg: RuntimeConfig) =
  # Create a database with performance information for every epoch
  info "Opening database..."
  let db = BeaconChainDB.new(conf.databaseDir.string, false, true)
  defer: db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})

  let outDb = SqStoreRef.init(conf.outDir, "validatorDb").expect("DB")
  defer: outDb.close()

  outDb.createValidatorsRawTable
  outDb.createValidatorsView

  let
    startEpoch =
      if conf.startEpoch.isSome:
        Epoch(conf.startEpoch.get)
      else:
        getStartEpoch(conf.outDir)
    endEpoch =
      if conf.endEpoch.isSome:
        Epoch(conf.endEpoch.get)
      else:
        dag.finalizedHead.slot.epoch # Avoid dealing with changes

  if startEpoch > endEpoch:
    fatal "Start epoch cannot be bigger than end epoch.",
          startEpoch = startEpoch, endEpoch = endEpoch
    quit QuitFailure

  info "Analyzing performance for epochs.",
       startEpoch = startEpoch, endEpoch = endEpoch

  let
    startSlot = startEpoch.start_slot
    endSlot = endEpoch.start_slot + SLOTS_PER_EPOCH
    blockRefs = dag.getBlockRange(startSlot, endSlot)

  let tmpState = newClone(dag.headState)
  var cache = StateCache()
  let slot = if startSlot > 0: startSlot - 1 else: 0.Slot
  if blockRefs.len > 0:
    discard dag.updateStateData(tmpState[], blockRefs[^1].atSlot(slot), false, cache)
  else:
    discard dag.updateStateData(tmpState[], dag.head.atSlot(slot), false, cache)

  let savedValidatorsCount = outDb.getDbValidatorsCount
  var validatorsCount = getStateField(tmpState[].data, validators).len
  outDb.insertValidators(tmpState[].data, savedValidatorsCount, validatorsCount)

  var previousEpochBalances: seq[uint64]
  collectBalances(previousEpochBalances, tmpState[].data)

  var forkedInfo = ForkedEpochInfo()
  var rewardsAndPenalties: seq[RewardsAndPenalties]
  rewardsAndPenalties.setLen(validatorsCount)

  var auxiliaryState: AuxiliaryState
  auxiliaryState.copyParticipationFlags(tmpState[].data)

  proc processEpoch() =
    let epoch = getStateField(tmpState[].data, slot).epoch
    info "Processing epoch ...", epoch = epoch

    var csvLines = newStringOfCap(1000000)

    withState(tmpState[].data):
      withEpochInfo(forkedInfo):
        doAssert state.data.balances.len == info.validators.len
        doAssert state.data.balances.len == previousEpochBalances.len
        doAssert state.data.balances.len == rewardsAndPenalties.len

        for index, validator in info.validators.pairs:
          template rp: untyped = rewardsAndPenalties[index]

          checkBalance(index, validator, state.data.balances[index],
                       previousEpochBalances[index], rp)

          when infoFork == EpochInfoFork.Phase0:
            rp.inclusion_delay = block:
              let notSlashed = (RewardFlags.isSlashed notin validator.flags)
              if notSlashed and validator.is_previous_epoch_attester.isSome():
                some(validator.is_previous_epoch_attester.get().delay.uint64)
              else:
                none(uint64)
          csvLines.add rp.serializeToCsv

    let fileName = getFilePathForEpoch(epoch, conf.outDir)
    var res = io2.removeFile(fileName)
    doAssert res.isOk
    res = io2.writeFile(fileName, snappy.encode(csvLines.toBytes))
    doAssert res.isOk

    if shouldShutDown: quit QuitSuccess
    collectBalances(previousEpochBalances, tmpState[].data)

  proc processSlots(ends: Slot, endsFlags: UpdateFlags) =
    var currentSlot = getStateField(tmpState[].data, slot)
    while currentSlot < ends:
      let nextSlot = currentSlot + 1
      let flags = if nextSlot == ends: endsFlags else: {}

      if nextSlot.isEpoch:
        withState(tmpState[].data):
          rewardsAndPenalties.collectEpochRewardsAndPenalties(
            state.data, cache, cfg)

      let res = process_slots(cfg, tmpState[].data, nextSlot, cache, forkedInfo, flags)
      doAssert res.isOk, "Slot processing can't fail with correct inputs"

      currentSlot = nextSlot

      if currentSlot.isEpoch:
        processEpoch()
        rewardsAndPenalties.setLen(0)
        rewardsAndPenalties.setLen(validatorsCount)
        auxiliaryState.copyParticipationFlags(tmpState[].data)
        clear cache

  for bi in 0 ..< blockRefs.len:
    let forkedBlock = dag.getForkedBlock(blockRefs[blockRefs.len - bi - 1])
    withBlck(forkedBlock):
      processSlots(blck.message.slot, {skipLastStateRootCalculation})

      rewardsAndPenalties.collectBlockRewardsAndPenalties(
        tmpState[].data, forkedBlock, auxiliaryState, cache, cfg)

      let res = state_transition_block(
        cfg, tmpState[].data, blck, cache, {}, noRollback)
      if res.isErr:
        fatal "State transition failed (!)"
        quit QuitFailure

      let newValidatorsCount = getStateField(tmpState[].data, validators).len
      if newValidatorsCount > validatorsCount:
        # Resize the structures in case a new validator has appeared after
        # the state_transition_block procedure call ...
        rewardsAndPenalties.setLen(newValidatorsCount)
        previousEpochBalances.setLen(newValidatorsCount)
        # ... and add the new validators to the database.
        outDb.insertValidators(
          tmpState[].data, validatorsCount, newValidatorsCount)
        validatorsCount = newValidatorsCount

  # Capture rewards of empty slots as well, including the epoch that got
  # finalized
  processSlots(endSlot, {})

proc controlCHook {.noconv.} =
  notice "Shutting down after having received SIGINT."
  shouldShutDown = true

proc exitOnSigterm(signal: cint) {.noconv.} =
  notice "Shutting down after having received SIGTERM."
  shouldShutDown = true

when isMainModule:
  setControlCHook(controlCHook)
  when defined(posix):
    c_signal(SIGTERM, exitOnSigterm)

  var
    conf = DbConf.load()
    cfg = getRuntimeConfig(conf.eth2Network)

  case conf.cmd
  of DbCmd.bench:
    cmdBench(conf, cfg)
  of DbCmd.dumpState:
    cmdDumpState(conf)
  of DbCmd.putState:
    cmdPutState(conf, cfg)
  of DbCmd.dumpBlock:
    cmdDumpBlock(conf)
  of DbCmd.putBlock:
    cmdPutBlock(conf, cfg)
  of DbCmd.pruneDatabase:
    cmdPrune(conf)
  of DbCmd.rewindState:
    cmdRewindState(conf, cfg)
  of DbCmd.exportEra:
    cmdExportEra(conf, cfg)
  of DbCmd.validatorPerf:
    cmdValidatorPerf(conf, cfg)
  of DbCmd.validatorDb:
    cmdValidatorDb(conf, cfg)

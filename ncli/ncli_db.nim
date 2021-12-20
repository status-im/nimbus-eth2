import
  os, stats, strformat, tables,
  chronicles, confutils, stew/[byteutils, io2], eth/db/kvstore_sqlite3,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/[beacon_chain_db],
  ../beacon_chain/consensus_object_pools/[blockchain_dag],
  ../beacon_chain/spec/datatypes/[phase0, altair, merge],
  ../beacon_chain/spec/[
    beaconstate, helpers, state_transition, state_transition_epoch, validator],
  ../beacon_chain/sszdump,
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
        defaultValue: ""
        name: "out-db"
        desc: "Output database".}: string
      perfect* {.
        defaultValue: false
        name: "perfect"
        desc: "Include perfect records (full rewards)".}: bool

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

func getBlockRange(dag: ChainDAGRef, start, ends: Slot): seq[BlockRef] =
  # Range of block in reverse order
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

proc cmdBench(conf: DbConf, cfg: RuntimeConfig) =
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.new(conf.databaseDir.string,)
    dbBenchmark = BeaconChainDB.new("benchmark")
  defer:
    db.close()
    dbBenchmark.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
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
      seq[merge.TrustedSignedBeaconBlock])

  echo &"Loaded {dag.blocks.len} blocks, head slot {dag.head.slot}, selected {blockRefs.len} blocks"
  doAssert blockRefs.len() > 0, "Must select at least one block"

  for b in 0..<blockRefs.len:
    let blck = blockRefs[blockRefs.len - b - 1]
    withTimer(timers[tLoadBlock]):
      case cfg.blockForkAtEpoch(blck.slot.epoch)
      of BeaconBlockFork.Phase0:
        blocks[0].add dag.db.getPhase0Block(blck.root).get()
      of BeaconBlockFork.Altair:
        blocks[1].add dag.db.getAltairBlock(blck.root).get()
      of BeaconBlockFork.Merge:
        blocks[2].add dag.db.getMergeBlock(blck.root).get()

  let stateData = newClone(dag.headState)

  var
    cache = StateCache()
    info = ForkedEpochInfo()
    loadedState = (
      (ref phase0.HashedBeaconState)(),
      (ref altair.HashedBeaconState)(),
      (ref merge.HashedBeaconState)())

  withTimer(timers[tLoadState]):
    dag.updateStateData(
      stateData[], blockRefs[^1].atSlot(blockRefs[^1].slot - 1), false, cache)

  template processBlocks(blocks: auto) =
    for b in blocks.mitems():
      while getStateField(stateData[].data, slot) < b.message.slot:
        let isEpoch = (getStateField(stateData[].data, slot) + 1).isEpoch()
        withTimer(timers[if isEpoch: tAdvanceEpoch else: tAdvanceSlot]):
          let ok = process_slots(
            dag.cfg, stateData[].data, getStateField(stateData[].data, slot) + 1, cache,
            info, {})
          doAssert ok, "Slot processing can't fail with correct inputs"

      var start = Moment.now()
      withTimer(timers[tApplyBlock]):
        if conf.resetCache:
          cache = StateCache()
        if not state_transition_block(
            dag.cfg, stateData[].data, b, cache, {}, noRollback):
          dump("./", b)
          echo "State transition failed (!)"
          quit 1
      if conf.printTimes:
        echo b.message.slot, ",", toHex(b.root.data), ",", nanoseconds(Moment.now() - start)
      if conf.storeBlocks:
        withTimer(timers[tDbStore]):
          dbBenchmark.putBlock(b)

      withState(stateData[].data):
        if state.data.slot.isEpoch and conf.storeStates:
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
              of BeaconStateFork.Merge:
                doAssert dbBenchmark.getState(
                  state.root, loadedState[2][].data, noRollback)

            if state.data.slot.epoch mod 16 == 0:
              let loadedRoot = case stateFork
                of BeaconStateFork.Phase0: hash_tree_root(loadedState[0][].data)
                of BeaconStateFork.Altair: hash_tree_root(loadedState[1][].data)
                of BeaconStateFork.Merge: hash_tree_root(loadedState[2][].data)
              doAssert hash_tree_root(state.data) == loadedRoot

  processBlocks(blocks[0])
  processBlocks(blocks[1])
  processBlocks(blocks[2])

  printTimers(false, timers)

proc cmdDumpState(conf: DbConf) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  let
    phase0State = (ref phase0.HashedBeaconState)()
    altairState = (ref altair.HashedBeaconState)()
    mergeState = (ref merge.HashedBeaconState)()

  for stateRoot in conf.stateRoot:
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
    doit(mergeState[])

    echo "Couldn't load ", stateRoot

proc cmdPutState(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  for file in conf.stateFile:
    let state = newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(file).tryGet()))
    db.putState(state[])

proc cmdDumpBlock(conf: DbConf) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  for blockRoot in conf.blockRootx:
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
    let blck = readSszForkedTrustedSignedBeaconBlock(
        cfg, readAllBytes(file).tryGet())

    withBlck(blck):
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

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."

  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

  let blckRef = dag.getRef(fromHex(Eth2Digest, conf.blockRoot))
  if blckRef == nil:
    echo "Block not found in database"
    return

  let tmpState = assignClone(dag.headState)
  dag.withState(tmpState[], blckRef.atSlot(Slot(conf.slot))):
    echo "Writing state..."
    withState(stateData.data):
      dump("./", state)

func atCanonicalSlot(blck: BlockRef, slot: Slot): BlockSlot =
  if slot == 0:
    blck.atSlot(slot)
  else:
    blck.atSlot(slot - 1).blck.atSlot(slot)

proc cmdExportEra(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})

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
      e2s.appendRecord(stateData.data.phase0Data.data).get()

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
        e2s.appendRecord(db.getPhase0Block(ancestor.root).get()).get()

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

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
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
  dag.updateStateData(
    state[], blockRefs[^1].atSlot(blockRefs[^1].slot - 1), false, cache)

  proc processEpoch() =
    let
      prev_epoch_target_slot =
        state[].data.get_previous_epoch().compute_start_slot_at_epoch()
      penultimate_epoch_end_slot =
        if prev_epoch_target_slot == 0: Slot(0)
        else: prev_epoch_target_slot - 1
      first_slot_empty =
        state[].data.get_block_root_at_slot(prev_epoch_target_slot) ==
        state[].data.get_block_root_at_slot(penultimate_epoch_end_slot)

    let first_slot_attesters = block:
      let committee_count = state[].data.get_committee_count_per_slot(
        prev_epoch_target_slot.epoch, cache)
      var indices = HashSet[ValidatorIndex]()
      for committee_index in 0..<committee_count:
        for validator_index in state[].data.get_beacon_committee(
            prev_epoch_target_slot, committee_index.CommitteeIndex, cache):
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

  for bi in 0..<blockRefs.len:
    blck = db.getPhase0Block(blockRefs[blockRefs.len - bi - 1].root).get()
    while getStateField(state[].data, slot) < blck.message.slot:
      let
        nextSlot = getStateField(state[].data, slot) + 1
        flags =
          if nextSlot == blck.message.slot: {skipLastStateRootCalculation}
          else: {}
      let ok = process_slots(
        dag.cfg, state[].data, nextSlot, cache, info, flags)
      doAssert ok, "Slot processing can't fail with correct inputs"

      if getStateField(state[].data, slot).isEpoch():
        processEpoch()

    if not state_transition_block(
        dag.cfg, state[].data, blck, cache, {}, noRollback):
      echo "State transition failed (!)"
      quit 1

  # Capture rewards of empty slots as well
  while getStateField(state[].data, slot) < ends:
    let ok = process_slots(
      dag.cfg, state[].data, getStateField(state[].data, slot) + 1, cache,
      info, {})
    doAssert ok, "Slot processing can't fail with correct inputs"

    if getStateField(state[].data, slot).isEpoch():
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

proc cmdValidatorDb(conf: DbConf, cfg: RuntimeConfig) =
  # Create a database with performance information for every epoch
  echo "Opening database..."
  let
    db = BeaconChainDB.new(conf.databaseDir.string,)
  defer:
    db.close()

  if not ChainDAGRef.isInitialized(db):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})

  let outDb = SqStoreRef.init(conf.outDir, "validatorDb").expect("DB")
  defer: outDb.close()

  outDb.exec("""
    CREATE TABLE IF NOT EXISTS validators_raw(
      validator_index INTEGER PRIMARY KEY,
      pubkey BLOB NOT NULL,
      withdrawal_credentials BLOB NOT NULL
    );
  """).expect("DB")

  # For convenient viewing
  outDb.exec("""
    CREATE VIEW IF NOT EXISTS validators AS
    SELECT
      validator_index,
      '0x' || lower(hex(pubkey)) as pubkey,
      '0x' || lower(hex(withdrawal_credentials)) as with_cred
    FROM validators_raw;
  """).expect("DB")

  outDb.exec("""
    CREATE TABLE IF NOT EXISTS epoch_info(
      epoch INTEGER PRIMARY KEY,
      current_epoch_raw INTEGER NOT NULL,
      previous_epoch_raw INTEGER NOT NULL,
      current_epoch_attesters_raw INTEGER NOT NULL,
      current_epoch_target_attesters_raw INTEGER NOT NULL,
      previous_epoch_attesters_raw INTEGER NOT NULL,
      previous_epoch_target_attesters_raw INTEGER NOT NULL,
      previous_epoch_head_attesters_raw INTEGER NOT NULL
    );
  """).expect("DB")
  outDb.exec("""
    CREATE TABLE IF NOT EXISTS validator_epoch_info(
      validator_index INTEGER,
      epoch INTEGER,
      rewards INTEGER NOT NULL,
      penalties INTEGER NOT NULL,
      source_attester INTEGER NOT NULL,
      target_attester INTEGER NOT NULL,
      head_attester INTEGER NOT NULL,
      inclusion_delay INTEGER NULL,
      PRIMARY KEY(validator_index, epoch)
    );
  """).expect("DB")

  let
    insertValidator = outDb.prepareStmt("""
      INSERT INTO validators_raw(
        validator_index,
        pubkey,
        withdrawal_credentials)
      VALUES(?, ?, ?);""",
      (int64, array[48, byte], array[32, byte]), void).expect("DB")
    insertEpochInfo = outDb.prepareStmt("""
      INSERT INTO epoch_info(
        epoch,
        current_epoch_raw,
        previous_epoch_raw,
        current_epoch_attesters_raw,
        current_epoch_target_attesters_raw,
        previous_epoch_attesters_raw,
        previous_epoch_target_attesters_raw,
        previous_epoch_head_attesters_raw)
      VALUES(?, ?, ?, ?, ?, ?, ?, ?);""",
      (int64, int64, int64, int64, int64, int64, int64, int64), void).expect("DB")
    insertValidatorInfo = outDb.prepareStmt("""
        INSERT INTO validator_epoch_info(
          validator_index,
          epoch,
          rewards,
          penalties,
          source_attester,
          target_attester,
          head_attester,
          inclusion_delay)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?);""",
      (int64, int64, int64, int64, int64, int64, int64, Option[int64]), void).expect("DB")

  var vals: int64
  discard outDb.exec("SELECT count(*) FROM validators", ()) do (res: int64):
    vals = res

  outDb.exec("BEGIN TRANSACTION;").expect("DB")

  for i in vals..<getStateField(dag.headState.data, validators).len():
    insertValidator.exec((
      i,
      getStateField(dag.headState.data, validators).data[i].pubkey.toRaw(),
      getStateField(dag.headState.data, validators).data[i].withdrawal_credentials.data)).expect("DB")

  outDb.exec("COMMIT;").expect("DB")

  var minEpoch: Epoch
  discard outDb.exec("SELECT MAX(epoch) FROM epoch_info", ()) do (res: int64):
    minEpoch = (res + 1).Epoch

  var
    cache = StateCache()
    info = ForkedEpochInfo()
    blck: phase0.TrustedSignedBeaconBlock

  let
    start = minEpoch.compute_start_slot_at_epoch()
    ends = dag.finalizedHead.slot # Avoid dealing with changes

  if start > ends:
    echo "No (new) data found, database at ", minEpoch, ", finalized to ", ends.epoch
    quit 1

  let blockRefs = dag.getBlockRange(start, ends)

  echo "Analyzing performance for epochs ",
    start.epoch, " - ", ends.epoch

  let state = newClone(dag.headState)
  dag.updateStateData(
    state[], blockRefs[^1].atSlot(if start > 0: start - 1 else: 0.Slot),
    false, cache)

  var inTxn = false
  proc processEpoch() =
    echo getStateField(state[].data, slot).epoch
    if not inTxn:
      outDb.exec("BEGIN TRANSACTION;").expect("DB")
      inTxn = true
    case info.kind
    of EpochInfoFork.Phase0:
      template info: untyped = info.phase0Data
      insertEpochInfo.exec(
        (getStateField(state[].data, slot).epoch.int64,
        info.balances.current_epoch_raw.int64,
        info.balances.previous_epoch_raw.int64,
        info.balances.current_epoch_attesters_raw.int64,
        info.balances.current_epoch_target_attesters_raw.int64,
        info.balances.previous_epoch_attesters_raw.int64,
        info.balances.previous_epoch_target_attesters_raw.int64,
        info.balances.previous_epoch_head_attesters_raw.int64)
        ).expect("DB")

      for index, status in info.validators.pairs():
        if not is_eligible_validator(status):
          continue
        let
          notSlashed = (RewardFlags.isSlashed notin status.flags)
          source_attester =
            notSlashed and status.is_previous_epoch_attester.isSome()
          target_attester =
            notSlashed and RewardFlags.isPreviousEpochTargetAttester in status.flags
          head_attester =
            notSlashed and RewardFlags.isPreviousEpochHeadAttester in status.flags
          delay =
            if notSlashed and status.is_previous_epoch_attester.isSome():
              some(int64(status.is_previous_epoch_attester.get().delay))
            else:
              none(int64)

        if conf.perfect or not
            (source_attester and target_attester and head_attester and
              delay.isSome() and delay.get() == 1):
          insertValidatorInfo.exec(
            (index.int64,
            getStateField(state[].data, slot).epoch.int64,
            status.delta.rewards.int64,
            status.delta.penalties.int64,
            int64(source_attester), # Source delta
            int64(target_attester), # Target delta
            int64(head_attester), # Head delta
            delay)).expect("DB")
    of EpochInfoFork.Altair:
      echo "TODO altair support"

    if getStateField(state[].data, slot).epoch.int64 mod 16 == 0:
      inTxn = false
      outDb.exec("COMMIT;").expect("DB")

  for bi in 0..<blockRefs.len:
    blck = db.getPhase0Block(blockRefs[blockRefs.len - bi - 1].root).get()
    while getStateField(state[].data, slot) < blck.message.slot:
      let
        nextSlot = getStateField(state[].data, slot) + 1
        flags =
          if nextSlot == blck.message.slot: {skipLastStateRootCalculation}
          else: {}

      let ok = process_slots(cfg, state[].data, nextSlot, cache, info, flags)
      doAssert ok, "Slot processing can't fail with correct inputs"

      if getStateField(state[].data, slot).isEpoch():
        processEpoch()

    if not state_transition_block(
        cfg, state[].data, blck, cache, {}, noRollback):
      echo "State transition failed (!)"
      quit 1

  # Capture rewards of empty slots as well, including the epoch that got
  # finalized
  while getStateField(state[].data, slot) <= ends:
    let ok = process_slots(
      cfg, state[].data, getStateField(state[].data, slot) + 1, cache,
      info, {})
    doAssert ok, "Slot processing can't fail with correct inputs"

    if getStateField(state[].data, slot).isEpoch():
      processEpoch()

  if inTxn:
    inTxn = false
    outDb.exec("COMMIT;").expect("DB")

when isMainModule:
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

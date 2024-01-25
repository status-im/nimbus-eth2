# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[os, stats, strformat, tables],
  snappy,
  chronicles, confutils, stew/[byteutils, io2], eth/db/kvstore_sqlite3,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/[beacon_chain_db, era_db],
  ../beacon_chain/consensus_object_pools/[blockchain_dag],
  ../beacon_chain/spec/[
    beaconstate, state_transition, state_transition_epoch, validator,
    ssz_codec],
  ../beacon_chain/sszdump,
  ../research/simutils,
  ./e2store, ./ncli_common, ./validator_db_aggregator

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
    rewindState = "Extract any state from the database based on a given block and slot, replaying if needed"
    verifyEra = "Verify a single era file"
    exportEra = "Export historical data to era store in current directory"
    importEra = "Import era files to the database"
    validatorPerf
    validatorDb = "Create or update attestation performance database"

  DbConf = object
    databaseDir* {.
      defaultValue: "db"
      desc: "Directory where `nbc.sqlite` is stored"
      name: "db".}: InputDir

    eraDir* {.
      defaultValue: "era"
      desc: "Directory where era files are read from"
      name: "era-dir".}: string

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network".}: Option[string]

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
        name: "store-states"
        desc: "Store a state each epoch into a separate database".}: bool
      printTimes* {.
        defaultValue: true
        name: "print-times"
        desc: "Print csv of block processing time".}: bool
      resetCache* {.
        defaultValue: false
        name: "reset-cache"
        desc: "Process each block with a fresh cache".}: bool

    of DbCmd.dumpState:
      stateRoot* {.
        argument
        name: "state-root"
        desc: "State root(s) to save".}: seq[string]

    of DbCmd.putState:
      stateFile {.
        argument
        name: "file"
        desc: "Files to import".}: seq[string]

    of DbCmd.dumpBlock:
      blockRootx* {.
        argument
        name: "block-root"
        desc: "Block root(s) to save".}: seq[string]

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

    of DbCmd.rewindState:
      blockRoot* {.
        argument
        name: "block-root"
        desc: "Block root".}: string

      slot* {.
        argument
        desc: "Slot".}: uint64

    of DbCmd.verifyEra:
      eraFile* {.
        desc: "Era file name".}: string

    of DbCmd.exportEra:
      era* {.
        defaultValue: 0
        desc: "The era number to write".}: uint64
      eraCount* {.
        defaultValue: 0
        name: "count"
        desc: "Number of eras to write (0=all)".}: uint64

    of DbCmd.importEra:
      eraFiles* {.
        argument
        name: "file"
        desc: "The name of the era file(s) to import".}: seq[string]

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
      resolution {.
        defaultValue: 225,
        name: "resolution"
        abbr: "r"
        desc: "How many epochs to be aggregated in a single compacted file" .}: uint
      writeAggregatedFiles {.
        name: "aggregated"
        defaultValue: true
        abbr: "a"
        desc: "Whether to write aggregated files for a range of epochs with a given resolution" .}: bool
      writeUnaggregatedFiles {.
        name: "unaggregated"
        defaultValue: true
        abbr: "u"
        desc: "Whether to write unaggregated file for each epoch" .}: bool

var shouldShutDown = false

func getSlotRange(dag: ChainDAGRef, startSlot: int64, count: uint64): (Slot, Slot) =
  let
    start =
      if startSlot >= 0: Slot(startSlot)
      elif uint64(-startSlot) >= dag.head.slot: Slot(0)
      else: dag.head.slot - uint64(-startSlot)
    ends =
      if count == 0: dag.head.slot + 1
      else: start + count
  (start, ends)

proc cmdBench(conf: DbConf, cfg: RuntimeConfig) =
  var timers: array[Timers, RunningStat]

  echo "Opening database..."
  let
    db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
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
      ChainDAGRef.init(cfg, db, validatorMonitor, {}, conf.eraDir)

  var
    (start, ends) = dag.getSlotRange(conf.benchSlot, conf.benchSlots)
    blockRefs = dag.getBlockRange(max(start, Slot 1), ends)
    blocks: (
      seq[phase0.TrustedSignedBeaconBlock],
      seq[altair.TrustedSignedBeaconBlock],
      seq[bellatrix.TrustedSignedBeaconBlock],
      seq[capella.TrustedSignedBeaconBlock],
      seq[deneb.TrustedSignedBeaconBlock])

  echo &"Loaded head slot {dag.head.slot}, selected {blockRefs.len} blocks"
  doAssert blockRefs.len() > 0, "Must select at least one block"

  for b in 0 ..< blockRefs.len:
    let blck = blockRefs[blockRefs.len - b - 1]

    withTimer(timers[tLoadBlock]):
      case cfg.consensusForkAtEpoch(blck.slot.epoch)
      of ConsensusFork.Phase0:
        blocks[0].add dag.db.getBlock(
          blck.root, phase0.TrustedSignedBeaconBlock).get()
      of ConsensusFork.Altair:
        blocks[1].add dag.db.getBlock(
          blck.root, altair.TrustedSignedBeaconBlock).get()
      of ConsensusFork.Bellatrix:
        blocks[2].add dag.db.getBlock(
          blck.root, bellatrix.TrustedSignedBeaconBlock).get()
      of ConsensusFork.Capella:
        blocks[3].add dag.db.getBlock(
          blck.root, capella.TrustedSignedBeaconBlock).get()
      of ConsensusFork.Deneb:
        blocks[4].add dag.db.getBlock(
          blck.root, deneb.TrustedSignedBeaconBlock).get()

  let stateData = newClone(dag.headState)

  var
    cache = StateCache()
    info = ForkedEpochInfo()
    loadedState = (
      (ref phase0.HashedBeaconState)(),
      (ref altair.HashedBeaconState)(),
      (ref bellatrix.HashedBeaconState)(),
      (ref capella.HashedBeaconState)(),
      (ref deneb.HashedBeaconState)())

  withTimer(timers[tLoadState]):
    doAssert dag.updateState(
      stateData[],
      dag.atSlot(blockRefs[^1], blockRefs[^1].slot - 1).expect("not nil"),
      false, cache)

  template processBlocks(blocks: auto) =
    for b in blocks.mitems():
      if shouldShutDown: quit QuitSuccess
      while getStateField(stateData[], slot) < b.message.slot:
        let isEpoch = (getStateField(stateData[], slot) + 1).is_epoch()
        withTimer(timers[if isEpoch: tAdvanceEpoch else: tAdvanceSlot]):
          process_slots(
            dag.cfg, stateData[], getStateField(stateData[], slot) + 1, cache,
            info, {}).expect("Slot processing can't fail with correct inputs")

      var start = Moment.now()
      withTimer(timers[tApplyBlock]):
        if conf.resetCache:
          cache = StateCache()
        let res = state_transition_block(
            dag.cfg, stateData[], b, cache, {}, noRollback)
        if res.isErr():
          dump("./", b)
          echo "State transition failed (!) ", res.error()
          quit 1
      if conf.printTimes:
        echo b.message.slot, ",", toHex(b.root.data), ",", nanoseconds(Moment.now() - start)
      if conf.storeBlocks:
        withTimer(timers[tDbStore]):
          dbBenchmark.putBlock(b)

      withState(stateData[]):
        if forkyState.data.slot.is_epoch and conf.storeStates:
          if forkyState.data.slot.epoch < 2:
            dbBenchmark.putState(forkyState.root, forkyState.data)
            dbBenchmark.checkpoint()
          else:
            withTimer(timers[tDbStore]):
              dbBenchmark.putState(forkyState.root, forkyState.data)
              dbBenchmark.checkpoint()

            withTimer(timers[tDbLoad]):
              case consensusFork
              of ConsensusFork.Phase0:
                doAssert dbBenchmark.getState(
                  forkyState.root, loadedState[0][].data, noRollback)
              of ConsensusFork.Altair:
                doAssert dbBenchmark.getState(
                  forkyState.root, loadedState[1][].data, noRollback)
              of ConsensusFork.Bellatrix:
                doAssert dbBenchmark.getState(
                  forkyState.root, loadedState[2][].data, noRollback)
              of ConsensusFork.Capella:
                doAssert dbBenchmark.getState(
                  forkyState.root, loadedState[3][].data, noRollback)
              of ConsensusFork.Deneb:
                doAssert dbBenchmark.getState(
                  forkyState.root, loadedState[4][].data, noRollback)

            if forkyState.data.slot.epoch mod 16 == 0:
              let loadedRoot = case consensusFork
                of ConsensusFork.Phase0:    hash_tree_root(loadedState[0][].data)
                of ConsensusFork.Altair:    hash_tree_root(loadedState[1][].data)
                of ConsensusFork.Bellatrix: hash_tree_root(loadedState[2][].data)
                of ConsensusFork.Capella:   hash_tree_root(loadedState[3][].data)
                of ConsensusFork.Deneb:     hash_tree_root(loadedState[4][].data)
              doAssert hash_tree_root(forkyState.data) == loadedRoot

  processBlocks(blocks[0])
  processBlocks(blocks[1])
  processBlocks(blocks[2])
  processBlocks(blocks[3])
  processBlocks(blocks[4])

  printTimers(false, timers)

proc cmdDumpState(conf: DbConf) =
  let db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
  defer: db.close()

  let
    phase0State    = (ref phase0.HashedBeaconState)()
    altairState    = (ref altair.HashedBeaconState)()
    bellatrixState = (ref bellatrix.HashedBeaconState)()
    capellaState   = (ref capella.HashedBeaconState)()
    denebState     = (ref deneb.HashedBeaconState)()

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
    doit(capellaState[])
    doit(denebState[])

    echo "Couldn't load ", stateRoot

proc cmdPutState(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  for file in conf.stateFile:
    if shouldShutDown: quit QuitSuccess
    let state = newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(file).tryGet()))
    withState(state[]):
      db.putState(forkyState)

proc cmdDumpBlock(conf: DbConf) =
  let db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
  defer: db.close()

  for blockRoot in conf.blockRootx:
    if shouldShutDown: quit QuitSuccess
    try:
      let root = Eth2Digest.fromHex(blockRoot)
      if (let blck = db.getBlock(
          root, phase0.TrustedSignedBeaconBlock); blck.isSome):
        dump("./", blck.get())
      elif (let blck = db.getBlock(
          root, altair.TrustedSignedBeaconBlock); blck.isSome):
        dump("./", blck.get())
      elif (let blck = db.getBlock(root, bellatrix.TrustedSignedBeaconBlock); blck.isSome):
        dump("./", blck.get())
      elif (let blck = db.getBlock(root, capella.TrustedSignedBeaconBlock); blck.isSome):
        dump("./", blck.get())
      elif (let blck = db.getBlock(root, deneb.TrustedSignedBeaconBlock); blck.isSome):
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
      db.putBlock(forkyBlck)
      if conf.setHead:
        db.putHeadBlock(forkyBlck.root)
      if conf.setTail:
        db.putTailBlock(forkyBlck.root)
      if conf.setGenesis:
        db.putGenesisBlock(forkyBlck.root)

proc cmdRewindState(conf: DbConf, cfg: RuntimeConfig) =
  echo "Opening database..."
  let db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
  defer: db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized: ", v.error()
    quit 1

  echo "Initializing block pool..."

  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {}, conf.eraDir)

  let bid = dag.getBlockId(fromHex(Eth2Digest, conf.blockRoot)).valueOr:
    echo "Block not found in database"
    return

  let tmpState = assignClone(dag.headState)
  dag.withUpdatedState(
      tmpState[], dag.atSlot(bid, Slot(conf.slot)).expect("block found")) do:
    echo "Writing state..."
    withState(updatedState):
      dump("./", forkyState)
  do: raiseAssert "withUpdatedState failed"

proc cmdVerifyEra(conf: DbConf, cfg: RuntimeConfig) =
  let
    f = EraFile.open(conf.eraFile).valueOr:
      echo error
      quit 1
    root = f.verify(cfg).valueOr:
      echo error
      quit 1
  echo root

proc cmdExportEra(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
  defer: db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    fatal "Database not initialized", error = v.error()
    quit 1

  type Timers = enum
    tState
    tBlocks

  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {}, conf.eraDir)

  let tmpState = assignClone(dag.headState)
  var
    tmp: seq[byte]
    timers: array[Timers, RunningStat]

  var
    era = Era(conf.era)
    missingHistory = false
  while conf.eraCount == 0 or era < Era(conf.era) + conf.eraCount:
    defer: era += 1

    if shouldShutDown:
      break

    # Era files hold the blocks for the "previous" era, and the first state in
    # the era itself
    let
      firstSlot =
        if era == 0: none(Slot)
        else: some((era - 1).start_slot)
      endSlot = era.start_slot

    if endSlot > dag.head.slot:
      notice "Written all complete eras", era, endSlot, head = dag.head
      break

    let
      eraRoot = withState(dag.headState):
        eraRoot(
          forkyState.data.genesis_validators_root,
          forkyState.data.historical_roots.asSeq,
          dag.headState.historical_summaries().asSeq,
          era).expect("have era root since we checked slot")
      name = eraFileName(cfg, era, eraRoot)

    if isFile(name):
      debug "Era file already exists", era, name
      continue

    # Check if we reasonably could write the era file given what's in the
    # database - we perform this check after checking for existing era files
    # since the database might have been pruned up to the "existing" era files!
    if endSlot < dag.tail.slot and era != 0:
      notice "Skipping era, state history not available",
        era, tail = shortLog(dag.tail)
      missingHistory = true
      continue

    let
      eraBid = dag.atSlot(dag.head.bid, endSlot).valueOr:
        notice "Skipping era, blocks not available", era, name
        missingHistory = true
        continue

    withTimer(timers[tState]):
      var cache: StateCache
      if not updateState(dag, tmpState[], eraBid, false, cache):
        notice "Skipping era, state history not available", era, name
        missingHistory = true
        continue

    info "Writing ", name
    let tmpName = name & ".tmp"
    var completed = false
    block writeFileBlock:
      let e2 = openFile(tmpName, {OpenFlags.Write, OpenFlags.Create, OpenFlags.Truncate}).get()
      defer: discard closeFile(e2)

      var group = EraGroup.init(e2, firstSlot).get()
      if firstSlot.isSome():
        withTimer(timers[tBlocks]):
          var blocks: array[SLOTS_PER_HISTORICAL_ROOT.int, BlockId]
          for i in dag.getBlockRange(firstSlot.get(), 1, blocks)..<blocks.len:
            if not dag.getBlockSZ(blocks[i], tmp):
              break writeFileBlock
            group.update(e2, blocks[i].slot, tmp).get()

      withState(tmpState[]):
        group.finish(e2, forkyState.data).get()
        completed = true
    if completed:
      try:
        moveFile(tmpName, name)
      except IOError as e:
        warn "Failed to rename era file to its final name",
          name, tmpName, error = e.msg
    else:
      if (let e = io2.removeFile(name); e.isErr):
        warn "Failed to clean up incomplete era file", tmpName, error = e.error

  if missingHistory:
    notice "Some era files were not written due to missing state history - see https://nimbus.guide/trusted-node-sync.html#recreate-historical-state-access-indices for more information"
  printTimers(true, timers)

proc cmdImportEra(conf: DbConf, cfg: RuntimeConfig) =
  let db = BeaconChainDB.new(conf.databaseDir.string)
  defer: db.close()

  type Timers = enum
    tBlock
    tState

  var
    blocks = 0
    states = 0
    others = 0
    timers: array[Timers, RunningStat]

  var data: seq[byte]
  for file in conf.eraFiles:
    if shouldShutDown: quit QuitSuccess

    let f = openFile(file, {OpenFlags.Read}).valueOr:
      warn "Can't open ", file
      continue
    defer: discard closeFile(f)

    while true:
      let header = readRecord(f, data).valueOr:
        break

      if header.typ == SnappyBeaconBlock:
        withTimer(timers[tBlock]):
          let uncompressed = decodeFramed(data, checkIntegrity = false)
          let blck = try: readSszForkedSignedBeaconBlock(cfg, uncompressed)
          except CatchableError as exc:
            error "Invalid snappy block", msg = exc.msg, file
            continue

          withBlck(blck.asTrusted()):
            db.putBlock(forkyBlck)
        blocks += 1
      elif header.typ == SnappyBeaconState:
        info "Skipping beacon state (use reindexing to recreate state snapshots)"
        states += 1
      else:
        info "Skipping record", typ = toHex(header.typ)
        others += 1

  notice "Done", blocks, states, others
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
    db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
  defer:
    db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized: ", v.error()
    quit 1

  echo "# Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {}, conf.eraDir)

  var
    (start, ends) = dag.getSlotRange(conf.perfSlot, conf.perfSlots)
    blockRefs = dag.getBlockRange(start, ends)
    perfs = newSeq[ValidatorPerformance](
      getStateField(dag.headState, validators).len())
    cache = StateCache()
    info = ForkedEpochInfo()
    blck: phase0.TrustedSignedBeaconBlock

  doAssert blockRefs.len() > 0, "Must select at least one block"

  echo "# Analyzing performance for epochs ",
    blockRefs[^1].slot.epoch, " - ", blockRefs[0].slot.epoch

  let state = newClone(dag.headState)
  doAssert dag.updateState(
    state[],
    dag.atSlot(blockRefs[^1], blockRefs[^1].slot - 1).expect("block found"),
    false, cache)

  proc processEpoch() =
    let
      prev_epoch_target_slot =
        state[].get_previous_epoch().start_slot()
      penultimate_epoch_end_slot =
        if prev_epoch_target_slot == 0: Slot(0)
        else: prev_epoch_target_slot - 1
      first_slot_empty =
        state[].get_block_root_at_slot(prev_epoch_target_slot) ==
        state[].get_block_root_at_slot(penultimate_epoch_end_slot)

    let first_slot_attesters = block:
      let committees_per_slot = state[].get_committee_count_per_slot(
        prev_epoch_target_slot.epoch, cache)
      var indices = HashSet[ValidatorIndex]()
      for committee_index in get_committee_indices(committees_per_slot):
        for validator_index in state[].get_beacon_committee(
            prev_epoch_target_slot, committee_index, cache):
          indices.incl(validator_index)
      indices
    case info.kind
    of EpochInfoFork.Phase0:
      template info: untyped = info.phase0Data
      for i, s in info.validators:
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
    blck = db.getBlock(
      blockRefs[blockRefs.len - bi - 1].root,
      phase0.TrustedSignedBeaconBlock).get()
    while getStateField(state[], slot) < blck.message.slot:
      let
        nextSlot = getStateField(state[], slot) + 1
        flags =
          if nextSlot == blck.message.slot: {skipLastStateRootCalculation}
          else: {}
      process_slots(
        dag.cfg, state[], nextSlot, cache, info, flags).expect(
          "Slot processing can't fail with correct inputs")

      if getStateField(state[], slot).is_epoch():
        processEpoch()

    let res = state_transition_block(
        dag.cfg, state[], blck, cache, {}, noRollback)
    if res.isErr:
      echo "State transition failed (!) ", res.error()
      quit 1

  # Capture rewards of empty slots as well
  while getStateField(state[], slot) < ends:
    process_slots(
      dag.cfg, state[], getStateField(state[], slot) + 1, cache,
      info, {}).expect("Slot processing can't fail with correct inputs")

    if getStateField(state[], slot).is_epoch():
      processEpoch()

  echo "validator_index,attestation_hits,attestation_misses,head_attestation_hits,head_attestation_misses,target_attestation_hits,target_attestation_misses,delay_avg,first_slot_head_attester_when_first_slot_empty,first_slot_head_attester_when_first_slot_not_empty"

  for i, perf in perfs:
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
    balances = seq[uint64](forkyState.data.balances.data)

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
                  currentEpochBalance, previousEpochBalance: int64,
                  validatorInfo: RewardsAndPenalties) =
  let delta = validatorInfo.calculateDelta
  if currentEpochBalance == previousEpochBalance + delta:
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
          (i, forkyState.data.validators[i].pubkey.toRaw)).expect("DB")

proc cmdValidatorDb(conf: DbConf, cfg: RuntimeConfig) =
  # Create a database with performance information for every epoch
  info "Opening database..."
  let db = BeaconChainDB.new(conf.databaseDir.string, readOnly = true)
  defer: db.close()

  if (let v = ChainDAGRef.isInitialized(db); v.isErr()):
    echo "Database not initialized"
    quit 1

  echo "Initializing block pool..."
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {}, conf.eraDir)

  let outDb = SqStoreRef.init(conf.outDir, "validatorDb").expect("DB")
  defer: outDb.close()

  outDb.createValidatorsRawTable
  outDb.createValidatorsView

  let
    unaggregatedFilesOutputDir = conf.outDir / "unaggregated"
    aggregatedFilesOutputDir = conf.outDir / "aggregated"
    startEpoch =
      if conf.startEpoch.isSome:
        Epoch(conf.startEpoch.get)
      else:
        let unaggregatedFilesNextEpoch = getUnaggregatedFilesLastEpoch(
          unaggregatedFilesOutputDir) + 1
        let aggregatedFilesNextEpoch = getAggregatedFilesLastEpoch(
          aggregatedFilesOutputDir) + 1
        if conf.writeUnaggregatedFiles and conf.writeAggregatedFiles:
          min(unaggregatedFilesNextEpoch, aggregatedFilesNextEpoch)
        elif conf.writeUnaggregatedFiles:
          unaggregatedFilesNextEpoch
        elif conf.writeAggregatedFiles:
          aggregatedFilesNextEpoch
        else:
          min(unaggregatedFilesNextEpoch, aggregatedFilesNextEpoch)
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

  if not unaggregatedFilesOutputDir.dirExists:
    unaggregatedFilesOutputDir.createDir

  if not aggregatedFilesOutputDir.dirExists:
    aggregatedFilesOutputDir.createDir

  let tmpState = newClone(dag.headState)
  var cache = StateCache()
  let slot = if startSlot > 0: startSlot - 1 else: 0.Slot
  if blockRefs.len > 0:
    discard dag.updateState(
      tmpState[], dag.atSlot(blockRefs[^1], slot).expect("block"), false, cache)
  else:
    discard dag.updateState(
      tmpState[], dag.getBlockIdAtSlot(slot).expect("block"), false, cache)

  let savedValidatorsCount = outDb.getDbValidatorsCount
  var validatorsCount = getStateField(tmpState[], validators).len
  outDb.insertValidators(tmpState[], savedValidatorsCount, validatorsCount)

  var previousEpochBalances: seq[uint64]
  collectBalances(previousEpochBalances, tmpState[])

  var forkedInfo = ForkedEpochInfo()
  var rewardsAndPenalties: seq[RewardsAndPenalties]
  rewardsAndPenalties.setLen(validatorsCount)

  var auxiliaryState: AuxiliaryState
  auxiliaryState.copyParticipationFlags(tmpState[])

  var aggregator = ValidatorDbAggregator.init(
    aggregatedFilesOutputDir, conf.resolution, endEpoch)

  proc processEpoch() =
    let epoch = getStateField(tmpState[], slot).epoch
    info "Processing epoch ...", epoch = epoch

    var csvLines = newStringOfCap(1000000)

    withState(tmpState[]):
      withEpochInfo(forkedInfo):
        doAssert forkyState.data.balances.len == info.validators.len
        doAssert forkyState.data.balances.len == previousEpochBalances.len
        doAssert forkyState.data.balances.len == rewardsAndPenalties.len

        for index, validator in info.validators:
          template rp: untyped = rewardsAndPenalties[index]

          checkBalance(
            index, validator, forkyState.data.balances.item(index).int64,
            previousEpochBalances[index].int64, rp)

          when infoFork == EpochInfoFork.Phase0:
            rp.inclusion_delay = block:
              let notSlashed = (RewardFlags.isSlashed notin validator.flags)
              if notSlashed and validator.is_previous_epoch_attester.isSome():
                some(validator.is_previous_epoch_attester.get().delay.uint64)
              else:
                none(uint64)

          if conf.writeUnaggregatedFiles:
            csvLines.add rp.serializeToCsv

          if conf.writeAggregatedFiles:
            aggregator.addValidatorData(index, rp)

    if conf.writeUnaggregatedFiles:
      let fileName = getFilePathForEpoch(epoch, unaggregatedFilesOutputDir)
      var res = io2.removeFile(fileName)
      doAssert res.isOk
      res = io2.writeFile(fileName, snappy.encode(csvLines.toBytes))
      doAssert res.isOk

    if conf.writeAggregatedFiles:
      aggregator.advanceEpochs(epoch, shouldShutDown)

    if shouldShutDown: quit QuitSuccess
    collectBalances(previousEpochBalances, tmpState[])

  proc processSlots(ends: Slot, endsFlags: UpdateFlags) =
    var currentSlot = getStateField(tmpState[], slot)
    while currentSlot < ends:
      let nextSlot = currentSlot + 1
      let flags = if nextSlot == ends: endsFlags else: {}

      if nextSlot.is_epoch:
        withState(tmpState[]):
          var stateData = newClone(forkyState.data)
          rewardsAndPenalties.collectEpochRewardsAndPenalties(
            stateData[], cache, cfg, flags)

      let res = process_slots(cfg, tmpState[], nextSlot, cache, forkedInfo, flags)
      doAssert res.isOk, "Slot processing can't fail with correct inputs"

      currentSlot = nextSlot

      if currentSlot.is_epoch:
        processEpoch()
        rewardsAndPenalties.setLen(0)
        rewardsAndPenalties.setLen(validatorsCount)
        auxiliaryState.copyParticipationFlags(tmpState[])
        clear cache

  for bi in 0 ..< blockRefs.len:
    let forkedBlock = dag.getForkedBlock(blockRefs[blockRefs.len - bi - 1]).get()
    withBlck(forkedBlock):
      processSlots(forkyBlck.message.slot, {skipLastStateRootCalculation})

      rewardsAndPenalties.collectBlockRewardsAndPenalties(
        tmpState[], forkedBlock, auxiliaryState, cache, cfg)

      let res = state_transition_block(
        cfg, tmpState[], forkyBlck, cache, {}, noRollback)
      if res.isErr:
        fatal "State transition failed (!)"
        quit QuitFailure

      let newValidatorsCount = getStateField(tmpState[], validators).len
      if newValidatorsCount > validatorsCount:
        # Resize the structures in case a new validator has appeared after
        # the state_transition_block procedure call ...
        rewardsAndPenalties.setLen(newValidatorsCount)
        previousEpochBalances.setLen(newValidatorsCount)
        # ... and add the new validators to the database.
        outDb.insertValidators(
          tmpState[], validatorsCount, newValidatorsCount)
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
  of DbCmd.rewindState:
    cmdRewindState(conf, cfg)
  of DbCmd.verifyEra:
    cmdVerifyEra(conf, cfg)
  of DbCmd.exportEra:
    cmdExportEra(conf, cfg)
  of DbCmd.importEra:
    cmdImportEra(conf, cfg)
  of DbCmd.validatorPerf:
    cmdValidatorPerf(conf, cfg)
  of DbCmd.validatorDb:
    cmdValidatorDb(conf, cfg)

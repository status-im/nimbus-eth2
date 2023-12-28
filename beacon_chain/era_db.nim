# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/os,
  chronicles,
  stew/results, snappy, taskpools,
  ../ncli/e2store,
  ./spec/datatypes/[altair, bellatrix, phase0],
  ./spec/[beaconstate, forks, signatures_batch],
  ./consensus_object_pools/block_dag # TODO move to somewhere else to avoid circular deps

export results, forks, e2store

type
  EraFile* = ref object
    handle: Opt[IoHandle]
    stateIdx: Index
    blockIdx: Index

  EraDB* = ref object
    ## The Era database manages a collection of era files that together make up
    ## a linear history of beacon chain data.
    cfg: RuntimeConfig
    path: string
    genesis_validators_root: Eth2Digest

    files: seq[EraFile]

proc open*(_: type EraFile, name: string): Result[EraFile, string] =
  var
    f = Opt[IoHandle].ok(? openFile(name, {OpenFlags.Read}).mapErr(ioErrorMsg))

  defer:
    if f.isSome(): discard closeFile(f[])

  # Indices can be found at the end of each era file - we only support
  # single-era files for now
  ? f[].setFilePos(0, SeekPosition.SeekEnd).mapErr(ioErrorMsg)

  # Last in the file is the state index
  let
    stateIdxPos = ? f[].findIndexStartOffset()
  ? f[].setFilePos(stateIdxPos, SeekPosition.SeekCurrent).mapErr(ioErrorMsg)

  let
    stateIdx = ? f[].readIndex()
  if stateIdx.offsets.len() != 1:
    return err("State index length invalid")

  ? f[].setFilePos(stateIdxPos, SeekPosition.SeekCurrent).mapErr(ioErrorMsg)

  # The genesis era file does not contain a block index
  let blockIdx = if stateIdx.startSlot > 0:
    let
      blockIdxPos = ? f[].findIndexStartOffset()
    ? f[].setFilePos(blockIdxPos, SeekPosition.SeekCurrent).mapErr(ioErrorMsg)
    let idx = ? f[].readIndex()
    if idx.offsets.lenu64() != SLOTS_PER_HISTORICAL_ROOT:
      return err("Block index length invalid")

    idx
  else:
    Index()

  let res = EraFile(handle: f, stateIdx: stateIdx, blockIdx: blockIdx)
  reset(f)
  ok res

proc close(f: EraFile) =
  if f.handle.isSome():
    discard closeFile(f.handle.get())
    reset(f.handle)

proc getBlockSZ*(
    f: EraFile, slot: Slot, bytes: var seq[byte]): Result[void, string] =
  ## Get a snappy-frame-compressed version of the block data - may overwrite
  ## `bytes` on error
  ##
  ## Sets `bytes` to an empty seq and returns success if there is no block at
  ## the given slot, according to the index

  # Block content for the blocks of an era is found in the file for the _next_
  # era
  doAssert not isNil(f) and f[].handle.isSome

  let
    pos = f[].blockIdx.offsets[slot - f[].blockIdx.startSlot]

  if pos == 0:
    bytes = @[]
    return ok()

  ? f[].handle.get().setFilePos(pos, SeekPosition.SeekBegin).mapErr(ioErrorMsg)

  let header = ? f[].handle.get().readRecord(bytes)
  if header.typ != SnappyBeaconBlock:
    return err("Invalid era file: didn't find block at index position")

  ok()

proc getBlockSSZ*(
    f: EraFile, slot: Slot, bytes: var seq[byte]): Result[void, string] =
  ## Get raw SSZ bytes of the block at the given slot - may overwrite
  ## `bytes` on error.
  ##
  ## Sets `bytes` to an empty seq and returns success if there is no block at
  ## the given slot, according to the index
  var tmp: seq[byte]
  ? f.getBlockSZ(slot, tmp)

  let
    len = uncompressedLenFramed(tmp).valueOr:
      return err("Cannot read uncompressed length, era file corrupt?")

  if len == 0:
    # Given slot is empty
    reset(bytes)
    return ok()

  if len > int.high.uint64:
    return err("Invalid uncompressed size")

  bytes = newSeqUninitialized[byte](len)

  # Where it matters, we will integrity-check the data with SSZ - no
  # need to waste cycles on crc32
  discard uncompressFramed(tmp, bytes, checkIntegrity = false).valueOr:
    return err("Block failed to decompress, era file corrupt?")
  ok()

proc getStateSZ*(
    f: EraFile, slot: Slot, bytes: var seq[byte]): Result[void, string] =
  ## Get a snappy-frame-compressed version of the state data - may overwrite
  ## `bytes` on error
  ## https://github.com/google/snappy/blob/8dd58a519f79f0742d4c68fbccb2aed2ddb651e8/framing_format.txt#L34
  doAssert not isNil(f) and f[].handle.isSome

  # TODO consider multi-era files
  if f[].stateIdx.startSlot != slot:
    return err("State not found in era file")

  let pos = f[].stateIdx.offsets[0]
  if pos == 0:
    return err("No state at given slot")

  ? f[].handle.get().setFilePos(pos, SeekPosition.SeekBegin).mapErr(ioErrorMsg)

  let header = ? f[].handle.get().readRecord(bytes)
  if header.typ != SnappyBeaconState:
    return err("Invalid era file: didn't find state at index position")

  ok()

proc getStateSSZ*(
    f: EraFile, slot: Slot, bytes: var seq[byte],
    partial = Opt.none(int)): Result[void, string] =
  var tmp: seq[byte]
  ? f.getStateSZ(slot, tmp)

  let
    len = uncompressedLenFramed(tmp).valueOr:
      return err("Cannot read uncompressed length, era file corrupt?")
    wanted =
      if partial.isSome():
        min(len, partial.get().uint64 + maxUncompressedFrameDataLen - 1)
      else: len

  bytes = newSeqUninitialized[byte](wanted)

  # Where it matters, we will integrity-check the data with SSZ - no
  # need to waste cycles on crc32
  discard uncompressFramed(tmp, bytes, checkIntegrity = false).valueOr:
    return err("State failed to decompress, era file corrupt?")

  ok()

proc verify*(f: EraFile, cfg: RuntimeConfig): Result[Eth2Digest, string] =
  ## Verify that an era file is internally consistent, returning the state root
  ## Verification is dominated by block signature checks - about 4-10s on
  ## decent hardware.

  # We'll load the full state and compute its root - then we'll load the blocks
  # and make sure that they match the state and that their signatures check out
  let
    startSlot = f.stateIdx.startSlot
    era = startSlot.era

    rng = HmacDrbgContext.new()
    taskpool = Taskpool.new()
  var verifier = BatchVerifier.init(rng, taskpool)

  var tmp: seq[byte]
  ? f.getStateSSZ(startSlot, tmp)

  let
    state =
      try: newClone(readSszForkedHashedBeaconState(cfg, tmp))
      except CatchableError as exc:
        return err("Unable to read state: " & exc.msg)

  if era > 0:
    var sigs: seq[SignatureSet]

    for slot in (era - 1).start_slot()..<era.start_slot():
      ? f.getBlockSSZ(slot, tmp)

      # TODO verify that missing blocks correspond to "repeated" block roots
      #      in state.block_roots - how to do this for "initial" empty slots in
      #      the era?
      if tmp.len > 0:
        let
          blck =
            try: newClone(readSszForkedSignedBeaconBlock(cfg, tmp))
            except CatchableError as exc:
              return err("Unable to read block: " & exc.msg)

        if getForkedBlockField(blck[], slot) != slot:
          return err("Block slot does not match era index")
        if blck[].root !=
            state[].get_block_root_at_slot(getForkedBlockField(blck[], slot)):
          return err("Block does not match state")
        if slot > GENESIS_SLOT:
          let
            proposer = getForkedBlockField(blck[], proposer_index)
            key = withState(state[]):
              if proposer >= forkyState.data.validators.lenu64:
                return err("Invalid proposer in block")
              forkyState.data.validators.item(proposer).pubkey
            cooked = key.load()
            sig = blck[].signature.load()

          if cooked.isNone():
            return err("Cannot load proposer key")
          if sig.isNone():
            warn "Signature invalid",
              sig = blck[].signature, blck = shortLog(blck[])
            return err("Cannot load block signature")

          # Batch-verification more than doubles total verification speed
          sigs.add block_signature_set(
              cfg.forkAtEpoch(slot.epoch),
              getStateField(state[], genesis_validators_root), slot,
              blck[].root, cooked.get(), sig.get())

        else: # slot == GENESIS_SLOT:
          if blck[].signature != default(type(blck[].signature)):
            return err("Genesis slot signature not empty")

    if not batchVerify(verifier, sigs):
      return err("Invalid block signature")

  ok(getStateRoot(state[]))

proc getEraFile(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], era: Era):
    Result[EraFile, string] =
  for f in db.files:
    if f.stateIdx.startSlot.era == era:
      return ok(f)

  let
    eraRoot = eraRoot(
        db.genesis_validators_root, historical_roots, historical_summaries,
        era).valueOr:
      return err("Era outside of known history")
    name = eraFileName(db.cfg, era, eraRoot)
    path = db.path / name

  if not isFile(path):
    return err("No such era file")

  let
    f = EraFile.open(path).valueOr:
      # TODO allow caller to differentiate between invalid and missing era file,
      #      then move logging elsewhere
      warn "Failed to open era file", path, error = error
      return err(error)

  if db.files.len > 16: # TODO LRU
    close(db.files[0])
    db.files.delete(0)

  db.files.add(f)
  ok(f)

proc getBlockSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    bytes: var seq[byte]): Result[void, string] =
  ## Get a snappy-frame-compressed version of the block data - may overwrite
  ## `bytes` on error
  ##
  ## Sets `bytes` to an empty seq and returns success if there is no block at
  ## the given slot, according to the index

  # Block content for the blocks of an era is found in the file for the _next_
  # era
  let
    f = ? db.getEraFile(historical_roots, historical_summaries, slot.era + 1)

  f.getBlockSZ(slot, bytes)

proc getBlockSSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    bytes: var seq[byte]): Result[void, string] =
  ## Get raw SSZ bytes of the block at the given slot - may overwrite
  ## `bytes` on error.
  ##
  ## Sets `bytes` to an empty seq and returns success if there is no block at
  ## the given slot according to the index
  let
    f = ? db.getEraFile(historical_roots, historical_summaries, slot.era + 1)

  f.getBlockSSZ(slot, bytes)

proc getBlock*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    root: Opt[Eth2Digest], T: type ForkyTrustedSignedBeaconBlock): Opt[T] =
  var bytes: seq[byte]
  ? db.getBlockSSZ(
    historical_roots, historical_summaries, slot, bytes).mapConvertErr(void)
  if bytes.len() == 0:
    return Opt.none(T)

  result.ok(default(T))
  try:
    readSszBytes(bytes, result.get(), updateRoot = root.isNone)
    if root.isSome():
      result.get().root = root.get()
  except CatchableError:
    result.err()

proc getStateSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    bytes: var seq[byte]):
    Result[void, string] =
  ## Get a snappy-frame-compressed version of the state data - may overwrite
  ## `bytes` on error
  ## https://github.com/google/snappy/blob/8dd58a519f79f0742d4c68fbccb2aed2ddb651e8/framing_format.txt#L34

  # Block content for the blocks of an era is found in the file for the _next_
  # era
  let
    f = ? db.getEraFile(historical_roots, historical_summaries, slot.era)

  f.getStateSZ(slot, bytes)

proc getStateSSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    bytes: var seq[byte], partial = Opt.none(int)): Result[void, string] =
  let
    f = ? db.getEraFile(historical_roots, historical_summaries, slot.era)

  f.getStateSSZ(slot, bytes, partial)

proc getState*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    state: var ForkedHashedBeaconState): Result[void, string] =
  var bytes: seq[byte]
  ? db.getStateSSZ(historical_roots, historical_summaries, slot, bytes)
  if bytes.len() == 0:
    return err("State not found")

  try:
    state = readSszForkedHashedBeaconState(db.cfg, slot, bytes)
    ok()
  except CatchableError as exc:
    err(exc.msg)

type
  PartialBeaconState = object
    # The first bytes of a beacon state object are (for now) shared between all
    # forks - we exploit this to speed up loading

    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Needed to process attestations, older to newer

proc getPartialState(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary], slot: Slot,
    output: var PartialBeaconState): bool =
  static: doAssert isFixedSize(PartialBeaconState)
  const partialBytes = fixedPortionSize(PartialBeaconState)

  # TODO we don't need to read all bytes: ideally we could use something like
  # faststreams to read uncompressed bytes up to a limit and it would take care
  # of reading the minimal number of bytes from disk
  var tmp: seq[byte]
  if (let e = db.getStateSSZ(
      historical_roots, historical_summaries, slot, tmp,
      Opt[int].ok(partialBytes));
      e.isErr):
    return false

  try:
    readSszBytes(tmp.toOpenArray(0, partialBytes - 1), output)
    true
  except CatchableError:
    # TODO log?
    false

iterator getBlockIds*(
    db: EraDB, historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary],
    start_slot: Slot, prev_root: Eth2Digest): BlockId =
  ## Iterate over block roots starting from the given slot - `prev_root` must
  ## point out the last block added to the chain before `start_slot` such that
  ## empty slots can be filtered out correctly
  var
    state = (ref PartialBeaconState)() # avoid stack overflow
    slot = start_slot
    prev_root = prev_root

  while true:
    # `case` ensures we're on a fork for which the `PartialBeaconState`
    # definition is consistent
    case db.cfg.consensusForkAtEpoch(slot.epoch)
    of ConsensusFork.Phase0 .. ConsensusFork.Deneb:
      let stateSlot = (slot.era() + 1).start_slot()
      if not getPartialState(
          db, historical_roots, historical_summaries, stateSlot, state[]):
        state = nil # No `return` in iterators

    if state == nil:
      break

    let
      x = slot.uint64 mod state[].block_roots.lenu64

    for i in x..<state[].block_roots.lenu64():
      # When no block is included for a particular slot, the block root is
      # repeated
      if slot == 0 or prev_root != state[].block_roots.data[i]:
        yield BlockId(root: state[].block_roots.data[i], slot: slot)
        prev_root = state[].block_roots.data[i]
      slot += 1

proc new*(
    T: type EraDB, cfg: RuntimeConfig, path: string,
    genesis_validators_root: Eth2Digest): EraDB =
  EraDB(cfg: cfg, path: path, genesis_validators_root: genesis_validators_root)

when isMainModule:
  # Testing EraDB gets messy because of the large amounts of data involved:
  # this snippet contains some sanity checks for mainnet at least

  import
    os,
    stew/arrayops

  let
    dbPath =
      if os.paramCount() == 1: os.paramStr(1)
      else: "era"

    cfg = defaultRuntimeConfig
    db = EraDB.new(
      defaultRuntimeConfig, dbPath,
      Eth2Digest.fromHex(
        "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"))
    historical_roots = [
      Eth2Digest.fromHex(
        "0x40cf2f3cffd63d9ffeb89999ee359926abfa07ca5eb3fe2a70bc9d6b15720b8c"),
      Eth2Digest.fromHex(
        "0x74a3850f3cbccce2271f7c99e53ab07dae55cd8022c937c2dde7a20c5a2b83f9")]

  var
    got0 = false
    got8191 = false
    got8192 = false
    got8193 = false
  for bid in db.getBlockIds(historical_roots, [], Slot(0), Eth2Digest()):
    if bid.slot == Slot(0):
      doAssert bid.root == Eth2Digest.fromHex(
        "0x4d611d5b93fdab69013a7f0a2f961caca0c853f87cfe9595fe50038163079360")
      got0 = true
    elif bid.slot == Slot(1):
      doAssert bid.root == Eth2Digest.fromHex(
        "0xbacd20f09da907734434f052bd4c9503aa16bab1960e89ea20610d08d064481c")
    elif bid.slot == Slot(5):
      raiseAssert "this slot was skipped, should not be iterated over"
    elif bid.slot == Slot(8191):
      doAssert bid.root == Eth2Digest.fromHex(
        "0x48ea23af46320b0290eae668b0c3e6ae3e0534270f897db0e83a57f51a22baca")
      got8191 = true
    elif bid.slot == Slot(8192):
      doAssert bid.root == Eth2Digest.fromHex(
        "0xa7d379a9cbf87ae62127ddee8660ddc08a83a788087d23eaddd852fd8c408ef1")
      got8192 = true
    elif bid.slot == Slot(8193):
      doAssert bid.root == Eth2Digest.fromHex(
        "0x0934b14ec4ec9d45f4a2a7c3e4f6bb12d35444c74de8e30c13138c4d41b393aa")
      got8193 = true
      break

  doAssert got0
  doAssert got8191
  doAssert got8192
  doAssert got8193

  doAssert db.getBlock(
      historical_roots, [], Slot(1), Opt[Eth2Digest].err(),
      phase0.TrustedSignedBeaconBlock).get().root ==
    Eth2Digest.fromHex(
        "0xbacd20f09da907734434f052bd4c9503aa16bab1960e89ea20610d08d064481c")

  let
    f = EraFile.open(dbPath & "/mainnet-00001-40cf2f3c.era").expect(
      "opening works")
  doAssert f.verify(cfg).isOk()

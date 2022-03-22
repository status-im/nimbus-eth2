# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/os,
  chronicles,
  stew/results,
  snappy/framing,
  ../ncli/e2store,
  ./spec/datatypes/[altair, bellatrix, phase0],
  ./spec/forks,
  ./consensus_object_pools/block_dag # TODO move to somewhere else to avoid circular deps

export results, forks, e2store

type
  EraFile = ref object
    handle: IoHandle
    stateIdx: Index
    blockIdx: Index

  EraDB* = ref object
    ## The Era database manages a collection of era files that together make up
    ## a linear history of beacon chain data.
    cfg: RuntimeConfig
    path: string
    genesis_validators_root: Eth2Digest

    files: seq[EraFile]

proc getEraFile(
    db: EraDB, historical_roots: openArray[Eth2Digest], era: Era):
    Result[EraFile, string] =
  for f in db.files:
    if f.stateIdx.startSlot.era == era:
      return ok(f)

  if db.files.len > 16:
    discard closeFile(db.files[0].handle)
    db.files.delete(0)

  if era.uint64 > historical_roots.lenu64():
    return err("Era outside of known history")

  let
    name = eraFileName(db.cfg, db.genesis_validators_root, historical_roots, era)

  var
    f = Opt[IoHandle].ok(? openFile(db.path / name, {OpenFlags.Read}).mapErr(ioErrorMsg))

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

  let res = EraFile(handle: f[], stateIdx: stateIdx, blockIdx: blockIdx)
  reset(f)

  db.files.add(res)
  ok(res)

proc getBlockSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest], slot: Slot, bytes: var seq[byte]):
    Result[void, string] =
  ## Get a snappy-frame-compressed version of the block data - may overwrite
  ## `bytes` on error

  # Block content for the blocks of an era is found in the file for the _next_
  # era
  let
    f = ? db.getEraFile(historical_roots, slot.era + 1)
    pos = f[].blockIdx.offsets[slot - f[].blockIdx.startSlot]

  if pos == 0:
    return err("No block at given slot")

  ? f.handle.setFilePos(pos, SeekPosition.SeekBegin).mapErr(ioErrorMsg)

  let header = ? f.handle.readRecord(bytes)
  if header.typ != SnappyBeaconBlock:
    return err("Invalid era file: didn't find block at index position")

  ok()

proc getBlockSSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest], slot: Slot,
    bytes: var seq[byte]): Result[void, string] =
  var tmp: seq[byte]
  ? db.getBlockSZ(historical_roots, slot, tmp)

  try:
    bytes = framingFormatUncompress(tmp)
    ok()
  except CatchableError as exc:
    err(exc.msg)

proc getBlock*(
    db: EraDB, historical_roots: openArray[Eth2Digest], slot: Slot,
    root: Opt[Eth2Digest], T: type ForkyTrustedSignedBeaconBlock): Opt[T] =
  var tmp: seq[byte]
  ? db.getBlockSSZ(historical_roots, slot, tmp).mapErr(proc(x: auto) = discard)

  result.ok(default(T))
  try:
    readSszBytes(tmp, result.get(), updateRoot = root.isNone)
    if root.isSome():
      result.get().root = root.get()
  except CatchableError as exc:
    result.err()

proc getStateSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest], slot: Slot,
    bytes: var seq[byte]):
    Result[void, string] =
  ## Get a snappy-frame-compressed version of the state data - may overwrite
  ## `bytes` on error

  # Block content for the blocks of an era is found in the file for the _next_
  # era
  let
    f = ? db.getEraFile(historical_roots, slot.era)

  if f.stateIdx.startSlot != slot:
    return err("State not found in era file")

  let pos = f.stateIdx.offsets[0]
  if pos == 0:
    return err("No state at given slot")

  ? f.handle.setFilePos(pos, SeekPosition.SeekBegin).mapErr(ioErrorMsg)

  let header = ? f.handle.readRecord(bytes)
  if header.typ != SnappyBeaconState:
    return err("Invalid era file: didn't find state at index position")

  ok()

proc getStateSSZ*(
    db: EraDB, historical_roots: openArray[Eth2Digest], slot: Slot,
    bytes: var seq[byte]): Result[void, string] =
  var tmp: seq[byte]
  ? db.getStateSZ(historical_roots, slot, tmp)

  try:
    bytes = framingFormatUncompress(tmp)
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
    db: EraDB, historical_roots: openArray[Eth2Digest], slot: Slot,
    output: var PartialBeaconState): bool =
  # TODO don't read all bytes: we only need a few, and shouldn't decompress the
  #      rest - our snappy impl is very slow, in part to the crc32 check it
  #      performs
  var tmp: seq[byte]
  if (let e = db.getStateSSZ(historical_roots, slot, tmp); e.isErr):
    debugecho e.error()
    return false

  static: doAssert isFixedSize(PartialBeaconState)
  const partialBytes = fixedPortionSize(PartialBeaconState)

  try:
    readSszBytes(tmp.toOpenArray(0, partialBytes - 1), output)
    true
  except CatchableError as exc:
    # TODO log?
    false

iterator getBlockIds*(
    db: EraDB, historical_roots: openArray[Eth2Digest], era: Era): BlockId =
  # The state from which we load block roots is stored in the file corresponding
  # to the "next" era
  let fileEra = era + 1

  var
    state = (ref PartialBeaconState)() # avoid stack overflow

  # `case` ensures we're on a fork for which the `PartialBeaconState`
  # definition is consistent
  case db.cfg.stateForkAtEpoch(fileEra.start_slot().epoch)
  of BeaconStateFork.Phase0, BeaconStateFork.Altair, BeaconStateFork.Bellatrix:
    if not getPartialState(db, historical_roots, fileEra.start_slot(), state[]):
      state = nil # No `return` in iterators

  if state != nil:
    var
      slot = era.start_slot()
    for root in state[].block_roots:
      yield BlockId(root: root, slot: slot)
      slot += 1

proc new*(
    T: type EraDB, cfg: RuntimeConfig, path: string,
    genesis_validators_root: Eth2Digest): EraDB =
  EraDb(cfg: cfg, path: path, genesis_validators_root: genesis_validators_root)

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

    db = EraDB.new(
      defaultRuntimeConfig, dbPath,
      Eth2Digest(
        data: array[32, byte].initCopyFrom([byte 0x4b, 0x36, 0x3d, 0xb9])))
    historical_roots = [
      Eth2Digest(
        data: array[32, byte].initCopyFrom([byte 0x40, 0xcf, 0x2f, 0x3c]))]

  var got8191 = false
  for slot, root in db.getSummaries(historical_roots, Era(0)):
    if slot == Slot(1):
      doAssert root == Eth2Digest.fromHex(
        "0xbacd20f09da907734434f052bd4c9503aa16bab1960e89ea20610d08d064481c")
    elif slot == Slot(5):
      raiseAssert "this slot was skipped"
    elif slot == Slot(8191):
      doAssert root == Eth2Digest.fromHex(
        "0x48ea23af46320b0290eae668b0c3e6ae3e0534270f897db0e83a57f51a22baca")
      got8191 = true

  doAssert db.getBlock(
      historical_roots, Slot(1), Opt[Eth2Digest].err(),
      phase0.TrustedSignedBeaconBlock).get().root ==
    Eth2Digest.fromHex(
        "0xbacd20f09da907734434f052bd4c9503aa16bab1960e89ea20610d08d064481c")

  doAssert got8191

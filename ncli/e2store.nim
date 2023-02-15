{.push raises: [].}

import
  std/strformat,
  stew/[arrayops, endians2, io2, results],
  snappy,
  ../beacon_chain/spec/[beacon_time, forks],
  ../beacon_chain/spec/eth2_ssz_serialization

export io2

type
  Era* = distinct uint64 # Time unit, similar to slot

const
  E2Version* = [byte 0x65, 0x32]
  E2Index* = [byte 0x69, 0x32]

  SnappyBeaconBlock* = [byte 0x01, 0x00]
  SnappyBeaconState* = [byte 0x02, 0x00]

  TypeFieldLen = 2
  LengthFieldLen = 4
  ReservedFieldLen = 2
  HeaderFieldLen = TypeFieldLen + LengthFieldLen + ReservedFieldLen

  FAR_FUTURE_ERA* = Era(not 0'u64)

type
  Type* = array[2, byte]

  Header* = object
    typ*: Type
    len*: int

  Index* = object
    startSlot*: Slot
    offsets*: seq[int64] # Absolute positions in file

ethTimeUnit Era

func era*(s: Slot): Era =
  if s == FAR_FUTURE_SLOT: FAR_FUTURE_ERA
  else: Era(s div SLOTS_PER_HISTORICAL_ROOT)

func start_slot*(e: Era): Slot =
  const maxEra = Era(FAR_FUTURE_SLOT div SLOTS_PER_HISTORICAL_ROOT)
  if e >= maxEra: FAR_FUTURE_SLOT
  else: Slot(e.uint64 * SLOTS_PER_HISTORICAL_ROOT)

proc toString(v: IoErrorCode): string =
  try: ioErrorMsg(v)
  except Exception as e: raiseAssert e.msg

func eraRoot*(
    genesis_validators_root: Eth2Digest,
    historical_roots: openArray[Eth2Digest], era: Era): Opt[Eth2Digest] =
  if era == Era(0): ok(genesis_validators_root)
  elif era <= historical_roots.lenu64(): ok(historical_roots[int(uint64(era) - 1)])
  else: err()

func eraFileName*(
    cfg: RuntimeConfig, era: Era, eraRoot: Eth2Digest): string =
  try:
    &"{cfg.name()}-{era.uint64:05}-{shortLog(eraRoot)}.era"
  except ValueError as exc:
    raiseAssert exc.msg

proc append(f: IoHandle, data: openArray[byte]): Result[void, string] =
  if (? writeFile(f, data).mapErr(toString)) != data.len.uint:
    return err("could not write data")
  ok()

proc appendHeader(f: IoHandle, typ: Type, dataLen: int): Result[int64, string] =
  if dataLen.uint64 > uint32.high:
    return err("entry does not fit 32-bit length")

  let start = ? getFilePos(f).mapErr(toString)

  ? append(f, typ)
  ? append(f, toBytesLE(dataLen.uint32))
  ? append(f, [0'u8, 0'u8])

  ok(start)

proc appendRecord*(
    f: IoHandle, typ: Type, data: openArray[byte]): Result[int64, string] =
  let start = ? appendHeader(f, typ, data.len())
  ? append(f, data)
  ok(start)

proc toCompressedBytes(item: auto): seq[byte] =
  snappy.encodeFramed(SSZ.encode(item))

proc appendRecord*(
    f: IoHandle, v: ForkyTrustedSignedBeaconBlock): Result[int64, string] =
  f.appendRecord(SnappyBeaconBlock, toCompressedBytes(v))

proc appendRecord*(f: IoHandle, v: ForkyBeaconState): Result[int64, string] =
  f.appendRecord(SnappyBeaconState, toCompressedBytes(v))

proc appendIndex*(
    f: IoHandle, startSlot: Slot, offsets: openArray[int64]):
    Result[int64, string] =
  let
    len = offsets.len() * sizeof(int64) + 16
    pos = ? f.appendHeader(E2Index, len)

  ? f.append(startSlot.uint64.toBytesLE())

  for v in offsets:
    ? f.append(cast[uint64](v - pos).toBytesLE())

  ? f.append(offsets.lenu64().toBytesLE())

  ok(pos)

proc appendRecord(f: IoHandle, index: Index): Result[int64, string] =
  f.appendIndex(index.startSlot, index.offsets)

proc checkBytesLeft(f: IoHandle, expected: int64): Result[void, string] =
  let size = ? getFileSize(f).mapErr(toString)
  if expected > size:
    return err("Record extends past end of file")

  let pos = ? getFilePos(f).mapErr(toString)
  if expected > size - pos:
    return err("Record extends past end of file")

  ok()

proc readFileExact(f: IoHandle, buf: var openArray[byte]): Result[void, string] =
  if (? f.readFile(buf).mapErr(toString)) != buf.len().uint:
    return err("missing data")
  ok()

proc readHeader(f: IoHandle): Result[Header, string] =
  var buf: array[10, byte]
  ? readFileExact(f, buf.toOpenArray(0, 7))

  var
    typ: Type
  discard typ.copyFrom(buf)

  # Cast safe because we had only 4 bytes of length data
  let
    len = cast[int64](uint32.fromBytesLE(buf.toOpenArray(2, 5)))

  # No point reading these..
  if len > int.high(): return err("header length exceeds int.high")

  # Must have at least that much data, or header is invalid
  ? f.checkBytesLeft(len)

  ok(Header(typ: typ, len: int(len)))

proc readRecord*(f: IoHandle, data: var seq[byte]): Result[Header, string] =
  let header = ? readHeader(f)
  if header.len > 0:
    ? f.checkBytesLeft(header.len)

    data.setLen(header.len)

    ? readFileExact(f, data)

  ok(header)

proc readIndexCount*(f: IoHandle): Result[int, string] =
  var bytes: array[8, byte]
  ? f.readFileExact(bytes)

  let count = uint64.fromBytesLE(bytes)
  if count > (int.high() div 8) - 3: return err("count: too large")

  let size = uint64(? f.getFileSize().mapErr(toString))
  # Need to have at least this much data in the file to read an index with
  # this count
  if count > (size div 8 + 3): return err("count: too large")

  ok(int(count)) # Sizes checked against int above

proc findIndexStartOffset*(f: IoHandle): Result[int64, string] =
  ? f.setFilePos(-8, SeekPosition.SeekCurrent).mapErr(toString)

  let
    count = ? f.readIndexCount() # Now we're back at the end of the index
    bytes = count.int64 * 8 + 24

  ok(-bytes)

proc readIndex*(f: IoHandle): Result[Index, string] =
  let
    startPos = ? f.getFilePos().mapErr(toString)
    fileSize = ? f.getFileSize().mapErr(toString)
    header = ? f.readHeader()

  if header.typ != E2Index: return err("not an index")
  if header.len < 16: return err("index entry too small")
  if header.len mod 8 != 0: return err("index length invalid")

  var buf: array[8, byte]
  ? f.readFileExact(buf)
  let
    slot = uint64.fromBytesLE(buf)
    count = header.len div 8 - 2

  var offsets = newSeqUninitialized[int64](count)
  for i in 0..<count:
    ? f.readFileExact(buf)

    let
      offset = uint64.fromBytesLE(buf)
      absolute =
        if offset == 0: 0'i64
        else:
          # Wrapping math is actually convenient here
          cast[int64](cast[uint64](startPos) + offset)

    if absolute < 0 or absolute > fileSize: return err("Invalid offset")
    offsets[i] = absolute

  ? f.readFileExact(buf)
  if uint64(count) != uint64.fromBytesLE(buf): return err("invalid count")

  # technically not an error, but we'll throw this sanity check in here..
  if slot > int32.high().uint64: return err("fishy slot")

  ok(Index(startSlot: Slot(slot), offsets: offsets))

type
  EraGroup* = object
    slotIndex*: Index

proc init*(
    T: type EraGroup, f: IoHandle, startSlot: Option[Slot]): Result[T, string] =
  discard ? f.appendHeader(E2Version, 0)

  ok(EraGroup(
    slotIndex: Index(
      startSlot: startSlot.get(Slot(0)),
      offsets: newSeq[int64](
        if startSlot.isSome(): SLOTS_PER_HISTORICAL_ROOT.int
        else: 0
  ))))

proc update*(
    g: var EraGroup, f: IoHandle, slot: Slot, szBytes: openArray[byte]):
    Result[void, string] =
  doAssert slot >= g.slotIndex.startSlot
  #  doAssert slot < g.slotIndex.startSlot + g.slotIndex.offsets.len

  g.slotIndex.offsets[int(slot - g.slotIndex.startSlot)] =
    ? f.appendRecord(SnappyBeaconBlock, szBytes)

  ok()

proc finish*(
    g: var EraGroup, f: IoHandle, state: ForkyBeaconState):
    Result[void, string] =
  let
    statePos = ? f.appendRecord(state)

  if state.slot > Slot(0):
    discard ? f.appendRecord(g.slotIndex)

  discard ? f.appendIndex(state.slot, [statePos])

  ok()

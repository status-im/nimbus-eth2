# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/strformat,
  results,
  stew/[endians2, io2],
  snappy,
  ../beacon_chain/spec/[beacon_time, forks],
  ../beacon_chain/spec/eth2_ssz_serialization,
  ./e2store

export
  io2,
  e2store.readRecord, e2store.findIndexStartOffset,
  e2store.SnappyBeaconBlock, e2store.SnappyBeaconState

type
  Era* = distinct uint64 # Time unit, similar to slot

  Index* = object
    startSlot*: Slot
    offsets*: seq[int64] # Absolute positions in file

const
  FAR_FUTURE_ERA* = Era(not 0'u64)

ethTimeUnit Era

func era*(s: Slot): Era =
  if s == FAR_FUTURE_SLOT: FAR_FUTURE_ERA
  else: Era(s div SLOTS_PER_HISTORICAL_ROOT)

func start_slot*(e: Era): Slot =
  const maxEra = Era(FAR_FUTURE_SLOT div SLOTS_PER_HISTORICAL_ROOT)
  if e >= maxEra: FAR_FUTURE_SLOT
  else: Slot(e.uint64 * SLOTS_PER_HISTORICAL_ROOT)

func eraRoot*(
    genesis_validators_root: Eth2Digest,
    historical_roots: openArray[Eth2Digest],
    historical_summaries: openArray[HistoricalSummary],
    era: Era): Opt[Eth2Digest] =
  if era == Era(0): ok(genesis_validators_root)
  elif era <= historical_roots.lenu64():
    ok(historical_roots[int(uint64(era) - 1)])
  elif era <= historical_roots.lenu64() + historical_summaries.lenu64():
    ok(hash_tree_root(
      historical_summaries[int(uint64(era) - 1) - historical_roots.len()]))
  else: err()

func eraFileName*(
    cfg: RuntimeConfig, era: Era, eraRoot: Eth2Digest): string =
  try:
    &"{cfg.name()}-{era.uint64:05}-{shortLog(eraRoot)}.era"
  except ValueError as exc:
    raiseAssert exc.msg

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

proc readIndex*(f: IoHandle): Result[Index, string] =
  var
    buf: seq[byte]
    pos: int

  let
    startPos = ? f.getFilePos().mapErr(toString)
    fileSize = ? f.getFileSize().mapErr(toString)
    header = ? f.readRecord(buf)

  if header.typ != E2Index: return err("not an index")
  if buf.len < 16: return err("index entry too small")
  if buf.len mod 8 != 0: return err("index length invalid")

  let
    slot = uint64.fromBytesLE(buf.toOpenArray(pos, pos + 7))
    count = buf.len div 8 - 2
  pos += 8

  # technically not an error, but we'll throw this sanity check in here..
  if slot > int32.high().uint64: return err("fishy slot")

  var offsets = newSeqUninitialized[int64](count)
  for i in 0..<count:
    let
      offset = uint64.fromBytesLE(buf.toOpenArray(pos, pos + 7))
      absolute =
        if offset == 0: 0'i64
        else:
          # Wrapping math is actually convenient here
          cast[int64](cast[uint64](startPos) + offset)

    if absolute < 0 or absolute > fileSize: return err("invalid offset")
    offsets[i] = absolute
    pos += 8

  if uint64(count) != uint64.fromBytesLE(buf.toOpenArray(pos, pos + 7)):
    return err("invalid count")

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

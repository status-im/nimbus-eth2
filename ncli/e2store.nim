# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  results,
  stew/[arrayops, endians2, io2]

export io2

const
  E2Version* = [byte 0x65, 0x32]
  E2Index* = [byte 0x69, 0x32]

  SnappyBeaconBlock* = [byte 0x01, 0x00]
  SnappyBeaconState* = [byte 0x02, 0x00]

type
  Type* = array[2, byte]

  Header* = object
    typ*: Type
    len*: int

proc toString*(v: IoErrorCode): string =
  try: ioErrorMsg(v)
  except Exception as e: raiseAssert e.msg

proc append*(f: IoHandle, data: openArray[byte]): Result[void, string] =
  if (? writeFile(f, data).mapErr(toString)) != data.len.uint:
    return err("could not write data")
  ok()

proc appendHeader*(f: IoHandle, typ: Type, dataLen: int): Result[int64, string] =
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

proc checkBytesLeft(f: IoHandle, expected: int64): Result[void, string] =
  let size = ? getFileSize(f).mapErr(toString)
  if expected > size:
    return err("Record extends past end of file")

  let pos = ? getFilePos(f).mapErr(toString)
  if expected > size - pos:
    return err("Record extends past end of file")

  ok()

proc readFileExact*(f: IoHandle, buf: var openArray[byte]): Result[void, string] =
  if (? f.readFile(buf).mapErr(toString)) != buf.len().uint:
    return err("missing data")
  ok()

proc readHeader*(f: IoHandle): Result[Header, string] =
  var buf: array[10, byte]
  ? readFileExact(f, buf.toOpenArray(0, 7))

  var
    typ: Type
  discard typ.copyFrom(buf)

  # Conversion safe because we had only 4 bytes of length data
  let len = (uint32.fromBytesLE(buf.toOpenArray(2, 5))).int64

  # No point reading these..
  if len > int.high(): return err("header length exceeds int.high")

  # Must have at least that much data, or header is invalid
  ? f.checkBytesLeft(len)

  ok(Header(typ: typ, len: int(len)))

proc readRecord*(f: IoHandle, data: var seq[byte]): Result[Header, string] =
  let header = ? readHeader(f)
  if header.len > 0:
    ? f.checkBytesLeft(header.len)

    if data.len != header.len:
      data = newSeqUninitialized[byte](header.len)

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


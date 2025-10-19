# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles,
  snappy,
  spec/datatypes/constants,
  spec/eth2_ssz_serialization

# No `uint64` support in Sqlite
template isSupportedBySQLite*(slot: Slot): bool =
  slot <= int64.high.Slot
template isSupportedBySQLite*(period: SyncCommitteePeriod): bool =
  period <= int64.high.SyncCommitteePeriod

template disposeSafe*(s: untyped): untyped =
  if distinctBase(s) != nil:
    s.dispose()
    s = typeof(s)(nil)

proc decodeSZSSZ*[T](
    data: openArray[byte], output: var T, updateRoot = false): bool =
  try:
    let decompressed = decodeFramed(data, checkIntegrity = false)
    readSszBytes(decompressed, output, updateRoot)
    true
  except CatchableError as e:
    # If the data can't be deserialized, it could be because it's from a
    # version of the software that uses a different SSZ encoding
    warn "Unable to deserialize data, old database?",
      err = e.msg, typ = name(T), dataLen = data.len
    false

func encodeSZSSZ*(v: auto): seq[byte] =
  # https://github.com/google/snappy/blob/main/framing_format.txt
  try:
    encodeFramed(SSZ.encode(v))
  except CatchableError as err:
    # In-memory encode shouldn't fail!
    raiseAssert err.msg

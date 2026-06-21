# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  stew/bitops2,
  ../spec/datatypes/fulu

from std/sequtils import mapIt
from std/strutils import join

static:
  doAssert(NUMBER_OF_COLUMNS == 2 * 64, "ColumnMap should be updated")

type
  ColumnMap* = object
    data: array[2, uint64]

template getPos(column: ColumnIndex): tuple[index: int, offset: int] =
  (int(uint64(column) shr 6), int(uint64(column) and 0x3F'u64))

func contains*(a: ColumnMap, column: ColumnIndex): bool =
  if uint64(column) >= NUMBER_OF_COLUMNS:
    return false
  let (index, offset) = column.getPos()
  a.data[index].getBit(offset)

func incl*(a: var ColumnMap, column: ColumnIndex) =
  if uint64(column) >= NUMBER_OF_COLUMNS:
    return
  let (index, offset) = column.getPos()
  a.data[index].setBit(offset)

func excl*(a: var ColumnMap, column: ColumnIndex) =
  if uint64(column) >= NUMBER_OF_COLUMNS:
    return
  let (index, offset) = column.getPos()
  a.data[index].clearBit(offset)

func init*(t: typedesc[ColumnMap], columns: openArray[ColumnIndex]): ColumnMap =
  ## NOTE: `columns` array's content should be checked before running this
  ## function. Function will assert if `ColumnIndex >= NUMBER_OF_COLUMNS`.
  var res: ColumnMap
  for column in columns:
    if uint64(column) >= NUMBER_OF_COLUMNS:
      raiseAssert "Incorrect column index, " & $uint64(column)
    let (index, offset) = column.getPos()
    res.data[index].setBit(offset)
  res

func `and`*(a, b: ColumnMap): ColumnMap =
  ColumnMap(data: [a.data[0] and b.data[0], a.data[1] and b.data[1]])

func `or`*(a, b: ColumnMap): ColumnMap =
  ColumnMap(data: [a.data[0] or b.data[0], a.data[1] or b.data[1]])

func `xor`*(a, b: ColumnMap): ColumnMap =
  ColumnMap(data: [a.data[0] xor b.data[0], a.data[1] xor b.data[1]])

func `not`*(a: ColumnMap): ColumnMap =
  ColumnMap(data: [not(a.data[0]), not(a.data[1])])

func `==`*(a, b: ColumnMap): bool =
  (a.data[0] == b.data[0]) and (a.data[1] == b.data[1])

func empty*(a: ColumnMap): bool =
  (a.data[0] == 0'u64) and (a.data[1] == 0'u64)

iterator items*(a: ColumnMap): ColumnIndex =
  var
    data0 = a.data[0]
    data1 = a.data[1]

  while data0 != 0'u64:
    let
      # t = data0 and -data0
      t = data0 and (not(data0) + 1'u64)
      res = firstOne(data0)
    yield ColumnIndex(res - 1)
    data0 = data0 xor t

  while data1 != 0'u64:
    let
      # t = data0 and -data0
      t = data1 and (not(data1) + 1'u64)
      res = firstOne(data1)
    yield ColumnIndex(64 + res - 1)
    data1 = data1 xor t

iterator pairs*(a: ColumnMap): (int, ColumnIndex) =
  var index = 0
  for item in a.items():
    yield (index, item)
    inc(index)

func len*(a: ColumnMap): int =
  # Returns number of columns in map.
  countOnes(a.data[0]) + countOnes(a.data[1])

func `$`*(a: ColumnMap): string =
  "[" & a.mapIt($it).join(", ") & "]"

func shortLog*(a: ColumnMap): string =
  if len(a) > NUMBER_OF_COLUMNS div 2:
    return "[supernode]"
  $a

func supernodeMap*(): ColumnMap =
  ColumnMap(data: [0xFFFF_FFFF_FFFF_FFFF'u64, 0xFFFF_FFFF_FFFF_FFFF'u64])

func lightSupernodeMap*(): ColumnMap =
  ColumnMap(data: [0xFFFF_FFFF_FFFF_FFFF'u64, 0'u64])

# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[strutils, sequtils], unittest2,
  ../beacon_chain/spec/column_map,
  ../beacon_chain/spec/datatypes/fulu

suite "ColumnMap test suite":
  test "fill test":
    # Filling columns of different sizes with all bits [4, 128)
    for columnSize in 4 .. 128:
      let
        columnsCount = 128 div columnSize
        lastColumnSize = 128 mod columnSize

      for i in 0 ..< columnsCount:
        let
          start = i * columnSize
          finish = start + columnSize
        var
          columns: seq[ColumnIndex]
          numbers: seq[int]

        for k in start ..< finish:
          columns.add(ColumnIndex(k))
          numbers.add(k)

        check:
          $ColumnMap.init(columns) ==
            "[" & $ numbers.mapIt($it).join(", ") & "]"

      if lastColumnSize > 0:
        let
          start = columnsCount * columnSize
          finish = start + lastColumnSize
        var
          columns: seq[ColumnIndex]
          numbers: seq[int]
        for k in start ..< finish:
          columns.add(ColumnIndex(k))
          numbers.add(k)

        check:
          $ColumnMap.init(columns) ==
            "[" & $ numbers.mapIt($it).join(", ") & "]"

  test "and() operation test":
    const TestVectors = [
      (
        [1, 2, 3, 4, 5, 6, 7, 8],
        [5, 6, 7, 8, 9, 10, 11, 12],
        "[5, 6, 7, 8]"
      ),
      (
        [56, 57, 58, 59, 60, 61, 62, 63],
        [60, 61, 62, 63, 64, 65, 66, 67],
        "[60, 61, 62, 63]"
      ),
      (
        [1, 5, 10, 15, 20, 25, 64, 65],
        [1, 5, 6, 7, 8, 9, 64, 65],
        "[1, 5, 64, 65]"
      ),
      (
        [60, 61, 62, 63, 124, 125, 126, 127],
        [60, 61, 62, 63, 124, 125, 126, 127],
        "[60, 61, 62, 63, 124, 125, 126, 127]"
      ),
      (
        [0, 1, 63, 64, 65, 93, 126, 127],
        [0, 2, 63, 64, 67, 94, 126, 127],
        "[0, 63, 64, 126, 127]"
      )
    ]

    for vector in TestVectors:
      let
        map1 = ColumnMap.init(vector[0].mapIt(ColumnIndex(it)))
        map2 = ColumnMap.init(vector[1].mapIt(ColumnIndex(it)))
      check:
        $(map1 and map2) == vector[2]

    for vector in TestVectors:
      let
        map1 = ColumnMap.init(vector[0].mapIt(ColumnIndex(it)))
        map2 = ColumnMap.init(vector[1].mapIt(ColumnIndex(it)))
        map3 = map1 and map2

      check:
        map1.items().toSeq().mapIt($int(it)).join(", ") ==
          vector[0].mapIt($it).join(", ")
        map2.items().toSeq().mapIt($int(it)).join(", ") ==
          vector[1].mapIt($it).join(", ")
        "[" & map3.items().toSeq().mapIt($int(it)).join(", ") & "]" ==
          vector[2]

  test "supernode test":
    for max in ((NUMBER_OF_COLUMNS div 2) + 1) ..< NUMBER_OF_COLUMNS:
      var columns: seq[ColumnIndex]
      for i in 0 ..< max:
        columns.add(ColumnIndex(i))
      let map = ColumnMap.init(columns)
      check:
        map.items().toSeq().mapIt($int(it)).join(", ") ==
          columns.mapIt($it).join(", ")
        shortLog(map) == "[supernode]"

  test "contains() test":
    for i in 0 ..< NUMBER_OF_COLUMNS:
      let testMap = ColumnMap.init([ColumnIndex(i)])
      for k in 0 ..< NUMBER_OF_COLUMNS:
        if k == i:
          check ColumnIndex(k) in testMap == true
        else:
          check ColumnIndex(k) in testMap == false

  test "incl()/excl() test":
    for i in 0 ..< NUMBER_OF_COLUMNS:
      var map: ColumnMap
      for k in 0 ..< NUMBER_OF_COLUMNS:
        map.incl(ColumnIndex(k))
        check:
          ColumnIndex(k) in map == true
        map.excl(ColumnIndex(k))
        check:
          ColumnIndex(k) notin map == true

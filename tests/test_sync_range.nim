# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

{.used.}

import std/[sequtils, strutils],
       unittest2,
       ../beacon_chain/sync/sync_range

suite "SyncRange test suite":
  test "init() test":
    const
      TestVectors1 = [
        (Slot(0), 32, "[0:31]", Slot(31)),
        (Slot(32), 32, "[32:63]", Slot(63)),
        (Slot(32000000), 32, "[32000000:32000031]", Slot(32000031)),
        (Slot(0), 64, "[0:63]", Slot(63)),
        (Slot(64), 64, "[64:127]", Slot(127)),
        (Slot(32000000), 64, "[32000000:32000063]", Slot(32000063)),
        (Slot(500000), 1, "[500000:500000]", Slot(500000)),
        (Slot(500), 0, "[empty]", FAR_FUTURE_SLOT)
      ]
      TestVectors2 = [
        (Slot(0), Slot(31), "[0:31]", Slot(31)),
        (Slot(32), Slot(63), "[32:63]", Slot(63)),
        (Slot(32000000), Slot(32000031), "[32000000:32000031]", Slot(32000031)),
        (Slot(0), Slot(63), "[0:63]", Slot(63)),
        (Slot(64), Slot(127), "[64:127]", Slot(127)),
        (Slot(32000000), Slot(32000063), "[32000000:32000063]", Slot(32000063)),
        (Slot(50000), Slot(50000), "[50000:50000]", Slot(50000))
      ]
    for vector in TestVectors1:
      let sr = SyncRange.init(vector[0], uint64(vector[1]))
      check $sr == vector[2]
      if not(sr.isEmpty()):
        check:
          sr.start_slot() == vector[0]
          sr.last_slot() == vector[3]
      else:
        expect(Defect):
          discard sr.start_slot()
        expect(Defect):
          discard sr.last_slot()

    for vector in TestVectors2:
      check $SyncRange.init(vector[0], vector[1]) == vector[2]
    check $SyncRange.init() == "[empty]"

  test "contains() test":
    const
      TestVectors = [
        (Slot(0), Slot(31),
          @[(0 .. 31, true), (32 .. 64, false)]),
        (Slot(128), Slot(159),
          @[(128 .. 159, true), (96 .. 127, false), (160 .. 191, false)]),
        (Slot(0), Slot(127),
          @[(0 .. 127, true), (128 .. 192, false)]),
        (Slot(128), Slot(255),
          @[(128 .. 255, true), (0 .. 127, false), (256 .. 512, false)])
      ]

    for vector in TestVectors:
      let srange = SyncRange.init(vector[0], vector[1])
      for item in vector[2]:
        for slotnum in item[0]:
          check:
            contains(srange, Slot(slotnum)) == item[1]
            Slot(slotnum) in srange == item[1]

    var erange = SyncRange.init()

    for slot in Slot(0) .. Slot(31):
      check:
        contains(erange, slot) == false
        slot in erange == false

  test "split() test":
    const TestVectors = [
      (Slot(0), Slot(3), Slot(0), "[0:0]", "[1:3]"),
      (Slot(0), Slot(3), Slot(1), "[0:1]", "[2:3]"),
      (Slot(0), Slot(3), Slot(2), "[0:2]", "[3:3]"),
      (Slot(0), Slot(3), Slot(3), "[0:3]", "[empty]"),
      (Slot(10), Slot(13), Slot(10), "[10:10]", "[11:13]"),
      (Slot(10), Slot(13), Slot(11), "[10:11]", "[12:13]"),
      (Slot(10), Slot(13), Slot(12), "[10:12]", "[13:13]"),
      (Slot(10), Slot(13), Slot(13), "[10:13]", "[empty]")
    ]
    for vector in TestVectors:
      let
        msr = SyncRange.init(vector[0], vector[1])
        (sr1, sr2) = msr.split(vector[2])
      check:
        $sr1 == vector[3]
        $sr2 == vector[4]

  test "iterator test":
    const TestVectors = [
      (Slot(0), Slot(5), "[0,1,2,3,4,5]"),
      (Slot(0), Slot(0), "[0]"),
      (Slot(100), Slot(100), "[100]"),
    ]
    for vector in TestVectors:
      let
        msr = SyncRange.init(vector[0], vector[1])
      check:
        "[" & msr.items().toSeq().mapIt($int(it)).join(",") & "]" == vector[2]

    let esr = SyncRange.init()
    check:
      "[" & esr.items().toSeq().mapIt($int(it)).join(",") & "]" == "[]"

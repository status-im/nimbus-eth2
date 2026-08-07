# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import stew/base10
import ../spec/beacon_time

export beacon_time

type
  SyncQueueKind* {.pure.} = enum
    Forward, Backward

  SyncRange* = object
    slot*: Slot
    count*: uint64

template isEmpty*(sr: SyncRange): bool =
  ## Returns `true` when sync range `sr` is empty.
  sr.count == 0'u64

func `$`*(srange: SyncRange): string =
  if isEmpty(srange):
    "[empty]"
  else:
    "[" & Base10.toString(uint64(srange.slot)) & ":" &
      Base10.toString(uint64(srange.slot + srange.count - 1)) & "]"

func init*(t: typedesc[SyncRange], start_slot, last_slot: Slot): SyncRange =
  if last_slot < start_slot:
    SyncRange(slot: last_slot, count: (start_slot - last_slot) + 1)
  else:
    SyncRange(slot: start_slot, count: (last_slot - start_slot) + 1)

func init*(t: typedesc[SyncRange], slot: Slot, count: uint64): SyncRange =
  if uint64(slot) + count < uint64(slot):
    # `uint64` overflow, so we create range which is limited by FAR_FUTURE_SLOT.
    SyncRange.init(slot, FAR_FUTURE_SLOT)
  else:
    SyncRange(slot: slot, count: count)

func init*(t: typedesc[SyncRange]): SyncRange =
  ## Create new empty sync range.
  SyncRange.init(FAR_FUTURE_SLOT, 0'u64)

func start_slot*(sr: SyncRange): Slot {.inline.} =
  ## Returns start slot in range `sr`.
  doAssert(not(sr.isEmpty()), "Range must not be empty!")
  sr.slot

func last_slot*(sr: SyncRange): Slot {.inline.} =
  ## Returns last slot in range `sr`.
  doAssert(not(sr.isEmpty()), "Range must not be empty!")
  if sr.slot + (uint64(sr.count) - 1'u64) < sr.slot:
    FAR_FUTURE_SLOT
  else:
    sr.slot + (uint64(sr.count) - 1'u64)

func contains*(sr: SyncRange, slot: Slot): bool {.inline.} =
  ## Returns `true` if `slot` is in range of `sr`.
  if sr.isEmpty():
    return false
  (slot >= sr.start_slot()) and (slot <= sr.last_slot())

func `<=`*(sr: SyncRange, b: Slot): bool {.inline.} =
  ## Returns `true` if all slots in range `sr` are equal or smaller than
  ## slot `b`.
  sr.last_slot() <= b

func `<`*(a: Slot, sr: SyncRange): bool {.inline.} =
  ## Returns `true` if all slots in range `sr` are bigger than slot `a`.
  a < sr.start_slot()

func `<`*(sr: SyncRange, b: Slot): bool {.inline.} =
  ## Returns `true` if all slots in range `a` are smaller than slot `b`.
  sr.last_slot() < b

func `<`*(a, b: SyncRange): bool {.inline.} =
  ## Returns `true` if range `a` is below of range `b`.
  a.last_slot() < b.start_slot()

func split*(a: SyncRange, b: Slot): tuple[left: SyncRange, right: SyncRange] =
  doAssert(b in a, "Slot should be inside the range")
  let
    left = SyncRange.init(a.start_slot(), b)
    right =
      if b + 1 < b:
        SyncRange.init()
      else:
        if a.last_slot() == b:
          SyncRange.init()
        else:
          SyncRange.init(b + 1, a.last_slot())
  (left, right)

func `==`*(a, b: SyncRange): bool {.inline.} =
  (a.slot == b.slot) and (a.count == b.count)

iterator items*(srange: SyncRange): Slot =
  if not(srange.isEmpty()):
    for slot in srange.slot .. (srange.slot + srange.count - 1):
      yield slot

# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[strutils, sequtils, algorithm]
import stew/base10, chronos, chronicles, results
import
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/rest_types,
  ../spec/[helpers, forks, network, peerdas_helpers],
  ../networking/[peer_pool, peer_scores, eth2_network],
  ../gossip_processing/block_processor,
  ../beacon_clock,
  "."/[sync_protocol, column_syncer, sync_queue]

export phase0, altair, merge, chronos, chronicles, results,
       helpers, peer_scores, sync_queue, forks, sync_protocol

type
  ColumnSyncWaiter* = ref object
    future: Future[void].Raising([CancelledError])
    reset: bool

  ColumnSyncerAssist*[T] = ref object
    inpSlot*: Slot
    outSlot*: Slot
    startSlot*: Slot
    finalSlot*: Slot
    counter*: uint64
    received_table*: ColumnSyncerTable
    pending*: Table[uint64, ColumnSyncRequest[T]]
    gapList*: seq[GapItem[T]]
    waiters*: seq[ColumnSyncWaiter]
    getSafeSlot*: GetSlotCallback

proc init[T](t: typedesc[ColumnSyncRequest],
             start: Slot,
             finish: Slot):
             ColumnSyncRequest[T] =
  let count = finish - start + 1'u64
  ColumnSyncRequest[T](slot: start, count: count)

proc init[T](t: typedesc[ColumnSyncRequest],
             start: Slot,
             count: uint64,
             item: T):
             ColumnSyncRequest[T] =
  ColumnSyncRequest[T](slot: start, count: count, item: item)

proc init[T](t: typedesc[ColumnSyncRequest],
             start: Slot,
             finish: Slot,
             item: T):
             ColumnSyncRequest[T] =
  let count = finish - start + 1'u64
  ColumnSyncRequest[T](slot: start, count: count, item: item)

proc empty*[T](t: typedesc[ColumnSyncRequest]):
               ColumnSyncRequest[T] {.inline.} =
  ColumnSyncRequest[T](count: 0'u64)

proc setItem*[T](r: var ColumnSyncRequest[T], item: T):
                 bool {.inline.} =
  r.item = item

proc isReqEmpty*[T](r: ColumnSyncRequest[T]):
                    bool {.inline.} =
  (r.count == 0'u64)

template shortLog*[T](req: ColumnSyncRequest[T]): string =
  Base10.toString(uint64(req.slot)) & ":" &
  Base10.toString(req.count) & "@" &
  Base10.toString(req.index)

proc contains*[T](req: ColumnSyncRequest, slot: Slot): bool {.inline.} =
  slot >= req.slot and slot < req.slot + req.count

proc cmp*[T](a, b: ColumnSyncRequest[T]): int =
  cmp(uint64(a.slot), uint64(b.slot))

proc checkDataColumnResponse*[T](req: ColumnSyncRequest[T],
                                 data: openArray[Slot]):
                                 Result[void, string] =
  if data.len == 0:
    return ok()

  if lenu64(data) > (req.count * NUMBER_OF_COLUMNS):
    # Number of data columns in the response should be less than
    # or equal to (MAX_BLOBS_PER_BLOCK_FULU * NUMBER_OF_COLUMNS).
    return err ("Too many data columns have been received")

  var
    pSlot = data[0]
    counter = 0'u64
  for slot in data:
    if (slot < req.slot) or (slot >= req.slot + req.count):
      return err ("Some of the data columns are not in the range")
    if slot < pSlot:
      return err ("Data columns have been sent in incorrect order")
    if slot == pSlot:
      inc counter
      # keeping this constant Electra until Fulu comes in
      if counter > MAX_BLOBS_PER_BLOCK_ELECTRA:
        return err ("Number of data columns in the block has exceeded the limit")
    else:
      counter = 1'u64
    pSlot = slot

  ok()

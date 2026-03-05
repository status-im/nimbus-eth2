# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[
  deques, heapqueue, sets, tables, strutils, sequtils, math, typetraits]
import stew/base10, chronos, chronicles, results
import
  ../spec/[helpers, forks, column_map],
  ../networking/[peer_pool, eth2_network],
  ../gossip_processing/block_processor,
  ../consensus_object_pools/block_pools_types

export base, phase0, altair, merge, chronos, chronicles, results,
       block_pools_types, helpers

type
  GetSlotCallback* = proc(): Slot {.gcsafe, raises: [].}
  GetBoolCallback* = proc(): bool {.gcsafe, raises: [].}
  ProcessingCallback* = proc() {.gcsafe, raises: [].}
  PeerMapCallback*[T] = proc(peer: T): ColumnMap {.gcsafe, raises: [].}
  LocalColumnMapCallback* = proc(): ColumnMap {.gcsafe, raises: [].}
  MissingMapCallback* = proc(root: Eth2Digest): ColumnMap {.gcsafe, raises: [].}
  BlockVerifier* =
    proc(signedBlock: ref ForkedSignedBeaconBlock, maybeFinalized: bool):
      Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}
  ForkAtEpochCallback* =
    proc(epoch: Epoch): ConsensusFork {.gcsafe, raises: [].}

  UniqueId* = distinct uint64

  SyncRange* = object
    slot*: Slot
    count*: uint64

  SyncPosition* = object
    qindex*: int
    sindex*: int

  SyncQueueKind* {.pure.} = enum
    Forward, Backward

  SyncRequestFlag* {.pure.} = enum
    Void

  SyncRequestReason* {.pure.} = enum
    NoMoreSpace, PeerSlotKnowledge, TooBigDistance

  BlockCompleteness* = object
    count: int
    done: bool

  ColumnCompleteness* = object
    map: ColumnMap
    keys: HashSet[string]
    done: bool

  SomeCompleteness* = BlockCompleteness | SomeCompleteness

  SyncRequest*[T] = object
    kind*: SyncQueueKind
    id*: UniqueId
    data*: SyncRange
    flags*: set[SyncRequestFlag]
    reason*: SyncRequestReason
    item*: T

  SyncQueueItem[M, N] = object
    requests: seq[SyncRequest[M]]
    data: SyncRange
    completeness: N
    failuresCount: Natural
    voidsCount: Natural

  SyncWaiterItem[T] = ref object
    future: Future[void].Raising([CancelledError])
    request: SyncRequest[T]
    resetFlag: bool

  SyncProcessError* {.pure.} = enum
    Invalid,
    MissingParent,
    GoodAndMissingParent,
    UnviableFork,
    Duplicate,
    Empty,
    MissingSidecars,
    NoRelevant,
    NoError

  SyncProcessingResult = object
    code: SyncProcessError
    blck: Opt[BlockId]

  SyncPushResponse* = object
    code*: SyncProcessError
    count*: int64
    blck*: Opt[BlockId]

  GapItem[T] = object
    data: SyncRange
    item: T

  RewindPoint = object
    failSlot: Slot
    epochCount: uint64

  SyncQueue*[M, N] = ref object
    kind*: SyncQueueKind
    inpSlot*: Slot
    outSlot*: Slot
    startSlot*: Slot
    finalSlot*: Slot
    rewind: Opt[RewindPoint]
    chunkSize: uint64
    requestsCount: Natural
    failureResetThreshold: Natural
    maxSlotDistance: Natural
    requests: Deque[SyncQueueItem[M, N]]
    getSafeSlot: GetSlotCallback
    blockVerifier: BlockVerifier
    forkAtEpoch: ForkAtEpochCallback
    cbGetColumnMap: PeerMapCallback[M]
    cbGetMissingMap: MissingMapCallback
    cbGetLocalColumnMap: LocalColumnMapCallback
    waiters: seq[SyncWaiterItem[M]]
    gapList: seq[GapItem[M]]
    lock: AsyncLock
    uniqId: uint64
    skipId: uint64
    ident: string

proc `$`*(srange: SyncRange): string =
  if (srange.slot == FAR_FUTURE_SLOT) and (srange.count == 0):
    "[empty]"
  else:
    "[" & Base10.toString(uint64(srange.slot)) & ":" &
      Base10.toString(uint64(srange.slot + srange.count - 1)) & "]"

template shortLog*[T](req: SyncRequest[T]): string =
  if (req.data.slot == FAR_FUTURE_SLOT) and (req.data.count == 0):
    "[empty]"
  else:
    $req.data & "@" & Base10.toString(req.data.count)

chronicles.formatIt SyncQueueKind: toLowerAscii($it)
chronicles.expandIt SyncRequest:
  `it` = shortLog(it)
  peer = shortLog(it.item)
  direction = toLowerAscii($it.kind)

func shortLog(data: BlockCompleteness): string =
  if data.done:
    "complete"
  else:
    $data.count

func shortLog(data: ColumnCompleteness): string =
  if data.done:
    "complete"
  else:
    $len(data.map)

func getId[M, N](sq: SyncQueue[M, N]): UniqueId =
  inc(sq.uniqId)
  UniqueId(sq.uniqId)

proc shortLog*[M, N](sq: SyncQueue[M, N]): string =
  if isNil(sq):
    "[empty]"
  else:
    let start =
      case sq.kind
      of SyncQueueKind.Forward:
        "[F:"
      of SyncQueueKind.Backward:
        "[B:"
    start & $sq.startSlot & ":" & $sq.finalSlot & "@" & $sq.inpSlot & "]"

func slimLog*(blocks: openArray[ref ForkedSignedBeaconBlock]): string =
  "[" & blocks.mapIt(
    "(slot: " & $it[].slot() & ", root: " & shortLog(it[].root()) &
    ", parent_root: " & shortLog(it[].parent_root()) & ")").join(",") & "]"

func getShortMap*[T](
    req: SyncRequest[T],
    data: openArray[ref ForkedSignedBeaconBlock]
): string =
  ## Returns all slot numbers in ``data`` as placement map.
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    last = 0

  for i in 0 ..< req.data.count:
    if last < len(data):
      for k in last ..< len(data):
        if slider == data[k][].slot:
          res.add('x')
          last = k + 1
          break
        elif slider < data[k][].slot:
          res.add('.')
          break
    else:
      res.add('.')
    slider = slider + 1
  res

func getBlockBlobsMap*[T](
    req: SyncRequest[T],
    data: openArray[ref ForkedSignedBeaconBlock]
): string =
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    last = 0

  for i in 0 ..< req.data.count:
    if last < len(data):
      for k in last ..< len(data):
        let (slot, count) =
          withBlck(data[k][]):
            when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
              (forkyBlck.message.slot,
                len(forkyBlck.message.body.blob_kzg_commitments))
            else:
              (forkyBlck.message.slot, 0)
        if slider == slot:
          res.add($count)
          last = k + 1
          break
        elif slider < slot:
          res.add('.')
          break
    else:
      res.add('.')
    slider = slider + 1

  res

proc getShortMap*[T](
    req: SyncRequest[T],
    data: openArray[ref BlobSidecar]
): string =
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    last = 0

  for i in 0 ..< req.data.count:
    if last < len(data):
      var counter = 0
      for k in last ..< len(data):
        if slider < data[k][].signed_block_header.message.slot:
          break
        elif slider == data[k][].signed_block_header.message.slot:
          inc(counter)
      last = last + counter
      if counter == 0:
        res.add('.')
      else:
        res.add($counter)
    else:
      res.add('.')
    slider = slider + 1
  res

proc getShortMap*[T](
    req: SyncRequest[T],
    blobs: openArray[BlobSidecars]
): string =
  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    notFirst = false

  for i in 0 ..< int(req.data.count):
    if i >= len(blobs):
      res.add('.'.repeat(int(req.data.count) - len(res)))
      return res

    if len(blobs[i]) > 0:
      let slot = blobs[i][0][].signed_block_header.message.slot
      if not(notFirst):
        doAssert(slot >= slider, "Incorrect slot number in blobs list")
        let firstCount = int(slot - slider)
        res.add('.'.repeat(firstCount))
        res.add(Base10.toString(lenu64(blobs[i])))
        slider = slot
        notFirst = true
      else:
        if slot == slider:
          res.add(Base10.toString(lenu64(blobs[i])))
        else:
          res.add('.')
    else:
      if notFirst: res.add('.')
    if notFirst: inc(slider)
  res

proc getShortMap*[T](
    req: SyncRequest[T],
    data: Opt[seq[BlobSidecars]]
): string =
  if data.isNone():
    return '.'.repeat(req.data.count)
  getShortMap(req, data.get())

func getShortMap*[T](
    req: SyncRequest[T],
    map: ColumnMap,
    data: openArray[ref fulu.DataColumnSidecar]
): string =
  let
    alphabet =
      "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/#-"
    unknown = "…"

  var
    res = newStringOfCap(req.data.count)
    slider = req.data.slot
    last = 0

  for i in 0 ..< req.data.count:
    if last < len(data):
      var counter = 0
      for k in last ..< len(data):
        if slider < data[k][].signed_block_header.message.slot:
          break
        elif slider == data[k][].signed_block_header.message.slot:
          if data[k][].index in map:
            inc(counter)
      last = last + counter
      if counter == 0:
        res.add('.')
      else:
        if counter < 66:
          res.add(alphabet[counter - 1])
        else:
          res.add(unknown)
    else:
      res.add('.')
    slider = slider + 1
  res

func isComplete[M, N](
    sq: SyncQueue[M, N],
    srange: SyncRange,
    peer: M,
    criteria: var N
): bool =
  mixin getKey
  if criteria.done:
    return true
  when N is BlockCompleteness:
    criteria.count >= sq.requestsCount
  elif N is ColumnCompleteness:
    if criteria.map.empty():
      # If criteria's map is empty, it means that we do not need columns for
      # the range.
      return true
    if $(peer.getKey()) in criteria.keys:
      # Columns was already downloaded from this peer for the range, there is no
      # reason to request it one more time.
      return true
    # If the peer has columns that we are still missing, we should return
    # `false`, so that peer will get request for that range, but if the peer
    # does not have the columns we need, we should return `true`.
    (criteria.map and sq.cbGetColumnMap(peer)).empty()

proc drainCompleteness[M, N](
    sq: SyncQueue[M, N],
    srange: SyncRange,
    peer: M,
    criteria: var N
) =
  when N is BlockCompleteness:
    inc(criteria.count)
  elif N is ColumnCompleteness:
    criteria.map = criteria.map and
      not(sq.cbGetLocalColumnMap() and sq.cbGetColumnMap(peer))

func fillCompleteness[M](
    sq: SyncQueue[M, BlockCompleteness],
    srange: SyncRange,
    peer: M,
    done: bool,
    criteria: var BlockCompleteness
) =
  if done:
    criteria.done = true
  dec(criteria.count)

func fillCompleteness[M](
    sq: SyncQueue[M, ColumnCompleteness],
    srange: SyncRange,
    peer: M,
    missingMap: Opt[ColumnMap],
    done: bool,
    storePeer: bool,
    criteria: var ColumnCompleteness
) =
  mixin getKey

  if done:
    criteria.done = true
    criteria.map = ColumnMap()
    return

  if storePeer:
    let key = peer.getKey()
    criteria.keys.incl($key)

  if missingMap.isSome():
    criteria.map = missingMap.get()

func init*(t: typedesc[SyncRange], slot: Slot, count: uint64): SyncRange =
  SyncRange(slot: slot, count: count)

func init(t: typedesc[SyncProcessError],
          kind: VerifierError): SyncProcessError =
  case kind
  of VerifierError.Invalid:
    SyncProcessError.Invalid
  of VerifierError.MissingParent:
    SyncProcessError.MissingParent
  of VerifierError.UnviableFork:
    SyncProcessError.UnviableFork
  of VerifierError.Duplicate:
    SyncProcessError.Duplicate
  of VerifierError.MissingSidecars:
    SyncProcessError.MissingSidecars

func init(t: typedesc[SyncProcessError]): SyncProcessError =
  SyncProcessError.NoError

func init(t: typedesc[SyncProcessingResult], se: SyncProcessError,
          slot: Slot, root: Eth2Digest): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(BlockId(slot: slot, root: root)),
    code: se)

func init(t: typedesc[SyncProcessingResult],
          se: SyncProcessError): SyncProcessingResult =
  SyncProcessingResult(code: se)

func init(t: typedesc[SyncProcessingResult], se: SyncProcessError,
          sblck: BlockId): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(sblck), code: se)

func init(t: typedesc[SyncProcessingResult], ve: VerifierError,
          slot: Slot, root: Eth2Digest): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(BlockId(slot: slot, root: root)),
    code: SyncProcessError.init(ve))

func init(t: typedesc[SyncProcessingResult], ve: VerifierError,
          sblck: BlockId): SyncProcessingResult =
  SyncProcessingResult(blck: Opt.some(sblck), code: SyncProcessError.init(ve))

func init*[T](
    t: typedesc[SyncRequest],
    kind: SyncQueueKind,
    item: T,
    reason: SyncRequestReason
): SyncRequest[T] =
  SyncRequest[T](
    kind: kind,
    data: SyncRange(slot: FAR_FUTURE_SLOT, count: 0'u64),
    item: item,
    reason: reason
  )

func init*[M, N](
    t: typedesc[SyncRequest],
    sq: SyncQueue[M, N],
    kind: SyncQueueKind,
    data: SyncRange,
    item: M
): SyncRequest[M] =
  SyncRequest[M](
    kind: kind,
    data: data,
    item: item,
    id: sq.getId()
  )

func init[M, BlockCompleteness](
    t1: typedesc[SyncQueueItem],
    t2: typedesc[BlockCompleteness],
    req: SyncRequest[M]
): SyncQueueItem[M, BlockCompleteness] =
  SyncQueueItem[M, BlockCompleteness](
    data: req.data,
    requests: @[req],
    completeness: BlockCompleteness()
  )

func init[M, ColumnCompleteness](
    t1: typedesc[SyncQueueItem],
    t2: typedesc[ColumnCompleteness],
    req: SyncRequest[M],
    localMap: ColumnMap
): SyncQueueItem[M, ColumnCompleteness] =
  SyncQueueItem[M, ColumnCompleteness](
    data: req.data,
    requests: @[req],
    completeness: ColumnCompleteness(map: localMap)
  )

func init[T](
    t: typedesc[GapItem],
    req: SyncRequest[T]
): GapItem[T] =
  GapItem[T](data: req.data, item: req.item)

func last_slot*(epoch: Epoch): Slot =
  ## Return the start slot of ``epoch``.
  const maxEpoch = Epoch(FAR_FUTURE_SLOT div SLOTS_PER_EPOCH)
  if epoch >= maxEpoch: FAR_FUTURE_SLOT
  else: Slot(epoch * SLOTS_PER_EPOCH + (SLOTS_PER_EPOCH - 1'u64))

template start_slot*(sr: SyncRange): Slot =
  sr.slot

template last_slot*(sr: SyncRange): Slot =
  if sr.slot + (uint64(sr.count) - 1'u64) < sr.slot:
    FAR_FUTURE_SLOT
  else:
    sr.slot + (uint64(sr.count) - 1'u64)

proc epochFilter*[M, N](
    squeue: SyncQueue[M, N], srange: SyncRange
): SyncRange =
  case squeue.kind
  of SyncQueueKind.Forward:
    let
      startEpoch = srange.slot.epoch()
      startFork = squeue.forkAtEpoch(startEpoch)

    var currentEpoch = startEpoch
    while (currentEpoch.start_slot() <= srange.last_slot()) and
          (squeue.forkAtEpoch(currentEpoch) == startFork) and
          (currentEpoch != FAR_FUTURE_EPOCH):
      currentEpoch += 1

    if (currentEpoch.start_slot() <= srange.last_slot()) and
       (squeue.forkAtEpoch(currentEpoch) != startFork):
      SyncRange(
        slot: srange.start_slot(),
        count: currentEpoch.start_slot() - srange.slot)
    else:
      srange
  of SyncQueueKind.Backward:
    let
      startEpoch = srange.last_slot().epoch()
      startFork = squeue.forkAtEpoch(startEpoch)

    var currentEpoch = startEpoch
    while (currentEpoch.last_slot() >= srange.start_slot()) and
          (squeue.forkAtEpoch(currentEpoch) == startFork) and
          (currentEpoch != GENESIS_EPOCH):
      currentEpoch -= 1

    if (currentEpoch.last_slot() >= srange.start_slot()) and
       (squeue.forkAtEpoch(currentEpoch) != startFork):
      let ncount = srange.last_slot() - (currentEpoch + 1).start_slot() + 1'u64
      SyncRange(slot: (currentEpoch + 1).start_slot(), count: ncount)
    else:
      srange

func next*[M, N](
    sq: SyncQueue[M, N],
    currentSlot: Slot
): Opt[SyncRange] {.inline.} =
  if currentSlot == FAR_FUTURE_SLOT:
    # Finish range
    return Opt.none(SyncRange)

  let slot = currentSlot + sq.chunkSize
  if slot < currentSlot:
    # Range that causes uint64 overflow, fixing.
    if currentSlot < sq.finalSlot:
      Opt.some(SyncRange.init(currentSlot, sq.finalSlot - currentSlot + 1))
    else:
      Opt.some(SyncRange.init(currentSlot, FAR_FUTURE_SLOT - currentSlot))
  else:
    if slot > sq.finalSlot:
      Opt.some(SyncRange.init(currentSlot, sq.finalSlot - currentSlot + 1))
    else:
      Opt.some(SyncRange.init(currentSlot, sq.chunkSize))

func prev*[M, N](
    sq: SyncQueue[M, N],
    currentSlot: Slot
): Opt[SyncRange] {.inline.} =
  if currentSlot == GENESIS_SLOT:
    # Start range
    return Opt.none(SyncRange)

  let slot = currentSlot - sq.chunkSize
  if slot > currentSlot:
    # Range that causes uint64 underflow, fixing.
    if currentSlot > sq.finalSlot:
      Opt.some(SyncRange.init(sq.finalSlot, currentSlot - sq.finalSlot))
    else:
      Opt.some(SyncRange.init(GENESIS_SLOT, uint64(currentSlot)))
  else:
    if slot < sq.finalSlot:
      Opt.some(SyncRange.init(sq.finalSlot, currentSlot - sq.finalSlot))
    else:
      Opt.some(SyncRange.init(slot, sq.chunkSize))

func contains*(srange: SyncRange, slot: Slot): bool {.inline.} =
  ## Returns `true` if `slot` is in range of `srange`.
  if (srange.slot + srange.count) < srange.slot:
    (slot >= srange.slot) and (slot <= FAR_FUTURE_SLOT)
  else:
    (slot >= srange.slot) and (slot < (srange.slot + srange.count))

func `<`*(a, b: SyncRange): bool {.inline.} =
  ## Returns `true` if range `a` is below of range `b`.
  (a.slot < b.slot) and (a.slot + a.count - 1 < b.slot)

func `==`*(a, b: SyncRange): bool {.inline.} =
  (a.slot == b.slot) and (a.count == b.count)

func `==`*[T](a, b: SyncRequest[T]): bool {.inline.} =
  (a.kind == b.kind) and (a.item == b.item) and (a.data == b.data)

proc hasEndGap*[T](
    sr: SyncRequest[T],
    data: openArray[ref ForkedSignedBeaconBlock]
): bool {.inline.} =
  ## Returns ``true`` if response chain of blocks has gap at the end.
  if len(data) == 0:
    return true
  if data[^1][].slot != (sr.data.slot + sr.data.count - 1'u64):
    return true
  false

proc updateLastSlot*[M, N](
    sq: SyncQueue[M, N],
    last: Slot
) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  sq.finalSlot = last

func contains*[M, N](
    sq: SyncQueue[M, N],
    slot: Slot
): bool =
  ## Returns ``true`` if ``slot`` is in queue's range [startSlot, finalSlot].
  (slot >= sq.startSlot) and (slot <= sq.finalSlot)

proc getRewindPoint*[M, N](
    sq: SyncQueue[M, N],
    failSlot: Slot,
    safeSlot: Slot
): Slot =
  case sq.kind
  of SyncQueueKind.Forward:
    # Calculate the latest finalized epoch.
    let finalizedEpoch = epoch(safeSlot)

    # Calculate failure epoch.
    let failEpoch = epoch(failSlot)

    # Calculate exponential rewind point in number of epochs.
    let epochCount =
      if sq.rewind.isSome():
        let rewind = sq.rewind.get()
        if failSlot == rewind.failSlot:
          # `MissingParent` happened at same slot so we increase rewind point by
          # factor of 2.
          if failEpoch > finalizedEpoch:
            let rewindPoint = rewind.epochCount shl 1
            if rewindPoint < rewind.epochCount:
              # If exponential rewind point produces `uint64` overflow we will
              # make rewind to latest finalized epoch.
              failEpoch - finalizedEpoch
            else:
              if (failEpoch < rewindPoint) or
                 (failEpoch - rewindPoint < finalizedEpoch):
                # If exponential rewind point points to position which is far
                # behind latest finalized epoch.
                failEpoch - finalizedEpoch
              else:
                rewindPoint
          else:
            warn "Trying to rewind over the last finalized epoch",
                 finalized_slot = safeSlot,
                 fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch,
                 fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.epochCount,
                 finalized_epoch = finalizedEpoch,
                 sync_ident = sq.ident,
                 direction = sq.kind,
                 topics = "sync"
            0'u64
        else:
          # `MissingParent` happened at different slot so we going to rewind for
          # 1 epoch only.
          if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
            warn "Could not rewind further than the last finalized epoch",
                 finalized_slot = safeSlot,
                 fail_slot = failSlot,
                 finalized_epoch = finalizedEpoch,
                 fail_epoch = failEpoch,
                 rewind_epoch_count = rewind.epochCount,
                 finalized_epoch = finalizedEpoch,
                 sync_ident = sq.ident,
                 direction = sq.kind,
                 topics = "sync"
            0'u64
          else:
            1'u64
      else:
        # `MissingParent` happened first time.
        if (failEpoch < 1'u64) or (failEpoch - 1'u64 < finalizedEpoch):
          warn "Could not rewind further than the last finalized epoch",
               finalized_slot = safeSlot,
               fail_slot = failSlot,
               finalized_epoch = finalizedEpoch,
               fail_epoch = failEpoch,
               finalized_epoch = finalizedEpoch,
               sync_ident = sq.ident,
               direction = sq.kind,
               topics = "sync"
          0'u64
        else:
          1'u64

    if epochCount == 0'u64:
      warn "Unable to continue syncing, please restart the node",
           finalized_slot = safeSlot,
           fail_slot = failSlot,
           finalized_epoch = finalizedEpoch,
           fail_epoch = failEpoch,
           finalized_epoch = finalizedEpoch,
           sync_ident = sq.ident,
           direction = sq.kind,
           topics = "sync"
      # Calculate the rewind epoch, which will be equal to last rewind point or
      # finalizedEpoch
      let rewindEpoch =
        if sq.rewind.isNone():
          finalizedEpoch
        else:
          epoch(sq.rewind.get().failSlot) - sq.rewind.get().epochCount
      rewindEpoch.start_slot()
    else:
      # Calculate the rewind epoch, which should not be less than the latest
      # finalized epoch.
      let rewindEpoch = failEpoch - epochCount
      # Update and save new rewind point in SyncQueue.
      sq.rewind = Opt.some(
        RewindPoint(failSlot: failSlot, epochCount: epochCount))
      rewindEpoch.start_slot()
  of SyncQueueKind.Backward:
    # While we perform backward sync, the only possible slot we could rewind is
    # latest stored block.
    if failSlot == safeSlot:
      warn "Unable to continue syncing, please restart the node",
           safe_slot = safeSlot,
           fail_slot = failSlot,
           sync_ident = sq.ident,
           direction = sq.kind,
           topics = "sync"
    safeSlot

func reset*[M, N](
    sq: SyncQueue[M, N],
    start, final: Slot
) =
  sq.startSlot = start
  sq.finalSlot = final
  sq.inpSlot = start
  sq.outSlot = start
  sq.skipId = 0'u64
  sq.uniqId = 0'u64
  sq.requests.reset()

func searchPeer[T](requests: openArray[SyncRequest[T]], source: T): int =
  for index, request in requests.pairs():
    if request.item == source:
      return index
  -1

func find[M, N](sq: SyncQueue[M, N], req: SyncRequest[M]): Opt[SyncPosition] =
  if len(sq.requests) == 0:
    return Opt.none(SyncPosition)

  case sq.kind
  of SyncQueueKind.Forward:
    if (req.data < sq.requests[0].data) or (req.data > sq.requests[^1].data):
      return Opt.none(SyncPosition)
  of SyncQueueKind.Backward:
    if (req.data > sq.requests[0].data) or (req.data < sq.requests[^1].data) :
      return Opt.none(SyncPosition)

  for qindex, qitem in sq.requests.pairs():
    for sindex, request in qitem.requests.pairs():
      if request == req:
        return Opt.some(SyncPosition(qindex: qindex, sindex: sindex))

  Opt.none(SyncPosition)

proc del[M, N](sq: SyncQueue[M, N], position: SyncPosition) =
  doAssert(len(sq.requests) > position.qindex)
  doAssert(len(sq.requests[position.qindex].requests) > position.sindex)
  del(sq.requests[position.qindex].requests, position.sindex)

proc del[M, N](sq: SyncQueue[M, N], request: SyncRequest[M]) =
  let pos = sq.find(request).valueOr:
    return
  sq.del(pos)

proc rewardForGaps[M, N](sq: SyncQueue[M, N], score: int) =
  mixin updateScore, getStats

  for gap in sq.gapList:
    if score < 0:
      # Every empty response increases penalty by 25%, but not more than 200%.
      let
        emptyCount = gap.item.getStats(SyncResponseKind.Empty)
        goodCount = gap.item.getStats(SyncResponseKind.Good)

      if emptyCount <= goodCount:
        gap.item.updateScore(score)
      else:
        let
          weight = int(min(emptyCount - goodCount, 8'u64))
          newScore = score + score * weight div 4
        gap.item.updateScore(newScore)
        debug "Peer received gap penalty",
              peer = gap.item,
              penalty = newScore,
              sync_ident = sq.ident,
              direction = sq.kind,
              topics = "sync"

    else:
      gap.item.updateScore(score)

func getCurrentRange*[M, N](sq: SyncQueue[M, N]): Opt[SyncRange] =
  ## Returns current working range.
  case sq.kind
  of SyncQueueKind.Forward:
    if len(sq.requests) > 0:
      return Opt.some(sq.requests[0].data)
    let startSlot = sq.inpSlot
    if startSlot >= sq.finalSlot:
      return Opt.none(SyncRange)
    let res = sq.next(startSlot).valueOr:
      return Opt.none(SyncRange)
    Opt.some(res)
  of SyncQueueKind.Backward:
    if len(sq.requests) > 0:
      return Opt.some(sq.requests[0].data)
    let startSlot = sq.inpSlot + 1
    if startSlot < sq.finalSlot:
      return Opt.none(SyncRange)
    let res = sq.prev(startSlot).valueOr:
      return Opt.none(SyncRange)
    Opt.some(res)

func getNextRange*[M, N](sq: SyncQueue[M, N]): Opt[SyncRange] =
  case sq.kind
  of SyncQueueKind.Forward:
    let startSlot =
      if len(sq.requests) > 0:
        let lastRange = sq.requests[^1].data
        if lastRange.slot + lastRange.count < lastRange.slot:
          return Opt.none(SyncRange)
        lastRange.slot + lastRange.count
      else:
        sq.inpSlot
    if startSlot >= sq.finalSlot:
      return Opt.none(SyncRange)
    let res = sq.next(startSlot).valueOr:
      return Opt.none(SyncRange)
    Opt.some(res)
  of SyncQueueKind.Backward:
    let startSlot =
      if len(sq.requests) > 0:
        let lastRange = sq.requests[^1].data
        if lastRange.slot <= sq.finalSlot:
          return Opt.none(SyncRange)
        lastRange.slot
      else:
        if sq.inpSlot <= sq.finalSlot:
          return Opt.none(SyncRange)
        sq.inpSlot + 1
    if startSlot < sq.finalSlot:
      return Opt.none(SyncRange)
    let res = sq.prev(startSlot).valueOr:
      return Opt.none(SyncRange)
    Opt.some(res)

proc getNextRequest*[M, N](sq: SyncQueue[M, N], item: M): SyncRequest[M] =
  let newRange = sq.getNextRange().valueOr:
    return SyncRequest.init(
      sq.kind, item, SyncRequestReason.NoMoreSpace)
  SyncRequest.init(sq, sq.kind, sq.epochFilter(newRange), item)

proc getDistance*[M, N](sq: SyncQueue[M, N], srange: SyncRange): int =
  let currentRange = sq.getCurrentRange().valueOr:
    return 0
  case sq.kind
  of SyncQueueKind.Forward:
    if srange.slot < currentRange.slot:
      return 0
    int((srange.slot - currentRange.slot))
  of SyncQueueKind.Backward:
    if srange.slot > currentRange.slot:
      return 0
    int((currentRange.slot - srange.slot))

proc pop*[M, N](
    sq: SyncQueue[M, N],
    peerMaxSlot: Slot,
    item: M
): SyncRequest[M] =
  # Searching requests queue for an empty space.
  var peerCount = 0
  for qitem in sq.requests.mitems():
    if not(sq.isComplete(qitem.data, item, qitem.completeness)):
      let sindex = qitem.requests.searchPeer(item)
      if sindex < 0:
        return
          if qitem.data.slot > peerMaxSlot:
            # Peer could not satisfy our request, returning empty one.
            SyncRequest.init(
              sq.kind, item, SyncRequestReason.PeerSlotKnowledge)
          else:
            let request = SyncRequest.init(sq, sq.kind, qitem.data, item)
            qitem.requests.add(request)
            sq.drainCompleteness(qitem.data, item, qitem.completeness)
            request
      else:
        if SyncRequestFlag.Void notin qitem.requests[sindex].flags:
          # We only count non-empty requests.
          inc(peerCount)
    else:
      let sindex = qitem.requests.searchPeer(item)
      if sindex >= 0:
        if SyncRequestFlag.Void notin qitem.requests[sindex].flags:
          # We only count non-empty requests.
          inc(peerCount)

  when N is BlockCompleteness:
    doAssert(peerCount < sq.requestsCount,
             "You should not pop so many requests for single peer")

  let request = sq.getNextRequest(item)
  if request.isEmpty():
    return SyncRequest.init(
      sq.kind, item, SyncRequestReason.NoMoreSpace)
  elif request.data.slot > peerMaxSlot:
    # Peer could not satisfy our request - returning empty request.
    return SyncRequest.init(
      sq.kind, item, SyncRequestReason.PeerSlotKnowledge)
  var qitem =
    when N is BlockCompleteness:
      SyncQueueItem.init(N, request)
    elif N is ColumnCompleteness:
      let distance = sq.getDistance(request.data)
      if distance >= sq.maxSlotDistance:
        return SyncRequest.init(
          sq.kind, item, SyncRequestReason.TooBigDistance)
      SyncQueueItem.init(N, request, sq.cbGetLocalColumnMap())
  sq.drainCompleteness(qitem.data, item, qitem.completeness)
  sq.requests.addLast(qitem)
  request

proc wakeupWaiters*[M, N](sq: SyncQueue[M, N], resetFlag = false) =
  ## Wakeup one or all blocked waiters.
  for item in sq.waiters:
    item.resetFlag = resetFlag
    if not(item.future.finished()):
      item.future.complete()

proc waitForChanges[M, N](
    sq: SyncQueue[M, N]
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Create new waiter and wait for completion from `wakeupWaiters()`.
  let
    future =
      Future[void].Raising([CancelledError]).init("SyncQueue.waitForChanges")
    item = SyncWaiterItem[M](future: future, resetFlag: false)

  sq.waiters.add(item)

  try:
    await future
    item.resetFlag
  finally:
    sq.waiters.delete(sq.waiters.find(item))

proc wakeupAndWaitWaiters[M, N](
    sq: SyncQueue[M, N]
) {.async: (raises: [CancelledError]).} =
  ## This procedure will perform wakeupWaiters(true) and blocks until last
  ## waiter will be awakened.
  let waitChanges = sq.waitForChanges()
  sq.wakeupWaiters(true)
  discard await waitChanges

template advanceImpl(kind, slot: untyped, number: uint64) =
  case kind
  of SyncQueueKind.Forward:
    if slot + number < slot:
      slot = FAR_FUTURE_SLOT
    else:
      slot = slot + number
  of SyncQueueKind.Backward:
    if slot - number > slot:
      slot = GENESIS_SLOT
    else:
      slot = slot - number

proc advanceOutput[M, N](sq: SyncQueue[M, N], number: uint64) =
  advanceImpl(sq.kind, sq.outSlot, number)

proc advanceInput[M, N](sq: SyncQueue[M, N], number: uint64) =
  advanceImpl(sq.kind, sq.inpSlot, number)

proc advanceQueue[M, N](sq: SyncQueue[M, N], count: var int64) =
  if len(sq.requests) > 0:
    let item = sq.requests.popFirst()
    sq.advanceInput(item.data.count)
    sq.advanceOutput(item.data.count)
    # It is usually safe conversion, because value is limited by `sq.chunkSize`.
    count = int64(item.data.count)
  else:
    sq.advanceInput(sq.chunkSize)
    sq.advanceOutput(sq.chunkSize)
    # It is usually safe conversion, because value is limited by `sq.chunkSize`.
    count = int64(sq.chunkSize)
  sq.wakeupWaiters()

proc getRetreatCount(requestSlot, rewindSlot: Slot): int64 =
  let res =
    if requestSlot >= rewindSlot:
      # In some case this value could exceed int64 bounds, but it would be fully
      # unfunctional network.
      -int64(requestSlot - rewindSlot)
    else:
      # In some case this value could exceed int64 bounds, but it would be fully
      # unfunctional network.
      -int64(rewindSlot - requestSlot)
  res

proc resetQueue[M, N](sq: SyncQueue[M, N]) =
  sq.requests.reset()
  # We are making all requests that have been issued up to this moment of time -
  # non-relevant.
  sq.skipId = sq.uniqId

proc clearAndWakeup*[M, N](sq: SyncQueue[M, N]) =
  # Reset queue and wakeup all the waiters.
  sq.resetQueue()
  sq.wakeupWaiters(true)

proc isEmpty*[T](sr: SyncRequest[T]): bool =
  # Returns `true` if request `sr` is empty.
  sr.data.count == 0'u64

proc resetWait*[M, N](
    sq: SyncQueue[M, N],
    toSlot: Slot
) {.async: (raises: [CancelledError], raw: true).} =
  sq.inpSlot = toSlot
  sq.outSlot = toSlot
  # We are going to wakeup all the waiters and wait for last one.
  sq.resetQueue()
  sq.wakeupAndWaitWaiters()

iterator blocks(
    kind: SyncQueueKind,
    blcks: openArray[ref ForkedSignedBeaconBlock],
): ref ForkedSignedBeaconBlock =
  case kind
  of SyncQueueKind.Forward:
    for i in countup(0, len(blcks) - 1):
      yield blcks[i]
  of SyncQueueKind.Backward:
    for i in countdown(len(blcks) - 1, 0):
      yield blcks[i]

proc push*[M, N](sq: SyncQueue[M, N], requests: openArray[SyncRequest[M]]) =
  ## Push multiple failed requests back to queue.
  for request in requests.items():
    let pos = sq.find(request).valueOr:
      debug "Request is not relevant anymore", request = request
      continue
    when N is BlockCompleteness:
      sq.fillCompleteness(
        sq.requests[pos.qindex].data, request.item,
        done = false, sq.requests[pos.qindex].completeness)
    elif N is ColumnCompleteness:
      let
        localMap = sq.cbGetLocalColumnMap()
        peerMap = sq.cbGetColumnMap(request.item)
        map =
          sq.requests[pos.qindex].completeness.map or (peerMap and localMap)
      sq.fillCompleteness(
        sq.requests[pos.qindex].data, request.item, Opt.some(map),
        done = false, storePeer = false, sq.requests[pos.qindex].completeness)
    sq.del(pos)

proc push*[M, N](sq: SyncQueue[M, N], sr: SyncRequest[M]) =
  ## Push single failed request back to queue.
  sq.push([sr])

proc process[M, N](
    sq: SyncQueue[M, N],
    sr: SyncRequest[M],
    blcks: seq[ref ForkedSignedBeaconBlock],
    maybeFinalized: bool
): Future[SyncProcessingResult] {.
  async: (raises: [CancelledError]).} =
  var
    slot: Opt[BlockId]
    unviableBlock: Opt[BlockId]
    dupBlock: Opt[BlockId]

  if len(blcks) == 0:
    return SyncProcessingResult.init(SyncProcessError.Empty)

  for blk in blocks(sq.kind, blcks):
    let res = await sq.blockVerifier(blk, maybeFinalized)
    if res.isOk():
      slot = Opt.some(BlockId(slot: blk[].slot, root: blk[].root))
    else:
      case res.error()
      of VerifierError.MissingParent:
        if slot.isSome() or dupBlock.isSome():
          return SyncProcessingResult.init(
            SyncProcessError.GoodAndMissingParent, blk[].slot, blk[].root)
        else:
          return SyncProcessingResult.init(res.error(), blk[].slot, blk[].root)
      of VerifierError.Duplicate:
        # Keep going, happens naturally
        if dupBlock.isNone():
          dupBlock = Opt.some(BlockId(slot: blk[].slot, root: blk[].root))
      of VerifierError.MissingSidecars:
        return SyncProcessingResult.init(res.error(), blk[].slot, blk[].root)
      of VerifierError.UnviableFork:
        # Keep going so as to register other unviable blocks with the
        # quarantine
        if unviableBlock.isNone():
          # Remember the first unviable block, so we can log it
          unviableBlock = Opt.some(BlockId(slot: blk[].slot, root: blk[].root))
      of VerifierError.Invalid:
        return SyncProcessingResult.init(res.error(), blk[].slot, blk[].root)

  if unviableBlock.isSome():
    return SyncProcessingResult.init(VerifierError.UnviableFork,
                                     unviableBlock.get())
  if dupBlock.isSome():
    return SyncProcessingResult.init(VerifierError.Duplicate,
                                     dupBlock.get())

  SyncProcessingResult.init(SyncProcessError.NoError, slot.get())

func isError(e: SyncProcessError): bool =
  case e
  of SyncProcessError.Empty, SyncProcessError.NoError,
     SyncProcessError.Duplicate, SyncProcessError.GoodAndMissingParent,
     SyncProcessError.NoRelevant, SyncProcessError.MissingSidecars:
    false
  of SyncProcessError.Invalid, SyncProcessError.UnviableFork,
     SyncProcessError.MissingParent:
    true

proc getMissingMap*[M](
    sq: SyncQueue[M, ColumnCompleteness],
    data: openArray[ref ForkedSignedBeaconBlock],
    startBid: Opt[BlockId]
): ColumnMap =
  var
    res: ColumnMap
    started =
      if startBid.isSome():
        false
      else:
        true
  for blck in data:
    if started or (startBid.isSome() and (blck[].root == startBid.get().root)):
      started = true
      let map = sq.cbGetMissingMap(blck[].root)
      res = res or map
  res

func isRelevant*[M, N](sq: SyncQueue[M, N], sr: SyncRequest[M]): bool =
  uint64(sr.id) > uint64(sq.skipId)

proc push*[M, N](
    sq: SyncQueue[M, N],
    sr: SyncRequest[M],
    data: seq[ref ForkedSignedBeaconBlock],
    maybeFinalized: bool = false,
    processingCb: ProcessingCallback = nil
): Future[SyncPushResponse] {.async: (raises: [CancelledError]).} =
  ## Push successful result to queue ``sq``.
  mixin updateScore, updateStats, getStats

  template findPosition(sq, sr: untyped): SyncPosition =
    sq.find(sr).valueOr:
      debug "Request is not relevant anymore",
            request = sr, queue = shortLog(sq), sync_ident = sq.ident,
            topics = "sync"
      # Request is not in queue anymore, probably reset happened.
      return SyncPushResponse(
        code: SyncProcessError.NoRelevant, count: 0'i64)

  template checkRelevance(sq, sr: untyped) =
    if not(sq.isRelevant(sr)):
      debug "Request is not relevant anymore",
        request = sr, queue = shortLog(sq), sync_ident = sq.ident,
        topics = "sync"
      return SyncPushResponse(
        code: SyncProcessError.NoRelevant, count: 0'i64)

  template fillCompleteness(pdone, pblck, pstore: untyped) =
    when N is BlockCompleteness:
      sq.fillCompleteness(
        sq.requests[position.qindex].data, sr.item, done = pdone,
        sq.requests[position.qindex].completeness)
    elif N is ColumnCompleteness:
      let map = sq.getMissingMap(data, pblck)
      sq.fillCompleteness(
        sq.requests[position.qindex].data, sr.item, Opt.some(map),
        done = pdone, storePeer = pstore,
        sq.requests[position.qindex].completeness)

  # This is backpressure handling algorithm, this algorithm is blocking
  # all pending `push` requests if `request` is not in range.
  var
    position =
      block:
        var pos: SyncPosition
        while true:
          sq.checkRelevance(sr)
          pos = sq.findPosition(sr)

          if pos.qindex == 0:
            # Exiting loop when request is first in queue.
            break

          try:
            let res = await sq.waitForChanges()
            if res:
              # SyncQueue reset happen
              debug "Request is not relevant anymore, reset has happened",
                    request = sr, queue = shortLog(sq),
                    sync_ident = sq.ident,
                    topics = "sync"
              return SyncPushResponse(
                code: SyncProcessError.NoRelevant, count: 0'i64)
          except CancelledError as exc:
            # Removing request from queue.
            sq.del(sr)
            raise exc
        pos

  try:
    await sq.lock.acquire()
  except CancelledError as exc:
    # Removing request from queue
    sq.del(sr)
    raise exc

  var res = 0'i64
  try:
    sq.checkRelevance(sr)

    position = sq.findPosition(sr)

    if not(isNil(processingCb)):
      processingCb()

    let pres = await sq.process(sr, data, maybeFinalized)

    # We need to update position, because while we waiting for `process()` to
    # complete - clearAndWakeup() could be invoked which could clean whole the
    # queue (invalidating all the positions).
    position = sq.findPosition(sr)

    case pres.code
    of SyncProcessError.Empty:
      # Empty responses does not affect failures count
      debug "Received empty response",
            request = sr,
            queue = shortLog(sq),
            completeness = shortLog(sq.requests[position.qindex].completeness),
            voids_count = sq.requests[position.qindex].voidsCount,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            sync_ident = sq.ident,
            topics = "sync"

      sr.item.updateStats(SyncResponseKind.Empty, 1'u64)
      inc(sq.requests[position.qindex].voidsCount)
      # Mark empty request in queue, so this range will not be requested by
      # the same peer.
      sq.requests[position.qindex].requests[position.sindex].flags.incl(
        SyncRequestFlag.Void)
      sq.gapList.add(GapItem.init(sr))
      # With empty response - advance only when `requestsCount` of different
      # peers returns empty response for the same range.
      if sq.requests[position.qindex].voidsCount >= sq.requestsCount:
        when N is BlockCompleteness:
          fillCompleteness(true, Opt.none(BlockId), false)
          sq.advanceQueue(res)
        elif N is ColumnCompleteness:
          let localMap = sq.cbGetLocalColumnMap()
          # If completeness map was changed it proves that specific range is
          # not actually empty and we should not move forward.
          if sq.requests[position.qindex].completeness.map != localMap:
            fillCompleteness(false, Opt.none(BlockId), false)
          else:
            fillCompleteness(true, Opt.none(BlockId), false)
      else:
        fillCompleteness(false, Opt.none(BlockId), false)

    of SyncProcessError.Duplicate:
      # Duplicate responses does not affect failures count
      debug "Received duplicate response",
            request = sr,
            queue = shortLog(sq),
            completeness = shortLog(sq.requests[position.qindex].completeness),
            voids_count = sq.requests[position.qindex].voidsCount,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            sync_ident = sq.ident,
            topics = "sync"

      sq.gapList.reset()
      fillCompleteness(true, Opt.none(BlockId), false)
      sq.advanceQueue(res)

    of SyncProcessError.MissingSidecars:
      debug "Received blocks without sidecars",
            request = sr,
            queue = shortLog(sq),
            completeness = shortLog(sq.requests[position.qindex].completeness),
            voids_count = sq.requests[position.qindex].voidsCount,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            sync_ident = sq.ident,
            topics = "sync"

      inc(sq.requests[position.qindex].failuresCount)
      fillCompleteness(false, pres.blck, true)
      sq.del(position)
      res = 0'i64

    of SyncProcessError.Invalid:
      debug "Block pool rejected peer's response",
            request = sr,
            queue = shortLog(sq),
            invalid_block = pres.blck,
            completeness = shortLog(sq.requests[position.qindex].completeness),
            voids_count = sq.requests[position.qindex].voidsCount,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            sync_ident = sq.ident,
            topics = "sync"

      inc(sq.requests[position.qindex].failuresCount)
      fillCompleteness(false, pres.blck, false)
      sq.del(position)
      res = 0'i64

    of SyncProcessError.UnviableFork:
      notice "Received blocks from an unviable fork",
             request = sr,
             queue = shortLog(sq),
             unviable_block = pres.blck,
             completeness = shortLog(sq.requests[position.qindex].completeness),
             voids_count = sq.requests[position.qindex].voidsCount,
             failures_count = sq.requests[position.qindex].failuresCount,
             blocks_count = len(data),
             blocks_map = getShortMap(sr, data),
             sync_ident = sq.ident,
             topics = "sync"

      sr.item.updateScore(PeerScoreUnviableFork)
      inc(sq.requests[position.qindex].failuresCount)
      fillCompleteness(false, pres.blck, false)
      sq.del(position)
      res = 0'i64

    of SyncProcessError.MissingParent:
      debug "Unexpected missing parent",
             request = sr,
             queue = shortLog(sq),
             missing_parent_block = pres.blck,
             completeness = shortLog(sq.requests[position.qindex].completeness),
             voids_count = sq.requests[position.qindex].voidsCount,
             failures_count = sq.requests[position.qindex].failuresCount,
             blocks_count = len(data),
             blocks_map = getShortMap(sr, data),
             sync_ident = sq.ident,
             direction = sq.kind,
             topics = "sync"

      sr.item.updateScore(PeerScoreMissingValues)
      sq.rewardForGaps(PeerScoreMissingValues)
      sq.gapList.reset()
      inc(sq.requests[position.qindex].failuresCount)
      fillCompleteness(false, pres.blck, false)
      sq.del(position)
      res = 0'i64

    of SyncProcessError.GoodAndMissingParent:
      # Responses which has at least one good block and a gap does not affect
      # failures count
      debug "Unexpected missing parent, but no rewind needed",
            request = sr,
            queue = shortLog(sq),
            finalized_slot = sq.getSafeSlot(),
            missing_parent_block = pres.blck,
            completeness = shortLog(sq.requests[position.qindex].completeness),
            voids_count = sq.requests[position.qindex].voidsCount,
            failures_count = sq.requests[position.qindex].failuresCount,
            blocks_count = len(data),
            blocks_map = getShortMap(sr, data),
            sync_ident = sq.ident,
            topics = "sync"

      sr.item.updateScore(PeerScoreMissingValues)
      fillCompleteness(false, pres.blck, false)
      sq.del(position)
      res = 0'i64

    of SyncProcessError.NoError:
      sr.item.updateScore(PeerScoreGoodValues)
      sr.item.updateStats(SyncResponseKind.Good, 1'u64)
      sq.rewardForGaps(PeerScoreGoodValues)
      sq.gapList.reset()

      if sr.hasEndGap(data):
        sq.gapList.add(GapItem.init(sr))

      fillCompleteness(true, Opt.none(BlockId), false)
      sq.advanceQueue(res)
    of SyncProcessError.NoRelevant:
      raiseAssert "Processor should not return this error code"

    if pres.code.isError():
      if sq.requests[position.qindex].failuresCount >= sq.failureResetThreshold:
        let point = sq.getRewindPoint(pres.blck.get().slot, sq.getSafeSlot())
        debug "Multiple repeating errors occurred, rewinding",
              voids_count = sq.requests[position.qindex].voidsCount,
              failures_count = sq.requests[position.qindex].failuresCount,
              rewind_slot = point,
              sync_ident = sq.ident,
              topics = "sync"
        await sq.resetWait(point)
        res =
          case sq.kind
          of SyncQueueKind.Forward:
            getRetreatCount(sr.data.start_slot(), point)
          of SyncQueueKind.Backward:
            getRetreatCount(sr.data.last_slot(), point)
    SyncPushResponse(code: pres.code, count: res, blck: pres.blck)
  except CancelledError as exc:
    let pos = sq.find(sr)
    if pos.isSome():
      fillCompleteness(false, Opt.none(BlockId), false)
      sq.del(pos.get())
    raise exc
  finally:
    try:
      sq.lock.release()
    except AsyncLockError:
      raiseAssert "Lock is not acquired"

proc len*[M, N](sq: SyncQueue[M, N]): uint64 {.inline.} =
  ## Returns number of slots left in queue ``sq``.
  case sq.kind
  of SyncQueueKind.Forward:
    if sq.finalSlot >= sq.outSlot:
      sq.finalSlot + 1'u64 - sq.outSlot
    else:
      0'u64
  of SyncQueueKind.Backward:
    if sq.outSlot >= sq.finalSlot:
      sq.outSlot + 1'u64 - sq.finalSlot
    else:
      0'u64

proc total*[M, N](sq: SyncQueue[M, N]): uint64 {.inline.} =
  ## Returns total number of slots in queue ``sq``.
  case sq.kind
  of SyncQueueKind.Forward:
    if sq.finalSlot >= sq.startSlot:
      sq.finalSlot + 1'u64 - sq.startSlot
    else:
      0'u64
  of SyncQueueKind.Backward:
    if sq.startSlot >= sq.finalSlot:
      sq.startSlot + 1'u64 - sq.finalSlot
    else:
      0'u64

proc progress*[M, N](sq: SyncQueue[M, N]): uint64 =
  ## How many useful slots we've synced so far, adjusting for how much has
  ## become obsolete by time movements
  sq.total() - len(sq)

func running*[M, N](sq: SyncQueue[M, N]): bool =
  ## Returns `true` when SyncQueue is in process.
  if isNil(sq):
    return false

  case sq.kind
  of SyncQueueKind.Forward:
    (sq.startSlot < sq.inpSlot) and (sq.finalSlot > sq.inpSlot)
  of SyncQueueKind.Backward:
    (sq.startSlot > sq.inpSlot) and (sq.finalSlot < sq.inpSlot)

func started*[M, N](sq: SyncQueue[M, N]): bool =
  ## Returns `true` if SyncQueue was started, e.g. internal counters changed
  ## since starting state.
  sq.startSlot != sq.inpSlot

func init*[M](
    t1: typedesc[SyncQueue],
    t2: typedesc[M],
    t3: typedesc[BlockCompleteness],
    queueKind: SyncQueueKind,
    start, final: Slot,
    chunkSize: uint64,
    requestsCount: Natural,
    failureResetThreshold: Natural,
    getSafeSlotCb: GetSlotCallback,
    blockVerifier: BlockVerifier,
    forkAtEpoch: ForkAtEpochCallback,
    ident: string = "main"
): SyncQueue[M, BlockCompleteness] =
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  doAssert(requestsCount > 0, "Number of requests should not be zero")

  SyncQueue[M, BlockCompleteness](
    kind: queueKind,
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    requestsCount: requestsCount,
    failureResetThreshold: failureResetThreshold,
    getSafeSlot: getSafeSlotCb,
    inpSlot: start,
    outSlot: start,
    blockVerifier: blockVerifier,
    forkAtEpoch: forkAtEpoch,
    requests: initDeque[SyncQueueItem[M, BlockCompleteness]](),
    lock: newAsyncLock(),
    uniqId: 0'u64,
    skipId: 0'u64,
    ident: ident
  )

func init*[M](
    t1: typedesc[SyncQueue],
    t2: typedesc[M],
    t3: typedesc[ColumnCompleteness],
    queueKind: SyncQueueKind,
    start, final: Slot,
    chunkSize: uint64,
    requestsCount: Natural,
    failureResetThreshold: Natural,
    maxSlotDistance: Natural,
    getSafeSlotCb: GetSlotCallback,
    blockVerifier: BlockVerifier,
    forkAtEpoch: ForkAtEpochCallback,
    localMapCb: LocalColumnMapCallback,
    peerMapCb: PeerMapCallback[M],
    missingMapCb: MissingMapCallback,
    ident: string = "main"
): SyncQueue[M, ColumnCompleteness] =
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  doAssert(requestsCount > 0, "Number of requests should not be zero")

  SyncQueue[M, ColumnCompleteness](
    kind: queueKind,
    startSlot: start,
    finalSlot: final,
    chunkSize: chunkSize,
    requestsCount: requestsCount,
    failureResetThreshold: failureResetThreshold,
    maxSlotDistance: maxSlotDistance,
    getSafeSlot: getSafeSlotCb,
    inpSlot: start,
    outSlot: start,
    blockVerifier: blockVerifier,
    forkAtEpoch: forkAtEpoch,
    requests: initDeque[SyncQueueItem[M, ColumnCompleteness]](),
    lock: newAsyncLock(),
    cbGetColumnMap: peerMapCb,
    cbGetMissingMap: missingMapCb,
    cbGetLocalColumnMap: localMapCb,
    uniqId: 0'u64,
    skipId: 0'u64,
    ident: ident
  )

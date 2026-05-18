# beacon_chain
# Copyright (c) 2020-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import unittest2
import chronos, stew/base10, chronos/unittest2/asynctests, libp2p/peerid
import ../beacon_chain/networking/[peer_scores, eth2_agents]
import ../beacon_chain/gossip_processing/block_processor,
       ../beacon_chain/sync/[sync_queue, response_utils],
       ../beacon_chain/spec/[forks, column_map]

from std/sequtils import repeat, mapIt

type
  SomeTPeer = ref object
    id: string
    peerId: PeerId
    score: int
    map: ColumnMap

  ColQuarantine = TableRef[Eth2Digest, ColumnMap]

func init(t: typedesc[SomeTPeer], id: string, score = 1000): SomeTPeer =
  SomeTPeer(id: id, score: score)

proc init(t: typedesc[SomeTPeer], id: string, map: ColumnMap): SomeTPeer =
  SomeTPeer(id: id, map: map, peerId: PeerId.random().get())

func init(t: typedesc[ColumnMap], columns: openArray[int]): ColumnMap =
  var res = columns.mapIt(ColumnIndex(it))
  ColumnMap.init(res)

func `$`(peer: SomeTPeer): string =
  "peer#" & peer.id

func getKey*(peer: SomeTPeer): PeerId =
  peer.peerId

template shortLog(peer: SomeTPeer): string =
  $peer

func updateScore(peer: SomeTPeer, score: int) =
  peer[].score += score

func getRemoteAgent(peer: SomeTPeer): Eth2Agent =
  Eth2Agent.Nimbus

func updateStats(peer: SomeTPeer, index: SyncResponseKind, score: uint64) =
  discard

func getStats(peer: SomeTPeer, index: SyncResponseKind): uint64 =
  0

func getStaticSlotCb(slot: Slot): GetSlotCallback =
  func getSlot(): Slot =
    slot
  getSlot

func testforkAtEpoch(epoch: Epoch): ConsensusFork =
  ConsensusFork.Phase0

type
  BlockEntry = object
    blck*: ForkedSignedBeaconBlock
    resfut*: Future[Result[void, VerifierError]]

  FuluColumnData = object
    block_root*: Eth2Digest
    map: ColumnMap

func createChain(slots: Slice[Slot]): seq[ref ForkedSignedBeaconBlock] =
  var res = newSeqOfCap[ref ForkedSignedBeaconBlock](len(slots))
  for slot in slots:
    let item = newClone ForkedSignedBeaconBlock(kind: ConsensusFork.Deneb)
    item[].denebData.message.slot = slot
    res.add(item)
  res

func createDigest(data: int): Eth2Digest =
  var res = Eth2Digest()
  let tmp = uint64(data).toBytesBE()
  copyMem(addr res.data[0], addr tmp[0], 8)
  res

func createFuluChain(
    slots: Slice[Slot],
    map: ColumnMap
): tuple[blocks: seq[ref ForkedSignedBeaconBlock],
         columns: seq[FuluColumnData]] =
  var
    res1 = newSeqOfCap[ref ForkedSignedBeaconBlock](len(slots))
    res2 = newSeqOfCap[FuluColumnData](len(slots))
  for slot in slots:
    let item = newClone ForkedSignedBeaconBlock(kind: ConsensusFork.Fulu)
    item[].fuluData.message.slot = slot
    item[].fuluData.root = createDigest(int(slot))
    res1.add(item)
    res2.add(FuluColumnData(block_root: item[].fuluData.root, map: map))
  (res1, res2)

func createChain(slots: openArray[Slot]): seq[ref ForkedSignedBeaconBlock] =
  var
    res: seq[ref ForkedSignedBeaconBlock]
    root = 0

  for slot in slots:
    let item = newClone ForkedSignedBeaconBlock(kind: ConsensusFork.Deneb)
    item[].denebData.message.slot = slot
    if root == 0:
      item[].denebData.root = createDigest(1)
      item[].denebData.message.parent_root = createDigest(0)
      inc(root)
    else:
      let prev_root = root
      inc(root)
      item[].denebData.root = createDigest(root)
      item[].denebData.message.parent_root = createDigest(prev_root)
    res.add(item)
  res

proc createChain(srange: SyncRange): seq[ref ForkedSignedBeaconBlock] =
  createChain(srange.slot .. (srange.slot + srange.count - 1))

proc createFuluChain(
    request: SyncRequest[SomeTPeer],
    map: ColumnMap
): tuple[blocks: seq[ref ForkedSignedBeaconBlock],
         columns: seq[FuluColumnData]] =
  let srange = request.data
  createFuluChain(srange.slot .. (srange.slot + srange.count - 1), map)

func cmp(request: SyncRequest[SomeTPeer], srange: Slice[Slot]): bool =
  (request.data.start_slot() == srange.a) and
  (request.data.last_slot() == srange.b)

func collector(queue: AsyncQueue[BlockEntry]): BlockVerifier =
  proc verify(
      signedBlock: ref ForkedSignedBeaconBlock,
      maybeFinalized: bool
  ): Future[Result[void, VerifierError]] {.
    async: (raises: [CancelledError], raw: true).} =
    let fut =
      Future[Result[void, VerifierError]].Raising([CancelledError]).init()
    try:
      queue.addLastNoWait(BlockEntry(blck: signedBlock[], resfut: fut))
    except CatchableError as exc:
      raiseAssert exc.msg
    fut
  verify

proc setupVerifier(
  skind: SyncQueueKind,
  sc: openArray[tuple[slots: Slice[Slot], code: Opt[VerifierError]]]
): tuple[collector: BlockVerifier, verifier: Future[void]] =
  doAssert(len(sc) > 0, "Empty scenarios are not allowed")

  let
    scenario = @sc
    aq = newAsyncQueue[BlockEntry]()

  template done(b: BlockEntry) =
    b.resfut.complete(Result[void, VerifierError].ok())
  template fail(b: BlockEntry, e: untyped) =
    b.resfut.complete(Result[void, VerifierError].err(e))
  template verifyBlock(i, e, s, v: untyped): untyped =
    let item = await queue.popFirst()
    if item.blck.slot == s:
      if e.code.isSome():
        item.fail(e.code.get())
      else:
        item.done()
    else:
      raiseAssert "Verifier got block from incorrect slot, " &
                  "expected " & $s & ", got " &
                  $item.blck.slot & ", position [" &
                  $i & ", " & $s & "]"
    inc(v)

  proc verifier(queue: AsyncQueue[BlockEntry]) {.async: (raises: []).} =
    var slotsVerified = 0
    try:
      for index, entry in scenario.pairs():
        case skind
        of SyncQueueKind.Forward:
          for slot in countup(entry.slots.a, entry.slots.b):
            verifyBlock(index, entry, slot, slotsVerified)
        of SyncQueueKind.Backward:
          for slot in countdown(entry.slots.b, entry.slots.a):
            verifyBlock(index, entry, slot, slotsVerified)
    except CancelledError:
      raiseAssert "Scenario is not completed, " &
                  "number of slots passed " & $slotsVerified

  (collector(aq), verifier(aq))

proc setupColumnsVerifier(
  skind: SyncQueueKind,
  scenarioMap: ColumnMap,
  sc: openArray[tuple[slots: Slice[Slot], code: Opt[VerifierError]]]
): tuple[quarantine: ColQuarantine, collector: BlockVerifier,
         verifier: Future[void]] =
  var
    quarantine = newTable[Eth2Digest, ColumnMap]()
    scenario = @sc
    aq = newAsyncQueue[BlockEntry]()

  template done(b: BlockEntry) =
    b.resfut.complete(Result[void, VerifierError].ok())
  template fail(b: BlockEntry, e: untyped) =
    b.resfut.complete(Result[void, VerifierError].err(e))
  template verifyBlock(i, e, s, v: untyped): untyped =
    let item = await queue.popFirst()
    if item.blck.slot == s:
      if e.code.isSome():
        item.fail(e.code.get())
      else:
        let bmap = quarantine.getOrDefault(item.blck.root)
        if (bmap and scenarioMap) == scenarioMap:
          item.done()
        else:
          item.fail(VerifierError.MissingSidecars)
    else:
      raiseAssert "Verifier got block from incorrect slot, " &
                  "expected " & $s & ", got " &
                  $item.blck.slot & ", position [" &
                  $i & ", " & $s & "]"
    inc(v)

  func collector2(queue: AsyncQueue[BlockEntry]): BlockVerifier =
    proc verify(
        signedBlock: ref ForkedSignedBeaconBlock,
        maybeFinalized: bool
    ): Future[Result[void, VerifierError]] {.
      async: (raises: [CancelledError], raw: true).} =
      let fut =
        Future[Result[void, VerifierError]].Raising([CancelledError]).init()
      try:
        queue.addLastNoWait(BlockEntry(blck: signedBlock[], resfut: fut))
      except CatchableError as exc:
        raiseAssert exc.msg
      fut
    verify

  proc verifier2(queue: AsyncQueue[BlockEntry]) {.async: (raises: []).} =
    var slotsVerified = 0
    try:
      for index, entry in scenario.pairs():
        case skind
        of SyncQueueKind.Forward:
          for slot in countup(entry.slots.a, entry.slots.b):
            verifyBlock(index, entry, slot, slotsVerified)
        of SyncQueueKind.Backward:
          for slot in countdown(entry.slots.b, entry.slots.a):
            verifyBlock(index, entry, slot, slotsVerified)

    except CancelledError:
      raiseAssert "Scenario is not completed, " &
                  "number of slots passed " & $slotsVerified

  (quarantine, collector2(aq), verifier2(aq))

suite "SyncManager test suite":
  for kind in [SyncQueueKind.Forward, SyncQueueKind.Backward]:
    asyncTest "[SyncQueue#" & $kind & "] Smoke [single peer] test":
      # Four ranges was distributed to single peer only.
      let
        scenario = [
          (Slot(0) .. Slot(127), Opt.none(VerifierError))
        ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(127),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(127), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(127)),
                           verifier.collector,
                           testforkAtEpoch)
        peer = SomeTPeer.init("1")
        r1 = sq.pop(Slot(127), peer)
        r2 = sq.pop(Slot(127), peer)
        r3 = sq.pop(Slot(127), peer)
        d1 = createChain(r1.data)
        d2 = createChain(r2.data)
        d3 = createChain(r3.data)

      let
        f1 = sq.push(r1, d1)
        f2 = sq.push(r2, d2)
        f3 = sq.push(r3, d3)

      check:
        f1.finished == false
        f2.finished == false
        f3.finished == false

      check:
        (await noCancel f1).count == 32

      check:
        f1.finished == true
        f2.finished == false
        f3.finished == false

      check:
        (await noCancel f2).count == 32

      check:
        f1.finished == true
        f2.finished == true
        f3.finished == false

      check:
        (await noCancel f3).count == 32

      check:
        f1.finished == true
        f2.finished == true
        f3.finished == true

      let
        r4 = sq.pop(Slot(127), peer)
        d4 = createChain(r4.data)
        f4 = sq.push(r4, d4)

      check:
        (await noCancel f4).count == 32

      check:
        f1.finished == true
        f2.finished == true
        f3.finished == true
        f4.finished == true

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] Smoke [3 peers] test":
      # Three ranges was distributed between 3 peers, every range is going to
      # be pushed by all peers.
      let
        scenario = [
          (Slot(0) .. Slot(127), Opt.none(VerifierError))
        ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(127),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(127), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(127)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")
        r11 = sq.pop(Slot(127), peer1)
        r12 = sq.pop(Slot(127), peer2)
        r13 = sq.pop(Slot(127), peer3)
        d11 = createChain(r11.data)
        d12 = createChain(r12.data)
        d13 = createChain(r13.data)
        r21 = sq.pop(Slot(127), peer1)
        r22 = sq.pop(Slot(127), peer2)
        r23 = sq.pop(Slot(127), peer3)
        d21 = createChain(r21.data)
        d22 = createChain(r22.data)
        d23 = createChain(r23.data)
        r31 = sq.pop(Slot(127), peer1)
        r32 = sq.pop(Slot(127), peer2)
        r33 = sq.pop(Slot(127), peer3)
        d31 = createChain(r31.data)
        d32 = createChain(r32.data)
        d33 = createChain(r33.data)

      let
        f11 = sq.push(r11, d11)
        f12 = sq.push(r12, d12)
        f13 = sq.push(r13, d13)

        f22 = sq.push(r22, d22)
        f21 = sq.push(r21, d21)
        f23 = sq.push(r23, d23)

        f33 = sq.push(r33, d33)
        f32 = sq.push(r32, d32)
        f31 = sq.push(r31, d31)

      check:
        (await noCancel f11).count == 32

      check:
        f11.finished == true
        # We do not check f12 and f13 here because their state is undefined
        # at this time.
        f21.finished == false
        f22.finished == false
        f23.finished == false
        f31.finished == false
        f32.finished == false
        f33.finished == false

      check:
        (await noCancel f22).count == 32

      check:
        f11.finished == true
        f12.finished == true
        f13.finished == true
        f22.finished == true
        # We do not check f21 and f23 here because their state is undefined
        # at this time.
        f31.finished == false
        f32.finished == false
        f33.finished == false

      check:
        (await noCancel f33).count == 32

      check:
        f11.finished == true
        f12.finished == true
        f13.finished == true
        f21.finished == true
        f22.finished == true
        f23.finished == true
        f33.finished == true
        # We do not check f31 and f32 here because their state is undefined
        # at this time.

      let
        r41 = sq.pop(Slot(127), peer1)
        d41 = createChain(r41.data)

      check:
        (await noCancel sq.push(r41, d41)).count == 32

      check:
        f11.finished == true
        f12.finished == true
        f13.finished == true
        f21.finished == true
        f22.finished == true
        f23.finished == true
        f31.finished == true
        f32.finished == true
        f33.finished == true

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] Failure request push test":
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            [
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            [
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError))
            ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(63),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(63), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(63)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")

      block:
        let
          r11 = sq.pop(Slot(63), peer1)
          r12 = sq.pop(Slot(63), peer2)
          r13 = sq.pop(Slot(63), peer3)

        sq.push(r11)
        sq.push(r12)
        sq.push(r13)
        # Next couple of calls should be detected as non relevant
        sq.push(r11)
        sq.push(r12)
        sq.push(r13)

      block:
        let
          r11 = sq.pop(Slot(63), peer1)
          r12 = sq.pop(Slot(63), peer2)
          r13 = sq.pop(Slot(63), peer3)
          d12 = createChain(r12.data)

        sq.push(r11)
        check:
          (await noCancel sq.push(r12, d12)).count == 32
        sq.push(r13)
        # Next couple of calls should be detected as non relevant
        sq.push(r11)
        sq.push(r12)
        sq.push(r13)

      block:
        let
          r11 = sq.pop(Slot(63), peer1)
          r12 = sq.pop(Slot(63), peer2)
          r13 = sq.pop(Slot(63), peer3)
          d13 = createChain(r13.data)

        sq.push(r11)
        sq.push(r12)
        check:
          (await noCancel sq.push(r13, d13)).count == 32
        # Next couple of calls should be detected as non relevant
        sq.push(r11)
        sq.push(r12)
        sq.push(r13)

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] Invalid block [3 peers] test":
      # This scenario performs test for 2 cases.
      # 1. When first error encountered it just drops the the response and
      #    increases `failuresCounter`.
      # 2. When another error encountered it will reset whole queue to the
      #    last known good/safe point (rewind process).
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            [
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(40), Opt.none(VerifierError)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.Invalid)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.Invalid)),
              (Slot(0) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.none(VerifierError)),
              (Slot(42) .. Slot(63), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            [
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(22) .. Slot(31), Opt.none(VerifierError)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.Invalid)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.Invalid)),
              (Slot(32) .. Slot(63), Opt.some(VerifierError.Duplicate)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.none(VerifierError)),
              (Slot(0) .. Slot(20), Opt.none(VerifierError)),
            ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(63),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(63), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(63)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")
        r11 = sq.pop(Slot(63), peer1)
        r12 = sq.pop(Slot(63), peer2)
        r13 = sq.pop(Slot(63), peer3)
        d11 = createChain(r11.data)
        d12 = createChain(r12.data)
        d13 = createChain(r13.data)
        r21 = sq.pop(Slot(63), peer1)
        r22 = sq.pop(Slot(63), peer2)
        r23 = sq.pop(Slot(63), peer3)
        d21 = createChain(r21.data)
        d22 = createChain(r22.data)
        d23 = createChain(r23.data)

      let
        f11 = sq.push(r11, d11)
        f12 = sq.push(r12, d12)
        f13 = sq.push(r13, d13)

      check:
        (await noCancel f11).count == 32
        f11.finished == true

      let
        f21 = sq.push(r21, d21)
        f22 = sq.push(r22, d22)
        f23 = sq.push(r23, d23)

      check:
        (await noCancel f21).count == 0
      check:
        f21.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      check:
        (await noCancel f22).count == -32
      check:
        f21.finished == true
        f22.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      check:
        (await noCancel f23).count == 0
      check:
        f21.finished == true
        f22.finished == true
        f23.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      let
        r31 = sq.pop(Slot(63), peer1)
        r32 = sq.pop(Slot(63), peer2)
        r33 = sq.pop(Slot(63), peer3)
        d31 = createChain(r31.data)
        d32 = createChain(r32.data)
        d33 = createChain(r33.data)
        r41 = sq.pop(Slot(63), peer1)
        r42 = sq.pop(Slot(63), peer2)
        r43 = sq.pop(Slot(63), peer3)
        d41 = createChain(r41.data)
        d42 = createChain(r42.data)
        d43 = createChain(r43.data)

      let
        f31 = sq.push(r31, d31)
        f32 = sq.push(r32, d32)
        f33 = sq.push(r33, d33)
        f42 = sq.push(r42, d42)
        f41 = sq.push(r41, d41)
        f43 = sq.push(r43, d43)

      check:
        (await noCancel f31).count == 32
      check:
        f31.finished == true

      check:
        (await noCancel f42).count == 32
      check:
        f31.finished == true
        f32.finished == true
        f33.finished == true
        f42.finished == true

      check:
        (await noCancel f43).count == 0
      check:
        f31.finished == true
        f32.finished == true
        f33.finished == true
        f41.finished == true
        f42.finished == true
        f43.finished == true

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] Unviable block [3 peers] test":
      # This scenario performs test for 2 cases.
      # 1. When first error encountered it just drops the the response and
      #    increases `failuresCounter`.
      # 2. When another error encountered it will reset whole queue to the
      #    last known good/safe point (rewind process).
      # Unviable fork blocks processed differently from invalid blocks, all
      # this blocks should be added to quarantine, so blocks range is not get
      # failed immediately.
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            [
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(40), Opt.none(VerifierError)),
              (Slot(41) .. Slot(63), Opt.some(VerifierError.UnviableFork)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(63), Opt.some(VerifierError.UnviableFork)),
              (Slot(0) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(63), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            [
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(22) .. Slot(31), Opt.none(VerifierError)),
              (Slot(0) .. Slot(21), Opt.some(VerifierError.UnviableFork)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(0) .. Slot(21), Opt.some(VerifierError.UnviableFork)),
              (Slot(32) .. Slot(63), Opt.some(VerifierError.Duplicate)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(0) .. Slot(21), Opt.none(VerifierError))
            ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(63),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(63), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(63)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")
        r11 = sq.pop(Slot(63), peer1)
        r12 = sq.pop(Slot(63), peer2)
        r13 = sq.pop(Slot(63), peer3)
        d11 = createChain(r11.data)
        d12 = createChain(r12.data)
        d13 = createChain(r13.data)
        r21 = sq.pop(Slot(63), peer1)
        r22 = sq.pop(Slot(63), peer2)
        r23 = sq.pop(Slot(63), peer3)
        d21 = createChain(r21.data)
        d22 = createChain(r22.data)
        d23 = createChain(r23.data)

      let
        f11 = sq.push(r11, d11)
        f12 = sq.push(r12, d12)
        f13 = sq.push(r13, d13)

      check:
        (await noCancel f11).count == 32
      check f11.finished == true

      let
        f21 = sq.push(r21, d21)
        f22 = sq.push(r22, d22)
        f23 = sq.push(r23, d23)

      check:
        (await noCancel f21).count == 0
      check:
        f21.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      check:
        (await noCancel f22).count == -32
      check:
        f21.finished == true
        f22.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      check:
        (await noCancel f23).count == 0
      check:
        f21.finished == true
        f22.finished == true
        f23.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      let
        r31 = sq.pop(Slot(63), peer1)
        r32 = sq.pop(Slot(63), peer2)
        r33 = sq.pop(Slot(63), peer3)

      let
        d31 = createChain(r31.data)
        d32 = createChain(r32.data)
        d33 = createChain(r33.data)
        r41 = sq.pop(Slot(63), peer1)
        r42 = sq.pop(Slot(63), peer2)
        r43 = sq.pop(Slot(63), peer3)
        d41 = createChain(r41.data)
        d42 = createChain(r42.data)
        d43 = createChain(r43.data)

      let
        f31 = sq.push(r31, d31)
        f32 = sq.push(r32, d32)
        f33 = sq.push(r33, d33)
        f42 = sq.push(r42, d42)
        f41 = sq.push(r41, d41)
        f43 = sq.push(r43, d43)

      check:
        (await noCancel f31).count == 32
      check:
        f31.finished == true

      check:
        (await noCancel f42).count == 32
      check:
        f31.finished == true
        f32.finished == true
        f33.finished == true
        f42.finished == true

      check:
        (await noCancel f43).count == 0
      check:
        f31.finished == true
        f32.finished == true
        f33.finished == true
        f41.finished == true
        f42.finished == true
        f43.finished == true

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] finish test":
      const
        TestScenarios =
          [
            (
              Slot(0), Slot(127),
              (Slot(0) .. Slot(127), Opt.none(VerifierError)), 4, false, 32
            ),
            (
              Slot(0), Slot(127),
              (Slot(0) .. Slot(127), Opt.none(VerifierError)), 5, true, 32
            ),
            (
              Slot(0), Slot(120),
              (Slot(0) .. Slot(120), Opt.none(VerifierError)), 4, false, 25
            ),
            (
              Slot(0), Slot(120),
              (Slot(0) .. Slot(120), Opt.none(VerifierError)), 5, true, 25
            ),
            (
              Slot(32), Slot(159),
              (Slot(32) .. Slot(159), Opt.none(VerifierError)), 4, false, 32
            ),
            (
              Slot(32), Slot(159),
              (Slot(32) .. Slot(159), Opt.none(VerifierError)), 5, true, 32
            ),
            (
              Slot(32), Slot(150),
              (Slot(32) .. Slot(150), Opt.none(VerifierError)), 4, false, 23
            ),
            (
              Slot(32), Slot(150),
              (Slot(32) .. Slot(150), Opt.none(VerifierError)), 5, true, 23
            ),
            (
              Slot(13), Slot(120),
              (Slot(13) .. Slot(120), Opt.none(VerifierError)), 4, false, 12
            ),
            (
              Slot(13), Slot(120),
              (Slot(13) .. Slot(120), Opt.none(VerifierError)), 5, true, 12
            ),
            (
              Slot(43), Slot(150),
              (Slot(43) .. Slot(150), Opt.none(VerifierError)), 4, false, 12
            ),
            (
              Slot(43), Slot(150),
              (Slot(43) .. Slot(150), Opt.none(VerifierError)), 5, true, 12
            )
          ]

      for scenario in TestScenarios:
        let
          verifier = setupVerifier(kind, [scenario[2]])
          sq =
            case kind
            of SyncQueueKind.Forward:
              SyncQueue.init(
                SomeTPeer, BlockCompleteness, kind, scenario[0], scenario[1],
                32'u64, # 32 slots per request
                scenario[3], # N concurrent requests
                2, # 2 failures allowed
                getStaticSlotCb(scenario[0]),
                verifier.collector,
                testforkAtEpoch)
            of SyncQueueKind.Backward:
              SyncQueue.init(
                SomeTPeer, BlockCompleteness, kind, scenario[1], scenario[0],
                32'u64, # 32 slots per request
                scenario[3], # N concurrent requests
                2, # 2 failures allowed
                getStaticSlotCb(scenario[1]),
                verifier.collector,
                testforkAtEpoch)

          peer = SomeTPeer.init("1")
          r11 = sq.pop(Slot(1000), peer)
          r12 = sq.pop(Slot(1000), peer)
          r13 = sq.pop(Slot(1000), peer)
          r14 = sq.pop(Slot(1000), peer)
          d11 = createChain(r11.data)
          d12 = createChain(r12.data)
          d13 = createChain(r13.data)
          d14 = createChain(r14.data)

        if not(scenario[4]):
          let
            f11 = await sq.push(r11, d11)
            f12 = await sq.push(r12, d12)
            f13 = await sq.push(r13, d13)
            f14 = await sq.push(r14, d14)

          check:
            f11.count == 32
            f12.count == 32
            f13.count == 32
            f14.count == scenario[5]

          let
            r1 = sq.pop(Slot(10000), peer)
            r2 = sq.pop(Slot(20000), peer)
            r3 = sq.pop(Slot(30000), peer)

          check:
            r1.isEmpty() == true
            r2.isEmpty() == true
            r3.isEmpty() == true
        else:
          let
            f11 = await sq.push(r11, d11)
            f12 = await sq.push(r12, d12)
            f13 = await sq.push(r13, d13)

          check:
            f11.count == 32
            f12.count == 32
            f13.count == 32

          check:
            isEmpty(sq.pop(Slot(10000), peer)) == true
            isEmpty(sq.pop(Slot(20000), peer)) == true
            isEmpty(sq.pop(Slot(30000), peer)) == true

          let
            f14 = await sq.push(r14, d14)
          check:
            f14.count == scenario[5]

        await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] Empty responses should not " &
              "advance queue until other peers will not confirm [3 peers] " &
              "test":
      var emptyResponse: seq[ref ForkedSignedBeaconBlock]

      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            [
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
            ]
          of SyncQueueKind.Backward:
            [
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError))
            ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness, kind, Slot(0), Slot(95),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness, kind, Slot(95), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(127)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")
        startSlot =
          case kind
          of SyncQueueKind.Forward:
            Slot(0)
          of SyncQueueKind.Backward:
            Slot(95)
        finishSlot =
          case kind
          of SyncQueueKind.Forward:
            Slot(96)
          of SyncQueueKind.Backward:
            Slot(0)
        middleSlot1 =
          case kind
          of SyncQueueKind.Forward:
            Slot(32)
          of SyncQueueKind.Backward:
            Slot(63)
        middleSlot2 =
          case kind
          of SyncQueueKind.Forward:
            Slot(64)
          of SyncQueueKind.Backward:
            Slot(31)

      check:
        sq.inpSlot == startSlot
        sq.outSlot == startSlot

      let
        r11 = sq.pop(Slot(127), peer1)
      check:
        (await sq.push(r11, emptyResponse)).count == 0
      check:
        # No movement after 1st empty response
        sq.inpSlot == startSlot
        sq.outSlot == startSlot

      let
        r12 = sq.pop(Slot(127), peer2)
      check:
        (await sq.push(r12, emptyResponse)).count == 0
      check:
        # No movement after 2nd empty response
        sq.inpSlot == startSlot
        sq.outSlot == startSlot

      let
        r13 = sq.pop(Slot(127), peer3)
      check:
        (await sq.push(r13, emptyResponse)).count == 32
      check:
        # After 3rd empty response we moving forward
        sq.inpSlot == middleSlot1
        sq.outSlot == middleSlot1

      let
        r21 = sq.pop(Slot(127), peer1)
      check:
        (await sq.push(r21, emptyResponse)).count == 0
      check:
        # No movement after 1st empty response
        sq.inpSlot == middleSlot1
        sq.outSlot == middleSlot1

      let
        r22 = sq.pop(Slot(127), peer2)
      check:
        (await sq.push(r22, emptyResponse)).count == 0
      check:
        # No movement after 2nd empty response
        sq.inpSlot == middleSlot1
        sq.outSlot == middleSlot1

      let
        r23 = sq.pop(Slot(127), peer3)
        d23 = createChain(r23.data)

      check:
        (await sq.push(r23, d23)).count == 32
      check:
        # We got non-empty response so we should advance
        sq.inpSlot == middleSlot2
        sq.outSlot == middleSlot2

      let
        r31 = sq.pop(Slot(127), peer1)
      check:
        (await sq.push(r31, emptyResponse)).count == 0
      check:
        # No movement after 1st empty response
        sq.inpSlot == middleSlot2
        sq.outSlot == middleSlot2

      let
        r32 = sq.pop(Slot(127), peer2)
        d32 = createChain(r32.data)
      check:
        (await sq.push(r32, d32)).count == 32
      check:
        # We got non-empty response, so we should advance
        sq.inpSlot == finishSlot
        sq.outSlot == finishSlot

    asyncTest "[SyncQueue#" & $kind & "] Empty responses should not " &
              "be accounted [3 peers] test":
      var emptyResponse: seq[ref ForkedSignedBeaconBlock]
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            [
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(96) .. Slot(127), Opt.none(VerifierError)),
              (Slot(128) .. Slot(159), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            [
              (Slot(128) .. Slot(159), Opt.none(VerifierError)),
              (Slot(96) .. Slot(127), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError))
            ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(159),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(159), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(159)),
                           verifier.collector,
                           testforkAtEpoch)
        slots =
          case kind
          of SyncQueueKind.Forward:
            @[Slot(0), Slot(32), Slot(64), Slot(96), Slot(128)]
          of SyncQueueKind.Backward:
            @[Slot(128), Slot(96), Slot(64), Slot(32), Slot(0)]
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")

      let
        r11 = sq.pop(Slot(159), peer1)
        r21 = sq.pop(Slot(159), peer2)
      check:
        (await sq.push(r11, emptyResponse)).count == 0
      let
        r12 = sq.pop(Slot(159), peer1)
        r13 = sq.pop(Slot(159), peer1)
        # This should not raise an assertion, as the previously sent empty
        # response should not be taken into account.
        r14 = sq.pop(Slot(159), peer1)

      expect AssertionDefect:
        let r1e {.used.} = sq.pop(Slot(159), peer1)

      check:
        r11.data.slot == slots[0]
        r12.data.slot == slots[1]
        r13.data.slot == slots[2]
        r14.data.slot == slots[3]

      # Scenario requires some finish steps
      check:
        (await sq.push(r21, createChain(r21.data))).count == 32
      let r22 = sq.pop(Slot(159), peer2)
      check:
        (await sq.push(r22, createChain(r22.data))).count == 32
      let r23 = sq.pop(Slot(159), peer2)
      check:
        (await sq.push(r23, createChain(r23.data))).count == 32
      let r24 = sq.pop(Slot(159), peer2)
      check:
        (await sq.push(r24, createChain(r24.data))).count == 32
      let r35 = sq.pop(Slot(159), peer3)
      check:
        (await sq.push(r35, createChain(r35.data))).count == 32

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] Combination of missing parent " &
              "and good blocks [3 peers] test":
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            [
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(40), Opt.none(VerifierError)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.MissingParent)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.MissingParent)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.MissingParent)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.MissingParent)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.MissingParent)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(41), Opt.some(VerifierError.MissingParent)),
              (Slot(32) .. Slot(40), Opt.some(VerifierError.Duplicate)),
              (Slot(41) .. Slot(63), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            [
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(22) .. Slot(31), Opt.none(VerifierError)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.MissingParent)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.MissingParent)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.MissingParent)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.MissingParent)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.MissingParent)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(21) .. Slot(21), Opt.some(VerifierError.MissingParent)),
              (Slot(22) .. Slot(31), Opt.some(VerifierError.Duplicate)),
              (Slot(0) .. Slot(21), Opt.none(VerifierError)),
            ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(63),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(63), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(63)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")
        r11 = sq.pop(Slot(63), peer1)
        r12 = sq.pop(Slot(63), peer2)
        r13 = sq.pop(Slot(63), peer3)
        d11 = createChain(r11.data)
        d12 = createChain(r12.data)
        d13 = createChain(r13.data)
        r21 = sq.pop(Slot(63), peer1)
        r22 = sq.pop(Slot(63), peer2)
        r23 = sq.pop(Slot(63), peer3)
        d21 = createChain(r21.data)
        d22 = createChain(r22.data)
        d23 = createChain(r23.data)

      let
        f11 = sq.push(r11, d11)
        f12 = sq.push(r12, d12)
        f13 = sq.push(r13, d13)

      check:
        (await noCancel f11).count == 32
      check f11.finished == true

      let
        f21 = sq.push(r21, d21)
        f22 = sq.push(r22, d22)
        f23 = sq.push(r23, d23)

      check:
        (await noCancel f21).count == 0
      check:
        f21.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      check:
        (await noCancel f22).count == 0
      check:
        f21.finished == true
        f22.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      check:
        (await noCancel f23).count == 0
      check:
        f21.finished == true
        f22.finished == true
        f23.finished == true
        f11.finished == true
        f12.finished == true
        f13.finished == true

      let
        r31 = sq.pop(Slot(63), peer1)
        r32 = sq.pop(Slot(63), peer2)
        r33 = sq.pop(Slot(63), peer3)
        d31 = createChain(r31.data)
        d32 = createChain(r32.data)
        d33 = createChain(r33.data)
        f31 = sq.push(r31, d31)
        f32 = sq.push(r32, d32)
        f33 = sq.push(r33, d33)

      check:
        (await noCancel f31).count == 0
        (await noCancel f32).count == 0
        (await noCancel f33).count == 0

      let
        r41 = sq.pop(Slot(63), peer1)
        r42 = sq.pop(Slot(63), peer2)
        r43 = sq.pop(Slot(63), peer3)
        d41 = createChain(r41.data)
        d42 = createChain(r42.data)
        d43 = createChain(r43.data)
        f42 = sq.push(r32, d42)
        f41 = sq.push(r31, d41)
        f43 = sq.push(r33, d43)

      await noCancel allFutures(f42, f41, f43)

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] block completeness test":
      let
        scenario = [
          (Slot(0) .. Slot(127), Opt.none(VerifierError))
        ]
        verifier = setupVerifier(kind, scenario)
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(0), Slot(127),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, BlockCompleteness,
                           kind, Slot(127), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(127)),
                           verifier.collector,
                           testforkAtEpoch)
        peer1 = SomeTPeer.init("1")
        peer2 = SomeTPeer.init("2")
        peer3 = SomeTPeer.init("3")
        peer4 = SomeTPeer.init("4")
        peer5 = SomeTPeer.init("5")
        peer6 = SomeTPeer.init("6")
      let
        r1 = sq.pop(Slot(127), peer1) # 0..31
        r2 = sq.pop(Slot(127), peer2) # 0..31
        r3 = sq.pop(Slot(127), peer3) # 0..31
        r4 = sq.pop(Slot(127), peer1) # 32..63
        r5 = sq.pop(Slot(127), peer2) # 32..63
        r6 = sq.pop(Slot(127), peer3) # 32..63
        r7 = sq.pop(Slot(127), peer1) # 64..95
        r8 = sq.pop(Slot(127), peer2) # 64..95
        r9 = sq.pop(Slot(127), peer3) # 64..95

      check:
        r1.isEmpty() == false
        r2.isEmpty() == false
        r3.isEmpty() == false
        r4.isEmpty() == false
        r5.isEmpty() == false
        r6.isEmpty() == false
        r7.isEmpty() == false
        r8.isEmpty() == false
        r9.isEmpty() == false

      expect AssertionDefect:
        let f1 {.used.} = sq.pop(Slot(127), peer1)
      expect AssertionDefect:
        let f2 {.used.} = sq.pop(Slot(127), peer2)
      expect AssertionDefect:
        let f3 {.used.} = sq.pop(Slot(127), peer3)

      let
        r11 = sq.pop(Slot(127), peer4) # 96..127
        r12 = sq.pop(Slot(127), peer5) # 96..127
        r13 = sq.pop(Slot(127), peer6) # 96..127
        r14 = sq.pop(Slot(127), peer4) # <empty>
        r15 = sq.pop(Slot(127), peer5) # <empty>
        r16 = sq.pop(Slot(127), peer6) # <empty>
        r17 = sq.pop(Slot(127), peer4) # <empty>
        r18 = sq.pop(Slot(127), peer5) # <empty>
        r19 = sq.pop(Slot(127), peer6) # <empty>

      check:
        r11.isEmpty() == false
        r12.isEmpty() == false
        r13.isEmpty() == false
        r14.isEmpty() == true
        r15.isEmpty() == true
        r16.isEmpty() == true
        r17.isEmpty() == true
        r18.isEmpty() == true
        r19.isEmpty() == true

      let
        d1 = createChain(r1.data)  # peer1
        d5 = createChain(r5.data)  # peer2
        d9 = createChain(r9.data)  # peer3
        d13 = createChain(r13.data) # peer6

      discard await sq.push(r1, d1)
      check:
        sq.pop(Slot(127), peer1).isEmpty() == true
        sq.pop(Slot(127), peer2).isEmpty() == true
        sq.pop(Slot(127), peer3).isEmpty() == true
      discard await sq.push(r5, d5)
      check:
        sq.pop(Slot(127), peer1).isEmpty() == true
        sq.pop(Slot(127), peer2).isEmpty() == true
        sq.pop(Slot(127), peer3).isEmpty() == true
      discard await sq.push(r9, d9)
      check:
        sq.pop(Slot(127), peer1).isEmpty() == true
        sq.pop(Slot(127), peer2).isEmpty() == true
        sq.pop(Slot(127), peer3).isEmpty() == true
      discard await sq.push(r13, d13)
      check:
        sq.pop(Slot(127), peer1).isEmpty() == true
        sq.pop(Slot(127), peer2).isEmpty() == true
        sq.pop(Slot(127), peer3).isEmpty() == true
        sq.pop(Slot(127), peer4).isEmpty() == true
        sq.pop(Slot(127), peer5).isEmpty() == true
        sq.pop(Slot(127), peer6).isEmpty() == true

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] data column completeness test":
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            @[
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(32), Opt.none(VerifierError)),
              (Slot(32) .. Slot(33), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(96) .. Slot(127), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            @[
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(96) .. Slot(127), Opt.none(VerifierError)),
              (Slot(95) .. Slot(95), Opt.none(VerifierError)),
              (Slot(94) .. Slot(95), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError))
            ]
        localMap = ColumnMap.init([4, 13, 18, 23])
        verifier = setupColumnsVerifier(kind, localMap, scenario)

      func getLocalMap(): ColumnMap =
        localMap

      func getMissingMap(root: Eth2Digest): ColumnMap =
        let
          map = verifier.quarantine.getOrDefault(root)
          localMap = getLocalMap()
        localMap and not(localMap and map)

      func getPeerMap(peer: SomeTPeer): ColumnMap =
        peer.map

      func updateMap(a: var ColumnMap, b: ColumnMap) =
        a = a or b

      proc push(
          sq: SyncQueue[SomeTPeer, ColumnCompleteness],
          sr: SyncRequest[SomeTPeer],
          data: seq[ref ForkedSignedBeaconBlock],
          columns: seq[FuluColumnData]
      ): Future[SyncPushResponse] {.
          async: (raises: [CancelledError], raw: true).} =
        let localMap = getLocalMap()
        # Add all columns into "quarantine".
        for item in columns:
          let map = localMap and item.map
          verifier.quarantine.mgetOrPut(
            item.block_root, ColumnMap()).updateMap(map)
        # Start processing blocks.
        push(sq, sr, data)

      let
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, ColumnCompleteness,
                           kind, Slot(0), Slot(127),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           128, # maximum allowed distance
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch,
                           getLocalMap,
                           getPeerMap,
                           getMissingMap)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, ColumnCompleteness,
                           kind, Slot(127), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           128, # maximum allowed distance
                           getStaticSlotCb(Slot(127)),
                           verifier.collector,
                           testforkAtEpoch,
                           getLocalMap,
                           getPeerMap,
                           getMissingMap)
        peer1 = SomeTPeer.init("1", ColumnMap.init([0, 1, 2, 3]))
        peer2 = SomeTPeer.init("2", ColumnMap.init([4, 5, 6, 7]))
        peer3 = SomeTPeer.init("3", ColumnMap.init([8, 9, 10, 11]))
        peer4 = SomeTPeer.init("4", ColumnMap.init([12, 13, 14, 15]))
        peer5 = SomeTPeer.init("5", ColumnMap.init([16, 17, 18, 19]))
        peer6 = SomeTPeer.init("6", ColumnMap.init([20, 21, 22, 23]))
        peer8 = SomeTPeer.init("8", getLocalMap())
        peer9 = SomeTPeer.init("9", getLocalMap())
        peer10 = SomeTPeer.init("10", getLocalMap())
        peer11 = SomeTPeer.init("11", getLocalMap())
        peer12 = SomeTPeer.init("12", getLocalMap())

      let
        r1 = sq.pop(Slot(127), peer1)
        r2 = sq.pop(Slot(127), peer2)
        r3 = sq.pop(Slot(127), peer3)
        r4 = sq.pop(Slot(127), peer4)
        r5 = sq.pop(Slot(127), peer5)
        r6 = sq.pop(Slot(127), peer6)

      check:
        r1.isEmpty() == false
        r2.isEmpty() == false
        r3.isEmpty() == false
        r4.isEmpty() == false
        r5.isEmpty() == false
        r6.isEmpty() == false

      let
        (d1, c1) = createFuluChain(r1, r1.item.map)
        (d2, c2) = createFuluChain(r2, r2.item.map)
        (d3, c3) = createFuluChain(r3, r3.item.map)
        (d4, c4) = createFuluChain(r4, r4.item.map)
        (d5, c5) = createFuluChain(r5, r5.item.map)
        (d6, c6) = createFuluChain(r6, r6.item.map)

      # Peer 1 has no useful columns, but since it goes first, it does
      # not block queue processing.
      let p1 = await sq.push(r1, d1, c1)
      check p1.code == SyncProcessError.MissingSidecars
      # Peer 2 has column 4
      let p2 = await sq.push(r2, d2, c2)
      check p2.code == SyncProcessError.MissingSidecars
      # Peer 3 does not have useful columns, so it is blocks queue right now.
      let f3 = sq.push(r3, d3, c3)
      # Peer 4 has column 13
      let p4 = await sq.push(r4, d4, c4)
      check p4.code == SyncProcessError.MissingSidecars
      # Peer 5 has column 18
      let p5 = await sq.push(r5, d5, c5)
      check p5.code == SyncProcessError.MissingSidecars
      # Peer 6 has column 23
      let p6 = await sq.push(r6, d6, c6)
      check p6.code == SyncProcessError.NoError
      # Now when first range is being processed SyncQueue moves forward and
      # request 3 should not be blocking.
      let p3 = await f3
      check p3.code == SyncProcessError.MissingSidecars
      # Because request 3 does not give us any progress, request 7 is still
      # blocking.
      let
        r8 = sq.pop(Slot(127), peer8)
        (d8, c8) = createFuluChain(r8, r8.item.map)

      var columns8 =
        case kind
        of SyncQueueKind.Forward: @(c8.toOpenArray(0, 0))
        of SyncQueueKind.Backward: @(c8.toOpenArray(31, 31))

      # We are giving only one block of columns
      let p8 = await sq.push(r8, d8, columns8)
      check p8.code == SyncProcessError.MissingSidecars

      let
        r9 = sq.pop(Slot(127), peer9)
        (d9, c9) = createFuluChain(r9, r9.item.map)

      var columns9 =
        case kind
        of SyncQueueKind.Forward: @(c9.toOpenArray(0, 30))
        of SyncQueueKind.Backward: @(c9.toOpenArray(1, 31))

      # We are giving 31 blocks of columns
      let p9 = await sq.push(r9, d9, columns9)
      check p9.code == SyncProcessError.MissingSidecars

      # Finish this range with full 32 blocks and columns
      let
        r10 = sq.pop(Slot(127), peer10)
        (d10, c10) = createFuluChain(r10, r10.item.map)

      let p10 = await sq.push(r10, d10, c10)
      check p10.code == SyncProcessError.NoError

      let
        r11 = sq.pop(Slot(127), peer11)
        r12 = sq.pop(Slot(127), peer12)
        (d11, c11) = createFuluChain(r11, r11.item.map)
        (d12, c12) = createFuluChain(r12, r12.item.map)

      check:
        r11.isEmpty() == false
        r12.isEmpty() == false

      let p11 = await sq.push(r11, d11, c11)
      check p11.code == SyncProcessError.NoError

      let p12 = await sq.push(r12, d12, c12)
      check p12.code == SyncProcessError.NoRelevant

      let
        r13 = sq.pop(Slot(127), peer11)
        r14 = sq.pop(Slot(127), peer12)
        (d13, c13) = createFuluChain(r13, r13.item.map)
        (d14, c14) = createFuluChain(r14, r14.item.map)

      check:
        r13.isEmpty() == false
        r14.isEmpty() == false

      let p14 = await sq.push(r14, d14, c14)
      check p14.code == SyncProcessError.NoError

      let p13 = await sq.push(r13, d13, c13)
      check p13.code == SyncProcessError.NoRelevant

      let
        r15 = sq.pop(Slot(127), peer11)
        r16 = sq.pop(Slot(127), peer12)

      check:
        r15.isEmpty() == true
        r16.isEmpty() == true

      await noCancel wait(verifier.verifier, 2.seconds)

    asyncTest "[SyncQueue#" & $kind & "] data column max distance test":
      let
        scenario =
          case kind
          of SyncQueueKind.Forward:
            @[
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(0), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError)),
              (Slot(32) .. Slot(32), Opt.none(VerifierError)),
              (Slot(32) .. Slot(32), Opt.none(VerifierError)),
              (Slot(32) .. Slot(32), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(64) .. Slot(64), Opt.none(VerifierError)),
              (Slot(64) .. Slot(64), Opt.none(VerifierError)),
              (Slot(64) .. Slot(64), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(96) .. Slot(96), Opt.none(VerifierError)),
              (Slot(96) .. Slot(96), Opt.none(VerifierError)),
              (Slot(96) .. Slot(96), Opt.none(VerifierError)),
              (Slot(96) .. Slot(127), Opt.none(VerifierError))
            ]
          of SyncQueueKind.Backward:
            @[
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(127) .. Slot(127), Opt.none(VerifierError)),
              (Slot(96) .. Slot(127), Opt.none(VerifierError)),
              (Slot(95) .. Slot(95), Opt.none(VerifierError)),
              (Slot(95) .. Slot(95), Opt.none(VerifierError)),
              (Slot(95) .. Slot(95), Opt.none(VerifierError)),
              (Slot(64) .. Slot(95), Opt.none(VerifierError)),
              (Slot(63) .. Slot(63), Opt.none(VerifierError)),
              (Slot(63) .. Slot(63), Opt.none(VerifierError)),
              (Slot(63) .. Slot(63), Opt.none(VerifierError)),
              (Slot(32) .. Slot(63), Opt.none(VerifierError)),
              (Slot(31) .. Slot(31), Opt.none(VerifierError)),
              (Slot(31) .. Slot(31), Opt.none(VerifierError)),
              (Slot(31) .. Slot(31), Opt.none(VerifierError)),
              (Slot(0) .. Slot(31), Opt.none(VerifierError))
            ]
        localMap = ColumnMap.init([4, 13, 38, 56])
        verifier = setupColumnsVerifier(kind, localMap, scenario)

      func getLocalMap(): ColumnMap =
        localMap

      func getMissingMap(root: Eth2Digest): ColumnMap =
        let
          map = verifier.quarantine.getOrDefault(root)
          localMap = getLocalMap()
        localMap and not(localMap and map)

      func getPeerMap(peer: SomeTPeer): ColumnMap =
        peer.map

      func updateMap(a: var ColumnMap, b: ColumnMap) =
        a = a or b

      proc push(
          sq: SyncQueue[SomeTPeer, ColumnCompleteness],
          sr: SyncRequest[SomeTPeer],
          data: seq[ref ForkedSignedBeaconBlock],
          columns: seq[FuluColumnData]
      ): Future[SyncPushResponse] {.
          async: (raises: [CancelledError], raw: true).} =
        let localMap = getLocalMap()
        # Add all columns into "quarantine".
        for item in columns:
          let map = localMap and item.map
          verifier.quarantine.mgetOrPut(
            item.block_root, ColumnMap()).updateMap(map)
        # Start processing blocks.
        push(sq, sr, data)

      let
        sq =
          case kind
          of SyncQueueKind.Forward:
            SyncQueue.init(SomeTPeer, ColumnCompleteness,
                           kind, Slot(0), Slot(127),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           5, # 2 failures allowed
                           64, # maximum allowed distance
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch,
                           getLocalMap,
                           getPeerMap,
                           getMissingMap)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, ColumnCompleteness,
                           kind, Slot(127), Slot(0),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           5, # 2 failures allowed
                           64, # maximum allowed distance
                           getStaticSlotCb(Slot(127)),
                           verifier.collector,
                           testforkAtEpoch,
                           getLocalMap,
                           getPeerMap,
                           getMissingMap)
        peer1 = SomeTPeer.init("1", ColumnMap.init([0, 1, 2, 4]))
        peer2 = SomeTPeer.init("2", ColumnMap.init([13, 15, 16, 17]))
        peer3 = SomeTPeer.init("3", ColumnMap.init([38, 39, 40, 41]))
        peer4 = SomeTPeer.init("4", ColumnMap.init([56, 57, 58, 59]))

      var
        requests1: seq[SyncRequest[SomeTPeer]]
        requests2: seq[SyncRequest[SomeTPeer]]
        requests3: seq[SyncRequest[SomeTPeer]]
        requests4: seq[SyncRequest[SomeTPeer]]

      for peer in [peer1, peer2, peer3, peer4]:
        let
          r1 = sq.pop(Slot(127), peer)
          r2 = sq.pop(Slot(127), peer)
          r3 = sq.pop(Slot(127), peer)
          r4 = sq.pop(Slot(127), peer)

        check:
          r1.isEmpty() == false
          r2.isEmpty() == false
          r3.isEmpty() == true
          r4.isEmpty() == true
          r3.reason == SyncRequestReason.TooBigDistance
          r4.reason == SyncRequestReason.TooBigDistance

        requests1.add(r1)
        requests2.add(r2)

      let
        (d1, c1) = createFuluChain(requests1[0], requests1[0].item.map)
        (d2, c2) = createFuluChain(requests1[1], requests1[1].item.map)
        (d3, c3) = createFuluChain(requests1[2], requests1[2].item.map)
        (d4, c4) = createFuluChain(requests1[3], requests1[3].item.map)

      let
        res1 = await sq.push(requests1[0], d1, c1)
        res2 = await sq.push(requests1[1], d2, c2)
        res3 = await sq.push(requests1[2], d3, c3)
        res4 = await sq.push(requests1[3], d4, c4)

      check:
        res1.code == SyncProcessError.MissingSidecars
        res2.code == SyncProcessError.MissingSidecars
        res3.code == SyncProcessError.MissingSidecars
        res4.code == SyncProcessError.NoError

      for peer in [peer1, peer2, peer3, peer4]:
        let
          r1 = sq.pop(Slot(127), peer)
          r2 = sq.pop(Slot(127), peer)
          r3 = sq.pop(Slot(127), peer)
          r4 = sq.pop(Slot(127), peer)

        check:
          r1.isEmpty() == false
          r2.isEmpty() == true
          r3.isEmpty() == true
          r4.isEmpty() == true
          r2.reason == SyncRequestReason.TooBigDistance
          r3.reason == SyncRequestReason.TooBigDistance
          r4.reason == SyncRequestReason.TooBigDistance

        requests3.add(r1)

      let
        (d5, c5) = createFuluChain(requests2[0], requests2[0].item.map)
        (d6, c6) = createFuluChain(requests2[1], requests2[1].item.map)
        (d7, c7) = createFuluChain(requests2[2], requests2[2].item.map)
        (d8, c8) = createFuluChain(requests2[3], requests2[3].item.map)

      let
        res5 = await sq.push(requests2[0], d5, c5)
        res6 = await sq.push(requests2[1], d6, c6)
        res7 = await sq.push(requests2[2], d7, c7)
        res8 = await sq.push(requests2[3], d8, c8)

      check:
        res5.code == SyncProcessError.MissingSidecars
        res6.code == SyncProcessError.MissingSidecars
        res7.code == SyncProcessError.MissingSidecars
        res8.code == SyncProcessError.NoError

      for peer in [peer1, peer2, peer3, peer4]:
        let
          r1 = sq.pop(Slot(127), peer)
          r2 = sq.pop(Slot(127), peer)
          r3 = sq.pop(Slot(127), peer)
          r4 = sq.pop(Slot(127), peer)

        check:
          r1.isEmpty() == false
          r2.isEmpty() == true
          r3.isEmpty() == true
          r4.isEmpty() == true
          r2.reason == SyncRequestReason.NoMoreSpace
          r3.reason == SyncRequestReason.NoMoreSpace
          r4.reason == SyncRequestReason.NoMoreSpace

        requests4.add(r1)

      let
        (d9, c9) = createFuluChain(requests3[0], requests3[0].item.map)
        (d10, c10) = createFuluChain(requests3[1], requests3[1].item.map)
        (d11, c11) = createFuluChain(requests3[2], requests3[2].item.map)
        (d12, c12) = createFuluChain(requests3[3], requests3[3].item.map)

      let
        res9 = await sq.push(requests3[0], d9, c9)
        res10 = await sq.push(requests3[1], d10, c10)
        res11 = await sq.push(requests3[2], d11, c11)
        res12 = await sq.push(requests3[3], d12, c12)

      check:
        res9.code == SyncProcessError.MissingSidecars
        res10.code == SyncProcessError.MissingSidecars
        res11.code == SyncProcessError.MissingSidecars
        res12.code == SyncProcessError.NoError

      let
        (d13, c13) = createFuluChain(requests4[0], requests4[0].item.map)
        (d14, c14) = createFuluChain(requests4[1], requests4[1].item.map)
        (d15, c15) = createFuluChain(requests4[2], requests4[2].item.map)
        (d16, c16) = createFuluChain(requests4[3], requests4[3].item.map)

      let
        res13 = await sq.push(requests4[0], d13, c13)
        res14 = await sq.push(requests4[1], d14, c14)
        res15 = await sq.push(requests4[2], d15, c15)
        res16 = await sq.push(requests4[3], d16, c16)

      check:
        res13.code == SyncProcessError.MissingSidecars
        res14.code == SyncProcessError.MissingSidecars
        res15.code == SyncProcessError.MissingSidecars
        res16.code == SyncProcessError.NoError

      await noCancel wait(verifier.verifier, 2.seconds)

    test "[SyncQueue#" & $kind & "] epochFilter() test":
      let
        aq = newAsyncQueue[BlockEntry]()
        scenario =
          case kind
          of SyncQueueKind.Forward:
            @[
              (
                Slot(0), 128, 13,
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix],
                @[Slot(0)..Slot(12), Slot(13)..Slot(25), Slot(26)..Slot(31),
                  Slot(32)..Slot(44), Slot(45)..Slot(57), Slot(58)..Slot(63),
                  Slot(64)..Slot(76)]
              ),
              (
                Slot(0), 128, 31,
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(0)..Slot(30), Slot(31)..Slot(31), Slot(32)..Slot(62),
                  Slot(63)..Slot(63), Slot(64)..Slot(94), Slot(95)..Slot(95),
                  Slot(96)..Slot(126)]
              ),
              (
                Slot(0), 128, 32, # Size of chunk equal to SLOTS_PER_EPOCH
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(0)..Slot(31), Slot(32)..Slot(63), Slot(64)..Slot(95),
                  Slot(96)..Slot(127)]
              ),
              (
                Slot(0), 192, 33, # Size of chunk bigger than SLOTS_PER_EPOCH
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(0)..Slot(31), Slot(32)..Slot(63), Slot(64)..Slot(95),
                  Slot(96)..Slot(128), Slot(129)..Slot(161)]
              ),
              (
                Slot(0), 192, 192, # Size of chunk bigger than SLOTS_PER_EPOCH
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella,
                  ConsensusFork.Deneb, ConsensusFork.Electra],
                @[Slot(0)..Slot(31), Slot(32)..Slot(63), Slot(64)..Slot(95),
                  Slot(96)..Slot(127)]
              )
            ]
          of SyncQueueKind.Backward:
            @[
              (
                Slot(95), 96, 13,
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix],
                @[Slot(83)..Slot(95), Slot(70)..Slot(82), Slot(64)..Slot(69),
                  Slot(51)..Slot(63), Slot(38)..Slot(50), Slot(32)..Slot(37),
                  Slot(19)..Slot(31), Slot(6)..Slot(18), Slot(0)..Slot(5)]
              ),
              (
                Slot(127), 128, 31,
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(97)..Slot(127), Slot(96)..Slot(96), Slot(65)..Slot(95),
                  Slot(64)..Slot(64), Slot(33)..Slot(63), Slot(32)..Slot(32),
                  Slot(1)..Slot(31), Slot(0)..Slot(0)]
              ),
              (
                Slot(127), 128, 32, # Size of chunk equal to SLOTS_PER_EPOCH
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(96)..Slot(127), Slot(64)..Slot(95), Slot(32)..Slot(63),
                  Slot(0)..Slot(31)]
              ),
              (
                Slot(127), 128, 33, # Size of chunk bigger than SLOTS_PER_EPOCH
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(96)..Slot(127), Slot(64)..Slot(95), Slot(32)..Slot(63),
                  Slot(0)..Slot(31)]
              ),
              (
                Slot(127), 128, 128, # Size of chunk bigger than SLOTS_PER_EPOCH
                @[ConsensusFork.Phase0, ConsensusFork.Altair,
                  ConsensusFork.Bellatrix, ConsensusFork.Capella],
                @[Slot(96)..Slot(127), Slot(64)..Slot(95), Slot(32)..Slot(63),
                  Slot(0)..Slot(31)]
              )
            ]

      func epochManager(epochs: openArray[ConsensusFork]): ForkAtEpochCallback =
        let epochsSeq = @epochs
        func forkAtEpoch(epoch: Epoch): ConsensusFork =
          let index = int(epoch)
          if index >= len(epochsSeq):
            epochsSeq[^1]
          elif index < 0:
            epochsSeq[0]
          else:
            epochsSeq[index]
        forkAtEpoch

      for vector in scenario:
        case kind
        of SyncQueueKind.Forward:
          let
            maxSlot = vector[0] + uint64(vector[1]) - 1'u64
            sq =
              SyncQueue.init(SomeTPeer, BlockCompleteness,
                             kind, vector[0], maxSlot,
                             uint64(vector[2]),
                             9, # 8 concurrent requests
                             2, # 2 failures allowed
                             getStaticSlotCb(Slot(0)),
                             collector(aq),
                             epochManager(vector[3]))
            peer = SomeTPeer.init("1")
          for srange in vector[4]:
            let request = sq.pop(maxSlot, peer)
            check cmp(request, srange)
        of SyncQueueKind.Backward:
          let
            minSlot = vector[0] + 1'u64 - uint64(vector[1])
            maxSlot = vector[0]
            sq =
              SyncQueue.init(SomeTPeer, BlockCompleteness,
                             kind, vector[0], minSlot,
                             uint64(vector[2]),
                             9, # 8 concurrent requests
                             2, # 2 failures allowed
                             getStaticSlotCb(Slot(0)),
                             collector(aq),
                             epochManager(vector[3]))
            peer = SomeTPeer.init("1")
          for srange in vector[4]:
            let request = sq.pop(maxSlot, peer)
            check cmp(request, srange)

  asyncTest "[SyncQueue#Forward] Missing parent and exponential rewind " &
            "[3 peers] test":
    let
      scenario =
        [
          (Slot(0) .. Slot(31), Opt.none(VerifierError)),
          # .. 3 ranges are empty
          (Slot(128) .. Slot(128), Opt.some(VerifierError.MissingParent)),
          (Slot(128) .. Slot(128), Opt.some(VerifierError.MissingParent)),
          # 1st rewind should be to (failed_slot - 1 * epoch) = 96
          (Slot(128) .. Slot(128), Opt.some(VerifierError.MissingParent)),
          (Slot(128) .. Slot(128), Opt.some(VerifierError.MissingParent)),
          # 2nd rewind should be to (failed_slot - 2 * epoch) = 64
          (Slot(128) .. Slot(128), Opt.some(VerifierError.MissingParent)),
          (Slot(128) .. Slot(128), Opt.some(VerifierError.MissingParent)),
          # 3rd rewind should be to (failed_slot - 4 * epoch) = 0
          (Slot(0) .. Slot(31), Opt.some(VerifierError.Duplicate)),
          (Slot(32) .. Slot(63), Opt.none(VerifierError)),
          (Slot(64) .. Slot(95), Opt.none(VerifierError)),
          (Slot(96) .. Slot(127), Opt.none(VerifierError)),
          (Slot(128) .. Slot(159), Opt.none(VerifierError)),
        ]
      kind = SyncQueueKind.Forward
      verifier = setupVerifier(kind, scenario)
      sq = SyncQueue.init(SomeTPeer, BlockCompleteness, kind, Slot(0), Slot(159),
                          32'u64, # 32 slots per request
                          3, # 3 concurrent requests
                          2, # 2 failures allowed
                          getStaticSlotCb(Slot(0)),
                          verifier.collector,
                          testforkAtEpoch)
      peer1 = SomeTPeer.init("1")
      peer2 = SomeTPeer.init("2")
      peer3 = SomeTPeer.init("3")
      r11 = sq.pop(Slot(159), peer1)
      r12 = sq.pop(Slot(159), peer2)
      r13 = sq.pop(Slot(159), peer3)
      d11 = createChain(r11.data)
      d12 = createChain(r12.data)
      d13 = createChain(r13.data)
      f11 = sq.push(r11, d11)
      f12 = sq.push(r12, d12)
      f13 = sq.push(r13, d13)

    check:
      (await noCancel f11).count == 32
      (await noCancel f12).count == 0
      (await noCancel f13).count == 0

    for i in 0 ..< 3:
      let
        re1 = sq.pop(Slot(159), peer1)
        re2 = sq.pop(Slot(159), peer2)
        re3 = sq.pop(Slot(159), peer3)
        de1 = default(seq[ref ForkedSignedBeaconBlock])
        de2 = default(seq[ref ForkedSignedBeaconBlock])
        de3 = default(seq[ref ForkedSignedBeaconBlock])
        fe1 = sq.push(re1, de1)
        fe2 = sq.push(re2, de2)
        fe3 = sq.push(re3, de3)

      discard await noCancel fe1
      discard await noCancel fe2
      discard await noCancel fe3

    let
      r21 = sq.pop(Slot(159), peer1)
      r22 = sq.pop(Slot(159), peer2)
      r23 = sq.pop(Slot(159), peer3)
      d21 = createChain(r21.data)
      d22 = createChain(r22.data)
      d23 = createChain(r23.data)
      f21 = sq.push(r21, d21)
      f22 = sq.push(r22, d22)
      f23 = sq.push(r23, d23)

    check:
      (await noCancel f21).count == 0
      (await noCancel f22).count == -32
      (await noCancel f23).count == 0

    for i in 0 ..< 1:
      let
        re1 = sq.pop(Slot(159), peer1)
        re2 = sq.pop(Slot(159), peer2)
        re3 = sq.pop(Slot(159), peer3)
        de1 = default(seq[ref ForkedSignedBeaconBlock])
        de2 = default(seq[ref ForkedSignedBeaconBlock])
        de3 = default(seq[ref ForkedSignedBeaconBlock])
        fe1 = sq.push(re1, de1)
        fe2 = sq.push(re2, de2)
        fe3 = sq.push(re3, de3)

      discard await noCancel fe1
      discard await noCancel fe2
      discard await noCancel fe3

    let
      r31 = sq.pop(Slot(159), peer1)
      r32 = sq.pop(Slot(159), peer2)
      r33 = sq.pop(Slot(159), peer3)
      d31 = createChain(r31.data)
      d32 = createChain(r32.data)
      d33 = createChain(r33.data)
      f31 = sq.push(r31, d31)
      f32 = sq.push(r32, d32)
      f33 = sq.push(r33, d33)

    check:
      (await noCancel f31).count == 0
      (await noCancel f32).count == -64
      (await noCancel f33).count == 0

    for i in 0 ..< 2:
      let
        re1 = sq.pop(Slot(159), peer1)
        re2 = sq.pop(Slot(159), peer2)
        re3 = sq.pop(Slot(159), peer3)
        de1 = default(seq[ref ForkedSignedBeaconBlock])
        de2 = default(seq[ref ForkedSignedBeaconBlock])
        de3 = default(seq[ref ForkedSignedBeaconBlock])
        fe1 = sq.push(re1, de1)
        fe2 = sq.push(re2, de2)
        fe3 = sq.push(re3, de3)

      discard await noCancel fe1
      discard await noCancel fe2
      discard await noCancel fe3

    let
      r41 = sq.pop(Slot(159), peer1)
      r42 = sq.pop(Slot(159), peer2)
      r43 = sq.pop(Slot(159), peer3)
      d41 = createChain(r41.data)
      d42 = createChain(r42.data)
      d43 = createChain(r43.data)
      f41 = sq.push(r41, d41)
      f42 = sq.push(r42, d42)
      f43 = sq.push(r43, d43)

    check:
      (await noCancel f41).count == 0
      (await noCancel f42).count == -128
      (await noCancel f43).count == 0

    for i in 0 ..< 5:
      let
        rf1 = sq.pop(Slot(159), peer1)
        rf2 = sq.pop(Slot(159), peer2)
        rf3 = sq.pop(Slot(159), peer3)
        df1 = createChain(rf1.data)
        df2 = createChain(rf2.data)
        df3 = createChain(rf3.data)
        ff1 = sq.push(rf1, df1)
        ff2 = sq.push(rf2, df2)
        ff3 = sq.push(rf3, df3)

      check:
        (await noCancel ff1).count == 32
        (await noCancel ff2).count == 0
        (await noCancel ff3).count == 0

    await noCancel wait(verifier.verifier, 2.seconds)

  asyncTest "[SyncQueue#Backward] Missing parent and exponential rewind " &
             "[3 peers] test":
    let
      scenario =
        [
          (Slot(128) .. Slot(159), Opt.none(VerifierError)),
          # .. 3 ranges are empty
          (Slot(31) .. Slot(31), Opt.some(VerifierError.MissingParent)),
          (Slot(31) .. Slot(31), Opt.some(VerifierError.MissingParent)),
          (Slot(128) .. Slot(159), Opt.some(VerifierError.Duplicate)),
          (Slot(96) .. Slot(127), Opt.none(VerifierError)),
          # .. 2 ranges are empty
          (Slot(31) .. Slot(31), Opt.some(VerifierError.MissingParent)),
          (Slot(31) .. Slot(31), Opt.some(VerifierError.MissingParent)),
          (Slot(128) .. Slot(159), Opt.some(VerifierError.Duplicate)),
          (Slot(96) .. Slot(127), Opt.some(VerifierError.Duplicate)),
          (Slot(64) .. Slot(95), Opt.none(VerifierError)),
          # .. 1 range is empty
          (Slot(31) .. Slot(31), Opt.some(VerifierError.MissingParent)),
          (Slot(31) .. Slot(31), Opt.some(VerifierError.MissingParent)),
          (Slot(128) .. Slot(159), Opt.some(VerifierError.Duplicate)),
          (Slot(96) .. Slot(127), Opt.some(VerifierError.Duplicate)),
          (Slot(64) .. Slot(95), Opt.some(VerifierError.Duplicate)),
          (Slot(32) .. Slot(63), Opt.none(VerifierError)),
          (Slot(0) .. Slot(31), Opt.none(VerifierError))
        ]
      kind = SyncQueueKind.Backward
      verifier = setupVerifier(kind, scenario)
      sq = SyncQueue.init(SomeTPeer, BlockCompleteness, kind, Slot(159), Slot(0),
                          32'u64, # 32 slots per request
                          3, # 3 concurrent requests
                          2, # 2 failures allowed
                          getStaticSlotCb(Slot(159)),
                          verifier.collector,
                          testforkAtEpoch)
      peer1 = SomeTPeer.init("1")
      peer2 = SomeTPeer.init("2")
      peer3 = SomeTPeer.init("3")
      r11 = sq.pop(Slot(159), peer1)
      r12 = sq.pop(Slot(159), peer2)
      r13 = sq.pop(Slot(159), peer3)
      d11 = createChain(r11.data)
      d12 = createChain(r12.data)
      d13 = createChain(r13.data)
      f11 = sq.push(r11, d11)
      f12 = sq.push(r12, d12)
      f13 = sq.push(r13, d13)

    check:
      (await noCancel f11).count == 32
      (await noCancel f12).count == 0
      (await noCancel f13).count == 0

    for i in 0 ..< 3:
      let
        re1 = sq.pop(Slot(159), peer1)
        re2 = sq.pop(Slot(159), peer2)
        re3 = sq.pop(Slot(159), peer3)
        de1 = default(seq[ref ForkedSignedBeaconBlock])
        de2 = default(seq[ref ForkedSignedBeaconBlock])
        de3 = default(seq[ref ForkedSignedBeaconBlock])
        fe1 = sq.push(re1, de1)
        fe2 = sq.push(re2, de2)
        fe3 = sq.push(re3, de3)

      discard await noCancel fe1
      discard await noCancel fe2
      discard await noCancel fe3

    let
      r21 = sq.pop(Slot(159), peer1)
      r22 = sq.pop(Slot(159), peer2)
      r23 = sq.pop(Slot(159), peer3)
      d21 = createChain(r21.data)
      d22 = createChain(r22.data)
      d23 = createChain(r23.data)
      f21 = sq.push(r21, d21)
      f22 = sq.push(r22, d22)
      f23 = sq.push(r23, d23)

    check:
      (await noCancel f21).count == 0
      (await noCancel f22).count == -128
      (await noCancel f23).count == 0

    for i in 0 ..< 2:
      let
        r31 = sq.pop(Slot(159), peer1)
        r32 = sq.pop(Slot(159), peer2)
        r33 = sq.pop(Slot(159), peer3)
        d31 = createChain(r31.data)
        d32 = createChain(r32.data)
        d33 = createChain(r33.data)
        f31 = sq.push(r31, d31)
        f32 = sq.push(r32, d32)
        f33 = sq.push(r33, d33)

      check:
        (await noCancel f31).count == 32
        (await noCancel f32).count == 0
        (await noCancel f33).count == 0

    for i in 0 ..< 2:
      let
        re1 = sq.pop(Slot(159), peer1)
        re2 = sq.pop(Slot(159), peer2)
        re3 = sq.pop(Slot(159), peer3)
        de1 = default(seq[ref ForkedSignedBeaconBlock])
        de2 = default(seq[ref ForkedSignedBeaconBlock])
        de3 = default(seq[ref ForkedSignedBeaconBlock])
        fe1 = sq.push(re1, de1)
        fe2 = sq.push(re2, de2)
        fe3 = sq.push(re3, de3)

      discard await noCancel fe1
      discard await noCancel fe2
      discard await noCancel fe3

    let
      r41 = sq.pop(Slot(159), peer1)
      r42 = sq.pop(Slot(159), peer2)
      r43 = sq.pop(Slot(159), peer3)
      d41 = createChain(r41.data)
      d42 = createChain(r42.data)
      d43 = createChain(r43.data)
      f41 = sq.push(r41, d41)
      f42 = sq.push(r42, d42)
      f43 = sq.push(r43, d43)

    check:
      (await noCancel f41).count == 0
      (await noCancel f42).count == -128
      (await noCancel f43).count == 0

    for i in 0 ..< 3:
      let
        r51 = sq.pop(Slot(159), peer1)
        r52 = sq.pop(Slot(159), peer2)
        r53 = sq.pop(Slot(159), peer3)
        d51 = createChain(r51.data)
        d52 = createChain(r52.data)
        d53 = createChain(r53.data)
        f51 = sq.push(r51, d51)
        f52 = sq.push(r52, d52)
        f53 = sq.push(r53, d53)

      check:
        (await noCancel f51).count == 32
        (await noCancel f52).count == 0
        (await noCancel f53).count == 0

    for i in 0 ..< 1:
      let
        re1 = sq.pop(Slot(159), peer1)
        re2 = sq.pop(Slot(159), peer2)
        re3 = sq.pop(Slot(159), peer3)
        de1 = default(seq[ref ForkedSignedBeaconBlock])
        de2 = default(seq[ref ForkedSignedBeaconBlock])
        de3 = default(seq[ref ForkedSignedBeaconBlock])
        fe1 = sq.push(re1, de1)
        fe2 = sq.push(re2, de2)
        fe3 = sq.push(re3, de3)

      discard await noCancel fe1
      discard await noCancel fe2
      discard await noCancel fe3

    let
      r61 = sq.pop(Slot(159), peer1)
      r62 = sq.pop(Slot(159), peer2)
      r63 = sq.pop(Slot(159), peer3)
      d61 = createChain(r61.data)
      d62 = createChain(r62.data)
      d63 = createChain(r63.data)
      f61 = sq.push(r61, d61)
      f62 = sq.push(r62, d62)
      f63 = sq.push(r63, d63)

    check:
      (await noCancel f61).count == 0
      (await noCancel f62).count == -128
      (await noCancel f63).count == 0

    for i in 0 ..< 5:
      let
        r71 = sq.pop(Slot(159), peer1)
        r72 = sq.pop(Slot(159), peer2)
        r73 = sq.pop(Slot(159), peer3)
        d71 = createChain(r71.data)
        d72 = createChain(r72.data)
        d73 = createChain(r73.data)
        f71 = sq.push(r71, d71)
        f72 = sq.push(r72, d72)
        f73 = sq.push(r73, d73)

      check:
        (await noCancel f71).count == 32
        (await noCancel f72).count == 0
        (await noCancel f73).count == 0

    await noCancel wait(verifier.verifier, 2.seconds)

  test "[SyncQueue#Forward] getRewindPoint() test":
    let aq = newAsyncQueue[BlockEntry]()
    block:
      let
        queue = SyncQueue.init(SomeTPeer, BlockCompleteness,
                               SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
        finalizedSlot = start_slot(Epoch(0'u64))
        epochStartSlot = start_slot(Epoch(0'u64)) + 1'u64
        finishSlot = start_slot(Epoch(2'u64))

      for i in uint64(epochStartSlot) ..< uint64(finishSlot):
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      let
        queue = SyncQueue.init(SomeTPeer, BlockCompleteness,
                               SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
        finalizedSlot = start_slot(Epoch(1'u64))
        epochStartSlot = start_slot(Epoch(1'u64)) + 1'u64
        finishSlot = start_slot(Epoch(3'u64))

      for i in uint64(epochStartSlot) ..< uint64(finishSlot) :
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      let
        queue = SyncQueue.init(SomeTPeer, BlockCompleteness,
                               SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
        finalizedSlot = start_slot(Epoch(0'u64))
        failSlot = Slot(0xFFFF_FFFF_FFFF_FFFF'u64)
        failEpoch = epoch(failSlot)

      var counter = 1'u64
      for i in 0 ..< 64:
        if counter >= failEpoch:
          break
        let rewindEpoch = failEpoch - counter
        let rewindSlot = start_slot(rewindEpoch)
        check queue.getRewindPoint(failSlot, finalizedSlot) == rewindSlot
        counter = counter shl 1

    block:
      let
        queue = SyncQueue.init(SomeTPeer, BlockCompleteness,
                               SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
      let
        finalizedSlot = start_slot(Epoch(1'u64))
        failSlot = Slot(0xFFFF_FFFF_FFFF_FFFF'u64)
        failEpoch = epoch(failSlot)

      var counter = 1'u64
      for i in 0 ..< 64:
        if counter >= failEpoch:
          break
        let
          rewindEpoch = failEpoch - counter
          rewindSlot = start_slot(rewindEpoch)
        check queue.getRewindPoint(failSlot, finalizedSlot) == rewindSlot
        counter = counter shl 1

  test "[SyncQueue#Backward] getRewindPoint() test":
    let aq = newAsyncQueue[BlockEntry]()
    block:
      let
        getSafeSlot = getStaticSlotCb(Slot(1024))
        queue = SyncQueue.init(SomeTPeer, BlockCompleteness,
                               SyncQueueKind.Backward,
                               Slot(1024), Slot(0),
                               1'u64, 3, 2, getSafeSlot, collector(aq),
                               testforkAtEpoch)
        safeSlot = getSafeSlot()

      for i in countdown(1023, 0):
        check queue.getRewindPoint(Slot(i), safeSlot) == safeSlot

  test "[SyncQueue] hasEndGap() test":
    let
      chain1 = createChain(Slot(1) .. Slot(1))
      chain2 = newSeq[ref ForkedSignedBeaconBlock]()

    for counter in countdown(32'u64, 2'u64):
      let
        srange = SyncRange.init(Slot(1), counter)
        req = SyncRequest[SomeTPeer](data: srange)
      check req.hasEndGap(chain1) == true

    let req = SyncRequest[SomeTPeer](data: SyncRange.init(Slot(1), 1'u64))
    check:
      req.hasEndGap(chain1) == false
      req.hasEndGap(chain2) == true

  test "[SyncQueue] checkResponse() test":
    let
      r1 = SyncRequest[SomeTPeer](data: SyncRange.init(Slot(11), 1'u64))
      r2 = SyncRequest[SomeTPeer](data: SyncRange.init(Slot(11), 2'u64))
      r3 = SyncRequest[SomeTPeer](data: SyncRange.init(Slot(11), 3'u64))
      r4 = SyncRequest[SomeTPeer](data: SyncRange.init(Slot(11), 4'u64))

    check:
      checkResponse(r1.data,
        createChain([Slot(11)])).isOk() == true
      checkResponse(r1.data,
        createChain(@[])).isOk() == true
      checkResponse(r1.data,
        createChain(@[Slot(11), Slot(11)])).isOk() == false
      checkResponse(r1.data,
        createChain([Slot(10)])).isOk() == false
      checkResponse(r1.data,
        createChain([Slot(12)])).isOk() == false

      checkResponse(r2.data,
        createChain([Slot(11)])).isOk() == true
      checkResponse(r2.data,
        createChain([Slot(12)])).isOk() == true
      checkResponse(r2.data,
        createChain(@[])).isOk() == true
      checkResponse(r2.data,
        createChain([Slot(11), Slot(12)])).isOk() == true
      checkResponse(r2.data,
        createChain([Slot(12)])).isOk() == true
      checkResponse(r2.data,
        createChain([Slot(11), Slot(12), Slot(13)])).isOk() == false
      checkResponse(r2.data,
        createChain([Slot(10), Slot(11)])).isOk() == false
      checkResponse(r2.data,
        createChain([Slot(10)])).isOk() == false
      checkResponse(r2.data,
        createChain([Slot(12), Slot(11)])).isOk() == false
      checkResponse(r2.data,
        createChain([Slot(12), Slot(13)])).isOk() == false
      checkResponse(r2.data,
        createChain([Slot(13)])).isOk() == false

      checkResponse(r2.data,
        createChain([Slot(11), Slot(11)])).isOk() == false
      checkResponse(r2.data,
        createChain([Slot(12), Slot(12)])).isOk() == false

      checkResponse(r3.data,
        createChain(@[Slot(11)])).isOk() == true
      checkResponse(r3.data,
        createChain(@[Slot(12)])).isOk() == true
      checkResponse(r3.data,
        createChain(@[Slot(13)])).isOk() == true
      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(12)])).isOk() == true
      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(13)])).isOk() == true
      checkResponse(r3.data,
        createChain(@[Slot(12), Slot(13)])).isOk() == true
      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(13), Slot(12)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(12), Slot(13), Slot(11)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(13), Slot(12), Slot(11)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(13), Slot(11)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(13), Slot(12)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(12), Slot(11)])).isOk() == false

      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(11), Slot(11)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(12), Slot(12)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(13), Slot(13)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(12), Slot(13), Slot(13)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(12), Slot(12), Slot(12)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(13), Slot(13), Slot(13)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(11), Slot(11)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(12), Slot(12)])).isOk() == false
      checkResponse(r3.data,
        createChain(@[Slot(13), Slot(13)])).isOk() == false

    var
      chain1 = createChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])
      chain2 = createChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])
      chain3 = createChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])
      chain4 = createChain(@[Slot(11), Slot(12), Slot(13), Slot(14)])

    withBlck(chain2[1][]):
      forkyBlck.message.parent_root = Eth2Digest()
    withBlck(chain3[2][]):
      forkyBlck.message.parent_root = Eth2Digest()
    withBlck(chain4[3][]):
      forkyBlck.message.parent_root = Eth2Digest()

    check:
      checkResponse(r4.data, chain1).isOk() == true
      checkResponse(r4.data, chain2).isOk() == false
      checkResponse(r4.data, chain3).isOk() == false
      checkResponse(r4.data, chain4).isOk() == false

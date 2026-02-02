# beacon_chain
# Copyright (c) 2020-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/strutils
import unittest2
import chronos, stew/base10, chronos/unittest2/asynctests
import ../beacon_chain/networking/peer_scores
import ../beacon_chain/gossip_processing/block_processor,
       ../beacon_chain/sync/[sync_manager, sync_queue, response_utils],
       ../beacon_chain/spec/forks

type
  SomeTPeer = ref object
    id: string
    score: int

func init(t: typedesc[SomeTPeer], id: string, score = 1000): SomeTPeer =
  SomeTPeer(id: id, score: score)

func `$`(peer: SomeTPeer): string =
  "peer#" & peer.id

template shortLog(peer: SomeTPeer): string =
  $peer

func updateScore(peer: SomeTPeer, score: int) =
  peer[].score += score

func updateStats(peer: SomeTPeer, index: SyncResponseKind, score: uint64) =
  discard

func getStats(peer: SomeTPeer, index: SyncResponseKind): uint64 =
  0

func getStaticSlotCb(slot: Slot): GetSlotCallback =
  func getSlot(): Slot =
    slot
  getSlot

proc testforkAtEpoch(epoch: Epoch): ConsensusFork =
  ConsensusFork.Phase0

type
  BlockEntry = object
    blck*: ForkedSignedBeaconBlock
    resfut*: Future[Result[void, VerifierError]]

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

func cmp(request: SyncRequest[SomeTPeer], srange: Slice[Slot]): bool =
  (request.data.start_slot() == srange.a) and
  (request.data.last_slot() == srange.b)

func createBlobs(
    blocks: var seq[ref ForkedSignedBeaconBlock],
    slots: openArray[Slot]
): seq[ref BlobSidecar] =
  var res = newSeq[ref BlobSidecar](len(slots))
  for blck in blocks:
    withBlck(blck[]):
      when consensusFork >= ConsensusFork.Fulu:
        doAssert false   # create_blob_sidecars() might not work as such
      elif consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
        template kzgs: untyped = forkyBlck.message.body.blob_kzg_commitments
        for i, slot in slots:
          if slot == forkyBlck.message.slot:
            doAssert kzgs.add default(KzgCommitment)
        if kzgs.len > 0:
          forkyBlck.root = hash_tree_root(forkyBlck.message)
          var
            kzg_proofs: deneb.KzgProofs
            blobs: Blobs
          for _ in kzgs:
            doAssert kzg_proofs.add default(KzgProof)
            doAssert blobs.add default(Blob)
          let sidecars = forkyBlck.create_blob_sidecars(kzg_proofs, blobs)
          var sidecarIdx = 0
          for i, slot in slots:
            if slot == forkyBlck.message.slot:
              res[i] = newClone sidecars[sidecarIdx]
              inc sidecarIdx
  res

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

  var
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(127),
                            32'u64, # 32 slots per request
                            3, # 3 concurrent requests
                            2, # 2 failures allowed
                            getStaticSlotCb(Slot(0)),
                            verifier.collector,
                            testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(127), Slot(0),
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(127),
                            32'u64, # 32 slots per request
                            3, # 3 concurrent requests
                            2, # 2 failures allowed
                            getStaticSlotCb(Slot(0)),
                            verifier.collector,
                            testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(127), Slot(0),
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(63),
                            32'u64, # 32 slots per request
                            3, # 3 concurrent requests
                            2, # 2 failures allowed
                            getStaticSlotCb(Slot(0)),
                            verifier.collector,
                            testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(63), Slot(0),
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(63),
                            32'u64, # 32 slots per request
                            3, # 3 concurrent requests
                            2, # 2 failures allowed
                            getStaticSlotCb(Slot(0)),
                            verifier.collector,
                            testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(63), Slot(0),
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(63),
                            32'u64, # 32 slots per request
                            3, # 3 concurrent requests
                            2, # 2 failures allowed
                            getStaticSlotCb(Slot(0)),
                            verifier.collector,
                            testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(63), Slot(0),
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
                SomeTPeer, kind, scenario[0], scenario[1],
                32'u64, # 32 slots per request
                scenario[3], # N concurrent requests
                2, # 2 failures allowed
                getStaticSlotCb(scenario[0]),
                verifier.collector,
                testforkAtEpoch)
            of SyncQueueKind.Backward:
              SyncQueue.init(
                SomeTPeer, kind, scenario[1], scenario[0],
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(95),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(95), Slot(0),
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(159),
                           32'u64, # 32 slots per request
                           3, # 3 concurrent requests
                           2, # 2 failures allowed
                           getStaticSlotCb(Slot(0)),
                           verifier.collector,
                           testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(159), Slot(0),
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
            SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(63),
                            32'u64, # 32 slots per request
                            3, # 3 concurrent requests
                            2, # 2 failures allowed
                            getStaticSlotCb(Slot(0)),
                            verifier.collector,
                            testforkAtEpoch)
          of SyncQueueKind.Backward:
            SyncQueue.init(SomeTPeer, kind, Slot(63), Slot(0),
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
        var epochsSeq = @epochs
        proc forkAtEpoch(epoch: Epoch): ConsensusFork =
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
              SyncQueue.init(SomeTPeer, kind, vector[0], maxSlot,
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
              SyncQueue.init(SomeTPeer, kind, vector[0], minSlot,
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
      sq = SyncQueue.init(SomeTPeer, kind, Slot(0), Slot(159),
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
      sq = SyncQueue.init(SomeTPeer, kind, Slot(159), Slot(0),
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
        queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
        finalizedSlot = start_slot(Epoch(0'u64))
        epochStartSlot = start_slot(Epoch(0'u64)) + 1'u64
        finishSlot = start_slot(Epoch(2'u64))

      for i in uint64(epochStartSlot) ..< uint64(finishSlot):
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      let
        queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
        finalizedSlot = start_slot(Epoch(1'u64))
        epochStartSlot = start_slot(Epoch(1'u64)) + 1'u64
        finishSlot = start_slot(Epoch(3'u64))

      for i in uint64(epochStartSlot) ..< uint64(finishSlot) :
        check queue.getRewindPoint(Slot(i), finalizedSlot) == finalizedSlot

    block:
      let
        queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
        finalizedSlot = start_slot(Epoch(0'u64))
        failSlot = Slot(0xFFFF_FFFF_FFFF_FFFFF'u64)
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
        queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Forward,
                               Slot(0), Slot(0xFFFF_FFFF_FFFF_FFFFF'u64),
                               1'u64, 3, 2, getStaticSlotCb(Slot(0)),
                               collector(aq), testforkAtEpoch)
      let
        finalizedSlot = start_slot(Epoch(1'u64))
        failSlot = Slot(0xFFFF_FFFF_FFFF_FFFFF'u64)
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
        queue = SyncQueue.init(SomeTPeer, SyncQueueKind.Backward,
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

  test "[SyncManager] groupBlobs() test":
    var
      blocks = createChain(Slot(10) .. Slot(15))
      blobs = createBlobs(blocks, @[Slot(11), Slot(11), Slot(12), Slot(14)])

    let groupedRes = groupBlobs(blocks, blobs)

    check groupedRes.isOk()

    let grouped = groupedRes.get()

    check:
      len(grouped) == 6
      # slot 10
      len(grouped[0]) == 0
      # slot 11
      len(grouped[1]) == 2
      grouped[1][0].signed_block_header.message.slot == Slot(11)
      grouped[1][1].signed_block_header.message.slot == Slot(11)
      # slot 12
      len(grouped[2]) == 1
      grouped[2][0].signed_block_header.message.slot == Slot(12)
      # slot 13
      len(grouped[3]) == 0
      # slot 14
      len(grouped[4]) == 1
      grouped[4][0].signed_block_header.message.slot == Slot(14)
      # slot 15
      len(grouped[5]) == 0

    # Add block with a gap from previous block.
    let block17 = newClone ForkedSignedBeaconBlock(kind: ConsensusFork.Deneb)
    block17[].denebData.message.slot = Slot(17)
    blocks.add(block17)
    let groupedRes2 = groupBlobs(blocks, blobs)

    check:
      groupedRes2.isOk()
    let grouped2 = groupedRes2.get()
    check:
      len(grouped2) == 7
      len(grouped2[6]) == 0 # slot 17

    let blob18 = new (ref BlobSidecar)
    blob18[].signed_block_header.message.slot = Slot(18)
    blobs.add(blob18)
    let groupedRes3 = groupBlobs(blocks, blobs)

    check:
      groupedRes3.isErr()

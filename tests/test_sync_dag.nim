# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

{.used.}

import unittest2,
       std/[tables, algorithm],
       libp2p/peerid, libp2p/crypto/rng,
       ../beacon_chain/spec/[forks, presets],
       ../beacon_chain/sync/sync_dag

func genBlockRoot(index: int): Eth2Digest =
  var res: Eth2Digest
  let tmp = uint64(index).toBytesLE()
  copyMem(addr res.data[0], addr tmp[0], sizeof(uint64))
  res

type
  SomeTPeer = ref object
    id: string
    peerId: PeerId

  ChainSource* = object
    roots: Table[Eth2Digest, ref ForkedSignedBeaconBlock]
    slots: Table[Slot, ref ForkedSignedBeaconBlock]

proc init(t: typedesc[SomeTPeer], id: string): SomeTPeer =
  SomeTPeer(id: id, peerId: PeerId.random(newRng()).get())

func getKey*(peer: SomeTPeer): PeerId =
  peer.peerId

func createChainSource(
    slots: Slice[Slot],
    addvalue: int,
    startRoot: Eth2Digest
): ChainSource =
  var
    res: ChainSource
    parentRoot: Opt[Eth2Digest]

  parentRoot = Opt.some(startRoot)

  for slot in slots:
    let
      blockRoot = genBlockRoot(int(slot) + addvalue)
      currentParentRoot = parentRoot.valueOr: genBlockRoot(0)
      item = newClone ForkedSignedBeaconBlock(
        kind: ConsensusFork.Gloas,
        gloasData: gloas.SignedBeaconBlock(
          message: gloas.BeaconBlock(
            slot: slot,
            parent_root: currentParentRoot
          ),
          root: blockRoot
      ))
    res.roots[blockRoot] = item
    res.slots[slot] = item
    parentRoot = Opt.some(blockRoot)
  res

func createPeerBlockId(source: ChainSource, slot: Slot): BlockId =
  let blck = source.slots.getOrDefault(slot)
  doAssert(not(isNil(blck)), "Block not found in chain source [" & $slot & "]")
  blck[].toBlockId()

func createPeerCheckpoint(source: ChainSource, slot: Slot): Checkpoint =
  let
    eslot = slot.epoch().start_slot()
    blck = source.slots.getOrDefault(eslot)
  doAssert(not(isNil(blck)), "Block not found in chain source [" & $eslot & "]")
  Checkpoint(epoch: slot.epoch(), root: blck[].root())

proc pushBlocks*[A, B](
    sdag: var SyncDag[A, B],
    src: ChainSource,
    startEntry: SyncDagEntryRef
) =
  var currentRoot = Opt.some(startEntry.blockId.root)
  while currentRoot.isSome():
    let blck = src.roots.getOrDefault(currentRoot.get())
    currentRoot =
      sdag.updateRoot(blck[].root(), blck[].slot(), blck[].parent_root(),
        false, false, DagBlockSourceType.Dag)

suite "SyncDag test suite":
  test "Single chain and iterator test":
    const TestVectors =
      [Slot(0) .. Slot(256), Slot(32) .. Slot(191)]

    for vector in TestVectors:
      var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
      let
        chain = createChainSource(vector, 0, Eth2Digest())
        bid = createPeerBlockId(chain, vector.b)
        checkpoint = createPeerCheckpoint(chain, vector.a)
        hentry = sdag.mgetOrPut(bid)
        fentry {.used.} = sdag.mgetOrPut(checkpoint)

      sdag.pushBlocks(chain, hentry)

      var rcheck: seq[Eth2Digest]
      rcheck.add(hentry.blockId.root)
      for currentEntry in hentry.parents():
        rcheck.add(currentEntry.blockId.root)
      rcheck.reverse()

      var expect: seq[Eth2Digest]
      for slot in vector:
        if slot == Slot(0):
          # Slot(0) is GENESIS_SLOT so it will be not stored inside SyncDag.
          continue
        let blck = chain.slots.getOrDefault(slot)
        expect.add(blck[].root)

      check len(rcheck) == len(expect)
      for i in 0 ..< len(expect):
        check rcheck[i] == expect[i]

  test "Multiple chains and ancestors iterator test":
    const TestVectors = [
      (
        (Slot(0) .. Slot(128), 0), (Slot(64) .. Slot(128), 1000),
        (Slot(96) .. Slot(128), 10000)
      )
    ]
    for vector in TestVectors:
      var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
      let
        chain1 =
          createChainSource(vector[0][0], vector[0][1], Eth2Digest())
        chain2 =
          createChainSource(vector[1][0], vector[1][1],
            genBlockRoot(int(vector[1][0].a) - 1))
        chain3 =
          createChainSource(vector[2][0], vector[2][1],
            genBlockRoot(int(vector[2][0].a) - 1 + vector[1][1]))
        bid1 = createPeerBlockId(chain1, vector[0][0].b)
        bid2 = createPeerBlockId(chain2, vector[1][0].b)
        bid3 = createPeerBlockId(chain3, vector[2][0].b)
        cp1 = createPeerCheckpoint(chain1, vector[0][0].a)
        cp2 = createPeerCheckpoint(chain2, vector[1][0].a)
        cp3 = createPeerCheckpoint(chain3, vector[2][0].a)
        hentry1 = sdag.mgetOrPut(bid1)
        hentry2 = sdag.mgetOrPut(bid2)
        hentry3 = sdag.mgetOrPut(bid3)
        fentry1 {.used.} = sdag.mgetOrPut(cp1)
        fentry2 {.used.} = sdag.mgetOrPut(cp2)
        fentry3 {.used.} = sdag.mgetOrPut(cp3)

      sdag.pushBlocks(chain1, hentry1)
      sdag.pushBlocks(chain2, hentry2)
      sdag.pushBlocks(chain3, hentry3)

      var
        rcheck1: seq[Eth2Digest]
        rcheck2: seq[Eth2Digest]
        rcheck3: seq[Eth2Digest]

      rcheck1.add(hentry1.blockId.root)
      rcheck2.add(hentry2.blockId.root)
      rcheck3.add(hentry3.blockId.root)

      for currentEntry in hentry1.parents():
        rcheck1.add(currentEntry.blockId.root)
      for currentEntry in hentry2.parents():
        rcheck2.add(currentEntry.blockId.root)
      for currentEntry in hentry3.parents():
        rcheck3.add(currentEntry.blockId.root)

      rcheck1.reverse()
      rcheck2.reverse()
      rcheck3.reverse()

      var
        expect1: seq[Eth2Digest]
        expect2: seq[Eth2Digest]
        expect3: seq[Eth2Digest]

      for slot in vector[0][0]:
        if slot == Slot(0):
          # Slot(0) is GENESIS_SLOT so it will be not stored inside SyncDag.
          continue
        let blck = chain1.slots.getOrDefault(slot)
        expect1.add(blck[].root)

      for slot in vector[0][0]:
        if slot == Slot(0):
          # Slot(0) is GENESIS_SLOT so it will be not stored inside SyncDag.
          continue
        if slot == vector[1][0].a:
          break
        let blck = chain1.slots.getOrDefault(slot)
        expect2.add(blck[].root)

      for slot in vector[1][0]:
        let blck = chain2.slots.getOrDefault(slot)
        expect2.add(blck[].root)

      for slot in vector[0][0]:
        if slot == Slot(0):
          # Slot(0) is GENESIS_SLOT so it will be not stored inside SyncDag.
          continue
        if slot == vector[1][0].a:
          break
        let blck = chain1.slots.getOrDefault(slot)
        expect3.add(blck[].root)

      for slot in vector[1][0]:
        if slot == vector[2][0].a:
          break
        let blck = chain2.slots.getOrDefault(slot)
        expect3.add(blck[].root)

      for slot in vector[2][0]:
        let blck = chain3.slots.getOrDefault(slot)
        expect3.add(blck[].root)

      check:
        len(expect1) == len(rcheck1)
      for i in 0 ..< len(expect1):
        check rcheck1[i] == expect1[i]

      check:
        len(expect2) == len(rcheck2)
      for i in 0 ..< len(expect2):
        check rcheck2[i] == expect2[i]

      check:
        len(expect3) == len(rcheck3)
      for i in 0 ..< len(expect3):
        check rcheck3[i] == expect3[i]

      let
        proot1 = genBlockRoot(int(vector[1][0].a) - 1)
        proot2 = genBlockRoot(int(vector[2][0].a) - 1 + vector[1][1])
        aroot1 = chain1.slots.getOrDefault(vector[1][0].a)[].root()
        aroot2 = chain2.slots.getOrDefault(vector[1][0].a)[].root()
        broot1 = chain2.slots.getOrDefault(vector[2][0].a)[].root()
        broot2 = chain3.slots.getOrDefault(vector[2][0].a)[].root()

      var
        pcheck1: seq[Eth2Digest]
        pcheck2: seq[Eth2Digest]

      for entry in sdag.ancestors(proot1):
        pcheck1.add(entry.blockId.root)

      for entry in sdag.ancestors(proot2):
        pcheck2.add(entry.blockId.root)

      check:
        len(pcheck1) == 2
        len(pcheck2) == 2
        aroot1 in pcheck1
        aroot2 in pcheck1
        broot1 in pcheck2
        broot2 in pcheck2

  test "getMissingSidecarsRoots()/cleanMissingSidecarsRoots() test":
    const TestVectors = [
      (Slot(0) .. Slot(32),
       @[Slot(7), Slot(15), Slot(25), Slot(30), Slot(31)]),
      (Slot(32) .. Slot(64),
       @[Slot(33), Slot(40), Slot(41), Slot(50), Slot(63), Slot(64)])
    ]
    for vector in TestVectors:
      var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
      let
        chain = createChainSource(vector[0], 0, Eth2Digest())
        bid = createPeerBlockId(chain, vector[0].b)
        checkpoint = createPeerCheckpoint(chain, vector[0].a)
        hentry = sdag.mgetOrPut(bid)
        fentry {.used.} = sdag.mgetOrPut(checkpoint)

      var currentRoot = Opt.some(hentry.blockId.root)
      while currentRoot.isSome():
        let
          blck = chain.roots.getOrDefault(currentRoot.get())
          missingSidecars = (blck[].slot() in vector[1])
        currentRoot = sdag.updateRoot(
          blck[].root(), blck[].slot(), blck[].parent_root(), missingSidecars,
          false, DagBlockSourceType.Dag)

      block:
        let missingRoots = hentry.getMissingSidecarsRoots()
        for item in missingRoots:
          check item.slot in vector[1]

      hentry.cleanMissingSidecarsRoots()

      block:
        let missingRoots = hentry.getMissingSidecarsRoots()
        check len(missingRoots) == 0

  test "getMissingEnvelopeRoots()/cleanMissingEnvelopeRoots() test":
    const TestVectors = [
      (Slot(0) .. Slot(32),
       @[Slot(7), Slot(15), Slot(25), Slot(30), Slot(31)]),
      (Slot(32) .. Slot(64),
       @[Slot(33), Slot(40), Slot(41), Slot(50), Slot(63), Slot(64)])
    ]
    for vector in TestVectors:
      var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
      let
        chain = createChainSource(vector[0], 0, Eth2Digest())
        bid = createPeerBlockId(chain, vector[0].b)
        checkpoint = createPeerCheckpoint(chain, vector[0].a)
        hentry = sdag.mgetOrPut(bid)
        fentry {.used.} = sdag.mgetOrPut(checkpoint)

      var currentRoot = Opt.some(hentry.blockId.root)
      while currentRoot.isSome():
        let
          blck = chain.roots.getOrDefault(currentRoot.get())
          missingEnvelope =
            if blck[].slot() in vector[1]:
              true
            else:
              false
        currentRoot = sdag.updateRoot(
          blck[].root(), blck[].slot(), blck[].parent_root(), false,
          missingEnvelope, DagBlockSourceType.Dag)

      block:
        let missingRoots = hentry.getMissingEnvelopeRoots()
        for item in missingRoots:
          check item.slot in vector[1]

      hentry.cleanMissingEnvelopeRoots()

      block:
        let missingRoots = hentry.getMissingEnvelopeRoots()
        check len(missingRoots) == 0

  test "mgetOrPut(peer)/getPeerEntry() test":
    var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
    let
      peer1 = SomeTPeer.init("peer1")
      peer2 = SomeTPeer.init("peer2")
      entry = sdag.mgetOrPut(peer1)
    block:
      let res = sdag.getPeerEntry(peer1.peerId)
      check:
        res.isSome()
        res.get() == entry
    block:
      let res = sdag.getPeerEntry(peer2.peerId)
      check:
        res.isNone()

  test "mgetOrPut(bid)/getRootEntry(root) test":
    var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
    let
      bid1 = BlockId(slot: Slot(100), root: genBlockRoot(100))
      bid2 = BlockId(slot: Slot(101), root: genBlockRoot(101))
      entry = sdag.mgetOrPut(bid1)
    block:
      let res = sdag.getRootEntry(bid1.root)
      check:
        res.isSome()
        res.get() == entry
    block:
      let res = sdag.getRootEntry(bid2.root)
      check:
        res.isNone()

  test "mgetOrPut(checkpoint)/getRootEntry(root) test":
    var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
    let
      cp1 = Checkpoint(epoch: Epoch(100), root: genBlockRoot(100))
      cp2 = Checkpoint(epoch: Epoch(101), root: genBlockRoot(101))
      entry = sdag.mgetOrPut(cp1)
    block:
      let res = sdag.getRootEntry(cp1.root)
      check:
        res.isSome()
        res.get() == entry
    block:
      let res = sdag.getRootEntry(cp2.root)
      check:
        res.isNone()

  test "Pruning test":
    const TestVectors = [
      (Slot(0) .. Slot(256), Epoch(6), Slot(192) .. Slot(256)),
      (Slot(192) .. Slot(512), Epoch(15), Slot(480) .. Slot(512))
    ]

    for vector in TestVectors:
      var sdag = SyncDag.init(SomeTPeer, PeerId, defaultRuntimeConfig)
      let
        chain = createChainSource(vector[0], 0, Eth2Digest())
        bid = createPeerBlockId(chain, vector[0].b)
        checkpoint = createPeerCheckpoint(chain, vector[0].a)
        hentry = sdag.mgetOrPut(bid)
        fentry {.used.} = sdag.mgetOrPut(checkpoint)

      sdag.pushBlocks(chain, hentry)

      block:
        var rcheck: seq[Eth2Digest]
        rcheck.add(hentry.blockId.root)
        for currentEntry in hentry.parents():
          rcheck.add(currentEntry.blockId.root)
        rcheck.reverse()

        var expect: seq[Eth2Digest]
        for slot in vector[0]:
          if slot == Slot(0):
            # Slot(0) is GENESIS_SLOT so it will be not stored inside SyncDag.
            continue
          let blck = chain.slots.getOrDefault(slot)
          expect.add(blck[].root)

        check len(rcheck) == len(expect)
        for i in 0 ..< len(expect):
          check rcheck[i] == expect[i]

      sdag.prune(vector[1])

      block:
        var rcheck: seq[Eth2Digest]
        rcheck.add(hentry.blockId.root)
        for currentEntry in hentry.parents():
          rcheck.add(currentEntry.blockId.root)
        rcheck.reverse()

        var expect: seq[Eth2Digest]
        for slot in vector[2]:
          if slot == Slot(0):
            # Slot(0) is GENESIS_SLOT so it will be not stored inside SyncDag.
            continue
          let blck = chain.slots.getOrDefault(slot)
          expect.add(blck[].root)

        check len(rcheck) == len(expect)
        for i in 0 ..< len(expect):
          check rcheck[i] == expect[i]

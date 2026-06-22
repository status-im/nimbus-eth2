# beacon_chain
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/[random, heapqueue, tables, sequtils, strutils]
import chronos, chronos/unittest2/asynctests
import eth/enr/enr, eth/common/keys
import ../beacon_chain/networking/[peer_pool, eth2_network]
import ../beacon_chain/spec/[forks, network, eth2_ssz_serialization]
import ./testutil

type
  PeerTestID = string
  PeerTest = ref object
    id: PeerTestID
    weight: int
    metadata: uint64
    future: Future[void]

func getKey(peer: PeerTest): PeerTestID =
  peer.id

func getFuture(peer: PeerTest): Future[void] =
  peer.future

func getMetadata(peer: PeerTest): uint64 =
  peer.metadata

func cmp*(a, b: PeerTest): int =
  cmp(a.weight, b.weight)

proc init*(t: typedesc[PeerTest], id: string = "",
           weight: int = 0): PeerTest =
  PeerTest(id: id, weight: weight, future: newFuture[void]())

proc init*(t: typedesc[PeerTest], id: string = "",
           weight: int = 0, metadata: uint64): PeerTest =
  PeerTest(id: id, weight: weight, future: newFuture[void](),
           metadata: metadata)

proc toString(a: openArray[PeerTest]): string =
  "[" & a.mapIt(it.getKey()).join(",") & "]"

proc close(peer: PeerTest) =
  peer.future.complete()

suite "PeerPool testing suite":
  test "addPeerNoWait() test":
    const peersCount = [
      [10, 5, 5, 10, 5, 5],
      [-1, 5, 5, 10, 5, 5],
      [-1, -1, -1, 10, 5, 5]
    ]
    for item in peersCount:
      var pool = newPeerPool[PeerTest, PeerTestID](item[0], item[1], item[2])
      for i in 0 ..< item[4]:
        var peer = PeerTest.init("idInc" & $i)
        check pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success

      for i in 0 ..< item[5]:
        var peer = PeerTest.init("idOut" & $i)
        check pool.addPeerNoWait(peer, PeerType.Outgoing) == PeerStatus.Success

      var peer = PeerTest.init("idCheck")
      if item[1] != -1:
        for i in 0 ..< item[3]:
          check pool.addPeerNoWait(peer, PeerType.Incoming) ==
            PeerStatus.NoSpaceError
      if item[2] != -1:
        for i in 0 ..< item[3]:
          check pool.addPeerNoWait(peer, PeerType.Outgoing) ==
            PeerStatus.NoSpaceError
      check:
        pool.lenAvailable == item[3]
        pool.lenAvailable({PeerType.Incoming}) == item[4]
        pool.lenAvailable({PeerType.Outgoing}) == item[5]

  test "addPeer() test":
    proc testAddPeer1(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID](maxPeers = 1,
                                                   maxIncomingPeers = 1,
                                                   maxOutgoingPeers = 0)
      var peer0 = PeerTest.init("idInc0")
      var peer1 = PeerTest.init("idOut0")
      var peer2 = PeerTest.init("idInc1")
      var fut0 = pool.addPeer(peer0, PeerType.Incoming)
      var fut1 = pool.addPeer(peer1, PeerType.Outgoing)
      var fut2 = pool.addPeer(peer2, PeerType.Incoming)
      doAssert(fut0.finished == true and fut0.failed == false)
      doAssert(fut1.finished == false)
      doAssert(fut2.finished == false)
      peer0.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut1.finished == false)
      doAssert(fut2.finished == true and fut2.failed == false)
      result = true

    proc testAddPeer2(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID](maxPeers = 2,
                                                   maxIncomingPeers = 1,
                                                   maxOutgoingPeers = 1)
      var peer0 = PeerTest.init("idInc0")
      var peer1 = PeerTest.init("idOut0")
      var peer2 = PeerTest.init("idInc1")
      var peer3 = PeerTest.init("idOut1")
      var fut0 = pool.addPeer(peer0, PeerType.Incoming)
      var fut1 = pool.addPeer(peer1, PeerType.Outgoing)
      var fut2 = pool.addPeer(peer2, PeerType.Incoming)
      var fut3 = pool.addPeer(peer3, PeerType.Outgoing)
      doAssert(fut0.finished == true and fut0.failed == false)
      doAssert(fut1.finished == true and fut1.failed == false)
      doAssert(fut2.finished == false)
      doAssert(fut3.finished == false)
      peer0.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut2.finished == true and fut2.failed == false)
      doAssert(fut3.finished == false)
      peer1.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut3.finished == true and fut3.failed == false)
      result = true

    proc testAddPeer3(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID](maxPeers = 3,
                                                   maxIncomingPeers = 1,
                                                   maxOutgoingPeers = 1)
      var peer0 = PeerTest.init("idInc0")
      var peer1 = PeerTest.init("idInc1")
      var peer2 = PeerTest.init("idOut0")
      var peer3 = PeerTest.init("idOut1")

      var fut0 = pool.addPeer(peer0, PeerType.Incoming)
      var fut1 = pool.addPeer(peer1, PeerType.Incoming)
      var fut2 = pool.addPeer(peer2, PeerType.Outgoing)
      var fut3 = pool.addPeer(peer3, PeerType.Outgoing)
      doAssert(fut0.finished == true and fut0.failed == false)
      doAssert(fut1.finished == false)
      doAssert(fut2.finished == true and fut2.failed == false)
      doAssert(fut3.finished == false)
      peer0.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut1.finished == true and fut1.failed == false)
      doAssert(fut3.finished == false)
      peer2.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut3.finished == true and fut3.failed == false)
      result = true

    proc testAddPeer4(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID](maxPeers = 3)

      var peer0 = PeerTest.init("idInc0")
      var peer1 = PeerTest.init("idInc1")
      var peer2 = PeerTest.init("idOut0")
      var peer3 = PeerTest.init("idOut1")
      var peer4 = PeerTest.init("idOut2")
      var peer5 = PeerTest.init("idInc2")

      var fut0 = pool.addPeer(peer0, PeerType.Incoming)
      var fut1 = pool.addPeer(peer1, PeerType.Incoming)
      var fut2 = pool.addPeer(peer2, PeerType.Outgoing)
      var fut3 = pool.addPeer(peer3, PeerType.Outgoing)
      var fut4 = pool.addPeer(peer4, PeerType.Outgoing)
      var fut5 = pool.addPeer(peer5, PeerType.Incoming)

      doAssert(fut0.finished == true and fut0.failed == false)
      doAssert(fut1.finished == true and fut1.failed == false)
      doAssert(fut2.finished == true and fut2.failed == false)
      doAssert(fut3.finished == false)
      doAssert(fut4.finished == false)
      doAssert(fut5.finished == false)

      await sleepAsync(100.milliseconds)
      doAssert(fut3.finished == false)
      doAssert(fut4.finished == false)
      doAssert(fut5.finished == false)
      peer0.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut3.finished == true and fut3.failed == false)
      doAssert(fut4.finished == false)
      doAssert(fut5.finished == false)
      peer1.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut4.finished == true and fut4.failed == false)
      doAssert(fut5.finished == false)
      peer2.close()
      await sleepAsync(100.milliseconds)
      doAssert(fut5.finished == true and fut5.failed == false)
      result = true

    check:
      waitFor(testAddPeer1()) == true
      waitFor(testAddPeer2()) == true
      waitFor(testAddPeer3()) == true
      waitFor(testAddPeer4()) == true

  test "Acquire from empty pool":
    var pool0 = newPeerPool[PeerTest, PeerTestID]()
    var pool1 = newPeerPool[PeerTest, PeerTestID]()
    var pool2 = newPeerPool[PeerTest, PeerTestID]()

    var itemFut01 = pool0.acquire({PeerType.Incoming})
    var itemFut02 = pool0.acquire({PeerType.Outgoing})
    var itemFut03 = pool0.acquire({PeerType.Incoming, PeerType.Outgoing})
    var itemFut04 = pool0.acquire()
    var itemFut05 = pool0.acquire(5, {PeerType.Incoming})
    var itemFut06 = pool0.acquire(5, {PeerType.Outgoing})
    var itemFut07 = pool0.acquire(5, {PeerType.Incoming, PeerType.Outgoing})
    var itemFut08 = pool0.acquire(5)
    check:
      itemFut01.finished == false
      itemFut02.finished == false
      itemFut03.finished == false
      itemFut04.finished == false
      itemFut05.finished == false
      itemFut06.finished == false
      itemFut07.finished == false
      itemFut08.finished == false

    var peer11 = PeerTest.init("peer11")
    var peer12 = PeerTest.init("peer12")
    var peer21 = PeerTest.init("peer21")
    var peer22 = PeerTest.init("peer22")
    check:
      pool1.addPeerNoWait(peer11, PeerType.Incoming) == PeerStatus.Success
      pool1.addPeerNoWait(peer12, PeerType.Incoming) == PeerStatus.Success
      pool2.addPeerNoWait(peer21, PeerType.Outgoing) == PeerStatus.Success
      pool2.addPeerNoWait(peer22, PeerType.Outgoing) == PeerStatus.Success

    var itemFut11 = pool1.acquire({PeerType.Outgoing})
    var itemFut12 = pool1.acquire(10, {PeerType.Outgoing})
    var itemFut13 = pool1.acquire(3, {PeerType.Incoming})
    var itemFut14 = pool1.acquire({PeerType.Incoming})

    var itemFut21 = pool2.acquire({PeerType.Incoming})
    var itemFut22 = pool2.acquire(10, {PeerType.Incoming})
    var itemFut23 = pool2.acquire(3, {PeerType.Outgoing})
    var itemFut24 = pool1.acquire({PeerType.Outgoing})
    check:
      itemFut11.finished == false
      itemFut12.finished == false
      itemFut13.finished == false
      itemFut14.finished == false
      itemFut21.finished == false
      itemFut22.finished == false
      itemFut23.finished == false
      itemFut24.finished == false

  test "Acquire/Sorting and consistency test":
    const
      TestsCount = 1000
      MaxNumber = 1_000_000

    var pool = newPeerPool[PeerTest, PeerTestID]()

    proc testAcquireRelease(): Future[int] {.async, gcsafe.} =
      var weight: int
      var incoming, outgoing, total: seq[PeerTest]
      var incWeight1, outWeight1, totWeight1: int

      incoming.setLen(0)
      for i in 0 ..< pool.lenAvailable({PeerType.Incoming}):
        var peer = await pool.acquire({PeerType.Incoming})
        incoming.add(peer)

      outgoing.setLen(0)
      for i in 0 ..< pool.lenAvailable({PeerType.Outgoing}):
        var peer = await pool.acquire({PeerType.Outgoing})
        outgoing.add(peer)

      weight = MaxNumber + 1
      incWeight1 = 0
      for i in 0 ..< len(incoming):
        incWeight1 = incWeight1 + incoming[i].weight
        if incoming[i].weight > weight:
          raise newException(ValueError, "Incoming items are not sorted")
        weight = incoming[i].weight
        pool.release(incoming[i])

      weight = MaxNumber + 1
      outWeight1 = 0
      for i in 0..<len(outgoing):
        outWeight1 = outWeight1 + outgoing[i].weight
        if outgoing[i].weight > weight:
          raise newException(ValueError, "Outgoing items are not sorted")
        weight = outgoing[i].weight
        pool.release(outgoing[i])

      for i in 0 ..< pool.lenAvailable():
        var peer = await pool.acquire()
        total.add(peer)

      weight = MaxNumber + 1
      totWeight1 = 0
      for i in 0 ..< len(total):
        totWeight1 = totWeight1 + total[i].weight
        if total[i].weight > weight:
          raise newException(ValueError, "Outgoing items are not sorted")
        weight = total[i].weight
        pool.release(total[i])

      doAssert(totWeight1 == incWeight1 + outWeight1)
      doAssert(len(total) == len(incoming) + len(outgoing))

      result = TestsCount

    randomize()
    for i in 0 ..< TestsCount:
      var peer = PeerTest.init("peer" & $i, rand(MaxNumber))
      # echo repr peer
      if rand(100) mod 2 == 0:
        check pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
      else:
        check pool.addPeerNoWait(peer, PeerType.Outgoing) == PeerStatus.Success

    check waitFor(testAcquireRelease()) == TestsCount

  asyncTest "deletePeer() test":
    var pool = newPeerPool[PeerTest, PeerTestID]()

    ## Delete available peer
    block:
      let peer = PeerTest.init("deletePeer")
      check:
        pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
        pool.len == 1
        pool.lenAvailable == 1
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 1
        pool.deletePeer(peer) == true
        pool.len == 0
        pool.lenAvailable == 0
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 0

    ## Delete acquired peer
    block:
      let peer = PeerTest.init("closingPeer")
      check:
        pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
        pool.len == 1
        pool.lenAvailable == 1
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 1
      let apeer = await pool.acquire()
      check:
        pool.deletePeer(peer) == true
        pool.len == 1
        pool.lenAvailable == 0
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 0
      pool.release(apeer)
      check:
        pool.len == 0
        pool.lenAvailable == 0
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 0

    ## Force delete acquired peer
    block:
      let peer = PeerTest.init("closingPeer")
      check:
        pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
        pool.len == 1
        pool.lenAvailable == 1
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 1
      let apeer = await pool.acquire()
      check:
        pool.deletePeer(apeer, true) == true
        pool.len == 0
        pool.lenAvailable == 0
        pool.lenAvailable({PeerType.Outgoing}) == 0
        pool.lenAvailable({PeerType.Incoming}) == 0

    ## Delete single available peer in pool full of peers
    block:
      for i in 0 ..< 100:
        let peer = PeerTest.init("peer" & $i)
        check pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
      for i in 100 ..< 200:
        let peer = PeerTest.init("peer" & $i)
        check pool.addPeerNoWait(peer, PeerType.Outgoing) == PeerStatus.Success
      check:
        pool.len == 200
        pool.lenAvailable == 200
        pool.lenAvailable({PeerType.Outgoing}) == 100
        pool.lenAvailable({PeerType.Incoming}) == 100
      for i in 0 ..< 20:
        let
          index = 90 + i
          peerKey = "peer" & $index
          dpeer = pool.getOrDefault(peerKey, default(PeerTest))
        check:
          pool.deletePeer(dpeer) == true
          pool.hasPeer(peerKey) == false
      check:
        pool.len == 180
        pool.lenAvailable == 180
        pool.lenAvailable({PeerType.Outgoing}) == 90
        pool.lenAvailable({PeerType.Incoming}) == 90
      pool.clear()

    ## Delete single acquired peer in pool full of peers
    block:
      for i in 0 ..< 100:
        let peer = PeerTest.init("peer" & $i)
        check pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
      for i in 100 ..< 200:
        let peer = PeerTest.init("peer" & $i)
        check pool.addPeerNoWait(peer, PeerType.Outgoing) == PeerStatus.Success
      check:
        pool.len == 200
        pool.lenAvailable == 200
        pool.lenAvailable({PeerType.Outgoing}) == 100
        pool.lenAvailable({PeerType.Incoming}) == 100

      for i in 0 ..< 20:
        let apeer = await pool.acquire()
        check pool.deletePeer(apeer) == true
        pool.release(apeer)
        check pool.hasPeer(apeer.getKey()) == false

      check:
        pool.len == 180
        pool.lenAvailable == 180
      pool.clear()

    ## Force delete single acquired peer in pool full of peers
    block:
      for i in 0 ..< 100:
        let peer = PeerTest.init("peer" & $i)
        check pool.addPeerNoWait(peer, PeerType.Incoming) == PeerStatus.Success
      for i in 100 ..< 200:
        let peer = PeerTest.init("peer" & $i)
        check pool.addPeerNoWait(peer, PeerType.Outgoing) == PeerStatus.Success
      check:
        pool.len == 200
        pool.lenAvailable == 200
        pool.lenAvailable({PeerType.Outgoing}) == 100
        pool.lenAvailable({PeerType.Incoming}) == 100

      for i in 0 ..< 20:
        let apeer = await pool.acquire()
        check:
          pool.deletePeer(apeer, true) == true
          pool.hasPeer(apeer.getKey()) == false

      check:
        pool.len == 180
        pool.lenAvailable == 180

  test "Peer lifetime test":
    proc testPeerLifetime(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID]()
      var peer = PeerTest.init("closingPeer")

      ## Close available peer
      doAssert(pool.addPeerNoWait(peer,
                                  PeerType.Incoming) == PeerStatus.Success)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 1)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 1)
      close(peer)
      # We need to wait next callback scheduler
      await sleepAsync(1.milliseconds)
      doAssert(pool.len == 0)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)

      ## Close acquired peer
      peer = PeerTest.init("closingPeer")
      doAssert(pool.addPeerNoWait(peer,
                                  PeerType.Incoming) == PeerStatus.Success)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 1)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 1)
      var apeer = await pool.acquire()
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)
      close(peer)
      await sleepAsync(1.milliseconds)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)
      pool.release(apeer)
      doAssert(pool.len == 0)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)

      result = true

    check waitFor(testPeerLifetime()) == true

  test "Safe/Clear test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    var peer1 = PeerTest.init("peer1", 10)
    var peer2 = PeerTest.init("peer2", 9)
    var peer3 = PeerTest.init("peer3", 8)

    check:
      pool.addPeerNoWait(peer1, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer2, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == PeerStatus.Success
      pool.lenAvailable == 3
      pool.lenAvailable({PeerType.Outgoing}) == 1
      pool.lenAvailable({PeerType.Incoming}) == 2
      pool.lenAcquired == 0
      pool.len == 3

    pool.clear()

    check:
      pool.lenAvailable == 0
      pool.lenAvailable({PeerType.Outgoing}) == 0
      pool.lenAvailable({PeerType.Incoming}) == 0
      pool.lenAcquired == 0
      pool.len == 0

    check:
      pool.addPeerNoWait(peer1, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer2, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == PeerStatus.Success
      pool.lenAvailable == 3
      pool.lenAvailable({PeerType.Outgoing}) == 1
      pool.lenAvailable({PeerType.Incoming}) == 2
      pool.lenAcquired == 0
      pool.len == 3

    proc testConsumer() {.async.} =
      var p = await pool.acquire()
      await sleepAsync(100.milliseconds)
      pool.release(p)

    proc testClose(): Future[bool] {.async.} =
      await pool.clearSafe()
      result = true

    asyncSpawn testConsumer()
    check waitFor(testClose()) == true

  test "Access peers by key test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    var peer1 = PeerTest.init("peer1", 10)
    var peer2 = PeerTest.init("peer2", 9)
    var peer3 = PeerTest.init("peer3", 8)

    check:
      pool.addPeerNoWait(peer1, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer2, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == PeerStatus.Success
      pool.hasPeer("peer4") == false
      pool.hasPeer("peer1") == true
      pool.hasPeer("peer2") == true
      pool.hasPeer("peer3") == true
      pool.getOrDefault("peer4").id == ""
      pool.getOrDefault("peer4", PeerTest.init("peer5")).id == "peer5"
      pool.getOrDefault("peer1").id == "peer1"
      pool.getOrDefault("peer1", PeerTest.init("peer5")).id == "peer1"
      pool["peer1"].id == "peer1"
      pool["peer1"].weight == 10
      pool["peer2"].id == "peer2"
      pool["peer2"].weight == 9
      pool["peer3"].id == "peer3"
      pool["peer3"].weight == 8

    var ppeer = addr(pool["peer1"])
    ppeer[].weight = 100
    check pool["peer1"].weight == 100

  test "Iterators test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    var peer1 = PeerTest.init("peer1", 10)
    var peer2 = PeerTest.init("peer2", 9)
    var peer3 = PeerTest.init("peer3", 8)
    var peer4 = PeerTest.init("peer4", 7)
    var peer5 = PeerTest.init("peer5", 6)
    var peer6 = PeerTest.init("peer6", 5)
    var peer7 = PeerTest.init("peer7", 4)
    var peer8 = PeerTest.init("peer8", 3)
    var peer9 = PeerTest.init("peer9", 2)

    check:
      pool.addPeerNoWait(peer2, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer3, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer1, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer4, PeerType.Incoming) == PeerStatus.Success

      pool.addPeerNoWait(peer5, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer8, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer7, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer6, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer9, PeerType.Outgoing) == PeerStatus.Success

    var total1, total2, total3: seq[PeerTest]
    var avail1, avail2, avail3: seq[PeerTest]
    var acqui1, acqui2, acqui3: seq[PeerTest]

    for item in pool.peers():
      total1.add(item)
    for item in pool.peers({PeerType.Incoming}):
      total2.add(item)
    for item in pool.peers({PeerType.Outgoing}):
      total3.add(item)

    for item in pool.availablePeers():
      avail1.add(item)
    for item in pool.availablePeers({PeerType.Incoming}):
      avail2.add(item)
    for item in pool.availablePeers({PeerType.Outgoing}):
      avail3.add(item)

    for item in pool.acquiredPeers():
      acqui1.add(item)
    for item in pool.acquiredPeers({PeerType.Incoming}):
      acqui2.add(item)
    for item in pool.acquiredPeers({PeerType.Outgoing}):
      acqui3.add(item)

    check:
      len(total1) == 9
      len(total2) == 4
      len(total3) == 5
      len(avail1) == 9
      len(avail2) == 4
      len(avail3) == 5
      len(acqui1) == 0
      len(acqui2) == 0
      len(acqui3) == 0

    discard waitFor(pool.acquire({PeerType.Incoming}))
    discard waitFor(pool.acquire({PeerType.Incoming}))
    discard waitFor(pool.acquire({PeerType.Outgoing}))

    total1.setLen(0); total2.setLen(0); total3.setLen(0)
    avail1.setLen(0); avail2.setLen(0); avail3.setLen(0)
    acqui1.setLen(0); acqui2.setLen(0); acqui3.setLen(0)

    for item in pool.peers():
      total1.add(item)
    for item in pool.peers({PeerType.Incoming}):
      total2.add(item)
    for item in pool.peers({PeerType.Outgoing}):
      total3.add(item)

    for item in pool.availablePeers():
      avail1.add(item)
    for item in pool.availablePeers({PeerType.Incoming}):
      avail2.add(item)
    for item in pool.availablePeers({PeerType.Outgoing}):
      avail3.add(item)

    for item in pool.acquiredPeers():
      acqui1.add(item)
    for item in pool.acquiredPeers({PeerType.Incoming}):
      acqui2.add(item)
    for item in pool.acquiredPeers({PeerType.Outgoing}):
      acqui3.add(item)

    check:
      len(total1) == 9
      len(total2) == 4
      len(total3) == 5
      len(avail1) == 6
      len(avail2) == 2
      len(avail3) == 4
      len(acqui1) == 3
      len(acqui2) == 2
      len(acqui3) == 1

  asyncTest "Custom filters test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    let
      peer1 = PeerTest.init("peer1", 10, 256'u64)
      peer2 = PeerTest.init("peer2", 9, 0'u64)
      peer3 = PeerTest.init("peer3", 8, 4'u64)
      peer4 = PeerTest.init("peer4", 7, 2'u64)
      peer5 = PeerTest.init("peer5", 6, 2'u64)
      peer6 = PeerTest.init("peer6", 5, 2'u64)
      peer7 = PeerTest.init("peer7", 4, 4'u64)
      peer8 = PeerTest.init("peer8", 3, 128'u64)
      peer9 = PeerTest.init("peer9", 2, 4'u64)
      peer10 = PeerTest.init("peer10", 1, 256'u64)

    proc custom1(peer: PeerTest): bool =
      true

    proc custom2(peer: PeerTest): bool =
      if peer.getMetadata() == 2'u64:
        true
      else:
        false

    proc custom3(peer: PeerTest): bool =
      if peer.getMetadata() in [2'u64, 4'u64]:
        true
      else:
        false

    check:
      pool.addPeerNoWait(peer2, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer3, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer1, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer4, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer5, PeerType.Incoming) == PeerStatus.Success

      pool.addPeerNoWait(peer10, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer7, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer6, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer8, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer9, PeerType.Outgoing) == PeerStatus.Success

    template checkTotal() =
      let
        total1 =
          pool.peers({PeerType.Incoming, PeerType.Outgoing}, custom1).toSeq()
        total2 =
          pool.peers({PeerType.Incoming}, custom1).toSeq()
        total3 =
          pool.peers({PeerType.Outgoing}, custom1).toSeq()
        total4 =
          pool.peers({PeerType.Incoming, PeerType.Outgoing}, custom2).toSeq()
        total5 =
          pool.peers({PeerType.Incoming}, custom2).toSeq()
        total6 =
          pool.peers({PeerType.Outgoing}, custom2).toSeq()
        total7 =
          pool.peers({PeerType.Incoming, PeerType.Outgoing}, custom3).toSeq()
        total8 =
          pool.peers({PeerType.Incoming}, custom3).toSeq()
        total9 =
          pool.peers({PeerType.Outgoing}, custom3).toSeq()

      check:
        total1.toString() ==
          "[peer1,peer2,peer3,peer4,peer5,peer6,peer7,peer8,peer9,peer10]"
        total2.toString() == "[peer1,peer2,peer3,peer4,peer5]"
        total3.toString() == "[peer6,peer7,peer8,peer9,peer10]"
        total4.toString() == "[peer4,peer5,peer6]"
        total5.toString() == "[peer4,peer5]"
        total6.toString() == "[peer6]"
        total7.toString() == "[peer3,peer4,peer5,peer6,peer7,peer9]"
        total8.toString() == "[peer3,peer4,peer5]"
        total9.toString() == "[peer6,peer7,peer9]"

    checkTotal()

    block:
      let
        avail1 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom1).toSeq()
        avail2 =
          pool.availablePeers({PeerType.Incoming}, custom1).toSeq()
        avail3 =
          pool.availablePeers({PeerType.Outgoing}, custom1).toSeq()
        avail4 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom2).toSeq()
        avail5 =
          pool.availablePeers({PeerType.Incoming}, custom2).toSeq()
        avail6 =
          pool.availablePeers({PeerType.Outgoing}, custom2).toSeq()
        avail7 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom3).toSeq()
        avail8 =
          pool.availablePeers({PeerType.Incoming}, custom3).toSeq()
        avail9 =
          pool.availablePeers({PeerType.Outgoing}, custom3).toSeq()

      check:
        avail1.toString() ==
          "[peer1,peer2,peer3,peer4,peer5,peer6,peer7,peer8,peer9,peer10]"
        avail2.toString() == "[peer1,peer2,peer3,peer4,peer5]"
        avail3.toString() == "[peer6,peer7,peer8,peer9,peer10]"
        avail4.toString() == "[peer4,peer5,peer6]"
        avail5.toString() == "[peer4,peer5]"
        avail6.toString() == "[peer6]"
        avail7.toString() == "[peer3,peer4,peer5,peer6,peer7,peer9]"
        avail8.toString() == "[peer3,peer4,peer5]"
        avail9.toString() == "[peer6,peer7,peer9]"

    let
      tpeer1 = await pool.acquire({PeerType.Incoming, PeerType.Outgoing},
                                  custom1)
      tpeer2 = await pool.acquire({PeerType.Incoming}, custom2)
      tpeer3 = await pool.acquire({PeerType.Outgoing}, custom2)
      tpeer4 = await pool.acquire({PeerType.Incoming}, custom3)
      tpeer5 = await pool.acquire({PeerType.Outgoing}, custom3)

    check:
      tpeer1.getKey() == "peer1"
      tpeer2.getKey() == "peer4"
      tpeer3.getKey() == "peer6"
      tpeer4.getKey() == "peer3"
      tpeer5.getKey() == "peer7"

    checkTotal()

    block:
      let
        avail1 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom1).toSeq()
        avail2 =
          pool.availablePeers({PeerType.Incoming}, custom1).toSeq()
        avail3 =
          pool.availablePeers({PeerType.Outgoing}, custom1).toSeq()
        avail4 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom2).toSeq()
        avail5 =
          pool.availablePeers({PeerType.Incoming}, custom2).toSeq()
        avail6 =
          pool.availablePeers({PeerType.Outgoing}, custom2).toSeq()
        avail7 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom3).toSeq()
        avail8 =
          pool.availablePeers({PeerType.Incoming}, custom3).toSeq()
        avail9 =
          pool.availablePeers({PeerType.Outgoing}, custom3).toSeq()

      check:
        avail1.toString() == "[peer2,peer5,peer8,peer9,peer10]"
        avail2.toString() == "[peer2,peer5]"
        avail3.toString() == "[peer8,peer9,peer10]"

        avail4.toString() == "[peer5]"
        avail5.toString() == "[peer5]"
        avail6.toString() == "[]"

        avail7.toString() == "[peer5,peer9]"
        avail8.toString() == "[peer5]"
        avail9.toString() == "[peer9]"

    let
      tpeer6 = await pool.acquire({PeerType.Incoming, PeerType.Outgoing},
                                  custom1)
      tpeer7 = await pool.acquire({PeerType.Incoming}, custom2)
      tpeer8 = await pool.acquire({PeerType.Outgoing}, custom3)
      tpeer9 = await pool.acquire({PeerType.Outgoing}, custom1)
      tpeer10 = await pool.acquire({PeerType.Outgoing}, custom1)

    check:
      tpeer6.getKey() == "peer2"
      tpeer7.getKey() == "peer5"
      tpeer8.getKey() == "peer9"
      tpeer9.getKey() == "peer8"
      tpeer10.getKey() == "peer10"

    checkTotal()

    block:
      let
        avail1 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom1).toSeq()
        avail2 =
          pool.availablePeers({PeerType.Incoming}, custom1).toSeq()
        avail3 =
          pool.availablePeers({PeerType.Outgoing}, custom1).toSeq()
        avail4 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom2).toSeq()
        avail5 =
          pool.availablePeers({PeerType.Incoming}, custom2).toSeq()
        avail6 =
          pool.availablePeers({PeerType.Outgoing}, custom2).toSeq()
        avail7 =
          pool.availablePeers({PeerType.Incoming, PeerType.Outgoing},
                              custom3).toSeq()
        avail8 =
          pool.availablePeers({PeerType.Incoming}, custom3).toSeq()
        avail9 =
          pool.availablePeers({PeerType.Outgoing}, custom3).toSeq()

      check:
        avail1.toString() == "[]"
        avail2.toString() == "[]"
        avail3.toString() == "[]"

        avail4.toString() == "[]"
        avail5.toString() == "[]"
        avail6.toString() == "[]"

        avail7.toString() == "[]"
        avail8.toString() == "[]"
        avail9.toString() == "[]"

    let
      fut1 = pool.acquire({PeerType.Incoming}, custom2)
      fut2 = pool.acquire({PeerType.Incoming}, custom2)
      fut3 = pool.acquire({PeerType.Outgoing}, custom3)
      fut4 = pool.acquire({PeerType.Outgoing}, custom3)

    check:
      fut1.finished == false
      fut2.finished == false
      fut3.finished == false
      fut4.finished == false

    pool.release(tpeer1)
    await sleepAsync(100.milliseconds)
    check:
      fut1.finished == false
      fut2.finished == false
      fut3.finished == false
      fut4.finished == false

    pool.release(tpeer2)
    await sleepAsync(100.milliseconds)
    check:
      fut1.finished == true
      fut1.value.getKey() == "peer4"
      fut2.finished == false
      fut3.finished == false
      fut4.finished == false

    pool.release(tpeer3)
    await sleepAsync(100.milliseconds)
    check:
      fut2.finished == false
      fut3.finished == true
      fut3.value.getKey() == "peer6"
      fut4.finished == false

    pool.release(tpeer5)
    await sleepAsync(100.milliseconds)
    check:
      fut2.finished == false
      fut4.finished == true
      fut4.value.getKey() == "peer7"

    pool.release(tpeer4)
    pool.release(tpeer6)
    pool.release(tpeer8)
    pool.release(tpeer10)
    await sleepAsync(100.milliseconds)
    check:
      fut2.finished == false

    pool.release(tpeer7)
    await sleepAsync(100.milliseconds)
    check:
      fut2.finished == true
      fut2.value.getKey() == "peer5"

  test "Score check test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    func scoreCheck(peer: PeerTest): bool =
      if peer.weight >= 0:
        result = true
      else:
        result = false
    var peer1 = PeerTest.init("peer1", 100)
    var peer2 = PeerTest.init("peer2", 50)
    var peer3 = PeerTest.init("peer3", 1)
    var peer4 = PeerTest.init("peer4", -50)
    var peer5 = PeerTest.init("peer5", -100)

    pool.setScoreCheck(scoreCheck)

    check:
      pool.addPeerNoWait(peer1, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer2, PeerType.Incoming) == PeerStatus.Success
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == PeerStatus.Success
      pool.addPeerNoWait(peer4, PeerType.Incoming) == PeerStatus.LowScoreError
      pool.addPeerNoWait(peer5, PeerType.Outgoing) == PeerStatus.LowScoreError
      len(pool) == 3
      lenAvailable(pool) == 3

    check:
      waitFor(pool.addPeer(peer4, PeerType.Incoming)) ==
        PeerStatus.LowScoreError
      waitFor(pool.addPeer(peer5, PeerType.Outgoing)) ==
        PeerStatus.LowScoreError
      len(pool) == 3
      lenAvailable(pool) == 3

    discard waitFor(pool.acquire({PeerType.Incoming}))
    discard waitFor(pool.acquire({PeerType.Incoming}))
    discard waitFor(pool.acquire({PeerType.Outgoing}))

    check:
      lenAvailable(pool) == 0
      lenAcquired(pool) == 3
      len(pool) == 3

    peer3.weight -= 2
    pool.release(peer3)
    check:
      lenAvailable(pool) == 0
      lenAcquired(pool) == 2
      len(pool) == 2

    peer2.weight -= 100
    pool.release(peer2)
    check:
      lenAvailable(pool) == 0
      lenAcquired(pool) == 1
      len(pool) == 1

    peer1.weight -= 200
    pool.release(peer1)
    check:
      lenAvailable(pool) == 0
      lenAcquired(pool) == 0
      len(pool) == 0

  test "Delete peer on release text":
    proc testDeleteOnRelease(): Future[bool] {.async.} =
      func scoreCheck(peer: PeerTest): bool =
        if peer.weight >= 0:
          result = true
        else:
          result = false

      var pool = newPeerPool[PeerTest, PeerTestID](maxPeers = 1,
                                                   maxIncomingPeers = 1,
                                                   maxOutgoingPeers = 0)
      pool.setScoreCheck(scoreCheck)

      var peer0 = PeerTest.init("idInc0", 100)
      var peer1 = PeerTest.init("idOut0", 100)
      var peer2 = PeerTest.init("idInc1", 100)
      var fut0 = pool.addPeer(peer0, PeerType.Incoming)
      var fut1 = pool.addPeer(peer1, PeerType.Outgoing)
      var fut2 = pool.addPeer(peer2, PeerType.Incoming)
      doAssert(fut0.finished == true and fut0.failed == false)
      doAssert(fut1.finished == false)
      doAssert(fut2.finished == false)
      var p = await pool.acquire()
      doAssert(p.id == "idInc0")
      p.weight = -200
      pool.release(p)
      await sleepAsync(100.milliseconds)
      doAssert(fut1.finished == false)
      doAssert(fut2.finished == true and fut2.failed == false)
      doAssert(len(pool) == 1)
      result = true

    check waitFor(testDeleteOnRelease()) == true

  test "Space tests":
    var pool1 = newPeerPool[PeerTest, PeerTestID](maxPeers = 79)
    var pool2 = newPeerPool[PeerTest, PeerTestID](maxPeers = 79,
                                                  maxIncomingPeers = 39)
    var pool3 = newPeerPool[PeerTest, PeerTestID](maxPeers = 79,
                                                  maxOutgoingPeers = 40)
    var pool4 = newPeerPool[PeerTest, PeerTestID](maxPeers = 79,
                                                  maxOutgoingPeers = 40,
                                                  maxIncomingPeers = 0)
    var pool5 = newPeerPool[PeerTest, PeerTestID](maxPeers = 79,
                                                  maxIncomingPeers = 39,
                                                  maxOutgoingPeers = 0)
    var pool6 = newPeerPool[PeerTest, PeerTestID](maxPeers = 79,
                                                  maxIncomingPeers = 39,
                                                  maxOutgoingPeers = 40)
    var pool7 = newPeerPool[PeerTest, PeerTestID](maxIncomingPeers = 39)
    var pool8 = newPeerPool[PeerTest, PeerTestID](maxOutgoingPeers = 40)
    var pool9 = newPeerPool[PeerTest, PeerTestID]()

    check:
      pool1.lenSpace() == 79
      pool1.lenSpace({PeerType.Incoming}) == 79
      pool1.lenSpace({PeerType.Outgoing}) == 79
      pool2.lenSpace() == 79
      pool2.lenSpace({PeerType.Incoming}) == 39
      pool2.lenSpace({PeerType.Outgoing}) == 79
      pool3.lenSpace() == 79
      pool3.lenSpace({PeerType.Incoming}) == 79
      pool3.lenSpace({PeerType.Outgoing}) == 40
      pool4.lenSpace() == 40
      pool4.lenSpace({PeerType.Incoming}) == 0
      pool4.lenSpace({PeerType.Outgoing}) == 40
      pool5.lenSpace() == 39
      pool5.lenSpace({PeerType.Incoming}) == 39
      pool5.lenSpace({PeerType.Outgoing}) == 0
      pool6.lenSpace() == 79
      pool6.lenSpace({PeerType.Incoming}) == 39
      pool6.lenSpace({PeerType.Outgoing}) == 40
      pool7.lenSpace() == high(int)
      pool7.lenSpace({PeerType.Incoming}) == 39
      pool7.lenSpace({PeerType.Outgoing}) == high(int)
      pool8.lenSpace() == high(int)
      pool8.lenSpace({PeerType.Incoming}) == high(int)
      pool8.lenSpace({PeerType.Outgoing}) == 40
      pool9.lenSpace() == high(int)
      pool9.lenSpace({PeerType.Incoming}) == high(int)
      pool9.lenSpace({PeerType.Outgoing}) == high(int)

    # POOL 1
    for i in 0 ..< 79:
      if i mod 2 == 0:
        check pool1.addPeerNoWait(PeerTest.init("idInc" & $i),
                                  PeerType.Incoming) == PeerStatus.Success
      else:
        check pool1.addPeerNoWait(PeerTest.init("idOut" & $i),
                                  PeerType.Outgoing) == PeerStatus.Success
      check pool1.lenSpace() == 79 - (i + 1)

    # POOL 2
    for i in 0 ..< 39:
      check:
        pool2.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool2.lenSpace() == 79 - (i + 1)
        pool2.lenSpace({PeerType.Incoming}) == 39 - (i + 1)
        pool2.lenSpace({PeerType.Outgoing}) == 79 - (i + 1)

    check:
      pool2.addPeerNoWait(PeerTest.init("idInc39"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool2.lenSpace({PeerType.Incoming}) == 0

    for i in 39 ..< 79:
      check:
        pool2.addPeerNoWait(PeerTest.init("idOut" & $i),
                            PeerType.Outgoing) == PeerStatus.Success
        pool2.addPeerNoWait(PeerTest.init("idIncSome"),
                            PeerType.Incoming) == PeerStatus.NoSpaceError
        pool2.lenSpace() == 79 - (i + 1)
        pool2.lenSpace({PeerType.Incoming}) == 0
        pool2.lenSpace({PeerType.Outgoing}) == 79 - (i + 1)

    check:
      pool2.addPeerNoWait(PeerTest.init("idOut79"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool2.addPeerNoWait(PeerTest.init("idInc79"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool2.lenSpace() == 0
      pool2.lenSpace({PeerType.Incoming}) == 0
      pool2.lenSpace({PeerType.Outgoing}) == 0

    # POOL 3
    for i in 0 ..< 40:
      check:
        pool3.addPeerNoWait(PeerTest.init("idOut" & $i),
                            PeerType.Outgoing) == PeerStatus.Success
        pool3.lenSpace() == 79 - (i + 1)
        pool3.lenSpace({PeerType.Outgoing}) == 40 - (i + 1)
        pool3.lenSpace({PeerType.Incoming}) == 79 - (i + 1)

    check:
      pool3.addPeerNoWait(PeerTest.init("idInc40"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool3.lenSpace({PeerType.Outgoing}) == 0

    for i in 40 ..< 79:
      check:
        pool3.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool3.addPeerNoWait(PeerTest.init("idOutSome"),
                            PeerType.Outgoing) == PeerStatus.NoSpaceError
        pool3.lenSpace() == 79 - (i + 1)
        pool3.lenSpace({PeerType.Outgoing}) == 0
        pool3.lenSpace({PeerType.Incoming}) == 79 - (i + 1)

    check:
      pool3.addPeerNoWait(PeerTest.init("idInc79"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool3.addPeerNoWait(PeerTest.init("idOut79"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool3.lenSpace() == 0
      pool3.lenSpace({PeerType.Incoming}) == 0
      pool3.lenSpace({PeerType.Outgoing}) == 0

    # POOL 4
    for i in 0 ..< 40:
      check:
        pool4.addPeerNoWait(PeerTest.init("idOut" & $i),
                            PeerType.Outgoing) == PeerStatus.Success
        pool4.addPeerNoWait(PeerTest.init("idIncSome"),
                            PeerType.Incoming) == PeerStatus.NoSpaceError
        pool4.lenSpace() == 40 - (i + 1)
        pool4.lenSpace({PeerType.Incoming}) == 0
        pool4.lenSpace({PeerType.Outgoing}) == 40 - (i + 1)

    check:
      pool4.addPeerNoWait(PeerTest.init("idOut40"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool4.addPeerNoWait(PeerTest.init("idInc40"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool4.lenSpace() == 0
      pool4.lenSpace({PeerType.Incoming}) == 0
      pool4.lenSpace({PeerType.Outgoing}) == 0

    # POOL 5
    for i in 0 ..< 39:
      check:
        pool5.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool5.addPeerNoWait(PeerTest.init("idOutSome"),
                            PeerType.Outgoing) == PeerStatus.NoSpaceError
        pool5.lenSpace() == 39 - (i + 1)
        pool5.lenSpace({PeerType.Incoming}) == 39 - (i + 1)
        pool5.lenSpace({PeerType.Outgoing}) == 0

    check:
      pool5.addPeerNoWait(PeerTest.init("idOut39"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool5.addPeerNoWait(PeerTest.init("idInc39"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool5.lenSpace() == 0
      pool5.lenSpace({PeerType.Incoming}) == 0
      pool5.lenSpace({PeerType.Outgoing}) == 0

    # POOL 6
    for i in 0 ..< 39:
      check:
        pool6.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool6.addPeerNoWait(PeerTest.init("idOut" & $(i + 39)),
                            PeerType.Outgoing) == PeerStatus.Success
        pool6.lenSpace() == 79 - (i + 1) * 2
        pool6.lenSpace({PeerType.Incoming}) == 39 - (i + 1)
        pool6.lenSpace({PeerType.Outgoing}) == 40 - (i + 1)

    check:
      pool6.addPeerNoWait(PeerTest.init("idInc39"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool6.addPeerNoWait(PeerTest.init("idOut79"),
                          PeerType.Outgoing) == PeerStatus.Success
      pool6.addPeerNoWait(PeerTest.init("idOut80"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool6.lenSpace() == 0
      pool6.lenSpace({PeerType.Incoming}) == 0
      pool6.lenSpace({PeerType.Outgoing}) == 0

    # POOL 7
    for i in 0 ..< 39:
      check:
        pool7.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool7.lenSpace() == high(int) - (i + 1)
        pool7.lenSpace({PeerType.Incoming}) == 39 - (i + 1)
        pool7.lenSpace({PeerType.Outgoing}) == high(int) - (i + 1)

    check:
      pool7.addPeerNoWait(PeerTest.init("idInc39"),
                          PeerType.Incoming) == PeerStatus.NoSpaceError
      pool7.lenSpace() == high(int) - 39
      pool7.lenSpace({PeerType.Incoming}) == 0
      pool7.lenSpace({PeerType.Outgoing}) == high(int) - 39

    # We could not check whole high(int), so we check 1000 items
    for i in 0 ..< 1000:
      check:
        pool7.addPeerNoWait(PeerTest.init("idOut" & $i),
                            PeerType.Outgoing) == PeerStatus.Success
        pool7.lenSpace() == high(int) - 39 - (i + 1)
        pool7.lenSpace({PeerType.Incoming}) == 0
        pool7.lenSpace({PeerType.Outgoing}) == high(int) - 39 - (i + 1)

    # POOL 8
    for i in 0 ..< 40:
      check:
        pool8.addPeerNoWait(PeerTest.init("idOut" & $i),
                            PeerType.Outgoing) == PeerStatus.Success
        pool8.lenSpace() == high(int) - (i + 1)
        pool8.lenSpace({PeerType.Outgoing}) == 40 - (i + 1)
        pool8.lenSpace({PeerType.Incoming}) == high(int) - (i + 1)

    check:
      pool8.addPeerNoWait(PeerTest.init("idOut40"),
                          PeerType.Outgoing) == PeerStatus.NoSpaceError
      pool8.lenSpace() == high(int) - 40
      pool8.lenSpace({PeerType.Outgoing}) == 0
      pool8.lenSpace({PeerType.Incoming}) == high(int) - 40

    # We could not check whole high(int), so we check 1000 items
    for i in 0 ..< 1000:
      check:
        pool8.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool8.lenSpace() == high(int) - 40 - (i + 1)
        pool8.lenSpace({PeerType.Outgoing}) == 0
        pool8.lenSpace({PeerType.Incoming}) == high(int) - 40 - (i + 1)

    # POOL 9
    # We could not check whole high(int), so we check 1000 items
    for i in 0 ..< 1000:
      check:
        pool9.addPeerNoWait(PeerTest.init("idInc" & $i),
                            PeerType.Incoming) == PeerStatus.Success
        pool9.addPeerNoWait(PeerTest.init("idOut" & $i),
                            PeerType.Outgoing) == PeerStatus.Success
        pool9.lenSpace() == high(int) - (i + 1) * 2
        pool9.lenSpace({PeerType.Outgoing}) == high(int) - (i + 1) * 2
        pool9.lenSpace({PeerType.Incoming}) == high(int) - (i + 1) * 2

suite "lookupCgcFromPeer testing suite":
  proc createEnrWithCgc(rng: ref HmacDrbgContext,
                        cgcValue: uint8): enr.Record =
    let pk = keys.PrivateKey.random(rng[])
    Record.init(
      1, pk,
      extraFields = [toFieldPair(enrCustodyGroupCountField,
                                 SSZ.encode(cgcValue))]).expect(
      "Valid ENR")

  proc createEnrWithoutCgc(rng: ref HmacDrbgContext): enr.Record =
    let pk = keys.PrivateKey.random(rng[])
    Record.init(1, pk).expect("Valid ENR")

  let testNetwork = Eth2Node(cfg: defaultRuntimeConfig)

  proc createMinimalPeer(
      metadata: Opt[fulu.MetaData] = Opt.none(fulu.MetaData),
      enrRecord: Opt[enr.Record] = Opt.none(enr.Record)): Peer =
    # Create a minimal Peer for testing lookupCgcFromPeer.
    # Only network.cfg, metadata and enr fields are accessed by the function.
    Peer(
      network: testNetwork,
      metadata: metadata,
      enr: enrRecord,
    )

  test "No metadata, no ENR - returns default CUSTODY_REQUIREMENT":
    let peer = createMinimalPeer()
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == CUSTODY_REQUIREMENT

  test "Valid metadata with cgc >= CUSTODY_REQUIREMENT":
    let metadata = fulu.MetaData(custody_group_count: 8)
    let peer = createMinimalPeer(
      metadata = Opt.some(metadata))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == 8

  test "Valid metadata with cgc == CUSTODY_REQUIREMENT (boundary)":
    let metadata = fulu.MetaData(
      custody_group_count: CUSTODY_REQUIREMENT)
    let peer = createMinimalPeer(
      metadata = Opt.some(metadata))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == CUSTODY_REQUIREMENT

  test "Valid metadata with cgc == NUMBER_OF_CUSTODY_GROUPS (supernode)":
    let metadata = fulu.MetaData(
      custody_group_count: defaultRuntimeConfig.NUMBER_OF_CUSTODY_GROUPS)
    let peer = createMinimalPeer(
      metadata = Opt.some(metadata))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == defaultRuntimeConfig.NUMBER_OF_CUSTODY_GROUPS

  test "Metadata cgc exceeds NUMBER_OF_CUSTODY_GROUPS - returns OutOfRange":
    let metadata = fulu.MetaData(
      custody_group_count: defaultRuntimeConfig.NUMBER_OF_CUSTODY_GROUPS + 1)
    let peer = createMinimalPeer(
      metadata = Opt.some(metadata))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isErr
      res.error == PeerCgcStatus.OutOfRange

  test "Metadata cgc below CUSTODY_REQUIREMENT, valid ENR cgc":
    let
      rng = HmacDrbgContext.new()
      enrRecord = createEnrWithCgc(rng, 8)
      metadata = fulu.MetaData(custody_group_count: 0)
      peer = createMinimalPeer(
        metadata = Opt.some(metadata),
        enrRecord = Opt.some(enrRecord))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == 8

  test "Metadata cgc below CUSTODY_REQUIREMENT, valid ENR cgc updates metadata":
    let
      rng = HmacDrbgContext.new()
      enrRecord = createEnrWithCgc(rng, 16)
      metadata = fulu.MetaData(custody_group_count: 0)
      peer = createMinimalPeer(
        metadata = Opt.some(metadata),
        enrRecord = Opt.some(enrRecord))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == 16
      peer.metadata.get.custody_group_count == 16

  test "No metadata, valid ENR cgc":
    let
      rng = HmacDrbgContext.new()
      enrRecord = createEnrWithCgc(rng, 10)
      peer = createMinimalPeer(
        enrRecord = Opt.some(enrRecord))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == 10

  test "No metadata, ENR cgc exceeds NUMBER_OF_CUSTODY_GROUPS - returns OutOfRange":
    let
      rng = HmacDrbgContext.new()
      enrRecord = createEnrWithCgc(
        rng, (defaultRuntimeConfig.NUMBER_OF_CUSTODY_GROUPS + 1).uint8)
      peer = createMinimalPeer(
        enrRecord = Opt.some(enrRecord))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isErr
      res.error == PeerCgcStatus.OutOfRange

  test "No metadata, ENR without cgc field - returns default":
    let
      rng = HmacDrbgContext.new()
      enrRecord = createEnrWithoutCgc(rng)
      peer = createMinimalPeer(
        enrRecord = Opt.some(enrRecord))
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == CUSTODY_REQUIREMENT

  test "No metadata, no ENR - returns default CUSTODY_REQUIREMENT":
    let peer = createMinimalPeer()
    let res = peer.lookupCgcFromPeer()
    check:
      res.isOk
      res.get == CUSTODY_REQUIREMENT

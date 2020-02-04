# beacon_chain
# Copyright (c) 2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest, random, heapqueue, tables, strutils,
  ./testutil,
  chronos,
  ../beacon_chain/peer_pool

type
  PeerTestID* = string
  PeerTest* = object
    id: PeerTestID
    weight: int
    future: Future[void]

proc getKey*(peer: PeerTest): PeerTestID =
  result = peer.id

proc getFuture*(peer: PeerTest): Future[void] =
  result = peer.future

proc `<`*(a, b: PeerTest): bool =
  result = `<`(a.weight, b.weight)

proc init*(t: typedesc[PeerTest], id: string = "",
           weight: int = 0): PeerTest =
  result = PeerTest(id: id, weight: weight, future: newFuture[void]())

proc close*(peer: PeerTest) =
  peer.future.complete()

suite "PeerPool testing suite":
  timedTest "addPeerNoWait() test":
    const peersCount = [
      [10, 5, 5, 10, 5, 5],
      [-1, 5, 5, 10, 5, 5],
      [-1, -1, -1, 10, 5, 5]
    ]
    for item in peersCount:
      var pool = newPeerPool[PeerTest, PeerTestID](item[0], item[1], item[2])
      for i in 0 ..< item[4]:
        var peer = PeerTest.init("idInc" & $i)
        check pool.addIncomingPeerNoWait(peer) == true

      for i in 0 ..< item[5]:
        var peer = PeerTest.init("idOut" & $i)
        check pool.addOutgoingPeerNoWait(peer) == true

      var peer = PeerTest.init("idCheck")
      if item[1] != -1:
        for i in 0 ..< item[3]:
          check pool.addIncomingPeerNoWait(peer) == false
      if item[2] != -1:
        for i in 0 ..< item[3]:
          check pool.addOutgoingPeerNoWait(peer) == false
      check:
        pool.lenAvailable == item[3]
        pool.lenAvailable({PeerType.Incoming}) == item[4]
        pool.lenAvailable({PeerType.Outgoing}) == item[5]

  timedTest "addPeer() test":
    proc testAddPeer1(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID](maxPeers = 1,
                                                   maxIncomingPeers = 1,
                                                   maxOutgoingPeers = 0)
      var peer0 = PeerTest.init("idInc0")
      var peer1 = PeerTest.init("idOut0")
      var peer2 = PeerTest.init("idInc1")
      var fut0 = pool.addIncomingPeer(peer0)
      var fut1 = pool.addOutgoingPeer(peer1)
      var fut2 = pool.addIncomingPeer(peer2)
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
      var fut0 = pool.addIncomingPeer(peer0)
      var fut1 = pool.addOutgoingPeer(peer1)
      var fut2 = pool.addIncomingPeer(peer2)
      var fut3 = pool.addOutgoingPeer(peer3)
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

      var fut0 = pool.addIncomingPeer(peer0)
      var fut1 = pool.addIncomingPeer(peer1)
      var fut2 = pool.addOutgoingPeer(peer2)
      var fut3 = pool.addOutgoingPeer(peer3)
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

    check:
      waitFor(testAddPeer1()) == true
      waitFor(testAddPeer2()) == true
      waitFor(testAddPeer3()) == true

  timedTest "Acquire from empty pool":
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
      pool1.addPeerNoWait(peer11, PeerType.Incoming) == true
      pool1.addPeerNoWait(peer12, PeerType.Incoming) == true
      pool2.addPeerNoWait(peer21, PeerType.Outgoing) == true
      pool2.addPeerNoWait(peer22, PeerType.Outgoing) == true

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

  timedTest "Acquire/Sorting and consistency test":
    const
      TestsCount = 1000
      MaxNumber = 1_000_000

    var pool = newPeerPool[PeerTest, PeerTestID]()

    proc testAcquireRelease(): Future[int] {.async.} =
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
        check pool.addPeerNoWait(peer, PeerType.Incoming) == true
      else:
        check pool.addPeerNoWait(peer, PeerType.Outgoing) == true

    check waitFor(testAcquireRelease()) == TestsCount

  timedTest "deletePeer() test":
    proc testDeletePeer(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID]()
      var peer = PeerTest.init("deletePeer")

      ## Delete available peer
      doAssert(pool.addIncomingPeerNoWait(peer) == true)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 1)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 1)
      doAssert(pool.deletePeer(peer) == true)
      doAssert(pool.len == 0)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)

      ## Delete acquired peer
      peer = PeerTest.init("closingPeer")
      doAssert(pool.addIncomingPeerNoWait(peer) == true)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 1)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 1)
      var apeer = await pool.acquire()
      doAssert(pool.deletePeer(peer) == true)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)
      pool.release(apeer)
      doAssert(pool.len == 0)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)

      ## Force delete acquired peer
      peer = PeerTest.init("closingPeer")
      doAssert(pool.addIncomingPeerNoWait(peer) == true)
      doAssert(pool.len == 1)
      doAssert(pool.lenAvailable == 1)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 1)
      apeer = await pool.acquire()
      doAssert(pool.deletePeer(peer, true) == true)
      doAssert(pool.len == 0)
      doAssert(pool.lenAvailable == 0)
      doAssert(pool.lenAvailable({PeerType.Outgoing}) == 0)
      doAssert(pool.lenAvailable({PeerType.Incoming}) == 0)

      result = true
    check waitFor(testDeletePeer()) == true

  timedTest "Peer lifetime test":
    proc testPeerLifetime(): Future[bool] {.async.} =
      var pool = newPeerPool[PeerTest, PeerTestID]()
      var peer = PeerTest.init("closingPeer")

      ## Close available peer
      doAssert(pool.addIncomingPeerNoWait(peer) == true)
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
      doAssert(pool.addIncomingPeerNoWait(peer) == true)
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

  timedTest "Safe/Clear test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    var peer1 = PeerTest.init("peer1", 10)
    var peer2 = PeerTest.init("peer2", 9)
    var peer3 = PeerTest.init("peer3", 8)

    check:
      pool.addPeerNoWait(peer1, PeerType.Incoming) == true
      pool.addPeerNoWait(peer2, PeerType.Incoming) == true
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == true
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
      pool.addPeerNoWait(peer1, PeerType.Incoming) == true
      pool.addPeerNoWait(peer2, PeerType.Incoming) == true
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == true
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

    asyncCheck testConsumer()
    check waitFor(testClose()) == true

  timedTest "Access peers by key test":
    var pool = newPeerPool[PeerTest, PeerTestID]()
    var peer1 = PeerTest.init("peer1", 10)
    var peer2 = PeerTest.init("peer2", 9)
    var peer3 = PeerTest.init("peer3", 8)

    check:
      pool.addPeerNoWait(peer1, PeerType.Incoming) == true
      pool.addPeerNoWait(peer2, PeerType.Incoming) == true
      pool.addPeerNoWait(peer3, PeerType.Outgoing) == true
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

  timedTest "Iterators test":
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
      pool.addPeerNoWait(peer2, PeerType.Incoming) == true
      pool.addPeerNoWait(peer3, PeerType.Incoming) == true
      pool.addPeerNoWait(peer1, PeerType.Incoming) == true
      pool.addPeerNoWait(peer4, PeerType.Incoming) == true

      pool.addPeerNoWait(peer5, PeerType.Outgoing) == true
      pool.addPeerNoWait(peer8, PeerType.Outgoing) == true
      pool.addPeerNoWait(peer7, PeerType.Outgoing) == true
      pool.addPeerNoWait(peer6, PeerType.Outgoing) == true
      pool.addPeerNoWait(peer9, PeerType.Outgoing) == true

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

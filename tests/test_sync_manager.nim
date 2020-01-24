# beacon_chain
# Copyright (c) 2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import options, hashes, unittest
import ./testutil
import chronos
import ../beacon_chain/peer_pool, ../beacon_chain/sync_manager

type
  PeerRequest = object
    headRoot: Eth2Digest
    startSlot: Slot
    count: uint64
    step: uint64
    data: seq[Slot]

  SimplePeerKey = string

  SimplePeer = ref object
    id: SimplePeerKey
    weight: int
    lifu: Future[void]
    blockchain: seq[SignedBeaconBlock]
    latestSlot: Slot
    delay: Duration
    malicious: bool
    failure: bool
    disconnect: bool
    requests: seq[PeerRequest]

proc getKey*(peer: SimplePeer): SimplePeerKey =
  result = peer.id

proc getFuture*(peer: SimplePeer): Future[void] =
  result = peer.lifu

proc `<`*(a, b: SimplePeer): bool =
  result = `<`(a.weight, b.weight)

proc getHeadSlot*(peer: SimplePeer): Slot =
  if len(peer.blockchain) == 0:
    result = peer.latestSlot
  else:
    result = peer.blockchain[len(peer.blockchain) - 1].message.slot

proc init*(t: typedesc[SimplePeer], id: string = "", malicious = false,
           weight: int = 0, slot: int = 0,
           delay: Duration = ZeroDuration): SimplePeer =
  result = SimplePeer(id: id, weight: weight, lifu: newFuture[void](),
                      delay: delay, latestSlot: Slot(slot),
                      malicious: malicious)

proc update*(peer: SimplePeer, chain: openarray[SignedBeaconBlock],
             malicious = false, failure = false, disconnect = false,
             delay: Duration = ZeroDuration) =
  peer.malicious = malicious
  peer.delay = delay
  peer.failure = failure
  peer.disconnect = disconnect
  peer.blockchain.setLen(0)
  for item in chain:
    peer.blockchain.add(item)

proc close*(peer: SimplePeer) =
  peer.lifu.complete()

proc getHeadRoot*(peer: SimplePeer): Eth2Digest =
  discard

proc updateStatus*[A](peer: A): Future[void] =
  var res = newFuture[void]("updateStatus")
  res.complete()
  return res

proc getBeaconBlocksByRange*[A](peer: A, headRoot: Eth2Digest, startSlot: Slot,
                                count: uint64,
                         step: uint64): Future[OptionBeaconBlockSeq] {.async.} =
  var req = PeerRequest(headRoot: headRoot, startSlot: startSlot, count: count,
                        step: step)
  var res = newSeq[SignedBeaconBlock]()
  var reqres = newSeq[Slot]()
  if peer.delay != ZeroDuration:
    await sleepAsync(peer.delay)

  var counter = 0'u64

  if peer.failure:
    peer.requests.add(req)
    if peer.disconnect:
      peer.close()
    raise newException(SyncManagerError, "Error")

  if peer.malicious:
    var index = 0
    while counter < count:
      if index < len(peer.blockchain):
        res.add(peer.blockchain[index])
        reqres.add(peer.blockchain[index].message.slot)
      else:
        break
      index = index + int(step)
      counter = counter + 1'u64
    req.data = reqres
    peer.requests.add(req)
    result = some(res)
  else:
    var index = -1
    for i in 0 ..< len(peer.blockchain):
      if peer.blockchain[i].message.slot == startSlot:
        index = i
        break

    if index >= 0:
      while counter < count:
        if index < len(peer.blockchain):
          res.add(peer.blockchain[index])
          reqres.add(peer.blockchain[index].message.slot)
        else:
          break
        index = index + int(step)
        counter = counter + 1'u64
      req.data = reqres
      result = some(res)
    peer.requests.add(req)

proc newTempChain*(number: int, start: Slot): seq[SignedBeaconBlock] =
  result = newSeq[SignedBeaconBlock](number)
  for i in 0 ..< number:
    result[i].message.slot = start + uint64(i)

proc `==`*(a1, a2: SignedBeaconBlock): bool {.inline.} =
  result = (a1.message.slot == a2.message.slot) and
           (a1.message.parent_root == a2.message.parent_root) and
           (a1.message.state_root == a2.message.state_root)

proc peerSlotTests(): Future[bool] {.async.} =
  # slot0: 3 ok
  # slot1: 2 ok 1 timeout
  # slot2: 1 ok 2 timeout
  # slot3: 2 ok 1 bad
  # slot4: 1 ok 2 bad
  # slot5: 2 ok 1 failure
  # slot6: 1 ok 2 failure
  # slot7: 1 ok 1 bad 1 failure
  # slot8: 1 bad 1 timeout 1 failure
  # slot9: 3 bad
  # slot10: 3 timeout
  # slot11: 3 failure
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()
  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, nil, nil,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 6)

  var chain1 = newTempChain(10, Slot(10000))
  var chain2 = newTempChain(10, Slot(11000))

  var peers = newSeq[SimplePeer]()
  for i in 0 ..< 36:
    var peer = SimplePeer.init("id" & $i)
    peers.add(peer)

  peers[0].update(chain1)
  peers[1].update(chain1)
  peers[2].update(chain1)

  peers[3].update(chain1)
  peers[4].update(chain1, delay = 2.seconds)
  peers[5].update(chain1)

  peers[6].update(chain1)
  peers[7].update(chain1, delay = 2.seconds)
  peers[8].update(chain1, delay = 2.seconds)

  peers[9].update(chain1)
  peers[10].update(chain1)
  peers[11].update(chain2, malicious = true)

  peers[12].update(chain1)
  peers[13].update(chain2, malicious = true)
  peers[14].update(chain2, malicious = true)

  peers[15].update(chain1)
  peers[16].update(chain1)
  peers[17].update(chain1, failure = true)

  peers[18].update(chain1)
  peers[19].update(chain1, failure = true)
  peers[20].update(chain1, failure = true)

  peers[21].update(chain1)
  peers[22].update(chain2, malicious = true)
  peers[23].update(chain1, failure = true)

  peers[24].update(chain2, malicious = true)
  peers[25].update(chain1, failure = true)
  peers[26].update(chain1, delay = 2.seconds)

  peers[27].update(chain2, malicious = true)
  peers[28].update(chain2, malicious = true)
  peers[29].update(chain2, malicious = true)

  peers[30].update(chain1, delay = 2.seconds)
  peers[31].update(chain1, delay = 2.seconds)
  peers[32].update(chain1, delay = 2.seconds)

  peers[33].update(chain1, failure = true)
  peers[34].update(chain1, failure = true)
  peers[35].update(chain1, failure = true)

  var slot0 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot0.peers = @[peers[0], peers[1], peers[2]]

  var slot1 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot1.peers = @[peers[3], peers[4], peers[5]]

  var slot2 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot2.peers = @[peers[6], peers[7], peers[8]]

  var slot3 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot3.peers = @[peers[9], peers[10], peers[11]]

  var slot4 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot4.peers = @[peers[12], peers[13], peers[14]]

  var slot5 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot5.peers = @[peers[15], peers[16], peers[17]]

  var slot6 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot6.peers = @[peers[18], peers[19], peers[20]]

  var slot7 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot7.peers = @[peers[21], peers[22], peers[23]]

  var slot8 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot8.peers = @[peers[24], peers[25], peers[26]]

  var slot9 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot9.peers = @[peers[27], peers[28], peers[29]]

  var slot10 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot10.peers = @[peers[30], peers[31], peers[32]]

  var slot11 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot11.peers = @[peers[33], peers[34], peers[35]]

  var s0 = await slot0.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s1 = await slot1.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s2 = await slot2.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s3 = await slot3.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s4 = await slot4.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s5 = await slot5.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s6 = await slot6.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s7 = await slot7.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s8 = await slot8.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s9 = await slot9.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s10 = await slot10.getBlocks(Slot(10000), 10'u64, 1'u64)
  var s11 = await slot11.getBlocks(Slot(10000), 10'u64, 1'u64)

  var expected = BlockList.init(Slot(10000), 10'u64, 1'u64, chain1).get()

  doAssert(s0.isSome())
  doAssert(s1.isSome())
  doAssert(s2.isNone())
  doAssert(s3.isSome())
  doAssert(s4.isNone())
  doAssert(s5.isSome())
  doAssert(s6.isNone())
  doAssert(s7.isNone())
  doAssert(s8.isNone())
  doAssert(s9.isNone())
  doAssert(s10.isNone())
  doAssert(s11.isNone())
  doAssert($s0.get() == $expected)
  doAssert($s1.get() == $expected)
  doAssert($s3.get() == $expected)
  doAssert($s5.get() == $expected)

  result = true

proc peerGroupTests(): Future[bool] {.async.} =
  # group0: 3 ok
  # group1: 2 ok 1 bad
  # group2: 1 ok 2 bad
  # group3: 3 bad
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()
  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, nil, nil,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 6)

  var chain1 = newTempChain(10, Slot(10000))
  var chain2 = newTempChain(10, Slot(11000))

  var peers = newSeq[SimplePeer]()
  for i in 0 ..< 18:
    var peer = SimplePeer.init("id" & $i)
    peers.add(peer)

  proc cleanup() =
    for i in 0 ..< 18:
      peers[i].requests.setLen(0)

  peers[0].update(chain1)
  peers[1].update(chain1)
  peers[2].update(chain1)

  peers[3].update(chain1)
  peers[4].update(chain1)
  peers[5].update(chain1)

  peers[6].update(chain1)
  peers[7].update(chain1)
  peers[8].update(chain1)

  peers[9].update(chain1)
  peers[10].update(chain2, malicious = true)
  peers[11].update(chain2, malicious = true)

  peers[12].update(chain1, delay = 2.seconds)
  peers[13].update(chain1, delay = 2.seconds)
  peers[14].update(chain1, delay = 2.seconds)

  peers[15].update(chain1, failure = true)
  peers[16].update(chain1, failure = true)
  peers[17].update(chain1, failure = true)

  var slot0 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot0.peers = @[peers[0], peers[1], peers[2]]
  var slot1 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot1.peers = @[peers[3], peers[4], peers[5]]
  var slot2 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot2.peers = @[peers[6], peers[7], peers[8]]
  var slot3 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot3.peers = @[peers[9], peers[10], peers[11]]
  var slot4 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot4.peers = @[peers[12], peers[13], peers[14]]
  var slot5 = newPeerSlot[SimplePeer, SimplePeerKey](sman)
  slot5.peers = @[peers[15], peers[16], peers[17]]

  var group0 = newPeerGroup(sman)
  group0.slots = @[slot0, slot1, slot2]
  var group1 = newPeerGroup(sman)
  group1.slots = @[slot0, slot1, slot3]
  var group2 = newPeerGroup(sman)
  group2.slots = @[slot0, slot3, slot4]
  var group3 = newPeerGroup(sman)
  group3.slots = @[slot3, slot4, slot5]

  var s0 = await group0.getBlocks(Slot(10000), 10'u64)
  cleanup()
  var s1 = await group1.getBlocks(Slot(10000), 10'u64)
  cleanup()
  var s2 = await group2.getBlocks(Slot(10000), 10'u64)
  cleanup()
  var s3 = await group3.getBlocks(Slot(10000), 10'u64)
  cleanup()

  var expected = BlockList.init(Slot(10000), 10'u64, 1'u64, chain1).get()

  doAssert(s0.isSome())
  doAssert(s1.isSome())
  doAssert(s2.isSome())
  doAssert(s3.isNone())

  doAssert($s0.get() == $expected)
  doAssert($s1.get() == $expected)
  doAssert($s2.get() == $expected)

  result = true

proc syncQueueNonAsyncTests(): bool =
  var q1 = SyncQueue.init(Slot(0), Slot(0), 1'u64, nil)
  doAssert(len(q1) == 1)
  var r11 = q1.pop()
  doAssert(len(q1) == 0)
  q1.push(r11)
  doAssert(len(q1) == 1)
  var r11e = q1.pop()
  doAssert(len(q1) == 0)
  doAssert(r11e == r11)
  doAssert(r11.slot == Slot(0) and r11.count == 1'u64)

  var q2 = SyncQueue.init(Slot(0), Slot(1), 1'u64, nil)
  doAssert(len(q2) == 2)
  var r21 = q2.pop()
  doAssert(len(q2) == 1)
  var r22 = q2.pop()
  doAssert(len(q2) == 0)
  q2.push(r22)
  doAssert(len(q2) == 1)
  q2.push(r21)
  doAssert(len(q2) == 2)
  var r21e = q2.pop()
  doAssert(len(q2) == 1)
  var r22e = q2.pop()
  doAssert(len(q2) == 0)
  doAssert(r21 == r21e)
  doAssert(r22 == r22e)
  doAssert(r21.slot == Slot(0) and r21.count == 1'u64)
  doAssert(r22.slot == Slot(1) and r22.count == 1'u64)

  var q3 = SyncQueue.init(Slot(0), Slot(4), 2'u64, nil)
  doAssert(len(q3) == 5)
  var r31 = q3.pop()
  doAssert(len(q3) == 3)
  var r32 = q3.pop()
  doAssert(len(q3) == 1)
  var r33 = q3.pop()
  doAssert(len(q3) == 0)
  q3.push(r33)
  doAssert(len(q3) == 1)
  q3.push(r32)
  doAssert(len(q3) == 3)
  q3.push(r31)
  doAssert(len(q3) == 5)
  var r31e = q3.pop()
  doAssert(len(q3) == 3)
  var r32e = q3.pop()
  doAssert(len(q3) == 1)
  var r33e = q3.pop()
  doAssert(len(q3) == 0)
  doAssert(r31 == r31e)
  doAssert(r32 == r32e)
  doAssert(r33 == r33e)
  doAssert(r31.slot == Slot(0) and r31.count == 2'u64)
  doAssert(r32.slot == Slot(2) and r32.count == 2'u64)
  doAssert(r33.slot == Slot(4) and r33.count == 1'u64)

  var q4 = SyncQueue.init(Slot(1), Slot(5), 3'u64, nil)
  doAssert(len(q4) == 5)
  var r41 = q4.pop()
  doAssert(len(q4) == 2)
  var r42 = q4.pop()
  doAssert(len(q4) == 0)
  q4.push(r42)
  doAssert(len(q4) == 2)
  q4.push(r41)
  doAssert(len(q4) == 5)
  var r41e = q4.pop()
  doAssert(len(q4) == 2)
  var r42e = q4.pop()
  doAssert(len(q4) == 0)
  doAssert(r41 == r41e)
  doAssert(r42 == r42e)
  doAssert(r41.slot == Slot(1) and r41.count == 3'u64)
  doAssert(r42.slot == Slot(4) and r42.count == 2'u64)

  var q5 = SyncQueue.init(Slot(1), Slot(30), 2'u64, nil)
  doAssert(len(q5) == 30)
  var r51 = q5.pop(5)
  doAssert(len(q5) == 20)
  doAssert(r51.slot == Slot(1) and r51.count == 10 and r51.step == 5)
  q5.push(r51, 3'u64)
  doAssert(len(q5) == 30)
  var r511 = q5.pop()
  var r512 = q5.pop()
  doAssert(len(q5) == 20)
  doAssert(r511.slot == Slot(1) and r511.count == 6 and r511.step == 3)
  doAssert(r512.slot == Slot(7) and r512.count == 4 and r512.step == 2)
  q5.push(r511, 2'u64)
  q5.push(r512, 1'u64)
  doAssert(len(q5) == 30)
  var r5111 = q5.pop()
  var r5112 = q5.pop()
  var r5121 = q5.pop()
  var r5122 = q5.pop()
  doAssert(len(q5) == 20)
  doAssert(r5111.slot == Slot(1) and r5111.count == 4 and r5111.step == 2)
  doAssert(r5112.slot == Slot(5) and r5112.count == 2 and r5112.step == 1)
  doAssert(r5121.slot == Slot(7) and r5121.count == 2 and r5121.step == 1)
  doAssert(r5122.slot == Slot(9) and r5122.count == 2 and r5122.step == 1)

  var q6 = SyncQueue.init(Slot(1), Slot(7), 10'u64, nil)
  doAssert(len(q6) == 7)
  var r61 = q6.pop()
  doAssert(r61.slot == Slot(1) and r61.count == 7 and r61.step == 1)
  doAssert(len(q6) == 0)

  var q7 = SyncQueue.init(Slot(1), Slot(7), 10'u64, nil)
  doAssert(len(q7) == 7)
  var r71 = q7.pop(5)
  doAssert(len(q7) == 0)
  doAssert(r71.slot == Slot(1) and r71.count == 7 and r71.step == 5)
  q7.push(r71, 3'u64)
  doAssert(len(q7) == 7)
  var r72 = q7.pop()
  doAssert(r72.slot == Slot(1) and r72.count == 7 and r72.step == 3)
  q7.push(r72, 2'u64)
  doAssert(len(q7) == 7)
  var r73 = q7.pop()
  doAssert(len(q7) == 0)
  doAssert(r73.slot == Slot(1) and r73.count == 7 and r73.step == 2)
  q7.push(r73, 1'u64)
  doAssert(len(q7) == 7)
  var r74 = q7.pop()
  doAssert(len(q7) == 0)
  doAssert(r74.slot == Slot(1) and r74.count == 7 and r74.step == 1)

  result = true

proc syncQueueAsyncTests(): Future[bool] {.async.} =
  var chain1 = newSeq[SignedBeaconBlock](3)
  chain1[0].message.slot = Slot(0)
  chain1[1].message.slot = Slot(1)
  chain1[2].message.slot = Slot(2)
  var chain2 = newSeq[SignedBeaconBlock](7)
  chain2[0].message.slot = Slot(5)
  chain2[1].message.slot = Slot(6)
  chain2[2].message.slot = Slot(7)
  chain2[3].message.slot = Slot(8)
  chain2[4].message.slot = Slot(9)
  chain2[5].message.slot = Slot(10)
  chain2[6].message.slot = Slot(11)

  var counter = 0
  proc receiver1(list: openarray[SignedBeaconBlock]): bool =
    result = true
    for item in list:
      if item.message.slot == uint64(counter):
        inc(counter)
      else:
        result = false
        break

  var q1 = SyncQueue.init(Slot(0), Slot(2), 1'u64, receiver1, 1)
  var r11 = q1.pop()
  var r12 = q1.pop()
  var r13 = q1.pop()
  var f13 = q1.push(r13, @[chain1[2]])
  var f12 = q1.push(r12, @[chain1[1]])
  await sleepAsync(100.milliseconds)
  doAssert(f12.finished == false)
  doAssert(f13.finished == false)
  doAssert(counter == 0)
  var f11 = q1.push(r11, @[chain1[0]])
  doAssert(counter == 1)
  doAssert(f11.finished == true and f11.failed == false)
  await sleepAsync(100.milliseconds)
  doAssert(f12.finished == true and f12.failed == false)
  doAssert(f13.finished == true and f13.failed == false)
  doAssert(counter == 3)

  var q2 = SyncQueue.init(Slot(5), Slot(11), 2'u64, receiver1, 2)
  var r21 = q2.pop()
  var r22 = q2.pop()
  var r23 = q2.pop()
  var r24 = q2.pop()

  counter = 5

  var f24 = q2.push(r24, @[chain2[6]])
  var f22 = q2.push(r22, @[chain2[2], chain2[3]])
  doAssert(f24.finished == false)
  doAssert(f22.finished == false)
  doAssert(counter == 5)
  var f21 = q2.push(r21, @[chain2[0], chain2[1]])
  doAssert(f21.finished == true and f21.failed == false)
  await sleepAsync(100.milliseconds)
  doAssert(f22.finished == true and f22.failed == false)
  doAssert(f24.finished == false)
  doAssert(counter == 9)
  var f23 = q2.push(r23, @[chain2[4], chain2[5]])
  doAssert(f23.finished == true and f23.failed == false)
  doAssert(counter == 11)
  await sleepAsync(100.milliseconds)
  doAssert(f24.finished == true and f24.failed == false)
  doAssert(counter == 12)

  result = true

proc checkRequest(req: PeerRequest, slot, count, step: int,
                  data: varargs[int]): bool =
  result = (req.startSlot == Slot(slot)) and (req.count == uint64(count)) and
           (req.step == uint64(step))
  if result:
    if len(data) != len(req.data):
      result = false
    else:
      for i in 0 ..< len(data):
        if Slot(data[i]) != req.data[i]:
          result = false
          break

proc checkRequest(peer: SimplePeer, index: int, slot, count, step: int,
                  data: varargs[int]): bool {.inline.} =
  result = checkRequest(peer.requests[index], slot, count, step, data)

proc syncManagerOnePeerTest(): Future[bool] {.async.} =
  # Syncing with one peer only.
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()
  var peer = SimplePeer.init("id1")
  var srcChain = newTempChain(100, Slot(10000))
  var dstChain = newSeq[SignedBeaconBlock]()

  proc lastLocalSlot(): Slot =
    if len(dstChain) == 0:
      result = Slot(9999)
    else:
      result = dstChain[^1].message.slot

  proc updateBlocks(list: openarray[SignedBeaconBlock]): bool =
    for item in list:
      dstChain.add(item)
    result = true

  peer.update(srcChain)
  doAssert(pool.addIncomingPeerNoWait(peer) == true)

  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, lastLocalSlot, updateBlocks,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 6)
  await sman.synchronize()
  doAssert(checkRequest(peer, 0, 10000, 20, 1,
                        10000, 10001, 10002, 10003, 10004,
                        10005, 10006, 10007, 10008, 10009,
                        10010, 10011, 10012, 10013, 10014,
                        10015, 10016, 10017, 10018, 10019) == true)
  doAssert(checkRequest(peer, 1, 10020, 20, 1,
                        10020, 10021, 10022, 10023, 10024,
                        10025, 10026, 10027, 10028, 10029,
                        10030, 10031, 10032, 10033, 10034,
                        10035, 10036, 10037, 10038, 10039) == true)
  doAssert(checkRequest(peer, 2, 10040, 20, 1,
                        10040, 10041, 10042, 10043, 10044,
                        10045, 10046, 10047, 10048, 10049,
                        10050, 10051, 10052, 10053, 10054,
                        10055, 10056, 10057, 10058, 10059) == true)
  doAssert(checkRequest(peer, 3, 10060, 20, 1,
                        10060, 10061, 10062, 10063, 10064,
                        10065, 10066, 10067, 10068, 10069,
                        10070, 10071, 10072, 10073, 10074,
                        10075, 10076, 10077, 10078, 10079) == true)
  doAssert(checkRequest(peer, 4, 10080, 20, 1,
                        10080, 10081, 10082, 10083, 10084,
                        10085, 10086, 10087, 10088, 10089,
                        10090, 10091, 10092, 10093, 10094,
                        10095, 10096, 10097, 10098, 10099) == true)
  result = true

proc syncManagerOneSlotTest(): Future[bool] {.async.} =
  # Syncing with one slot (2n + 1 number of peers) only.
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()

  var peers = newSeq[SimplePeer](3)
  for i in 0 ..< len(peers):
    peers[i] = SimplePeer.init("id" & $(i + 1))

  var srcChain = newTempChain(100, Slot(10000))
  var dstChain = newSeq[SignedBeaconBlock]()

  proc lastLocalSlot(): Slot =
    if len(dstChain) == 0:
      result = Slot(9999)
    else:
      result = dstChain[^1].message.slot

  proc updateBlocks(list: openarray[SignedBeaconBlock]): bool =
    for item in list:
      dstChain.add(item)
    result = true

  for i in 0 ..< len(peers):
    peers[i].update(srcChain)
  doAssert(pool.addIncomingPeerNoWait(peers[0]) == true)
  doAssert(pool.addOutgoingPeerNoWait(peers[1]) == true)
  doAssert(pool.addOutgoingPeerNoWait(peers[2]) == true)

  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, lastLocalSlot, updateBlocks,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 6)
  await sman.synchronize()
  for i in 0 ..< len(peers):
    doAssert(checkRequest(peers[i], 0, 10000, 20, 1,
                          10000, 10001, 10002, 10003, 10004,
                          10005, 10006, 10007, 10008, 10009,
                          10010, 10011, 10012, 10013, 10014,
                          10015, 10016, 10017, 10018, 10019) == true)
    doAssert(checkRequest(peers[i], 1, 10020, 20, 1,
                          10020, 10021, 10022, 10023, 10024,
                          10025, 10026, 10027, 10028, 10029,
                          10030, 10031, 10032, 10033, 10034,
                          10035, 10036, 10037, 10038, 10039) == true)
    doAssert(checkRequest(peers[i], 2, 10040, 20, 1,
                          10040, 10041, 10042, 10043, 10044,
                          10045, 10046, 10047, 10048, 10049,
                          10050, 10051, 10052, 10053, 10054,
                          10055, 10056, 10057, 10058, 10059) == true)
    doAssert(checkRequest(peers[i], 3, 10060, 20, 1,
                          10060, 10061, 10062, 10063, 10064,
                          10065, 10066, 10067, 10068, 10069,
                          10070, 10071, 10072, 10073, 10074,
                          10075, 10076, 10077, 10078, 10079) == true)
    doAssert(checkRequest(peers[i], 4, 10080, 20, 1,
                          10080, 10081, 10082, 10083, 10084,
                          10085, 10086, 10087, 10088, 10089,
                          10090, 10091, 10092, 10093, 10094,
                          10095, 10096, 10097, 10098, 10099) == true)
  result = true

proc syncManagerOneGroupTest(): Future[bool] {.async.} =
  # Syncing with one group of peers (n peer slots).
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()
  var peers = newSeq[SimplePeer](6)
  for i in 0 ..< len(peers):
    peers[i] = SimplePeer.init("id" & $(i + 1), weight = 10 - i)

  var srcChain = newTempChain(100, Slot(10000))
  var dstChain = newSeq[SignedBeaconBlock]()

  proc lastLocalSlot(): Slot =
    if len(dstChain) == 0:
      result = Slot(9999)
    else:
      result = dstChain[^1].message.slot

  proc updateBlocks(list: openarray[SignedBeaconBlock]): bool =
    for item in list:
      dstChain.add(item)
    result = true

  for i in 0 ..< len(peers):
    peers[i].update(srcChain)
    if i mod 2 == 0:
      doAssert(pool.addIncomingPeerNoWait(peers[i]) == true)
    else:
      doAssert(pool.addOutgoingPeerNoWait(peers[i]) == true)

  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, lastLocalSlot, updateBlocks,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 2)
  await sman.synchronize()
  for i in 0 ..< len(peers):
    if i in {0, 1, 2}:
      doAssert(checkRequest(peers[i], 0, 10000, 20, 2,
                            10000, 10002, 10004, 10006, 10008,
                            10010, 10012, 10014, 10016, 10018,
                            10020, 10022, 10024, 10026, 10028,
                            10030, 10032, 10034, 10036, 10038) == true)
      doAssert(checkRequest(peers[i], 1, 10040, 20, 2,
                            10040, 10042, 10044, 10046, 10048,
                            10050, 10052, 10054, 10056, 10058,
                            10060, 10062, 10064, 10066, 10068,
                            10070, 10072, 10074, 10076, 10078) == true)
      doAssert(checkRequest(peers[i], 2, 10080, 10, 2,
                            10080, 10082, 10084, 10086, 10088,
                            10090, 10092, 10094, 10096, 10098) == true)
    elif i in {3, 4, 5}:
      doAssert(checkRequest(peers[i], 0, 10001, 20, 2,
                            10001, 10003, 10005, 10007, 10009,
                            10011, 10013, 10015, 10017, 10019,
                            10021, 10023, 10025, 10027, 10029,
                            10031, 10033, 10035, 10037, 10039) == true)
      doAssert(checkRequest(peers[i], 1, 10041, 20, 2,
                            10041, 10043, 10045, 10047, 10049,
                            10051, 10053, 10055, 10057, 10059,
                            10061, 10063, 10065, 10067, 10069,
                            10071, 10073, 10075, 10077, 10079) == true)
      doAssert(checkRequest(peers[i], 2, 10081, 10, 2,
                            10081, 10083, 10085, 10087, 10089,
                            10091, 10093, 10095, 10097, 10099) == true)

  result = true

proc syncManagerGroupRecoveryTest(): Future[bool] {.async.} =
  # Syncing with two groups of peers (n peer slots), when one groups is failed
  # to deliver request, and this request is bigger then other group.
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()
  var peers = newSeq[SimplePeer](6 + 3)
  for i in 0 ..< len(peers):
    peers[i] = SimplePeer.init("id" & $(i + 1), weight = 9 - i)

  var srcChain = newTempChain(100, Slot(10000))
  var dstChain = newSeq[SignedBeaconBlock]()

  for i in 0 ..< 6:
    peers[i].update(srcChain, failure = true, disconnect = true)
  for i in 6 ..< len(peers):
    peers[i].update(srcChain)

  proc lastLocalSlot(): Slot =
    if len(dstChain) == 0:
      result = Slot(9999)
    else:
      result = dstChain[^1].message.slot

  proc updateBlocks(list: openarray[SignedBeaconBlock]): bool =
    for item in list:
      dstChain.add(item)
    result = true

  for i in 0 ..< len(peers):
    if i mod 2 == 0:
      doAssert(pool.addIncomingPeerNoWait(peers[i]) == true)
    else:
      doAssert(pool.addOutgoingPeerNoWait(peers[i]) == true)

  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, lastLocalSlot, updateBlocks,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 2)
  await sman.synchronize()
  for i in 0 ..< len(peers):
    if i in {0, 1, 2}:
      doAssert(checkRequest(peers[i], 0, 10020, 20, 2) == true)
    elif i in {3, 4, 5}:
      doAssert(checkRequest(peers[i], 0, 10021, 20, 2) == true)
    elif i in {6, 7, 8}:
      doAssert(checkRequest(peers[i], 0, 10000, 20, 1,
                            10000, 10001, 10002, 10003, 10004,
                            10005, 10006, 10007, 10008, 10009,
                            10010, 10011, 10012, 10013, 10014,
                            10015, 10016, 10017, 10018, 10019) == true)
      doAssert(checkRequest(peers[i], 1, 10020, 20, 1,
                            10020, 10021, 10022, 10023, 10024,
                            10025, 10026, 10027, 10028, 10029,
                            10030, 10031, 10032, 10033, 10034,
                            10035, 10036, 10037, 10038, 10039) == true)
      doAssert(checkRequest(peers[i], 2, 10040, 20, 1,
                            10040, 10041, 10042, 10043, 10044,
                            10045, 10046, 10047, 10048, 10049,
                            10050, 10051, 10052, 10053, 10054,
                            10055, 10056, 10057, 10058, 10059) == true)
      doAssert(checkRequest(peers[i], 3, 10060, 20, 1,
                            10060, 10061, 10062, 10063, 10064,
                            10065, 10066, 10067, 10068, 10069,
                            10070, 10071, 10072, 10073, 10074,
                            10075, 10076, 10077, 10078, 10079) == true)
      doAssert(checkRequest(peers[i], 4, 10080, 20, 1,
                            10080, 10081, 10082, 10083, 10084,
                            10085, 10086, 10087, 10088, 10089,
                            10090, 10091, 10092, 10093, 10094,
                            10095, 10096, 10097, 10098, 10099) == true)
  result = true

proc syncManagerFailureTest(): Future[bool] {.async.} =
  # Failure test
  const FailuresCount = 3
  var pool = newPeerPool[SimplePeer, SimplePeerKey]()
  var peer = SimplePeer.init("id1", weight = 0)

  var srcChain = newTempChain(100, Slot(10000))
  var dstChain = newSeq[SignedBeaconBlock]()

  peer.update(srcChain, failure = true)

  proc lastLocalSlot(): Slot =
    if len(dstChain) == 0:
      result = Slot(9999)
    else:
      result = dstChain[^1].message.slot

  proc updateBlocks(list: openarray[SignedBeaconBlock]): bool =
    for item in list:
      dstChain.add(item)
    result = true

  doAssert(pool.addIncomingPeerNoWait(peer) == true)

  var sman = newSyncManager[SimplePeer,
                            SimplePeerKey](pool, lastLocalSlot, updateBlocks,
                                           peersInSlot = 3,
                                           peerSlotTimeout = 1.seconds,
                                           slotsInGroup = 2,
                                           failuresCount = FailuresCount,
                                           failurePause = 100.milliseconds)
  await sman.synchronize()
  doAssert(len(peer.requests) == FailuresCount)
  for i in 0 ..< len(peer.requests):
    doAssert(checkRequest(peer, i, 10000, 20, 1) == true)
  result = true

suite "SyncManager test suite":
  timedTest "PeerSlot tests":
    check waitFor(peerSlotTests()) == true
  timedTest "PeerGroup tests":
    check waitFor(peerGroupTests()) == true
  timedTest "SyncQueue non-async tests":
    check syncQueueNonAsyncTests() == true
  timedTest "SyncQueue async tests":
    check waitFor(syncQueueAsyncTests()) == true
  timedTest "SyncManager one-peer test":
    check waitFor(syncManagerOnePeerTest()) == true
  timedTest "SyncManager one-peer-slot test":
    check waitFor(syncManagerOneSlotTest()) == true
  timedTest "SyncManager one-peer-group test":
    check waitFor(syncManagerOneGroupTest()) == true
  timedTest "SyncManager group-recovery test":
    check waitFor(syncManagerGroupRecoveryTest()) == true
  timedTest "SyncManager failure test":
    check waitFor(syncManagerFailureTest()) == true

import options, hashes, unittest
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
    blockchain: seq[BeaconBlock]
    latestSlot: Slot
    delay: Duration
    malicious: bool
    failure: bool
    requests: seq[PeerRequest]

proc getKey*(peer: SimplePeer): SimplePeerKey =
  result = peer.id

proc getFuture*(peer: SimplePeer): Future[void] =
  result = peer.lifu

proc `<`*(a, b: SimplePeer): bool =
  result = `<`(a.weight, b.weight)

proc getLastSlot*(peer: SimplePeer): Slot =
  if len(peer.blockchain) == 0:
    result = peer.latestSlot
  else:
    result = peer.blockchain[len(peer.blockchain) - 1].slot

proc init*(t: typedesc[SimplePeer], id: string = "", malicious = false,
           weight: int = 0, slot: int = 0,
           delay: Duration = ZeroDuration): SimplePeer =
  result = SimplePeer(id: id, weight: weight, lifu: newFuture[void](),
                      delay: delay, latestSlot: Slot(slot),
                      malicious: malicious)

proc update*(peer: SimplePeer, chain: openarray[BeaconBlock],
             malicious = false, failure = false,
             delay: Duration = ZeroDuration) =
  peer.malicious = malicious
  peer.delay = delay
  peer.failure = failure
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
  var res = newSeq[BeaconBlock]()
  var reqres = newSeq[Slot]()
  if peer.delay != ZeroDuration:
    await sleepAsync(peer.delay)

  var counter = 0'u64

  if peer.failure:
    raise newException(SyncManagerError, "Error")

  if peer.malicious:
    var index = 0
    while counter < count:
      if index < len(peer.blockchain):
        res.add(peer.blockchain[index])
        reqres.add(peer.blockchain[index].slot)
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
      if peer.blockchain[i].slot == startSlot:
        index = i
        break

    if index >= 0:
      while counter < count:
        if index < len(peer.blockchain):
          res.add(peer.blockchain[index])
          reqres.add(peer.blockchain[index].slot)
        else:
          break
        index = index + int(step)
        counter = counter + 1'u64
      req.data = reqres
      peer.requests.add(req)
      result = some(res)

proc newTempChain*(number: int, start: Slot): seq[BeaconBlock] =
  result = newSeq[BeaconBlock](number)
  for i in 0 ..< number:
    result[i].slot = start + uint64(i)

proc `==`*(a1, a2: BeaconBlock): bool {.inline.} =
  result = (a1.slot == a2.slot) and
           (a1.parent_root == a2.parent_root) and
           (a1.state_root == a2.state_root)

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
                            SimplePeerKey](pool,
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
                            SimplePeerKey](pool,
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

when isMainModule:
  suite "SyncManager test suite":
    test "BlockList tests":
      # TODO
      discard
    test "PeerSlot tests":
      check waitFor(peerSlotTests()) == true
    test "PeerGroup tests":
      check waitFor(peerGroupTests()) == true
    test "SyncManager tests":
      # TODO
      discard

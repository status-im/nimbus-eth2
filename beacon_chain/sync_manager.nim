import chronicles
import options, deques, heapqueue
import stew/bitseqs, chronos, chronicles
import spec/datatypes, spec/digest, peer_pool
export datatypes, digest, chronos, chronicles

logScope:
  topics = "syncman"

const MAX_REQUESTED_BLOCKS* = 20'u64

type
  ## A - `Peer` type
  ## B - `PeerID` type
  ##
  ## Procedures which needs to be implemented and will be mixed to SyncManager's
  ## code:
  ##
  ## getHeadSlot(Peer): Slot
  ## getHeadRoot(Peer): Eth2Digest
  ## getBeaconBlocksByRange(Peer, Eth2Digest, Slot, uint64,
  ##                        uint64): Future[Option[seq[SignedBeaconBlock]]]
  ## updateStatus(Peer): void

  PeerSlot*[A, B] = ref object
    peers*: seq[A]
    man: SyncManager[A, B]

  PeerGroup*[A, B] = ref object
    slots*: seq[PeerSlot[A, B]]
    man: SyncManager[A, B]

  GetLocalHeadSlotCallback* = proc(): Slot
  UpdateLocalBlocksCallback* = proc(list: openarray[SignedBeaconBlock]): bool

  SyncManager*[A, B] = ref object
    groups*: seq[PeerGroup[A, B]]
    pool: PeerPool[A, B]
    peersInSlot: int
    slotsInGroup: int
    groupsCount: int
    failuresCount: int
    failurePause: chronos.Duration
    peerSlotTimeout: chronos.Duration
    peerGroupTimeout: chronos.Duration
    statusPeriod: chronos.Duration
    getLocalHeadSlot: GetLocalHeadSlotCallback
    updateLocalBlocks: UpdateLocalBlocksCallback

  BlockList* = object
    list*: seq[SignedBeaconBlock]
    map*: BitSeq
    start*: Slot

  OptionBlockList* = Option[BlockList]
  OptionBeaconBlockSeq* = Option[seq[SignedBeaconBlock]]

  SyncRequest* = object
    slot*: Slot
    count*: uint64
    step*: uint64
    group*: int

  SyncResult* = object
    request*: SyncRequest
    data*: seq[SignedBeaconBlock]

  SyncQueue* = ref object
    inpSlot*: Slot
    outSlot*: Slot

    startSlot*: Slot
    lastSlot: Slot
    chunkSize*: uint64
    queueSize*: int

    notFullEvent*: AsyncEvent
    syncUpdate*: UpdateLocalBlocksCallback

    debtsQueue: HeapQueue[SyncRequest]
    debtsCount: uint64
    readyQueue: HeapQueue[SyncResult]
    readyData: seq[seq[SignedBeaconBlock]]

  SyncManagerError* = object of CatchableError

proc init*(t: typedesc[SyncQueue], start, last: Slot, chunkSize: uint64,
           updateCb: UpdateLocalBlocksCallback,
           queueSize: int = -1): SyncQueue =
  ## Create new synchronization queue with parameters
  ##
  ## ``start`` and ``last`` are starting and finishing Slots.
  ##
  ## ``chunkSize`` maximum number of slots in one request.
  ##
  ## ``queueSize`` maximum queue size for incoming data. If ``queueSize > 0``
  ## queue will help to keep backpressure under control. If ``queueSize <= 0``
  ## then queue size is unlimited (default).
  ##
  ## ``updateCb`` procedure which will be used to send downloaded blocks to
  ## consumer. Block sequences will be sent sequentially. Procedure should
  ## return ``false`` only when it receives incorrect blocks, and ``true``
  ## if sequence of blocks is correct.
  doAssert(chunkSize > 0'u64, "Chunk size should not be zero")
  result = SyncQueue(startSlot: start, lastSlot: last, chunkSize: chunkSize,
                     queueSize: queueSize, syncUpdate: updateCb,
                     notFullEvent: newAsyncEvent(),
                     debtsQueue: initHeapQueue[SyncRequest](),
                     inpSlot: start, outSlot: start)

proc `<`*(a, b: SyncRequest): bool {.inline.} =
  result = (a.slot < b.slot)

proc `<`*(a, b: SyncResult): bool {.inline.} =
  result = (a.request.slot < b.request.slot)

proc `==`*(a, b: SyncRequest): bool {.inline.} =
  result = ((a.slot == b.slot) and (a.count == b.count) and
            (a.step == b.step))

proc lastSlot*(req: SyncRequest): Slot {.inline.} =
  ## Returns last slot for request ``req``.
  result = req.slot + req.count - 1'u64

proc updateLastSlot*(sq: SyncQueue, last: Slot) {.inline.} =
  ## Update last slot stored in queue ``sq`` with value ``last``.
  doAssert(sq.lastSlot <= last, "Last slot could not be lower then stored one")
  sq.lastSlot = last

proc push*(sq: SyncQueue, sr: SyncRequest,
           data: seq[SignedBeaconBlock]) {.async.} =
  ## Push successfull result to queue ``sq``.
  while true:
    if (sq.queueSize > 0) and (sr.slot >= sq.outSlot + uint64(sq.queueSize)):
      await sq.notFullEvent.wait()
      sq.notFullEvent.clear()
      continue
    let res = SyncResult(request: sr, data: data)
    sq.readyQueue.push(res)
    break

  while len(sq.readyQueue) > 0:
    let minSlot = sq.readyQueue[0].request.slot
    if sq.outSlot != minSlot:
      break
    let item = sq.readyQueue.pop()
    if not(sq.syncUpdate(item.data)):
      sq.debtsQueue.push(item.request)
      sq.debtsCount = sq.debtsCount + item.request.count
      break
    sq.outSlot = sq.outSlot + item.request.count
    sq.notFullEvent.fire()

proc push*(sq: SyncQueue, sr: SyncRequest) =
  ## Push failed request back to queue.
  sq.debtsQueue.push(sr)
  sq.debtsCount = sq.debtsCount + sr.count

proc push*(sq: SyncQueue, sr: SyncRequest, newstep: uint64) =
  ## Push request with changed number of steps.
  doAssert(sr.step > newstep, "The new step should be less than the original")
  var count = sr.count
  var slot = sr.slot
  var newcount = 0'u64

  for i in 0 ..< (sr.step div newstep):
    if newstep * sq.chunkSize <= count:
      newcount = newstep * sq.chunkSize
    else:
      newcount = count
    var newsr = SyncRequest(slot: slot, count: newcount, step: newstep)
    slot = slot + newcount
    count = count - newcount
    sq.debtsQueue.push(newsr)
    sq.debtsCount = sq.debtsCount + newsr.count
    if count == 0:
      break

  if count > 0'u64:
    let step = sr.step mod newstep
    doAssert(step * sq.chunkSize <= count)
    var newsr = SyncRequest(slot: slot, count: count, step: step)
    sq.debtsQueue.push(newsr)
    sq.debtsCount = sq.debtsCount + newsr.count

proc pop*(sq: SyncQueue, step = 0'u64): SyncRequest =
  ## Obtain request from queue ``sq``.
  if len(sq.debtsQueue) > 0:
    var sr = sq.debtsQueue.pop()
    if step != 0'u64:
      if sr.step > step:
        sq.push(sr, step)
        sr = sq.debtsQueue.pop()
    sq.debtsCount = sq.debtsCount - sr.count
    result = sr
  else:
    let nstep = if step == 0'u64: 1'u64 else: step
    if sq.inpSlot <= sq.lastSlot:
      let count = min(sq.lastSlot + 1'u64 - sq.inpSlot, sq.chunkSize * nstep)
      result = SyncRequest(slot: sq.inpSlot, count: count, step: nstep)
      sq.inpSlot = sq.inpSlot + count
    else:
      raise newException(SyncManagerError, "Queue is already empty!")

proc len*(sq: SyncQueue): uint64 {.inline.} =
  ## Returns number of slots left in queue ``sq``.
  if sq.inpSlot > sq.lastSlot:
    result = sq.debtsCount
  else:
    result = sq.lastSlot - sq.inpSlot + 1'u64 + sq.debtsCount

proc total*(sq: SyncQueue): uint64 {.inline.} =
  ## Returns total number of slots in queue ``sq``.
  result = sq.lastSlot - sq.startSlot + 1'u64

proc progress*(sq: SyncQueue): string =
  ## Returns queue's ``sq`` progress string.
  let curSlot = sq.outSlot - sq.startSlot
  result = $curSlot & "/" & $sq.total()

proc init*(t: typedesc[BlockList], start: Slot, count, step: uint64,
           list: openarray[SignedBeaconBlock]): Option[BlockList] =
  mixin getSlot
  var res: BlockList
  var error = false
  var current = start
  var index = 0

  res.map = BitSeq.init(0)

  for i in 0'u64 ..< count:
    if index < len(list):
      let slot = list[index].message.slot
      if slot < current:
        error = true
        break
      elif slot == current:
        res.map.add(true)
        inc(index)
      else:
        res.map.add(false)
    else:
      res.map.add(false)

    let next = current + step
    current = current + 1'u64
    if i < (count - 1):
      while current < next:
        res.map.add(false)
        current = current + 1'u64

  if not(error) and index == len(list):
    res.list = @list
    res.start = start
    result = some(res)

proc init*(t: typedesc[BlockList], start, finish: Slot): BlockList =
  result = BlockList(start: start)
  result.map = BitSeq.init(int((finish - start) + 1'u64))

proc `$`*(blist: BlockList): string =
  var index = 0
  for i in 0 ..< len(blist.map):
    if blist.map[i]:
      result = result & $blist.list[index].message.slot & ", "
      index = index + 1
    else:
      result = result & "<empty>, "
  if len(result) > 2:
    result.setLen(len(result) - 2)

proc startSlot*(blist: BlockList): Slot {.inline.} =
  result = blist.start

proc lastSlot*(blist: BlockList): Slot {.inline.} =
  doAssert(len(blist.map) > 0)
  result = blist.start + uint64(len(blist.map) - 1)

proc contains*(blist: BlockList, slot: Slot): bool {.inline.} =
  if (blist.startSlot() <= slot) and (slot <= blist.lastSlot()):
    result = true

proc merge*(optlists: varargs[Option[BlockList]]): Option[BlockList] =
  if len(optlists) > 0:
    if len(optlists) == 1:
      result = optlists[0]
    else:
      var blists = newSeq[BlockList](len(optlists))
      for i in 0 ..< len(optlists):
        doAssert(optlists[i].isSome()) # Must not be happens
        blists[i] = optlists[i].get()

      var minSlot, maxSlot: Slot
      for i in 0 ..< len(blists):
        if i == 0:
          minSlot = blists[i].startSlot()
          maxSlot = blists[i].lastSlot()
        else:
          let candidateMinSlot = blists[i].startSlot()
          let candidateMaxSlot = blists[i].lastSlot()
          if candidateMinSlot < minSlot:
            minSlot = candidateMinSlot
          if candidateMaxSlot > maxSlot:
            maxSlot = candidateMaxSlot

      var res = BlockList.init(minSlot, maxSlot)
      var slot = minSlot
      var indexes = newSeq[int](len(blists))
      var resIndex = 0
      while slot <= maxSlot:
        for i in 0 ..< len(blists):
          if blists[i].contains(slot):
            let slotIndex = slot - blists[i].startSlot()
            if blists[i].map[slotIndex]:
              res.map.setBit(resIndex)
              res.list.add(blists[i].list[indexes[i]])
              inc(indexes[i])
        inc(resIndex)
        slot = slot + 1'u64
      result = some(res)

proc newSyncManager*[A, B](pool: PeerPool[A, B],
                           getLocalHeadSlotCb: GetLocalHeadSlotCallback,
                           updateLocalBlocksCb: UpdateLocalBlocksCallback,
                           peersInSlot = 3, peerSlotTimeout = 6.seconds,
                           slotsInGroup = 2, peerGroupTimeout = 10.seconds,
                           groupsCount = 10,
                           statusPeriod = 10.minutes,
                           failuresCount = 3,
                           failurePause = 5.seconds): SyncManager[A, B] =
  ## ``pool`` - PeerPool object which will be used as source of peers.
  ##
  ## ``peersInSlot`` - maximum number of peers in slot.
  ##
  ## ``peerSlotTimeout`` - timeout for PeerSlot.getBlocks() execution.
  ##
  ## ``slotsInGroup`` - maximum number of slots in group.
  ##
  ## ``peerGroupTimeout`` - timeout for PeerGroup.getBlocks() execution.
  ##
  ## ``groupsCount`` - maximum number of groups used in sync process.
  ##
  ## ``statusPeriod`` - period of time between status updates.
  ##
  ## ``getLocalHeadSlotCb`` - function which provides current latest `Slot` in
  ## local database.
  ##
  ## ``updateLocalBlocksCb`` - function which accepts list of downloaded blocks
  ## and stores it to local database.
  ##
  ## ``failuresCount`` - number of consecutive failures, after which the
  ## procedure will exit.
  ##
  ## ``failurePause`` - period of time which will be waited by sync manager, if
  ## all the nodes could not satisfy requested slot.
  result = SyncManager[A, B](pool: pool, peersInSlot: peersInSlot,
                             slotsInGroup: slotsInGroup,
                             groupsCount: groupsCount,
                             peerSlotTimeout: peerSlotTimeout,
                             peerGroupTimeout: peerGroupTimeout,
                             statusPeriod: statusPeriod,
                             getLocalHeadSlot: getLocalHeadSlotCb,
                             updateLocalBlocks: updateLocalBlocksCb,
                             failuresCount: failuresCount,
                             failurePause: failurePause)

template nearestOdd(number: int): int =
  number - ((number - 1) mod 2)

proc newPeerSlot*[A, B](man: SyncManager[A, B]): PeerSlot[A, B] =
  result = PeerSlot[A, B]()
  result.man = man
  result.peers = newSeq[A]()

proc `$`*[A, B](peerslot: PeerSlot[A, B]): string =
  ## Returns string representation of peer's slot ``peerslot``.
  mixin getKey, getHeadSlot
  if len(peerslot.peers) == 0:
    result = "<>"
  else:
    result = "<"
    for item in peerslot.peers:
      result.add("\"" & getKey(item) & "\"")
      result.add(":" & $getHeadSlot(item))
      result.add(", ")
    result.setLen(len(result) - 2)
    result.add(">")

proc isFull*[A, B](peerslot: PeerSlot[A, B]): bool {.inline.} =
  ## Returns ``true`` if peer's slot ``peerslot`` is full of peers.
  result = (len(peerslot.peers) == peerslot.man.peersInSlot)

proc isEmpty*[A, B](peerslot: PeerSlot[A, B]): bool {.inline.} =
  ## Returns ``true`` if peer's slot ``peerslot`` is empty (out of peers).
  result = (len(peerslot.peers) == 0)

proc fillPeers*[A, B](slot: PeerSlot[A, B]) {.async.} =
  doAssert(slot.man.peersInSlot > 0 and
           (slot.man.peersInSlot mod 2 == 1))
  doAssert(len(slot.peers) == 0 or (len(slot.peers) mod 2 == 0))
  doAssert(len(slot.peers) <= slot.man.peersInSlot)
  if len(slot.peers) == 0:
    # This is new slot
    var peer = await slot.man.pool.acquire()
    let available = slot.man.pool.lenAvailable()
    slot.peers.add(peer)
    if available > 0:
      if available + len(slot.peers) < slot.man.peersInSlot:
        # There not enoug available peers in pool, so we add only some of them,
        # but we still want to keep number of peers in slot odd.
        let count = nearestOdd(available + len(slot.peers))
        if count > len(slot.peers):
          let peers = slot.man.pool.acquireNoWait(count - len(slot.peers))
          slot.peers.add(peers)
      else:
        # There enough peers to fill a slot.
        let peers = slot.man.pool.acquireNoWait(slot.man.peersInSlot -
                                                len(slot.peers))
        slot.peers.add(peers)
    else:
      # Only one peer obtained and there no more available peers, so we are
      # starting with just one peer.
      discard
  else:
    # If slot already has some peers, then we are not going to wait for peers,
    # we will consume everything available.
    if len(slot.peers) < slot.man.peersInSlot:
      # Slot do not have enough peers inside, we need to add missing peers.
      let available = slot.man.pool.lenAvailable()
      if available == 0:
        # There no peers available so we just exiting
        discard
      else:
        if available + len(slot.peers) < slot.man.peersInSlot:
          let count = nearestOdd(available + len(slot.peers))
          let peers = slot.man.pool.acquireNoWait(count - len(slot.peers))
          slot.peers.add(peers)
        else:
          let peers = slot.man.pool.acquireNoWait(slot.man.peersInSlot -
                                                  len(slot.peers))
          slot.peers.add(peers)
    else:
      # Slot has enough peers inside, we do nothing here
      discard

proc newPeerGroup*[A, B](man: SyncManager[A, B]): PeerGroup[A, B] =
  result = PeerGroup[A, B]()
  result.man = man
  result.slots = newSeq[PeerSlot[A, B]]()

proc fillSlots*[A, B](group: PeerGroup[A, B]) {.async.} =
  ## Filling peer's group ``group`` with peers from PeerPool.
  if len(group.slots) == 0:
    while len(group.slots) < group.man.slotsInGroup:
      var slot = newPeerSlot[A, B](group.man)
      await slot.fillPeers()
      doAssert(not(slot.isEmpty()))
      group.slots.add(slot)
      if not(slot.isFull()) or (group.man.pool.lenAvailable() == 0):
        break
  else:
    for i in 0 ..< group.man.slotsInGroup:
      if i < len(group.slots):
        if group.man.pool.lenAvailable() == 0:
          break
        # PeerPool is not empty, so this call will be finished immediately.
        await group.slots[i].fillPeers()
        if not(group.slots[i].isFull()):
          break
      else:
        if group.man.pool.lenAvailable() == 0:
          break
        var slot = newPeerSlot[A, B](group.man)
        # PeerPool is not empty, so this call will be finished immediately.
        await slot.fillPeers()
        doAssert(not(slot.isEmpty()))
        group.slots.add(slot)
        if not(slot.isFull()):
          break

proc isFull*[A, B](group: PeerGroup[A, B]): bool =
  result = false
  if len(group.slots) >= group.man.slotsInGroup:
    result = true
    for item in group.slots:
      if not(item.isFull()):
        result = false
        break

proc isEmpty*[A, B](group: PeerGroup[A, B]): bool =
  result = (len(group.slots) == 0)

proc `$`*[A, B](group: PeerGroup[A, B]): string =
  if len(group.slots) == 0:
    result = "[]"
  else:
    result = "["
    for item in group.slots:
      result.add($item)
      result.add(", ")
    result.setLen(len(result) - 2)
    result.add("]")

proc `$`*[A, B](man: SyncManager[A, B]): string =
  result = ""
  for i in 0 ..< man.groupsCount:
    result.add($i & ":")
    if i < len(man.groups):
      result.add($man.groups[i])
    else:
      result.add("[]")
    result.add(", ")

  if len(result) > 0:
    result.setLen(len(result) - 2)

proc peersCount*[A, B](man: SyncManager[A, B]): int =
  ## Returns number of peers which is managed by Sync Manager ``man``.
  for i in 0 ..< len(man.groups):
    for k in 0 ..< len(man.groups[i].slots):
      result = result + len(man.groups[i].slots[k].peers)

proc fillGroups*[A, B](man: SyncManager[A, B]) {.async.} =
  if len(man.groups) == 0:
    while len(man.groups) < man.groupsCount:
      var group = newPeerGroup[A, B](man)
      await group.fillSlots()
      doAssert(not(group.isEmpty()))
      man.groups.add(group)
      if not(group.isFull()) or (man.pool.lenAvailable() == 0):
        break
  else:
    for i in 0 ..< man.groupsCount:
      if i < len(man.groups):
        if man.pool.lenAvailable() == 0:
          break
        # PeerPool is not empty, so this call will be finished immediately.
        await man.groups[i].fillSlots()
        if not(man.groups[i].isFull()):
          break
      else:
        if man.pool.lenAvailable() == 0:
          break
        var group = newPeerGroup[A, B](man)
        # PeerPool is not empty, so this call will be finished immediately.
        await group.fillSlots()
        doAssert(not(group.isEmpty()))
        man.groups.add(group)
        if not(group.isFull()):
          break

proc compactGroups*[A, B](man: SyncManager[A, B]) =
  ## Removes empty slots from SyncManager's groups list.
  var ngroups = newSeq[PeerGroup[A, B]]()
  for i in 0 ..< len(man.groups):
    if not(man.groups[i].isEmpty()):
      ngroups.add(man.groups[i])
  man.groups = ngroups

proc isFull*[A, B](man: SyncManager[A, B]): bool =
  result = false
  if len(man.groups) >= man.groupsCount:
    result = true
    for item in man.groups:
      if not(item.isFull()):
        result = false
        break

proc isEmpty*[A, B](man: SyncManager[A, B]): bool =
  result = (len(man.groups) == 0)

proc reorderGroups*[A, B](man: SyncManager[A, B]) =
  mixin getHeadSlot
  doAssert(not(man.isEmpty()))

  var x, y, z: int
  for i0 in 0 ..< len(man.groups):
    let group0 = man.groups[i0]
    for j0 in 0 ..< len(group0.slots):
      let slot0 = group0.slots[j0]
      for k0 in 0 ..< len(slot0.peers):
        var curSlot = getHeadSlot(slot0.peers[k0])
        x = -1; y = -1; z = -1

        for i1 in i0 ..< len(man.groups):
          let group1 = man.groups[i1]
          for j1 in j0 ..< len(group1.slots):
            let slot1 = group1.slots[j1]
            let start = if (i1 == i0) and (j1 == j0): k0 + 1 else: 0
            for k1 in start ..< len(slot1.peers):
              let newSlot = getHeadSlot(slot1.peers[k1])
              if curSlot < newSlot:
                curSlot = newSlot
                x = i1; y = j1; z = k1

        if x >= 0:
          swap(man.groups[i0].slots[j0].peers[k0],
               man.groups[x].slots[y].peers[z])

proc disband*[A, B](peerslot: PeerSlot[A, B]) =
  ## Releases all the peers back to the PeerPool, and make ``peerslot`` empty.
  for peer in peerslot.peers:
    peerslot.man.pool.release(peer)
  peerslot.peers.setLen(0)

proc disband*[A, B](peergroup: PeerGroup[A, B]) =
  ## Releases all the slots back to the PeerPool, and make ``peergroup`` empty.
  for slot in peergroup.slots:
    disband(slot)
  peergroup.slots.setLen(0)

proc disband*[A, B](syncman: SyncManager[A, B]) =
  ## Releases all the groups to the PeerPool, and make SyncManager peer groups
  ## empty.
  for group in syncman.groups:
    disband(group)
  syncman.groups.setLen(0)

proc getHeadSlot*[A, B](peerslot: PeerSlot[A, B]): Slot =
  ## Returns minimal available beacon chain slot, for peer's slot ``peerslot``.
  mixin getHeadSlot
  doAssert(len(peerslot.peers) > 0, "Number of peers in slot must not be zero")
  for i in 0 ..< len(peerslot.peers):
    if i == 0:
      result = getHeadSlot(peerslot.peers[i])
    else:
      let slot = getHeadSlot(peerslot.peers[i])
      if slot < result:
        result = slot

proc getHeadSlot*[A, B](peergroup: PeerGroup[A, B]): Slot =
  ## Returns minimal available beacon chain slot, for peer's group
  ## ``peergroup``.
  doAssert(len(peergroup.slots) > 0,
           "Number of slots in group must not be zero")
  for i in 0 ..< len(peergroup.slots):
    if i == 0:
      result = getHeadSlot(peergroup.slots[i])
    else:
      let slot = getHeadSlot(peergroup.slots[i])
      if slot < result:
        result = slot

proc getHeadSlot*[A, B](sman: SyncManager[A, B]): Slot =
  ## Returns minimal available beacon chain slot, for all peers in sync manager
  ## ``sman``.
  for i in 0 ..< len(sman.groups):
    if i == 0:
      result = getHeadSlot(sman.groups[i])
    else:
      let slot = getHeadSlot(sman.groups[i])
      if slot < result:
        result = slot

proc getBlocks*[A, B](peerslot: PeerSlot[A, B], slot: Slot, count: uint64,
                      step: uint64): Future[Option[BlockList]] {.async.} =
  mixin getBeaconBlocksByRange, getHeadRoot, `==`
  doAssert(len(peerslot.peers) > 0, "Number of peers in slot must not be zero")
  var pending = newSeq[Future[OptionBeaconBlockSeq]](len(peerslot.peers))
  var allFut, timeFut: Future[void]
  try:
    for i in 0 ..< len(peerslot.peers):
      let root = getHeadRoot(peerslot.peers[i])
      pending[i] = getBeaconBlocksByRange(peerslot.peers[i], root, slot, count,
                                          step)

    allFut = allFutures(pending)
    if peerslot.man.peerSlotTimeout == InfiniteDuration:
      timeFut = newFuture[void]()
    else:
      timeFut = sleepAsync(peerslot.man.peerSlotTimeout)

    discard await one(allFut, timeFut)
    # We do not care about who finished first, because we are waiting for all
    # peers it can happens that some peers returned data, and some are not.
    var results = newSeq[seq[SignedBeaconBlock]]()
    for i in 0 ..< len(pending):
      if pending[i].finished() and
         not(pending[i].failed()) and not(pending[i].cancelled()):
        var fdata = pending[i].read()
        if fdata.isSome():
          results.add(fdata.get())
        else:
          # remote peer did not returns any data
          discard
      else:
        # getBeaconBlocksByRange() returns failure
        discard

    if len(results) > 0:
      var m: seq[SignedBeaconBlock]
      var i = 0
      if len(results) > (len(peerslot.peers) div 2):
        # Now we going to obtain major sequence of blocks by using
        # Boyer–Moore majority vote algorithm.
        for x in results:
          if i == 0:
            m = x
            i = 1
          elif m == x:
            i = i + 1
          else:
            i = i - 1
        i = 0
        for x in results:
          if m == x:
            i = i + 1
        if i > (len(peerslot.peers) div 2):
          # Major sequence of blocks found, so we going to return such result
          # and penalize all the peers which returned different sequences of
          # blocks.
          for i in 0 ..< len(pending):
            if pending[i].finished() and
               not(pending[i].failed()) and not(pending[i].cancelled()):
              let fdata = pending[i].read()
              if fdata.isSome():
                if fdata.get() != m:
                  # peer returned data which is not major
                  discard
          result = BlockList.init(slot, count, step, m)
        else:
          # Major sequence could not be found, so we going to penalize all the
          # peers.
          discard
    else:
      # Timeout exceeded while we waiting data from peers, or peers returned
      # an error.
      discard
  except CancelledError as exc:
    if not allFut.finished:
      allFut.cancel()
    if not timeFut.finished:
      timeFut.cancel()
    for i in 0 ..< len(peerslot.peers):
      if not pending[i].finished:
        pending[i].cancel()
    raise exc

proc getParams*[T](peerslots: int, index: int, slot: T,
                  count: uint64): tuple[start: T, count: uint64, step: uint64] =
  mixin `+`
  doAssert(peerslots > 0, "Number of peerslots must not be zero")
  doAssert(count > 0'u64, "Number of requested blocks must not be zero")
  doAssert(index < peerslots, "Peer slot index must be lower then slots count")
  result.start = slot + uint64(index)
  let more = if uint64(index) < (count mod uint64(peerslots)): 1'u64 else: 0'u64
  result.count = (count div uint64(peerslots)) + more
  result.step = uint64(peerslots)

proc getBlocks*[A, B](peergroup: PeerGroup[A, B], slot: Slot,
                      count: uint64): Future[Option[BlockList]] {.async.} =
  doAssert(len(peergroup.slots) > 0,
           "Number of slots in group must not be zero")
  doAssert(count > 0'u64)
  let slotsCount = len(peergroup.slots)
  var
    params = newSeq[tuple[start: Slot, count: uint64, step: uint64]](slotsCount)
    results = newSeq[Option[BlockList]](slotsCount)
    pending = newSeq[Future[OptionBlockList]]()
    requests = newSeq[tuple[slot: int, param: int]]()
    failures = newSeq[int]()

  var allFut, timeFut: Future[void]
  try:
    for i in 0 ..< slotsCount:
      params[i] = getParams(slotsCount, i, slot, count)
      requests.add((slot: i, param: i))
      pending.add(getBlocks(peergroup.slots[i], params[i].start,
                            params[i].count, params[i].step))

    if peergroup.man.peerGroupTimeout == InfiniteDuration:
      timeFut = newFuture[void]()
    else:
      timeFut = sleepAsync(peergroup.man.peerGroupTimeout)

    while true:
      allFut = allFutures(pending)
      if not timeFut.finished():
        discard await one(allFut, timeFut)
        # We do not care about who finished first, because we are waiting for
        # all slots and it can happens that some slots returned data, and some
        # are not.
        for i in 0 ..< len(pending):
          let slotIndex = requests[i].slot
          let resIndex = requests[i].param
          if pending[i].finished() and
             not(pending[i].failed()) and not(pending[i].cancelled()):
            results[resIndex] = pending[i].read()
            if results[resIndex].isNone():
              failures.add(slotIndex)
          else:
            failures.add(slotIndex)

        if len(failures) == len(peergroup.slots):
          # All the slots in group are failed to download blocks.
          peergroup.disband()
          break
        else:
          pending.setLen(0)
          requests.setLen(0)

          var missing = 0
          for i in 0 ..< len(results):
            if results[i].isNone():
              inc(missing)

          if missing > 0:
            for k in 0 ..< len(peergroup.slots):
              if (missing > 0) and (k notin failures):
                for i in 0 ..< len(results):
                  if results[i].isNone():
                    requests.add((slot: k, param: i))
                    pending.add(getBlocks(peergroup.slots[k], params[i].start,
                                          params[i].count, params[i].step))
                    break
                dec(missing)
          else:
            # All the blocks downloaded.
            if len(failures) > 0:
              var slots = newSeq[PeerSlot[A, B]]()
              for i in 0 ..< len(peergroup.slots):
                if i notin failures:
                  slots.add(peergroup.slots[i])
                else:
                  disband(peergroup.slots[i])
              peergroup.slots = slots
            result = merge(results)
            break

  except CancelledError as exc:
    if not allFut.finished:
      allFut.cancel()
    if not timeFut.finished:
      timeFut.cancel()
    for i in 0 ..< len(peergroup.slots):
      if not pending[i].finished:
        pending[i].cancel()
    raise exc

proc updateStatus*[A, B](peerslot: PeerSlot[A, B]) {.async.} =
  mixin updateStatus
  doAssert(len(peerslot.peers) > 0, "Number of peers in slot must not be zero")
  let peersCount = len(peerslot.peers)
  var pending = newSeq[Future[void]](peersCount)
  var failed = newSeq[int]()
  var allFut, timeFut: Future[void]

  try:
    for i in 0 ..< peersCount:
      pending.add(updateStatus(peerslot.peers[i]))

    if peerslot.man.peerSlotTimeout == InfiniteDuration:
      timeFut = newFuture[void]()
    else:
      timeFut = sleepAsync(peerslot.man.peerSlotTimeout)

    allFut = allFutures(pending)
    discard await one(allFut, timeFut)
    for i in 0 ..< len(pending):
      if pending[i].finished() and pending[i].failed():
        failed.add(i)

    if len(failed) > 0:
      for index in failed:
        peerslot.man.pool.release(peerslot.peers[index])
        peerslot.peers.del(index)

  except CancelledError as exc:
    if not allFut.finished:
      allFut.cancel()
    if not timeFut.finished:
      timeFut.cancel()
    for i in 0 ..< peersCount:
      if not pending[i].finished:
        pending[i].cancel()
    raise exc

proc updateStatus*[A, B](sman: SyncManager[A, B]) {.async.} =
  var pending = newSeq[Future[void]]()
  try:
    for i in 0 ..< len(sman.groups):
      for k in 0 ..< len(sman.groups[i].slots):
        pending.add(updateStatus(sman.groups[i].slots[k]))
    await allFutures(pending)
  except CancelledError as exc:
    for i in 0 ..< len(pending):
      if not pending[i].finished:
        pending[i].cancel()
    raise exc

proc synchronize*[A, B](sman: SyncManager[A, B]) {.async.} =
  ## TODO: This synchronization procedure is not optimal, we can do it better
  ## if spawn N parallel tasks, where N is number of peer groups.
  var
    squeue: SyncQueue
    remoteKnownHeadSlot: Slot
    localHeadSlot: Slot = sman.getLocalHeadSlot()
    pending = newSeq[Future[OptionBlockList]]()
    requests = newSeq[SyncRequest]()
    startMoment = Moment.now()
    checkMoment = startMoment
    errorsCount = 0
    counter = 0'u64

  squeue = SyncQueue.init(localHeadSlot + 1'u64, localHeadSlot + 2'u64,
                          MAX_REQUESTED_BLOCKS, sman.updateLocalBlocks,
                          sman.groupsCount)
  while true:
    if errorsCount == sman.failuresCount:
      # Number of consecutive errors exceeds limit
      error "Synchronization failed", errors = errorsCount,
                                      duration = $(Moment.now() - startMoment)
      break

    pending.setLen(0)
    requests.setLen(0)

    await sman.fillGroups()
    sman.reorderGroups()

    localHeadSlot = sman.getLocalHeadSlot()
    let remoteHeadSlot = sman.getHeadSlot()
    if remoteHeadSlot > remoteKnownHeadSlot:
      remoteKnownHeadSlot = remoteHeadSlot
      squeue.updateLastSlot(remoteKnownHeadSlot)

    if localHeadSlot >= remoteKnownHeadSlot:
      info "Synchronization finished", progress = squeue.progress(),
                                       peers = sman.peersCount(),
                                       groups = len(sman.groups),
                                       duration = $(Moment.now() - startMoment)
      break
    else:
      if counter == 0:
        info "Starting synchronization", local_head_slot = localHeadSlot,
                                         remote_head_slot = remoteKnownHeadSlot,
                                         count = len(squeue),
                                         peers = sman.peersCount(),
                                         groups = len(sman.groups),
                                         progress = squeue.progress()

      else:
        info "Synchronization progress", progress = squeue.progress(),
                                         peers = sman.peersCount(),
                                         groups = len(sman.groups),
                                         iteration = counter

    counter = counter + 1'u64

    for i in countdown(len(sman.groups) - 1, 0):
      if len(squeue) == 0:
        break
      let groupLastSlot = sman.groups[i].getHeadSlot()
      var req = squeue.pop(uint64(len(sman.groups[i].slots)))
      trace "Request created", slot = req.slot, step = req.step,
                               count = req.count
      if groupLastSlot >= req.lastSlot():
        req.group = i
        pending.add(getBlocks(sman.groups[i], req.slot, req.count))
        requests.add(req)
        trace "Request sent to a group", group = i, slot = req.slot,
                                         step = req.step,
                                         count = req.count
      else:
        trace "Request returned to queue", slot = req.slot, step = req.step,
                                           count = req.count,
                                           group_last_slot = groupLastSlot
        squeue.push(req)

    if len(pending) == 0:
      # All the peer groups do not satisfy slot requirements
      # Disbanding all the peers
      sman.disband()
      inc(errorsCount)
      warn "Unable to create requests, disbanding peers", errors = errorsCount
      await sleepAsync(sman.failurePause)
      continue

    await allFutures(pending)

    var failedCount = 0
    for i in 0 ..< len(pending):
      if pending[i].finished() and not(pending[i].failed()):
        let res = pending[i].read()
        if res.isSome():
          trace "Request data received", group = requests[i].group,
                                         slot = requests[i].slot,
                                         step = requests[i].step,
                                         count = requests[i].count
          await squeue.push(requests[i], res.get().list)
        else:
          inc(failedCount)
          trace "Request failed", group = requests[i].group,
                                  slot = requests[i].slot,
                                  step = requests[i].step,
                                  count = requests[i].count
          squeue.push(requests[i])
          sman.groups[requests[i].group].disband()
      else:
        inc(failedCount)
        trace "Request failed", group = requests[i].group,
                                slot = requests[i].slot,
                                step = requests[i].step,
                                count = requests[i].count
        squeue.push(requests[i])
        sman.groups[requests[i].group].disband()

    if failedCount == len(pending):
      # All the peer groups failed to download requests.
      inc(errorsCount)
      warn "All requests failed to deliver data, disbanding peers",
                                                            errors = errorsCount
      await sleepAsync(sman.failurePause)
      continue
    else:
      errorsCount = 0

    sman.compactGroups()

    # if `statusPeriod` time passed, we are updating peers status.
    let stamp = Moment.now()
    if stamp - checkMoment > sman.statusPeriod:
      checkMoment = stamp
      info "Updating peers status"
      await sman.updateStatus()
      info "Peers status updated", duration = $(Moment.now() - checkMoment)

  # Returning all the peers back to PeerPool.
  sman.disband()

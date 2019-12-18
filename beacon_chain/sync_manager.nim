import options
import spec/datatypes, spec/digest, stew/bitseqs, chronos
import peer_pool

export datatypes, digest

const MAX_REQUESTED_BLOCKS = 20'u64

type
  # A - Peer type
  # B - PeerID type
  #
  # getLastSlot(Peer): Slot
  # getHeadRoot(Peer): Eth2Digest
  # getBeaconBlocksByRange(Peer, Eth2Digest, Slot, uint64, uint64): Future[Option[seq[BeaconBlock]]]
  # updateStatus(Peer): void

  PeerSlot*[A, B] = ref object
    peers*: seq[A]
    man: SyncManager[A, B]

  PeerGroup*[A, B] = ref object
    slots*: seq[PeerSlot[A, B]]
    man: SyncManager[A, B]

  SyncManager*[A, B] = ref object
    groups*: seq[PeerGroup[A, B]]
    pool: PeerPool[A, B]
    peersInSlot: int
    slotsInGroup: int
    groupsCount: int
    peerSlotTimeout: chronos.Duration
    peerGroupTimeout: chronos.Duration
    statusPeriod: chronos.Duration

  BlockList* = object
    list*: seq[BeaconBlock]
    map*: BitSeq
    start*: Slot

  OptionBlockList* = Option[BlockList]
  OptionBeaconBlockSeq* = Option[seq[BeaconBlock]]

  SyncManagerError* = object of CatchableError

proc init*(t: typedesc[BlockList], start: Slot, count, step: uint64,
           list: openarray[BeaconBlock]): Option[BlockList] =
  mixin getSlot
  var res: BlockList
  var error = false
  var current = start
  var index = 0

  res.map = BitSeq.init(0)

  for i in 0'u64 ..< count:
    if index < len(list):
      let slot = list[index].slot
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
      result = result & $blist.list[index].slot & ", "
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
              res.map.raiseBit(resIndex)
              res.list.add(blists[i].list[indexes[i]])
              inc(indexes[i])
        inc(resIndex)
        slot = slot + 1'u64
      result = some(res)

proc newSyncManager*[A, B](pool: PeerPool[A, B],
                           peersInSlot = 3, peerSlotTimeout = 6.seconds,
                           slotsInGroup = 2, peerGroupTimeout = 10.seconds,
                           groupsCount = 10,
                           statusPeriod = 10.minutes): SyncManager[A, B] =
  ## ``pool`` - PeerPool object which will be used as source of peers.
  ##
  ## ``peersInSlot`` - maximum number of peers in slot.
  ##
  ## ``slotsInGroup`` - maximum number of slots in group.
  ##
  ## ``groupsCount`` - maximum number of groups used in sync process.
  result = SyncManager[A, B]()
  result.pool = pool
  result.peersInSlot = peersInSlot
  result.slotsInGroup = slotsInGroup
  result.groupsCount = groupsCount
  result.peerSlotTimeout = peerSlotTimeout
  result.peerGroupTimeout = peerGroupTimeout
  result.statusPeriod = statusPeriod

template nearestOdd(number: int): int =
  number - ((number - 1) mod 2)

proc newPeerSlot*[A, B](man: SyncManager[A, B]): PeerSlot[A, B] =
  result = PeerSlot[A, B]()
  result.man = man
  result.peers = newSeq[A]()

proc `$`*[A, B](peerslot: PeerSlot[A, B]): string =
  mixin getKey, getLastSlot
  if len(peerslot.peers) == 0:
    result = "<>"
  else:
    result = "<"
    for item in peerslot.peers:
      result.add("\"" & getKey(item) & "\"")
      result.add(":" & $getLastSlot(item))
      result.add(", ")
    result.setLen(len(result) - 2)
    result.add(">")

proc isFull*[A, B](peerslot: PeerSlot[A, B]): bool {.inline.} =
  result = (len(peerslot.peers) == peerslot.man.peersInSlot)

proc isEmpty*[A, B](peerslot: PeerSlot[A, B]): bool {.inline.} =
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
  mixin getLastSlot
  doAssert(not(man.isEmpty()))

  var x, y, z: int
  for i0 in 0 ..< len(man.groups):
    let group0 = man.groups[i0]
    for j0 in 0 ..< len(group0.slots):
      let slot0 = group0.slots[j0]
      for k0 in 0 ..< len(slot0.peers):
        var curSlot = getLastSlot(slot0.peers[k0])
        x = -1; y = -1; z = -1

        for i1 in i0 ..< len(man.groups):
          let group1 = man.groups[i1]
          for j1 in j0 ..< len(group1.slots):
            let slot1 = group1.slots[j1]
            let start = if (i1 == i0) and (j1 == j0): k0 + 1 else: 0
            for k1 in start ..< len(slot1.peers):
              let newSlot = getLastSlot(slot1.peers[k1])
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
  ## Released all the slots back to the PeerPool, and make ``peergroup`` empty.
  for slot in peergroup.slots:
    disband(slot)
  peergroup.slots.setLen(0)

proc getLastSlot*[A, B](peerslot: PeerSlot[A, B]): Slot =
  ## Returns minimal available beacon chain slot, for peer's slot ``peerslot``.
  mixin getLastSlot
  doAssert(len(peerslot.peers) > 0, "Number of peers in slot must not be zero")
  for i in 0 ..< len(peerslot.peers):
    if i == 0:
      result = getLastSlot(peerslot.peers[i])
    else:
      let slot = getLastSlot(peerslot.peers[i])
      if slot < result:
        result = slot

proc getLastSlot*[A, B](peergroup: PeerGroup[A, B]): Slot =
  ## Returns minimal available beacon chain slot, for peer's group
  ## ``peergroup``.
  doAssert(len(peergroup.slots) > 0,
           "Number of slots in group must not be zero")
  for i in 0 ..< len(peergroup.slots):
    if i == 0:
      result = getLastSlot(peergroup.slots[i])
    else:
      let slot = getLastSlot(peergroup.slots[i])
      if slot < result:
        result = slot

proc getLastSlot*[A, B](sman: SyncManager[A, B]): Slot =
  ## Returns minimal available beacon chain slot, for all peers in sync manager
  ## ``sman``.
  for i in 0 ..< len(sman.groups):
    if i == 0:
      result = getLastSlot(sman.groups[i])
    else:
      let slot = getLastSlot(sman.groups[i])
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

    var ready = await one(allFut, timeFut)
    # We do not care about who finished first, because we are waiting for all
    # peers it can happens that some peers returned data, and some are not.
    var results = newSeq[seq[BeaconBlock]]()
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
      var m: seq[BeaconBlock]
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
        var ready = await one(allFut, timeFut)
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
    var ready = await one(allFut, timeFut)
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
    for i in 0 ..< len(peersCount):
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

proc sync*[A, B](sman: SyncManager[A, B], lastSlot: Slot) {.async.} =
  var remoteLastKnownSlot: Slot
  var localLastSlot = lastSlot
  var requests = newSeq[tuple[slot: Slot, count: uint64, group: int]]()
  var pending = newSeq[Future[OptionBlockList]]()
  var failed = newSeq[int]()
  var checkMoment = Moment.now()

  while true:
    pending.setLen(0)
    requests.setLen(0)

    await sman.fillGroups()
    sman.reorderGroups()

    let remoteLastSlot = sman.getLastSlot()
    if remoteLastSlot > remoteLastKnownSlot:
      remoteLastKnownSlot = remoteLastSlot

    if localLastSlot >= remoteLastKnownSlot:
      # We are already synced.
      break

    var currentSlot = localLastSlot + 1
    for i in 0 ..< len(sman.groups):
      let groupLastSlot = sman.groups[i].getLastSlot()
      if localLastSlot < groupLastSlot:
        var groupCount = min(uint64(groupLastSlot - currentSlot),
                             MAX_REQUESTED_BLOCKS)
        currentSlot = currentSlot + groupCount
        requests.add((slot: currentSlot, count: groupCount, group: i))
        pending.add(getBlocks(sman.groups[i], currentSlot, groupCount))
      else:
        # Group's minimal slot is less than ours.
        discard

    await allFutures(pending)

    for i in 0 ..< len(pending):
      if pending[i].finished() and pending[i].failed():
        failed.add(i)

    if len(failed) == len(pending):
      # All groups are failed
      discard
    elif len(failed) < len(pending) and len(failed) != 0:
      # Groups failed partially
      discard
    else:
      # All groups are succeed
      discard

    # if `statusPeriod` time passed, we are updating peer status.
    let stamp = Moment.now()
    if stamp - checkMoment > sman.statusPeriod:
      checkMoment = stamp
      await sman.updateStatus()

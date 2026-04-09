# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[tables, heapqueue, algorithm, sequtils, typetraits]
import chronos

export tables

type
  PeerType* = enum
    Incoming, Outgoing

  PeerFlags = enum
    Acquired, DeleteOnRelease

  PeerStatus* = enum
    Success,        ## Peer was successfully added to PeerPool.
    DuplicateError, ## Peer is already present in PeerPool.
    NoSpaceError,   ## There no space for the peer in PeerPool.
    LowScoreError,  ## Peer has too low score.
    DeadPeerError   ## Peer is already dead.

  PeerIndex = distinct int
    # Distinct type is important here, because we are using custom sorting
    # functions which are not compatible with integer behavior.

  PeerItem[T] = object
    data: T
    peerType: PeerType
    flags: set[PeerFlags]
    index: PeerIndex

  PeerScoreCheckCallback*[T] = proc(peer: T): bool {.gcsafe, raises: [].}

  PeerCounterCallback* = proc() {.gcsafe, raises: [].}

  PeerOnDeleteCallback*[T] = proc(peer: T) {.gcsafe, raises: [].}

  PeerCustomFilterCallback*[T] = proc(peer: T): bool {.gcsafe, raises: [].}

  PeerPool*[A, B] = ref object
    changeEvent: AsyncEvent
    storage: seq[PeerItem[A]]
    registry: Table[B, PeerIndex]
    sorted: seq[PeerIndex]
    empties: seq[PeerIndex]
    scoreCheck: PeerScoreCheckCallback[A]
    onDeletePeer: PeerOnDeleteCallback[A]
    peerCounter: PeerCounterCallback
    maxPeersCount: int
    maxIncPeersCount: int
    maxOutPeersCount: int
    curIncPeersCount: int
    curOutPeersCount: int
    acqIncPeersCount: int
    acqOutPeersCount: int

  PeerPoolError* = object of CatchableError

func `==`*(a, b: PeerIndex): bool {.borrow.}

iterator pairs*[A, B](pool: PeerPool[A, B]): (B, A) =
  for peerId, pindex in pool.registry:
    yield (peerId, pool.storage[distinctBase(pindex)].data)

proc resort[A, B](
    pool: PeerPool[A, B],
    unsorted: var openArray[PeerIndex]
) =
  mixin `cmp`
  proc pcmp(a, b: PeerIndex): int {.closure, raises: [].} =
    cmp(pool.storage[distinctBase(a)].data, pool.storage[distinctBase(b)].data)
  unsorted.sort(pcmp, order = SortOrder.Descending)

proc resorted[A, B](
    pool: PeerPool[A, B],
    unsorted: openArray[PeerIndex]
): seq[PeerIndex] =
  var res = @unsorted
  pool.resort(res)
  res

proc addToStorage[A, B](pool: PeerPool[A, B], item: PeerItem[A]): PeerIndex =
  var indexedItem = item
  if len(pool.empties) > 0:
    indexedItem.index = pool.empties[0]
    pool.storage[distinctBase(indexedItem.index)] = indexedItem
    pool.empties.del(0)
  else:
    indexedItem.index = PeerIndex(len(pool.storage))
    pool.storage.add(indexedItem)
  indexedItem.index

proc newPeerPool*[A, B](
    maxPeers = -1,
    maxIncomingPeers = -1,
    maxOutgoingPeers = -1,
    scoreCheckCb: PeerScoreCheckCallback[A] = nil,
    peerCounterCb: PeerCounterCallback = nil,
    onDeleteCb: PeerOnDeleteCallback[A] = nil
): PeerPool[A, B] =
  ## Create new PeerPool.
  ##
  ## ``maxPeers`` - maximum number of peers allowed. All the peers which
  ## exceeds this number will be rejected (``addPeer()`` procedure will return
  ## ``false``). By default this number is infinite.
  ##
  ## ``maxIncomingPeers`` - maximum number of incoming peers allowed. All the
  ## incoming peers exceeds this number will be rejected. By default this
  ## number is infinite.
  ##
  ## ``maxOutgoingPeers`` - maximum number of outgoing peers allowed. All the
  ## outgoing peers exceeds this number will be rejected. By default this
  ## number if infinite.
  ##
  ## ``scoreCheckCb`` - callback which will be called for all released peers.
  ## If callback procedure returns ``false`` peer will be removed from
  ## PeerPool.
  ##
  ## ``peerCountCb`` - callback to be called when number of peers in PeerPool
  ## has been changed.
  ##
  ## ``onDeleteCb`` - callback to be called when peer is leaving PeerPool.
  ##
  ## Please note, that if ``maxPeers`` is positive non-zero value, then equation
  ## ``maxPeers >= maxIncomingPeers + maxOutgoingPeers`` must be ``true``.
  if maxPeers != -1:
    doAssert(maxPeers >= maxIncomingPeers + maxOutgoingPeers)

  let
    maxPeersCount = if maxPeers < 0: high(int) else: maxPeers
    maxIncPeersCount =
      if maxIncomingPeers < 0:
        high(int)
      else:
        maxIncomingPeers
    maxOutPeersCount =
      if maxOutgoingPeers < 0:
        high(int)
      else:
        maxOutgoingPeers
    res = PeerPool[A, B](
      changeEvent: newAsyncEvent(),
      registry: initTable[B, PeerIndex](),
      scoreCheck: scoreCheckCb,
      peerCounter: peerCounterCb,
      onDeletePeer: onDeleteCb,
      maxPeersCount: maxPeersCount,
      maxIncPeersCount: maxIncPeersCount,
      maxOutPeersCount: maxOutPeersCount,
      curIncPeersCount: 0,
      curOutPeersCount: 0,
      acqIncPeersCount: 0,
      acqOutPeersCount: 0
    )
  res

proc len*[A, B](pool: PeerPool[A, B]): int =
  ## Returns number of registered peers in PeerPool ``pool``. This number
  ## includes all the peers (acquired and available).
  len(pool.registry)

proc lenCurrent*[A, B](pool: PeerPool[A, B],
                       filter = {PeerType.Incoming,
                                 PeerType.Outgoing}): int =
  ## Returns number of registered peers in PeerPool ``pool`` which satisfies
  ## filter ``filter``.
  (if PeerType.Incoming in filter: pool.curIncPeersCount else: 0) +
  (if PeerType.Outgoing in filter: pool.curOutPeersCount else: 0)

proc lenAvailable*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): int =
  ## Returns number of peers available for acquisition in PeerPool
  ## ``pool`` which satisfies filter ``filter``.
  (if PeerType.Incoming in filter:
     pool.curIncPeersCount - pool.acqIncPeersCount
   else:
     0) +
  (if PeerType.Outgoing in filter:
     pool.curOutPeersCount - pool.acqOutPeersCount
   else:
     0)

proc lenAvailable*[A, B](
    pool: PeerPool[A, B],
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): int =
  ## Returns number of peers available for acquisition in PeerPool
  ## ``pool`` which satisfies filter ``filter`` and custom filter
  ## ``customFilter``.
  ## Note: This is O(n) operation.
  let available = pool.lenAvailable(filter)
  var res = 0
  for pindex in pool.sorted.items():
    let item = addr(pool.storage[distinctBase(pindex)])
    if (PeerFlags.Acquired notin item[].flags) and
       (item[].peerType in filter) and
       (isNil(customFilter) or customFilter(item[].data)):
      inc(res)
    if res == available:
      # Number of customly filtered items could not be higher than number of
      # peers of specific directions.
      break
  res

proc lenAcquired*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): int =
  ## Returns number of acquired peers in PeerPool ``pool`` which satisifies
  ## filter ``filter``.
  (if PeerType.Incoming in filter: pool.acqIncPeersCount else: 0) +
  (if PeerType.Outgoing in filter: pool.acqOutPeersCount else: 0)

proc lenSpace*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): int =
  ## Returns number of available space for peers in PeerPool ``pool`` which
  ## satisfies filter ``filter``.
  let
    curPeersCount = pool.curIncPeersCount + pool.curOutPeersCount
    spaceAvailable = pool.maxPeersCount - curPeersCount
    incoming = min(spaceAvailable,
                   pool.maxIncPeersCount - pool.curIncPeersCount)
    outgoing = min(spaceAvailable,
                   pool.maxOutPeersCount - pool.curOutPeersCount)
  if filter == {PeerType.Incoming, PeerType.Outgoing}:
    # To avoid overflow check we need to check by ourself.
    if uint64(incoming) + uint64(outgoing) > uint64(high(int)):
      min(spaceAvailable, high(int))
    else:
      min(spaceAvailable, incoming + outgoing)
  elif PeerType.Incoming in filter:
    incoming
  else:
    outgoing

proc shortLogAvailable*[A, B](pool: PeerPool[A, B]): string =
  $pool.lenAvailable({PeerType.Incoming}) & "/" &
    $pool.lenAvailable({PeerType.Outgoing})

proc shortLogAcquired*[A, B](pool: PeerPool[A, B]): string =
  $pool.acqIncPeersCount & "/" & $pool.acqOutPeersCount

proc shortLogSpace*[A, B](pool: PeerPool[A, B]): string =
  $pool.lenSpace({PeerType.Incoming}) & "/" &
    $pool.lenSpace({PeerType.Outgoing})

proc shortLogCurrent*[A, B](pool: PeerPool[A, B]): string =
  $pool.curIncPeersCount & "/" & $pool.curOutPeersCount

proc checkPeerScore*[A, B](pool: PeerPool[A, B], peer: A): bool {.inline.} =
  ## Returns ``true`` if peer passing score check.
  if not(isNil(pool.scoreCheck)):
    pool.scoreCheck(peer)
  else:
    true

proc peerCountChanged[A, B](pool: PeerPool[A, B]) =
  ## Call callback when number of peers changed.
  if not(isNil(pool.peerCounter)):
    pool.peerCounter()

proc peerDeleted[A, B](pool: PeerPool[A, B], peer: A) =
  ## Call callback when peer is leaving PeerPool.
  if not(isNil(pool.onDeletePeer)):
    pool.onDeletePeer(peer)

proc deletePeerImpl[A, B](
    pool: PeerPool[A, B],
    peer: A,
    key: B,
    pindex: PeerIndex
) =
  let sindex = pool.sorted.find(pindex)
  pool.storage[distinctBase(pindex)] = PeerItem[A](index: PeerIndex(-1))
  pool.empties.add(pindex)
  pool.registry.del(key)
  if sindex >= 0:
    # sindex == -1 when deleting peer which was acquired (not in `sorted` array).
    pool.sorted.delete(sindex)

  # Indicate that we have an empty space
  pool.changeEvent.fire()
  pool.peerDeleted(peer)
  pool.peerCountChanged()

proc deletePeer*[A, B](pool: PeerPool[A, B], peer: A, force = false): bool =
  ## Remove ``peer`` from PeerPool ``pool``.
  ##
  ## Deletion occurs immediately only if peer is available, otherwise it will
  ## be deleted only when peer will be released. You can change this behavior
  ## with ``force`` option.
  mixin getKey
  let
    key = peer.getKey()
    pindex =
      block:
        let res = pool.registry.getOrDefault(key, PeerIndex(-1))
        if res == PeerIndex(-1):
          return false
        res

  var item = addr(pool.storage[distinctBase(pindex)])
  if (PeerFlags.Acquired in item[].flags):
    if not(force):
      item[].flags.incl(PeerFlags.DeleteOnRelease)
    else:
      case item[].peerType
      of PeerType.Incoming:
        dec(pool.acqIncPeersCount)
        dec(pool.curIncPeersCount)
      of PeerType.Outgoing:
        dec(pool.acqOutPeersCount)
        dec(pool.curOutPeersCount)
      pool.deletePeerImpl(peer, key, pindex)
  else:
    case item[].peerType
    of PeerType.Incoming:
      dec(pool.curIncPeersCount)
    of PeerType.Outgoing:
      dec(pool.curOutPeersCount)
    pool.deletePeerImpl(peer, key, pindex)

  true

proc addPeerImpl[A, B](pool: PeerPool[A, B], peer: A, peerKey: B,
                       peerType: PeerType) =
  mixin getFuture
  proc onPeerClosed(udata: pointer) {.gcsafe, raises: [].} =
    discard pool.deletePeer(peer)

  let
    item = PeerItem[A](data: peer, peerType: peerType)
    pindex = pool.addToStorage(item)
    pitem = addr(pool.storage[distinctBase(pindex)])

  pool.registry[peerKey] = pindex
  pool.sorted.add(pindex)
  pool.resort(pool.sorted)

  pitem[].data.getFuture().addCallback(onPeerClosed)
  case peerType
  of PeerType.Incoming:
    inc(pool.curIncPeersCount)
  of PeerType.Outgoing:
    inc(pool.curOutPeersCount)
  pool.changeEvent.fire()
  pool.peerCountChanged()

proc checkPeer*[A, B](pool: PeerPool[A, B], peer: A): PeerStatus {.inline.} =
  ## Checks if peer could be added to PeerPool, e.g. it has:
  ##
  ## * Positive value of peer's score - (PeerStatus.LowScoreError)
  ## * Peer's key is not present in PeerPool - (PeerStatus.DuplicateError)
  ## * Peer's lifetime future is not finished yet - (PeerStatus.DeadPeerError)
  ##
  ## If peer could be added to PeerPool procedure returns (PeerStatus.Success)
  mixin getKey, getFuture
  if not(pool.checkPeerScore(peer)):
    PeerStatus.LowScoreError
  else:
    let peerKey = getKey(peer)
    if not(pool.registry.hasKey(peerKey)):
      if not(peer.getFuture().finished):
        PeerStatus.Success
      else:
        PeerStatus.DeadPeerError
    else:
      PeerStatus.DuplicateError

proc addPeerNoWait*[A, B](
    pool: PeerPool[A, B],
    peer: A,
    peerType: PeerType
): PeerStatus =
  ## Add peer ``peer`` of type ``peerType`` to PeerPool ``pool``.
  ##
  ## Procedure returns ``PeerStatus``
  ##   * if ``peer`` is already closed - (PeerStatus.DeadPeerError)
  ##   * if ``pool`` already has peer ``peer`` - (PeerStatus.DuplicateError)
  ##   * if ``pool`` currently has a maximum of peers.
  ##     (PeerStatus.NoSpaceError)
  ##   * if ``pool`` currently has a maximum of `Incoming` or `Outgoing` peers.
  ##     (PeerStatus.NoSpaceError)
  ##
  ## Procedure returns (PeerStatus.Success) on success.
  mixin getKey, getFuture
  let res = pool.checkPeer(peer)
  if res != PeerStatus.Success:
    res
  else:
    let peerKey = peer.getKey()
    case peerType:
    of PeerType.Incoming:
      if pool.lenSpace({PeerType.Incoming}) > 0:
        pool.addPeerImpl(peer, peerKey, peerType)
        PeerStatus.Success
      else:
        PeerStatus.NoSpaceError
    of PeerType.Outgoing:
      if pool.lenSpace({PeerType.Outgoing}) > 0:
        pool.addPeerImpl(peer, peerKey, peerType)
        PeerStatus.Success
      else:
        PeerStatus.NoSpaceError

proc waitForEmptySpace*[A, B](
    pool: PeerPool[A, B],
    peerType: PeerType
) {.async: (raises: [CancelledError]).} =
  ## This procedure will block until ``pool`` will have an empty space for peer
  ## of type ``peerType``.
  while pool.lenSpace({peerType}) == 0:
    await pool.changeEvent.wait()
    pool.changeEvent.clear()

proc addPeer*[A, B](
    pool: PeerPool[A, B],
    peer: A,
    peerType: PeerType
): Future[PeerStatus] {.async: (raises: [CancelledError]).} =
  ## Add peer ``peer`` of type ``peerType`` to PeerPool ``pool``.
  ##
  ## This procedure will wait for an empty space in PeerPool ``pool``, if
  ## PeerPool ``pool`` is full.
  ##
  ## Procedure returns ``PeerStatus``
  ##   * if ``peer`` is already closed - (PeerStatus.DeadPeerError)
  ##   * if ``pool`` already has peer ``peer`` - (PeerStatus.DuplicateError)
  ##
  ## Procedure returns (PeerStatus.Success) on success.
  mixin getKey

  template check(peer: untyped) =
    let res = pool.checkPeer(peer)
    if res != PeerStatus.Success:
      return res

  while pool.lenSpace({peerType}) == 0:
    peer.check()
    await pool.changeEvent.wait()
    pool.changeEvent.clear()

  # Because we could wait for a long time we need to check peer one more
  # time to avoid race condition.
  peer.check()

  pool.addPeerImpl(peer, peer.getKey(), peerType)
  PeerStatus.Success

proc acquireItemImpl[A, B](
    pool: PeerPool[A, B],
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A] = nil
): A =
  let (sindex, pitem) =
    block:
      var
        rindex = -1
        res: ptr PeerItem[A] = nil
      for sindex, pindex in pool.sorted.pairs():
        res = addr(pool.storage[distinctBase(pindex)])
        if (PeerFlags.Acquired notin res[].flags) and
             (res[].peerType in filter) and
             (isNil(customFilter) or customFilter(res[].data)):
          rindex = sindex
          break
      (rindex, res)

  doAssert(sindex >= 0)

  case pitem[].peerType
  of PeerType.Incoming:
    inc(pool.acqIncPeersCount)
  of PeerType.Outgoing:
    inc(pool.acqOutPeersCount)

  pool.sorted.delete(sindex)

  pitem[].flags.incl(PeerFlags.Acquired)
  pitem[].data

proc acquire*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): Future[A] {.async: (raises: [CancelledError]).} =
  ## Acquire peer from PeerPool ``pool``, which match the filter ``filter``.
  ## This procedure will wait for peer which satisfy filter will become
  ## available for acquisition.
  mixin getKey
  doAssert(filter != {}, "Filter must not be empty")
  while true:
    if pool.lenAvailable(filter) == 0:
      await pool.changeEvent.wait()
      pool.changeEvent.clear()
    else:
      return pool.acquireItemImpl(filter, nil)

proc acquire*[A, B](
    pool: PeerPool[A, B],
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): Future[A] {.async: (raises: [CancelledError]).} =
  ## Acquire peer from PeerPool ``pool``, which match the filter ``filter`` and
  ## custom filter ``customFilter``. This procedure will wait for peer which
  ## satisfy filters will become available for acquisition.
  mixin getKey
  doAssert(filter != {}, "Filter must not be empty")
  while true:
    if pool.lenAvailable(filter, customFilter) == 0:
      await pool.changeEvent.wait()
      pool.changeEvent.clear()
    else:
      return pool.acquireItemImpl(filter, customFilter)

proc acquireNoWait*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): A {.raises: [PeerPoolError].} =
  ## Acquire peer from PeerPool ``pool``, which match the filter ``filter``
  ## without waiting, this procedure will raise PeerPoolError if no peers
  ## which satisfy filters are available for acquisition.
  doAssert(filter != {}, "Filter must not be empty")
  if pool.lenAvailable(filter) < 1:
    raise newException(PeerPoolError, "Not enough peers in pool")
  pool.acquireItemImpl(filter, nil)

proc acquireNoWait*[A, B](
    pool: PeerPool[A, B],
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): A {.raises: [PeerPoolError].} =
  ## Acquire peer from PeerPool ``pool``, which match the filter ``filter`` and
  ## custom filter ``customFilter`` without waiting, this procedure will raise
  ## PeerPoolError if no peers which satisfy filters are available for
  ## acquisition.
  doAssert(filter != {}, "Filter must not be empty")
  if pool.lenAvailable(filter, customFilter) < 1:
    raise newException(PeerPoolError, "Not enough peers in pool")
  pool.acquireItemImpl(filter, customFilter)

proc release*[A, B](pool: PeerPool[A, B], peer: A) =
  ## Release peer ``peer`` back to PeerPool ``pool``
  mixin getKey
  let
    key = peer.getKey()
    pindex =
      block:
        let res = pool.registry.getOrDefault(key, PeerIndex(-1))
        if res == PeerIndex(-1):
          return
        res
    item = addr(pool.storage[distinctBase(pindex)])

  if PeerFlags.Acquired in item[].flags:
    if not(pool.checkPeerScore(peer)):
      item[].flags.incl(DeleteOnRelease)
    if PeerFlags.DeleteOnRelease in item[].flags:
      case item[].peerType
      of PeerType.Incoming:
        dec(pool.acqIncPeersCount)
        dec(pool.curIncPeersCount)
      of PeerType.Outgoing:
        dec(pool.acqOutPeersCount)
        dec(pool.curOutPeersCount)
      pool.deletePeerImpl(peer, key, pindex)
    else:
      item[].flags.excl(PeerFlags.Acquired)
      case item[].peerType
      of PeerType.Incoming:
        dec(pool.acqIncPeersCount)
      of PeerType.Outgoing:
        dec(pool.acqOutPeersCount)

      pool.sorted.add(pindex)
      pool.resort(pool.sorted)
      pool.changeEvent.fire()

proc release*[A, B](pool: PeerPool[A, B], peers: openArray[A]) =
  ## Release array of peers ``peers`` back to PeerPool ``pool``.
  for item in peers:
    pool.release(item)

proc acquire*[A, B](
    pool: PeerPool[A, B],
    number: int,
    filter = {PeerType.Incoming, PeerType.Outgoing}
): Future[seq[A]] {.async: (raises: [CancelledError]).} =
  ## Acquire ``number`` number of peers from PeerPool ``pool``, which match the
  ## filter ``filter``.
  doAssert(filter != {}, "Filter must not be empty")
  var peers: seq[A]
  try:
    if number > 0:
      while true:
        if len(peers) >= number:
          break
        if pool.lenAvailable(filter) == 0:
          await pool.changeEvent.wait()
          pool.changeEvent.clear()
        else:
          peers.add(pool.acquireItemImpl(filter))
  except CancelledError as exc:
    # If we got cancelled, we need to return all the acquired peers back to
    # pool.
    for item in peers:
      pool.release(item)
    peers.setLen(0)
    raise exc
  peers

proc acquire*[A, B](
    pool: PeerPool[A, B],
    number: int,
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): Future[seq[A]] {.async: (raises: [CancelledError]).} =
  ## Acquire ``number`` number of peers from PeerPool ``pool``, which match the
  ## filter ``filter`` and custom filter ``customFilter``. This procedure will
  ## wait for ``number`` of peers which satisfy filter will become available
  ## and acquired.
  doAssert(filter != {}, "Filter must not be empty")
  var peers: seq[A]
  try:
    if number > 0:
      while true:
        if len(peers) >= number:
          break
        if pool.lenAvailable(filter, customFilter) == 0:
          await pool.changeEvent.wait()
          pool.changeEvent.clear()
        else:
          peers.add(pool.acquireItemImpl(filter, customFilter))
  except CancelledError as exc:
    # If we got cancelled, we need to return all the acquired peers back to
    # pool.
    for item in peers:
      pool.release(item)
    peers.setLen(0)
    raise exc
  peers

proc acquireNoWait*[A, B](
    pool: PeerPool[A, B],
    number: int,
    filter = {PeerType.Incoming, PeerType.Outgoing}
): seq[A] =
  ## Acquire ``number`` number of peers from PeerPool ``pool``, which match the
  ## filter ``filter``. This procedure does not wait for peers, it will raise
  ## `PeerPoolError` if peers matching the filters are not available.
  doAssert(filter != {}, "Filter must not be empty")
  var peers: seq[A]
  if pool.lenAvailable(filter) < number:
    raise newException(PeerPoolError, "Not enough peers in pool")
  for i in 0 ..< number:
    peers.add(pool.acquireItemImpl(filter))
  peers

proc acquireNoWait*[A, B](
    pool: PeerPool[A, B],
    number: int,
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): seq[A] =
  ## Acquire ``number`` number of peers from PeerPool ``pool``, which match the
  ## filter ``filter`` and custom filter ``filter``. This procedure does not
  ## wait for peers, it will raise `PeerPoolError` if peers matching the
  ## filters are not available.
  doAssert(filter != {}, "Filter must not be empty")
  var peers: seq[A]
  if pool.lenAvailable(filter, customFilter) < number:
    raise newException(PeerPoolError, "Not enough peers in pool")
  for i in 0 ..< number:
    peers.add(pool.acquireItemImpl(filter, customFilter))
  peers

proc acquireIncomingPeer*[A, B](
    pool: PeerPool[A, B]
): Future[A] {.async: (raises: [CancelledError], raw: true).}  =
  ## Acquire single incoming peer from PeerPool ``pool``.
  pool.acquire({PeerType.Incoming})

proc acquireOutgoingPeer*[A, B](
    pool: PeerPool[A, B]
): Future[A] {.async: (raises: [CancelledError], raw: true).}  =
  ## Acquire single outgoing peer from PeerPool ``pool``.
  pool.acquire({PeerType.Outgoing})

proc acquireIncomingPeers*[A, B](
    pool: PeerPool[A, B],
    number: int
): Future[seq[A]] {.async: (raises: [CancelledError], raw: true).}  =
  ## Acquire ``number`` number of incoming peers from PeerPool ``pool``.
  pool.acquire(number, {PeerType.Incoming})

proc acquireOutgoingPeers*[A, B](
    pool: PeerPool[A, B],
    number: int
): Future[seq[A]] {.async: (raises: [CancelledError], raw: true).}  =
  ## Acquire ``number`` number of outgoing peers from PeerPool ``pool``.
  pool.acquire(number, {PeerType.Outgoing})

iterator peers*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): A =
  ## Iterate over sorted list of peers.
  ##
  ## All peers will be sorted by equation `>`(Peer1, Peer2), so biggest values
  ## will be first.
  ##
  ## NOTE: While it safe to use this iterator in combination with await calls,
  ## consider that right after `await` call, PeerPool could become different
  ## from the snapshot this iterator provides.
  var unsorted: seq[PeerIndex]
  for pindex in pool.registry.values():
    if pool.storage[distinctBase(pindex)].peerType in filter:
      unsorted.add(pindex)

  # We allocate new sequence here to avoid problems with missing indices when
  # await operation could be part of iteration.
  let sortedPeers =
    pool.resorted(unsorted).mapIt(pool.storage[distinctBase(it)].data)
  for peer in sortedPeers:
    yield peer

iterator peers*[A, B](
    pool: PeerPool[A, B],
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): A =
  ## Iterate over sorted list of peers.
  ##
  ## All peers will be sorted by equation `>`(Peer1, Peer2), so biggest values
  ## will be first.
  ##
  ## NOTE: While it safe to use this iterator in combination with await calls,
  ## consider that right after `await` call, PeerPool could become different
  ## from the snapshot this iterator provides.
  var unsorted: seq[PeerIndex]
  for pindex in pool.registry.values():
    let item = addr(pool.storage[distinctBase(pindex)])
    if (item[].peerType in filter) and
       (isNil(customFilter) or customFilter(item[].data)):
      unsorted.add(pindex)

  # We allocate new sequence here to avoid problems with missing indices when
  # await operation could be part of iteration.
  let sortedPeers =
    pool.resorted(unsorted).mapIt(pool.storage[distinctBase(it)].data)
  for peer in sortedPeers:
    yield peer

iterator availablePeers*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): A =
  ## Iterate over sorted list of available peers.
  ##
  ## All peers will be sorted by equation `>`(Peer1, Peer2), so biggest values
  ## will be first.
  ##
  ## NOTE: While it safe to use this iterator in combination with await calls,
  ## consider that right after `await` call, PeerPool could become different
  ## from the snapshot this iterator provides.

  # We allocate new sequence here to avoid problems with missing indices when
  # await operation could be part of iteration.
  let sortedPeers =
    pool.sorted.filterIt(
      (PeerFlags.Acquired notin pool.storage[distinctBase(it)].flags) and
      (pool.storage[distinctBase(it)].peerType in filter)).
    mapIt(pool.storage[distinctBase(it)].data)

  for peer in sortedPeers:
    yield peer

iterator availablePeers*[A, B](
    pool: PeerPool[A, B],
    filter: set[PeerType],
    customFilter: PeerCustomFilterCallback[A]
): A =
  ## Iterate over sorted list of available peers.
  ##
  ## All peers will be sorted by equation `>`(Peer1, Peer2), so biggest values
  ## will be first.
  ##
  ## NOTE: While it safe to use this iterator in combination with await calls,
  ## consider that right after `await` call, PeerPool could become different
  ## from the snapshot this iterator provides.

  # We allocate new sequence here to avoid problems with missing indices when
  # await operation could be part of iteration.
  let sortedPeers =
    pool.sorted.filterIt(
      (PeerFlags.Acquired notin pool.storage[distinctBase(it)].flags) and
      (pool.storage[distinctBase(it)].peerType in filter) and
      (isNil(customFilter) or
       customFilter(pool.storage[distinctBase(it)].data))).
    mapIt(pool.storage[distinctBase(it)].data)

  for peer in sortedPeers:
    yield peer

iterator acquiredPeers*[A, B](
    pool: PeerPool[A, B],
    filter = {PeerType.Incoming, PeerType.Outgoing}
): A =
  ## Iterate over sorted list of acquired (non-available) peers.
  ##
  ## All peers will be sorted by equation `>`(Peer1, Peer2), so biggest values
  ## will be first.
  ##
  ## NOTE: While it safe to use this iterator in combination with await calls,
  ## consider that right after `await` call, PeerPool could become different
  ## from the snapshot this iterator provides.
  var unsorted: seq[PeerIndex]
  for pindex in pool.registry.values():
    if (PeerFlags.Acquired in pool.storage[distinctBase(pindex)].flags) and
       (pool.storage[distinctBase(pindex)].peerType in filter):
      unsorted.add(pindex)

  # We allocate new sequence here to avoid problems with missing indices when
  # await operation could be part of iteration.
  let sortedPeers =
    pool.resorted(unsorted).mapIt(pool.storage[distinctBase(it)].data)
  for peer in sortedPeers:
    yield peer

proc `[]`*[A, B](
    pool: PeerPool[A, B],
    key: B
): A {.inline, raises: [KeyError].} =
  ## Retrieve peer with key ``key`` from PeerPool ``pool``.
  pool.storage[distinctBase(pool.registry[key])].data

proc `[]`*[A, B](
    pool: var PeerPool[A, B],
    key: B
): var A {.inline, raises: [KeyError].} =
  ## Retrieve peer with key ``key`` from PeerPool ``pool``.
  pool.storage[distinctBase(pool.registry[key])].data

proc hasPeer*[A, B](pool: PeerPool[A, B], key: B): bool {.inline.} =
  ## Returns ``true`` if peer with ``key`` present in PeerPool ``pool``.
  pool.registry.hasKey(key)

proc getOrDefault*[A, B](pool: PeerPool[A, B], key: B): A {.inline.} =
  ## Retrieves the peer from PeerPool ``pool`` using key ``key``. If peer is
  ## not present, default initialization value for type ``A`` is returned
  ## (e.g. 0 for any integer type).
  let pindex = pool.registry.getOrDefault(key, PeerIndex(-1))
  if pindex != PeerIndex(-1):
    pool.storage[distinctBase(pindex)].data
  else:
    A()

proc getOrDefault*[A, B](pool: PeerPool[A, B], key: B,
                         default: A): A {.inline.} =
  ## Retrieves the peer from PeerPool ``pool`` using key ``key``. If peer is
  ## not present, default value ``default`` is returned.
  let pindex = pool.registry.getOrDefault(key, PeerIndex(-1))
  if pindex != PeerIndex(-1):
    pool.storage[distinctBase(pindex)].data
  else:
    default

proc clear*[A, B](pool: PeerPool[A, B]) =
  ## Performs PeerPool's ``pool`` storage and counters reset.
  pool.registry.clear()

  pool.sorted.reset()
  for i in 0 ..< len(pool.storage):
    pool.storage[i] = PeerItem[A]()
  pool.empties.reset()
  pool.storage.reset()
  pool.curIncPeersCount = 0
  pool.curOutPeersCount = 0
  pool.acqIncPeersCount = 0
  pool.acqOutPeersCount = 0

proc clearSafe*[A, B](
    pool: PeerPool[A, B]
) {.async: (raises: [CancelledError]).} =
  ## Performs "safe" clear. Safe means that it first acquires all the peers
  ## in PeerPool, and only after that it will reset storage.
  var acquired: seq[A]
  while len(pool.registry) > len(acquired):
    var peers = await pool.acquire(len(pool.registry) - len(acquired))
    for item in peers:
      acquired.add(item)
  pool.clear()

proc setScoreCheck*[A, B](pool: PeerPool[A, B],
                          scoreCheckCb: PeerScoreCheckCallback[A]) =
  ## Sets ScoreCheck callback.
  pool.scoreCheck = scoreCheckCb

proc setOnDeletePeer*[A, B](pool: PeerPool[A, B],
                            deletePeerCb: PeerOnDeleteCallback[A]) =
  ## Sets DeletePeer callback.
  pool.onDeletePeer = deletePeerCb

proc setPeerCounter*[A, B](pool: PeerPool[A, B],
                           peerCounterCb: PeerCounterCallback) =
  ## Sets PeerCounter callback.
  pool.peerCounter = peerCounterCb

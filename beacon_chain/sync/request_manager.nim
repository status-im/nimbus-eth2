# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/[sets, sequtils], chronos, chronicles
import ssz_serialization/types
import
  ../spec/[forks, network, peerdas_helpers],
  ../networking/eth2_network,
  ../consensus_object_pools/block_quarantine,
  ../consensus_object_pools/blob_quarantine,
  "."/sync_protocol, "."/sync_manager,
  ../gossip_processing/block_processor

from std/algorithm import binarySearch, sort
from std/strutils import join
from ../beacon_clock import GetBeaconTimeFn
export block_quarantine, sync_manager

logScope:
  topics = "requman"

const
  SYNC_MAX_REQUESTED_BLOCKS = 32 # Spec allows up to MAX_REQUEST_BLOCKS.
    ## Maximum number of blocks which will be requested in each
    ## `beaconBlocksByRoot` invocation.
  PARALLEL_REQUESTS = 2
    ## Number of peers we're using to resolve our request.

  PARALLEL_REQUESTS_DATA_COLUMNS = 32

  BLOB_GOSSIP_WAIT_TIME_NS = 2 * 1_000_000_000
    ## How long to wait for blobs to arri ve over gossip before fetching.

  DATA_COLUMN_GOSSIP_WAIT_TIME_NS = 2 * 1_000_000_000
    ## How long to wait for blobs to arri ve over gossip before fetching.

  POLL_INTERVAL = 1.seconds

type
  BlockVerifierFn = proc(
      signedBlock: ForkedSignedBeaconBlock,
      maybeFinalized: bool
  ): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

  BlockLoaderFn = proc(
      blockRoot: Eth2Digest
  ): Opt[ForkedTrustedSignedBeaconBlock] {.gcsafe, raises: [].}

  BlobLoaderFn = proc(
      blobId: BlobIdentifier): Opt[ref BlobSidecar] {.gcsafe, raises: [].}

  DataColumnLoaderFn = proc(
      columnId: DataColumnIdentifier):
      Opt[ref DataColumnSidecar] {.gcsafe, raises: [].}

  InhibitFn = proc: bool {.gcsafe, raises: [].}

  BlobResponseRecord = object
    block_root: Eth2Digest
    sidecar: ref BlobSidecar

  DataColumnResponseRecord* = object
    block_root*: Eth2Digest
    sidecar*: ref DataColumnSidecar

  RequestManager* = object
    network*: Eth2Node
    supernode*: bool
    custody_columns_set: HashSet[ColumnIndex]
    getBeaconTime: GetBeaconTimeFn
    inhibit: InhibitFn
    quarantine: ref Quarantine
    blobQuarantine: ref BlobQuarantine
    dataColumnQuarantine: ref ColumnQuarantine
    blockVerifier: BlockVerifierFn
    blockLoader: BlockLoaderFn
    blobLoader: BlobLoaderFn
    dataColumnLoader: DataColumnLoaderFn
    blockLoopFuture: Future[void].Raising([CancelledError])
    blobLoopFuture: Future[void].Raising([CancelledError])
    dataColumnLoopFuture: Future[void].Raising([CancelledError])

func shortLog*(x: seq[Eth2Digest]): string =
  "[" & x.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[FetchRecord]): string =
  "[" & x.mapIt(shortLog(it.root)).join(", ") & "]"

proc init*(T: type RequestManager, network: Eth2Node,
              supernode: bool,
              custody_columns_set: HashSet[ColumnIndex],
              denebEpoch: Epoch,
              getBeaconTime: GetBeaconTimeFn,
              inhibit: InhibitFn,
              quarantine: ref Quarantine,
              blobQuarantine: ref BlobQuarantine,
              dataColumnQuarantine: ref ColumnQuarantine,
              blockVerifier: BlockVerifierFn,
              blockLoader: BlockLoaderFn = nil,
              blobLoader: BlobLoaderFn = nil,
              dataColumnLoader: DataColumnLoaderFn = nil): RequestManager =
  RequestManager(
    network: network,
    supernode: supernode,
    custody_columns_set: custody_columns_set,
    getBeaconTime: getBeaconTime,
    inhibit: inhibit,
    quarantine: quarantine,
    blobQuarantine: blobQuarantine,
    dataColumnQuarantine: dataColumnQuarantine,
    blockVerifier: blockVerifier,
    blockLoader: blockLoader,
    blobLoader: blobLoader,
    dataColumnLoader: dataColumnLoader)

func checkResponse(roots: openArray[Eth2Digest],
                   blocks: openArray[ref ForkedSignedBeaconBlock]): bool =
  ## This procedure checks peer's response.
  var checks = @roots
  if len(blocks) > len(roots):
    return false
  for blk in blocks:
    let res = checks.find(blk[].root)
    if res == -1:
      return false
    else:
      checks.del(res)
  true

func cmpSidecarIdentifier(x: BlobIdentifier | DataColumnIdentifier,
                          y: ref BlobSidecar | ref DataColumnSidecar): int =
  cmp(x.index, y[].index)

func cmpColumnIndex(x: ColumnIndex, y: ref DataColumnSidecar): int =
  cmp(x, y[].index)

func checkResponseSanity(
    idents: openArray[BlobIdentifier],
    blobs: openArray[ref BlobSidecar]
): Opt[seq[BlobResponseRecord]] =
  # Cannot respond more than what I have asked
  if len(blobs) > len(idents):
    return Opt.none(seq[BlobResponseRecord])

  var
    checks = idents.toHashSet()
    records: seq[BlobResponseRecord]

  for sidecar in blobs.items():
    let
      block_root = hash_tree_root(sidecar[].signed_block_header.message)
      sidecarIdent =
        BlobIdentifier(block_root: block_root, index: sidecar[].index)

    if checks.missingOrExcl(sidecarIdent):
      return Opt.none(seq[BlobResponseRecord])

    # Verify inclusion proof
    sidecar[].verify_blob_sidecar_inclusion_proof().isOkOr:
      return Opt.none(seq[BlobResponseRecord])

    records.add(BlobResponseRecord(block_root: block_root, sidecar: sidecar))

  Opt.some(records)

func checkColumnResponse*(idList: seq[DataColumnsByRootIdentifier],
                          columns: openArray[ref DataColumnSidecar]):
                          Opt[seq[DataColumnResponseRecord]] =
  var colRec: seq[DataColumnResponseRecord]
  for colresp in columns:
    let block_root =
      hash_tree_root(colresp[].signed_block_header.message)
    for id in idList:
      if id.block_root == block_root:
        if binarySearch(id.indices.asSeq, colresp, cmpColumnIndex) == -1:
          # at the common block root level, the response
          # is NOT a subset of the request ids
          return Opt.none(seq[DataColumnResponseRecord])
        # verify the inclusion proof
        colresp[].verify_data_column_sidecar_inclusion_proof().isOkOr:
          return Opt.none(seq[DataColumnResponseRecord])
        colRec.add(DataColumnResponseRecord(block_root: block_root,
                                            sidecar: colresp))
  Opt.some(colRec)

proc requestBlocksByRoot(rman: RequestManager, items: seq[Eth2Digest]) {.async: (raises: [CancelledError]).} =
  var peer: Peer
  try:
    peer = await rman.network.peerPool.acquire()
    debug "Requesting blocks by root", peer = peer, blocks = shortLog(items),
                                       peer_score = peer.getScore()

    let blocks = (await beaconBlocksByRoot_v2(peer, BlockRootsList items))

    if blocks.isOk:
      let ublocks = blocks.get()
      if checkResponse(items, ublocks.asSeq()):
        var
          gotGoodBlock = false
          gotUnviableBlock = false

        for b in ublocks:
          let ver = await rman.blockVerifier(b[], false)
          if ver.isErr():
            case ver.error()
            of VerifierError.MissingParent:
              # Ignoring because the order of the blocks that
              # we requested may be different from the order in which we need
              # these blocks to apply.
              discard
            of VerifierError.Duplicate:
              # Ignoring because these errors could occur due to the
              # concurrent/parallel requests we made.
              discard
            of VerifierError.UnviableFork:
              # If they're working a different fork, we'll want to descore them
              # but also process the other blocks (in case we can register the
              # other blocks as unviable)
              gotUnviableBlock = true
            of VerifierError.Invalid:
              # We stop processing blocks because peer is either sending us
              # junk or working a different fork
              notice "Received invalid block",
                peer = peer, blocks = shortLog(items),
                peer_score = peer.getScore()
              peer.updateScore(PeerScoreBadValues)

              return # Stop processing this junk...
          else:
            gotGoodBlock = true

        if gotUnviableBlock:
          notice "Received blocks from an unviable fork",
            peer = peer, blocks = shortLog(items),
            peer_score = peer.getScore()
          peer.updateScore(PeerScoreUnviableFork)
        elif gotGoodBlock:
          debug "Request manager got good block",
            peer = peer, blocks = shortLog(items), ublocks = len(ublocks)

          # We reward peer only if it returns something.
          peer.updateScore(PeerScoreGoodValues)

      else:
        debug "Mismatching response to blocks by root",
          peer = peer, blocks = shortLog(items), ublocks = len(ublocks)
        peer.updateScore(PeerScoreBadResponse)
    else:
      debug "Blocks by root request failed",
        peer = peer, blocks = shortLog(items), err = blocks.error()
      peer.updateScore(PeerScoreNoValues)

  finally:
    if not(isNil(peer)):
      rman.network.peerPool.release(peer)

func cmpSidecarIndexes(x, y: ref BlobSidecar | ref DataColumnSidecar): int =
  cmp(x[].index, y[].index)

proc fetchBlobsFromNetwork(self: RequestManager,
                           idList: seq[BlobIdentifier])
                           {.async: (raises: [CancelledError]).} =
  var peer: Peer

  try:
    peer = await self.network.peerPool.acquire()
    debug "Requesting blobs by root", peer = peer, blobs = shortLog(idList),
                                             peer_score = peer.getScore()

    let blobs = await blobSidecarsByRoot(
      peer, BlobIdentifierList idList, maxResponseItems = idList.len)

    if blobs.isOk:
      var ublobs = blobs.get().asSeq()
      let records = checkResponseSanity(idList, ublobs).valueOr:
        debug "Response to blobs by root is incorrect",
              peer = peer, blobs = shortLog(idList), ublobs = len(ublobs)
        peer.updateScore(PeerScoreBadResponse)
        return

      for b in records:
        self.blobQuarantine[].put(b.block_root, b.sidecar)

      var curRoot: Eth2Digest
      for record in records:
        if record.block_root != curRoot:
          curRoot = record.block_root
          if (let o = self.quarantine[].popSidecarless(curRoot); o.isSome):
            let blck = o.unsafeGet()
            discard await self.blockVerifier(blck, false)
            # TODO:
            # If appropriate, return a VerifierError.InvalidBlob from
            # verification, check for it here, and penalize the peer accordingly
    else:
      debug "Blobs by root request failed",
            peer = peer, blobs = shortLog(idList), err = blobs.error()
      peer.updateScore(PeerScoreNoValues)

  finally:
    if not(isNil(peer)):
      self.network.peerPool.release(peer)

proc checkPeerCustody(rman: RequestManager,
                      peer: Peer):
                      bool =
  # Returns true if the peer custodies atleast
  # ONE of the common custody columns, straight
  # away returns true if the peer is a supernode.
  if rman.supernode:
    # For a supernode, it is always best/optimistic
    # to filter other supernodes, rather than filter
    # too many full nodes that have a subset of the custody
    # columns
    if peer.lookupCgcFromPeer() ==
        rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS.uint64:
      return true

  else:
    if peer.lookupCgcFromPeer() ==
        rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS.uint64:
      return true

    elif peer.lookupCgcFromPeer() ==
        CUSTODY_REQUIREMENT.uint64:

      # Fetch the remote custody count
      let remoteCustodyGroupCount =
        peer.lookupCgcFromPeer()

      # Extract remote peer's nodeID from peerID
      # Fetch custody columns from remote peer
      let
        remoteNodeId = fetchNodeIdFromPeerId(peer)
        remoteCustodyColumns =
          rman.network.cfg.resolve_columns_from_custody_groups(
            remoteNodeId,
            max(rman.network.cfg.SAMPLES_PER_SLOT.uint64,
                remoteCustodyGroupCount))

      for local_column in rman.custody_columns_set:
        if local_column notin remoteCustodyColumns:
          return false

      return true

    else:
      return false

proc fetchDataColumnsFromNetwork(rman: RequestManager,
                                 colIdList: seq[DataColumnsByRootIdentifier])
                                 {.async: (raises: [CancelledError]).} =
  var peer = await rman.network.peerPool.acquire()
  try:
    if rman.checkPeerCustody(peer):
      debug "Requesting data columns by root", peer = peer, columns = shortLog(colIdList),
                                                      peer_score = peer.getScore()
      let columns = await dataColumnSidecarsByRoot(peer, DataColumnsByRootIdentifierList colIdList)

      if columns.isOk:
        var ucolumns = columns.get().asSeq()
        ucolumns.sort(cmpSidecarIndexes)
        let records = checkColumnResponse(colIdList, ucolumns).valueOr:
          debug "Response to columns by root is not a subset",
            peer = peer, columns = shortLog(colIdList), ucolumns = len(ucolumns)
          peer.updateScore(PeerScoreBadResponse)
          return

        for col in records:
          rman.dataColumnQuarantine[].put(col.block_root, col.sidecar)

        var curRoot: Eth2Digest
        for col in records:
          if col.block_root != curRoot:
            curRoot = col.block_root
            if (let o = rman.quarantine[].popColumnless(curRoot); o.isSome):
              let col = o.unsafeGet()
              discard await rman.blockVerifier(col, false)
      else:
        debug "Data columns by root request not done, peer doesn't have custody column",
          peer = peer, columns = shortLog(colIdList), err = columns.error()
        peer.updateScore(PeerScoreNoValues)

  finally:
    if not(isNil(peer)):
      rman.network.peerPool.release(peer)

proc requestManagerBlockLoop(
    rman: RequestManager) {.async: (raises: [CancelledError]).} =
  while true:
    # TODO This polling could be replaced with an AsyncEvent that is fired
    #      from the quarantine when there's work to do
    await sleepAsync(POLL_INTERVAL)

    if rman.inhibit():
      continue

    let missingBlockRoots =
      rman.quarantine[].checkMissing(SYNC_MAX_REQUESTED_BLOCKS).mapIt(it.root)
    if missingBlockRoots.len == 0:
      continue

    # TODO This logic can be removed if the database schema is extended
    # to store non-canonical heads on top of the canonical head!
    # If that is done, the database no longer contains extra blocks
    # that have not yet been assigned a `BlockRef`
    var blockRoots: seq[Eth2Digest]
    if rman.blockLoader == nil:
      blockRoots = missingBlockRoots
    else:
      var verifiers:
        seq[Future[Result[void, VerifierError]].Raising([CancelledError])]
      for blockRoot in missingBlockRoots:
        let blck = rman.blockLoader(blockRoot).valueOr:
          blockRoots.add blockRoot
          continue
        debug "Loaded orphaned block from storage", blockRoot
        verifiers.add rman.blockVerifier(
          blck.asSigned(), maybeFinalized = false)
      try:
        await allFutures(verifiers)
      except CancelledError as exc:
        var futs = newSeqOfCap[Future[void].Raising([])](verifiers.len)
        for verifier in verifiers:
          futs.add verifier.cancelAndWait()
        await noCancel allFutures(futs)
        raise exc

    if blockRoots.len == 0:
      continue

    debug "Requesting detected missing blocks", blocks = shortLog(blockRoots)
    let start = SyncMoment.now(0)

    var workers:
      array[PARALLEL_REQUESTS, Future[void].Raising([CancelledError])]

    for i in 0 ..< PARALLEL_REQUESTS:
      workers[i] = rman.requestBlocksByRoot(blockRoots)

    await allFutures(workers)

    let finish = SyncMoment.now(uint64(len(blockRoots)))

    debug "Request manager block tick", blocks = shortLog(blockRoots),
                                        sync_speed = speed(start, finish)

proc getMissingBlobs(rman: RequestManager): seq[BlobIdentifier] =
  let
    wallTime = rman.getBeaconTime()
    wallSlot = wallTime.slotOrZero()
    delay = wallTime - wallSlot.start_beacon_time()
    waitDur = TimeDiff(nanoseconds: BLOB_GOSSIP_WAIT_TIME_NS)

  var
    idents: seq[BlobIdentifier]
    ready: seq[Eth2Digest]
  for blobless in rman.quarantine[].peekSidecarless():
    withBlck(blobless):
      when consensusFork >= ConsensusFork.Gloas:
        debugGloasComment ""
      elif consensusFork >= ConsensusFork.Deneb:
        # give blobs a chance to arrive over gossip
        if forkyBlck.message.slot == wallSlot and delay < waitDur:
          debug "Not handling missing blobs early in slot"
          continue

        let
          commitmentsCount = len(forkyBlck.message.body.blob_kzg_commitments)
          missing =
            rman.blobQuarantine[].fetchMissingSidecars(blobless.root, forkyBlck)

        if len(missing) > 0:
          for ident in missing:
            idents.add(ident)
        else:
          if commitmentsCount == 0:
            # this is a programming error should it occur.
            warn "missing blob handler found blobless block with all blobs",
                 blk = blobless.root,
                 commitments = len(forkyBlck.message.body.blob_kzg_commitments)
            ready.add(blobless.root)
          else:
            # This should not happen either...
            warn "quarantine missing blobs, but missing indices is empty",
                 blk = blobless.root,
                 commitments = len(forkyBlck.message.body.blob_kzg_commitments)

  for root in ready:
    let blobless = rman.quarantine[].popSidecarless(root).valueOr:
      continue
    discard rman.blockVerifier(blobless, false)
  idents

proc requestManagerBlobLoop(
    rman: RequestManager) {.async: (raises: [CancelledError]).} =
  while true:
    # TODO This polling could be replaced with an AsyncEvent that is fired
    #      from the quarantine when there's work to do
    await sleepAsync(POLL_INTERVAL)
    if rman.inhibit():
      continue

    let missingBlobIds = rman.getMissingBlobs()
    if missingBlobIds.len == 0:
      continue

    # TODO This logic can be removed if the database schema is extended
    # to store non-canonical heads on top of the canonical head!
    # If that is done, the database no longer contains extra blocks
    # that have not yet been assigned a `BlockRef`
    var blobIds: seq[BlobIdentifier]
    if rman.blobLoader == nil:
      blobIds = missingBlobIds
    else:
      var
        blockRoots: seq[Eth2Digest]
        curRoot: Eth2Digest
      for blobId in missingBlobIds:
        if blobId.block_root != curRoot:
          curRoot = blobId.block_root
          blockRoots.add curRoot
        let blob_sidecar = rman.blobLoader(blobId).valueOr:
          blobIds.add blobId
          if blockRoots.len > 0 and blockRoots[^1] == curRoot:
            # A blob is missing, remove from list of fully available blocks
            discard blockRoots.pop()
          continue
        debug "Loaded orphaned blob from storage", blobId
        rman.blobQuarantine[].put(curRoot, blob_sidecar)
      var verifiers = newSeqOfCap[
        Future[Result[void, VerifierError]]
          .Raising([CancelledError])](blockRoots.len)
      for blockRoot in blockRoots:
        let blck = rman.quarantine[].popSidecarless(blockRoot).valueOr:
          continue
        verifiers.add rman.blockVerifier(blck, maybeFinalized = false)
      try:
        await allFutures(verifiers)
      except CancelledError as exc:
        var futs = newSeqOfCap[Future[void].Raising([])](verifiers.len)
        for verifier in verifiers:
          futs.add verifier.cancelAndWait()
        await noCancel allFutures(futs)
        raise exc

    if blobIds.len > 0:
      debug "Requesting detected missing blobs", blobs = shortLog(blobIds)
      let start = SyncMoment.now(0)
      var workers:
        array[PARALLEL_REQUESTS, Future[void].Raising([CancelledError])]
      for i in 0 ..< PARALLEL_REQUESTS:
        workers[i] = rman.fetchBlobsFromNetwork(blobIds)

      await allFutures(workers)
      let finish = SyncMoment.now(uint64(len(blobIds)))

      debug "Request manager blob tick",
            blobs_count = len(blobIds),
            sync_speed = speed(start, finish)

proc getMissingDataColumns(rman: RequestManager): seq[DataColumnsByRootIdentifier] =
  let
    wallTime = rman.getBeaconTime()
    wallSlot = wallTime.slotOrZero()
    delay = wallTime - wallSlot.start_beacon_time()

  const waitDur = TimeDiff(nanoseconds: DATA_COLUMN_GOSSIP_WAIT_TIME_NS)

  var
    fetches: seq[DataColumnsByRootIdentifier]
    ready: seq[Eth2Digest]

  for columnless in rman.quarantine[].peekSidecarless():
    withBlck(columnless):
      debugGloasComment ""
      when consensusFork >= ConsensusFork.Fulu and consensusFork != ConsensusFork.Gloas:
        # granting data columns a chance to arrive over gossip
        if forkyBlck.message.slot == wallSlot and delay < waitDur:
          debug "Not handling missing data columns early in slot"
          continue

        let
          commitmentsCount = len(forkyBlck.message.body.blob_kzg_commitments)
          ident = rman.dataColumnQuarantine[].fetchMissingSidecars(
            columnless.root, forkyBlck)

        if len(ident.indices) > 0:
          fetches.add(ident)
        else:
          if commitmentsCount == 0:
            # this is a programming error should it occur.
            warn "missing column handler found columnless block with all data columns",
                 blk = columnless.root,
                 commitments = len(forkyBlck.message.body.blob_kzg_commitments)
            ready.add(columnless.root)
          else:
            # This should not happen either...
            warn "quarantine missing data columns, but missing indices is empty",
                 blk = columnless.root,
                 commitments = len(forkyBlck.message.body.blob_kzg_commitments)

  for root in ready:
    let columnless = rman.quarantine[].popSidecarless(root).valueOr:
      continue
    discard rman.blockVerifier(columnless, false)
  fetches

proc requestManagerDataColumnLoop(
    rman: RequestManager) {.async: (raises: [CancelledError]).} =
  while true:

    await sleepAsync(POLL_INTERVAL)
    if rman.inhibit():
      continue

    let missingColumnIds = rman.getMissingDataColumns()
    if missingColumnIds.len == 0:
      continue

    var columnIds: seq[DataColumnsByRootIdentifier]
    if rman.dataColumnLoader == nil:
      columnIds = missingColumnIds
    else:
      var
        blockRoots: seq[Eth2Digest]
        curRoot: Eth2Digest
      for columnId in missingColumnIds:
        if columnId.block_root != curRoot:
          curRoot = columnId.block_root
          blockRoots.add curRoot
        for index in columnId.indices:
          let loaderElem = DataColumnIdentifier(
            block_root: columnId.block_root,
            index: index)
          let data_column_sidecar = rman.dataColumnLoader(loaderElem).valueOr:
            columnIds.add columnId
            if blockRoots.len > 0 and blockRoots[^1] == curRoot:
              # A data column is missing, remove from list of fully available data columns
              discard blockRoots.pop()
            continue
          debug "Loaded orphaned data columns from storage", columnId
          rman.dataColumnQuarantine[].put(curRoot, data_column_sidecar)
      var verifiers = newSeqOfCap[
        Future[Result[void, VerifierError]]
          .Raising([CancelledError])](blockRoots.len)
      for blockRoot in blockRoots:
        let blck = rman.quarantine[].popSidecarless(blockRoot).valueOr:
          continue
        verifiers.add rman.blockVerifier(blck, maybeFinalized = false)
      try:
        await allFutures(verifiers)
      except CancelledError as exc:
        var futs = newSeqOfCap[Future[void].Raising([])](verifiers.len)
        for verifier in verifiers:
          futs.add verifier.cancelAndWait()
        await noCancel allFutures(futs)
        raise exc
    if columnIds.len > 0:
      debug "Requesting detected missing data columns", columns = shortLog(columnIds)
      let start = SyncMoment.now(0)
      let workerCount =
        if rman.custody_columns_set.lenu64 >
            rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS.uint64:
          PARALLEL_REQUESTS
        else:
          PARALLEL_REQUESTS_DATA_COLUMNS
      var workers =
        newSeq[Future[void].Raising([CancelledError])](workerCount)
      for i in 0..<workerCount:
        workers[i] = rman.fetchDataColumnsFromNetwork(columnIds)

      await allFutures(workers)
      let finish = SyncMoment.now(uint64(len(columnIds)))

      debug "Request manager data column tick",
            data_columns_count = len(columnIds),
            sync_speed = speed(start, finish)

proc start*(rman: var RequestManager) =
  ## Start Request Manager's loops.
  rman.blockLoopFuture = rman.requestManagerBlockLoop()
  rman.blobLoopFuture = rman.requestManagerBlobLoop()
  rman.dataColumnLoopFuture = rman.requestManagerDataColumnLoop()

proc stop*(rman: RequestManager) =
  ## Stop Request Manager's loop.
  if not(isNil(rman.blockLoopFuture)):
    rman.blockLoopFuture.cancelSoon()
  if not(isNil(rman.blobLoopFuture)):
    rman.blobLoopFuture.cancelSoon()
  if not(isNil(rman.dataColumnLoopFuture)):
    rman.dataColumnLoopFuture.cancelSoon()

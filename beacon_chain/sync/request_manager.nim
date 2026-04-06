# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
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
  ../consensus_object_pools/[
    blob_quarantine, block_quarantine, envelope_quarantine],
  "."/sync_protocol, "."/sync_manager,
  ../gossip_processing/block_processor

from std/algorithm import binarySearch, sort
from std/strutils import join
from ../beacon_clock import GetBeaconTimeFn
from stew/assign2 import assign
export block_quarantine, sync_manager

logScope:
  topics = "requman"

const
  SYNC_MAX_REQUESTED_BLOCKS = 32 # Spec allows up to MAX_REQUEST_BLOCKS.
    ## Maximum number of blocks which will be requested in each
    ## `beaconBlocksByRoot` invocation.
  PARALLEL_REQUESTS = 2
    ## Number of peers we're using to resolve our request.

  PARALLEL_DATA_COLUMNS = 8

  PARALLEL_DATA_COLUMNS_SUPER = 10

  BLOB_GOSSIP_WAIT_TIME_NS = 2 * 1_000_000_000
    ## How long to wait for blobs to arri ve over gossip before fetching.

  DATA_COLUMN_GOSSIP_WAIT_TIME_NS = 2 * 1_000_000_000
    ## How long to wait for data columns to arrive over gossip before fetching.

  POLL_INTERVAL = 1.seconds

  POLL_INTERVAL_COLUMNS = 500.milliseconds

type
  BlockVerifierFn = proc(
      signedBlock: ForkedSignedBeaconBlock,
      maybeFinalized: bool
  ): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

  EnvelopeVerifierFn = proc(
      signedEnvelope: gloas.SignedExecutionPayloadEnvelope,
  ): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).}

  BlockLoaderFn = proc(
      blockRoot: Eth2Digest
  ): Opt[ForkedTrustedSignedBeaconBlock] {.gcsafe, raises: [].}

  EnvelopeLoaderFn = proc(
      blockRoot: Eth2Digest,
  ): Opt[gloas.TrustedSignedExecutionPayloadEnvelope] {.gcsafe, raises: [].}

  BlobLoaderFn = proc(
      blobId: BlobIdentifier): Opt[ref BlobSidecar] {.gcsafe, raises: [].}

  DataColumnLoaderFn = proc(
      columnId: DataColumnIdentifier):
      Opt[ref fulu.DataColumnSidecar] {.gcsafe, raises: [].}

  InhibitFn = proc: bool {.gcsafe, raises: [].}

  BlobResponseRecord = object
    block_root: Eth2Digest
    sidecar: ref BlobSidecar

  DataColumnResponseRecord* = object
    block_root*: Eth2Digest
    sidecar*: ref fulu.DataColumnSidecar

  RequestManager* = object
    network*: Eth2Node
    supernode*: bool
    custody_columns_set*: HashSet[ColumnIndex]
    getBeaconTime: GetBeaconTimeFn
    inhibit: InhibitFn
    quarantine: ref Quarantine
    envelopeQuarantine: ref EnvelopeQuarantine
    blobQuarantine: ref BlobQuarantine
    dataColumnQuarantine: ref ColumnQuarantine
    blockVerifier: BlockVerifierFn
    blockLoader: BlockLoaderFn
    envelopeVerifier: EnvelopeVerifierFn
    envelopeLoader: EnvelopeLoaderFn
    blobLoader: BlobLoaderFn
    dataColumnLoader: DataColumnLoaderFn
    blockLoopFuture: Future[void].Raising([CancelledError])
    envelopeLoopFuture: Future[void].Raising([CancelledError])
    blobLoopFuture: Future[void].Raising([CancelledError])
    dataColumnLoopFuture: Future[void].Raising([CancelledError])

func shortLog*(x: seq[Eth2Digest]): string =
  "[" & x.mapIt(shortLog(it)).join(", ") & "]"

func shortLog*(x: seq[FetchRecord]): string =
  "[" & x.mapIt(shortLog(it.root)).join(", ") & "]"

func init*(T: type RequestManager, network: Eth2Node,
              supernode: bool,
              custody_columns_set: HashSet[ColumnIndex],
              denebEpoch: Epoch,
              getBeaconTime: GetBeaconTimeFn,
              inhibit: InhibitFn,
              quarantine: ref Quarantine,
              envelopeQuarantine: ref EnvelopeQuarantine,
              blobQuarantine: ref BlobQuarantine,
              dataColumnQuarantine: ref ColumnQuarantine,
              blockVerifier: BlockVerifierFn,
              blockLoader: BlockLoaderFn = nil,
              envelopeVerifier: EnvelopeVerifierFn,
              envelopeLoader: EnvelopeLoaderFn,
              blobLoader: BlobLoaderFn = nil,
              dataColumnLoader: DataColumnLoaderFn = nil): RequestManager =
  RequestManager(
    network: network,
    supernode: supernode,
    custody_columns_set: custody_columns_set,
    getBeaconTime: getBeaconTime,
    inhibit: inhibit,
    quarantine: quarantine,
    envelopeQuarantine: envelopeQuarantine,
    blobQuarantine: blobQuarantine,
    dataColumnQuarantine: dataColumnQuarantine,
    blockVerifier: blockVerifier,
    blockLoader: blockLoader,
    envelopeVerifier: envelopeVerifier,
    envelopeLoader: envelopeLoader,
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

func checkResponse(
    roots: openArray[Eth2Digest],
    envelopes: openArray[ref SignedExecutionPayloadEnvelope],
): bool =
  ## Ensure the response contains only the requested envelopes.
  envelopes.allIt(it[].message.beacon_block_root in roots)

func cmpColumnIndex(x: ColumnIndex, y: ref fulu.DataColumnSidecar): int =
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
                          columns: openArray[ref fulu.DataColumnSidecar]):
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

proc fetchEnvelopesFromNetwork(self: RequestManager, roots: seq[Eth2Digest])
    {.async: (raises: [CancelledError]).} =
  let peer = await self.network.peerPool.acquire()
  debug "Requesting envelopes by root",
    peer = peer, envelopes = shortLog(roots),
    peer_score = peer.getScore()

  try:
    let envelopes = await executionPayloadEnvelopesByRoot(
      peer, BlockRootsList roots)

    if envelopes.isOk:
      let uenvelopes = envelopes.get().asSeq()
      if checkResponse(roots, uenvelopes):
        var
          gotGoodEnvelope = false
          gotUnviableEnvelope = false

        for envelope in uenvelopes:
          self.envelopeQuarantine[].addOrphan(envelope[])
          let res = await self.envelopeVerifier(envelope[])
          if res.isErr():
            case res.error():
            of VerifierError.MissingParent:
              # Ignoring due to it should have checked in processing the valid
              # block.
              discard
            of VerifierError.Duplicate:
              # Ignoring as it could occur when making parallel requests.
              discard
            of VerifierError.UnviableFork:
              gotUnviableEnvelope = true
            of VerifierError.Invalid:
              notice "Received invalid envelope",
                peer = peer, envelopes = shortLog(roots)
              peer.updateScore(PeerScoreBadValues)
              return
          else:
            gotGoodEnvelope = true

        if gotUnviableEnvelope:
          notice "Received envelope from an unviable fork",
            peer = peer, envelopes = shortLog(roots)
          peer.updateScore(PeerScoreUnviableFork)
        if gotGoodEnvelope:
          debug "Request manager got good envelope",
            peer = peer, envelopes = shortLog(roots), uenvelopes = len(uenvelopes)
          peer.updateScore(PeerScoreGoodValues)

      else:
        debug "Mismatching response to envelopes by root",
          peer = peer, envelopes = shortLog(roots), uenvelopes = len(uenvelopes)
        peer.updateScore(PeerScoreBadResponse)
    else:
      debug "Envelopes by root request failed",
        peer = peer, envelopes = shortLog(roots), err = envelopes.error()
      peer.updateScore(PeerScoreNoValues)

  finally:
    if not(isNil(peer)):
      self.network.peerPool.release(peer)

func cmpSidecarIndexes(x, y: ref BlobSidecar | ref fulu.DataColumnSidecar): int =
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
                      peer: Peer): DataColumnIndices =
  ## Returns the intersection of custody columns
  ## with the peer. Also applies peer scoring.
  var intersection: DataColumnIndices
  let remoteCustodyGroupCount = peer.lookupCgcFromPeer().valueOr:
    debug "Failed to lookup cgc from peer",
      peer = peer, status = error
    peer.updateScore(PeerScoreNoValues)
    return intersection

  if rman.supernode:
    if remoteCustodyGroupCount == rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS:
      for col in 0 ..< rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS:
        discard intersection.add(ColumnIndex col)
      peer.updateScore(PeerScoreSupernode)
      debug "Peer is supernode",
        peer = peer, score = peer.getScore(),
        remote_custody = remoteCustodyGroupCount
      return intersection
  else:
    if remoteCustodyGroupCount == rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS:
      for col in 0 ..< rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS:
        discard intersection.add(ColumnIndex col)
      peer.updateScore(PeerScoreSupernode)
      debug "Peer is supernode",
        peer = peer, score = peer.getScore(),
        remote_custody = remoteCustodyGroupCount
      return intersection
    else:
      let
        remoteNodeId = fetchNodeIdFromPeerId(peer).valueOr:
          peer.updateScore(PeerScoreNoValues)
          return intersection
        remoteCustodyColumns =
          rman.network.cfg.resolve_columns_from_custody_groups(
            remoteNodeId,
            max(rman.network.cfg.SAMPLES_PER_SLOT,
                remoteCustodyGroupCount))

      for local_column in rman.custody_columns_set:
        if local_column in remoteCustodyColumns:
          discard intersection.add(local_column)
      # Apply scoring logic + logs
      if intersection.len == 0:
        peer.updateScore(PeerScoreBadColumnIntersection)
        debug "Peer has no custody overlap",
          peer = peer, score = peer.getScore(),
          remote_custody = remoteCustodyGroupCount
      elif intersection.len < (rman.custody_columns_set.len div 2):
        peer.updateScore(PeerScoreScantyColumnIntersection)
        debug "Peer has scanty custody overlap",
          peer = peer, score = peer.getScore(),
          remote_custody = remoteCustodyGroupCount,
          overlap = intersection.len, local = rman.custody_columns_set.len
      else:
        peer.updateScore(PeerScoreDecentColumnIntersection)
        debug "Peer has decent custody overlap",
          peer = peer, score = peer.getScore(),
          remote_custody = remoteCustodyGroupCount,
          overlap = intersection.len, local = rman.custody_columns_set.len

  intersection

func matchIntersection(rman: RequestManager): PeerCustomFilterCallback[Peer] =
  return proc(peer: Peer): bool =
    let
      remoteCustodyGroupCount = peer.lookupCgcFromPeer().valueOr:
        return false
      remoteNodeId = fetchNodeIdFromPeerId(peer).valueOr:
        return false
      remoteCustodyColumns =
        rman.network.cfg.resolve_columns_from_custody_groups(
          remoteNodeId,
          max(rman.network.cfg.SAMPLES_PER_SLOT, remoteCustodyGroupCount))
      overlap = rman.custody_columns_set.countIt(it in remoteCustodyColumns)
    overlap > (rman.custody_columns_set.len div 2)

proc fetchDataColumnsFromNetwork(rman: RequestManager,
                                 colIdList: seq[DataColumnsByRootIdentifier])
                                 {.async: (raises: [CancelledError]).} =
  var peer: Peer
  peer = await rman.network.peerPool.acquire(
    filter = {Incoming, Outgoing},
    customFilter = matchIntersection(rman))
  try:
    let intersection = rman.checkPeerCustody(peer)

    debug "Acquired peer after custody check",
      peer = peer,
      peer_score = peer.getScore(),
      overlap = intersection.len,
      local = rman.custody_columns_set.len
    if intersection.len == 0:
      debug "Peer has no usable custody overlap",
        peer = peer
      return
    let intColIdList = colIdList
      .mapIt(DataColumnsByRootIdentifier(
        block_root: it.block_root,
        indices: DataColumnIndices(
          filterIt(it.indices.asSeq, it in intersection))))
      .filterIt(it.indices.len > 0)
    if intColIdList.len == 0:
      debug "No intersecting custody columns to request",
        peer = peer,
        peer_score = peer.getScore()
      return
    debug "Requesting data columns by root",
      peer = peer,
      columns = shortLog(intColIdList),
      peer_score = peer.getScore()
    let columns = await dataColumnSidecarsByRoot(peer, DataColumnsByRootIdentifierList intColIdList)
    if columns.isOk:
      var ucolumns = columns.get().asSeq()
      ucolumns.sort(cmpSidecarIndexes)
      let records = checkColumnResponse(colIdList, ucolumns).valueOr:
        debug "Response to columns by root is not a subset",
          peer = peer,
          columns = shortLog(colIdList),
          ucolumns = len(ucolumns)
        peer.updateScore(PeerScoreBadResponse)
        return
      for col in records:
        debug "Received column responses",
          peer = peer,
          column_sidecars = shortLog(col.sidecar[]),
          peer_score = peer.getScore()
        rman.dataColumnQuarantine[].put(col.block_root, col.sidecar)
      var curRoot: Eth2Digest
      for col in records:
        if col.block_root != curRoot:
          curRoot = col.block_root
          if (let o = rman.quarantine[].popSidecarless(curRoot); o.isSome):
            let col = o.unsafeGet()
            discard await rman.blockVerifier(col, false)
    else:
      debug "Data columns by root request failed or peer missing custody columns",
        peer = peer,
        err = columns.error()
      peer.updateScore(PeerScoreNoValues)

  finally:
    if not isNil(peer):
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

proc requestManagerEnvelopeLoop(self: RequestManager)
    {.async: (raises: [CancelledError]).} =
  while true:
    # TODO This polling could be replaced with an AsyncEvent that is fired
    #      from the quarantine when there's work to do
    await sleepAsync(POLL_INTERVAL)

    if self.inhibit():
      continue

    let missingBlockRoots = self.envelopeQuarantine[].getMissing()
    if missingBlockRoots.len() == 0:
      continue

    var blockRoots: seq[Eth2Digest]
    if self.envelopeLoader == nil:
      assign(blockRoots, missingBlockRoots)
    else:
      var verifiers:
        seq[Future[Result[void, VerifierError]].Raising([CancelledError])]
      for blockRoot in missingBlockRoots:
        let envelope = self.envelopeLoader(blockRoot).valueOr:
          blockRoots.add blockRoot
          continue
        debug "Loaded orphaned envelope from storage", blockRoot
        verifiers.add self.envelopeVerifier(envelope.asSigned())
      try:
        await allFutures(verifiers)
      except CancelledError as exc:
        let futs = verifiers.mapIt(it.cancelAndWait())
        await noCancel allFutures(futs)
        raise exc

    if blockRoots.len() == 0:
      continue

    debug "Requesting detected missing envelopes", envelopes = shortLog(blockRoots)
    let start = SyncMoment.now(0)

    var workers:
      array[PARALLEL_REQUESTS, Future[void].Raising([CancelledError])]

    for i in 0 ..< PARALLEL_REQUESTS:
      workers[i] = self.fetchEnvelopesFromNetwork(blockRoots)

    await allFutures(workers)

    let finish = SyncMoment.now(lenu64(blockRoots))

    debug "Request manager envelope tick",
      envelopes = shortLog(blockRoots),
      sync_speed = speed(start, finish)

proc getMissingBlobs(rman: RequestManager): seq[BlobIdentifier] =
  let
    wallTime = rman.getBeaconTime()
    wallSlot = wallTime.slotOrZero(rman.network.cfg.timeParams)
    delay = wallTime - wallSlot.start_beacon_time(rman.network.cfg.timeParams)
    waitDur = TimeDiff(nanoseconds: BLOB_GOSSIP_WAIT_TIME_NS)

  var
    idents: seq[BlobIdentifier]
    ready: seq[Eth2Digest]
  for blobless in rman.quarantine[].peekSidecarless():
    withBlck(blobless):
      when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
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
    wallSlot = wallTime.slotOrZero(rman.network.cfg.timeParams)
    delay = wallTime - wallSlot.start_beacon_time(rman.network.cfg.timeParams)

  const waitDur = TimeDiff(nanoseconds: DATA_COLUMN_GOSSIP_WAIT_TIME_NS)

  var
    fetches: seq[DataColumnsByRootIdentifier]
    ready: seq[Eth2Digest]

  for columnless in rman.quarantine[].peekSidecarless():
    withBlck(columnless):
      when consensusFork >= ConsensusFork.Fulu and consensusFork < ConsensusFork.Gloas:
        debugGloasComment "handle correctly for gloas"
        # granting data columns a chance to arrive over gossip
        if forkyBlck.message.slot == wallSlot and delay < waitDur:
          debug "Not handling missing data columns early in slot"
          continue

        let
          commitmentsCount = len(forkyBlck.message.body.blob_kzg_commitments)
          ident = rman.dataColumnQuarantine[].fetchMissingSidecars(
            columnless.root)

        if len(ident.indices) > 0 and ident notin fetches:
          fetches.add(ident)
        else:
          if commitmentsCount == 0:
            # this is a programming error it should not occur.
            warn "missing column handler found columnless block with all data columns",
                 blk = columnless.root,
                 commitments = len(forkyBlck.message.body.blob_kzg_commitments)
            ready.add(columnless.root)
          else:
            debug "requested column indices are no longer relevant",
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

    await sleepAsync(POLL_INTERVAL_COLUMNS)
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
          if curRoot notin blockRoots:
            blockRoots.add curRoot
        for index in columnId.indices:
          let loaderElem = DataColumnIdentifier(
            block_root: columnId.block_root,
            index: index)
          let data_column_sidecar = rman.dataColumnLoader(loaderElem).valueOr:
            if columnId notin columnIds:
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
        if rman.custody_columns_set.lenu64 >=
            rman.network.cfg.NUMBER_OF_CUSTODY_GROUPS:
          PARALLEL_DATA_COLUMNS_SUPER
        else:
          PARALLEL_DATA_COLUMNS
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

proc upgradeLoops*(rman: var RequestManager) =
  let currentEpoch =
    rman.getBeaconTime().slotOrZero(rman.network.cfg.timeParams).epoch()

  if currentEpoch >= rman.network.cfg.FULU_FORK_EPOCH and
     isNil(rman.dataColumnLoopFuture):
    if not(isNil(rman.blobLoopFuture)):
      rman.blobLoopFuture.cancelSoon()

    rman.dataColumnLoopFuture =
      rman.requestManagerDataColumnLoop()

  if currentEpoch >= rman.network.cfg.GLOAS_FORK_EPOCH and
     isNil(rman.envelopeLoopFuture):
    rman.envelopeLoopFuture = rman.requestManagerEnvelopeLoop()

proc stop*(rman: RequestManager) =
  ## Stop Request Manager's loop.
  if not(isNil(rman.blockLoopFuture)):
    rman.blockLoopFuture.cancelSoon()
  if not(isNil(rman.envelopeLoopFuture)):
    rman.envelopeLoopFuture.cancelSoon()
  if not(isNil(rman.blobLoopFuture)):
    rman.blobLoopFuture.cancelSoon()
  if not(isNil(rman.dataColumnLoopFuture)):
    rman.dataColumnLoopFuture.cancelSoon()

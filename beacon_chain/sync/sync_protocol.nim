# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, chronos, snappy, snappy/codec,
  ../spec/[eth2_ssz_serialization, helpers, forks, network],
  ../beacon_clock,
  ../networking/eth2_network,
  ../consensus_object_pools/[
    blockchain_dag, inclusion_list_pool, spec_cache],
  ../rpc/rest_constants

logScope:
  topics = "sync_proto"

const
  blockResponseCost = allowedOpsPerSecondCost(64)
    ## Allow syncing ~64 blocks/sec (minus request costs)
  envelopeResponseCost = allowedOpsPerSecondCost(64)
    ## Part of beacon block so keep it aligned with block's
  dataColumnResponseCost = allowedOpsPerSecondCost(8000)
    ## 8 data columns take the same memory as 1 blob approximately
  inclusionListResponseCost = allowedOpsPerSecondCost(1000)
    ## ~8 KiB each, so cheaper than blobs; keep them on the same budget anyway

type
  BeaconSyncNetworkState* {.final.} = ref object of RootObj
    dag: ChainDAGRef
    cfg: RuntimeConfig
    genesisBlockRoot: Eth2Digest
    inclusionListPool: ref InclusionListPool
      ## Inclusion lists are only live for a couple of slots, so they are served
      ## from the in-memory pool rather than the database.
    getBeaconTime: GetBeaconTimeFn
      ## `minimum_request_slot` is relative to the wall slot, which may run
      ## ahead of `dag.head.slot`.

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

  BlockRootsList* = List[Eth2Digest, Limit MAX_REQUEST_BLOCKS_DENEB]
  BlobIdentifierList* = List[
    BlobIdentifier, Limit MAX_SUPPORTED_REQUEST_BLOB_SIDECARS]
  DataColumnIdentifierList* = List[
    DataColumnIdentifier, Limit (MAX_REQUEST_DATA_COLUMN_SIDECARS)]
  DataColumnsByRootIdentifierList* = List[
    DataColumnsByRootIdentifier, Limit (MAX_REQUEST_BLOCKS_DENEB)]

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref ForkedSignedBeaconBlock)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withConsensusFork(contextFork):
    let res = await readChunkPayload(
      conn, peer, consensusFork.SignedBeaconBlock)
    if res.isOk:
      let contextEpoch = res.get.message.slot.epoch
      if peer.network.cfg.consensusForkAtEpoch(contextEpoch) != consensusFork:
        return neterr InvalidContextBytes
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)

proc readChunkPayload*(
    conn: Connection, peer: Peer,
    MsgType: type (ref gloas.SignedExecutionPayloadEnvelope)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withConsensusFork(contextFork):
    when consensusFork >= ConsensusFork.Gloas:
      let res = await readChunkPayload(
        conn, peer, gloas.SignedExecutionPayloadEnvelope)
      if res.isOk:
        let contextEpoch = res.get.message.slot.epoch
        if peer.network.cfg.consensusForkAtEpoch(contextEpoch) != consensusFork:
          return neterr InvalidContextBytes
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref BlobSidecar)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withConsensusFork(contextFork):
    when consensusFork >= ConsensusFork.Deneb:
      let res = await readChunkPayload(conn, peer, BlobSidecar)
      if res.isOk:
        let contextEpoch = res.get.signed_block_header.message.slot.epoch
        if peer.network.cfg.consensusForkAtEpoch(contextEpoch) != consensusFork:
          return neterr InvalidContextBytes
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref fulu.DataColumnSidecar)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withConsensusFork(contextFork):
    when consensusFork == ConsensusFork.Fulu:
      let res = await readChunkPayload(conn, peer, fulu.DataColumnSidecar)
      if res.isOk:
        let contextEpoch = res.get.signed_block_header.message.slot.epoch
        if peer.network.cfg.consensusForkAtEpoch(contextEpoch) != consensusFork:
          return neterr InvalidContextBytes
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer,
    MsgType: type (ref gloas.DataColumnSidecar)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withConsensusFork(contextFork):
    when consensusFork >= ConsensusFork.Gloas:
      let res = await readChunkPayload(conn, peer, gloas.DataColumnSidecar)
      if res.isOk:
        let contextEpoch = res.get.slot.epoch
        if peer.network.cfg.consensusForkAtEpoch(contextEpoch) != consensusFork:
          return neterr InvalidContextBytes
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer,
    MsgType: type (ref heze.SignedInclusionList)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withConsensusFork(contextFork):
    # `HEZE_FORK_VERSION` is the only entry in the chunk type table.
    when consensusFork >= ConsensusFork.Heze:
      let res = await readChunkPayload(conn, peer, heze.SignedInclusionList)
      if res.isOk:
        let contextEpoch = res.get.message.slot.epoch
        if peer.network.cfg.consensusForkAtEpoch(contextEpoch) != consensusFork:
          return neterr InvalidContextBytes
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

{.pop.} # TODO fix p2p macro for raises

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState):
  proc beaconBlocksByRange_v2(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS_DENEB])
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} =
    # TODO Semantically, this request should return a non-ref, but doing so
    #      runs into extreme inefficiency due to the compiler introducing
    #      hidden copies - in future nim versions with move support, this should
    #      be revisited
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref ForkedSignedBeaconBlock]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    trace "got range request", peer, startSlot, count = reqCount
    # https://github.com/ethereum/consensus-specs/pull/2856
    if reqStep != 1:
      raise newException(InvalidInputsError, "Step size must be 1")
    if reqCount == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    var blocks: array[MAX_REQUEST_BLOCKS_DENEB.int, BlockId]
    let dag = peer.networkState.dag
    if startSlot < dag.backfill.slot:
      # Peers that are unable to reply to block requests within the
      # `MIN_EPOCHS_FOR_BLOCK_REQUESTS` epoch range SHOULD respond with
      # error code `3: ResourceUnavailable`.
      # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/p2p-interface.md#responding-side
      raise newException(ResourceUnavailableError, BlocksUnavailable)

    let
      # Limit number of blocks in response
      count = int min(reqCount, blocks.lenu64)
      endIndex = count - 1
      startIndex = dag.getBlockRange(
        startSlot, blocks.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]

    for i in startIndex..endIndex:
      if dag.getBlockSZ(blocks[i], bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read block size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blocks[i])
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(blockResponseCost, "beacon_blocks_by_range/2")
        peer.network.awaitQuota(blockResponseCost, "beacon_blocks_by_range/2")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blocks[i].slot.epoch).data)

        inc found

    if found == 0 and startSlot < dag.horizon:
      # Distinguish empty response (we know that the slot is empty)
      # from unavailable response (we have not backfilled / range got pruned).
      # For slots before the horizon, data is available on a best-effort basis
      raise newException(ResourceUnavailableError, BlocksUnavailable)

    debug "Block range request done", peer, startSlot, count

  proc beaconBlocksByRoot_v2(
      peer: Peer,
      # Please note that the SSZ list here ensures that the
      # spec constant MAX_REQUEST_BLOCKS_DENEB is enforced:
      blockRoots: BlockRootsList,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS_DENEB])
      {.async, libp2pProtocol("beacon_blocks_by_root", 2).} =
    # TODO Semantically, this request should return a non-ref, but doing so
    #      runs into extreme inefficiency due to the compiler introducing
    #      hidden copies - in future nim versions with move support, this should
    #      be revisited
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref ForkedSignedBeaconBlock]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    if blockRoots.len == 0:
      raise newException(InvalidInputsError, "No blocks requested")

    let
      dag = peer.networkState.dag
      count = blockRoots.len

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      let
        blockRef = dag.getBlockRef(blockRoots[i]).valueOr:
          continue

      if dag.getBlockSZ(blockRef.bid, bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read block size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blockRef)
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(blockResponseCost, "beacon_blocks_by_root/2")
        peer.network.awaitQuota(blockResponseCost, "beacon_blocks_by_root/2")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blockRef.slot.epoch).data)

        inc found

    debug "Block root request done",
      peer, roots = blockRoots.len, count, found

  proc beaconBlocksByHead(
      peer: Peer,
      beaconRoot: Eth2Digest,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS_DENEB])
      {.async, libp2pProtocol("beacon_blocks_by_head", 1).} =
    trace "got blocks by head request",
      peer, beaconRoot = shortLog(beaconRoot), count = reqCount
    if reqCount == 0:
      raise newException(InvalidInputsError, "Empty request")

    let
      dag = peer.networkState.dag
      count = int min(reqCount, MAX_REQUEST_BLOCKS_DENEB)

      # The epoch range we are required to serve, per spec:
      # `[current_epoch - compute_min_epochs_for_block_requests(), current_epoch]`
      serveFloorEpoch =
        if dag.cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS >= dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch - dag.cfg.MIN_EPOCHS_FOR_BLOCK_REQUESTS

      startBid = dag.getBlockId(beaconRoot).valueOr:
        # We have no record of this block - peers MAY respond with
        # `ResourceUnavailable` when `beacon_root` is outside the served range
        # or simply unknown.
        raise newException(ResourceUnavailableError, BlocksUnavailable)

    if startBid.slot.epoch < serveFloorEpoch:
      # `beacon_root` is older than the epoch range we are required to serve.
      raise newException(ResourceUnavailableError, BlocksUnavailable)

    var
      cur = startBid
      found = 0
      bytes: seq[byte]

    while found < count:
      if not dag.getBlockSZ(cur, bytes):
        # Block bytes unavailable (e.g. summary present but block pruned).
        break

      let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
        warn "Cannot read block size, database corrupt?",
          bytes = bytes.len(), blck = shortLog(cur)
        break

      # TODO extract from libp2pProtocol
      peer.awaitQuota(blockResponseCost, "beacon_blocks_by_head/1")
      peer.network.awaitQuota(blockResponseCost, "beacon_blocks_by_head/1")

      await response.writeBytesSZ(
        uncompressedLen, bytes,
        peer.network.forkDigestAtEpoch(cur.slot.epoch).data)

      inc found

      if found >= count:
        break

      if cur.slot == GENESIS_SLOT:
        break

      # Walk the parent chain via the block summary table (root-indexed),
      # not via `dag.parent` - `dag.parent` for finalized blocks goes
      # through `getBlockIdAtSlot` (slot-indexed `dag.db.finalizedBlocks`),
      # which can run out before the summary table does. Every block we
      # have stored has a summary, so this walk spans the full available
      # history regardless of which side of the finalized head we're on.
      let summary = dag.db.getBeaconBlockSummary(cur.root).valueOr:
        break
      let parentBid = dag.getBlockId(summary.parent_root).valueOr:
        # Parent is not known to us - we've reached the lower bound of
        # locally available history (typically `dag.backfill.slot` on a
        # checkpoint-synced node, not genesis).
        break

      if parentBid.slot.epoch < serveFloorEpoch:
        # Next ancestor falls outside the epoch range we are required to
        # serve - stop per spec.
        break

      cur = parentBid

    debug "Block head request done",
      peer, beaconRoot = shortLog(beaconRoot), count = reqCount, found

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#executionpayloadenvelopesbyrange-v1
  proc executionPayloadEnvelopesByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ref gloas.SignedExecutionPayloadEnvelope, Limit MAX_REQUEST_BLOCKS_DENEB])
      {.async, libp2pProtocol("execution_payload_envelopes_by_range", 1).} =

    if reqCount == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    var blocks: array[MAX_REQUEST_BLOCKS_DENEB.int, BlockId]
    let dag = peer.networkState.dag
    if startSlot < dag.backfill.slot:
      # Peers that are unable to reply to block requests within the
      # `MIN_EPOCHS_FOR_BLOCK_REQUESTS` epoch range SHOULD respond with
      # error code `3: ResourceUnavailable`.
      # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/phase0/p2p-interface.md#responding-side
      raise newException(ResourceUnavailableError, "Requested envelope is unavailable")

    let
      # Limit number of blocks in response
      count = int min(reqCount, blocks.lenu64)
      endIndex = count - 1
      startIndex = dag.getBlockRange(
        startSlot, blocks.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]

    for i in startIndex..endIndex:
      if dag.db.getExecutionPayloadEnvelopeSZ(blocks[i].root, bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read block size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blocks[i])
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(envelopeResponseCost, "execution_payload_envelopes_by_range/1")
        peer.network.awaitQuota(envelopeResponseCost, "execution_payload_envelopes_by_range/1")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blocks[i].slot.epoch).data)

        inc found

    if found == 0 and startSlot < dag.horizon:
      # Distinguish empty response (we know that the slot is empty)
      # from unavailable response (we have not backfilled / range got pruned).
      # For slots before the horizon, data is available on a best-effort basis
      raise newException(ResourceUnavailableError, BlocksUnavailable)

    debug "Envelope range request done", peer, startSlot, count

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/p2p-interface.md#executionpayloadenvelopesbyroot-v1
  proc executionPayloadEnvelopesByRoot(
      peer: Peer,
      blockRoots: BlockRootsList,
      response: MultipleChunksResponse[
        ref gloas.SignedExecutionPayloadEnvelope, Limit MAX_REQUEST_PAYLOADS])
      {.async, libp2pProtocol("execution_payload_envelopes_by_root", 1).} =

    if blockRoots.len == 0:
      raise newException(InvalidInputsError, "No blocks requested")

    let
      dag = peer.networkState.dag
      count = blockRoots.len

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      let
        blockRef = dag.getBlockRef(blockRoots[i]).valueOr:
          continue

      if dag.db.getExecutionPayloadEnvelopeSZ(blockRef.root, bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read block size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blockRef)
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(envelopeResponseCost, "execution_payload_envelopes_by_root/1")
        peer.network.awaitQuota(envelopeResponseCost, "execution_payload_envelopes_by_root/1")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blockRef.slot.epoch).data)

        inc found

    debug "Envelope root request done",
      peer, roots = blockRoots.len, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyroot-v1
  proc blobSidecarsByRoot(
      peer: Peer,
      blobIds: BlobIdentifierList,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_SUPPORTED_REQUEST_BLOB_SIDECARS)])
      {.async, libp2pProtocol("blob_sidecars_by_root", 1).} =
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref BlobSidecar]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    trace "got blobs root request", peer, len = blobIds.len
    if blobIds.len == 0:
      raise newException(InvalidInputsError, "No blobs requested")
    if blobIds.lenu64 >
        peer.networkState.dag.cfg.MAX_REQUEST_BLOB_SIDECARS_ELECTRA:
      raise newException(InvalidInputsError, "Exceeding blob request limit")

    debug "Blob root request done", peer

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyrange-v1
  proc blobSidecarsByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_SUPPORTED_REQUEST_BLOB_SIDECARS)])
      {.async, libp2pProtocol("blob_sidecars_by_range", 1).} =
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref BlobSidecar]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    trace "got blobs range request", peer, startSlot, count = reqCount
    if reqCount == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    let
      dag = peer.networkState.dag
      epochBoundary =
        if dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS >= dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch - dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS

    if startSlot.epoch < epochBoundary:
      raise newException(ResourceUnavailableError, BlobsOutOfRange)

    debug "BlobSidecar range request done", peer, startSlot, count = reqCount

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.0/specs/fulu/p2p-interface.md#datacolumnsidecarsbyroot-v1
  proc dataColumnSidecarsByRoot(
      peer: Peer,
      colIds: DataColumnsByRootIdentifierList,
      response: MultipleChunksResponse[
        ref fulu.DataColumnSidecar, Limit(MAX_REQUEST_DATA_COLUMN_SIDECARS)])
      {.async, libp2pProtocol("data_column_sidecars_by_root", 1).} =

    trace "got data column root request", peer, len = colIds.len
    if colIds.len == 0:
      raise newException(InvalidInputsError, "No data columns request for root")

    static: doAssert MAX_REQUEST_BLOCKS_DENEB * NUMBER_OF_COLUMNS ==
      MAX_REQUEST_DATA_COLUMN_SIDECARS
    if colIds.lenu64 > MAX_REQUEST_BLOCKS_DENEB:
      raise newException(InvalidInputsError, "Exceeding data column request limit")

    let
      dag = peer.networkState.dag
      count = colIds.len
      epochBoundary =
        if dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS >=
            dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch -
            dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      var requiredBid: BlockId
      let blockRefOpt =
        dag.getBlockRef(colIds[i].block_root)
      if blockRefOpt.isSome():
        requiredBid = blockRefOpt.get.bid
      else:
        # If we cannot retrieve the block id from getBlockRef
        # the block is probably of a finalized slot, we can now
        # try using `blockSlotId`.
        requiredBid = dag.getBlockId(colIds[i].block_root).valueOr:
          continue
        let bsid = dag.getBlockIdAtSlot(requiredBid.slot).valueOr:
          continue
        requiredBid = bsid.bid

      # The requested block predates the earliest slot for which we can
      # guarantee serving data columns - respond with `ResourceUnavailable`.
      if requiredBid.slot < dag.earliestAvailableSlot():
        raise newException(ResourceUnavailableError, DataColumnsOutOfRange)

      if requiredBid.slot.epoch < epochBoundary:
        continue

      let blockFork = dag.cfg.consensusForkAtEpoch(requiredBid.slot.epoch)

      for id in colIds[i].indices:
        if dag.db.getDataColumnSidecarSZ(
            blockFork, requiredBid.root, id, bytes):
          let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
            warn "Cannot read data column size, database corrupt?",
              bytes = bytes.len, blck = shortLog(requiredBid), columnIndex = id
            continue

          peer.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_root/1")
          peer.network.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_root/1")

          await response.writeBytesSZ(
            uncompressedLen, bytes,
            peer.network.forkDigestAtEpoch(requiredBid.slot.epoch).data)
          inc found

          # additional logging for devnets
          trace "responded to data column sidecar by root request",
            peer, blck = shortLog(requiredBid), columnIndex = id

    debug "Data column root request done",
      peer, roots = colIds.len, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#datacolumnsidecarsbyrange-v1
  proc dataColumnSidecarsByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      reqColumns: List[ColumnIndex, NUMBER_OF_COLUMNS],
      response: MultipleChunksResponse[
        ref fulu.DataColumnSidecar, Limit(MAX_REQUEST_DATA_COLUMN_SIDECARS)])
      {.async, libp2pProtocol("data_column_sidecars_by_range", 1).} =

    trace "got data columns range request", peer, startSlot,
      count = reqCount, columns = reqColumns

    if reqCount == 0 or reqColumns.len == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    let
      dag = peer.networkState.dag
      epochBoundary =
        if dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS >=
            dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch -
            dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS

    if startSlot.epoch < epochBoundary:
      raise newException(ResourceUnavailableError, DataColumnsOutOfRange)

    # The requested range starts before the earliest slot for which we can
    # guarantee serving data columns - respond with `ResourceUnavailable`.
    if startSlot < dag.earliestAvailableSlot():
      raise newException(ResourceUnavailableError, DataColumnsOutOfRange)

    var blockIds: array[int(MAX_REQUEST_DATA_COLUMN_SIDECARS), BlockId]
    let
      count = int min(reqCount, blockIds.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, blockIds.toOpenArray(0, endIndex))

    var
      found = 0'u64
      bytes: seq[byte]

    block outer:
      for i in startIndex..endIndex:
        let blockFork = dag.cfg.consensusForkAtEpoch(blockIds[i].slot.epoch)
        for k in reqColumns:
          if dag.db.getDataColumnSidecarSZ(
              blockFork, blockIds[i].root, ColumnIndex k, bytes):
            let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
              warn "Cannot read data column sidecar size, database corrup?",
                bytes = bytes.len, blck = shortLog(blockIds[i])
              continue

            peer.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_range/1")
            peer.network.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_range/1")

            await response.writeBytesSZ(
              uncompressedLen, bytes,
              peer.network.forkDigestAtEpoch(blockIds[i].slot.epoch).data)
            inc found

            # additional logging for devnets
            trace "responded to data column sidecar range request",
              peer, blck = shortLog(blockIds[i]), column = k

            if found >= MAX_REQUEST_DATA_COLUMN_SIDECARS:
              break outer

    debug "Data column range request done",
      peer, startSlot, count = reqCount, columns = reqColumns, found

  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/heze/p2p-interface.md#inclusionlistsbyindices-v1
  # The request MUST be encoded as an SSZ-container - the DSL encodes the three
  # request fields as exactly that.
  proc inclusionListsByIndices(
      peer: Peer,
      slot: Slot,
      inclusionListCommitteeRoot: Eth2Digest,
      indices: InclusionListBits,
      response: MultipleChunksResponse[
        ref heze.SignedInclusionList,
        Limit MAX_SUPPORTED_REQUEST_INCLUSION_LIST])
      {.async, libp2pProtocol("inclusion_lists_by_indices", 1).} =
    let
      dag = peer.networkState.dag
      requested = indices.countOnes()

    trace "got inclusion lists by indices request", peer, slot, requested

    if requested == 0:
      raise newException(InvalidInputsError, "No inclusion lists requested")

    # No more than `MAX_REQUEST_INCLUSION_LIST` may be requested at a time - the
    # request's `BitVector[INCLUSION_LIST_COMMITTEE_SIZE]` bounds this already on
    # the mainnet config, but the two constants are independent.
    if requested.uint64 > dag.cfg.MAX_REQUEST_INCLUSION_LIST:
      raise newException(
        InvalidInputsError, "Exceeding inclusion list request limit")

    if dag.cfg.HEZE_FORK_EPOCH == FAR_FUTURE_EPOCH:
      # Heze is not scheduled, so there is no slot we could serve.
      raise newException(ResourceUnavailableError, InclusionListsOutOfRange)

    let
      wallSlot = peer.networkState.getBeaconTime().slotOrZero(dag.timeParams)
      lookbackFloor =
        if wallSlot >= MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS:
          wallSlot - MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS
        else:
          GENESIS_SLOT
      minimumRequestSlot = max(lookbackFloor, dag.cfg.HEZE_FORK_EPOCH.start_slot)

    # For a slot earlier than `minimum_request_slot`, peers MAY respond with
    # `3: ResourceUnavailable` or just omit the lists - the error is more
    # informative than an empty response the requester cannot tell apart from
    # us simply having none.
    if slot < minimumRequestSlot:
      raise newException(ResourceUnavailableError, InclusionListsOutOfRange)

    # The request addresses committee positions while the pool is keyed by
    # validator index, so resolve them through this node's view of
    # `get_inclusion_list_committee(state, slot)`. A requester asking about a
    # different committee is not an error - the pool's root filter below then
    # simply yields nothing.
    let shufflingRef = dag.getShufflingRef(dag.head, slot.epoch, false).valueOr:
      raise newException(ResourceUnavailableError, InclusionListsOutOfRange)

    var requestedValidators: seq[uint64]
    for i, validator_index in get_inclusion_list_committee(shufflingRef, slot):
      if indices[i]:
        requestedValidators.add validator_index

    # Clients MAY limit the number of inclusion lists in the response.
    let maxLists = int min(
      dag.cfg.MAX_REQUEST_INCLUSION_LIST, MAX_SUPPORTED_REQUEST_INCLUSION_LIST)

    var found = 0
    for signedInclusionList in peer.networkState.inclusionListPool[]
        .getInclusionLists(
          slot, inclusionListCommitteeRoot, requestedValidators, maxLists):
      # TODO extract from libp2pProtocol
      peer.awaitQuota(
        inclusionListResponseCost, "inclusion_lists_by_indices/1")
      peer.network.awaitQuota(
        inclusionListResponseCost, "inclusion_lists_by_indices/1")

      # The `ForkDigest` context epoch of each chunk is determined by
      # `compute_epoch_at_slot(signed_inclusion_list.message.slot)`.
      await response.writeSSZ(
        signedInclusionList,
        peer.network.forkDigestAtEpoch(slot.epoch).data)

      inc found

    debug "Inclusion list indices request done",
      peer, slot, requested, found

# Gloas client stubs for `data_column_sidecars_by_root/1` and
# `data_column_sidecars_by_range/1`.
const
  dataColumnSidecarsByRootProtocolId =
    "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
  dataColumnSidecarsByRangeProtocolId =
    "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"

proc dataColumnSidecarsByRootGloas*(
    peer: Peer, colIds: DataColumnsByRootIdentifierList, maxResponseItems: int):
    Future[NetRes[List[ref gloas.DataColumnSidecar, Limit MAX_REQUEST_DATA_COLUMN_SIDECARS]]]
    {.async: (raises: [CancelledError], raw: true).} =
  makeEth2Request(
    peer, dataColumnSidecarsByRootProtocolId, SSZ.encode(colIds),
    List[ref gloas.DataColumnSidecar, Limit MAX_REQUEST_DATA_COLUMN_SIDECARS],
    Limit maxResponseItems, RESP_TIMEOUT_DUR)

proc dataColumnSidecarsByRangeGloas*(
    peer: Peer, startSlot: Slot, reqCount: uint64,
    reqColumns: List[ColumnIndex, NUMBER_OF_COLUMNS], maxResponseItems: int):
    Future[NetRes[List[ref gloas.DataColumnSidecar, Limit MAX_REQUEST_DATA_COLUMN_SIDECARS]]]
    {.async: (raises: [CancelledError], raw: true).} =
  makeEth2Request(
    peer, dataColumnSidecarsByRangeProtocolId,
    SSZ.encode((startSlot, reqCount, reqColumns)),
    List[ref gloas.DataColumnSidecar, Limit MAX_REQUEST_DATA_COLUMN_SIDECARS],
    Limit maxResponseItems, RESP_TIMEOUT_DUR)

func init*(
    T: type BeaconSync.NetworkState, dag: ChainDAGRef,
    inclusionListPool: ref InclusionListPool,
    getBeaconTime: GetBeaconTimeFn): T =
  T(
    dag: dag,
    inclusionListPool: inclusionListPool,
    getBeaconTime: getBeaconTime,
  )

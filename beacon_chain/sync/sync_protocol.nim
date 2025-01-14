# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, chronos, snappy, snappy/codec,
  ../spec/[helpers, forks, network],
  ".."/[beacon_clock],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../rpc/rest_constants

logScope:
  topics = "sync_proto"

const
  blockResponseCost = allowedOpsPerSecondCost(64)
    ## Allow syncing ~64 blocks/sec (minus request costs)
  blobResponseCost = allowedOpsPerSecondCost(1000)
    ## Multiple can exist per block, they are much smaller than blocks
  dataColumnResponseCost = allowedOpsPerSecondCost(8000)
    ## 8 data columns take the same memory as 1 blob approximately

type
  BeaconSyncNetworkState* {.final.} = ref object of RootObj
    dag: ChainDAGRef
    cfg: RuntimeConfig
    genesisBlockRoot: Eth2Digest

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

  BlockRootsList* = List[Eth2Digest, Limit MAX_REQUEST_BLOCKS]
  BlobIdentifierList* = List[BlobIdentifier, Limit (MAX_REQUEST_BLOB_SIDECARS)]
  DataColumnIdentifierList* = List[DataColumnIdentifier, Limit (MAX_REQUEST_DATA_COLUMN_SIDECARS)]

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
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)

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
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref DataColumnSidecar)):
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
    when consensusFork >= ConsensusFork.Fulu:
      let res = await readChunkPayload(conn, peer, DataColumnSidecar)
      if res.isOk:
        return ok newClone(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

{.pop.} # TODO fix p2p macro for raises

template getBlobSidecarsByRoot(
    versionNumber: static string, peer: Peer, dag: ChainDAGRef, response: auto,
    blobIds: BlobIdentifierList) =
  trace "got v" & versionNumber & " blobs range request",
    peer, len = blobIds.len
  if blobIds.len == 0:
    raise newException(InvalidInputsError, "No blobs requested")

  let count = blobIds.len

  var
    found = 0
    bytes: seq[byte]

  for i in 0..<count:
    let blockRef = dag.getBlockRef(blobIds[i].block_root).valueOr:
      continue
    let index = blobIds[i].index
    if dag.db.getBlobSidecarSZ(blockRef.bid.root, index, bytes):
      let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
        warn "Cannot read blob size, database corrupt?",
          bytes = bytes.len(), blck = shortLog(blockRef), blobindex = index
        continue

      peer.awaitQuota(
        blobResponseCost, "blob_sidecars_by_root/" & versionNumber)
      peer.network.awaitQuota(
        blobResponseCost, "blob_sidecars_by_root/" & versionNumber)

      await response.writeBytesSZ(
        uncompressedLen, bytes,
        peer.network.forkDigestAtEpoch(blockRef.slot.epoch).data)
      inc found

  debug "Blob root v" & versionNumber & " request done",
    peer, roots = blobIds.len, count, found

template getBlobSidecarsByRange(
    versionNumber: static string, peer: Peer, dag: ChainDAGRef, response: auto,
    startSlot: Slot, reqCount: uint64, blobsPerBlock: static uint64,
    maxReqSidecars: static uint64) =
  trace "got v" & versionNumber & " blobs range request",
    peer, startSlot, count = reqCount
  if reqCount == 0:
    raise newException(InvalidInputsError, "Empty range requested")

  let epochBoundary =
    if dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS >= dag.head.slot.epoch:
      GENESIS_EPOCH
    else:
      dag.head.slot.epoch - dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS

  if startSlot.epoch < epochBoundary:
    raise newException(ResourceUnavailableError, BlobsOutOfRange)

  var blockIds: array[int(maxReqSidecars), BlockId]
  let
    count = int min(reqCount, blockIds.lenu64)
    endIndex = count - 1
    startIndex =
      dag.getBlockRange(startSlot, blockIds.toOpenArray(0, endIndex))

  var
    found = 0
    bytes: seq[byte]

  for i in startIndex..endIndex:
    for j in 0..<blobsPerBlock:
      if dag.db.getBlobSidecarSZ(blockIds[i].root, BlobIndex(j), bytes):
        if not dag.head.executionValid:
          continue

        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read blobs sidecar size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blockIds[i])
          continue

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          blobResponseCost, "blobs_sidecars_by_range/" & versionNumber)
        peer.network.awaitQuota(
          blobResponseCost, "blobs_sidecars_by_range/" & versionNumber)

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blockIds[i].slot.epoch).data)
        inc found
      else:
        break

  debug "BlobSidecar v" & versionNumber & " range request done",
    peer, startSlot, count = reqCount, found

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState):
  proc beaconBlocksByRange_v2(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS])
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

    var blocks: array[MAX_REQUEST_BLOCKS.int, BlockId]
    let
      dag = peer.networkState.dag
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
        # In general, there is not much intermediate time between post-merge
        # blocks all being optimistic and none of them being optimistic. The
        # EL catches up, tells the CL the head is verified, and that's it.
        if  blocks[i].slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
            not dag.head.executionValid:
          continue

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

    debug "Block range request done", peer, startSlot, count

  proc beaconBlocksByRoot_v2(
      peer: Peer,
      # Please note that the SSZ list here ensures that the
      # spec constant MAX_REQUEST_BLOCKS is enforced:
      blockRoots: BlockRootsList,
      response: MultipleChunksResponse[
        ref ForkedSignedBeaconBlock, Limit MAX_REQUEST_BLOCKS])
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
        # In general, there is not much intermediate time between post-merge
        # blocks all being optimistic and none of them being optimistic. The
        # EL catches up, tells the CL the head is verified, and that's it.
        if  blockRef.slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
            not dag.head.executionValid:
          continue

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

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyroot-v1
  proc blobSidecarsByRoot(
      peer: Peer,
      blobIds: BlobIdentifierList,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS_ELECTRA)])
      {.async, libp2pProtocol("blob_sidecars_by_root", 1).} =
    # TODO Semantically, this request should return a non-ref, but doing so
    #      runs into extreme inefficiency due to the compiler introducing
    #      hidden copies - in future nim versions with move support, this should
    #      be revisited
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref BlobSidecar]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    getBlobSidecarsByRoot("1", peer, peer.networkState.dag, response, blobIds)

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyrange-v1
  proc blobSidecarsByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS_ELECTRA)])
      {.async, libp2pProtocol("blob_sidecars_by_range", 1).} =
    # TODO This code is more complicated than it needs to be, since the type
    #      of the multiple chunks response is not actually used in this server
    #      implementation (it's used to derive the signature of the client
    #      function, not in the code below!)
    # TODO although you can't tell from this function definition, a magic
    #      client call that returns `seq[ref BlobSidecar]` will
    #      will be generated by the libp2p macro - we guarantee that seq items
    #      are `not-nil` in the implementation
    getBlobSidecarsByRange(
      "1", peer, peer.networkState.dag, response, startSlot, reqCount,
      MAX_BLOBS_PER_BLOCK, MAX_REQUEST_BLOB_SIDECARS_ELECTRA)

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#datacolumnsidecarsbyroot-v1
  proc dataColumnSidecarsByRoot(
      peer: Peer,
      colIds: DataColumnIdentifierList,
      response: MultipleChunksResponse[
        ref DataColumnSidecar, Limit(MAX_REQUEST_DATA_COLUMN_SIDECARS)])
      {.async, libp2pProtocol("data_column_sidecars_by_root", 1).} =

    trace "got data column root request", peer, len = colIds.len
    if colIds.len == 0:
      raise newException(InvalidInputsError, "No data columns request for root")

    if colIds.lenu64 > MAX_REQUEST_DATA_COLUMN_SIDECARS:
      raise newException(InvalidInputsError, "Exceeding data column request limit")

    let
      dag = peer.networkState.dag
      count = colIds.len

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      let blockRef =
        dag.getBlockRef(colIds[i].block_root).valueOr:
          continue
      let index =
        colIds[i].index
      if dag.db.getDataColumnSidecarSZ(blockRef.bid.root, index, bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read data column size, database corrupt?",
            bytes = bytes.len, blck = shortLog(blockRef), columnIndex = index
          continue

        peer.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_root/1")
        peer.network.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_root/1")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blockRef.slot.epoch).data)
        inc found

        # additional logging for devnets
        debug "responsded to data column sidecar by root request",
          peer, blck = shortLog(blockRef), columnIndex = index

    debug "Data column root request done",
      peer, roots = colIds.len, count, found

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#datacolumnsidecarsbyrange-v1
  proc dataColumnSidecarsByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      reqColumns: List[ColumnIndex, NUMBER_OF_COLUMNS],
      response: MultipleChunksResponse[
        ref DataColumnSidecar, Limit(MAX_REQUEST_DATA_COLUMN_SIDECARS)])
      {.async, libp2pProtocol("data_column_sidecars_by_range", 1).} =

    trace "got data columns range request", peer, startSlot,
      count = reqCount, columns = reqColumns

    if reqCount == 0 or reqColumns.len == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    let
      dag = peer.networkState.dag
      # Using MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS until
      # MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS is released in
      # Fulu. Effectively both the values are same
      epochBoundary =
        if dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS >= dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch - dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS

    if startSlot.epoch < epochBoundary:
      raise newException(ResourceUnavailableError, DataColumnsOutOfRange)

    var blockIds: array[int(MAX_REQUEST_DATA_COLUMN_SIDECARS), BlockId]
    let
      count = int min(reqCount, blockIds.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, blockIds.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]

    for i in startIndex..endIndex:
      for k in reqColumns:
        if dag.db.getDataColumnSidecarSZ(blockIds[i].root, ColumnIndex k, bytes):
          if blockIds[i].slot.epoch >= dag.cfg.DENEB_FORK_EPOCH and
              not dag.head.executionValid:
            continue

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

          var
            respondedCols: seq[ColumnIndex]
          respondedCols.add(k)

          # additional logging for devnets
          debug "responded to data column sidecar range request",
            peer, blck = shortLog(blockIds[i]), columns = respondedCols

    debug "Data column range request done",
      peer, startSlot, count = reqCount, columns = reqColumns, found

func init*(T: type BeaconSync.NetworkState, dag: ChainDAGRef): T =
  T(
    dag: dag,
  )

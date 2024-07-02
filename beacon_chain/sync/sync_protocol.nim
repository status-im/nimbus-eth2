# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, chronos, snappy, snappy/codec,
  ../spec/datatypes/[phase0, altair, bellatrix, capella, deneb, eip7594],
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
  dataColumnResponseCost = allowedOpsPerSecondCost(4000)
    ## 1 blob has an equivalent memory of 8 data columns

type
  BeaconSyncNetworkState* {.final.} = ref object of RootObj
    dag: ChainDAGRef
    cfg: RuntimeConfig
    genesisBlockRoot: Eth2Digest

  BlockRootSlot* = object
    blockRoot: Eth2Digest
    slot: Slot

  BlockRootsList* = List[Eth2Digest, Limit MAX_REQUEST_BLOCKS]
  BlobIdentifierList* = List[BlobIdentifier, Limit MAX_REQUEST_BLOB_SIDECARS]
  DataColumnIdentifierList* = List[DataColumnIdentifier, Limit MAX_REQUEST_DATA_COLUMNS]

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref ForkedSignedBeaconBlock)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CancelledError as exc:
    raise exc
  except CatchableError:
    return neterr UnexpectedEOF

  static: doAssert ConsensusFork.high == ConsensusFork.Electra
  if contextBytes == peer.network.forkDigests.phase0:
    let res = await readChunkPayload(conn, peer, phase0.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.altair:
    let res = await readChunkPayload(conn, peer, altair.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.bellatrix:
    let res = await readChunkPayload(conn, peer, bellatrix.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.capella:
    let res = await readChunkPayload(conn, peer, capella.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.deneb:
    let res = await readChunkPayload(conn, peer, deneb.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
    else:
      return err(res.error)
  elif contextBytes == peer.network.forkDigests.electra:
    let res = await readChunkPayload(conn, peer, electra.SignedBeaconBlock)
    if res.isOk:
      return ok newClone(ForkedSignedBeaconBlock.init(res.get))
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
  except CancelledError as exc:
    raise exc
  except CatchableError:
    return neterr UnexpectedEOF

  if contextBytes == peer.network.forkDigests.deneb:
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
  except CancelledError as exc:
    raise exc
  except CatchableError:
    return neterr UnexpectedEOF

  if contextBytes == peer.network.forkDigests.deneb:
    let res = await readChunkPayload(conn, peer, DataColumnSidecar)
    if res.isOk:
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
    # TODO reqStep is deprecated - future versions can remove support for
    #      values != 1: https://github.com/ethereum/consensus-specs/pull/2856

    trace "got range request", peer, startSlot,
                               count = reqCount, step = reqStep
    if reqCount == 0 or reqStep == 0:
      raise newException(InvalidInputsError, "Empty range requested")

    var blocks: array[MAX_REQUEST_BLOCKS.int, BlockId]
    let
      dag = peer.networkState.dag
      # Limit number of blocks in response
      count = int min(reqCount, blocks.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, reqStep,
                          blocks.toOpenArray(0, endIndex))

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

    debug "Block range request done",
      peer, startSlot, count, reqStep

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
        ref BlobSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS)])
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
    trace "got blobs range request", peer, len = blobIds.len
    if blobIds.len == 0:
      raise newException(InvalidInputsError, "No blobs requested")

    let
      dag = peer.networkState.dag
      count = blobIds.len

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

        peer.awaitQuota(blobResponseCost, "blob_sidecars_by_root/1")
        peer.network.awaitQuota(blobResponseCost, "blob_sidecars_by_root/1")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blockRef.slot.epoch).data)
        inc found

    debug "Blob root request done",
      peer, roots = blobIds.len, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/p2p-interface.md#blobsidecarsbyrange-v1
  proc blobSidecarsByRange(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ref BlobSidecar, Limit(MAX_REQUEST_BLOB_SIDECARS)])
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

    var blockIds: array[int(MAX_REQUEST_BLOB_SIDECARS), BlockId]
    let
      count = int min(reqCount, blockIds.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, 1, blockIds.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]

    for i in startIndex..endIndex:
      for j in 0..<MAX_BLOBS_PER_BLOCK:
        if dag.db.getBlobSidecarSZ(blockIds[i].root, BlobIndex(j), bytes):
          # In general, there is not much intermediate time between post-merge
          # blocks all being optimistic and none of them being optimistic. The
          # EL catches up, tells the CL the head is verified, and that's it.
          if  blockIds[i].slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
              not dag.head.executionValid:
            continue

          let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
            warn "Cannot read blobs sidecar size, database corrupt?",
              bytes = bytes.len(), blck = shortLog(blockIds[i])
            continue

          # TODO extract from libp2pProtocol
          peer.awaitQuota(blobResponseCost, "blobs_sidecars_by_range/1")
          peer.network.awaitQuota(blobResponseCost, "blobs_sidecars_by_range/1")

          await response.writeBytesSZ(
            uncompressedLen, bytes,
            peer.network.forkDigestAtEpoch(blockIds[i].slot.epoch).data)
          inc found
        else:
          break

    debug "BlobSidecar range request done",
      peer, startSlot, count = reqCount, found

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/specs/_features/eip7594/p2p-interface.md#datacolumnsidecarsbyroot-v1
  proc dataColumnSidecarsByRoot(
      peer: Peer,
      columnIds: DataColumnIdentifierList,
      response: MultipleChunksResponse[
        ref DataColumnSidecar, Limit(MAX_REQUEST_DATA_COLUMNS)])
      {.async, libp2pProtocol("data_column_sidecars_by_root", 1).} =

    trace "got data columns range request", peer, len = columnIds.len
    if columnIds.len == 0:
      raise newException(InvalidInputsError, "No data columns requested")

    if columnIds.lenu64 > MAX_REQUEST_DATA_COLUMNS:
      raise newException(InvalidInputsError, "Exceeding data column request limit")

    let
      dag = peer.networkState.dag
      count = columnIds.len

    var
      found = 0
      bytes: seq[byte]

    for i in 0..<count:
      let blockRef = dag.getBlockRef(columnIds[i].block_root).valueOr:
        continue
      let index = columnIds[i].index
      if dag.db.getDataColumnSidecarSZ(blockRef.bid.root, index, bytes):
        let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
          warn "Cannot read data column size, database corrupt?",
            bytes = bytes.len(), blck = shortLog(blockRef), columnIndex = index
          continue

        peer.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_root/1")
        peer.network.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_root/1")

        await response.writeBytesSZ(
          uncompressedLen, bytes,
          peer.network.forkDigestAtEpoch(blockRef.slot.epoch).data)
        inc found

    debug "Data column root request done",
      peer, roots = columnIds.len, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/specs/_features/eip7594/p2p-interface.md#datacolumnsidecarsbyrange-v1
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
      epochBoundary =
        if dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS >= dag.head.slot.epoch:
          GENESIS_EPOCH
        else:
          dag.head.slot.epoch - dag.cfg.MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS
    
    if startSlot.epoch < epochBoundary:
      raise newException(ResourceUnavailableError, DataColumnsOutOfRange)

    var blockIds: array[int(MAX_REQUEST_DATA_COLUMNS), BlockId]
    let
      count = int min(reqCount, blockIds.lenu64)
      endIndex = count - 1
      startIndex =
        dag.getBlockRange(startSlot, 1, blockIds.toOpenArray(0, endIndex))

    var
      found = 0
      bytes: seq[byte]
    
    for i in startIndex..endIndex:
      for j in 0..<MAX_REQUEST_DATA_COLUMNS:
        if dag.db.getDataColumnSidecarSZ(blockIds[i].root, ColumnIndex(j), bytes):
          if blockIds[i].slot.epoch >= dag.cfg.BELLATRIX_FORK_EPOCH and
              not dag.head.executionValid:
            continue

          let uncompressedLen = uncompressedLenFramed(bytes).valueOr:
            warn "Cannot read data column sidecar size, database, corrupt",
              bytes = bytes.len(), blck = shortLog(blockIds[i])
            continue

          peer.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_range/1")
          peer.network.awaitQuota(dataColumnResponseCost, "data_column_sidecars_by_range/1")

          await response.writeBytesSZ(
            uncompressedLen, bytes,
            peer.network.forkDigestAtEpoch(blockIds[i].slot.epoch).data)
          inc found
        else:
          break

    debug "DataColumnSidecar range request done",
      peer, startSlot, count = reqCount, columns = reqColumns, found

proc init*(T: type BeaconSync.NetworkState, dag: ChainDAGRef): T =
  T(
    dag: dag,
  )

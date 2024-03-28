# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, chronos, snappy, snappy/codec,
  ../spec/datatypes/[phase0, altair, bellatrix, capella, deneb],
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
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} = discard

import
  chronicles, chronos, snappy, snappy/codec,
  ".."/[beacon_clock],
  ../networking/eth2_network

type
  BeaconSyncNetworkState* {.final.} = ref object of RootObj
    cfg: RuntimeConfig

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref uint64)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} = discard

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState):
  proc beaconBlocksByRange_v2(
      peer: Peer,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref uint64, Limit MAX_REQUEST_BLOCKS])
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} = discard

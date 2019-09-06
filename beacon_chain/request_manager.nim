import
  options, random,
  chronos, chronicles,
  spec/datatypes,
  eth2_network, beacon_node_types, sync_protocol,
  eth/async_utils

proc init*(T: type RequestManager, network: Eth2Node): T =
  T(network: network)

type
  FetchAncestorsResponseHandler = proc (b: BeaconBlock) {.gcsafe.}

proc fetchAncestorBlocksFromPeer(peer: Peer, rec: FetchRecord, responseHandler: FetchAncestorsResponseHandler) {.async.} =
  # TODO: (zah) Why are we specifying `GENESIS_SLOT` here?
  #             I'm not sure what this meant for the old code.
  let blocksResp = await peer.getBeaconBlocks(rec.root, GENESIS_SLOT, rec.historySlots, 0'u64)
  if blocksResp.isSome:
    for b in blocksResp.get.blocks:
      responseHandler(b)

proc fetchAncestorBlocks*(requestManager: RequestManager,
                          roots: seq[FetchRecord],
                          responseHandler: FetchAncestorsResponseHandler) =
  # TODO: we could have some fancier logic here:
  #
  # * Keeps track of what was requested
  #   (this would give a little bit of time for the asked peer to respond)
  #
  # * Keep track of the average latency of each peer
  #   (we can give priority to peers with better latency)
  #

  const ParallelRequests = 2

  var fetchComplete = false
  for peer in requestManager.network.randomPeers(ParallelRequests, BeaconSync):
    traceAsyncErrors peer.fetchAncestorBlocksFromPeer(roots.rand(), responseHandler)

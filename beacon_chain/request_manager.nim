import
  options,
  chronos, chronicles,
  spec/datatypes,
  eth2_network, beacon_node_types, sync_protocol

proc init*(T: type RequestManager, network: EthereumNode): T =
  T(network: network)

type
  FetchAncestorsResponseHandler = proc (b: BeaconBlock) {.gcsafe.}

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
  # * Make more parallel requests, just in case
  #
  let peer = requestManager.network.randomPeerWith(BeaconSync)
  if peer != nil:
    var response = peer.getAncestorBlocks(roots)
    response.addCallback do (arg: pointer):
      if not response.failed and response.read.isSome:
        for blk in response.read.get.blocks:
          responseHandler(blk)
      else:
        debug "Failed to obtain ancestor blocks from peer", peer


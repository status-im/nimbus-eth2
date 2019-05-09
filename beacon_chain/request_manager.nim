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

  const ParallelRequests = 2

  var fetchComplete = false
  for peer in requestManager.network.randomPeers(ParallelRequests, BeaconSync):
    closureScope:
      let response = peer.getAncestorBlocks(roots)
      response.addCallback do(arg: pointer):
        if not response.failed and response.read.isSome and not fetchComplete:
          fetchComplete = true
          for blk in response.read.get.blocks:
            responseHandler(blk)
        else:
          debug "Failed to obtain ancestor blocks from peer", peer

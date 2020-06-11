import
  options, random,
  chronos, chronicles,
  spec/datatypes,
  eth2_network, beacon_node_types, sync_protocol,
  eth/async_utils

type
  RequestManager* = object
    network*: Eth2Node

proc init*(T: type RequestManager, network: Eth2Node): T =
  T(network: network)

type
  FetchAncestorsResponseHandler = proc (b: SignedBeaconBlock) {.gcsafe.}

proc fetchAncestorBlocksFromPeer(
     peer: Peer,
     rec: FetchRecord,
     responseHandler: FetchAncestorsResponseHandler) {.async.} =
  # TODO: It's not clear if this function follows the intention of the
  # FetchRecord data type. Perhaps it is supposed to get a range of blocks
  # instead. In order to do this, we'll need the slot number of the known
  # block to be stored in the FetchRecord, so we can ask for a range of
  # blocks starting N positions before this slot number.
  try:
    let blocks = await peer.beaconBlocksByRoot(BlockRootsList @[rec.root])
    if blocks.isOk:
      for b in blocks.get:
        responseHandler(b)
  except CatchableError as err:
    debug "Error while fetching ancestor blocks",
          err = err.msg, root = rec.root, peer = peer

proc fetchAncestorBlocksFromNetwork(
     network: Eth2Node,
     rec: FetchRecord,
     responseHandler: FetchAncestorsResponseHandler) {.async.} =
  var peer: Peer
  try:
    peer = await network.peerPool.acquire()
    let blocks = await peer.beaconBlocksByRoot(BlockRootsList @[rec.root])
    if blocks.isOk:
      for b in blocks.get:
        responseHandler(b)
  except CatchableError as err:
    debug "Error while fetching ancestor blocks",
          err = err.msg, root = rec.root, peer = peer
  finally:
    if not(isNil(peer)):
      network.peerPool.release(peer)

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

  for i in 0 ..< ParallelRequests:
    traceAsyncErrors fetchAncestorBlocksFromNetwork(requestManager.network,
                                                    roots.sample(),
                                                    responseHandler)


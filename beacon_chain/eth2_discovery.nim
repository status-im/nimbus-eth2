import
  net,
  eth/keys, eth/trie/db,
  eth/p2p/discoveryv5/[protocol, node, discovery_db, types],
  conf

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId

export
  Eth2DiscoveryProtocol, open, start, close

proc new*(T: type Eth2DiscoveryProtocol,
          conf: BeaconNodeConf,
          rawPrivKeyBytes: openarray[byte]): T =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  var
    pk = initPrivateKey(rawPrivKeyBytes)
    db = DiscoveryDB.init(newMemoryDB())

  newProtocol(pk, db, Port conf.udpPort)


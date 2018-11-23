import
  asyncdispatch2,
  datatypes, beacon_chain_db

proc obtainTrustedStateSnapshot*(db: BeaconChainDB): Future[BeaconState] {.async.} =
  # In case our latest state is too old, we must obtain a recent snapshot
  # of the state from a trusted location. This is explained in detail here:
  # https://notes.ethereum.org/oaQV3IF5R2qlJuW-V1r1ew#Beacon-chain-sync

  # TODO: implement this:
  #
  # 1. Specify a large set of trusted state signees
  # (perhaps stored in a config file)
  #
  # 2. Download a signed state hash from a known location
  # (The known location can be either a HTTPS host or a DHT record)
  #
  # 3. Check that enough of the specified required signatures are present
  #
  # 4. Download a snapshot file from a known location
  # (or just obtain it from the network using the ETH protocols)
  #
  # 5. Check that the state snapshot hash is correct and save it in the DB.

  discard


import
  asyncdispatch2, json_rpc,
  datatypes

type
  MainchainMonitor* = object
    gethAddress: string
    gethPort: Port



proc init*(T: type MainchainMonitor, gethAddress: string, gethPort: Port): T =
  result.gethAddress = gethAddress
  result.gethPort = gethPort

proc start*(m: var MainchainMonitor) =
  # TODO
  # Start an async loop following the new blocks using the ETH1 JSON-RPC
  # interface and keep an always-up-to-date receipt reference here
  discard

proc getBeaconBlockRef*(m: MainchainMonitor): Blake2_256_Digest =
  # This should be a simple accessor for the reference kept above
  discard

iterator getValidatorActions*(fromBlock,
                              toBlock: Blake2_256_Digest): SpecialRecord =
  # It's probably better if this doesn't return a SpecialRecord, but
  # rather a more readable description of the change that can be packed
  # in a SpecialRecord by the client of the API.
  discard

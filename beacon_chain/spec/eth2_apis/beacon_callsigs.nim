import
  options,
  ../datatypes

# https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/basic.md
#
proc getBeaconHead(): Slot
proc getBeaconBlock(slot = none(Slot), root = none(Eth2Digest)): BeaconBlock
proc getBeaconState(slot = none(Slot), root = none(Eth2Digest)): BeaconState
proc getNetworkPeerId()
proc getNetworkPeers()
proc getNetworkEnr()


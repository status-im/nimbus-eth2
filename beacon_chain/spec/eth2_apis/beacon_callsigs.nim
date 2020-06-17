import
  options,
  ../[datatypes, digest, crypto],
  json_rpc/jsonmarshal,
  callsigs_types

proc get_v1_beacon_genesis(): BeaconGenesisTuple

# TODO stateId is part of the REST path
proc get_v1_beacon_states_root(stateId: string): Eth2Digest

# TODO stateId is part of the REST path
proc get_v1_beacon_states_fork(stateId: string): Fork



# TODO: delete old stuff

# https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/basic.md
#
proc getBeaconHead(): Slot
proc getBeaconBlock(slot = none(Slot), root = none(Eth2Digest)): BeaconBlock
proc getBeaconState(slot = none(Slot), root = none(Eth2Digest)): BeaconState
proc getNetworkPeerId()
proc getNetworkPeers()
proc getNetworkEnr()


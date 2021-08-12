import
  rpc_types,
  ../datatypes/phase0

export rpc_types

proc get_v1_debug_beacon_states_stateId(stateId: string): phase0.BeaconState
proc get_v1_debug_beacon_heads(): seq[tuple[root: Eth2Digest, slot: Slot]]

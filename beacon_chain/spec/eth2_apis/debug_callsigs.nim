import
  options,
  ../[datatypes, digest, crypto],
  json_rpc/jsonmarshal,
  callsigs_types

proc get_v1_debug_beacon_states_stateId(stateId: string): BeaconState
proc get_v1_debug_beacon_heads(): seq[tuple[root: Eth2Digest, slot: Slot]]

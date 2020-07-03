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

# TODO stateId is part of the REST path
proc get_v1_beacon_states_finality_checkpoints(
  stateId: string): BeaconStatesFinalityCheckpointsTuple

# TODO stateId is part of the REST path
proc get_v1_beacon_states_stateId_validators(
  stateId: string, validatorIds: seq[string],
  status: string): seq[BeaconStatesValidatorsTuple]

# TODO stateId and validatorId are part of the REST path
proc get_v1_beacon_states_stateId_validators_validatorId(
  stateId: string, validatorId: string): BeaconStatesValidatorsTuple

# TODO stateId and epoch are part of the REST path
proc get_v1_beacon_states_stateId_committees_epoch(stateId: string,
  epoch: uint64, index: uint64, slot: uint64): seq[BeaconStatesCommitteesTuple]

proc get_v1_beacon_headers(slot: uint64, parent_root: Eth2Digest): seq[BeaconHeadersTuple]

# TODO blockId is part of the REST path
proc get_v1_beacon_headers_blockId(blockId: string):
  tuple[canonical: bool, header: SignedBeaconBlockHeader]

# TODO blockId is part of the REST path
proc get_v1_beacon_blocks_blockId(blockId: string): SignedBeaconBlock

# TODO blockId is part of the REST path
proc get_v1_beacon_blocks_blockId_root(blockId: string): Eth2Digest

# TODO blockId is part of the REST path
proc get_v1_beacon_blocks_blockId_attestations(blockId: string): seq[Attestation]

# TODO POST /v1/beacon/pool/attester_slashings
# TODO GET  /v1/beacon/pool/attester_slashings
# TODO POST /v1/beacon/pool/proposer_slashings
# TODO GET  /v1/beacon/pool/proposer_slashings
# TODO POST /v1/beacon/pool/voluntary_exits
# TODO GET  /v1/beacon/pool/voluntary_exits
# TODO POST /v1/beacon/pool/attestations
# TODO GET  /v1/beacon/pool/attestations



proc post_v1_beacon_pool_attestations(attestation: Attestation): bool

proc get_v1_config_fork_schedule(): seq[tuple[epoch: uint64, version: Version]]

# TODO stateId is part of the REST path
proc get_v1_debug_beacon_states_stateId(stateId: string): BeaconState


# TODO: delete old stuff

# https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/basic.md
#
proc getBeaconHead(): Slot
proc getBeaconBlock(slot = none(Slot), root = none(Eth2Digest)): BeaconBlock
proc getBeaconState(slot = none(Slot), root = none(Eth2Digest)): BeaconState
proc getNetworkPeerId()
proc getNetworkPeers()
proc getNetworkEnr()


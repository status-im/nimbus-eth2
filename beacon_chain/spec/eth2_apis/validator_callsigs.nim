import
  # Standard library
  options,
  # Local modules
  ../[datatypes, digest, crypto],
  json_rpc/jsonmarshal,
  validator_callsigs_types

# TODO check which arguments are part of the path in the REST API



# TODO this doesn't have "validator" in it's path but is used by the validators nonetheless
proc get_v1_beacon_states_fork(stateId: string): Fork

# TODO this doesn't have "validator" in it's path but is used by the validators nonetheless
proc get_v1_beacon_genesis(): BeaconGenesisTuple

proc get_v1_validator_blocks(slot: Slot, graffiti: Eth2Digest, randao_reveal: ValidatorSig): BeaconBlock

# TODO this doesn't have "validator" in it's path but is used by the validators nonetheless
# TODO returns a bool even though in the API there is no return type - because of nim-json-rpc
proc post_v1_beacon_blocks(body: SignedBeaconBlock): bool

proc get_v1_validator_attestation_data(slot: Slot, committee_index: CommitteeIndex): AttestationData

proc get_v1_validator_aggregate_attestation(query: Eth2Digest): Attestation

proc post_v1_validator_aggregate_and_proof(payload: SignedAggregateAndProof)

# TODO this should perhaps be a GET instead of a POST?
proc post_v1_validator_duties_attester(epoch: Epoch, public_keys: seq[ValidatorPubKey]): seq[AttesterDuties]

proc get_v1_validator_duties_proposer(epoch: Epoch): seq[ValidatorPubkeySlotPair]

proc post_v1_validator_beacon_committee_subscription(committee_index: CommitteeIndex,
                                                     slot: Slot,
                                                     aggregator: bool,
                                                     validator_pubkey: ValidatorPubKey,
                                                     slot_signature: ValidatorSig)

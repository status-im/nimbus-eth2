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

# TODO returns a bool even though in the API there is no return type - because of nim-json-rpc
proc post_v1_beacon_pool_attestations(attestation: Attestation): bool

proc get_v1_validator_blocks(slot: Slot, graffiti: Eth2Digest, randao_reveal: ValidatorSig): BeaconBlock

# TODO returns a bool even though in the API there is no return type - because of nim-json-rpc
proc post_v1_beacon_blocks(body: SignedBeaconBlock): bool

proc get_v1_validator_attestation_data(slot: Slot, committee_index: CommitteeIndex): AttestationData

# TODO at the time of writing (10.06.2020) the API specifies this call to have a hash of
# the attestation data instead of the object itself but we also need the slot.. see here:
# https://docs.google.com/spreadsheets/d/1kVIx6GvzVLwNYbcd-Fj8YUlPf4qGrWUlS35uaTnIAVg/edit?disco=AAAAGh7r_fQ
proc get_v1_validator_aggregate_attestation(attestation_data: AttestationData): Attestation

# TODO returns a bool even though in the API there is no return type - because of nim-json-rpc
proc post_v1_validator_aggregate_and_proof(payload: SignedAggregateAndProof): bool

# this is a POST instead of a GET because of this: https://docs.google.com/spreadsheets/d/1kVIx6GvzVLwNYbcd-Fj8YUlPf4qGrWUlS35uaTnIAVg/edit?disco=AAAAJk5rbKA
proc post_v1_validator_duties_attester(epoch: Epoch, public_keys: seq[ValidatorPubKey]): seq[AttesterDuties]

proc get_v1_validator_duties_proposer(epoch: Epoch): seq[ValidatorPubkeySlotPair]

proc post_v1_validator_beacon_committee_subscription(committee_index: CommitteeIndex,
                                                     slot: Slot,
                                                     aggregator: bool,
                                                     validator_pubkey: ValidatorPubKey,
                                                     slot_signature: ValidatorSig)

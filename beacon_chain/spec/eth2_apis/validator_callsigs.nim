import
  # Standard library
  options,
  # Local modules
  ../[datatypes, digest, crypto],
  json_rpc/jsonmarshal,
  callsigs_types


# calls that return a bool are actually without a return type in the main REST API
# spec but nim-json-rpc requires that all RPC calls have a return type.

proc post_v1_beacon_pool_attestations(attestation: Attestation): bool

# TODO slot is part of the REST path
proc get_v1_validator_blocks(slot: Slot, graffiti: Eth2Digest, randao_reveal: ValidatorSig): BeaconBlock

proc post_v1_beacon_blocks(body: SignedBeaconBlock): bool

proc get_v1_validator_attestation_data(slot: Slot, committee_index: CommitteeIndex): AttestationData

# TODO at the time of writing (10.06.2020) the API specifies this call to have a hash of
# the attestation data instead of the object itself but we also need the slot.. see here:
# https://docs.google.com/spreadsheets/d/1kVIx6GvzVLwNYbcd-Fj8YUlPf4qGrWUlS35uaTnIAVg/edit?disco=AAAAGh7r_fQ
proc get_v1_validator_aggregate_attestation(attestation_data: AttestationData): Attestation

proc post_v1_validator_aggregate_and_proof(payload: SignedAggregateAndProof): bool

# this is a POST instead of a GET because of this: https://docs.google.com/spreadsheets/d/1kVIx6GvzVLwNYbcd-Fj8YUlPf4qGrWUlS35uaTnIAVg/edit?disco=AAAAJk5rbKA
# TODO epoch is part of the REST path
proc post_v1_validator_duties_attester(epoch: Epoch, public_keys: seq[ValidatorPubKey]): seq[AttesterDuties]

# TODO epoch is part of the REST path
proc get_v1_validator_duties_proposer(epoch: Epoch): seq[ValidatorPubkeySlotPair]

proc post_v1_validator_beacon_committee_subscriptions(committee_index: CommitteeIndex,
                                                      slot: Slot,
                                                      aggregator: bool,
                                                      validator_pubkey: ValidatorPubKey,
                                                      slot_signature: ValidatorSig): bool

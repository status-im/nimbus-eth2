import
  options,
  rpc_types

# calls that return a bool are actually without a return type in the main REST API
# spec but nim-json-rpc requires that all RPC calls have a return type.

proc get_v1_validator_block(slot: Slot, graffiti: GraffitiBytes, randao_reveal: ValidatorSig): phase0.BeaconBlock

proc post_v1_validator_block(body: phase0.SignedBeaconBlock): bool

proc get_v1_validator_attestation_data(slot: Slot, committee_index: CommitteeIndex): AttestationData

proc get_v1_validator_aggregate_attestation(slot: Slot, attestation_data_root: Eth2Digest): Attestation

proc post_v1_validator_aggregate_and_proofs(payload: SignedAggregateAndProof): bool

# TODO epoch is part of the REST path
proc get_v1_validator_duties_attester(epoch: Epoch, public_keys: seq[ValidatorPubKey]): seq[RpcAttesterDuties]

# TODO epoch is part of the REST path
proc get_v1_validator_duties_proposer(epoch: Epoch): seq[RpcValidatorDuties]

proc post_v1_validator_beacon_committee_subscriptions(committee_index: CommitteeIndex,
                                                      slot: Slot,
                                                      aggregator: bool,
                                                      validator_pubkey: ValidatorPubKey,
                                                      slot_signature: ValidatorSig): bool

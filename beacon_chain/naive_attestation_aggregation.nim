import
  sequtils,
  ./spec/[datatypes, crypto, digest, helpers, validator],
  ./ssz

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
func get_slot_signature(state: BeaconState, slot: Slot, privkey: ValidatorPrivKey):
    ValidatorSig =
  # TODO privkey is int in spec, but bls_sign wants a ValidatorPrivKey
  let domain =
    get_domain(state, DOMAIN_BEACON_ATTESTER, compute_epoch_at_slot(slot))
  bls_sign(privkey, hash_tree_root(slot).data, domain)

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregation-selection
func is_aggregator(state: BeaconState, slot: Slot, index: uint64,
    slot_signature: ValidatorSig): bool =
  # TODO index is a CommitteeIndex, aka uint64
  var cache = get_empty_per_epoch_cache()

  let
    committee = get_beacon_committee(state, slot, index, cache)
    modulo = max(1, len(committee) div TARGET_AGGREGATORS_PER_COMMITTEE).uint64
  bytes_to_int(eth2hash(slot_signature.getBytes).data[0..7]) mod modulo == 0

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.2/specs/validator/0_beacon-chain-validator.md#aggregate-signature-1
func get_aggregate_signature(attestations: seq[Attestation]): ValidatorSig =
  let signatures = mapIt(attestations, it.signature)
  bls_aggregate_signatures(signatures)

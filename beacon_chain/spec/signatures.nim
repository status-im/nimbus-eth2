import
  ./crypto, ./digest, ./datatypes, ./helpers, ../ssz/merkleization

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#aggregation-selection
func get_slot_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    privkey: ValidatorPrivKey): ValidatorSig =
  let
    epoch = compute_epoch_at_slot(slot)
    domain = get_domain(
      fork, DOMAIN_SELECTION_PROOF, epoch, genesis_validators_root)
    signing_root = compute_signing_root(slot, domain)

  blsSign(privKey, signing_root.data)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#randao-reveal
func get_epoch_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch,
    privkey: ValidatorPrivKey): ValidatorSig =
  let
    domain = get_domain(fork, DOMAIN_RANDAO, epoch, genesis_validators_root)
    signing_root = compute_signing_root(epoch, domain)

  blsSign(privKey, signing_root.data)

func verify_epoch_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch,
    pubkey: ValidatorPubKey, signature: ValidatorSig): bool =
  let
    domain = get_domain(fork, DOMAIN_RANDAO, epoch, genesis_validators_root)
    signing_root = compute_signing_root(epoch, domain)

  blsVerify(pubkey, signing_root.data, signature)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#signature
func get_block_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    root: Eth2Digest, privkey: ValidatorPrivKey): ValidatorSig =
  let
    epoch = compute_epoch_at_slot(slot)
    domain = get_domain(
      fork, DOMAIN_BEACON_PROPOSER, epoch, genesis_validators_root)
    signing_root = compute_signing_root(root, domain)

  blsSign(privKey, signing_root.data)

func verify_block_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    blck: Eth2Digest | BeaconBlock | BeaconBlockHeader, pubkey: ValidatorPubKey,
    signature: ValidatorSig): bool =
  let
    epoch = compute_epoch_at_slot(slot)
    domain = get_domain(
      fork, DOMAIN_BEACON_PROPOSER, epoch, genesis_validators_root)
    signing_root = compute_signing_root(blck, domain)

  blsVerify(pubKey, signing_root.data, signature)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#broadcast-aggregate
func get_aggregate_and_proof_signature*(fork: Fork, genesis_validators_root: Eth2Digest,
                                        aggregate_and_proof: AggregateAndProof,
                                        privKey: ValidatorPrivKey): ValidatorSig =
  let
    epoch = compute_epoch_at_slot(aggregate_and_proof.aggregate.data.slot)
    domain = get_domain(
      fork, DOMAIN_AGGREGATE_AND_PROOF, epoch, genesis_validators_root)
    signing_root = compute_signing_root(aggregate_and_proof, domain)

  blsSign(privKey, signing_root.data)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#aggregate-signature
func get_attestation_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    attestation_data: AttestationData,
    privkey: ValidatorPrivKey): ValidatorSig =
  let
    epoch = attestation_data.target.epoch
    domain = get_domain(
      fork, DOMAIN_BEACON_ATTESTER, epoch, genesis_validators_root)
    signing_root = compute_signing_root(attestation_data, domain)

  blsSign(privKey, signing_root.data)

func verify_attestation_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    attestation_data: AttestationData,
    pubkeys: openArray[ValidatorPubKey],
    signature: ValidatorSig): bool =
  let
    epoch = attestation_data.target.epoch
    domain = get_domain(
      fork, DOMAIN_BEACON_ATTESTER, epoch, genesis_validators_root)
    signing_root = compute_signing_root(attestation_data, domain)

  blsFastAggregateVerify(pubkeys, signing_root.data, signature)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#deposits
func get_deposit_signature*(
    deposit: DepositData,
    privkey: ValidatorPrivKey): ValidatorSig =

  let
    deposit_message = deposit.getDepositMessage()
    # Fork-agnostic domain since deposits are valid across forks
    domain = compute_domain(DOMAIN_DEPOSIT)
    signing_root = compute_signing_root(deposit_message, domain)

  blsSign(privKey, signing_root.data)

func verify_deposit_signature*(deposit: DepositData): bool =
  let
    deposit_message = deposit.getDepositMessage()
    # Fork-agnostic domain since deposits are valid across forks
    domain = compute_domain(DOMAIN_DEPOSIT)
    signing_root = compute_signing_root(deposit_message, domain)

  blsVerify(deposit.pubkey, signing_root.data, deposit.signature)

func verify_voluntary_exit_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    voluntary_exit: VoluntaryExit,
    pubkey: ValidatorPubKey, signature: ValidatorSig): bool =
  let
    domain = get_domain(
      fork, DOMAIN_VOLUNTARY_EXIT, voluntary_exit.epoch, genesis_validators_root)
    signing_root = compute_signing_root(voluntary_exit, domain)

  blsVerify(pubkey, signing_root.data, signature)

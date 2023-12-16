# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Signature production and verification for spec types - for every type of
## signature, there are 3 functions:
## * `compute_*_signing_root` - reduce message to the data that will be signed
## * `get_*_signature` - sign the signing root with a private key
## * `verify_*_signature` - verify a signature produced by `get_*_signature`
##
## See also `signatures_batch` for batch verification versions of these
## functions.

import
  ./datatypes/[phase0, altair, bellatrix], ./helpers, ./eth2_merkleization

from ./datatypes/capella import BLSToExecutionChange, SignedBLSToExecutionChange

export phase0, altair

template withTrust(sig: SomeSig, body: untyped): bool =
  when sig is TrustedSig:
    true
  else:
    body

func getDepositMessage(depositData: DepositData): DepositMessage =
  DepositMessage(
    pubkey: depositData.pubkey,
    amount: depositData.amount,
    withdrawal_credentials: depositData.withdrawal_credentials)

func compute_slot_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot
    ): Eth2Digest =
  let
    epoch = epoch(slot)
    domain = get_domain(
      fork, DOMAIN_SELECTION_PROOF, epoch, genesis_validators_root)
  compute_signing_root(slot, domain)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.3/specs/phase0/validator.md#aggregation-selection
func get_slot_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_slot_signing_root(
    fork, genesis_validators_root, slot)

  blsSign(privkey, signing_root.data)

func compute_epoch_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch
    ): Eth2Digest =
  let domain = get_domain(fork, DOMAIN_RANDAO, epoch, genesis_validators_root)
  compute_signing_root(epoch, domain)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#randao-reveal
func get_epoch_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_epoch_signing_root(
    fork, genesis_validators_root, epoch)

  blsSign(privkey, signing_root.data)

proc verify_epoch_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  withTrust(signature):
    let signing_root = compute_epoch_signing_root(
      fork, genesis_validators_root, epoch)

    blsVerify(pubkey, signing_root.data, signature)

func compute_block_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    blck: Eth2Digest | SomeForkyBeaconBlock | BeaconBlockHeader |
          # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signing
          capella_mev.BlindedBeaconBlock): Eth2Digest =
  let
    epoch = epoch(slot)
    domain = get_domain(
      fork, DOMAIN_BEACON_PROPOSER, epoch, genesis_validators_root)
  compute_signing_root(blck, domain)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#signature
func get_block_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    root: Eth2Digest, privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_block_signing_root(
    fork, genesis_validators_root, slot, root)

  blsSign(privkey, signing_root.data)

proc verify_block_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    blck: Eth2Digest | SomeForkyBeaconBlock | BeaconBlockHeader,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  withTrust(signature):
    let
      signing_root = compute_block_signing_root(
        fork, genesis_validators_root, slot, blck)

    blsVerify(pubkey, signing_root.data, signature)

func compute_aggregate_and_proof_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    aggregate_and_proof: AggregateAndProof): Eth2Digest =
  let
    epoch = epoch(aggregate_and_proof.aggregate.data.slot)
    domain = get_domain(
      fork, DOMAIN_AGGREGATE_AND_PROOF, epoch, genesis_validators_root)
  compute_signing_root(aggregate_and_proof, domain)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#broadcast-aggregate
func get_aggregate_and_proof_signature*(fork: Fork, genesis_validators_root: Eth2Digest,
                                        aggregate_and_proof: AggregateAndProof,
                                        privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_aggregate_and_proof_signing_root(
    fork, genesis_validators_root, aggregate_and_proof)

  blsSign(privkey, signing_root.data)

proc verify_aggregate_and_proof_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    aggregate_and_proof: AggregateAndProof,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  withTrust(signature):
    let signing_root = compute_aggregate_and_proof_signing_root(
      fork, genesis_validators_root, aggregate_and_proof)

    blsVerify(pubkey, signing_root.data, signature)

func compute_attestation_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    attestation_data: AttestationData): Eth2Digest =
  let
    epoch = attestation_data.target.epoch
    domain = get_domain(
      fork, DOMAIN_BEACON_ATTESTER, epoch, genesis_validators_root)
  compute_signing_root(attestation_data, domain)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#aggregate-signature
func get_attestation_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    attestation_data: AttestationData,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_attestation_signing_root(
    fork, genesis_validators_root, attestation_data)

  blsSign(privkey, signing_root.data)

proc verify_attestation_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    attestation_data: AttestationData,
    pubkeys: auto, signature: SomeSig): bool =
  withTrust(signature):
    let signing_root = compute_attestation_signing_root(
      fork, genesis_validators_root, attestation_data)

    blsFastAggregateVerify(pubkeys, signing_root.data, signature)

func compute_deposit_signing_root(
    version: Version,
    deposit_message: DepositMessage): Eth2Digest =
  let
    # Fork-agnostic domain since deposits are valid across forks
    domain = compute_domain(DOMAIN_DEPOSIT, version)
  compute_signing_root(deposit_message, domain)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#deposits
func get_deposit_signature*(preset: RuntimeConfig,
                            deposit: DepositData,
                            privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_deposit_signing_root(
    preset.GENESIS_FORK_VERSION, deposit.getDepositMessage())

  blsSign(privkey, signing_root.data)

func get_deposit_signature*(message: DepositMessage, version: Version,
                            privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_deposit_signing_root(version, message)

  blsSign(privkey, signing_root.data)

proc verify_deposit_signature(preset: RuntimeConfig,
                              deposit: DepositData,
                              pubkey: CookedPubKey): bool =
  let
    deposit_message = deposit.getDepositMessage()
    signing_root = compute_deposit_signing_root(
      preset.GENESIS_FORK_VERSION, deposit_message)

  blsVerify(pubkey, signing_root.data, deposit.signature)

proc verify_deposit_signature*(preset: RuntimeConfig,
                               deposit: DepositData): bool =
  # Deposits come with compressed public keys; uncompressing them is expensive.
  # `blsVerify` fills an internal cache when using `ValidatorPubKey`.
  # To avoid filling this cache unnecessarily, uncompress explicitly here.
  let pubkey = deposit.pubkey.load().valueOr:  # Loading the pubkey is slow!
    return false
  verify_deposit_signature(preset, deposit, pubkey)

func compute_voluntary_exit_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    voluntary_exit: VoluntaryExit): Eth2Digest =
  let
    epoch = voluntary_exit.epoch
    domain = get_domain(
      fork, DOMAIN_VOLUNTARY_EXIT, epoch, genesis_validators_root)
  compute_signing_root(voluntary_exit, domain)

func get_voluntary_exit_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    voluntary_exit: VoluntaryExit,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_voluntary_exit_signing_root(
    fork, genesis_validators_root, voluntary_exit)

  blsSign(privkey, signing_root.data)

proc verify_voluntary_exit_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    voluntary_exit: VoluntaryExit,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  withTrust(signature):
    let signing_root = compute_voluntary_exit_signing_root(
      fork, genesis_validators_root, voluntary_exit)

    blsVerify(pubkey, signing_root.data, signature)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#prepare-sync-committee-message
func compute_sync_committee_message_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, beacon_block_root: Eth2Digest): Eth2Digest =
  let domain = get_domain(
    fork, DOMAIN_SYNC_COMMITTEE, slot.epoch, genesis_validators_root)
  compute_signing_root(beacon_block_root, domain)

func get_sync_committee_message_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, beacon_block_root: Eth2Digest,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_sync_committee_message_signing_root(
    fork, genesis_validators_root, slot, beacon_block_root)

  blsSign(privkey, signing_root.data)

proc verify_sync_committee_message_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, beacon_block_root: Eth2Digest,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  let signing_root = compute_sync_committee_message_signing_root(
    fork, genesis_validators_root, slot, beacon_block_root)

  blsVerify(pubkey, signing_root.data, signature)

proc verify_sync_committee_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, beacon_block_root: Eth2Digest,
    pubkeys: auto, signature: SomeSig): bool =
  let signing_root = compute_sync_committee_message_signing_root(
    fork, genesis_validators_root, slot, beacon_block_root)

  blsFastAggregateVerify(pubkeys, signing_root.data, signature)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#aggregation-selection
func compute_sync_committee_selection_proof_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, subcommittee_index: SyncSubcommitteeIndex): Eth2Digest =
  let
    domain = get_domain(fork, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                        slot.epoch, genesis_validators_root)
    signing_data = SyncAggregatorSelectionData(
      slot: slot,
      subcommittee_index: uint64 subcommittee_index)
  compute_signing_root(signing_data, domain)

func get_sync_committee_selection_proof*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, subcommittee_index: SyncSubcommitteeIndex,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_sync_committee_selection_proof_signing_root(
    fork, genesis_validators_root, slot, subcommittee_index)

  blsSign(privkey, signing_root.data)

proc verify_sync_committee_selection_proof*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, subcommittee_index: SyncSubcommitteeIndex,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  withTrust(signature):
    let signing_root = compute_sync_committee_selection_proof_signing_root(
      fork, genesis_validators_root, slot, subcommittee_index)

    blsVerify(pubkey, signing_root.data, signature)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#signature
func compute_contribution_and_proof_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    msg: ContributionAndProof): Eth2Digest =
  let domain = get_domain(fork, DOMAIN_CONTRIBUTION_AND_PROOF,
                          msg.contribution.slot.epoch,
                          genesis_validators_root)
  compute_signing_root(msg, domain)

proc get_contribution_and_proof_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    msg: ContributionAndProof,
    privkey: ValidatorPrivKey): CookedSig =
  let signing_root = compute_contribution_and_proof_signing_root(
    fork, genesis_validators_root, msg)

  blsSign(privkey, signing_root.data)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#aggregation-selection
func is_sync_committee_aggregator*(signature: ValidatorSig): bool =
  let
    signatureDigest = eth2digest(signature.blob)
    modulo = max(1'u64, (SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT) div TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
  bytes_to_uint64(signatureDigest.data.toOpenArray(0, 7)) mod modulo == 0

proc verify_contribution_and_proof_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    msg: ContributionAndProof,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  let signing_root = compute_contribution_and_proof_signing_root(
    fork, genesis_validators_root, msg)

  blsVerify(pubkey, signing_root.data, signature)

# https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signing
func compute_builder_signing_root(
    fork: Fork,
    msg: capella_mev.BuilderBid | deneb_mev.BuilderBid |
         ValidatorRegistrationV1): Eth2Digest =
  # Uses genesis fork version regardless
  doAssert fork.current_version == fork.previous_version

  let domain = get_domain(
    fork, DOMAIN_APPLICATION_BUILDER, GENESIS_EPOCH, ZERO_HASH)
  compute_signing_root(msg, domain)

proc get_builder_signature*(
    fork: Fork, msg: ValidatorRegistrationV1, privkey: ValidatorPrivKey):
    CookedSig =
  let signing_root = compute_builder_signing_root(fork, msg)
  blsSign(privkey, signing_root.data)

proc verify_builder_signature*(
    fork: Fork, msg: capella_mev.BuilderBid | deneb_mev.BuilderBid,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  let signing_root = compute_builder_signing_root(fork, msg)
  blsVerify(pubkey, signing_root.data, signature)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#new-process_bls_to_execution_change
func compute_bls_to_execution_change_signing_root*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: BLSToExecutionChange): Eth2Digest =
  # So the epoch doesn't matter when calling get_domain
  doAssert genesisFork.previous_version == genesisFork.current_version

  # Fork-agnostic domain since address changes are valid across forks
  let domain = get_domain(
    genesisFork, DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_EPOCH,
    genesis_validators_root)
  compute_signing_root(msg, domain)

proc get_bls_to_execution_change_signature*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: BLSToExecutionChange, privkey: ValidatorPrivKey):
    CookedSig =
  let signing_root = compute_bls_to_execution_change_signing_root(
    genesisFork, genesis_validators_root, msg)
  blsSign(privkey, signing_root.data)

proc verify_bls_to_execution_change_signature*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: SignedBLSToExecutionChange,
    pubkey: ValidatorPubKey | CookedPubKey, signature: SomeSig): bool =
  let signing_root = compute_bls_to_execution_change_signing_root(
    genesisFork, genesis_validators_root, msg.message)
  blsVerify(pubkey, signing_root.data, signature)

# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## This module contains signature verification helpers corresponding to those
## in signatures.nim, for use with signature sets / batch signature verification
## The functions follow the same structure and use the same arguments, except
## that the flow is split into separate collection and verification steps.

import
  # Status lib
  blscurve,
  stew/[byteutils, results],
  taskpools,
  bearssl/rand,
  # Internal
  "."/[helpers, beaconstate, forks, signatures],
  "."/datatypes/[altair, bellatrix, phase0]

export results, rand, altair, phase0, taskpools, signatures

type
  TaskPoolPtr* = Taskpool

  BatchVerifier* = object
    sigVerifCache*: BatchedBLSVerifierCache
      ## A cache for batch BLS signature verification contexts
    rng*: ref HmacDrbgContext
      ## A reference to the Nimbus application-wide RNG
    taskpool*: TaskPoolPtr

proc init*(
    T: type BatchVerifier, rng: ref HmacDrbgContext,
    taskpool: TaskPoolPtr): BatchVerifier =
  BatchVerifier(
    sigVerifCache: BatchedBLSVerifierCache.init(taskpool),
    rng: rng,
    taskpool: taskpool,
  )

proc new*(
    T: type BatchVerifier, rng: ref HmacDrbgContext,
    taskpool: TaskPoolPtr): ref BatchVerifier =
  (ref BatchVerifier)(
    sigVerifCache: BatchedBLSVerifierCache.init(taskpool),
    rng: rng,
    taskpool: taskpool,
  )

func `$`*(s: SignatureSet): string =
  "(pubkey: 0x" & s.pubkey.toHex() &
    ", signing_root: 0x" & s.message.toHex() &
    ", signature: 0x" & s.signature.toHex() & ')'

# Important:
#   - Due to lazy loading, when we do crypto verification
#     and only then state-transition verification,
#     there is no guarantee that pubkeys and signatures received are valid
#     unlike when Nimbus did eager loading which ensured they were correct beforehand

func init(T: type SignatureSet,
    pubkey: CookedPubKey, signing_root: Eth2Digest,
    signature: CookedSig): T =
  ## Add a new signature set triplet (pubkey, message, signature)
  ## to a collection of signature sets for batch verification.
  (
    blscurve.PublicKey(pubkey),
    signing_root.data,
    blscurve.Signature(signature)
  )

func aggregateAttesters(
      validatorIndices: openArray[uint64|ValidatorIndex],
      validatorKeys: auto,
     ): Result[CookedPubKey, cstring] =
  if validatorIndices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Consensus specs require at least one attesting index in attestation
    # - https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return err("aggregateAttesters: no attesting indices")

  let
    firstKey = validatorKeys.load(validatorIndices[0]).valueOr:
      return err("aggregateAttesters: invalid attesting index")

  var attestersAgg{.noinit.}: AggregatePublicKey

  attestersAgg.init(firstKey)
  for i in 1 ..< validatorIndices.len:
    let key = validatorKeys.load(validatorIndices[i]).valueOr:
      return err("aggregateAttesters: invalid attesting index")
    attestersAgg.aggregate(key)

  ok(finish(attestersAgg))

func aggregateAttesters(
      validatorIndices: openArray[uint64|ValidatorIndex],
      bits: auto,
      validatorKeys: auto,
     ): Result[CookedPubKey, cstring] =
  if validatorIndices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Consensus specs require at least one attesting index in attestation
    # - https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return err("aggregateAttesters: no attesting indices")

  var attestersAgg{.noinit.}: AggregatePublicKey

  var inited = false
  for i in 0..<bits.len:
    if bits[i]:
      let key = validatorKeys.load(validatorIndices[i]).valueOr:
        return err("aggregateAttesters: invalid attesting index")
      if inited:
        attestersAgg.aggregate(key)
      else:
        attestersAgg = AggregatePublicKey.init(key)
        inited = true

  if not inited:
    return err("aggregateAttesters:no attesting indices")

  ok(finish(attestersAgg))

# Public API
# ------------------------------------------------------

# See also: verify_slot_signature
func slot_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_slot_signing_root(
    fork, genesis_validators_root, slot)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_epoch_signature
func epoch_signature_set*(
   fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_epoch_signing_root(
    fork, genesis_validators_root, epoch)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_block_signature
func block_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    blck: Eth2Digest | SomeForkyBeaconBlock | BeaconBlockHeader,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_block_signing_root(
    fork, genesis_validators_root, slot, blck)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_aggregate_and_proof_signature
func aggregate_and_proof_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    aggregate_and_proof: AggregateAndProof,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_aggregate_and_proof_signing_root(
    fork, genesis_validators_root, aggregate_and_proof)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_attestation_signature
func attestation_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    attestation_data: AttestationData,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_attestation_signing_root(
    fork, genesis_validators_root, attestation_data)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_voluntary_exit_signature
func voluntary_exit_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    voluntary_exit: VoluntaryExit,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_voluntary_exit_signing_root(
    fork, genesis_validators_root, voluntary_exit)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_sync_committee_message_signature
func sync_committee_message_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, block_root: Eth2Digest,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_sync_committee_message_signing_root(
    fork, genesis_validators_root, slot, block_root)

  SignatureSet.init(pubkey, signing_root, signature)

# See also: verify_sync_committee_selection_proof
func sync_committee_selection_proof_set*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    slot: Slot, subcommittee_index: SyncSubcommitteeIndex,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_sync_committee_selection_proof_signing_root(
    fork, genesis_validators_root, slot, subcommittee_index)

  SignatureSet.init(pubkey, signing_root, signature)

func contribution_and_proof_signature_set*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    msg: ContributionAndProof,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_contribution_and_proof_signing_root(
    fork, genesis_validators_root, msg)

  SignatureSet.init(pubkey, signing_root, signature)

func bls_to_execution_change_signature_set*(
    genesisFork: Fork, genesis_validators_root: Eth2Digest,
    msg: BLSToExecutionChange,
    pubkey: CookedPubKey, signature: CookedSig): SignatureSet =
  let signing_root = compute_bls_to_execution_change_signing_root(
    genesisFork, genesis_validators_root, msg)

  SignatureSet.init(pubkey, signing_root, signature)

proc collectSignatureSets*(
       sigs: var seq[SignatureSet],
       signed_block: ForkySignedBeaconBlock,
       validatorKeys: openArray[ImmutableValidatorData2],
       state: ForkedHashedBeaconState,
       genesis_fork: Fork,
       capella_fork: Fork,
       cache: var StateCache): Result[void, cstring] =
  ## Collect all signature verifications that process_block would normally do
  ## except deposits, in one go.
  ##
  ## This includes
  ## - Block proposer
  ## - Randao Reaveal
  ## - Proposer slashings
  ## - Attester slashings
  ## - Attestations
  ## - VoluntaryExits
  ## - SyncCommittee (Altair+)
  ## - BLS to execution changes (Capella+)
  ##
  ## We do not include deposits as they can be invalid while still leaving the
  ## block valid

  # Metadata
  # ----------------------------------------------------
  mixin load

  let
    fork = getStateField(state, fork)
    genesis_validators_root = getStateField(state, genesis_validators_root)
    proposer_index = signed_block.message.proposer_index
    proposer_key = validatorKeys.load(proposer_index).valueOr:
      return err("collectSignatureSets: invalid proposer index")
    epoch = signed_block.message.slot.epoch()

  doAssert genesis_fork.previous_version == genesis_fork.current_version

  # 1. Block proposer
  # ----------------------------------------------------
  sigs.add block_signature_set(
    fork, genesis_validators_root,
    signed_block.message.slot, signed_block.root,
    proposer_key, signed_block.signature.load.valueOr do:
      return err("collectSignatureSets: cannot load signature"))

  # 2. Randao Reveal
  # ----------------------------------------------------
  sigs.add epoch_signature_set(
    fork, genesis_validators_root, epoch, proposer_key,
    signed_block.message.body.randao_reveal.load().valueOr do:
      return err("collectSignatureSets: cannot load randao"))

  # 3. Proposer slashings
  # ----------------------------------------------------
  # Denial-of-service:
  #   SSZ deserialization guarantees that blocks received from random sources
  #   including peer or RPC
  #   have at most MAX_PROPOSER_SLASHINGS proposer slashings.
  for i in 0 ..< signed_block.message.body.proposer_slashings.len:
    # don't use "items" for iterating over large type
    # due to https://github.com/nim-lang/Nim/issues/14421
    # fixed in 1.4.2

    # Alias
    template slashing: untyped = signed_block.message.body.proposer_slashings[i]

    # Proposed block 1
    block:
      let
        header = slashing.signed_header_1
        key = validatorKeys.load(header.message.proposer_index).valueOr:
          return err("collectSignatureSets: invalid slashing proposer index 1")

      sigs.add block_signature_set(
        fork, genesis_validators_root, header.message.slot, header.message,
        key, header.signature.load().valueOr do:
          return err(
            "collectSignatureSets: cannot load proposer slashing 1 signature"))

    # Conflicting block 2
    block:
      let
        header = slashing.signed_header_2
        key = validatorKeys.load(header.message.proposer_index).valueOr:
          return err("collectSignatureSets: invalid slashing proposer index 2")

      sigs.add block_signature_set(
        fork, genesis_validators_root, header.message.slot, header.message,
        key, header.signature.load().valueOr do:
          return err(
            "collectSignatureSets: cannot load proposer slashing 2 signature"))

  # 4. Attester slashings
  # ----------------------------------------------------
  # Denial-of-service:
  #   SSZ deserialization guarantees that blocks received from random sources
  #   including peer or RPC
  #   have at most MAX_ATTESTER_SLASHINGS attester slashings.
  for i in 0 ..< signed_block.message.body.attester_slashings.len:
    # don't use "items" for iterating over large type
    # due to https://github.com/nim-lang/Nim/issues/14421
    # fixed in 1.4.2

    # Alias
    template slashing: untyped = signed_block.message.body.attester_slashings[i]

    # Attestation 1
    block:
      let
        key = ? aggregateAttesters(
          slashing.attestation_1.attesting_indices.asSeq(), validatorKeys)
        sig = slashing.attestation_1.signature.load().valueOr:
          return err("Invalid attestation slashing signature 1")
      sigs.add attestation_signature_set(
        fork, genesis_validators_root, slashing.attestation_1.data, key, sig)

    # Conflicting attestation 2
    block:
      let
        key = ? aggregateAttesters(
          slashing.attestation_2.attesting_indices.asSeq(), validatorKeys)
        sig = slashing.attestation_2.signature.load().valueOr:
          return err("Invalid attestation slashing signature 2")
      sigs.add attestation_signature_set(
        fork, genesis_validators_root, slashing.attestation_2.data, key, sig)

  # 5. Attestations
  # ----------------------------------------------------
  # Denial-of-service:
  #   SSZ deserialization guarantees that blocks received from random sources
  #   including peer or RPC
  #   have at most MAX_ATTESTATIONS attestations.
  for i in 0 ..< signed_block.message.body.attestations.len:
    # don't use "items" for iterating over large type
    # due to https://github.com/nim-lang/Nim/issues/14421
    # fixed in 1.4.2
    template attestation: untyped = signed_block.message.body.attestations[i]

    let
      key = ? aggregateAttesters(
        get_attesting_indices(
          state, attestation.data, attestation.aggregation_bits, cache),
        validatorKeys)
      sig = attestation.signature.load().valueOr:
        return err("Invalid attestation signature")

    sigs.add attestation_signature_set(
      fork, genesis_validators_root, attestation.data, key, sig)

  # 6. VoluntaryExits
  # ----------------------------------------------------
  # Denial-of-service:
  #   SSZ deserialization guarantees that blocks received from random sources
  #   including peer or RPC
  #   have at most MAX_VOLUNTARY_EXITS voluntary exits.
  for i in 0 ..< signed_block.message.body.voluntary_exits.len:
    # don't use "items" for iterating over large type
    # due to https://github.com/nim-lang/Nim/issues/14421
    # fixed in 1.4.2
    template volex: untyped = signed_block.message.body.voluntary_exits[i]
    let key = validatorKeys.load(volex.message.validator_index).valueOr:
      return err("collectSignatureSets: invalid voluntary exit")

    sigs.add voluntary_exit_signature_set(
      # https://eips.ethereum.org/EIPS/eip-7044
      # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/deneb/beacon-chain.md#modified-process_voluntary_exit
      (if state.kind >= ConsensusFork.Capella:
         capella_fork
       else:
         fork),
      genesis_validators_root, volex.message, key,
      volex.signature.load.valueOr do:
        return err(
          "collectSignatureSets: cannot load voluntary exit signature"))

  block:
    when signed_block is phase0.SignedBeaconBlock:
      discard
    else:
      # 7. SyncAggregate
      # ----------------------------------------------------
      withState(state):
        when consensusFork >= ConsensusFork.Altair:
          if signed_block.message.body.sync_aggregate.sync_committee_bits.isZeros:
            if signed_block.message.body.sync_aggregate.sync_committee_signature != ValidatorSig.infinity():
              return err("collectSignatureSets: empty sync aggregates need signature of point at infinity")
          else:
            let
              current_sync_committee =
                forkyState.data.get_sync_committee_cache(cache).current_sync_committee
              previous_slot = max(forkyState.data.slot, Slot(1)) - 1
              beacon_block_root = get_block_root_at_slot(forkyState.data, previous_slot)
              pubkey = ? aggregateAttesters(
                current_sync_committee,
                signed_block.message.body.sync_aggregate.sync_committee_bits,
                validatorKeys)

            sigs.add sync_committee_message_signature_set(
              fork, genesis_validators_root, previous_slot, beacon_block_root,
              pubkey,
              signed_block.message.body.sync_aggregate.sync_committee_signature.load().valueOr do:
                return err("collectSignatureSets: cannot load signature"))

  block:
    # 8. BLS to execution changes
    when typeof(signed_block).kind >= ConsensusFork.Capella:
      withState(state):
        when consensusFork >= ConsensusFork.Capella:
          for bls_change in signed_block.message.body.bls_to_execution_changes:
            let sig = bls_change.signature.load.valueOr:
              return err("collectSignatureSets: cannot load BLS to execution change signature")

            # Otherwise, expensive loadWithCache can be spammed with irrelevant pubkeys
            ? check_bls_to_execution_change(
              genesis_fork, forkyState.data, bls_change, {skipBlsValidation})

            let validator_pubkey =
              bls_change.message.from_bls_pubkey.loadWithCache.valueOr:
                return err("collectSignatureSets: cannot load BLS to execution change pubkey")

            sigs.add bls_to_execution_change_signature_set(
              genesis_fork, genesis_validators_root, bls_change.message,
              validator_pubkey, sig)

  ok()

proc batchVerify*(verifier: var BatchVerifier, sigs: openArray[SignatureSet]): bool =
  let bytes = verifier.rng[].generate(array[32, byte])

  verifier.taskpool.batchVerify(verifier.sigVerifCache, sigs, bytes)

# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Status lib
  blscurve,
  stew/byteutils,
  # Internal
  ../ssz/merkleization,
  ./crypto, ./datatypes, ./helpers, ./presets,
  ./beaconstate, ./digest

export SignatureSet, BatchedBLSVerifierCache, batchVerify, batchVerifySerial, batchVerifyParallel

func `$`*(s: SignatureSet): string =
  "(pubkey: 0x" & s.pubkey.toHex() &
    ", signing_root: 0x" & s.message.toHex() &
    ", signature: 0x" & s.signature.toHex() & ')'

# Important:
#   - Due to lazy loading, when we do crypto verification
#     and only then state-transition verification,
#     there is no guarantee that pubkeys and signatures received are valid
#     unlike when Nimbus did eager loading which ensured they were correct beforehand

template loadOrExitFalse(signature: ValidatorSig): blscurve.Signature =
  ## Load a BLS signature from a raw signature
  ## Exists the **caller** with false if the signature is invalid
  let sig = signature.load()
  if sig.isNone:
    return false # this exits the calling scope, as templates are inlined.
  sig.unsafeGet()

template loadWithCacheOrExitFalse(pubkey: ValidatorPubKey): blscurve.PublicKey =
  ## Load a BLS signature from a raw public key
  ## Exists the **caller** with false if the public key is invalid
  let pk = pubkey.loadWithCache()
  if pk.isNone:
    return false # this exits the calling scope, as templates are inlined.
  pk.unsafeGet()

func addSignatureSet[T](
      sigs: var seq[SignatureSet],
      pubkey: blscurve.PublicKey,
      sszObj: T,
      signature: ValidatorSig,
      genesis_validators_root: Eth2Digest,
      fork: Fork,
      epoch: Epoch,
      domain: DomainType): bool {.raises: [Defect].}=
  ## Add a new signature set triplet (pubkey, message, signature)
  ## to a collection of signature sets for batch verification.
  ## Can return false if `signature` wasn't deserialized to a valid BLS signature.
  let signing_root = compute_signing_root(
      sszObj,
      get_domain(
        fork, domain,
        epoch,
        genesis_validators_root
      )
    ).data

  sigs.add((
    pubkey,
    signing_root,
    signature.loadOrExitFalse()
  ))

  return true

proc aggregateAttesters(
      aggPK: var blscurve.PublicKey,
      attestation: IndexedAttestation,
      state: BeaconState
     ): bool =
  doAssert attestation.attesting_indices.len > 0
  var attestersAgg{.noInit.}: AggregatePublicKey
  attestersAgg.init(state.validators[attestation.attesting_indices[0]]
                         .pubkey.loadWithCacheOrExitFalse())
  for i in 1 ..< attestation.attesting_indices.len:
    attestersAgg.aggregate(state.validators[attestation.attesting_indices[i]]
                                .pubkey.loadWithCacheOrExitFalse())
  aggPK.finish(attestersAgg)
  return true

proc aggregateAttesters(
      aggPK: var blscurve.PublicKey,
      attestation: IndexedAttestation,
      epochRef: auto
     ): bool =
  mixin validator_keys

  doAssert attestation.attesting_indices.len > 0
  var attestersAgg{.noInit.}: AggregatePublicKey
  attestersAgg.init(epochRef.validator_keys[attestation.attesting_indices[0]]
                         .pubkey.loadWithCacheOrExitFalse())
  for i in 1 ..< attestation.attesting_indices.len:
    attestersAgg.aggregate(epochRef.validator_keys[attestation.attesting_indices[i]]
                                .pubkey.loadWithCacheOrExitFalse())
  aggPK.finish(attestersAgg)
  return true

proc addIndexedAttestation(
      sigs: var seq[SignatureSet],
      attestation: IndexedAttestation,
      state: BeaconState
     ): bool =
  ## Add an indexed attestation for batched BLS verification
  ## purposes
  ## This only verifies cryptography, checking that
  ## the indices are sorted and unique is not checked for example.
  ##
  ## Returns true if the indexed attestations was added to the batching buffer
  ## Returns false if saniy checks failed (non-empty, keys are valid)
  if attestation.attesting_indices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Eth2 spec requires at least one attesting indice in slashing
    # - https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return false

  var aggPK {.noInit.}: blscurve.PublicKey
  if not aggPK.aggregateAttesters(attestation, state):
    return false

  if not sigs.addSignatureSet(
          aggPK,
          attestation.data,
          attestation.signature,
          state.genesis_validators_root,
          state.fork,
          attestation.data.target.epoch,
          DOMAIN_BEACON_ATTESTER):
    return false
  return true

proc addAttestation(
      sigs: var seq[SignatureSet],
      attestation: Attestation,
      state: BeaconState,
      cache: var StateCache
     ): bool =
  result = false

  var attestersAgg{.noInit.}: AggregatePublicKey
  for valIndex in state.get_attesting_indices(
                    attestation.data,
                    attestation.aggregation_bits,
                    cache
                  ):
    if not result: # first iteration
      attestersAgg.init(state.validators[valIndex]
                             .pubkey.loadWithCacheOrExitFalse())
      result = true
    else:
      attestersAgg.aggregate(state.validators[valIndex]
                                  .pubkey.loadWithCacheOrExitFalse())

  if not result:
    # There was no attesters
    return false

  var attesters{.noinit.}: blscurve.PublicKey
  attesters.finish(attestersAgg)

  if not sigs.addSignatureSet(
          attesters,
          attestation.data,
          attestation.signature,
          state.genesis_validators_root,
          state.fork,
          attestation.data.target.epoch,
          DOMAIN_BEACON_ATTESTER):
    return false
  return true

# Public API
# ------------------------------------------------------

proc addAttestation*(
      sigs: var seq[SignatureSet],
      fork: Fork, genesis_validators_root: Eth2Digest,
      epochRef: auto,
      attestation: Attestation
     ): bool =
  ## Add an attestation for batched BLS verification
  ## purposes
  ## This only verifies cryptography
  ##
  ## Returns true if the attestation was added to the batching buffer
  ## Returns false if saniy checks failed (non-empty, keys are valid)
  ## In that case the seq[SignatureSet] is unmodified
  mixin get_attesting_indices, validator_keys, pubkey

  result = false

  var attestersAgg{.noInit.}: AggregatePublicKey
  for valIndex in epochRef.get_attesting_indices(
                    attestation.data,
                    attestation.aggregation_bits):
    if not result: # first iteration
      attestersAgg.init(epochRef.validator_keys[valIndex]
                                .loadWithCacheOrExitFalse())
      result = true
    else:
      attestersAgg.aggregate(epochRef.validator_keys[valIndex]
                                     .loadWithCacheOrExitFalse())

  if not result:
    # There was no attesters
    return false

  var attesters{.noinit.}: blscurve.PublicKey
  attesters.finish(attestersAgg)

  if not sigs.addSignatureSet(
          attesters,
          attestation.data,
          attestation.signature,
          genesis_validators_root,
          fork,
          attestation.data.target.epoch,
          DOMAIN_BEACON_ATTESTER):
    return false
  return true

proc addIndexedAttestation*(
      sigs: var seq[SignatureSet],
      fork: Fork, genesis_validators_root: Eth2Digest,
      epochRef: auto,
      attestation: IndexedAttestation,
     ): bool =
  ## Add an indexed attestation for batched BLS verification
  ## purposes
  ## This only verifies cryptography, checking that
  ## the indices are sorted and unique is not checked for example.
  ##
  ## Returns true if the indexed attestations was added to the batching buffer
  ## Returns false if saniy checks failed (non-empty, keys are valid)
  ## In that case the seq[SignatureSet] is unmodified
  if attestation.attesting_indices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Eth2 spec requires at least one attesting indice in slashing
    # - https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return false

  var aggPK {.noInit.}: blscurve.PublicKey
  if not aggPK.aggregateAttesters(attestation, epochRef):
    return false

  if not sigs.addSignatureSet(
          aggPK,
          attestation.data,
          attestation.signature,
          genesis_validators_root,
          fork,
          attestation.data.target.epoch,
          DOMAIN_BEACON_ATTESTER):
    return false
  return true

proc collectSignatureSets*(
       sigs: var seq[SignatureSet],
       signed_block: SignedBeaconBlock,
       state: BeaconState,
       cache: var StateCache): bool =
  ## Collect all signatures in a single signed block.
  ## This includes
  ## - Block proposer
  ## - Randao Reaveal
  ## - Proposer slashings
  ## - Attester slashings
  ## - Attestations
  ## - VoluntaryExits
  ##
  ## We do not include deposits as they can be invalid per protocol
  ## (secp256k1 signature instead of BLS)

  # Metadata
  # ----------------------------------------------------

  let
    proposer_index = signed_block.message.proposer_index
  if proposer_index >= state.validators.lenu64:
    return false

  let pubkey = state.validators[proposer_index]
                    .pubkey.loadWithCacheOrExitFalse()
  let epoch = signed_block.message.slot.compute_epoch_at_slot()

  # 1. Block proposer
  # ----------------------------------------------------
  if not sigs.addSignatureSet(
          pubkey,
          signed_block.message,
          signed_block.signature,
          state.genesis_validators_root,
          state.fork,
          epoch,
          DOMAIN_BEACON_PROPOSER):
    return false

  # 2. Randao Reveal
  # ----------------------------------------------------
  if not sigs.addSignatureSet(
          pubkey,
          epoch,
          signed_block.message.body.randao_reveal,
          state.genesis_validators_root,
          state.fork,
          epoch,
          DOMAIN_RANDAO):
    return false

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
      let header_1 = slashing.signed_header_1
      let proposer1 = state.validators[header_1.message.proposer_index]
      let epoch1 = header_1.message.slot.compute_epoch_at_slot()
      if not sigs.addSignatureSet(
              proposer1.pubkey.loadWithCacheOrExitFalse(),
              header_1.message,
              header_1.signature,
              state.genesis_validators_root,
              state.fork,
              epoch1,
              DOMAIN_BEACON_PROPOSER
            ):
        return false

    # Conflicting block 2
    block:
      let header_2 = slashing.signed_header_2
      let proposer2 = state.validators[header_2.message.proposer_index]
      let epoch2 = header_2.message.slot.compute_epoch_at_slot()
      if not sigs.addSignatureSet(
              proposer2.pubkey.loadWithCacheOrExitFalse(),
              header_2.message,
              header_2.signature,
              state.genesis_validators_root,
              state.fork,
              epoch2,
              DOMAIN_BEACON_PROPOSER
            ):
        return false

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
    if not sigs.addIndexedAttestation(
            slashing.attestation_1,
            state):
      return false

    # Conflicting attestation 2
    if not sigs.addIndexedAttestation(
            slashing.attestation_2,
            state):
      return false

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
    if not sigs.addAttestation(
            signed_block.message.body.attestations[i],
            state, cache):
      return false

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

    if not sigs.addSignatureSet(
            state.validators[volex.message.validator_index]
                 .pubkey.loadWithCacheOrExitFalse(),
            volex.message,
            volex.signature,
            state.genesis_validators_root,
            state.fork,
            volex.message.epoch,
            DOMAIN_VOLUNTARY_EXIT):
      return false

  return true

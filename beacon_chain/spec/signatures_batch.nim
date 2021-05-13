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

template loadOrExit(signature: ValidatorSig, failReturn: auto):
    CookedSig =
  ## Load a BLS signature from a raw signature
  ## Exits the **caller** with false if the signature is invalid
  let sig = signature.load()
  if sig.isNone:
    return failReturn # this exits the calling scope, as templates are inlined.
  sig.unsafeGet()

template loadWithCacheOrExit(pubkey: ValidatorPubKey, failReturn: auto):
    blscurve.PublicKey =
  ## Load a BLS signature from a raw public key
  ## Exits the **caller** with false if the public key is invalid
  let pk = pubkey.loadWithCache()
  if pk.isNone:
    return failReturn # this exits the calling scope, as templates are inlined.
  pk.unsafeGet()

func addSignatureSet[T](
      sigs: var seq[SignatureSet],
      pubkey: blscurve.PublicKey,
      sszObj: T,
      signature: CookedSig,
      genesis_validators_root: Eth2Digest,
      fork: Fork,
      epoch: Epoch,
      domain: DomainType) =
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
    blscurve.Signature(signature)
  ))

proc aggregateAttesters(
      aggPK: var blscurve.PublicKey,
      attestation: IndexedAttestation,
      state: BeaconState
     ): bool =
  doAssert attestation.attesting_indices.len > 0
  var attestersAgg{.noInit.}: AggregatePublicKey
  attestersAgg.init(state.validators[attestation.attesting_indices[0]]
                         .pubkey.loadWithCacheOrExit(false))
  for i in 1 ..< attestation.attesting_indices.len:
    attestersAgg.aggregate(state.validators[attestation.attesting_indices[i]]
                                .pubkey.loadWithCacheOrExit(false))
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
      state: StateData
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
  if not aggPK.aggregateAttesters(attestation, state.data.data):
    return false

  sigs.addSignatureSet(
          aggPK,
          attestation.data,
          attestation.signature.loadOrExit(false),
          getStateField(state, genesis_validators_root),
          getStateField(state, fork),
          attestation.data.target.epoch,
          DOMAIN_BEACON_ATTESTER)
  return true

proc addAttestation(
      sigs: var seq[SignatureSet],
      attestation: Attestation,
      state: StateData,
      cache: var StateCache
     ): bool =
  var inited = false
  var attestersAgg{.noInit.}: AggregatePublicKey
  for valIndex in state.data.data.get_attesting_indices(
                    attestation.data,
                    attestation.aggregation_bits,
                    cache
                  ):
    if not inited: # first iteration
      attestersAgg.init(getStateField(state, validators)[valIndex]
                             .pubkey.loadWithCacheOrExit(false))
      inited = true
    else:
      attestersAgg.aggregate(getStateField(state, validators)[valIndex]
                                  .pubkey.loadWithCacheOrExit(false))

  if not inited:
    # There were no attesters
    return false

  var attesters{.noinit.}: blscurve.PublicKey
  attesters.finish(attestersAgg)

  sigs.addSignatureSet(
          attesters,
          attestation.data,
          attestation.signature.loadOrExit(false),
          getStateField(state, genesis_validators_root),
          getStateField(state, fork),
          attestation.data.target.epoch,
          DOMAIN_BEACON_ATTESTER)

  true

# Public API
# ------------------------------------------------------

proc addAttestation*(
      sigs: var seq[SignatureSet],
      fork: Fork, genesis_validators_root: Eth2Digest,
      epochRef: auto,
      attestation: Attestation
     ): Option[CookedSig] =
  ## Add an attestation for batched BLS verification
  ## purposes
  ## This only verifies cryptography
  ##
  ## Returns true if the attestation was added to the batching buffer
  ## Returns false if sanity checks failed (non-empty, keys are valid)
  ## In that case the seq[SignatureSet] is unmodified
  mixin get_attesting_indices, validator_keys, pubkey

  var inited = false
  var attestersAgg{.noInit.}: AggregatePublicKey
  for valIndex in epochRef.get_attesting_indices(
                    attestation.data,
                    attestation.aggregation_bits):
    if not inited: # first iteration
      attestersAgg.init(epochRef.validator_keys[valIndex]
                                .loadWithCacheOrExit(none(CookedSig)))
      inited = true
    else:
      attestersAgg.aggregate(epochRef.validator_keys[valIndex]
                                     .loadWithCacheOrExit(none(CookedSig)))

  if not inited:
    # There were no attesters
    return none(CookedSig)

  var attesters{.noinit.}: blscurve.PublicKey
  attesters.finish(attestersAgg)

  let cookedSig = attestation.signature.loadOrExit(none(CookedSig))

  sigs.addSignatureSet(
      attesters,
      attestation.data,
      cookedSig,
      genesis_validators_root,
      fork,
      attestation.data.target.epoch,
      DOMAIN_BEACON_ATTESTER)

  some(CookedSig(cookedSig))

proc addSlotSignature*(
      sigs: var seq[SignatureSet],
      fork: Fork, genesis_validators_root: Eth2Digest,
      slot: Slot,
      pubkey: ValidatorPubKey,
      signature: ValidatorSig): bool =
  let epoch = compute_epoch_at_slot(slot)
  sigs.addSignatureSet(
    pubkey.loadWithCacheOrExit(false),
    sszObj = slot,
    signature.loadOrExit(false),
    genesis_validators_root,
    fork,
    epoch,
    DOMAIN_SELECTION_PROOF
  )

  true

proc addAggregateAndProofSignature*(
      sigs: var seq[SignatureSet],
      fork: Fork, genesis_validators_root: Eth2Digest,
      aggregate_and_proof: AggregateAndProof,
      pubkey: ValidatorPubKey,
      signature: ValidatorSig
  ): bool =

  let epoch = compute_epoch_at_slot(aggregate_and_proof.aggregate.data.slot)
  sigs.addSignatureSet(
    pubkey.loadWithCacheOrExit(false),
    sszObj = aggregate_and_proof,
    signature.loadOrExit(false),
    genesis_validators_root,
    fork,
    epoch,
    DOMAIN_AGGREGATE_AND_PROOF
  )

  true

proc collectSignatureSets*(
       sigs: var seq[SignatureSet],
       signed_block: SignedBeaconBlock,
       state: StateData,
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
  if proposer_index >= getStateField(state, validators).lenu64:
    return false

  let pubkey = getStateField(state, validators)[proposer_index]
                    .pubkey.loadWithCacheOrExit(false)
  let epoch = signed_block.message.slot.compute_epoch_at_slot()

  # 1. Block proposer
  # ----------------------------------------------------
  sigs.addSignatureSet(
          pubkey,
          signed_block.message,
          signed_block.signature.loadOrExit(false),
          getStateField(state, genesis_validators_root),
          getStateField(state, fork),
          epoch,
          DOMAIN_BEACON_PROPOSER)

  # 2. Randao Reveal
  # ----------------------------------------------------
  sigs.addSignatureSet(
          pubkey,
          epoch,
          signed_block.message.body.randao_reveal.loadOrExit(false),
          getStateField(state, genesis_validators_root),
          getStateField(state, fork),
          epoch,
          DOMAIN_RANDAO)

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
      let proposer1 =
        getStateField(state, validators)[header_1.message.proposer_index]
      let epoch1 = header_1.message.slot.compute_epoch_at_slot()
      sigs.addSignatureSet(
              proposer1.pubkey.loadWithCacheOrExit(false),
              header_1.message,
              header_1.signature.loadOrExit(false),
              getStateField(state, genesis_validators_root),
              getStateField(state, fork),
              epoch1,
              DOMAIN_BEACON_PROPOSER
            )

    # Conflicting block 2
    block:
      let header_2 = slashing.signed_header_2
      let proposer2 =
        getStateField(state, validators)[header_2.message.proposer_index]
      let epoch2 = header_2.message.slot.compute_epoch_at_slot()
      sigs.addSignatureSet(
              proposer2.pubkey.loadWithCacheOrExit(false),
              header_2.message,
              header_2.signature.loadOrExit(false),
              getStateField(state, genesis_validators_root),
              getStateField(state, fork),
              epoch2,
              DOMAIN_BEACON_PROPOSER
            )

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

    sigs.addSignatureSet(
            getStateField(state, validators)[volex.message.validator_index]
                 .pubkey.loadWithCacheOrExit(false),
            volex.message,
            volex.signature.loadOrExit(false),
            getStateField(state, genesis_validators_root),
            getStateField(state, fork),
            volex.message.epoch,
            DOMAIN_VOLUNTARY_EXIT)

  return true

# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Status lib
  blscurve,
  stew/byteutils,
  eth/keys,
  # Internal
  ../ssz/merkleization,
  ./crypto, ./datatypes, ./helpers, ./presets,
  ./beaconstate

export SignatureSet, BatchedBLSVerifierCache

func `$`*(s: SignatureSet): string =
  "(pubkey: 0x" & s.pubkey.toHex() &
    ", signing_root: 0x" & s.message.toHex() &
    ", signature: 0x" & s.signature.toHex() & ')'

func addSignatureSet[T](
      sigs: var seq[SignatureSet],
      pubkey: blscurve.PublicKey,
      sszObj: T,
      signature: ValidatorSig,
      state: BeaconState,
      epoch: Epoch,
      domain: DomainType): bool {.raises: [Defect].}=
  ## Add a new signature set triplet (pubkey, message, signature)
  ## to a collection of signature sets for batch verification.
  ## Can return false if `signature` wasn't deserialized to a valid BLS signature.
  try:
    let signing_root = compute_signing_root(
        sszObj,
        get_domain(
          state.fork, domain,
          epoch,
          state.genesis_validators_root
        )
      ).data

    sigs.add((
      pubkey,
      signing_root,
      signature.blsValue
    ))

    return true
  except FieldError: # bad discriminant when accessing signature.blsValue
    return false

proc aggregateAttesters(
      attestation: IndexedAttestation,
      state: BeaconState
     ): blscurve.PublicKey {.noInit.} =
  doAssert attestation.attesting_indices.len > 0
  var attestersAgg{.noInit.}: AggregatePublicKey
  attestersAgg.init(state.validators[attestation.attesting_indices[0]].pubkey.toRealPubKey().get().blsValue)
  for i in 1 ..< attestation.attesting_indices.len:
    attestersAgg.aggregate(state.validators[attestation.attesting_indices[i]].pubkey.toRealPubKey().get().blsValue)
  result.finish(attestersAgg)

proc addIndexedAttestation(
      sigs: var seq[SignatureSet],
      attestation: IndexedAttestation,
      state: BeaconState
     ): bool =
  if attestation.attesting_indices.len == 0:
    # Aggregation spec requires non-empty collection
    # - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
    # Eth2 spec requires at least one attesting indice in slashing
    # - https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
    return false

  if not sigs.addSignatureSet(
          attestation.aggregateAttesters(state),
          attestation.data,
          attestation.signature,
          state, attestation.data.target.epoch,
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
      attestersAgg.init(state.validators[valIndex].pubkey.toRealPubKey().get().blsValue)
      result = true
    else:
      attestersAgg.aggregate(state.validators[valIndex].pubkey.toRealPubKey().get().blsValue)

  if not result:
    # There was no attesters
    return false

  var attesters{.noinit.}: blscurve.PublicKey
  attesters.finish(attestersAgg)

  if not sigs.addSignatureSet(
          attesters,
          attestation.data,
          attestation.signature,
          state, attestation.data.target.epoch,
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

  let pubkey = block:
    let pk = state.validators[proposer_index].pubkey.toRealPubKey()
    if pk.isNone:
      return false
    pk.unsafeGet().blsValue
  let epoch = signed_block.message.slot.compute_epoch_at_slot()

  # 1. Block proposer
  # ----------------------------------------------------
  if not sigs.addSignatureSet(
          pubkey,
          signed_block.message,
          signed_block.signature,
          state, epoch,
          DOMAIN_BEACON_PROPOSER):
    return false

  # 2. Randao Reveal
  # ----------------------------------------------------
  if not sigs.addSignatureSet(
          pubkey,
          epoch,
          signed_block.message.body.randao_reveal,
          state, epoch,
          DOMAIN_RANDAO):
    return false

  # 3. Proposer slashings
  # ----------------------------------------------------
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
              proposer1.pubkey.toRealPubKey().get().blsValue,
              header_1.message,
              header_1.signature,
              state, epoch1,
              DOMAIN_BEACON_PROPOSER
            ):
        return false

    # Conflicting block 2
    block:
      let header_2 = slashing.signed_header_2
      let proposer2 = state.validators[header_2.message.proposer_index]
      let epoch2 = header_2.message.slot.compute_epoch_at_slot()
      if not sigs.addSignatureSet(
              proposer2.pubkey.toRealPubKey().get().blsValue,
              header_2.message,
              header_2.signature,
              state, epoch2,
              DOMAIN_BEACON_PROPOSER
            ):
        return false

  # 4. Attester slashings
  # ----------------------------------------------------
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
  for i in 0 ..< signed_block.message.body.voluntary_exits.len:
    # don't use "items" for iterating over large type
    # due to https://github.com/nim-lang/Nim/issues/14421
    # fixed in 1.4.2
    template volex: untyped = signed_block.message.body.voluntary_exits[i]

    if not sigs.addSignatureSet(
            state.validators[volex.message.validator_index].pubkey.toRealPubKey().get().blsValue,
            volex.message,
            volex.signature,
            state, volex.message.epoch,
            DOMAIN_VOLUNTARY_EXIT):
      return false

  return true

proc batchVerify*(
      sigs: openArray[SignatureSet],
      cache: var BatchedBLSVerifierCache): bool =
  # Crypto secure HmacDrbg RNG from BearSSL / nim-eth/keys
  # TODO: We don't need high security for this RNG
  #       as it is not used for secret generation
  #       but only to mix non-public data a malicious party
  #       cannot control.
  #       We still likely want to use the application RNG instance
  var rng {.global.}: ref BrHmacDrbgContext
  var rngInit {.global.}: bool
  if not rngInit:
    rng = keys.newRng()
    rngInit = true

  var secureRandomBytes: array[32, byte]
  rng[].brHmacDrbgGenerate(secureRandomBytes)

  # TODO: For now only enable serial batch verification
  return batchVerifySerial(cache, sigs, secureRandomBytes)

proc batchVerify*(sigs: openArray[SignatureSet]): bool =
  # Don't {.noinit.} this or seq capacity will be != 0.
  var cache: BatchedBLSVerifierCache
  batchVerify(sigs, cache)

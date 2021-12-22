# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[options, tables, json, streams, uri],
  chronos, chronicles, metrics,
  json_serialization/std/net,
  presto, presto/client,

  ../spec/[keystore, signatures, helpers, crypto],
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/[rest_types, eth2_rest_serialization,
                     rest_remote_signer_calls],
  ./slashing_protection

export
  streams, options, keystore, phase0, altair, tables, uri, crypto,
  rest_types, eth2_rest_serialization, rest_remote_signer_calls

declareGauge validators,
  "Number of validators attached to the beacon node"

type
  ValidatorKind* {.pure.} = enum
    Local, Remote

  ValidatorConnection* = RestClientRef

  AttachedValidator* = ref object
    pubkey*: ValidatorPubKey
    data*: KeystoreData
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      discard
    of ValidatorKind.Remote:
      client*: RestClientRef

    # The index at which this validator has been observed in the chain -
    # it does not change as long as there are no reorgs on eth1 - however, the
    # index might not be valid in all eth2 histories, so it should not be
    # assumed that a valid index is stored here!
    index*: Option[ValidatorIndex]

    # Cache the latest slot signature - the slot signature is used to determine
    # if the validator will be aggregating (in the near future)
    slotSignature*: Option[tuple[slot: Slot, signature: ValidatorSig]]

  SignResponse* = Web3SignerDataResponse

  SignatureResult* = Result[ValidatorSig, string]
  AttestationResult* = Result[Attestation, string]
  SyncCommitteeMessageResult* = Result[SyncCommitteeMessage, string]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB

func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    shortLog(v.pubkey)
  of ValidatorKind.Remote:
    shortLog(v.pubkey) & "@" & $v.client.address.getUri()

func init*(T: type ValidatorPool,
            slashingProtectionDB: SlashingProtectionDB): T =
  ## Initialize the validator pool and the slashing protection service
  ## `genesis_validators_root` is used as an unique ID for the
  ## blockchain
  ## `backend` is the KeyValue Store backend
  T(slashingProtection: slashingProtectionDB)

template count*(pool: ValidatorPool): int =
  len(pool.validators)

proc addLocalValidator*(pool: var ValidatorPool, item: KeystoreData,
                        index: Option[ValidatorIndex]) =
  let pubkey = item.pubkey
  let v = AttachedValidator(kind: ValidatorKind.Local, pubkey: pubkey,
                            index: index, data: item)
  pool.validators[pubkey] = v
  notice "Local validator attached", pubkey, validator = shortLog(v)
  validators.set(pool.count().int64)

proc addLocalValidator*(pool: var ValidatorPool, item: KeystoreData) =
  addLocalValidator(pool, item, none[ValidatorIndex]())

proc addRemoteValidator*(pool: var ValidatorPool, item: KeystoreData,
                         client: RestClientRef, index: Option[ValidatorIndex]) =
  let pubkey = item.pubkey
  let v = AttachedValidator(kind: ValidatorKind.Remote, pubkey: pubkey,
                            index: index, data: item, client: client)
  pool.validators[pubkey] = v
  notice "Remote validator attached", pubkey, validator = shortLog(v),
         remote_signer = $item.remoteUrl
  validators.set(pool.count().int64)

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

proc contains*(pool: ValidatorPool, pubkey: ValidatorPubKey): bool =
  ## Returns ``true`` if validator with key ``pubkey`` present in ``pool``.
  pool.validators.contains(pubkey)

proc removeValidator*(pool: var ValidatorPool, pubkey: ValidatorPubKey) =
  ## Delete validator with public key ``pubkey`` from ``pool``.
  let validator = pool.validators.getOrDefault(pubkey)
  if not(isNil(validator)):
    pool.validators.del(pubkey)
    notice "Local or remote validator detached", pubkey,
           validator = shortLog(validator)
    validators.set(pool.count().int64)

proc updateValidator*(pool: var ValidatorPool, pubkey: ValidatorPubKey,
                      index: ValidatorIndex) =
  ## Set validator ``index`` to validator with public key ``pubkey`` stored
  ## in ``pool``.
  ## This procedure will not raise if validator with public key ``pubkey`` is
  ## not present in the pool.
  var v: AttachedValidator
  if pool.validators.pop(pubkey, v):
    v.index = some(index)
    pool.validators[pubkey] = v

iterator publicKeys*(pool: ValidatorPool): ValidatorPubKey =
  for item in pool.validators.keys():
    yield item

iterator indices*(pool: ValidatorPool): ValidatorIndex =
  for item in pool.validators.values():
    if item.index.isSome():
      yield item.index.get()

iterator items*(pool: ValidatorPool): AttachedValidator =
  for item in pool.validators.values():
    yield item

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              blck: ForkedBeaconBlock): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(fork, genesis_validators_root, blck)
  debug "Signing block proposal using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              adata: AttestationData): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(fork, genesis_validators_root, adata)
  debug "Signing block proposal using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              epoch: Epoch): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(fork, genesis_validators_root, epoch)
  debug "Generating randao reveal signature using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              proof: AggregateAndProof): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(fork, genesis_validators_root, proof)
  debug "Signing aggregate and proof using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              slot: Slot): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(fork, genesis_validators_root, slot)
  debug "Signing aggregate slot using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              slot: Slot,
                              blockRoot: Eth2Digest): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(fork, genesis_validators_root, blockRoot,
                                       slot)
  debug "Signing sync committee message using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              slot: Slot,
                              subIndex: uint64): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(
    fork, genesis_validators_root,
    SyncAggregatorSelectionData(slot: slot, subcommittee_index: subIndex),
  )
  debug "Signing sync aggregator selection data using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

proc signWithRemoteValidator*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              contribution: ContributionAndProof
                             ): Future[SignResponse] {.
     async.} =
  let request = Web3SignerRequest.init(
    fork, genesis_validators_root, contribution
  )
  debug "Signing sync contribution and proof message using remote signer",
        validator = shortLog(v)
  return await v.client.signData(v.pubkey, request)

# https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/phase0/validator.md#signature
proc signBlockProposal*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        blockRoot: Eth2Digest, blck: ForkedBeaconBlock
                        ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_block_signature(fork, genesis_validators_root, slot, blockRoot,
                            v.data.privateKey).toValidatorSig()
      )
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              blck)
      if res.isErr():
        SignatureResult.err(res.error())
      else:
        SignatureResult.ok(res.get().toValidatorSig())

proc signAttestation*(v: AttachedValidator,
                      data: AttestationData,
                      fork: Fork, genesis_validators_root: Eth2Digest):
                      Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_attestation_signature(fork, genesis_validators_root, data,
                                  v.data.privateKey).toValidatorSig()
      )
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              data)
      if res.isErr():
        SignatureResult.err(res.error())
      else:
        SignatureResult.ok(res.get().toValidatorSig())

proc produceAndSignAttestation*(validator: AttachedValidator,
                                attestationData: AttestationData,
                                committeeLen: int, indexInCommittee: Natural,
                                fork: Fork,
                                genesis_validators_root: Eth2Digest):
                                Future[AttestationResult] {.async.} =
  let validatorSignature =
    block:
      let res = await validator.signAttestation(attestationData, fork,
                                                genesis_validators_root)
      if res.isErr():
        return AttestationResult.err(res.error())
      res.get()

  var aggregationBits = CommitteeValidatorsBits.init(committeeLen)
  aggregationBits.setBit indexInCommittee

  return AttestationResult.ok(
    Attestation(data: attestationData, signature: validatorSignature,
                aggregation_bits: aggregationBits)
  )

proc signAggregateAndProof*(v: AttachedValidator,
                            aggregate_and_proof: AggregateAndProof,
                            fork: Fork, genesis_validators_root: Eth2Digest):
                            Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_aggregate_and_proof_signature(fork, genesis_validators_root,
                                          aggregate_and_proof,
                                          v.data.privateKey).toValidatorSig()
      )
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              aggregate_and_proof)
      if res.isErr():
        SignatureResult.err(res.error())
      else:
        SignatureResult.ok(res.get().toValidatorSig())

# https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/altair/validator.md#prepare-sync-committee-message
proc signSyncCommitteeMessage*(v: AttachedValidator,
                               fork: Fork,
                               genesis_validators_root: Eth2Digest,
                               slot: Slot,
                               beacon_block_root: Eth2Digest
                              ): Future[SyncCommitteeMessageResult] {.async.} =
  let signature =
    case v.kind
    of ValidatorKind.Local:
      get_sync_committee_message_signature(
        fork, genesis_validators_root, slot, beacon_block_root,
        v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              slot, beacon_block_root)
      if res.isErr():
        return SyncCommitteeMessageResult.err(res.error())
      res.get().toValidatorSig()

  return
    SyncCommitteeMessageResult.ok(
      SyncCommitteeMessage(
        slot: slot,
        beacon_block_root: beacon_block_root,
        validator_index: uint64(v.index.get()),
        signature: signature
      )
    )

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/altair/validator.md#aggregation-selection
proc getSyncCommitteeSelectionProof*(v: AttachedValidator,
                                     fork: Fork,
                                     genesis_validators_root: Eth2Digest,
                                     slot: Slot,
                                     subcommittee_index: uint64
                                    ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_sync_committee_selection_proof(
        fork, genesis_validators_root, slot, subcommittee_index,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              slot, subcommittee_index)
      if res.isErr():
        SignatureResult.err(res.error())
      else:
        SignatureResult.ok(res.get().toValidatorSig())

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/validator.md#signature
proc sign*(v: AttachedValidator, msg: ref SignedContributionAndProof,
           fork: Fork, genesis_validators_root: Eth2Digest
          ): Future[SignatureResult] {.async.} =
  msg.signature =
    case v.kind
    of ValidatorKind.Local:
      get_contribution_and_proof_signature(
        fork, genesis_validators_root, msg.message, v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              msg.message)
      if res.isErr():
        return SignatureResult.err(res.error())
      res.get().toValidatorSig()
  return SignatureResult.ok(msg.signature)

# https://github.com/ethereum/consensus-specs/blob/v1.1.6/specs/phase0/validator.md#randao-reveal
func genRandaoReveal*(k: ValidatorPrivKey, fork: Fork,
                      genesis_validators_root: Eth2Digest,
                      slot: Slot): CookedSig =
  get_epoch_signature(fork, genesis_validators_root,
                      slot.compute_epoch_at_slot, k)

proc genRandaoReveal*(v: AttachedValidator, fork: Fork,
                      genesis_validators_root: Eth2Digest, slot: Slot):
                      Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(genRandaoReveal(v.data.privateKey, fork,
                                         genesis_validators_root,
                                         slot).toValidatorSig())
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              slot.compute_epoch_at_slot())
      if res.isErr():
        SignatureResult.err(res.error())
      else:
        SignatureResult.ok(res.get().toValidatorSig())

proc getSlotSig*(v: AttachedValidator, fork: Fork,
                 genesis_validators_root: Eth2Digest, slot: Slot
                ): Future[SignatureResult] {.async.} =
  if v.slotSignature.isSome() and v.slotSignature.get().slot == slot:
    return SignatureResult.ok(v.slotSignature.get().signature)

  let signature =
    case v.kind
    of ValidatorKind.Local:
      get_slot_signature(fork, genesis_validators_root, slot,
                         v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let res = await signWithRemoteValidator(v, fork, genesis_validators_root,
                                              slot)
      if res.isErr():
        return SignatureResult.err(res.error())
      res.get().toValidatorSig()

  v.slotSignature = some((slot, signature))
  return SignatureResult.ok(signature)

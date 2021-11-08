# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[options, tables, json, streams],
  chronos, chronicles, metrics,
  json_serialization/std/net,
  ../spec/[keystore, signatures, helpers],
  ../spec/datatypes/[phase0, altair],
  ./slashing_protection

export
  streams, options, keystore, phase0, altair, tables

declareGauge validators,
  "Number of validators attached to the beacon node"

type
  ValidatorKind* {.pure.} = enum
    Local, Remote

  ValidatorConnection* = object
    inStream*: Stream
    outStream*: Stream
    pubKeyStr*: string

  ValidatorPrivateItem* = object
    privateKey*: ValidatorPrivKey
    description*: Option[string]
    path*: Option[KeyPath]
    uuid*: Option[string]
    version*: Option[uint64]

  AttachedValidator* = ref object
    pubKey*: ValidatorPubKey
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      data*: ValidatorPrivateItem
    of ValidatorKind.Remote:
      connection*: ValidatorConnection

    # The index at which this validator has been observed in the chain -
    # it does not change as long as there are no reorgs on eth1 - however, the
    # index might not be valid in all eth2 histories, so it should not be
    # assumed that a valid index is stored here!
    index*: Option[ValidatorIndex]

    # Cache the latest slot signature - the slot signature is used to determine
    # if the validator will be aggregating (in the near future)
    slotSignature*: Option[tuple[slot: Slot, signature: ValidatorSig]]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB

func shortLog*(v: AttachedValidator): string = shortLog(v.pubKey)

func init*(T: type ValidatorPool,
            slashingProtectionDB: SlashingProtectionDB): T =
  ## Initialize the validator pool and the slashing protection service
  ## `genesis_validators_root` is used as an unique ID for the
  ## blockchain
  ## `backend` is the KeyValue Store backend
  T(slashingProtection: slashingProtectionDB)

template count*(pool: ValidatorPool): int =
  len(pool.validators)

proc addLocalValidator*(pool: var ValidatorPool, item: ValidatorPrivateItem,
                        index: Option[ValidatorIndex]) =
  let pubKey = item.privateKey.toPubKey().toPubKey()
  let v = AttachedValidator(kind: ValidatorKind.Local, pubKey: pubKey,
                            index: index, data: item)
  pool.validators[pubKey] = v
  notice "Local validator attached", pubKey, validator = shortLog(v)
  validators.set(pool.count().int64)

proc addLocalValidator*(pool: var ValidatorPool, item: ValidatorPrivateItem) =
  addLocalValidator(pool, item, none[ValidatorIndex]())

proc addRemoteValidator*(pool: var ValidatorPool, pubKey: ValidatorPubKey,
                         v: AttachedValidator) =
  pool.validators[pubKey] = v
  notice "Remote validator attached", pubKey, validator = shortLog(v)
  validators.set(pool.count().int64)

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

proc contains*(pool: ValidatorPool, pubKey: ValidatorPubKey): bool =
  ## Returns ``true`` if validator with key ``pubKey`` present in ``pool``.
  pool.validators.contains(pubKey)

proc removeValidator*(pool: var ValidatorPool, validatorKey: ValidatorPubKey) =
  ## Delete validator with public key ``pubKey`` from ``pool``.
  let validator = pool.validators.getOrDefault(validatorKey)
  if not(isNil(validator)):
    pool.validators.del(validatorKey)
    notice "Local or remote validator detached", validatorKey,
           validator = shortLog(validator)
    validators.set(pool.count().int64)

proc updateValidator*(pool: var ValidatorPool, pubKey: ValidatorPubKey,
                      index: ValidatorIndex) =
  ## Set validator ``index`` to validator with public key ``pubKey`` stored
  ## in ``pool``.
  ## This procedure will not raise if validator with public key ``pubKey`` is
  ## not present in the pool.
  var v: AttachedValidator
  if pool.validators.pop(pubKey, v):
    v.index = some(index)
    pool.validators[pubKey] = v

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

proc signWithRemoteValidator(v: AttachedValidator,
                             data: Eth2Digest): Future[ValidatorSig] {.async.} =
  v.connection.inStream.writeLine(v.connection.pubKeyStr, " ", $data)
  v.connection.inStream.flush()
  var line = newStringOfCap(120).TaintedString
  discard v.connection.outStream.readLine(line)
  return ValidatorSig.fromHex(line).get()

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/phase0/validator.md#signature
proc signBlockProposal*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        blockRoot: Eth2Digest): Future[ValidatorSig] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      get_block_signature(fork, genesis_validators_root, slot, blockRoot,
                          v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let root = compute_block_root(fork, genesis_validators_root, slot,
                                    blockRoot)
      await signWithRemoteValidator(v, root)

proc signAttestation*(v: AttachedValidator,
                      data: AttestationData,
                      fork: Fork, genesis_validators_root: Eth2Digest):
                      Future[ValidatorSig] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      get_attestation_signature(fork, genesis_validators_root, data,
                                v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let root = compute_attestation_root(fork, genesis_validators_root, data)
      await signWithRemoteValidator(v, root)

proc produceAndSignAttestation*(validator: AttachedValidator,
                                attestationData: AttestationData,
                                committeeLen: int, indexInCommittee: Natural,
                                fork: Fork,
                                genesis_validators_root: Eth2Digest):
                                Future[Attestation] {.async.} =
  let validatorSignature =
    await validator.signAttestation(attestationData, fork,
                                    genesis_validators_root)

  var aggregationBits = CommitteeValidatorsBits.init(committeeLen)
  aggregationBits.setBit indexInCommittee

  return Attestation(data: attestationData, signature: validatorSignature,
                     aggregation_bits: aggregationBits)

proc signAggregateAndProof*(v: AttachedValidator,
                            aggregate_and_proof: AggregateAndProof,
                            fork: Fork, genesis_validators_root: Eth2Digest):
                            Future[ValidatorSig] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      get_aggregate_and_proof_signature(fork, genesis_validators_root,
                                        aggregate_and_proof,
                                        v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let root = compute_aggregate_and_proof_root(fork, genesis_validators_root,
                                                  aggregate_and_proof)
      await signWithRemoteValidator(v, root)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-alpha.7/specs/altair/validator.md#prepare-sync-committee-message
proc signSyncCommitteeMessage*(v: AttachedValidator,
                               slot: Slot,
                               fork: Fork,
                               genesis_validators_root: Eth2Digest,
                               block_root: Eth2Digest): Future[SyncCommitteeMessage] {.async.} =
  let
    signing_root = sync_committee_msg_signing_root(
      fork, slot.epoch, genesis_validators_root, block_root)

  let signature =
    case v.kind
    of ValidatorKind.Local:
      blsSign(v.data.privateKey, signing_root.data).toValidatorSig
    of ValidatorKind.Remote:
      await signWithRemoteValidator(v, signing_root)

  return SyncCommitteeMessage(
    slot: slot,
    beacon_block_root: block_root,
    validator_index: v.index.get.uint64,
    signature: signature)

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#aggregation-selection
proc getSyncCommitteeSelectionProof*(
    v: AttachedValidator,
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    slot: Slot,
    subcommittee_index: uint64): Future[ValidatorSig] {.async.} =
  let
    signing_root = sync_committee_selection_proof_signing_root(
      fork, genesis_validators_root, slot, subcommittee_index)

  return
    case v.kind
    of ValidatorKind.Local:
      blsSign(v.data.privateKey, signing_root.data).toValidatorSig
    of ValidatorKind.Remote:
      await signWithRemoteValidator(v, signing_root)

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#signature
proc sign*(
    v: AttachedValidator,
    msg: ref SignedContributionAndProof,
    fork: Fork,
    genesis_validators_root: Eth2Digest) {.async.} =
  let
    signing_root = contribution_and_proof_signing_root(
      fork, genesis_validators_root, msg.message)

  msg.signature =
    case v.kind
    of ValidatorKind.Local:
      blsSign(v.data.privateKey, signing_root.data).toValidatorSig
    of ValidatorKind.Remote:
      await signWithRemoteValidator(v, signing_root)

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/phase0/validator.md#randao-reveal
func genRandaoReveal*(k: ValidatorPrivKey, fork: Fork,
                      genesis_validators_root: Eth2Digest,
                      slot: Slot): CookedSig =
  get_epoch_signature(fork, genesis_validators_root,
                      slot.compute_epoch_at_slot, k)

proc genRandaoReveal*(v: AttachedValidator, fork: Fork,
                      genesis_validators_root: Eth2Digest, slot: Slot):
                      Future[ValidatorSig] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      genRandaoReveal(v.data.privateKey, fork, genesis_validators_root,
                      slot).toValidatorSig()
    of ValidatorKind.Remote:
      let root = compute_epoch_root(fork, genesis_validators_root,
                                    slot.compute_epoch_at_slot)
      await signWithRemoteValidator(v, root)

proc getSlotSig*(v: AttachedValidator, fork: Fork,
                 genesis_validators_root: Eth2Digest, slot: Slot
                 ): Future[ValidatorSig] {.async.} =
  if v.slotSignature.isSome() and v.slotSignature.get().slot == slot:
    return v.slotSignature.get().signature

  let signature =
    case v.kind
    of ValidatorKind.Local:
      get_slot_signature(fork, genesis_validators_root, slot,
                        v.data.privateKey).toValidatorSig()
    of ValidatorKind.Remote:
      let root = compute_slot_root(fork, genesis_validators_root, slot)
      await signWithRemoteValidator(v, root)
  v.slotSignature = some((slot, signature))
  return signature

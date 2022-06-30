# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[options, tables, json, streams, sequtils, uri],
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
  rest_types, eth2_rest_serialization, rest_remote_signer_calls,
  slashing_protection

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
      clients*: seq[(RestClientRef, RemoteSignerInfo)]
      threshold*: uint32

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
  SyncCommitteeMessageResult* = Result[SyncCommitteeMessage, string]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB

func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    shortLog(v.pubkey)
  of ValidatorKind.Remote:
    shortLog(v.pubkey)

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
  doAssert item.kind == KeystoreKind.Local
  let pubkey = item.pubkey
  let v = AttachedValidator(kind: ValidatorKind.Local, pubkey: pubkey,
                            index: index, data: item)
  pool.validators[pubkey] = v
  notice "Local validator attached", pubkey, validator = shortLog(v)
  validators.set(pool.count().int64)

proc addLocalValidator*(pool: var ValidatorPool, item: KeystoreData) =
  addLocalValidator(pool, item, none[ValidatorIndex]())

proc addRemoteValidator*(pool: var ValidatorPool, item: KeystoreData,
                         clients: seq[(RestClientRef, RemoteSignerInfo)], index: Option[ValidatorIndex]) =
  doAssert item.kind == KeystoreKind.Remote
  let pubkey = item.pubkey
  let v = AttachedValidator(kind: ValidatorKind.Remote, pubkey: pubkey,
                            index: index, data: item, clients: clients)
  pool.validators[pubkey] = v
  notice "Remote validator attached", pubkey, validator = shortLog(v),
         remote_signer = $item.remotes
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
    case validator.kind
    of ValidatorKind.Local:
      notice "Local validator detached", pubkey, validator = shortLog(validator)
    of ValidatorKind.Remote:
      notice "Remote validator detached", pubkey,
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

proc signWithDistributedKey(v: AttachedValidator,
                            request: Web3SignerRequest): Future[SignatureResult]
                           {.async.} =
  doAssert v.data.threshold <= uint32(v.clients.len)

  let signatureReqs = mapIt(v.clients, it[0].signData(it[1].pubkey, request))
  await allFutures(signatureReqs)

  var shares: seq[SignatureShare]
  var neededShares = v.data.threshold

  for i, req in signatureReqs:
    template shareInfo: untyped = v.clients[i][1]
    if req.done and req.read.isOk:
      shares.add req.read.get.toSignatureShare(shareInfo.id)
      neededShares = neededShares - 1
    else:
      warn "Failed to obtain signature from remote signer",
           pubkey = shareInfo.pubkey,
           signerUrl = $(v.clients[i][0].address)

    if neededShares == 0:
      let recovered = shares.recoverSignature()
      return SignatureResult.ok recovered.toValidatorSig

  return SignatureResult.err "Not enough shares to recover the signature"

proc signWithSingleKey(v: AttachedValidator,
                       request: Web3SignerRequest): Future[SignatureResult]
                      {.async.} =
  doAssert v.clients.len == 1
  let (client, info) = v.clients[0]
  let res = await client.signData(info.pubkey, request)
  if res.isErr:
    return SignatureResult.err res.error
  else:
    return SignatureResult.ok res.get.toValidatorSig

proc signData(v: AttachedValidator,
              request: Web3SignerRequest): Future[SignatureResult] =
  doAssert v.kind == ValidatorKind.Remote
  debug "Signing request with remote signer",
    validator = shortLog(v), kind = request.kind
  if v.clients.len == 1:
    v.signWithSingleKey(request)
  else:
    v.signWithDistributedKey(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#signature
proc getBlockSignature*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        block_root: Eth2Digest, blck: ForkedBeaconBlock
                       ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_block_signature(
          fork, genesis_validators_root, slot, block_root,
          v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root, blck.Web3SignerForkedBeaconBlock)
      await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#aggregate-signature
proc getAttestationSignature*(v: AttachedValidator, fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              data: AttestationData
                             ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_attestation_signature(
          fork, genesis_validators_root, data,
          v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(fork, genesis_validators_root, data)
      await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#broadcast-aggregate
proc getAggregateAndProofSignature*(v: AttachedValidator,
                                    fork: Fork,
                                    genesis_validators_root: Eth2Digest,
                                    aggregate_and_proof: AggregateAndProof
                                   ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_aggregate_and_proof_signature(
          fork, genesis_validators_root, aggregate_and_proof,
          v.data.privateKey).toValidatorSig()
      )
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root, aggregate_and_proof)
      await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#prepare-sync-committee-message
proc getSyncCommitteeMessage*(v: AttachedValidator,
                              fork: Fork,
                              genesis_validators_root: Eth2Digest,
                              slot: Slot,
                              beacon_block_root: Eth2Digest
                             ): Future[SyncCommitteeMessageResult] {.async.} =
  let signature =
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_sync_committee_message_signature(
        fork, genesis_validators_root, slot, beacon_block_root,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root, beacon_block_root, slot)
      await v.signData(request)

  if signature.isErr:
    return SyncCommitteeMessageResult.err("Failed to obtain signature")

  return
    SyncCommitteeMessageResult.ok(
      SyncCommitteeMessage(
        slot: slot,
        beacon_block_root: beacon_block_root,
        validator_index: uint64(v.index.get()),
        signature: signature.get()
      )
    )

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#aggregation-selection
proc getSyncCommitteeSelectionProof*(v: AttachedValidator, fork: Fork,
                                     genesis_validators_root: Eth2Digest,
                                     slot: Slot,
                                     subcommittee_index: SyncSubcommitteeIndex
                                    ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_sync_committee_selection_proof(
        fork, genesis_validators_root, slot, subcommittee_index,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root,
        SyncAggregatorSelectionData(
          slot: slot, subcommittee_index: uint64 subcommittee_index)
      )
      await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#broadcast-sync-committee-contribution
proc getContributionAndProofSignature*(v: AttachedValidator, fork: Fork,
                                       genesis_validators_root: Eth2Digest,
                                       contribution_and_proof: ContributionAndProof
                                      ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_contribution_and_proof_signature(
        fork, genesis_validators_root, contribution_and_proof,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root, contribution_and_proof)
      await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#randao-reveal
proc getEpochSignature*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, epoch: Epoch
                       ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_epoch_signature(
        fork, genesis_validators_root, epoch,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root, epoch)
      await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#aggregation-selection
proc getSlotSignature*(v: AttachedValidator, fork: Fork,
                       genesis_validators_root: Eth2Digest, slot: Slot
                      ): Future[SignatureResult] {.async.} =
  if v.slotSignature.isSome and v.slotSignature.get.slot == slot:
    return SignatureResult.ok(v.slotSignature.get.signature)

  let signature =
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_slot_signature(
        fork, genesis_validators_root, slot,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(fork, genesis_validators_root, slot)
      await v.signData(request)

  if signature.isErr:
    return signature

  v.slotSignature = some((slot, signature.get))
  return signature

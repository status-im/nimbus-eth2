# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[options, tables, json, streams, sequtils, uri],
  chronos, chronicles, metrics, eth/async_utils,
  json_serialization/std/net,
  presto, presto/client,

  ../spec/[keystore, signatures, helpers, crypto],
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/[rest_types, eth2_rest_serialization,
                     rest_remote_signer_calls],
  ../filepath,
  ./slashing_protection

export
  streams, options, keystore, phase0, altair, tables, uri, crypto,
  rest_types, eth2_rest_serialization, rest_remote_signer_calls,
  slashing_protection

const
  WEB3_SIGNER_DELAY_TOLERANCE = 3.seconds
  DOPPELGANGER_EPOCHS_COUNT = 1
    ## The number of full epochs that we monitor validators for doppelganger
    ## protection

declareGauge validators,
  "Number of validators attached to the beacon node"

type
  ValidatorKind* {.pure.} = enum
    Local, Remote

  ValidatorConnection* = RestClientRef

  DoppelgangerStatus {.pure.} = enum
    Unknown, Checking, Checked

  AttachedValidator* = ref object
    data*: KeystoreData
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      discard
    of ValidatorKind.Remote:
      clients*: seq[(RestClientRef, RemoteSignerInfo)]
      threshold*: uint32

    index*: Opt[ValidatorIndex]
      ## Validator index which is assigned after the eth1 deposit has been
      ## processed - this index is valid across all eth2 forks for fork depths
      ## up to ETH1_FOLLOW_DISTANCE - we don't support changing indices.

    activationEpoch*: Epoch
      ## Epoch when validator activated - this happens at the time or some time
      ## after the validator index has been assigned depending on how many
      ## validators are in the activation queue - this is the first epoch that
      ## the validator starts performing duties

    # Cache the latest slot signature - the slot signature is used to determine
    # if the validator will be aggregating (in the near future)
    slotSignature*: Opt[tuple[slot: Slot, signature: ValidatorSig]]

    # For the external payload builder; each epoch, the external payload
    # builder should be informed of current validators
    externalBuilderRegistration*: Opt[SignedValidatorRegistrationV1]

    doppelStatus: DoppelgangerStatus
    doppelEpoch*: Opt[Epoch]
      ## The epoch where doppelganger detection started doing its monitoring

    lastWarning*: Opt[Slot]

  SignResponse* = Web3SignerDataResponse

  SignatureResult* = Result[ValidatorSig, string]
  SyncCommitteeMessageResult* = Result[SyncCommitteeMessage, string]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB
    doppelgangerDetectionEnabled*: bool

template pubkey*(v: AttachedValidator): ValidatorPubKey =
  v.data.pubkey

func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    shortLog(v.pubkey)
  of ValidatorKind.Remote:
    shortLog(v.pubkey)

func init*(T: type ValidatorPool,
           slashingProtectionDB: SlashingProtectionDB,
           doppelgangerDetectionEnabled: bool): T =
  ## Initialize the validator pool and the slashing protection service
  ## `genesis_validators_root` is used as an unique ID for the
  ## blockchain
  ## `backend` is the KeyValue Store backend
  T(
    slashingProtection: slashingProtectionDB,
    doppelgangerDetectionEnabled: doppelgangerDetectionEnabled)

template count*(pool: ValidatorPool): int =
  len(pool.validators)

proc addLocalValidator*(
    pool: var ValidatorPool, keystore: KeystoreData,
    feeRecipient: Eth1Address): AttachedValidator =
  doAssert keystore.kind == KeystoreKind.Local
  let v = AttachedValidator(
    kind: ValidatorKind.Local,
    data: keystore,
    externalBuilderRegistration: Opt.none SignedValidatorRegistrationV1,
    activationEpoch: FAR_FUTURE_EPOCH
  )
  pool.validators[v.pubkey] = v

  # Fee recipient may change after startup, but we log the initial value here
  notice "Local validator attached",
    pubkey = v.pubkey,
    validator = shortLog(v),
    initial_fee_recipient = feeRecipient.toHex()
  validators.set(pool.count().int64)

  v

proc addRemoteValidator*(pool: var ValidatorPool, keystore: KeystoreData,
                         clients: seq[(RestClientRef, RemoteSignerInfo)],
                         feeRecipient: Eth1Address): AttachedValidator =
  doAssert keystore.kind == KeystoreKind.Remote
  let v = AttachedValidator(
    kind: ValidatorKind.Remote,
    data: keystore,
    clients: clients,
    externalBuilderRegistration: Opt.none SignedValidatorRegistrationV1,
    activationEpoch: FAR_FUTURE_EPOCH,
  )
  pool.validators[v.pubkey] = v
  notice "Remote validator attached",
    pubkey = v.pubkey,
    validator = shortLog(v),
    remote_signer = $keystore.remotes,
    initial_fee_recipient = feeRecipient.toHex()

  validators.set(pool.count().int64)

  v

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

proc needsUpdate*(validator: AttachedValidator): bool =
  validator.index.isNone() or validator.activationEpoch == FAR_FUTURE_EPOCH

proc updateValidator*(validator: AttachedValidator,
                      index: ValidatorIndex, activationEpoch: Epoch) =
  ## Update activation information for a validator
  validator.index = Opt.some(index)
  validator.activationEpoch = activationEpoch

  if validator.doppelStatus == DoppelgangerStatus.Unknown:
    if validator.doppelEpoch.isSome() and activationEpoch != FAR_FUTURE_EPOCH:
      let doppelEpoch = validator.doppelEpoch.get()
      if doppelEpoch >= validator.activationEpoch + DOPPELGANGER_EPOCHS_COUNT:
        validator.doppelStatus = DoppelgangerStatus.Checking
      else:
        validator.doppelStatus = DoppelgangerStatus.Checked

proc close*(pool: var ValidatorPool) =
  ## Unlock and close all validator keystore's files managed by ``pool``.
  for validator in pool.validators.values():
    let res = validator.data.handle.closeLockedFile()
    if res.isErr():
      notice "Could not unlock validator's keystore file",
             pubkey = validator.pubkey, validator = shortLog(validator)

proc addRemoteValidator*(pool: var ValidatorPool,
                         keystore: KeystoreData,
                         feeRecipient: Eth1Address): AttachedValidator =
  var clients: seq[(RestClientRef, RemoteSignerInfo)]
  let httpFlags =
    block:
      var res: set[HttpClientFlag]
      if RemoteKeystoreFlag.IgnoreSSLVerification in keystore.flags:
        res.incl({HttpClientFlag.NoVerifyHost,
                  HttpClientFlag.NoVerifyServerName})
      res
  let prestoFlags = {RestClientFlag.CommaSeparatedArray}
  for remote in keystore.remotes:
    let client = RestClientRef.new($remote.url, prestoFlags, httpFlags)
    if client.isErr():
      warn "Unable to resolve distributed signer address",
          remote_url = $remote.url, validator = $remote.pubkey
    clients.add((client.get(), remote))
  pool.addRemoteValidator(keystore, clients, feeRecipient)

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

proc triggersDoppelganger*(v: AttachedValidator, epoch: Epoch): bool =
  ## Returns true iff detected activity in the given epoch would trigger
  ## doppelganger detection
  if v.doppelStatus != DoppelgangerStatus.Checked:
    if v.activationEpoch == FAR_FUTURE_EPOCH:
      false
    elif epoch < v.activationEpoch + DOPPELGANGER_EPOCHS_COUNT:
      v.doppelStatus = DoppelgangerStatus.Checked
      false
    else:
      true
  else:
    false

proc updateDoppelganger*(validator: AttachedValidator, epoch: Epoch) =
  ## Called when the validator has proven to be inactive in the given epoch -
  ## this call should be made after the end of `epoch` before acting on duties
  ## in `epoch + 1`.

  if validator.doppelStatus == DoppelgangerStatus.Checked:
    return

  if validator.doppelEpoch.isNone():
    validator.doppelEpoch = Opt.some epoch

  let doppelEpoch = validator.doppelEpoch.get()

  if validator.doppelStatus == DoppelgangerStatus.Unknown:
    if validator.activationEpoch == FAR_FUTURE_EPOCH:
      return

    # We don't do doppelganger checking for validators that are about to be
    # activated since both clients would be waiting for the other to start
    # performing duties - this accounts for genesis as well
    # The slot is rounded up to ensure we cover all slots
    if doppelEpoch + 1 <= validator.activationEpoch + DOPPELGANGER_EPOCHS_COUNT:
      validator.doppelStatus = DoppelgangerStatus.Checked
      return

    validator.doppelStatus = DoppelgangerStatus.Checking

  if epoch + 1 >= doppelEpoch + DOPPELGANGER_EPOCHS_COUNT:
    validator.doppelStatus = DoppelgangerStatus.Checked

proc getValidatorForDuties*(
    pool: ValidatorPool, key: ValidatorPubKey, slot: Slot):
    Opt[AttachedValidator] =
  ## Return validator only if it is ready for duties (has index and has passed
  ## doppelganger check where applicable)
  let validator = pool.getValidator(key)
  if isNil(validator) or validator.index.isNone():
    return Opt.none(AttachedValidator)

  if pool.doppelgangerDetectionEnabled and
      validator.triggersDoppelganger(slot.epoch):
    # If the validator would trigger for an activity in the given slot, we don't
    # return it for duties
    notice "Doppelganger detection active - " &
           "skipping validator duties while observing the network",
            validator = shortLog(validator)
    return Opt.none(AttachedValidator)

  return Opt.some(validator)

proc signWithDistributedKey(v: AttachedValidator,
                            request: Web3SignerRequest): Future[SignatureResult]
                           {.async.} =
  doAssert v.data.threshold <= uint32(v.clients.len)

  let
    signatureReqs = mapIt(v.clients, it[0].signData(it[1].pubkey, request))
    deadline = sleepAsync(WEB3_SIGNER_DELAY_TOLERANCE)

  await allFutures(signatureReqs) or deadline

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
  let res = awaitWithTimeout(client.signData(info.pubkey, request),
                             WEB3_SIGNER_DELAY_TOLERANCE):
    return SignatureResult.err "Timeout"
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/validator.md#signature
proc getBlockSignature*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        block_root: Eth2Digest,
                        blck: ForkedBeaconBlock | ForkedBlindedBeaconBlock |
                              BlindedBeaconBlock
                       ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_block_signature(
          fork, genesis_validators_root, slot, block_root,
          v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      when blck is ForkedBlindedBeaconBlock:
        let
          web3SignerBlock =
            case blck.kind
            of ConsensusFork.Phase0:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Phase0,
                phase0Data: blck.phase0Data)
            of ConsensusFork.Altair:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Altair,
                altairData: blck.altairData)
            of ConsensusFork.Bellatrix:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Bellatrix,
                bellatrixData: blck.bellatrixData.toBeaconBlockHeader)
            of ConsensusFork.Capella:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Capella,
                capellaData: blck.capellaData.toBeaconBlockHeader)
            of ConsensusFork.EIP4844:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.EIP4844,
                eip4844Data: blck.eip4844Data.toBeaconBlockHeader)

          request = Web3SignerRequest.init(
            fork, genesis_validators_root, web3SignerBlock)
        await v.signData(request)
      elif blck is BlindedBeaconBlock:
        let request = Web3SignerRequest.init(
          fork, genesis_validators_root,
          Web3SignerForkedBeaconBlock(
            kind: ConsensusFork.Bellatrix,
            bellatrixData: blck.toBeaconBlockHeader))
        await v.signData(request)
      else:
        let
          web3SignerBlock =
            case blck.kind
            of ConsensusFork.Phase0:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Phase0,
                phase0Data: blck.phase0Data)
            of ConsensusFork.Altair:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Altair,
                altairData: blck.altairData)
            of ConsensusFork.Bellatrix:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Bellatrix,
                bellatrixData: blck.bellatrixData.toBeaconBlockHeader)
            of ConsensusFork.Capella:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.Capella,
                capellaData: blck.capellaData.toBeaconBlockHeader)
            of ConsensusFork.EIP4844:
              Web3SignerForkedBeaconBlock(
                kind: ConsensusFork.EIP4844,
                eip4844Data: blck.eip4844Data.toBeaconBlockHeader)

          request = Web3SignerRequest.init(
            fork, genesis_validators_root, web3SignerBlock)
        await v.signData(request)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/validator.md#aggregate-signature
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/validator.md#broadcast-aggregate
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/altair/validator.md#prepare-sync-committee-message
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/altair/validator.md#aggregation-selection
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/altair/validator.md#broadcast-sync-committee-contribution
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/validator.md#randao-reveal
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/validator.md#aggregation-selection
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

  v.slotSignature = Opt.some((slot, signature.get))
  return signature

# https://github.com/ethereum/builder-specs/blob/v0.2.0/specs/builder.md#signing
proc getBuilderSignature*(v: AttachedValidator, fork: Fork,
    validatorRegistration: ValidatorRegistrationV1):
    Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_builder_signature(
        fork, validatorRegistration, v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, ZERO_HASH, validatorRegistration)
      await v.signData(request)

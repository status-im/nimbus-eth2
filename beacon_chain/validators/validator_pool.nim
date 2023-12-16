# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[tables, json, streams, sequtils, uri],
  chronos, chronicles, metrics,
  json_serialization/std/net,
  presto, presto/client,

  ../spec/[keystore, signatures, helpers, crypto],
  ../spec/datatypes/[phase0, altair],
  ../spec/eth2_apis/[rest_types, eth2_rest_serialization,
                     rest_remote_signer_calls],
  ../filepath, ../conf,
  ./slashing_protection

export
  streams, keystore, phase0, altair, tables, uri, crypto,
  rest_types, eth2_rest_serialization, rest_remote_signer_calls,
  slashing_protection

const
  WEB3_SIGNER_DELAY_TOLERANCE = 3.seconds

declareGauge validators,
  "Number of validators attached to the beacon node"

logScope: topics = "val_pool"

type
  ValidatorKind* {.pure.} = enum
    Local, Remote

  ValidatorAndIndex* = object
    index*: ValidatorIndex
    validator*: Validator

  AttachedValidator* = ref object
    data*: KeystoreData
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      discard
    of ValidatorKind.Remote:
      clients*: seq[(RestClientRef, RemoteSignerInfo)]
      threshold*: uint32

    updated*: bool
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

    # Cache the latest epoch signature - the epoch signature is used for block
    # proposing.
    epochSignature*: Opt[tuple[epoch: Epoch, signature: ValidatorSig]]

    # For the external payload builder; each epoch, the external payload
    # builder should be informed of current validators
    externalBuilderRegistration*: Opt[SignedValidatorRegistrationV1]

    doppelCheck*: Opt[Epoch]
      ## The epoch where doppelganger detection last performed a check
    doppelActivity*: Opt[Epoch]
      ## The last time we attempted to perform a duty with this validator

    lastWarning*: Opt[Slot]

  SignResponse* = Web3SignerDataResponse

  SignatureResult* = Result[ValidatorSig, string]
  SyncCommitteeMessageResult* = Result[SyncCommitteeMessage, string]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB
    doppelgangerDetectionEnabled*: bool

  AddValidatorProc* = proc(keystore: KeystoreData) {.gcsafe, raises: [].}

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

proc addLocalValidator(
    pool: var ValidatorPool, keystore: KeystoreData,
    feeRecipient: Eth1Address, gasLimit: uint64): AttachedValidator =
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
    initial_fee_recipient = feeRecipient.toHex(),
    initial_gas_limit = gasLimit
  validators.set(pool.count().int64)

  v

proc addRemoteValidator(pool: var ValidatorPool, keystore: KeystoreData,
                        clients: seq[(RestClientRef, RemoteSignerInfo)],
                        feeRecipient: Eth1Address,
                        gasLimit: uint64): AttachedValidator =
  doAssert keystore.kind == KeystoreKind.Remote
  let v = AttachedValidator(
    kind: ValidatorKind.Remote,
    data: keystore,
    clients: clients,
    externalBuilderRegistration: Opt.none SignedValidatorRegistrationV1,
    activationEpoch: FAR_FUTURE_EPOCH,
  )
  pool.validators[v.pubkey] = v
  if RemoteKeystoreFlag.DynamicKeystore in keystore.flags:
    notice "Dynamic remote validator attached", pubkey = v.pubkey,
           validator = shortLog(v), remote_signer = $keystore.remotes,
           initial_fee_recipient = feeRecipient.toHex(),
           initial_gas_limit = gasLimit
  else:
    notice "Remote validator attached", pubkey = v.pubkey,
           validator = shortLog(v), remote_signer = $keystore.remotes,
           initial_fee_recipient = feeRecipient.toHex(),
           initial_gas_limit = gasLimit

  validators.set(pool.count().int64)

  v

proc addRemoteValidator(pool: var ValidatorPool,
                        keystore: KeystoreData,
                        feeRecipient: Eth1Address,
                        gasLimit: uint64): AttachedValidator =
  let
    httpFlags =
      if RemoteKeystoreFlag.IgnoreSSLVerification in keystore.flags:
        {HttpClientFlag.NoVerifyHost, HttpClientFlag.NoVerifyServerName}
      else:
        {}
    prestoFlags = {RestClientFlag.CommaSeparatedArray}
    socketFlags = {SocketFlags.TcpNoDelay}
    clients =
      block:
        var res: seq[(RestClientRef, RemoteSignerInfo)]
        for remote in keystore.remotes:
          let client = RestClientRef.new(
            $remote.url, prestoFlags, httpFlags, socketFlags = socketFlags)
          if client.isErr():
            # TODO keep trying in case of temporary network failure
            warn "Unable to resolve distributed signer address",
                  remote_url = $remote.url, validator = $remote.pubkey
          else:
            res.add((client.get(), remote))
        res

  pool.addRemoteValidator(keystore, clients, feeRecipient, gasLimit)

proc addValidator*(pool: var ValidatorPool,
                   keystore: KeystoreData,
                   feeRecipient: Eth1Address,
                   gasLimit: uint64): AttachedValidator =
  pool.validators.withValue(keystore.pubkey, v):
    notice "Adding already-known validator", validator = shortLog(v[])
    return v[]

  case keystore.kind
  of KeystoreKind.Local:
    pool.addLocalValidator(keystore, feeRecipient, gasLimit)
  of KeystoreKind.Remote:
    pool.addRemoteValidator(keystore, feeRecipient, gasLimit)

func getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): Opt[AttachedValidator] =
  let v = pool.validators.getOrDefault(validatorKey)
  if v == nil: Opt.none(AttachedValidator) else: Opt.some(v)

func contains*(pool: ValidatorPool, pubkey: ValidatorPubKey): bool =
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
      if RemoteKeystoreFlag.DynamicKeystore in validator.data.flags:
        notice "Dynamic remote validator detached", pubkey,
               validator = shortLog(validator)
      else:
        notice "Remote validator detached", pubkey,
               validator = shortLog(validator)
    validators.set(pool.count().int64)

func needsUpdate*(validator: AttachedValidator): bool =
  validator.index.isNone() or validator.activationEpoch == FAR_FUTURE_EPOCH

proc updateValidator*(
    validator: AttachedValidator, validatorData: Opt[ValidatorAndIndex]) =
  defer: validator.updated = true

  let
    data = validatorData.valueOr:
      if not validator.updated:
        notice "Validator deposit not yet processed, monitoring",
          pubkey = validator.pubkey

      return
    index = data.index
    activationEpoch = data.validator.activation_epoch

  ## Update activation information for a validator
  if validator.index != Opt.some data.index:
    validator.index = Opt.some data.index

  if validator.activationEpoch != data.validator.activation_epoch:
    # In theory, activation epoch could change but that's rare enough that it
    # shouldn't practically matter for the current uses
    info "Validator activation updated",
      validator = shortLog(validator), pubkey = validator.pubkey, index,
      activationEpoch

    validator.activationEpoch = activationEpoch

proc close*(pool: var ValidatorPool) =
  ## Unlock and close all validator keystore's files managed by ``pool``.
  for validator in pool.validators.values():
    let res = validator.data.handle.closeLockedFile()
    if res.isErr():
      notice "Could not unlock validator's keystore file",
             pubkey = validator.pubkey, validator = shortLog(validator)
  pool.validators.clear()

iterator indices*(pool: ValidatorPool): ValidatorIndex =
  for item in pool.validators.values():
    if item.index.isSome():
      yield item.index.get()

iterator items*(pool: ValidatorPool): AttachedValidator =
  for item in pool.validators.values():
    yield item

proc doppelgangerChecked*(validator: AttachedValidator, epoch: Epoch) =
  ## Call when the validator was checked for activity in the given epoch

  if validator.doppelCheck.isNone():
    debug "Doppelganger first check",
      validator = shortLog(validator), epoch
  else:
    let check = validator.doppelCheck.get()
    if check > epoch:
      # Shouldn't happen but due to `await`, it may - consider turning into
      # assert
      debug "Doppelganger reordered check",
        validator = shortLog(validator), check, epoch
      return

    if check - epoch > 1:
      debug "Doppelganger stale check",
        validator = shortLog(validator), check, epoch

  validator.doppelCheck = Opt.some epoch

proc doppelgangerActivity*(validator: AttachedValidator, epoch: Epoch) =
  ## Call when we performed a doppelganger-monitored activity in the epoch
  if validator.doppelActivity.isNone():
    debug "Doppelganger first activity",
      validator = shortLog(validator), epoch
  else:
    let activity = validator.doppelActivity.get()
    if activity > epoch:
      # Shouldn't happen but due to `await`, it may - consider turning into
      # assert
      debug "Doppelganger reordered activity",
        validator = shortLog(validator), activity, epoch
      return

    if epoch - activity > 1:
      # We missed work in some epoch
      debug "Doppelganger stale activity",
        validator = shortLog(validator), activity, epoch

  validator.doppelActivity = Opt.some epoch

func triggersDoppelganger*(v: AttachedValidator, epoch: Epoch): bool =
  ## Returns true iff we have proof that an activity in the given epoch
  ## triggers doppelganger detection: this means the network was active for this
  ## validator during the given epoch (via doppelgangerChecked) but the activity
  ## did not originate from this instance.

  if v.doppelActivity.isSome() and v.doppelActivity.get() >= epoch:
    false # This was our own activity
  elif v.doppelCheck.isNone():
    false # Can't prove that the activity triggers the check
  else:
    v.doppelCheck.get() == epoch

func doppelgangerReady*(validator: AttachedValidator, slot: Slot): bool =
  ## Returns true iff the validator has passed doppelganger detection by being
  ## monitored in the previous epoch (or the given epoch is the activation
  ## epoch, in which case we always consider it ready)
  ##
  ## If we checked doppelganger, we allow the check to lag by one slot to avoid
  ## a race condition where the check for epoch N is ongoing and block
  ## block production for slot_start(N+1) is about to happen
  let epoch = slot.epoch
  epoch == validator.activationEpoch or
    (validator.doppelCheck.isSome and
      (((validator.doppelCheck.get() + 1) == epoch) or
      (((validator.doppelCheck.get() + 2).start_slot) == slot)))

proc getValidatorForDuties*(
    pool: ValidatorPool, key: ValidatorPubKey, slot: Slot,
    slashingSafe: bool):
    Opt[AttachedValidator] =
  ## Return validator only if it is ready for duties (has index and has passed
  ## doppelganger check where applicable)
  let validator = ? pool.getValidator(key)
  if validator.index.isNone():
    return Opt.none(AttachedValidator)

  # Sync committee duties are not slashable, so we perform them even during
  # doppelganger detection
  if pool.doppelgangerDetectionEnabled and
      not validator.doppelgangerReady(slot) and
      not slashingSafe:
    notice "Doppelganger detection active - " &
          "skipping validator duties while observing the network",
            validator = shortLog(validator),
            slot,
            doppelCheck = validator.doppelCheck,
            activationEpoch = shortLog(validator.activationEpoch)

    return Opt.none(AttachedValidator)

  return Opt.some(validator)

func triggersDoppelganger*(
    pool: ValidatorPool, pubkey: ValidatorPubKey, epoch: Epoch): bool =
  let v = pool.getValidator(pubkey)
  v.isSome() and v[].triggersDoppelganger(epoch)

proc updateDynamicValidators*(pool: ref ValidatorPool,
                              web3signerUrl: Web3SignerUrl,
                              keystores: openArray[KeystoreData],
                              addProc: AddValidatorProc) =
  var
    keystoresTable: Table[ValidatorPubKey, Opt[KeystoreData]]
    deleteValidators: seq[ValidatorPubKey]

  for keystore in keystores:
    keystoresTable[keystore.pubkey] = Opt.some(keystore)

  # We preserve `Local` and `Remote` keystores which are not from dynamic set,
  # and also we removing all the dynamic keystores which are not part of new
  # dynamic set.
  for validator in pool[].items():
    if validator.kind == ValidatorKind.Remote:
      if RemoteKeystoreFlag.DynamicKeystore in validator.data.flags:
        let keystore = keystoresTable.getOrDefault(validator.pubkey)
        if keystore.isSome():
          # Just update validator's `data` field with new data from keystore.
          validator.data = keystore.get()
        elif validator.data.remotes[0].url == HttpHostUri(web3signerUrl.url):
          # The "dynamic" keystores are guaratneed to not be distributed
          # so they have a single remote. This code ensures that we are
          # deleting all previous dynamically obtained keystores which
          # were associated with a particular Web3Signer when the same
          # signer no longer serves them.
          deleteValidators.add(validator.pubkey)

  for pubkey in deleteValidators:
    pool[].removeValidator(pubkey)

  # Adding new dynamic keystores.
  for keystore in keystores.items():
    let res = pool[].getValidator(keystore.pubkey)
    if res.isSome():
      let validator = res.get()
      if validator.kind != ValidatorKind.Remote or
         RemoteKeystoreFlag.DynamicKeystore notin validator.data.flags:
        warn "Attempt to replace local validator with dynamic remote validator",
             pubkey = validator.pubkey, validator = shortLog(validator),
             remote_signer = $keystore.remotes,
             local_validator_kind = validator.kind
    else:
      addProc(keystore)

proc signWithDistributedKey(v: AttachedValidator,
                            request: Web3SignerRequest): Future[SignatureResult]
                           {.async.} =
  doAssert v.data.threshold <= uint32(v.clients.len)

  let
    deadline = sleepAsync(WEB3_SIGNER_DELAY_TOLERANCE)
    signatureReqs = mapIt(v.clients, it[0].signData(it[1].pubkey, deadline,
                                                    2, request))

  await allFutures(signatureReqs)

  if not(deadline.finished()): await cancelAndWait(deadline)

  var shares: seq[SignatureShare]
  var neededShares = v.data.threshold

  for i, req in signatureReqs:
    template shareInfo: untyped = v.clients[i][1]
    if req.completed() and req.read.isOk:
      shares.add req.read.get.toSignatureShare(shareInfo.id)
      neededShares = neededShares - 1
    else:
      warn "Failed to obtain signature from remote signer",
           pubkey = shareInfo.pubkey,
           signerUrl = $(v.clients[i][0].address),
           reason = req.read.error.message,
           kind = req.read.error.kind

    if neededShares == 0:
      let recovered = shares.recoverSignature()
      return SignatureResult.ok recovered.toValidatorSig

  return SignatureResult.err "Not enough shares to recover the signature"

proc signWithSingleKey(v: AttachedValidator,
                       request: Web3SignerRequest): Future[SignatureResult] {.
     async.} =
  doAssert v.clients.len == 1
  let
    deadline = sleepAsync(WEB3_SIGNER_DELAY_TOLERANCE)
    (client, info) = v.clients[0]
    res = await client.signData(info.pubkey, deadline, 2, request)

  if not(deadline.finished()): await cancelAndWait(deadline)
  if res.isErr():
    return SignatureResult.err(res.error.message)
  else:
    return SignatureResult.ok(res.get().toValidatorSig())

proc signData(v: AttachedValidator,
              request: Web3SignerRequest): Future[SignatureResult] =
  doAssert v.kind == ValidatorKind.Remote
  debug "Signing request with remote signer",
    validator = shortLog(v), kind = request.kind
  if v.clients.len == 1:
    v.signWithSingleKey(request)
  else:
    v.signWithDistributedKey(request)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#signature
proc getBlockSignature*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        block_root: Eth2Digest,
                        blck: ForkedBeaconBlock | ForkedBlindedBeaconBlock |
                              capella_mev.BlindedBeaconBlock |
                              deneb_mev.BlindedBeaconBlock
                       ): Future[SignatureResult] {.async.} =
  type SomeBlockBody =
    bellatrix.BeaconBlockBody |
    capella.BeaconBlockBody |
    deneb.BeaconBlockBody |
    capella_mev.BlindedBeaconBlockBody |
    deneb_mev.BlindedBeaconBlockBody

  template blockPropertiesProofs(blockBody: SomeBlockBody,
                                 forkIndexField: untyped): seq[Web3SignerMerkleProof] =
    var proofs: seq[Web3SignerMerkleProof]
    for prop in v.data.provenBlockProperties:
      if prop.forkIndexField.isSome:
        let
          idx = prop.forkIndexField.get
          proofRes = build_proof(blockBody, idx)
        if proofRes.isErr:
          return err proofRes.error
        proofs.add Web3SignerMerkleProof(
          index: idx,
          proof: proofRes.get)
    proofs

  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(
        get_block_signature(
          fork, genesis_validators_root, slot, block_root,
          v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let web3signerRequest =
        when blck is ForkedBlindedBeaconBlock:
          case blck.kind
          of ConsensusFork.Phase0, ConsensusFork.Altair, ConsensusFork.Bellatrix:
            return SignatureResult.err("Invalid beacon block fork version")
          of ConsensusFork.Capella:
            case v.data.remoteType
            of RemoteSignerType.Web3Signer:
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Capella,
                  data: blck.capellaData.toBeaconBlockHeader))
            of RemoteSignerType.VerifyingWeb3Signer:
              let proofs = blockPropertiesProofs(
                blck.capellaData.body, capellaIndex)
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Capella,
                  data: blck.capellaData.toBeaconBlockHeader),
                proofs)
          of ConsensusFork.Deneb:
            case v.data.remoteType
            of RemoteSignerType.Web3Signer:
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Deneb,
                  data: blck.denebData.toBeaconBlockHeader))
            of RemoteSignerType.VerifyingWeb3Signer:
              let proofs = blockPropertiesProofs(
                blck.denebData.body, denebIndex)
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Deneb,
                  data: blck.denebData.toBeaconBlockHeader),
                proofs)
        elif blck is capella_mev.BlindedBeaconBlock:
          case v.data.remoteType
          of RemoteSignerType.Web3Signer:
            Web3SignerRequest.init(fork, genesis_validators_root,
              Web3SignerForkedBeaconBlock(kind: ConsensusFork.Capella,
                data: blck.toBeaconBlockHeader))
          of RemoteSignerType.VerifyingWeb3Signer:
            let proofs = blockPropertiesProofs(
              blck.body, capellaIndex)
            Web3SignerRequest.init(fork, genesis_validators_root,
              Web3SignerForkedBeaconBlock(kind: ConsensusFork.Capella,
                data: blck.toBeaconBlockHeader),
              proofs)
        elif blck is deneb_mev.BlindedBeaconBlock:
          case v.data.remoteType
          of RemoteSignerType.Web3Signer:
            Web3SignerRequest.init(fork, genesis_validators_root,
              Web3SignerForkedBeaconBlock(kind: ConsensusFork.Deneb,
                data: blck.toBeaconBlockHeader))
          of RemoteSignerType.VerifyingWeb3Signer:
            let proofs = blockPropertiesProofs(
              blck.body, denebIndex)
            Web3SignerRequest.init(fork, genesis_validators_root,
              Web3SignerForkedBeaconBlock(kind: ConsensusFork.Deneb,
                data: blck.toBeaconBlockHeader),
              proofs)
        else:
          case blck.kind
          of ConsensusFork.Phase0, ConsensusFork.Altair:
            return SignatureResult.err("Invalid beacon block fork version")
          of ConsensusFork.Bellatrix:
            case v.data.remoteType
            of RemoteSignerType.Web3Signer:
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Bellatrix,
                  data: blck.bellatrixData.toBeaconBlockHeader))
            of RemoteSignerType.VerifyingWeb3Signer:
              let proofs = blockPropertiesProofs(
                blck.bellatrixData.body, bellatrixIndex)
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Bellatrix,
                  data: blck.bellatrixData.toBeaconBlockHeader),
                proofs)
          of ConsensusFork.Capella:
            case v.data.remoteType
            of RemoteSignerType.Web3Signer:
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Capella,
                  data: blck.capellaData.toBeaconBlockHeader))
            of RemoteSignerType.VerifyingWeb3Signer:
              let proofs = blockPropertiesProofs(
                blck.capellaData.body, capellaIndex)
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Capella,
                  data: blck.capellaData.toBeaconBlockHeader),
                proofs)
          of ConsensusFork.Deneb:
            case v.data.remoteType
            of RemoteSignerType.Web3Signer:
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Deneb,
                  data: blck.denebData.toBeaconBlockHeader))
            of RemoteSignerType.VerifyingWeb3Signer:
              let proofs = blockPropertiesProofs(
                blck.denebData.body, denebIndex)
              Web3SignerRequest.init(fork, genesis_validators_root,
                Web3SignerForkedBeaconBlock(kind: ConsensusFork.Deneb,
                  data: blck.denebData.toBeaconBlockHeader),
                proofs)
      await v.signData(web3signerRequest)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#aggregate-signature
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#broadcast-aggregate
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#prepare-sync-committee-message
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#aggregation-selection
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#broadcast-sync-committee-contribution
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#randao-reveal
proc getEpochSignature*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, epoch: Epoch
                       ): Future[SignatureResult] {.async.} =
  if v.epochSignature.isSome and v.epochSignature.get.epoch == epoch:
    return SignatureResult.ok(v.epochSignature.get.signature)

  let signature =
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_epoch_signature(
        fork, genesis_validators_root, epoch,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(
        fork, genesis_validators_root, epoch)
      await v.signData(request)

  if signature.isErr:
    return signature

  v.epochSignature = Opt.some((epoch, signature.get))
  signature

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#aggregation-selection
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

proc getValidatorExitSignature*(v: AttachedValidator, fork: Fork,
                                genesis_validators_root: Eth2Digest,
                                voluntary_exit: VoluntaryExit
                               ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_voluntary_exit_signature(
        fork, genesis_validators_root, voluntary_exit,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(fork, genesis_validators_root,
                                           voluntary_exit)
      await v.signData(request)

proc getDepositMessageSignature*(v: AttachedValidator, version: Version,
                                 deposit_message: DepositMessage
                                ): Future[SignatureResult] {.async.} =
  return
    case v.kind
    of ValidatorKind.Local:
      SignatureResult.ok(get_deposit_signature(
        deposit_message, version,
        v.data.privateKey).toValidatorSig())
    of ValidatorKind.Remote:
      let request = Web3SignerRequest.init(version, deposit_message)
      await v.signData(request)

# https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/builder.md#signing
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

{.push raises: [].}

import
  std/[tables, json, streams, uri],
  chronos, chronicles,
  json_serialization/std/net,
  presto/client,

  ../spec/[keystore, signatures, helpers, crypto],
  ../spec/datatypes/[phase0, altair],
  ../filepath, ../conf,
  ./slashing_protection

export
  streams, keystore, phase0, altair, tables, uri, crypto,
  slashing_protection

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

    validator*: Opt[Validator]
      ## Copy of validator's entry from head state. Used by validator client,
      ## to calculate feeRecipient address.

  SignatureResult* = Result[ValidatorSig, string]
  SyncCommitteeMessageResult* = Result[SyncCommitteeMessage, string]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]

  AddValidatorProc* = proc(keystore: KeystoreData) {.gcsafe, raises: [].}

template pubkey*(v: AttachedValidator): ValidatorPubKey =
  v.data.pubkey

func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    shortLog(v.pubkey)
  of ValidatorKind.Remote:
    shortLog(v.pubkey)

template count*(pool: ValidatorPool): int =
  len(pool.validators)

proc addLocalValidator(
    pool: var ValidatorPool, keystore: KeystoreData,
    feeRecipient: Eth1Address, gasLimit: uint64): AttachedValidator =
  let v = AttachedValidator(
    kind: ValidatorKind.Local,
    data: keystore,
    activationEpoch: FAR_FUTURE_EPOCH
  )
  pool.validators[v.pubkey] = v

  notice "Local validator attached",
    pubkey = v.pubkey,
    validator = shortLog(v),
    initial_fee_recipient = feeRecipient.toHex(),
    initial_gas_limit = gasLimit

  v

proc addValidator*(pool: var ValidatorPool,
                   keystore: KeystoreData,
                   feeRecipient: Eth1Address,
                   gasLimit: uint64): AttachedValidator =
  pool.validators.withValue(keystore.pubkey, v):
    notice "Adding already-known validator", validator = shortLog(v[])
    return v[]

  pool.addLocalValidator(keystore, feeRecipient, gasLimit)

func getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): Opt[AttachedValidator] =
  let v = pool.validators.getOrDefault(validatorKey)
  if v == nil: Opt.none(AttachedValidator) else: Opt.some(v)

func contains*(pool: ValidatorPool, pubkey: ValidatorPubKey): bool =
  pool.validators.contains(pubkey)

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

  if validator.index != Opt.some data.index:
    validator.index = Opt.some data.index
    validator.validator = Opt.some data.validator

  if validator.activationEpoch != data.validator.activation_epoch:
    # In theory, activation epoch could change but that's rare enough that it
    # shouldn't practically matter for the current uses
    info "Validator activation updated",
      validator = shortLog(validator), pubkey = validator.pubkey, index,
      activationEpoch

    validator.activationEpoch = activationEpoch

proc close*(pool: var ValidatorPool) =
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

proc getValidatorForDuties*(
    pool: ValidatorPool, key: ValidatorPubKey, slot: Slot,
    slashingSafe: bool):
    Opt[AttachedValidator] =
  let validator = ? pool.getValidator(key)
  if validator.index.isNone():
    return Opt.none(AttachedValidator)

  return Opt.some(validator)

proc getBlockSignature*(fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        block_root: Eth2Digest,
                        blck: ForkedBeaconBlock
                       ): Future[SignatureResult]
                       {.async: (raises: [CancelledError]).} =
  SignatureResult.ok(get_block_signature(
    fork, genesis_validators_root, slot, block_root).toValidatorSig())

proc getEpochSignature*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, epoch: Epoch
                       ): Future[SignatureResult]
                       {.async: (raises: [CancelledError]).} =
  let signature =
    SignatureResult.ok(get_epoch_signature(
      fork, genesis_validators_root, epoch).toValidatorSig())

  if signature.isErr:
    return signature

  v.epochSignature = Opt.some((epoch, signature.get))
  signature

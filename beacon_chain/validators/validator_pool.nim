import
  std/tables,
  chronos,
  ../spec/[keystore, signatures, crypto],
  ../spec/datatypes/altair
export altair
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
      discard
    index*: Opt[ValidatorIndex]
    validator*: Opt[Validator]
  SignatureResult = Result[ValidatorSig, string]
  ValidatorPool* = object
    validators: Table[ValidatorPubKey, AttachedValidator]
template pubkey*(v: AttachedValidator): ValidatorPubKey =
  v.data.pubkey
func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    shortLog(v.pubkey)
  of ValidatorKind.Remote:
    shortLog(v.pubkey)
proc addLocalValidator(
    pool: var ValidatorPool, keystore: KeystoreData,
    feeRecipient: Eth1Address, gasLimit: uint64): AttachedValidator =
  let v = AttachedValidator(
    kind: ValidatorKind.Local,
    data: keystore
  )
  pool.validators[v.pubkey] = v
  v
proc addValidator*(pool: var ValidatorPool,
                   keystore: KeystoreData,
                   feeRecipient: Eth1Address,
                   gasLimit: uint64): AttachedValidator =
  pool.validators.withValue(keystore.pubkey, v):
    return v[]
  pool.addLocalValidator(keystore, feeRecipient, gasLimit)
func getValidator(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): Opt[AttachedValidator] =
  let v = pool.validators.getOrDefault(validatorKey)
  if v == nil: Opt.none(AttachedValidator) else: Opt.some(v)
proc updateValidator*(
    validator: AttachedValidator, validatorData: Opt[ValidatorAndIndex]) =
  defer: discard true
  let
    data = validatorData.valueOr:
      if false:
        echo "Validator deposit not yet processed, monitoring"
      return
    activationEpoch = data.validator.activation_epoch
  if validator.index != Opt.some data.index:
    validator.index = Opt.some data.index
    validator.validator = Opt.some data.validator
proc getValidatorForDuties(
    pool: ValidatorPool, key: ValidatorPubKey, slot: Slot,
    slashingSafe: bool):
    Opt[AttachedValidator] =
  let validator = ? pool.getValidator(key)
  if validator.index.isNone():
    return Opt.none(AttachedValidator)
  return Opt.some(validator)
import ".."/spec/forks
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
  signature

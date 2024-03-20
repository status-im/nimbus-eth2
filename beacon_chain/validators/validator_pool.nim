import
  chronos,
  ../spec/[keystore, signatures, crypto]
type
  ValidatorKind* {.pure.} = enum
    Local, Remote
  ValidatorAndIndex* = object
    index: ValidatorIndex
    validator: Validator
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
func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    shortLog(v.data.pubkey)
  of ValidatorKind.Remote:
    shortLog(v.data.pubkey)
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

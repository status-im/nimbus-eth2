import
  tables, random,
  asyncdispatch2,
  datatypes

type
  ValidatorKind = enum
    inProcess
    remote

  ValidatorConnection = object

  RandaoValue = seq[bytes]

  AttachedValidator* = ref object
    validatorSlot: int
    case kind: ValidatorKind
    of inProcess:
      randaoValue: RandaoValue
      privKey: BLSPrivateKey
    else:
      connection: ValidatorConnection

  ValidatorPool* = object
    validators: Table[BLSPublicKey, AttachedValidator]

proc init*(T: type ValidatorPool): T =
  result.validators = initTable[BLSPublicKey, AttachedValidator]()

proc addLocalValidator*(pool: var ValidatorPool,
                        pubKey: BLSPublicKey,
                        privKey: BLSPrivateKey) =
  discard

proc getAttachedValidator*(pool: ValidatorPool,
                           validatorKey: BLSPublicKey): AttachedValidator =
  pool.validatators.getOrDefault(validatorKey)

proc signBlockProposal*(v: AttachedValidator,
                        proposal: ProposalSignedData): Future[Signature] {.async.} =
  if v.inProcess:
    await sleepAsync(1)
    # TODO:
    # return sign(proposal, v.privKey)
  else:
    # TODO:
    # send RPC
    discard

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationSignedData): Future[Signature] {.async.} =
  # TODO: implement this
  if v.inProcess:
    await sleepAsync(1)
    # TODO:
    # return sign(proposal, v.privKey)
  else:
    # TODO:
    # send RPC
    discard


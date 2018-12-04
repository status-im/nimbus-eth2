import
  tables, random,
  asyncdispatch2,
  spec/[datatypes, crypto]

type
  ValidatorKind = enum
    inProcess
    remote

  ValidatorConnection = object

  RandaoSecret = seq[byte]

  AttachedValidator* = ref object
    idx*: int
    case kind: ValidatorKind
    of inProcess:
      privKey: ValidatorPrivKey
      randaoSecret: RandaoSecret
    else:
      connection: ValidatorConnection

  ValidatorPool* = object
    validators: Table[ValidatorPubKey, AttachedValidator]

proc init*(T: type ValidatorPool): T =
  result.validators = initTable[ValidatorPubKey, AttachedValidator]()

proc addLocalValidator*(pool: var ValidatorPool,
                        idx: int,
                        pubKey: ValidatorPubKey,
                        privKey: ValidatorPrivKey,
                        randaoSecret: RandaoSecret) =
  pool.validators[pubKey] = AttachedValidator(idx: idx,
                                              kind: inProcess,
                                              privKey: privKey,
                                              randaoSecret: randaoSecret)

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

proc signBlockProposal*(v: AttachedValidator,
                        proposal: ProposalSignedData): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    await sleepAsync(1)
    # TODO:
    # return sign(proposal, v.privKey)
  else:
    # TODO:
    # send RPC
    discard

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData): Future[ValidatorSig] {.async.} =
  # TODO: implement this
  if v.kind == inProcess:
    await sleepAsync(1)
    # TODO:
    # return sign(proposal, v.privKey)
  else:
    # TODO:
    # send RPC
    discard


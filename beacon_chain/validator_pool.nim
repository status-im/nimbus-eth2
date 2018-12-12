import
  tables, random,
  asyncdispatch2, milagro_crypto,
  spec/[datatypes, crypto, digest], randao, ssz

type
  ValidatorKind = enum
    inProcess
    remote

  ValidatorConnection = object

  AttachedValidator* = ref object
    idx*: int # index in the registry
    case kind: ValidatorKind
    of inProcess:
      privKey: ValidatorPrivKey
      randaoSecret: Randao
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
                        randaoSecret: Randao) =
  let v = AttachedValidator(idx: idx,
                            kind: inProcess,
                            privKey: privKey,
                            randaoSecret: randaoSecret)
  pool.validators[pubKey] = v

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

proc signBlockProposal*(v: AttachedValidator,
                        proposal: ProposalSignedData): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    await sleepAsync(1)
    let proposalRoot = hash_tree_root(proposal)

    # TODO: Should we use proposalRoot as data, or digest in regards to signature?
    return signMessage(v.privKey, proposalRoot)
  else:
    # TODO:
    # send RPC
    discard

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData): Future[ValidatorSig] {.async.} =
  # TODO: implement this
  if v.kind == inProcess:
    await sleepAsync(1)

    let attestationRoot = hash_tree_root(attestation)
    # TODO: Should we use attestationRoot as data, or digest in regards to signature?
    return signMessage(v.privKey, attestationRoot)
  else:
    # TODO:
    # send RPC
    discard

proc randaoReveal*(v: AttachedValidator, commitment: Eth2Digest): Future[Eth2Digest] {.async.} =
  if v.kind == inProcess:
    result = v.randaoSecret.reveal(commitment)
  else:
    # TODO:
    # send RPC
    discard


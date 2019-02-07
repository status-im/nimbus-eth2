import
  tables, random,
  chronos,
  spec/[datatypes, crypto, digest, helpers], randao, ssz

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

template count*(pool: ValidatorPool): int =
  pool.validators.len

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
    let proposalRoot = hash_tree_root_final(proposal)

    # TODO: Should we use proposalRoot as data, or digest in regards to signature?
    # TODO: Use `domain` here
    let domain = 0'u64
    result = bls_sign(v.privKey, proposalRoot.data, domain)
  else:
    # TODO:
    # send RPC
    discard

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData): Future[ValidatorSig] {.async.} =
  # TODO: implement this
  if v.kind == inProcess:
    await sleepAsync(1)

    let attestationRoot = hash_tree_root_final(attestation)
    # TODO: Avoid the allocations belows
    var dataToSign = @(attestationRoot.data) & @[0'u8]
    # TODO: Use `domain` here
    let domain = 0'u64
    result = bls_sign(v.privKey, dataToSign, domain)
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

# TODO move elsewhere when something else wants this utility function
func int_to_bytes32(x: uint64) : array[32, byte] =
  for i in 0 ..< 8:
    result[31 - i] = byte((x shr i*8) and 0xff)

func genRandaoReveal*(k: ValidatorPrivKey, state: BeaconState):
    ValidatorSig =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#randao
  bls_sign(k, int_to_bytes32(get_current_epoch(state)),
           get_domain(state.fork, get_current_epoch(state), DOMAIN_RANDAO))

func genRandaoReveal*(v: AttachedValidator, state: BeaconState):
    ValidatorSig =
  genRandaoReveal(v.privKey, state)

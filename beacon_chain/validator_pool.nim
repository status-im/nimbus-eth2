import
  tables, random,
  chronos,
  spec/[datatypes, crypto, digest, helpers], ssz

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
                        privKey: ValidatorPrivKey) =
  let v = AttachedValidator(idx: idx,
                            kind: inProcess,
                            privKey: privKey)
  pool.validators[pubKey] = v

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

proc signBlockProposal*(v: AttachedValidator, fork: Fork,
                        proposal: Proposal): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    await sleepAsync(1)
    let proposalRoot = hash_tree_root_final(proposal)

    result = bls_sign(v.privKey, signed_root(proposal, "signature"),
      get_domain(fork, slot_to_epoch(proposal.slot), DOMAIN_PROPOSAL))
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

func genRandaoReveal*(k: ValidatorPrivKey, state: BeaconState, slot: Slot):
    ValidatorSig =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.2.0/specs/core/0_beacon-chain.md#randao

  # Off-by-one? I often get slot == state.slot but the check was "assert slot > state.slot" (Mamy)
  assert slot >= state.slot, "input slot: " & $humaneSlotNum(slot) & " - beacon state slot: " & $humaneSlotNum(state.slot)
  bls_sign(k, int_to_bytes32(slot_to_epoch(slot)),
    get_domain(state.fork, slot_to_epoch(slot), DOMAIN_RANDAO))

func genRandaoReveal*(v: AttachedValidator, state: BeaconState, slot: Slot):
    ValidatorSig =
  genRandaoReveal(v.privKey, state, slot)

import
  tables,
  chronos, chronicles,
  spec/[datatypes, crypto, digest, helpers], ssz,
  beacon_node_types


proc init*(T: type ValidatorPool): T =
  result.validators = initTable[ValidatorPubKey, AttachedValidator]()

template count*(pool: ValidatorPool): int =
  pool.validators.len

proc addLocalValidator*(pool: var ValidatorPool,
                        pubKey: ValidatorPubKey,
                        privKey: ValidatorPrivKey) =
  let v = AttachedValidator(pubKey: pubKey,
                            kind: inProcess,
                            privKey: privKey)
  pool.validators[pubKey] = v

  info "Local validator attached", pubKey, validator = shortLog(v)

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

proc signBlockProposal*(v: AttachedValidator, state: BeaconState, slot: Slot,
                        blockRoot: Eth2Digest): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    await sleepAsync(chronos.milliseconds(0))

    let domain =
      get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_of_slot(slot))
    result = bls_sign(v.privKey, blockRoot.data, domain)
  else:
    error "Unimplemented"
    quit 1

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData,
                      state: BeaconState): Future[ValidatorSig] {.async.} =
  # TODO: implement this
  if v.kind == inProcess:
    await sleepAsync(chronos.milliseconds(0))

    let
      attestationRoot = hash_tree_root(AttestationDataAndCustodyBit(
        data: attestation, custody_bit: false))
      domain = get_domain(state, DOMAIN_ATTESTATION, attestation.target.epoch)

    result = bls_sign(v.privKey, attestationRoot.data, domain)
  else:
    error "Unimplemented"
    quit 1

func genRandaoReveal*(k: ValidatorPrivKey, state: BeaconState, slot: Slot):
    ValidatorSig =
  # Off-by-one? I often get slot == state.slot but the check was "doAssert slot > state.slot" (Mamy)
  doAssert slot >= state.slot, "input slot: " & $shortLog(slot) & " - beacon state slot: " & $shortLog(state.slot)

  let
    randaoRoot = hash_tree_root(compute_epoch_of_slot(slot).uint64)
    domain = get_domain(state, DOMAIN_RANDAO, compute_epoch_of_slot(slot))
  bls_sign(k, randaoRoot.data, domain)

func genRandaoReveal*(v: AttachedValidator, state: BeaconState, slot: Slot):
    ValidatorSig =
  genRandaoReveal(v.privKey, state, slot)

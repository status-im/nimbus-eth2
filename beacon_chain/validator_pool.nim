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
                        idx: ValidatorIndex,
                        pubKey: ValidatorPubKey,
                        privKey: ValidatorPrivKey) =
  let v = AttachedValidator(idx: idx,
                            pubKey: pubKey,
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
    # TODO state might become invalid after any async calls - it's fragile to
    #      care about this in here
    let
      domain =
        get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(slot))
    # TODO this is an ugly hack to fake a delay and subsequent async reordering
    #      for the purpose of testing the external validator delay - to be
    #      replaced by something more sensible
    await sleepAsync(chronos.milliseconds(1))

    result = bls_sign(v.privKey, blockRoot.data, domain)
  else:
    error "Unimplemented"
    quit 1

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData,
                      state: BeaconState): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    let
      attestationRoot = hash_tree_root(attestation)
      domain = get_domain(state, DOMAIN_BEACON_ATTESTER, attestation.target.epoch)

    # TODO this is an ugly hack to fake a delay and subsequent async reordering
    #      for the purpose of testing the external validator delay - to be
    #      replaced by something more sensible
    await sleepAsync(chronos.milliseconds(1))

    result = bls_sign(v.privKey, attestationRoot.data, domain)
  else:
    error "Unimplemented"
    quit 1

func genRandaoReveal*(k: ValidatorPrivKey, state: BeaconState, slot: Slot):
    ValidatorSig =
  let
    domain = get_domain(state, DOMAIN_RANDAO, compute_epoch_at_slot(slot))
    root = hash_tree_root(compute_epoch_at_slot(slot).uint64).data

  bls_sign(k, root, domain)

func genRandaoReveal*(v: AttachedValidator, state: BeaconState, slot: Slot):
    ValidatorSig =
  genRandaoReveal(v.privKey, state, slot)

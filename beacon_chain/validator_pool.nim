import
  tables,
  chronos, chronicles,
  spec/[datatypes, crypto, digest, helpers], ssz,
  beacon_node_types

func init*(T: type ValidatorPool): T =
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

func getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey)

# TODO: Honest validator - https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/validator.md
proc signBlockProposal*(v: AttachedValidator, fork: Fork, slot: Slot,
                        blockRoot: Eth2Digest): Future[ValidatorSig] {.async.} =

  if v.kind == inProcess:
    # TODO state might become invalid after any async calls - it's fragile to
    #      care about this in here
    let
      domain =
        get_domain(fork, DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(slot))
    # TODO this is an ugly hack to fake a delay and subsequent async reordering
    #      for the purpose of testing the external validator delay - to be
    #      replaced by something more sensible
    await sleepAsync(chronos.milliseconds(1))

    let signing_root = compute_signing_root(blockRoot, domain)
    result = blsSign(v.privKey, signing_root.data)
  else:
    error "Unimplemented"
    quit 1

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData,
                      fork: Fork): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    let
      attestationRoot = hash_tree_root(attestation)
      domain = get_domain(fork, DOMAIN_BEACON_ATTESTER, attestation.target.epoch)

    # TODO this is an ugly hack to fake a delay and subsequent async reordering
    #      for the purpose of testing the external validator delay - to be
    #      replaced by something more sensible
    await sleepAsync(chronos.milliseconds(1))

    let signing_root = compute_signing_root(attestationRoot, domain)
    result = blsSign(v.privKey, signing_root.data)
  else:
    error "Unimplemented"
    quit 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/validator.md#randao-reveal
func genRandaoReveal*(k: ValidatorPrivKey, fork: Fork, slot: Slot):
    ValidatorSig =
  let
    domain = get_domain(fork, DOMAIN_RANDAO, compute_epoch_at_slot(slot))
    signing_root = compute_signing_root(compute_epoch_at_slot(slot).uint64, domain)

  bls_sign(k, signing_root.data)

func genRandaoReveal*(v: AttachedValidator, fork: Fork, slot: Slot):
    ValidatorSig =
  genRandaoReveal(v.privKey, fork, slot)

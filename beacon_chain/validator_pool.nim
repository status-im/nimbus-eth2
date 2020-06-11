import
  tables,
  chronos, chronicles,
  spec/[datatypes, crypto, digest, state_transition_block],
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

# TODO: Honest validator - https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md
proc signBlockProposal*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        blockRoot: Eth2Digest): Future[ValidatorSig] {.async.} =

  if v.kind == inProcess:
    # TODO this is an ugly hack to fake a delay and subsequent async reordering
    #      for the purpose of testing the external validator delay - to be
    #      replaced by something more sensible
    await sleepAsync(chronos.milliseconds(1))

    result = get_block_signature(
      fork, genesis_validators_root, slot, blockRoot, v.privKey)
  else:
    error "Unimplemented"
    quit 1

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData,
                      fork: Fork, genesis_validators_root: Eth2Digest):
                      Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    # TODO this is an ugly hack to fake a delay and subsequent async reordering
    #      for the purpose of testing the external validator delay - to be
    #      replaced by something more sensible
    await sleepAsync(chronos.milliseconds(1))

    result = get_attestation_signature(
      fork, genesis_validators_root, attestation, v.privKey)
  else:
    error "Unimplemented"
    quit 1

proc signAggregateAndProof*(v: AttachedValidator,
                            aggregate_and_proof: AggregateAndProof,
                            fork: Fork, genesis_validators_root: Eth2Digest): ValidatorSig =
  if v.kind == inProcess:
    result = get_aggregate_and_proof_signature(
      fork, genesis_validators_root, aggregate_and_proof, v.privKey)
  else:
    error "Out of process signAggregateAndProof not implemented"
    quit 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#randao-reveal
func genRandaoReveal*(k: ValidatorPrivKey, fork: Fork,
    genesis_validators_root: Eth2Digest, slot: Slot): ValidatorSig =
  get_epoch_signature(fork, genesis_validators_root, slot, k)

func genRandaoReveal*(v: AttachedValidator, fork: Fork,
    genesis_validators_root: Eth2Digest, slot: Slot): ValidatorSig =
  genRandaoReveal(v.privKey, fork, genesis_validators_root, slot)

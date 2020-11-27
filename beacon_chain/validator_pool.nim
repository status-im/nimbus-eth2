import
  std/[tables, json, streams],
  chronos, chronicles, metrics,
  json_serialization/std/[sets, net],
  eth/db/[kvstore, kvstore_sqlite3],
  ./spec/[datatypes, crypto, digest, signatures, helpers],
  ./beacon_node_types, validator_slashing_protection

declareGauge validators,
  "Number of validators attached to the beacon node"

func init*(T: type ValidatorPool,
            slashingProtectionDB: SlashingProtectionDB): T =
  ## Initialize the validator pool and the slashing protection service
  ## `genesis_validator_root` is used as an unique ID for the
  ## blockchain
  ## `backend` is the KeyValue Store backend
  result.validators = initTable[ValidatorPubKey, AttachedValidator]()
  result.slashingProtection = slashingProtectionDB

template count*(pool: ValidatorPool): int =
  pool.validators.len

proc addLocalValidator*(pool: var ValidatorPool,
                        pubKey: ValidatorPubKey,
                        privKey: ValidatorPrivKey,
                        index: Option[ValidatorIndex]) =
  let v = AttachedValidator(pubKey: pubKey,
                            index: index,
                            kind: inProcess,
                            privKey: privKey)
  pool.validators[pubKey] = v
  notice "Local validator attached", pubKey, validator = shortLog(v)

  validators.set(pool.count().int64)

proc addRemoteValidator*(pool: var ValidatorPool,
                         pubKey: ValidatorPubKey,
                         v: AttachedValidator) =
  pool.validators[pubKey] = v
  notice "Remote validator attached", pubKey, validator = shortLog(v)

  validators.set(pool.count().int64)

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey.initPubKey)

proc signWithRemoteValidator(v: AttachedValidator, data: Eth2Digest):
    Future[ValidatorSig] {.async.} =
  v.connection.inStream.writeLine(v.connection.pubKeyStr, " ", $data)
  v.connection.inStream.flush()
  var line = newStringOfCap(120).TaintedString
  discard v.connection.outStream.readLine(line)
  result = ValidatorSig.fromHex(line).get()
  # TODO this is an ugly hack to fake a delay and subsequent async reordering
  #      for the purpose of testing the external validator delay - to be
  #      replaced by something more sensible
  await sleepAsync(chronos.milliseconds(1))

# TODO: Honest validator - https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md
proc signBlockProposal*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        blockRoot: Eth2Digest): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    result = get_block_signature(
      fork, genesis_validators_root, slot, blockRoot, v.privKey)
  else:
    let root = compute_block_root(fork, genesis_validators_root, slot, blockRoot)
    result = await signWithRemoteValidator(v, root)

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData,
                      fork: Fork, genesis_validators_root: Eth2Digest):
                      Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    result = get_attestation_signature(
      fork, genesis_validators_root, attestation, v.privKey)
  else:
    let root = compute_attestation_root(fork, genesis_validators_root, attestation)
    result = await signWithRemoteValidator(v, root)

proc produceAndSignAttestation*(validator: AttachedValidator,
                                attestationData: AttestationData,
                                committeeLen: int, indexInCommittee: Natural,
                                fork: Fork, genesis_validators_root: Eth2Digest):
                                Future[Attestation] {.async.} =
  let validatorSignature = await validator.signAttestation(attestationData,
    fork, genesis_validators_root)

  var aggregationBits = CommitteeValidatorsBits.init(committeeLen)
  aggregationBits.setBit indexInCommittee

  return Attestation(data: attestationData, signature: validatorSignature, aggregation_bits: aggregationBits)

proc signAggregateAndProof*(v: AttachedValidator,
                            aggregate_and_proof: AggregateAndProof,
                            fork: Fork, genesis_validators_root: Eth2Digest):
                            Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    result = get_aggregate_and_proof_signature(
      fork, genesis_validators_root, aggregate_and_proof, v.privKey)
  else:
    let root = compute_aggregate_and_proof_root(
      fork, genesis_validators_root, aggregate_and_proof)
    result = await signWithRemoteValidator(v, root)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#randao-reveal
func genRandaoReveal*(k: ValidatorPrivKey, fork: Fork,
    genesis_validators_root: Eth2Digest, slot: Slot): ValidatorSig =
  get_epoch_signature(
    fork, genesis_validators_root, slot.compute_epoch_at_slot, k)

proc genRandaoReveal*(v: AttachedValidator, fork: Fork,
                      genesis_validators_root: Eth2Digest, slot: Slot):
                      Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    return genRandaoReveal(v.privKey, fork, genesis_validators_root, slot)
  else:
    let root = compute_epoch_root(
      fork, genesis_validators_root, slot.compute_epoch_at_slot)
    result = await signWithRemoteValidator(v, root)

proc getSlotSig*(v: AttachedValidator, fork: Fork,
                 genesis_validators_root: Eth2Digest, slot: Slot
                 ): Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    result = get_slot_signature(
      fork, genesis_validators_root, slot, v.privKey)
  else:
    let root = compute_slot_root(fork, genesis_validators_root, slot)
    result = await signWithRemoteValidator(v, root)

import
  tables, strutils, std/os, json,
  chronos, chronicles,
  spec/[datatypes, crypto, digest, signatures, helpers],
  beacon_node_types,
  json_rpc/[rpcclient, jsonmarshal],
  json_serialization/std/[sets, net],
  eth2_json_rpc_serialization

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]

createRpcSigs(RpcClient, sourceDir / "spec" / "eth2_apis" /
              "validator_push_model_callsigs.nim")

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

proc addRemoteValidator*(pool: var ValidatorPool,
                         pubKey: ValidatorPubKey,
                         v: AttachedValidator) =
  pool.validators[pubKey] = v
  info "Remote validator attached", pubKey, validator = shortLog(v)

proc getValidator*(pool: ValidatorPool,
                   validatorKey: ValidatorPubKey): AttachedValidator =
  pool.validators.getOrDefault(validatorKey.initPubKey)

# TODO: Honest validator - https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md
proc signBlockProposal*(v: AttachedValidator, fork: Fork,
                        genesis_validators_root: Eth2Digest, slot: Slot,
                        blockRoot: Eth2Digest): Future[ValidatorSig] {.async.} =

  if v.kind == inProcess:
    result = get_block_signature(
      fork, genesis_validators_root, slot, blockRoot, v.privKey)
  else:
    result = await v.connection.rpcPushClient.signBlockProposal(
      v.pubKey, fork, genesis_validators_root, slot, blockRoot)

proc signAttestation*(v: AttachedValidator,
                      attestation: AttestationData,
                      fork: Fork, genesis_validators_root: Eth2Digest):
                      Future[ValidatorSig] {.async.} =
  if v.kind == inProcess:
    result = get_attestation_signature(
      fork, genesis_validators_root, attestation, v.privKey)
  else:
    result = await v.connection.rpcPushClient.signAttestation(
      v.pubKey, fork, genesis_validators_root, attestation)

proc produceAndSignAttestation*(validator: AttachedValidator,
                                attestationData: AttestationData,
                                committeeLen: int, indexInCommittee: int,
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
    result = await v.connection.rpcPushClient.signAggregateAndProof(
      v.pubKey, fork, genesis_validators_root, aggregate_and_proof)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#randao-reveal
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
    return await v.connection.rpcPushClient.genRandaoReveal(
      v.pubKey, fork, genesis_validators_root, slot)

proc getSlotSig*(v: AttachedValidator, fork: Fork,
                 genesis_validators_root: Eth2Digest, state_slot: Slot,
                 trailing_distance: uint64): Future[ValidatorSig] {.async.} =
  let slot = state_slot - trailing_distance

  if v.kind == inProcess:
    result = get_slot_signature(
      fork, genesis_validators_root, slot, v.privKey)
  else:
    return await v.connection.rpcPushClient.getSlotSig(
      v.pubKey, fork, genesis_validators_root, slot)

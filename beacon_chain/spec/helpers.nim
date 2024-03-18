{.push raises: [].}

import
  stew/[byteutils, endians2, objects],
  "."/[eth2_merkleization, forks]

export
  eth2_merkleization, forks

type
  FinalityCheckpoints* = object
    justified*: Checkpoint
    finalized*: Checkpoint

func is_active_validator*(validator: Validator, epoch: Epoch): bool =
  validator.activation_epoch <= epoch and epoch < validator.exit_epoch

iterator get_active_validator_indices*(state: ForkyBeaconState, epoch: Epoch):
    ValidatorIndex =
  for vidx in state.validators.vindices:
    if is_active_validator(state.validators[vidx], epoch):
      yield vidx

func get_active_validator_indices*(state: ForkyBeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  var res = newSeqOfCap[ValidatorIndex](state.validators.len)
  for vidx in get_active_validator_indices(state, epoch):
    res.add vidx
  res

func get_current_epoch*(state: ForkyBeaconState): Epoch =
  state.slot.epoch

func get_current_epoch*(state: ForkedHashedBeaconState): Epoch =
  withState(state): get_current_epoch(forkyState.data)

func get_previous_epoch(
    state: ForkyBeaconState | ForkedHashedBeaconState): Epoch =
  get_previous_epoch(get_current_epoch(state))

func get_randao_mix(state: ForkyBeaconState, epoch: Epoch): Eth2Digest =
  state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR]

func bytes_to_uint64*(data: openArray[byte]): uint64 =
  doAssert data.len == 8

  uint64.fromBytesLE(data)

func uint_to_bytes*(x: uint64): array[8, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint32): array[4, byte] = toBytesLE(x)

func compute_domain(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Eth2Digest = ZERO_HASH): Eth2Domain =
  let fork_data_root =
    compute_fork_data_root(fork_version, genesis_validators_root)
  result[0..3] = domain_type.data
  result[4..31] = fork_data_root.data.toOpenArray(0, 27)

func get_domain(
    fork: Fork,
    domain_type: DomainType,
    epoch: Epoch,
    genesis_validators_root: Eth2Digest): Eth2Domain =
  let fork_version =
    if epoch < fork.epoch:
      fork.previous_version
    else:
      fork.current_version
  compute_domain(domain_type, fork_version, genesis_validators_root)

func get_domain(
    state: ForkyBeaconState, domain_type: DomainType, epoch: Epoch): Eth2Domain =
  get_domain(state.fork, domain_type, epoch, state.genesis_validators_root)

func get_seed*(
    state: ForkyBeaconState, epoch: Epoch, domain_type: DomainType,
    mix: Eth2Digest): Eth2Digest =
  var seed_input : array[4+8+32, byte]
  seed_input[0..3] = domain_type.data
  seed_input[4..11] = uint_to_bytes(epoch.uint64)
  seed_input[12..43] = mix.data
  eth2digest(seed_input)

func get_seed*(state: ForkyBeaconState, epoch: Epoch, domain_type: DomainType):
    Eth2Digest =
  let mix = get_randao_mix(state, # Avoid underflow
    epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1)
  state.get_seed(epoch, domain_type, mix)

func create_blob_sidecars*(
    forkyBlck: deneb.SignedBeaconBlock | electra.SignedBeaconBlock,
    kzg_proofs: KzgProofs,
    blobs: Blobs): seq[BlobSidecar] =
  template kzg_commitments: untyped =
    forkyBlck.message.body.blob_kzg_commitments
  doAssert kzg_proofs.len == blobs.len
  doAssert kzg_proofs.len == kzg_commitments.len

  var res = newSeqOfCap[BlobSidecar](blobs.len)
  let signedBlockHeader = forkyBlck.toSignedBeaconBlockHeader()
  for i in 0 ..< blobs.lenu64:
    var sidecar = BlobSidecar(
      index: i,
      blob: blobs[i],
      kzg_commitment: kzg_commitments[i],
      kzg_proof: kzg_proofs[i],
      signed_block_header: signedBlockHeader)
    forkyBlck.message.body.build_proof(
      kzg_commitment_inclusion_proof_gindex(i),
      sidecar.kzg_commitment_inclusion_proof).expect("Valid gindex")
    res.add(sidecar)
  res

func is_merge_transition_complete*(
    state: bellatrix.BeaconState | capella.BeaconState | deneb.BeaconState |
           electra.BeaconState): bool =
  const defaultExecutionPayloadHeader =
    default(typeof(state.latest_execution_payload_header))
  state.latest_execution_payload_header != defaultExecutionPayloadHeader

{.push raises: [].}

import
  # Status libraries
  stew/[byteutils, endians2, objects],
  chronicles,
  eth/common/[eth_types, eth_types_rlp],
  eth/rlp,
  # Internal
  "."/[eth2_merkleization, forks, ssz_codec]

# TODO although eth2_merkleization already exports ssz_codec, *sometimes* code
# fails to compile if the export is not done here also. Exporting rlp avoids a
# generics sandwich where rlp/writer.append() is not seen, by a caller outside
# this module via compute_execution_block_hash() called from block_processor.
export
  eth2_merkleization, forks, rlp, ssz_codec

func toEther*(gwei: Gwei): Ether =
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/weak-subjectivity.md#constants
  const ETH_TO_GWEI = 1_000_000_000
  (gwei div ETH_TO_GWEI).Ether

type
  ExecutionHash256* = eth_types.Hash256
  ExecutionTransaction* = eth_types.Transaction
  ExecutionReceipt* = eth_types.Receipt
  ExecutionWithdrawal* = eth_types.Withdrawal
  ExecutionBlockHeader* = eth_types.BlockHeader

  FinalityCheckpoints* = object
    justified*: Checkpoint
    finalized*: Checkpoint

func shortLog*(v: FinalityCheckpoints): auto =
  (
    justified: shortLog(v.justified),
    finalized: shortLog(v.finalized)
  )

chronicles.formatIt FinalityCheckpoints: it.shortLog

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#integer_squareroot
func integer_squareroot*(n: SomeInteger): SomeInteger =
  ## Return the largest integer ``x`` such that ``x**2 <= n``.
  doAssert n >= 0'u64

  if n == high(uint64):
    return 4294967295'u64

  var
    x = n
    y = (x + 1) div 2
  while y < x:
    x = y
    y = (x + n div x) div 2
  x

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#is_active_validator
func is_active_validator*(validator: Validator, epoch: Epoch): bool =
  ## Check if ``validator`` is active.
  validator.activation_epoch <= epoch and epoch < validator.exit_epoch

func is_exited_validator*(validator: Validator, epoch: Epoch): bool =
  ## Check if ``validator`` is exited.
  validator.exit_epoch <= epoch

func is_withdrawable_validator*(validator: Validator, epoch: Epoch): bool =
  epoch >= validator.withdrawable_epoch

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_active_validator_indices
iterator get_active_validator_indices*(state: ForkyBeaconState, epoch: Epoch):
    ValidatorIndex =
  for vidx in state.validators.vindices:
    if is_active_validator(state.validators[vidx], epoch):
      yield vidx

func get_active_validator_indices*(state: ForkyBeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  ## Return the sequence of active validator indices at ``epoch``.
  var res = newSeqOfCap[ValidatorIndex](state.validators.len)
  for vidx in get_active_validator_indices(state, epoch):
    res.add vidx
  res

func get_active_validator_indices_len*(state: ForkyBeaconState, epoch: Epoch):
    uint64 =
  for vidx in state.validators.vindices:
    if is_active_validator(state.validators.item(vidx), epoch):
      inc result

func get_active_validator_indices_len*(
    state: ForkedHashedBeaconState; epoch: Epoch): uint64 =
  withState(state):
    get_active_validator_indices_len(forkyState.data, epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: ForkyBeaconState): Epoch =
  ## Return the current epoch.
  state.slot.epoch

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: ForkedHashedBeaconState): Epoch =
  ## Return the current epoch.
  withState(state): get_current_epoch(forkyState.data)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(
    state: ForkyBeaconState | ForkedHashedBeaconState): Epoch =
  ## Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  get_previous_epoch(get_current_epoch(state))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_randao_mix
func get_randao_mix*(state: ForkyBeaconState, epoch: Epoch): Eth2Digest =
  ## Return the randao mix at a recent ``epoch``.
  state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR]

func bytes_to_uint32*(data: openArray[byte]): uint32 =
  doAssert data.len == 4

  # Little-endian data representation
  uint32.fromBytesLE(data)

func bytes_to_uint64*(data: openArray[byte]): uint64 =
  doAssert data.len == 8

  # Little-endian data representation
  uint64.fromBytesLE(data)

func uint_to_bytes*(x: uint64): array[8, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint32): array[4, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint16): array[2, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint8): array[1, byte] = toBytesLE(x)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#compute_domain
func compute_domain*(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Eth2Digest = ZERO_HASH): Eth2Domain =
  ## Return the domain for the ``domain_type`` and ``fork_version``.
  #
  # TODO toOpenArray can't be used from JavaScript backend
  # https://github.com/nim-lang/Nim/issues/15952
  let fork_data_root =
    compute_fork_data_root(fork_version, genesis_validators_root)
  result[0..3] = domain_type.data
  result[4..31] = fork_data_root.data.toOpenArray(0, 27)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_domain
func get_domain*(
    fork: Fork,
    domain_type: DomainType,
    epoch: Epoch,
    genesis_validators_root: Eth2Digest): Eth2Domain =
  ## Return the signature domain (fork version concatenated with domain type)
  ## of a message.
  let fork_version =
    if epoch < fork.epoch:
      fork.previous_version
    else:
      fork.current_version
  compute_domain(domain_type, fork_version, genesis_validators_root)

func get_domain*(
    state: ForkyBeaconState, domain_type: DomainType, epoch: Epoch): Eth2Domain =
  ## Return the signature domain (fork version concatenated with domain type)
  ## of a message.
  get_domain(state.fork, domain_type, epoch, state.genesis_validators_root)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#compute_signing_root
func compute_signing_root*(ssz_object: auto, domain: Eth2Domain): Eth2Digest =
  ## Return the signing root for the corresponding signing data.
  let domain_wrapped_object = SigningData(
    object_root: hash_tree_root(ssz_object),
    domain: domain
  )
  hash_tree_root(domain_wrapped_object)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/beacon-chain.md#get_seed
func get_seed*(
    state: ForkyBeaconState, epoch: Epoch, domain_type: DomainType,
    mix: Eth2Digest): Eth2Digest =
  ## Return the seed at ``epoch``.
  var seed_input : array[4+8+32, byte]
  seed_input[0..3] = domain_type.data
  seed_input[4..11] = uint_to_bytes(epoch.uint64)
  seed_input[12..43] = mix.data
  eth2digest(seed_input)

func get_seed*(state: ForkyBeaconState, epoch: Epoch, domain_type: DomainType):
    Eth2Digest =
  # Detect potential underflow
  static: doAssert EPOCHS_PER_HISTORICAL_VECTOR > MIN_SEED_LOOKAHEAD
  let mix = get_randao_mix(state, # Avoid underflow
    epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1)
  state.get_seed(epoch, domain_type, mix)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/beacon-chain.md#add_flag
func add_flag*(flags: ParticipationFlags, flag_index: TimelyFlag): ParticipationFlags =
  let flag = ParticipationFlags(1'u8 shl ord(flag_index))
  flags or flag

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/altair/beacon-chain.md#has_flag
func has_flag*(flags: ParticipationFlags, flag_index: TimelyFlag): bool =
  let flag = ParticipationFlags(1'u8 shl ord(flag_index))
  (flags and flag) == flag

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/deneb/p2p-interface.md#check_blob_sidecar_inclusion_proof
func verify_blob_sidecar_inclusion_proof*(
    blob_sidecar: BlobSidecar): Result[void, string] =
  let gindex = kzg_commitment_inclusion_proof_gindex(blob_sidecar.index)
  if not is_valid_merkle_branch(
      hash_tree_root(blob_sidecar.kzg_commitment),
      blob_sidecar.kzg_commitment_inclusion_proof,
      KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
      get_subtree_index(gindex),
      blob_sidecar.signed_block_header.message.body_root):
    return err("BlobSidecar: inclusion proof not valid")
  ok()

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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/bellatrix/beacon-chain.md#is_merge_transition_complete
func is_merge_transition_complete*(
    state: bellatrix.BeaconState | capella.BeaconState | deneb.BeaconState |
           electra.BeaconState): bool =
  const defaultExecutionPayloadHeader =
    default(typeof(state.latest_execution_payload_header))
  state.latest_execution_payload_header != defaultExecutionPayloadHeader

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/sync/optimistic.md#helpers
func is_execution_block*(blck: SomeForkyBeaconBlock): bool =
  when typeof(blck).kind >= ConsensusFork.Bellatrix:
    const defaultExecutionPayload =
      default(typeof(blck.body.execution_payload))
    blck.body.execution_payload != defaultExecutionPayload
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/bellatrix/beacon-chain.md#is_merge_transition_block
func is_merge_transition_block(
    state: bellatrix.BeaconState | capella.BeaconState | deneb.BeaconState |
           electra.BeaconState,
    body: bellatrix.BeaconBlockBody | bellatrix.TrustedBeaconBlockBody |
          bellatrix.SigVerifiedBeaconBlockBody |
          capella.BeaconBlockBody | capella.TrustedBeaconBlockBody |
          capella.SigVerifiedBeaconBlockBody |
          deneb.BeaconBlockBody | deneb.TrustedBeaconBlockBody |
          deneb.SigVerifiedBeaconBlockBody |
          electra.BeaconBlockBody | electra.TrustedBeaconBlockBody |
          electra.SigVerifiedBeaconBlockBody): bool =
  const defaultExecutionPayload = default(typeof(body.execution_payload))
  not is_merge_transition_complete(state) and
    body.execution_payload != defaultExecutionPayload

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/bellatrix/beacon-chain.md#is_execution_enabled
func is_execution_enabled*(
    state: bellatrix.BeaconState | capella.BeaconState | deneb.BeaconState |
           electra.BeaconState,
    body: bellatrix.BeaconBlockBody | bellatrix.TrustedBeaconBlockBody |
          bellatrix.SigVerifiedBeaconBlockBody |
          capella.BeaconBlockBody | capella.TrustedBeaconBlockBody |
          capella.SigVerifiedBeaconBlockBody |
          deneb.BeaconBlockBody | deneb.TrustedBeaconBlockBody |
          deneb.SigVerifiedBeaconBlockBody |
          electra.BeaconBlockBody | electra.TrustedBeaconBlockBody |
          electra.SigVerifiedBeaconBlockBody): bool =
  is_merge_transition_block(state, body) or is_merge_transition_complete(state)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
func compute_timestamp_at_slot*(state: ForkyBeaconState, slot: Slot): uint64 =
  # Note: This function is unsafe with respect to overflows and underflows.
  let slots_since_genesis = slot - GENESIS_SLOT
  state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT

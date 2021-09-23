# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Uncategorized helper functions from the spec

{.push raises: [Defect].}

import
  # Standard lib
  std/[math, tables],
  # Third-party
  stew/[byteutils, endians2, bitops2],
  # Internal
  ./datatypes/[phase0, altair, merge],
  ./eth2_merkleization, ./ssz_codec

# TODO although eth2_merkleization already exports ssz_codec, *sometimes* code
# fails to compile if the export is not done here also
export
  phase0, altair, eth2_merkleization, ssz_codec

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#integer_squareroot
func integer_squareroot*(n: SomeInteger): SomeInteger =
  ## Return the largest integer ``x`` such that ``x**2 <= n``.
  doAssert n >= 0'u64

  var
    x = n
    y = (x + 1) div 2
  while y < x:
    x = y
    y = (x + n div x) div 2
  x

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_epoch_at_slot
func compute_epoch_at_slot*(slot: Slot|uint64): Epoch =
  ## Return the epoch number at ``slot``.
  (slot div SLOTS_PER_EPOCH).Epoch

template epoch*(slot: Slot): Epoch =
  compute_epoch_at_slot(slot)

template isEpoch*(slot: Slot): bool =
  (slot mod SLOTS_PER_EPOCH) == 0

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#is_valid_merkle_branch
func is_valid_merkle_branch*(leaf: Eth2Digest, branch: openArray[Eth2Digest],
                             depth: int, index: uint64,
                             root: Eth2Digest): bool =
  ## Check if ``leaf`` at ``index`` verifies against the Merkle ``root`` and
  ## ``branch``.
  var
    value = leaf
    buf: array[64, byte]

  for i in 0 ..< depth:
    if (index div (1'u64 shl i)) mod 2 != 0:
      buf[0..31] = branch[i].data
      buf[32..63] = value.data
    else:
      buf[0..31] = value.data
      buf[32..63] = branch[i].data
    value = eth2digest(buf)
  value == root

const SLOTS_PER_SYNC_COMMITTEE_PERIOD* =
  EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH

template syncCommitteePeriod*(epoch: Epoch): uint64 =
  epoch div EPOCHS_PER_SYNC_COMMITTEE_PERIOD

template syncCommitteePeriod*(slot: Slot): uint64 =
  epoch(slot) div EPOCHS_PER_SYNC_COMMITTEE_PERIOD

func syncCommitteePeriodStartSlot*(period: uint64): Slot =
  Slot(period * EPOCHS_PER_SYNC_COMMITTEE_PERIOD * SLOTS_PER_EPOCH)

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_start_slot_at_epoch
func compute_start_slot_at_epoch*(epoch: Epoch): Slot =
  ## Return the start slot of ``epoch``.
  (epoch * SLOTS_PER_EPOCH).Slot

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#is_active_validator
func is_active_validator*(validator: Validator, epoch: Epoch): bool =
  ## Check if ``validator`` is active
  validator.activation_epoch <= epoch and epoch < validator.exit_epoch

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_active_validator_indices
iterator get_active_validator_indices*(state: SomeBeaconState, epoch: Epoch):
    ValidatorIndex =
  for idx in 0..<state.validators.len:
    if is_active_validator(state.validators[idx], epoch):
      yield idx.ValidatorIndex

func get_active_validator_indices*(state: SomeBeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  ## Return the sequence of active validator indices at ``epoch``.
  var res = newSeqOfCap[ValidatorIndex](state.validators.len)
  for idx in get_active_validator_indices(state, epoch):
    res.add idx.ValidatorIndex
  res

func get_active_validator_indices_len*(state: SomeBeaconState, epoch: Epoch):
    uint64 =
  for idx in 0..<state.validators.len:
    if is_active_validator(state.validators[idx], epoch):
      inc result

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: SomeBeaconState): Epoch =
  ## Return the current epoch.
  doAssert state.slot >= GENESIS_SLOT, $state.slot
  compute_epoch_at_slot(state.slot)

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_randao_mix
func get_randao_mix*(state: SomeBeaconState, epoch: Epoch): Eth2Digest =
  ## Returns the randao mix at a recent ``epoch``.
  state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR]

func bytes_to_uint64*(data: openArray[byte]): uint64 =
  doAssert data.len == 8

  # Little-endian data representation
  uint64.fromBytesLE(data)

# Have 1, 4, and 8-byte versions. Spec only defines 8-byte version, but useful
# to check invariants on rest.
func uint_to_bytes8*(x: uint64): array[8, byte] =
  x.toBytesLE()

func uint_to_bytes4*(x: uint64): array[4, byte] =
  doAssert x < 2'u64^32

  # Little-endian data representation
  result[0] = ((x shr  0) and 0xff).byte
  result[1] = ((x shr  8) and 0xff).byte
  result[2] = ((x shr 16) and 0xff).byte
  result[3] = ((x shr 24) and 0xff).byte

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_fork_data_root
func compute_fork_data_root(current_version: Version,
    genesis_validators_root: Eth2Digest): Eth2Digest =
  ## Return the 32-byte fork data root for the ``current_version`` and
  ## ``genesis_validators_root``.
  ## This is used primarily in signature domains to avoid collisions across
  ## forks/chains.
  hash_tree_root(ForkData(
    current_version: current_version,
    genesis_validators_root: genesis_validators_root
  ))

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_fork_digest
func compute_fork_digest*(current_version: Version,
                          genesis_validators_root: Eth2Digest): ForkDigest =
  ## Return the 4-byte fork digest for the ``current_version`` and
  ## ``genesis_validators_root``.
  ## This is a digest primarily used for domain separation on the p2p layer.
  ## 4-bytes suffices for practical separation of forks/chains.
  array[4, byte](result)[0..3] =
    compute_fork_data_root(
      current_version, genesis_validators_root).data.toOpenArray(0, 3)

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_domain
func compute_domain*(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Eth2Digest = ZERO_HASH): Eth2Domain =
  ## Return the domain for the ``domain_type`` and ``fork_version``.
  let fork_data_root =
    compute_fork_data_root(fork_version, genesis_validators_root)
  result[0..3] = uint_to_bytes4(domain_type.uint64)
  result[4..31] = fork_data_root.data.toOpenArray(0, 27)

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_domain
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
    state: SomeBeaconState, domain_type: DomainType, epoch: Epoch): Eth2Domain =
  ## Return the signature domain (fork version concatenated with domain type)
  ## of a message.
  get_domain(state.fork, domain_type, epoch, state.genesis_validators_root)

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_signing_root
func compute_signing_root*(ssz_object: auto, domain: Eth2Domain): Eth2Digest =
  ## Return the signing root of an object by calculating the root of the
  ## object-domain tree.
  let domain_wrapped_object = SigningData(
    object_root: hash_tree_root(ssz_object),
    domain: domain
  )
  hash_tree_root(domain_wrapped_object)

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_seed
func get_seed*(state: SomeBeaconState, epoch: Epoch, domain_type: DomainType):
    Eth2Digest =
  ## Return the seed at ``epoch``.

  var seed_input : array[4+8+32, byte]

  # Detect potential underflow
  static:
    doAssert EPOCHS_PER_HISTORICAL_VECTOR > MIN_SEED_LOOKAHEAD

  seed_input[0..3] = uint_to_bytes4(domain_type.uint64)
  seed_input[4..11] = uint_to_bytes8(epoch.uint64)
  seed_input[12..43] =
    get_randao_mix(state, # Avoid underflow
      epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1).data
  eth2digest(seed_input)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/beacon-chain.md#add_flag
func add_flag*(flags: ParticipationFlags, flag_index: int): ParticipationFlags =
  let flag = ParticipationFlags(1'u8 shl flag_index)
  flags or flag

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/beacon-chain.md#has_flag
func has_flag*(flags: ParticipationFlags, flag_index: int): bool =
  let flag = ParticipationFlags(1'u8 shl flag_index)
  (flags and flag) == flag

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/altair/sync-protocol.md#get_subtree_index
func get_subtree_index*(idx: GeneralizedIndex): uint64 =
  doAssert idx > 0
  uint64(idx mod (type(idx)(1) shl log2trunc(idx)))

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#is_merge_complete
func is_merge_complete*(state: merge.BeaconState): bool =
  state.latest_execution_payload_header != default(ExecutionPayloadHeader)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#is_merge_block
func is_merge_block(
    state: merge.BeaconState, body: merge.BeaconBlockBody): bool =
  not is_merge_complete(state) and body.execution_payload != ExecutionPayload()

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#is_execution_enabled
func is_execution_enabled(
    state: merge.BeaconState, body: merge.BeaconBlockBody): bool =
  is_merge_block(state, body) or is_merge_complete(state)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#compute_timestamp_at_slot
func compute_timestamp_at_slot*(state: SomeBeaconState, slot: Slot): uint64 =
  # Note: This function is unsafe with respect to overflows and underflows.
  let slots_since_genesis = slot - GENESIS_SLOT
  state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT

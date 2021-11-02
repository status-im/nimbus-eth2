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
  std/[algorithm, intsets, math, sequtils, tables],
  # Status libraries
  stew/[byteutils, endians2, bitops2],
  chronicles,
  # Internal
  ./datatypes/[phase0, altair, merge],
  ./eth2_merkleization, ./ssz_codec

# TODO although eth2_merkleization already exports ssz_codec, *sometimes* code
# fails to compile if the export is not done here also
export
  phase0, altair, eth2_merkleization, ssz_codec

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#integer_squareroot
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#compute_epoch_at_slot
func compute_epoch_at_slot*(slot: Slot|uint64): Epoch =
  ## Return the epoch number at ``slot``.
  (slot div SLOTS_PER_EPOCH).Epoch

template epoch*(slot: Slot): Epoch =
  compute_epoch_at_slot(slot)

template isEpoch*(slot: Slot): bool =
  (slot mod SLOTS_PER_EPOCH) == 0

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/ssz/merkle-proofs.md#generalized_index_sibling
template generalized_index_sibling*(
    index: GeneralizedIndex): GeneralizedIndex =
  index xor 1.GeneralizedIndex

template generalized_index_sibling_left(
    index: GeneralizedIndex): GeneralizedIndex =
  index and not 1.GeneralizedIndex

template generalized_index_sibling_right(
    index: GeneralizedIndex): GeneralizedIndex =
  index or 1.GeneralizedIndex

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/ssz/merkle-proofs.md#generalized_index_parent
template generalized_index_parent*(
    index: GeneralizedIndex): GeneralizedIndex =
  index shr 1

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/ssz/merkle-proofs.md#merkle-multiproofs
iterator get_branch_indices*(
    tree_index: GeneralizedIndex): GeneralizedIndex =
  ## Get the generalized indices of the sister chunks along the path
  ## from the chunk with the given tree index to the root.
  var index = tree_index
  while index > 1.GeneralizedIndex:
    yield generalized_index_sibling(index)
    index = generalized_index_parent(index)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/ssz/merkle-proofs.md#merkle-multiproofs
iterator get_path_indices*(
    tree_index: GeneralizedIndex): GeneralizedIndex =
  ## Get the generalized indices of the chunks along the path
  ## from the chunk with the given tree index to the root.
  var index = tree_index
  while index > 1.GeneralizedIndex:
    yield index
    index = generalized_index_parent(index)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/ssz/merkle-proofs.md#merkle-multiproofs
func get_helper_indices*(
    indices: openArray[GeneralizedIndex]): seq[GeneralizedIndex] =
  ## Get the generalized indices of all "extra" chunks in the tree needed
  ## to prove the chunks with the given generalized indices. Note that the
  ## decreasing order is chosen deliberately to ensure equivalence to the order
  ## of hashes in a regular single-item Merkle proof in the single-item case.
  var all_helper_indices = initIntSet()
  var all_path_indices = initIntSet()
  for index in indices:
    for idx in get_branch_indices(index):
      all_helper_indices.incl idx.int
    for idx in get_path_indices(index):
      all_path_indices.incl idx.int
  all_helper_indices.excl all_path_indices

  result = newSeqOfCap[GeneralizedIndex](all_helper_indices.len)
  for idx in all_helper_indices:
    result.add idx.GeneralizedIndex
  result.sort(SortOrder.Descending)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/ssz/merkle-proofs.md#merkle-multiproofs
func check_multiproof_acceptable*(
    indices: openArray[GeneralizedIndex]): Result[void, string] =
  # Check that proof verification won't allocate excessive amounts of memory.
  const max_multiproof_complexity = nextPowerOfTwo(256)
  if indices.len > max_multiproof_complexity:
    trace "Max multiproof complexity exceeded",
      num_indices=indices.len, max_multiproof_complexity
    return err("Unsupported multiproof complexity (" & $indices.len & ")")

  if indices.len == 0:
    return err("No indices specified")
  if indices.anyIt(it == 0.GeneralizedIndex):
    return err("Invalid index specified")
  ok()

func calculate_multi_merkle_root_impl(
    leaves: openArray[Eth2Digest],
    proof: openArray[Eth2Digest],
    indices: openArray[GeneralizedIndex],
    helper_indices: openArray[GeneralizedIndex]): Result[Eth2Digest, string] =
  # All callers have already verified the checks in check_multiproof_acceptable,
  # as well as whether lengths of leaves/indices and proof/helper_indices match.

  # Helper to retrieve a value from a table that is statically known to exist.
  template getExisting[A, B](t: var Table[A, B], key: A): var B =
    try: t[key]
    except KeyError: raiseAssert "Unreachable"

  # Populate data structure with all leaves.
  # This data structure only scales with the number of `leaves`,
  # in contrast to the spec one that also scales with the number of `proof`
  # items and the number of all intermediate roots, potentially the entire tree.
  let capacity = nextPowerOfTwo(leaves.len)
  var objects = initTable[GeneralizedIndex, Eth2Digest](capacity)
  for i, index in indices:
    if objects.mgetOrPut(index, leaves[i]) != leaves[i]:
      return err("Conflicting roots for same index")

  # Create list with keys of all active nodes that need to be visited.
  # This list is sorted in descending order, same as `helper_indices`.
  # Pulling from `objects` instead of from `indices` deduplicates the list.
  var keys = newSeqOfCap[GeneralizedIndex](objects.len)
  for index in objects.keys:
    if index > 1.GeneralizedIndex: # For the root, no work needs to be done.
      keys.add index
  keys.sort(SortOrder.Descending)

  # The merkle tree is processed from bottom to top, pulling in helper
  # indices from `proof` as needed. During processing, the `keys` list
  # may temporarily end up being split into two parts, sorted individually.
  # An additional index tracks the current maximum element of the list.
  var
    completed = 0         # All key indices before this are fully processed.
    maxIndex = completed  # Index of the list's largest key.
    helper = 0            # Helper index from `proof` to be pulled next.

  # Processing is done when there are no more keys to process.
  while completed < keys.len:
    let
      k = keys[maxIndex]
      sibling = generalized_index_sibling(k)
      left = generalized_index_sibling_left(k)
      right = generalized_index_sibling_right(k)
      parent = generalized_index_parent(k)
      parentRight = generalized_index_sibling_right(parent)

    # Keys need to be processed in descending order to ensure that intermediate
    # roots remain available until they are no longer needed. This ensures that
    # conflicting roots are detected in all cases.
    keys[maxIndex] =
      if not objects.hasKey(k):
        # A previous computation did already merge this key with its sibling.
        0.GeneralizedIndex
      else:
        # Compute expected root for parent. This deletes child roots.
        # Because the list is sorted in descending order, they are not needed.
        let root = withEth2Hash:
          if helper < helper_indices.len and helper_indices[helper] == sibling:
            # The next proof item is required to form the parent hash.
            if sibling == left:
              h.update proof[helper].data
              h.update objects.getExisting(right).data; objects.del right
            else:
              h.update objects.getExisting(left).data;  objects.del left
              h.update proof[helper].data
            inc helper
          else:
            # Both siblings are already known.
            h.update objects.getExisting(left).data;  objects.del left
            h.update objects.getExisting(right).data; objects.del right

        # Store parent root, and replace the current list entry with its parent.
        if objects.hasKeyOrPut(parent, root):
          if objects.getExisting(parent) != root:
            return err("Conflicting roots for same index")
          0.GeneralizedIndex
        elif parent > 1.GeneralizedIndex:
          # Note that the list may contain further nodes that are on a layer
          # beneath the parent, so this may break the strictly descending order
          # of the list. For example, given [12, 9], this will lead to [6, 9].
          # This will resolve itself after the additional nodes are processed,
          # i.e., [6, 9] -> [6, 4] -> [3, 4] -> [3, 2] -> [1].
          parent
        else:
          0.GeneralizedIndex
    if keys[maxIndex] != 0.GeneralizedIndex:
      # The list may have been temporarily split up into two parts that are
      # individually sorted in descending order. Have to first process further
      # nodes until the list is sorted once more.
      inc maxIndex

    # Determine whether descending sort order has been restored.
    let isSorted =
      if maxIndex == completed: true
      else:
        while maxIndex < keys.len and keys[maxIndex] == 0.GeneralizedIndex:
          inc maxIndex
        maxIndex >= keys.len or keys[maxIndex] <= parentRight
    if isSorted:
      # List is sorted once more. Reset `maxIndex` to its start.
      while completed < keys.len and keys[completed] == 0.GeneralizedIndex:
        inc completed
      maxIndex = completed

  # Proof is guaranteed to provide all info needed to reach the root.
  doAssert helper == helper_indices.len
  doAssert objects.len == 1
  ok(objects.getExisting(1.GeneralizedIndex))

func calculate_multi_merkle_root*(
    leaves: openArray[Eth2Digest],
    proof: openArray[Eth2Digest],
    indices: openArray[GeneralizedIndex],
    helper_indices: openArray[GeneralizedIndex]): Result[Eth2Digest, string] =
  doAssert proof.len == helper_indices.len
  if leaves.len != indices.len:
    return err("Length mismatch for leaves and indices")
  ? check_multiproof_acceptable(indices)
  calculate_multi_merkle_root_impl(
    leaves, proof, indices, helper_indices)

func calculate_multi_merkle_root*(
    leaves: openArray[Eth2Digest],
    proof: openArray[Eth2Digest],
    indices: openArray[GeneralizedIndex]): Result[Eth2Digest, string] =
  if leaves.len != indices.len:
    return err("Length mismatch for leaves and indices")
  ? check_multiproof_acceptable(indices)
  calculate_multi_merkle_root_impl(
    leaves, proof, indices, get_helper_indices(indices))

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/ssz/merkle-proofs.md#merkle-multiproofs
func verify_merkle_multiproof*(
    leaves: openArray[Eth2Digest],
    proof: openArray[Eth2Digest],
    indices: openArray[GeneralizedIndex],
    helper_indices: openArray[GeneralizedIndex],
    root: Eth2Digest): bool =
  let calc = calculate_multi_merkle_root(leaves, proof, indices, helper_indices)
  if calc.isErr: return false
  calc.get == root

func verify_merkle_multiproof*(
    leaves: openArray[Eth2Digest],
    proof: openArray[Eth2Digest],
    indices: openArray[GeneralizedIndex],
    root: Eth2Digest): bool =
  let calc = calculate_multi_merkle_root(leaves, proof, indices)
  if calc.isErr: return false
  calc.get == root

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#is_valid_merkle_branch
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/tests/core/pyspec/eth2spec/test/helpers/merkle.py#L4-L21
func build_proof_impl(anchor: object, leaf_index: uint64,
                      proof: var openArray[Eth2Digest]) =
  let
    bottom_length = nextPow2(typeof(anchor).totalSerializedFields.uint64)
    tree_depth = log2trunc(bottom_length)
    parent_index =
      if leaf_index < bottom_length shl 1:
        0'u64
      else:
        var i = leaf_index
        while i >= bottom_length shl 1:
          i = i shr 1
        i

  var
    prefix_len = 0
    proof_len = log2trunc(leaf_index)
    cache = newSeq[Eth2Digest](bottom_length shl 1)
  block:
    var i = bottom_length
    anchor.enumInstanceSerializedFields(fieldNameVar, fieldVar):
      if i == parent_index:
        when fieldVar is object:
          prefix_len = log2trunc(leaf_index) - tree_depth
          proof_len -= prefix_len
          let
            bottom_bits = leaf_index and not (uint64.high shl prefix_len)
            prefix_leaf_index = (1'u64 shl prefix_len) + bottom_bits
          build_proof_impl(fieldVar, prefix_leaf_index, proof)
        else: raiseAssert "Invalid leaf_index"
      cache[i] = hash_tree_root(fieldVar)
      i += 1
    for i in countdown(bottom_length - 1, 1):
      cache[i] = withEth2Hash:
        h.update cache[i shl 1].data
        h.update cache[i shl 1 + 1].data

  var i = if parent_index != 0: parent_index
          else: leaf_index
  doAssert i > 0 and i < bottom_length shl 1
  for proof_index in prefix_len ..< prefix_len + proof_len:
    let b = (i and 1) != 0
    i = i shr 1
    proof[proof_index] = if b: cache[i shl 1]
                         else: cache[i shl 1 + 1]

func build_proof*(anchor: object, leaf_index: uint64,
                  proof: var openArray[Eth2Digest]) =
  doAssert leaf_index > 0
  doAssert proof.len == log2trunc(leaf_index)
  build_proof_impl(anchor, leaf_index, proof)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/altair/validator.md#sync-committee
template sync_committee_period*(epoch: Epoch): SyncCommitteePeriod =
  (epoch div EPOCHS_PER_SYNC_COMMITTEE_PERIOD).SyncCommitteePeriod

template sync_committee_period*(slot: Slot): SyncCommitteePeriod =
  sync_committee_period(epoch(slot))

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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: SomeBeaconState): Epoch =
  ## Return the current epoch.
  doAssert state.slot >= GENESIS_SLOT, $state.slot
  compute_epoch_at_slot(state.slot)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_randao_mix
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#compute_fork_digest
func compute_fork_digest*(current_version: Version,
                          genesis_validators_root: Eth2Digest): ForkDigest =
  ## Return the 4-byte fork digest for the ``current_version`` and
  ## ``genesis_validators_root``.
  ## This is a digest primarily used for domain separation on the p2p layer.
  ## 4-bytes suffices for practical separation of forks/chains.
  array[4, byte](result)[0..3] =
    compute_fork_data_root(
      current_version, genesis_validators_root).data.toOpenArray(0, 3)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#compute_domain
func compute_domain*(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Eth2Digest = ZERO_HASH): Eth2Domain =
  ## Return the domain for the ``domain_type`` and ``fork_version``.
  let fork_data_root =
    compute_fork_data_root(fork_version, genesis_validators_root)
  result[0..3] = uint_to_bytes4(domain_type.uint64)
  result[4..31] = fork_data_root.data.toOpenArray(0, 27)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/phase0/beacon-chain.md#get_domain
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#compute_signing_root
func compute_signing_root*(ssz_object: auto, domain: Eth2Domain): Eth2Digest =
  ## Return the signing root of an object by calculating the root of the
  ## object-domain tree.
  let domain_wrapped_object = SigningData(
    object_root: hash_tree_root(ssz_object),
    domain: domain
  )
  hash_tree_root(domain_wrapped_object)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_seed
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

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/altair/beacon-chain.md#add_flag
func add_flag*(flags: ParticipationFlags, flag_index: int): ParticipationFlags =
  let flag = ParticipationFlags(1'u8 shl flag_index)
  flags or flag

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/altair/beacon-chain.md#has_flag
func has_flag*(flags: ParticipationFlags, flag_index: int): bool =
  let flag = ParticipationFlags(1'u8 shl flag_index)
  (flags and flag) == flag

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/altair/sync-protocol.md#get_subtree_index
func get_subtree_index*(idx: GeneralizedIndex): uint64 =
  doAssert idx > 0
  uint64(idx mod (type(idx)(1) shl log2trunc(idx)))

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/merge/beacon-chain.md#is_merge_complete
func is_merge_complete*(state: merge.BeaconState): bool =
  state.latest_execution_payload_header != default(ExecutionPayloadHeader)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/merge/beacon-chain.md#is_merge_block
func is_merge_block(
    state: merge.BeaconState,
    body: merge.BeaconBlockBody | merge.TrustedBeaconBlockBody |
          merge.SigVerifiedBeaconBlockBody): bool =
  not is_merge_complete(state) and
    body.execution_payload != default(merge.ExecutionPayload)

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/merge/beacon-chain.md#is_execution_enabled
func is_execution_enabled*(
    state: merge.BeaconState,
    body: merge.BeaconBlockBody | merge.TrustedBeaconBlockBody |
          merge.SigVerifiedBeaconBlockBody): bool =
  is_merge_block(state, body) or is_merge_complete(state)

# https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#compute_timestamp_at_slot
func compute_timestamp_at_slot*(state: SomeBeaconState, slot: Slot): uint64 =
  # Note: This function is unsafe with respect to overflows and underflows.
  let slots_since_genesis = slot - GENESIS_SLOT
  state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT

# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Uncategorized helper functions from the spec

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

# References to `vFuture` refer to the pre-release proposal of the libp2p based
# light client sync protocol. Conflicting release versions are not in use.
# https://github.com/ethereum/consensus-specs/pull/2802

import
  # Standard lib
  std/[algorithm, math, sets, tables],
  # Status libraries
  stew/[bitops2, byteutils, endians2, objects],
  chronicles,
  # Internal
  ./datatypes/[phase0, altair, bellatrix],
  "."/[eth2_merkleization, forks, ssz_codec]

# TODO although eth2_merkleization already exports ssz_codec, *sometimes* code
# fails to compile if the export is not done here also
export
  forks, eth2_merkleization, ssz_codec

type FinalityCheckpoints* = object
  justified*: Checkpoint
  finalized*: Checkpoint

func shortLog*(v: FinalityCheckpoints): auto =
  (
    justified: shortLog(v.justified),
    finalized: shortLog(v.finalized)
  )

chronicles.formatIt FinalityCheckpoints: it.shortLog

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#integer_squareroot
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

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#is_active_validator
func is_active_validator*(validator: Validator, epoch: Epoch): bool =
  ## Check if ``validator`` is active
  validator.activation_epoch <= epoch and epoch < validator.exit_epoch

func is_exited_validator*(validator: Validator, epoch: Epoch): bool =
  ## Check if ``validator`` is exited
  validator.exit_epoch <= epoch

func is_withdrawable_validator*(validator: Validator, epoch: Epoch): bool =
  epoch >= validator.withdrawable_epoch

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_active_validator_indices
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
    get_active_validator_indices_len(state.data, epoch)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: ForkyBeaconState): Epoch =
  ## Return the current epoch.
  state.slot.epoch

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: ForkedHashedBeaconState): Epoch =
  ## Return the current epoch.
  withState(state): get_current_epoch(state.data)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(
    state: ForkyBeaconState | ForkedHashedBeaconState): Epoch =
  ## Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  get_previous_epoch(get_current_epoch(state))

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_randao_mix
func get_randao_mix*(state: ForkyBeaconState, epoch: Epoch): Eth2Digest =
  ## Returns the randao mix at a recent ``epoch``.
  state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR]

func bytes_to_uint64*(data: openArray[byte]): uint64 =
  doAssert data.len == 8

  # Little-endian data representation
  uint64.fromBytesLE(data)

func uint_to_bytes*(x: uint64): array[8, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint32): array[4, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint16): array[2, byte] = toBytesLE(x)
func uint_to_bytes*(x: uint8): array[1, byte] = toBytesLE(x)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#compute_domain
func compute_domain*(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Eth2Digest = ZERO_HASH): Eth2Domain =
  ## Return the domain for the ``domain_type`` and ``fork_version``.
  #
  # TODO Can't be used as part of a const/static expression:
  # https://github.com/nim-lang/Nim/issues/15952
  # https://github.com/nim-lang/Nim/issues/19969
  let fork_data_root =
    compute_fork_data_root(fork_version, genesis_validators_root)
  result[0..3] = domain_type.data
  result[4..31] = fork_data_root.data.toOpenArray(0, 27)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_domain
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

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#compute_signing_root
func compute_signing_root*(ssz_object: auto, domain: Eth2Domain): Eth2Digest =
  ## Return the signing root of an object by calculating the root of the
  ## object-domain tree.
  let domain_wrapped_object = SigningData(
    object_root: hash_tree_root(ssz_object),
    domain: domain
  )
  hash_tree_root(domain_wrapped_object)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#get_seed
func get_seed*(state: ForkyBeaconState, epoch: Epoch, domain_type: DomainType):
    Eth2Digest =
  ## Return the seed at ``epoch``.

  var seed_input : array[4+8+32, byte]

  # Detect potential underflow
  static:
    doAssert EPOCHS_PER_HISTORICAL_VECTOR > MIN_SEED_LOOKAHEAD

  seed_input[0..3] = domain_type.data
  seed_input[4..11] = uint_to_bytes(epoch.uint64)
  seed_input[12..43] =
    get_randao_mix(state, # Avoid underflow
      epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1).data
  eth2digest(seed_input)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#add_flag
func add_flag*(flags: ParticipationFlags, flag_index: int): ParticipationFlags =
  let flag = ParticipationFlags(1'u8 shl flag_index)
  flags or flag

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#has_flag
func has_flag*(flags: ParticipationFlags, flag_index: int): bool =
  let flag = ParticipationFlags(1'u8 shl flag_index)
  (flags and flag) == flag

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#is_sync_committee_update
template is_sync_committee_update*(update: SomeLightClientUpdate): bool =
  when update is SomeLightClientUpdateWithSyncCommittee:
    not isZeroMemory(update.next_sync_committee_branch)
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/sync-protocol.md#get_active_header
template is_finality_update*(update: SomeLightClientUpdate): bool =
  when update is SomeLightClientUpdateWithFinality:
    not isZeroMemory(update.finality_branch)
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#is_next_sync_committee_known
template is_next_sync_committee_known*(store: LightClientStore): bool =
  not isZeroMemory(store.next_sync_committee)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/sync-protocol.md#get_safety_threshold
func get_safety_threshold*(store: LightClientStore): uint64 =
  max(
    store.previous_max_active_participants,
    store.current_max_active_participants
  ) div 2

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#is_better_update
type LightClientUpdateMetadata* = object
  attested_slot*, finalized_slot*, signature_slot*: Slot
  has_sync_committee*, has_finality*: bool
  num_active_participants*: uint64

func toMeta*(update: SomeLightClientUpdate): LightClientUpdateMetadata =
  var meta {.noinit.}: LightClientUpdateMetadata
  meta.attested_slot =
    update.attested_header.slot
  meta.finalized_slot =
    when update is SomeLightClientUpdateWithFinality:
      update.finalized_header.slot
    else:
      GENESIS_SLOT
  meta.signature_slot =
    update.signature_slot
  meta.has_sync_committee =
    when update is SomeLightClientUpdateWithSyncCommittee:
      not update.next_sync_committee_branch.isZeroMemory
    else:
      false
  meta.has_finality =
    when update is SomeLightClientUpdateWithFinality:
      not update.finality_branch.isZeroMemory
    else:
      false
  meta.num_active_participants =
    countOnes(update.sync_aggregate.sync_committee_bits).uint64
  meta

func is_better_data*(new_meta, old_meta: LightClientUpdateMetadata): bool =
  # Compare supermajority (> 2/3) sync committee participation
  const max_active_participants = SYNC_COMMITTEE_SIZE.uint64
  let
    new_has_supermajority =
      new_meta.num_active_participants * 3 >= max_active_participants * 2
    old_has_supermajority =
      old_meta.num_active_participants * 3 >= max_active_participants * 2
  if new_has_supermajority != old_has_supermajority:
    return new_has_supermajority > old_has_supermajority
  if not new_has_supermajority:
    if new_meta.num_active_participants != old_meta.num_active_participants:
      return new_meta.num_active_participants > old_meta.num_active_participants

  # Compare presence of relevant sync committee
  let
    new_has_relevant_sync_committee = new_meta.has_sync_committee and
      new_meta.attested_slot.sync_committee_period ==
      new_meta.signature_slot.sync_committee_period
    old_has_relevant_sync_committee = old_meta.has_sync_committee and
      old_meta.attested_slot.sync_committee_period ==
      old_meta.signature_slot.sync_committee_period
  if new_has_relevant_sync_committee != old_has_relevant_sync_committee:
    return new_has_relevant_sync_committee > old_has_relevant_sync_committee

  # Compare indication of any finality
  if new_meta.has_finality != old_meta.has_finality:
    return new_meta.has_finality > old_meta.has_finality

  # Compare sync committee finality
  if new_meta.has_finality:
    let
      new_has_sync_committee_finality =
        new_meta.finalized_slot.sync_committee_period ==
        new_meta.attested_slot.sync_committee_period
      old_has_sync_committee_finality =
        old_meta.finalized_slot.sync_committee_period ==
        old_meta.attested_slot.sync_committee_period
    if new_has_sync_committee_finality != old_has_sync_committee_finality:
      return new_has_sync_committee_finality > old_has_sync_committee_finality

  # Tiebreaker 1: Sync committee participation beyond supermajority
  if new_meta.num_active_participants != old_meta.num_active_participants:
    return new_meta.num_active_participants > old_meta.num_active_participants

  # Tiebreaker 2: Prefer older data (fewer changes to best data)
  new_meta.attested_slot < old_meta.attested_slot

template is_better_update*[A, B: SomeLightClientUpdate](
    new_update: A, old_update: B): bool =
  is_better_data(toMeta(new_update), toMeta(old_update))

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#is_merge_transition_complete
func is_merge_transition_complete*(state: bellatrix.BeaconState): bool =
  const defaultExecutionPayloadHeader = default(ExecutionPayloadHeader)
  state.latest_execution_payload_header != defaultExecutionPayloadHeader

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/sync/optimistic.md#helpers
func is_execution_block*(blck: SomeForkyBeaconBlock): bool =
  when typeof(blck).toFork >= BeaconBlockFork.Bellatrix:
    const defaultExecutionPayload =
      default(typeof(blck.body.execution_payload))
    blck.body.execution_payload != defaultExecutionPayload
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#is_merge_transition_block
func is_merge_transition_block(
    state: bellatrix.BeaconState,
    body: bellatrix.BeaconBlockBody | bellatrix.TrustedBeaconBlockBody |
          bellatrix.SigVerifiedBeaconBlockBody): bool =
  const defaultBellatrixExecutionPayload = default(bellatrix.ExecutionPayload)
  not is_merge_transition_complete(state) and
    body.execution_payload != defaultBellatrixExecutionPayload

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#is_execution_enabled
func is_execution_enabled*(
    state: bellatrix.BeaconState,
    body: bellatrix.BeaconBlockBody | bellatrix.TrustedBeaconBlockBody |
          bellatrix.SigVerifiedBeaconBlockBody): bool =
  is_merge_transition_block(state, body) or is_merge_transition_complete(state)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
func compute_timestamp_at_slot*(state: ForkyBeaconState, slot: Slot): uint64 =
  # Note: This function is unsafe with respect to overflows and underflows.
  let slots_since_genesis = slot - GENESIS_SLOT
  state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/tests/core/pyspec/eth2spec/test/helpers/execution_payload.py#L1-L31
func build_empty_execution_payload*(state: bellatrix.BeaconState): ExecutionPayload =
  ## Assuming a pre-state of the same slot, build a valid ExecutionPayload
  ## without any transactions.
  let
    latest = state.latest_execution_payload_header
    timestamp = compute_timestamp_at_slot(state, state.slot)
    randao_mix = get_randao_mix(state, get_current_epoch(state))

  var payload = ExecutionPayload(
    parent_hash: latest.block_hash,
    state_root: latest.state_root, # no changes to the state
    receipts_root: static(Eth2Digest.fromHex(
      "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")),
    block_number: latest.block_number + 1,
    prev_randao: randao_mix,
    gas_limit: latest.gas_limit, # retain same limit
    gas_used: 0, # empty block, 0 gas
    timestamp: timestamp,
    base_fee_per_gas: latest.base_fee_per_gas) # retain same base_fee

  payload.block_hash = withEth2Hash:
    h.update payload.hash_tree_root().data
    h.update cast[array[13, uint8]]("FAKE RLP HASH")

  payload

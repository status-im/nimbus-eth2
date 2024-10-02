# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec

import
  # Status libraries
  stew/[byteutils, endians2, objects],
  chronicles,
  eth/common/[eth_types, eth_types_rlp],
  eth/rlp, eth/trie/[db, hexary],
  # Internal
  "."/[eth2_merkleization, forks, ssz_codec]

# TODO although eth2_merkleization already exports ssz_codec, *sometimes* code
# fails to compile if the export is not done here also. Exporting rlp avoids a
# generics sandwich where rlp/writer.append() is not seen, by a caller outside
# this module via compute_execution_block_hash() called from block_processor.
export
  eth2_merkleization, forks, rlp, ssz_codec

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/weak-subjectivity.md#constants
const ETH_TO_GWEI = 1_000_000_000.Gwei

func toEther*(gwei: Gwei): Ether =
  (gwei div ETH_TO_GWEI).Ether

func toGwei*(eth: Ether): Gwei =
  distinctBase(eth) * ETH_TO_GWEI

type
  ExecutionHash256* = eth_types.Hash256
  ExecutionTransaction* = eth_types.Transaction
  ExecutionReceipt* = eth_types.Receipt
  ExecutionWithdrawal* = eth_types.Withdrawal
  ExecutionDepositRequest* = eth_types.DepositRequest
  ExecutionWithdrawalRequest* = eth_types.WithdrawalRequest
  ExecutionConsolidationRequest* = eth_types.ConsolidationRequest
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: ForkyBeaconState): Epoch =
  ## Return the current epoch.
  state.slot.epoch

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(state: ForkedHashedBeaconState): Epoch =
  ## Return the current epoch.
  withState(state): get_current_epoch(forkyState.data)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(
    state: ForkyBeaconState | ForkedHashedBeaconState): Epoch =
  ## Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  get_previous_epoch(get_current_epoch(state))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#get_randao_mix
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#get_domain
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/beacon-chain.md#get_seed
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/altair/beacon-chain.md#add_flag
func add_flag*(flags: ParticipationFlags, flag_index: TimelyFlag): ParticipationFlags =
  let flag = ParticipationFlags(1'u8 shl ord(flag_index))
  flags or flag

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/beacon-chain.md#has_flag
func has_flag*(flags: ParticipationFlags, flag_index: TimelyFlag): bool =
  let flag = ParticipationFlags(1'u8 shl ord(flag_index))
  (flags and flag) == flag

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/deneb/p2p-interface.md#verify_blob_sidecar_inclusion_proof
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/altair/light-client/sync-protocol.md#is_sync_committee_update
template is_sync_committee_update*(update: SomeForkyLightClientUpdate): bool =
  when update is SomeForkyLightClientUpdateWithSyncCommittee:
    update.next_sync_committee_branch !=
      static(default(typeof(update.next_sync_committee_branch)))
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/altair/light-client/sync-protocol.md#is_finality_update
template is_finality_update*(update: SomeForkyLightClientUpdate): bool =
  when update is SomeForkyLightClientUpdateWithFinality:
    update.finality_branch !=
      static(default(typeof(update.finality_branch)))
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/altair/light-client/sync-protocol.md#is_next_sync_committee_known
template is_next_sync_committee_known*(store: ForkyLightClientStore): bool =
  store.next_sync_committee !=
    static(default(typeof(store.next_sync_committee)))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#get_safety_threshold
func get_safety_threshold*(store: ForkyLightClientStore): uint64 =
  max(
    store.previous_max_active_participants,
    store.current_max_active_participants
  ) div 2

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#is_better_update
type LightClientUpdateMetadata* = object
  attested_slot*, finalized_slot*, signature_slot*: Slot
  has_sync_committee*, has_finality*: bool
  num_active_participants*: uint64

func toMeta*(update: SomeForkyLightClientUpdate): LightClientUpdateMetadata =
  var meta {.noinit.}: LightClientUpdateMetadata
  meta.attested_slot =
    update.attested_header.beacon.slot
  meta.finalized_slot =
    when update is SomeForkyLightClientUpdateWithFinality:
      update.finalized_header.beacon.slot
    else:
      GENESIS_SLOT
  meta.signature_slot =
    update.signature_slot
  meta.has_sync_committee =
    when update is SomeForkyLightClientUpdateWithSyncCommittee:
      update.is_sync_committee_update
    else:
      false
  meta.has_finality =
    when update is SomeForkyLightClientUpdateWithFinality:
      update.is_finality_update
    else:
      false
  meta.num_active_participants =
    update.sync_aggregate.num_active_participants.uint64
  meta

template toMeta*(
    update: SomeForkedLightClientUpdate): LightClientUpdateMetadata =
  withForkyObject(update):
    when lcDataFork > LightClientDataFork.None:
      forkyObject.toMeta()
    else:
      default(LightClientUpdateMetadata)

func is_better_data*(new_meta, old_meta: LightClientUpdateMetadata): bool =
  # Compare supermajority (> 2/3) sync committee participation
  let
    new_has_supermajority =
      hasSupermajoritySyncParticipation(new_meta.num_active_participants)
    old_has_supermajority =
      hasSupermajoritySyncParticipation(old_meta.num_active_participants)
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

template is_better_update*[
    A, B: SomeForkyLightClientUpdate | ForkedLightClientUpdate](
    new_update: A, old_update: B): bool =
  is_better_data(toMeta(new_update), toMeta(old_update))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientbootstrap
func contextEpoch*(bootstrap: ForkyLightClientBootstrap): Epoch =
  bootstrap.header.beacon.slot.epoch

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#lightclientupdatesbyrange
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientfinalityupdate
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientoptimisticupdate
func contextEpoch*(update: SomeForkyLightClientUpdate): Epoch =
  update.attested_header.beacon.slot.epoch

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#is_merge_transition_complete
func is_merge_transition_complete*(
    state: bellatrix.BeaconState | capella.BeaconState | deneb.BeaconState |
           electra.BeaconState): bool =
  const defaultExecutionPayloadHeader =
    default(typeof(state.latest_execution_payload_header))
  state.latest_execution_payload_header != defaultExecutionPayloadHeader

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/sync/optimistic.md#helpers
func is_execution_block*(blck: SomeForkyBeaconBlock): bool =
  when typeof(blck).kind >= ConsensusFork.Bellatrix:
    const defaultExecutionPayload =
      default(typeof(blck.body.execution_payload))
    blck.body.execution_payload != defaultExecutionPayload
  else:
    false

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#is_merge_transition_block
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#is_execution_enabled
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
func compute_timestamp_at_slot*(state: ForkyBeaconState, slot: Slot): uint64 =
  # Note: This function is unsafe with respect to overflows and underflows.
  let slots_since_genesis = slot - GENESIS_SLOT
  state.genesis_time + slots_since_genesis * SECONDS_PER_SLOT

proc computeTransactionsTrieRoot*(
    payload: ForkyExecutionPayload): ExecutionHash256 =
  if payload.transactions.len == 0:
    return EMPTY_ROOT_HASH

  var tr = initHexaryTrie(newMemoryDB())
  for i, transaction in payload.transactions:
    try:
      # Transactions are already RLP encoded
      tr.put(rlp.encode(i.uint), distinctBase(transaction))
    except RlpError as exc:
      raiseAssert "HexaryTrie.put failed: " & $exc.msg
  tr.rootHash()

func toExecutionWithdrawal(
    withdrawal: capella.Withdrawal): ExecutionWithdrawal =
  ExecutionWithdrawal(
    index: withdrawal.index,
    validatorIndex: withdrawal.validator_index,
    address: EthAddress withdrawal.address.data,
    amount: distinctBase(withdrawal.amount))

proc rlpEncode(withdrawal: capella.Withdrawal): seq[byte] =
  # TODO if this encode call is in a generic function, nim doesn't find the
  #      right `append` to use with `Address` (!)
  rlp.encode(toExecutionWithdrawal(withdrawal))

# https://eips.ethereum.org/EIPS/eip-4895
proc computeWithdrawalsTrieRoot*(
    payload: capella.ExecutionPayload | deneb.ExecutionPayload |
    electra.ExecutionPayload): ExecutionHash256 =
  if payload.withdrawals.len == 0:
    return EMPTY_ROOT_HASH

  var tr = initHexaryTrie(newMemoryDB())
  for i, withdrawal in payload.withdrawals:
    try:
      tr.put(rlp.encode(i.uint), rlpEncode(withdrawal))
    except RlpError as exc:
      raiseAssert "HexaryTrie.put failed: " & $exc.msg
  tr.rootHash()

func toExecutionDepositRequest*(
    request: electra.DepositRequest): ExecutionDepositRequest =
  ExecutionDepositRequest(
    pubkey: Bytes48 request.pubkey.blob,
    withdrawalCredentials: Bytes32 request.withdrawal_credentials.data,
    amount: distinctBase(request.amount),
    signature: Bytes96 request.signature.blob,
    index: request.index)

func toExecutionWithdrawalRequest*(
    request: electra.WithdrawalRequest): ExecutionWithdrawalRequest =
  ExecutionWithdrawalRequest(
    sourceAddress: Address request.source_address.data,
    validatorPubkey: Bytes48 request.validator_pubkey.blob,
    amount: distinctBase(request.amount))

func toExecutionConsolidationRequest*(
    request: electra.ConsolidationRequest): ExecutionConsolidationRequest =
  ExecutionConsolidationRequest(
    sourceAddress: Address request.source_address.data,
    sourcePubkey: Bytes48 request.source_pubkey.blob,
    targetPubkey: Bytes48 request.target_pubkey.blob)

# https://eips.ethereum.org/EIPS/eip-7685
proc computeRequestsTrieRoot(
    requests: electra.ExecutionRequests): ExecutionHash256 =
  if requests.deposits.len == 0 and
      requests.withdrawals.len == 0 and
      requests.consolidations.len == 0:
    return EMPTY_ROOT_HASH

  var
    tr = initHexaryTrie(newMemoryDB())
    i = 0'u64

  static:
    doAssert DEPOSIT_REQUEST_TYPE < WITHDRAWAL_REQUEST_TYPE
    doAssert WITHDRAWAL_REQUEST_TYPE < CONSOLIDATION_REQUEST_TYPE

  # EIP-6110
  for request in requests.deposits:
    try:
      tr.put(rlp.encode(i.uint), rlp.encode(
        toExecutionDepositRequest(request)))
    except RlpError as exc:
      raiseAssert "HexaryTree.put failed: " & $exc.msg
    inc i

  # EIP-7002
  for request in requests.withdrawals:
    try:
      tr.put(rlp.encode(i.uint), rlp.encode(
        toExecutionWithdrawalRequest(request)))
    except RlpError as exc:
      raiseAssert "HexaryTree.put failed: " & $exc.msg
    inc i

  # EIP-7251
  for request in requests.consolidations:
    try:
      tr.put(rlp.encode(i.uint), rlp.encode(
        toExecutionConsolidationRequest(request)))
    except RlpError as exc:
      raiseAssert "HexaryTree.put failed: " & $exc.msg
    inc i

  tr.rootHash()

proc blockToBlockHeader*(blck: ForkyBeaconBlock): ExecutionBlockHeader =
  template payload: auto = blck.body.execution_payload

  static:  # `GasInt` is signed. We only use it for hashing.
    doAssert sizeof(GasInt) == sizeof(payload.gas_limit)
    doAssert sizeof(GasInt) == sizeof(payload.gas_used)

  let
    txRoot = payload.computeTransactionsTrieRoot()
    withdrawalsRoot =
      when typeof(payload).kind >= ConsensusFork.Capella:
        Opt.some payload.computeWithdrawalsTrieRoot()
      else:
        Opt.none(ExecutionHash256)
    blobGasUsed =
      when typeof(payload).kind >= ConsensusFork.Deneb:
        Opt.some payload.blob_gas_used
      else:
        Opt.none(uint64)
    excessBlobGas =
      when typeof(payload).kind >= ConsensusFork.Deneb:
        Opt.some payload.excess_blob_gas
      else:
        Opt.none(uint64)
    parentBeaconBlockRoot =
      when typeof(payload).kind >= ConsensusFork.Deneb:
        Opt.some ExecutionHash256(blck.parent_root.data)
      else:
        Opt.none(ExecutionHash256)
    requestsRoot =
      when typeof(payload).kind >= ConsensusFork.Electra:
        Opt.some blck.body.execution_requests.computeRequestsTrieRoot()
      else:
        Opt.none(ExecutionHash256)

  ExecutionBlockHeader(
    parentHash            : payload.parent_hash.to(Hash32),
    ommersHash            : EMPTY_UNCLE_HASH,
    coinbase              : EthAddress payload.fee_recipient.data,
    stateRoot             : payload.state_root.to(Root),
    transactionsRoot      : txRoot,
    receiptsRoot          : payload.receipts_root.to(Root),
    logsBloom             : BloomFilter payload.logs_bloom.data.to(Bloom),
    difficulty            : default(DifficultyInt),
    number                : payload.block_number,
    gasLimit              : payload.gas_limit,
    gasUsed               : payload.gas_used,
    timestamp             : EthTime(payload.timestamp),
    extraData             : payload.extra_data.asSeq,
    mixHash               : Bytes32 payload.prev_randao.data, # EIP-4399 `mixHash` -> `prevRandao`
    nonce                 : default(BlockNonce),
    baseFeePerGas         : Opt.some payload.base_fee_per_gas,
    withdrawalsRoot       : withdrawalsRoot,
    blobGasUsed           : blobGasUsed,           # EIP-4844
    excessBlobGas         : excessBlobGas,         # EIP-4844
    parentBeaconBlockRoot : parentBeaconBlockRoot, # EIP-4788
    requestsRoot          : requestsRoot)          # EIP-7685

proc compute_execution_block_hash*(blck: ForkyBeaconBlock): Eth2Digest =
  rlpHash(blockToBlockHeader(blck)).to(Eth2Digest)

from std/math import exp, ln
from std/sequtils import foldl

func ln_binomial(n, k: int): float64 =
  if k > n:
    low(float64)
  else:
    template ln_factorial(n: int): float64 =
      (2 .. n).foldl(a + ln(b.float64), 0.0)
    ln_factorial(n) - ln_factorial(k) - ln_factorial(n - k)

func hypergeom_cdf*(k: int, population: int, successes: int, draws: int):
    float64 =
  if k < draws + successes - population:
    0.0
  elif k >= min(successes, draws):
    1.0
  else:
    let ln_denom = ln_binomial(population, draws)
    (0 .. k).foldl(a + exp(
      ln_binomial(successes, b) +
      ln_binomial(population - successes, draws - b) - ln_denom), 0.0)

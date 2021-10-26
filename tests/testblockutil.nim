# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  options, stew/endians2,
  ../beacon_chain/validators/validator_pool,
  ../beacon_chain/spec/datatypes/merge,
  ../beacon_chain/spec/[helpers, keystore, signatures, state_transition, forks]

type
  MockPrivKeysT = object
  MockPubKeysT = object
const
  MockPrivKeys* = MockPrivKeysT()
  MockPubKeys* = MockPubKeysT()

# https://github.com/ethereum/consensus-specs/blob/v1.1.2/tests/core/pyspec/eth2spec/test/helpers/keys.py
func `[]`*(_: MockPrivKeysT, index: ValidatorIndex): ValidatorPrivKey =
  # 0 is not a valid BLS private key - 1000 helps interop with rust BLS library,
  # lighthouse. EF tests use 1 instead of 1000.
  var bytes = (index.uint64 + 1000'u64).toBytesLE()
  static: doAssert sizeof(bytes) <= sizeof(result)
  copyMem(addr result, addr bytes, sizeof(bytes))

func `[]`*(_: MockPubKeysT, index: ValidatorIndex): ValidatorPubKey =
  MockPrivKeys[index].toPubKey().toPubKey()

func makeFakeHash*(i: int): Eth2Digest =
  var bytes = uint64(i).toBytesLE()
  static: doAssert sizeof(bytes) <= sizeof(result.data)
  copyMem(addr result.data[0], addr bytes[0], sizeof(bytes))

func makeDeposit*(
    i: int,
    flags: UpdateFlags = {},
    cfg = defaultRuntimeConfig): DepositData =
  let
    privkey = MockPrivKeys[i.ValidatorIndex]
    pubkey = MockPubKeys[i.ValidatorIndex]
    withdrawal_credentials = makeWithdrawalCredentials(pubkey)

  result = DepositData(
    pubkey: pubkey,
    withdrawal_credentials: withdrawal_credentials,
    amount: MAX_EFFECTIVE_BALANCE)

  if skipBLSValidation notin flags:
    result.signature = get_deposit_signature(cfg, result, privkey).toValidatorSig()

func makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}, cfg = defaultRuntimeConfig): seq[DepositData] =
  for i in 0..<n.int:
    result.add makeDeposit(i, flags, cfg = cfg)

func signBlock(
    fork: Fork, genesis_validators_root: Eth2Digest, forked: ForkedBeaconBlock,
    privKey: ValidatorPrivKey, flags: UpdateFlags = {}): ForkedSignedBeaconBlock =
  let
    slot = withBlck(forked): blck.slot
    root = hash_tree_root(forked)
    signature =
      if skipBlsValidation notin flags:
        get_block_signature(
          fork, genesis_validators_root, slot, root, privKey).toValidatorSig()
      else:
        ValidatorSig()
  ForkedSignedBeaconBlock.init(forked, root, signature)

proc addTestBlock*(
    state: var ForkedHashedBeaconState,
    parent_root: Eth2Digest,
    cache: var StateCache,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    graffiti = default(GraffitiBytes),
    flags: set[UpdateFlag] = {},
    nextSlot = true,
    cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  # Create and add a block to state - state will advance by one slot!
  if nextSlot:
    var info = ForkedEpochInfo()
    doAssert process_slots(
      cfg, state, getStateField(state, slot) + 1, cache, info, flags)

  let
    proposer_index = get_beacon_proposer_index(
      state, cache, getStateField(state, slot))
    privKey = MockPrivKeys[proposer_index.get]
    randao_reveal =
      if skipBlsValidation notin flags:
        privKey.genRandaoReveal(
          getStateField(state, fork),
          getStateField(state, genesis_validators_root),
          getStateField(state, slot)).toValidatorSig()
      else:
        ValidatorSig()

  let
    message = makeBeaconBlock(
      cfg,
      state,
      proposer_index.get(),
      parent_root,
      randao_reveal,
      # Keep deposit counts internally consistent.
      Eth1Data(
        deposit_root: eth1_data.deposit_root,
        deposit_count: getStateField(state, eth1_deposit_index) + deposits.lenu64,
        block_hash: eth1_data.block_hash),
      graffiti,
      attestations,
      deposits,
      BeaconBlockExits(),
      SyncAggregate.init(),
      default(ExecutionPayload),
      noRollback,
      cache)

  doAssert message.isOk(), "Should have created a valid block!"

  let
    new_block = signBlock(
      getStateField(state, fork),
      getStateField(state, genesis_validators_root), message.get(), privKey,
      flags)

  new_block

proc makeTestBlock*(
    state: ForkedHashedBeaconState,
    parent_root: Eth2Digest,
    cache: var StateCache,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    graffiti = default(GraffitiBytes),
    cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  var tmpState = assignClone(state)
  addTestBlock(
    tmpState[], parent_root, cache, eth1_data, attestations, deposits,
    graffiti, cfg = cfg)

func makeAttestationData*(
    state: ForkedHashedBeaconState, slot: Slot, committee_index: CommitteeIndex,
    beacon_block_root: Eth2Digest): AttestationData =
  ## Create an attestation / vote for the block `beacon_block_root` using the
  ## data in `state` to fill in the rest of the fields.
  ## `state` is the state corresponding to the `beacon_block_root` advanced to
  ## the slot we're attesting to.

  let
    current_epoch = get_current_epoch(state)
    start_slot = compute_start_slot_at_epoch(current_epoch)
    epoch_boundary_block_root =
      if start_slot == getStateField(state, slot): beacon_block_root
      else: get_block_root_at_slot(state, start_slot)

  doAssert slot.compute_epoch_at_slot == current_epoch,
    "Computed epoch was " & $slot.compute_epoch_at_slot &
    "  while the state current_epoch was " & $current_epoch

  # https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index.uint64,
    beacon_block_root: beacon_block_root,
    source: getStateField(state, current_justified_checkpoint),
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block_root
    )
  )

func makeAttestation*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    committee: seq[ValidatorIndex], slot: Slot, index: CommitteeIndex,
    validator_index: ValidatorIndex, cache: var StateCache,
    flags: UpdateFlags = {}): Attestation =
  # Avoids state_sim silliness; as it's responsible for all validators,
  # transforming, from monotonic enumerable index -> committee index ->
  # montonoic enumerable index, is wasteful and slow. Most test callers
  # want ValidatorIndex, so that's supported too.
  let
    validator = getStateField(state, validators)[validator_index]
    sac_index = committee.find(validator_index)
    data = makeAttestationData(state, slot, index, beacon_block_root)

  doAssert sac_index != -1, "find_beacon_committee should guarantee this"

  var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
  aggregation_bits.setBit sac_index

  let
    sig =
      if skipBLSValidation notin flags:
        get_attestation_signature(
          getStateField(state, fork),
          getStateField(state, genesis_validators_root),
          data, MockPrivKeys[validator_index]).toValidatorSig()
      else:
        ValidatorSig()

  Attestation(
    data: data,
    aggregation_bits: aggregation_bits,
    signature: sig
  )

func find_beacon_committee(
    state: ForkedHashedBeaconState, validator_index: ValidatorIndex,
    cache: var StateCache): auto =
  let epoch = compute_epoch_at_slot(getStateField(state, slot))
  for epoch_committee_index in 0'u64 ..< get_committee_count_per_slot(
      state, epoch, cache) * SLOTS_PER_EPOCH:
    let
      slot = ((epoch_committee_index mod SLOTS_PER_EPOCH) +
        epoch.compute_start_slot_at_epoch.uint64).Slot
      index = CommitteeIndex(epoch_committee_index div SLOTS_PER_EPOCH)
      committee = get_beacon_committee(state, slot, index, cache)
    if validator_index in committee:
      return (committee, slot, index)
  doAssert false

func makeAttestation*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, cache: var StateCache): Attestation =
  let (committee, slot, index) =
    find_beacon_committee(state, validator_index, cache)
  makeAttestation(state, beacon_block_root, committee, slot, index,
    validator_index, cache)

func makeFullAttestations*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest, slot: Slot,
    cache: var StateCache,
    flags: UpdateFlags = {}): seq[Attestation] =
  # Create attestations in which the full committee participates for each shard
  # that should be attested to during a particular slot
  let committees_per_slot =
    get_committee_count_per_slot(state, slot.epoch, cache)

  for index in 0'u64..<committees_per_slot:
    let
      committee = get_beacon_committee(
        state, slot, index.CommitteeIndex, cache)
      data = makeAttestationData(
        state, slot, index.CommitteeIndex, beacon_block_root)

    doAssert committee.len() >= 1
    # Initial attestation
    var attestation = Attestation(
      aggregation_bits: CommitteeValidatorsBits.init(committee.len),
      data: data)

    var agg {.noInit.}: AggregateSignature
    agg.init(get_attestation_signature(
        getStateField(state, fork),
        getStateField(state, genesis_validators_root), data,
        MockPrivKeys[committee[0]]))

    # Aggregate the remainder
    attestation.aggregation_bits.setBit 0
    for j in 1 ..< committee.len():
      attestation.aggregation_bits.setBit j
      if skipBLSValidation notin flags:
        agg.aggregate(get_attestation_signature(
          getStateField(state, fork),
          getStateField(state, genesis_validators_root), data,
          MockPrivKeys[committee[j]]
        ))

    attestation.signature = agg.finish().toValidatorSig()
    result.add attestation

iterator makeTestBlocks*(
  state: ForkedHashedBeaconState,
  parent_root: Eth2Digest,
  cache: var StateCache,
  blocks: int,
  attested: bool,
  cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  var
    state = assignClone(state)[]
    parent_root = parent_root
  for _ in 0..<blocks:
    let attestations = if attested:
      makeFullAttestations(state, parent_root, getStateField(state, slot), cache)
    else:
      @[]

    let blck = addTestBlock(
      state, parent_root, cache, attestations = attestations, cfg = cfg)
    yield blck
    parent_root = blck.root

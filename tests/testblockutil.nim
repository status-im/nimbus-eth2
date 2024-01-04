# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  stew/endians2,
  ../beacon_chain/consensus_object_pools/sync_committee_msg_pool,
  ../beacon_chain/spec/datatypes/bellatrix,
  ../beacon_chain/spec/[
    beaconstate, helpers, keystore, signatures, state_transition, validator]

# TODO remove this dependency
from std/random import rand

from eth/common/eth_types_rlp import rlpHash

type
  MockPrivKeysT = object
  MockPubKeysT = object
const
  MockPrivKeys* = MockPrivKeysT()
  MockPubKeys* = MockPubKeysT()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/core/pyspec/eth2spec/test/helpers/keys.py
func `[]`*(sk: MockPrivKeysT, index: ValidatorIndex|uint64): ValidatorPrivKey =
  var bytes = (index.uint64 + 1'u64).toBytesLE()  # Consistent with EF tests
  static: doAssert sizeof(bytes) <= sizeof(result)
  copyMem(addr result, addr bytes, sizeof(bytes))

proc `[]`*(pk: MockPubKeysT, index: uint64): ValidatorPubKey =
  var cache {.threadvar.}: Table[uint64, ValidatorPubKey]
  cache.withValue(index, key) do:
    return key[]
  do:
    let key = MockPrivKeys[index].toPubKey().toPubKey()
    cache[index] = key
    return key

proc `[]`*(pk: MockPubKeysT, index: ValidatorIndex): ValidatorPubKey =
  pk[index.uint64]

func makeFakeHash*(i: int): Eth2Digest =
  var bytes = uint64(i).toBytesLE()
  static: doAssert sizeof(bytes) <= sizeof(result.data)
  copyMem(addr result.data[0], addr bytes[0], sizeof(bytes))

proc makeDeposit*(
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

  if skipBlsValidation notin flags:
    result.signature = get_deposit_signature(cfg, result, privkey).toValidatorSig()

proc makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}, cfg = defaultRuntimeConfig): seq[DepositData] =
  for i in 0..<n.int:
    result.add makeDeposit(i, flags, cfg = cfg)

func signBlock(
    fork: Fork, genesis_validators_root: Eth2Digest, forked: ForkedBeaconBlock,
    privKey: ValidatorPrivKey, flags: UpdateFlags = {}): ForkedSignedBeaconBlock =
  let
    slot = withBlck(forked): forkyBlck.slot
    root = hash_tree_root(forked)
    signature =
      if skipBlsValidation notin flags:
        get_block_signature(
          fork, genesis_validators_root, slot, root, privKey).toValidatorSig()
      else:
        ValidatorSig()
  ForkedSignedBeaconBlock.init(forked, root, signature)

from eth/eip1559 import EIP1559_INITIAL_BASE_FEE, calcEip1599BaseFee
from eth/common/eth_types import EMPTY_ROOT_HASH, GasInt

proc build_empty_merge_execution_payload(state: bellatrix.BeaconState):
    bellatrix.ExecutionPayloadForSigning =
  ## Assuming a pre-state of the same slot, build a valid ExecutionPayload
  ## without any transactions from a non-merged block.

  doAssert not is_merge_transition_complete(state)

  let
    latest = state.latest_execution_payload_header
    timestamp = compute_timestamp_at_slot(state, state.slot)
    randao_mix = get_randao_mix(state, get_current_epoch(state))

  var payload = bellatrix.ExecutionPayload(
    parent_hash: latest.block_hash,
    state_root: latest.state_root, # no changes to the state
    receipts_root: EMPTY_ROOT_HASH,
    block_number: latest.block_number + 1,
    prev_randao: randao_mix,
    gas_limit: 30000000, # retain same limit
    gas_used: 0, # empty block, 0 gas
    timestamp: timestamp,
    base_fee_per_gas: EIP1559_INITIAL_BASE_FEE)

  payload.block_hash = rlpHash blockToBlockHeader(bellatrix.BeaconBlock(body:
    bellatrix.BeaconBlockBody(execution_payload: payload)))

  bellatrix.ExecutionPayloadForSigning(executionPayload: payload,
                                       blockValue: Wei.zero)

from stew/saturating_arith import saturate

proc build_empty_execution_payload(
    state: bellatrix.BeaconState,
    feeRecipient: Eth1Address): bellatrix.ExecutionPayloadForSigning =
  ## Assuming a pre-state of the same slot, build a valid ExecutionPayload
  ## without any transactions.
  let
    latest = state.latest_execution_payload_header
    timestamp = compute_timestamp_at_slot(state, state.slot)
    randao_mix = get_randao_mix(state, get_current_epoch(state))
    base_fee = calcEip1599BaseFee(GasInt.saturate latest.gas_limit,
                                  GasInt.saturate latest.gas_used,
                                  latest.base_fee_per_gas)

  var payload = bellatrix.ExecutionPayloadForSigning(
    executionPayload: bellatrix.ExecutionPayload(
      parent_hash: latest.block_hash,
      fee_recipient: bellatrix.ExecutionAddress(data: distinctBase(feeRecipient)),
      state_root: latest.state_root, # no changes to the state
      receipts_root: EMPTY_ROOT_HASH,
      block_number: latest.block_number + 1,
      prev_randao: randao_mix,
      gas_limit: latest.gas_limit, # retain same limit
      gas_used: 0, # empty block, 0 gas
      timestamp: timestamp,
      base_fee_per_gas: base_fee),
    blockValue: Wei.zero)

  payload.executionPayload.block_hash =
    bellatrix.BeaconBlock(body: bellatrix.BeaconBlockBody(execution_payload:
      payload.executionPayload)).compute_execution_block_hash()

  payload

proc addTestBlock*(
    state: var ForkedHashedBeaconState,
    cache: var StateCache,
    eth1_data: Eth1Data = Eth1Data(),
    attestations: seq[Attestation] = newSeq[Attestation](),
    deposits: seq[Deposit] = newSeq[Deposit](),
    sync_aggregate: SyncAggregate = SyncAggregate.init(),
    graffiti: GraffitiBytes = default(GraffitiBytes),
    flags: set[UpdateFlag] = {},
    nextSlot: bool = true,
    cfg: RuntimeConfig = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  # Create and add a block to state - state will advance by one slot!
  if nextSlot:
    var info = ForkedEpochInfo()
    process_slots(
      cfg, state, getStateField(state, slot) + 1, cache, info, flags).expect(
        "can advance 1")

  let
    proposer_index = get_beacon_proposer_index(
      state, cache, getStateField(state, slot)).expect("valid proposer index")
    privKey = MockPrivKeys[proposer_index]
    randao_reveal =
      if skipBlsValidation notin flags:
        get_epoch_signature(
          getStateField(state, fork),
          getStateField(state, genesis_validators_root),
          getStateField(state, slot).epoch, privKey).toValidatorSig()
      else:
        ValidatorSig()

  let message = withState(state):
    let execution_payload =
      when consensusFork > ConsensusFork.Bellatrix:
        default(consensusFork.ExecutionPayloadForSigning)
      elif consensusFork == ConsensusFork.Bellatrix:
        if cfg.CAPELLA_FORK_EPOCH != FAR_FUTURE_EPOCH:
          # Can't keep correctly doing this once Capella happens, but LVH search
          # test relies on merging. So, merge only if no Capella transition.
          default(bellatrix.ExecutionPayloadForSigning)
        else:
          # Merge shortly after Bellatrix
          if  forkyState.data.slot >
              cfg.BELLATRIX_FORK_EPOCH * SLOTS_PER_EPOCH + 10:
            if is_merge_transition_complete(forkyState.data):
              const feeRecipient = default(Eth1Address)
              build_empty_execution_payload(forkyState.data, feeRecipient)
            else:
              build_empty_merge_execution_payload(forkyState.data)
          else:
            default(bellatrix.ExecutionPayloadForSigning)
      else:
        default(bellatrix.ExecutionPayloadForSigning)

    makeBeaconBlock(
      cfg,
      state,
      proposer_index,
      randao_reveal,
      # Keep deposit counts internally consistent.
      Eth1Data(
        deposit_root: eth1_data.deposit_root,
        deposit_count: forkyState.data.eth1_deposit_index + deposits.lenu64,
        block_hash: eth1_data.block_hash),
      graffiti,
      attestations,
      deposits,
      BeaconBlockValidatorChanges(),
      sync_aggregate,
      execution_payload,
      noRollback,
      cache,
      verificationFlags = {skipBlsValidation})

  if message.isErr:
    raiseAssert "Failed to create a block: " & $message.error

  let
    new_block = signBlock(
      getStateField(state, fork),
      getStateField(state, genesis_validators_root), message.get(), privKey,
      flags)

  new_block

proc makeTestBlock*(
    state: ForkedHashedBeaconState,
    cache: var StateCache,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    sync_aggregate = SyncAggregate.init(),
    graffiti = default(GraffitiBytes),
    cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  let tmpState = assignClone(state)
  addTestBlock(
    tmpState[], cache, eth1_data,
    attestations, deposits, sync_aggregate, graffiti, cfg = cfg)

func makeAttestationData*(
    state: ForkyBeaconState, slot: Slot, committee_index: CommitteeIndex,
    beacon_block_root: Eth2Digest): AttestationData =
  let
    current_epoch = get_current_epoch(state)
    start_slot = start_slot(current_epoch)
    epoch_boundary_block_root =
      if start_slot == state.slot: beacon_block_root
      else: get_block_root_at_slot(state, start_slot)

  doAssert slot.epoch == current_epoch,
    "Computed epoch was " & $slot.epoch &
    "  while the state current_epoch was " & $current_epoch

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index.uint64,
    beacon_block_root: beacon_block_root,
    source: state.current_justified_checkpoint,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block_root
    )
  )

func makeAttestationSig(
    fork: Fork, genesis_validators_root: Eth2Digest, data: AttestationData,
    committee: openArray[ValidatorIndex],
    bits: CommitteeValidatorsBits): ValidatorSig =
  let signing_root = compute_attestation_signing_root(
    fork, genesis_validators_root, data)

  var
    agg {.noinit.}: AggregateSignature
    first = true

  for i in 0..<bits.len():
    if not bits[i]: continue
    let sig = blsSign(MockPrivKeys[committee[i]], signing_root.data)

    if first:
      agg.init(sig)
      first = false
    else:
      agg.aggregate(sig)

  if first:
    ValidatorSig.infinity()
  else:
    agg.finish().toValidatorSig()

func makeAttestationData*(
    state: ForkedHashedBeaconState, slot: Slot, committee_index: CommitteeIndex,
    beacon_block_root: Eth2Digest): AttestationData =
  ## Create an attestation / vote for the block `beacon_block_root` using the
  ## data in `state` to fill in the rest of the fields.
  ## `state` is the state corresponding to the `beacon_block_root` advanced to
  ## the slot we're attesting to.
  withState(state):
    makeAttestationData(
      forkyState.data, slot, committee_index, beacon_block_root)

func makeAttestation(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    committee: seq[ValidatorIndex], slot: Slot, committee_index: CommitteeIndex,
    validator_index: ValidatorIndex, cache: var StateCache,
    flags: UpdateFlags = {}): Attestation =
  let
    index_in_committee = committee.find(validator_index)
    data = makeAttestationData(state, slot, committee_index, beacon_block_root)

  doAssert index_in_committee != -1, "find_beacon_committee should guarantee this"

  var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
  aggregation_bits.setBit index_in_committee

  let sig = if skipBlsValidation in flags:
    ValidatorSig()
  else:
    makeAttestationSig(
      getStateField(state, fork),
      getStateField(state, genesis_validators_root),
      data, committee, aggregation_bits)

  Attestation(
    data: data,
    aggregation_bits: aggregation_bits,
    signature: sig
  )

func find_beacon_committee(
    state: ForkedHashedBeaconState, validator_index: ValidatorIndex,
    cache: var StateCache): auto =
  let epoch = epoch(getStateField(state, slot))
  for epoch_committee_index in 0'u64 ..< get_committee_count_per_slot(
      state, epoch, cache) * SLOTS_PER_EPOCH:
    let
      slot = ((epoch_committee_index mod SLOTS_PER_EPOCH) +
        epoch.start_slot.uint64).Slot
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
  let committees_per_slot = get_committee_count_per_slot(
    state, slot.epoch, cache)
  for committee_index in get_committee_indices(committees_per_slot):
    let
      committee = get_beacon_committee(state, slot, committee_index, cache)
      data = makeAttestationData(state, slot, committee_index, beacon_block_root)

    doAssert committee.len() >= 1
    var attestation = Attestation(
      aggregation_bits: CommitteeValidatorsBits.init(committee.len),
      data: data)
    for i in 0..<committee.len:
      attestation.aggregation_bits.setBit(i)

    attestation.signature = makeAttestationSig(
        getStateField(state, fork),
        getStateField(state, genesis_validators_root), data, committee,
        attestation.aggregation_bits)

    result.add attestation

proc makeSyncAggregate(
    state: ForkedHashedBeaconState,
    syncCommitteeRatio: float,
    cfg: RuntimeConfig): SyncAggregate =
  if syncCommitteeRatio <= 0.0:
    return SyncAggregate.init()

  let
    syncCommittee =
      withState(state):
        when consensusFork >= ConsensusFork.Altair:
          if (forkyState.data.slot + 1).is_sync_committee_period():
            forkyState.data.next_sync_committee
          else:
            forkyState.data.current_sync_committee
        else:
          return SyncAggregate.init()
    fork =
      getStateField(state, fork)
    genesis_validators_root =
      getStateField(state, genesis_validators_root)
    slot =
      getStateField(state, slot)
    latest_block_id =
      withState(state): forkyState.latest_block_id
    rng = HmacDrbgContext.new()
    syncCommitteePool = newClone(SyncCommitteeMsgPool.init(rng, cfg))

  type
    Aggregator = object
      subcommitteeIdx: SyncSubcommitteeIndex
      validatorIdx: ValidatorIndex
      selectionProof: ValidatorSig

  let
    minActiveParticipants =
      if syncCommitteeRatio >= 2.0 / 3: # Ensure supermajority is hit
        (SYNC_COMMITTEE_SIZE * 2 + 2) div 3
      else:
        0
    maxActiveParticipants = (syncCommitteeRatio * SYNC_COMMITTEE_SIZE).int
  var
    aggregators: seq[Aggregator]
    numActiveParticipants = 0
  for subcommitteeIdx in SyncSubcommitteeIndex:
    let
      firstKeyIdx = subcommitteeIdx.int * SYNC_SUBCOMMITTEE_SIZE
      lastKeyIdx = firstKeyIdx + SYNC_SUBCOMMITTEE_SIZE - 1
    var processedKeys = initHashSet[ValidatorPubKey]()
    for idx, validatorKey in syncCommittee.pubkeys[firstKeyIdx .. lastKeyIdx]:
      if validatorKey in processedKeys:
        continue
      processedKeys.incl validatorKey
      let
        validatorIdx =
          block:
            var res = 0
            for i, validator in getStateField(state, validators):
              if validator.pubkey == validatorKey:
                res = i
                break
            res.ValidatorIndex
        selectionProofSig = get_sync_committee_selection_proof(
          fork, genesis_validators_root,
          slot, subcommitteeIdx,
          MockPrivKeys[validatorIdx])
      if is_sync_committee_aggregator(selectionProofSig.toValidatorSig):
        aggregators.add Aggregator(
          subcommitteeIdx: subcommitteeIdx,
          validatorIdx: validatorIdx,
          selectionProof: selectionProofSig.toValidatorSig)

      if numActiveParticipants >= minActiveParticipants and
          rand(1.0) > syncCommitteeRatio:
        continue
      var positions: seq[uint64]
      for pos, key in syncCommittee.pubkeys[firstKeyIdx + idx .. lastKeyIdx]:
        if numActiveParticipants >= maxActiveParticipants:
          break
        if key == validatorKey:
          positions.add (idx + pos).uint64
          inc numActiveParticipants
      if positions.len == 0:
        continue

      let signature = get_sync_committee_message_signature(
        fork, genesis_validators_root,
        slot, latest_block_id.root,
        MockPrivKeys[validatorIdx])
      syncCommitteePool[].addSyncCommitteeMessage(
        slot,
        latest_block_id,
        uint64 validatorIdx,
        signature,
        subcommitteeIdx,
        positions)

  for aggregator in aggregators:
    var contribution: SyncCommitteeContribution
    if syncCommitteePool[].produceContribution(
        slot, latest_block_id, aggregator.subcommitteeIdx, contribution):
      let
        contributionAndProof = ContributionAndProof(
          aggregator_index: uint64 aggregator.validatorIdx,
          contribution: contribution,
          selection_proof: aggregator.selectionProof)
        contributionSig = get_contribution_and_proof_signature(
          fork, genesis_validators_root,
          contributionAndProof,
          MockPrivKeys[aggregator.validatorIdx])
        signedContributionAndProof = SignedContributionAndProof(
          message: contributionAndProof,
          signature: contributionSig.toValidatorSig)
      syncCommitteePool[].addContribution(
        signedContributionAndProof,
        latest_block_id, contribution.signature.load.get)

  syncCommitteePool[].produceSyncAggregate(latest_block_id, slot + 1)

iterator makeTestBlocks*(
  state: ForkedHashedBeaconState,
  cache: var StateCache,
  blocks: int,
  eth1_data = Eth1Data(),
  attested = false,
  allDeposits = newSeq[Deposit](),
  syncCommitteeRatio = 0.0,
  graffiti = default(GraffitiBytes),
  cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  var state = assignClone(state)
  for _ in 0..<blocks:
    let
      parent_root = withState(state[]): forkyState.latest_block_root
      attestations =
        if attested:
          makeFullAttestations(
            state[], parent_root, getStateField(state[], slot), cache)
        else:
          @[]
      stateEth1 = getStateField(state[], eth1_data)
      stateDepositIndex = getStateField(state[], eth1_deposit_index)
      deposits =
        if stateDepositIndex < stateEth1.deposit_count:
          let
            lowIndex = stateDepositIndex
            numDeposits = min(MAX_DEPOSITS, stateEth1.deposit_count - lowIndex)
            highIndex = lowIndex + numDeposits - 1
          allDeposits[lowIndex .. highIndex]
        else:
          newSeq[Deposit]()
      sync_aggregate = makeSyncAggregate(state[], syncCommitteeRatio, cfg)

    yield addTestBlock(
      state[], cache,
      eth1_data = eth1_data,
      attestations = attestations,
      deposits = deposits,
      sync_aggregate = sync_aggregate,
      graffiti = graffiti,
      cfg = cfg)

# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles,
  ssz_serialization,
  std/sequtils,
  stew/endians2,
  eth/rlp,
  eth/common/[headers_rlp, eth_types],
  ../beacon_chain/consensus_object_pools/sync_committee_msg_pool,
  ../beacon_chain/el/engine_api_conversions,
  ../beacon_chain/spec/[
    beaconstate, helpers, keystore, forks, signatures, state_transition, validator]

from ../beacon_chain/spec/state_transition_block import kzg_commitment_to_versioned_hash
from ../beacon_chain/spec/datatypes/electra import ExecutionRequests

from ../beacon_chain/spec/datatypes/deneb import
  BlobsBundle, Blobs, KzgCommitments, KzgProofs
from ../beacon_chain/spec/datatypes/fulu import BlobsBundle

from kzg4844 import KzgCommitment, KzgProof

# TODO remove this dependency
from std/random import rand

type
  MockPrivKeysT = object
  MockPubKeysT = object

const
  MockPrivKeys* = MockPrivKeysT()
  MockPubKeys* = MockPubKeysT()

type
  BlobsBundle* = object
    # TODO the fulu BlobsBundle uses an ugly hack to get deneb compatibility
    #      which defeats the purpose of using distinct types to begin with..
    commitments*: seq[kzg4844.KzgCommitment]
    proofs*: seq[kzg4844.KzgProof]
    blobs*: seq[deneb.Blob]

  EngineBlock*[BB: ForkySignedBeaconBlock] = object
    blck*: BB
    blobsBundle*: BlobsBundle

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

proc makeDepositData*(
    i: int,
    amount = MAX_EFFECTIVE_BALANCE.Gwei,
    flags: UpdateFlags = {},
    version = defaultRuntimeConfig.GENESIS_FORK_VERSION,
): DepositData =
  var cache {.threadvar.}: Table[int, DepositData]

  if amount == MAX_EFFECTIVE_BALANCE.Gwei and skipBlsValidation notin flags and
      version == defaultRuntimeConfig.GENESIS_FORK_VERSION:
    cache.withValue(i, data):
      return data[]

  let
    privkey = MockPrivKeys[i.ValidatorIndex]
    pubkey = MockPubKeys[i.ValidatorIndex]
    withdrawal_credentials = makeWithdrawalCredentials(pubkey)

  result = DepositData(
    pubkey: pubkey, withdrawal_credentials: withdrawal_credentials, amount: amount
  )

  if skipBlsValidation notin flags:
    result.signature = get_deposit_signature(version, result, privkey).toValidatorSig()

  if amount == MAX_EFFECTIVE_BALANCE.Gwei and skipBlsValidation notin flags and
      version == defaultRuntimeConfig.GENESIS_FORK_VERSION:
    cache[i] = result

func makeFakeHash*(i: int): Eth2Digest =
  var bytes = uint64(i).toBytesLE()
  static: doAssert sizeof(bytes) <= sizeof(result.data)
  copyMem(addr result.data[0], addr bytes[0], sizeof(bytes))

proc makeInitialDeposits*(
    cfg: RuntimeConfig, n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}
): seq[DepositData] =
  for i in 0 ..< n.int:
    result.add makeDepositData(
      i, MAX_EFFECTIVE_BALANCE.Gwei, flags, cfg.GENESIS_FORK_VERSION
    )

func signBlock(
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    blck: ForkyBeaconBlock,
    privKey: ValidatorPrivKey,
    flags: UpdateFlags,
): auto =
  let
    slot = blck.slot
    root = hash_tree_root(blck)
    signature =
      if skipBlsValidation notin flags:
        get_block_signature(fork, genesis_validators_root, slot, root, privKey)
        .toValidatorSig()
      else:
        ValidatorSig()
  ForkyBeaconBlock.kind.SignedBeaconBlock(message: blck, signature: signature, root: root)

from eth/eip1559 import EIP1559_INITIAL_BASE_FEE, calcEip1599BaseFee

func makeExecutionPayloadForSigning*(
    cfg: RuntimeConfig,
    consensusFork: static ConsensusFork,
    state: ForkyBeaconState,
    blobsBundle: testblockutil.BlobsBundle,
): consensusFork.ExecutionPayloadForSigning =
  ## Construct an execution payload that is sufficiently valid to pass consensus
  ## validations (without necessarily making sense on the execution side, which
  ## requires execution state) - in Bellatrix, it _should_ be EL-valid as well!

  let
    merged = is_merge_transition_complete(state)
    latest = state.latest_execution_payload_header
    timestamp = cfg.timeParams.compute_timestamp_at_slot(state, state.slot)
    randao_mix = get_randao_mix(state, get_current_epoch(state))
    base_fee =
      if merged:
        calcEip1599BaseFee(latest.gas_limit, latest.gas_used, latest.base_fee_per_gas)
      else:
        EIP1559_INITIAL_BASE_FEE

  var eps = default(consensusFork.ExecutionPayloadForSigning)
  var payload = typeof(eps.executionPayload)(
    parent_hash: latest.block_hash,
    fee_recipient: default(Eth1Address),
    state_root: latest.state_root,
    receipts_root: EMPTY_ROOT_HASH.asEth2Digest,
    block_number: latest.block_number + 1,
    prev_randao: randao_mix,
    gas_limit: if merged: latest.gas_limit else: 30000000,
    gas_used: 0, # empty block, 0 gas
    timestamp: timestamp,
    base_fee_per_gas: base_fee,
  )

  # Add withdrawals before computing hash (hash needs to include them)
  when consensusFork >= ConsensusFork.Capella:
    payload.withdrawals =
      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](get_expected_withdrawals(state))

  let parent_root = state.latest_block_root(default(Eth2Digest))
  payload.block_hash =
    when consensusFork >= ConsensusFork.Electra:
      let emptyRequestsHash = computeRequestsHash(default(electra.ExecutionRequests))
      compute_execution_block_hash(
        consensusFork, payload, parent_root, requestsHash = Opt.some emptyRequestsHash
      )
    else:
      compute_execution_block_hash(
        consensusFork, payload, parent_root
      )

  eps.executionPayload = payload

  when consensusFork == ConsensusFork.Fulu:
    eps.blobsBundle = fulu.BlobsBundle()
  elif consensusFork in ConsensusFork.Deneb..ConsensusFork.Electra:
    eps.blobsBundle = deneb.BlobsBundle()

  eps

func makeExecutionPayloadWithNonEmptyBlobsForSigning*(
    cfg: RuntimeConfig,
    consensusFork: static ConsensusFork,
    state: ForkyBeaconState,
    blobsBundle: testblockutil.BlobsBundle,
): consensusFork.ExecutionPayloadForSigning =
  ## Construct an execution payload that is sufficiently valid to pass consensus
  ## validations (without necessarily making sense on the execution side, which
  ## requires execution state) - in Bellatrix, it _should_ be EL-valid as well!

  let
    merged = is_merge_transition_complete(state)
    latest = state.latest_execution_payload_header
    timestamp = cfg.timeParams.compute_timestamp_at_slot(state, state.slot)
    randao_mix = get_randao_mix(state, get_current_epoch(state))
    base_fee =
      if merged:
        calcEip1599BaseFee(latest.gas_limit, latest.gas_used, latest.base_fee_per_gas)
      else:
        EIP1559_INITIAL_BASE_FEE

  var eps: consensusFork.ExecutionPayloadForSigning
  var payload = typeof(eps.executionPayload)(
    parent_hash: latest.block_hash,
    fee_recipient: default(Eth1Address),
    state_root: latest.state_root,
    receipts_root: EMPTY_ROOT_HASH.asEth2Digest,
    block_number: latest.block_number + 1,
    prev_randao: randao_mix,
    gas_limit: if merged: latest.gas_limit else: 30000000,
    gas_used: 0, # empty block, 0 gas
    timestamp: timestamp,
    base_fee_per_gas: base_fee,
  )

  # Add EIP-4844 transactions with versioned hashes for blob commitments
  when consensusFork >= ConsensusFork.Deneb:
    if blobsBundle.commitments.len > 0:
      # Create versioned hashes from commitments
      let versionedHashes = blobsBundle.commitments.mapIt(
        kzg_commitment_to_versioned_hash(it))

      # Create a simple EIP-4844 transaction
      let tx = eth_types.Transaction(
        txType: TxEip4844,
        chainId: chainId(1),
        nonce: 0.AccountNonce,
        gasLimit: 21000.GasInt,
        maxPriorityFeePerGas: 1.GasInt,
        maxFeePerGas: base_fee.truncate(uint64).GasInt,
        to: Opt.some(default(eth_types.Address)),
        versionedHashes: versionedHashes,
        maxFeePerBlobGas: 1.u256
      )

      # Encode and add to payload
      doAssert payload.transactions.add(bellatrix.Transaction.init(rlp.encode(tx)))
      # Update gas used (simple estimate: 21000 per transaction)
      payload.gas_used = 21000
  else:
    # For pre-Deneb forks, commitments should be empty
    doAssert blobsBundle.commitments.len == 0

  # Add withdrawals before computing hash (hash needs to include them)
  when consensusFork >= ConsensusFork.Capella:
    payload.withdrawals =
      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](get_expected_withdrawals(state))

  let parent_root = state.latest_block_root(default(Eth2Digest))
  payload.block_hash =
    when consensusFork >= ConsensusFork.Electra:
      # Use correct empty requests hash
      let emptyRequestsHash = computeRequestsHash(default(electra.ExecutionRequests))
      compute_execution_block_hash(
        consensusFork, payload, parent_root, requestsHash = Opt.some emptyRequestsHash
      )
    else:
      compute_execution_block_hash(
        consensusFork, payload, parent_root
      )

  eps.executionPayload = payload

  when consensusFork >= ConsensusFork.Deneb:
    eps.blobsBundle.commitments =
      typeof(eps.blobsBundle.commitments).init(blobsBundle.commitments)
    eps.blobsBundle.proofs =
      typeof(eps.blobsBundle.proofs).init(blobsBundle.proofs)
    eps.blobsBundle.blobs =
      typeof(eps.blobsBundle.blobs).init(blobsBundle.blobs)

  eps

func lastPremergeSlotInTestCfg*(cfg: RuntimeConfig): Slot =
  # Merge shortly after Bellatrix
  cfg.BELLATRIX_FORK_EPOCH.start_slot + 6

proc addTestEngineBlock*(
    cfg: RuntimeConfig,
    consensusFork: static ConsensusFork,
    state: var ForkyHashedBeaconState,
    cache: var StateCache,
    eth1_data: Eth1Data = Eth1Data(),
    attestations: seq[phase0.Attestation] = newSeq[phase0.Attestation](),
    electraAttestations: seq[electra.Attestation] = newSeq[electra.Attestation](),
    deposits: seq[Deposit] = newSeq[Deposit](),
    validator_changes = BeaconBlockValidatorChanges(),
    sync_aggregate: SyncAggregate = SyncAggregate.init(),
    graffiti: GraffitiBytes = default(GraffitiBytes),
    flags: set[UpdateFlag] = {},
): EngineBlock[consensusFork.SignedBeaconBlock] =
  # Create and add a block to state - state will advance by one slot!
  let
    proposer_index = get_beacon_proposer_index(state.data, cache, state.data.slot)
      .expect("valid proposer index")
    privKey = MockPrivKeys[proposer_index]
    randao_reveal =
      if skipBlsValidation notin flags:
        get_epoch_signature(
          state.data.fork, state.data.genesis_validators_root, state.data.slot.epoch,
          privKey,
        )
        .toValidatorSig()
      else:
        ValidatorSig()

    eth1_data =
      # Keep deposit counts internally consistent.
      Eth1Data(
        deposit_root: eth1_data.deposit_root,
        deposit_count: state.data.eth1_deposit_index + deposits.lenu64,
        block_hash: eth1_data.block_hash,
      )

    eps =
      when consensusFork >= ConsensusFork.Gloas:
        var gloasEps = default(gloas.ExecutionPayloadForSigning)
        gloasEps.executionPayload.parent_hash = state.data.latest_block_hash
        gloasEps.executionPayload.block_hash = eth2digest(
          state.data.slot.uint64.toBytesBE())
        gloasEps
      elif consensusFork >= ConsensusFork.Bellatrix:
        if state.data.slot > cfg.lastPremergeSlotInTestCfg:
          makeExecutionPayloadForSigning(
            cfg, consensusFork, state.data, BlobsBundle())
        else:
          default(consensusFork.ExecutionPayloadForSigning)
      else:
        default(bellatrix.ExecutionPayloadForSigning)

    attestations =
      when consensusFork >= ConsensusFork.Electra: electraAttestations else: attestations

    signed_execution_payload_bid =
      when consensusFork == ConsensusFork.Heze:
        debugHezeComment "..."
        default(gloas.SignedExecutionPayloadBid)
      elif consensusFork == ConsensusFork.Gloas:
        gloas.SignedExecutionPayloadBid(
          message: gloas.ExecutionPayloadBid(
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: state.data.slot,
            block_hash: eps.executionPayload.block_hash,
            parent_block_hash: state.data.latest_block_hash,
            parent_block_root: state.latest_block_root,
            prev_randao: get_randao_mix(state.data, get_current_epoch(state.data)),
            value: 0.Gwei,
          ),
          signature: ValidatorSig.infinity(),
        )
      else:
        default(gloas.SignedExecutionPayloadBid)

    message = makeBeaconBlock(
        cfg,
        consensusFork,
        state,
        cache,
        proposer_index,
        randao_reveal,
        eth1_data,
        graffiti,
        attestations,
        deposits,
        validator_changes,
        sync_aggregate,
        eps,
        verificationFlags = {skipBlsValidation},
        execution_requests = default(ExecutionRequests),
        signed_execution_payload_bid = signed_execution_payload_bid,
        payload_attestations = @[]
      )
      .expect("block")

  EngineBlock[consensusFork.SignedBeaconBlock](
    blck: signBlock(
      state.data.fork, state.data.genesis_validators_root, message, privKey, flags
    )
  )

proc addTestEngineBlockWithBlobs*(
    cfg: RuntimeConfig,
    consensusFork: static ConsensusFork,
    state: var ForkyHashedBeaconState,
    blobsBundle: testblockutil.BlobsBundle,
    eth1_data: Eth1Data = Eth1Data(),
    attestations: seq[phase0.Attestation] = newSeq[phase0.Attestation](),
    electraAttestations: seq[electra.Attestation] = newSeq[electra.Attestation](),
    deposits: seq[Deposit] = newSeq[Deposit](),
    validator_changes = BeaconBlockValidatorChanges(),
    sync_aggregate: SyncAggregate = SyncAggregate.init(),
    graffiti: GraffitiBytes = default(GraffitiBytes),
    flags: set[UpdateFlag] = {},
    cache: var StateCache,
): EngineBlock[consensusFork.SignedBeaconBlock] =
  # Create and add a block to state with blobs - state will advance by one slot!
  let
    proposer_index = get_beacon_proposer_index(state.data, cache, state.data.slot)
      .expect("valid proposer index")
    privKey = MockPrivKeys[proposer_index]
    randao_reveal =
      if skipBlsValidation notin flags:
        get_epoch_signature(
          state.data.fork, state.data.genesis_validators_root, state.data.slot.epoch,
          privKey,
        )
        .toValidatorSig()
      else:
        ValidatorSig()

    eth1_data =
      # Keep deposit counts internally consistent.
      Eth1Data(
        deposit_root: eth1_data.deposit_root,
        deposit_count: state.data.eth1_deposit_index + deposits.lenu64,
        block_hash: eth1_data.block_hash,
      )

    eps =
      when consensusFork >= ConsensusFork.Gloas:
        var gloasEps = default(gloas.ExecutionPayloadForSigning)
        gloasEps.executionPayload.parent_hash = state.data.latest_block_hash
        gloasEps.executionPayload.block_hash = eth2digest(
          state.data.slot.uint64.toBytesBE())
        gloasEps
      elif consensusFork >= ConsensusFork.Bellatrix:
        if state.data.slot > cfg.lastPremergeSlotInTestCfg:
          makeExecutionPayloadWithNonEmptyBlobsForSigning(
            cfg, consensusFork, state.data, blobsBundle)
        else:
          default(consensusFork.ExecutionPayloadForSigning)
      else:
        default(bellatrix.ExecutionPayloadForSigning)

    signed_execution_payload_bid =
      when consensusFork >= ConsensusFork.Gloas:
        debugHezeComment "..."
        default(gloas.SignedExecutionPayloadBid)
      elif consensusFork == ConsensusFork.Gloas:
        gloas.SignedExecutionPayloadBid(
          message: gloas.ExecutionPayloadBid(
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: state.data.slot,
            block_hash: eps.executionPayload.block_hash,
            parent_block_hash: state.data.latest_block_hash,
            parent_block_root: state.latest_block_root,
            prev_randao: get_randao_mix(state.data, get_current_epoch(state.data)),
            value: 0.Gwei,
          ),
          signature: ValidatorSig.infinity(),
        )
      else:
        default(gloas.SignedExecutionPayloadBid)

    attestations =
      when consensusFork >= ConsensusFork.Electra: electraAttestations else: attestations
    message = makeBeaconBlock(
        cfg,
        consensusFork,
        state,
        cache,
        proposer_index,
        randao_reveal,
        eth1_data,
        graffiti,
        attestations,
        deposits,
        validator_changes,
        sync_aggregate,
        eps,
        verificationFlags = {skipBlsValidation},
        execution_requests = default(ExecutionRequests),
        signed_execution_payload_bid = signed_execution_payload_bid,
        payload_attestations = @[]
      )
      .expect("block")

  EngineBlock[consensusFork.SignedBeaconBlock](
    blck: signBlock(
      state.data.fork, state.data.genesis_validators_root, message, privKey, flags
    ),
    blobsBundle: blobsBundle
  )

template toSidecarsOpt*(
    blobsBundle: BlobsBundle, consensusFork: static ConsensusFork
): untyped =
  # TODO actually construct sidecars..
  when consensusFork >= ConsensusFork.Gloas:
    Opt.some(default(gloas.DataColumnSidecars))
  elif consensusFork >= ConsensusFork.Fulu:
    Opt.some(default(fulu.DataColumnSidecars))
  elif consensusFork >= ConsensusFork.Deneb:
    Opt.some(default(BlobSidecars))
  else:
    noSidecars

proc addTestBlock*(
    state: var ForkedHashedBeaconState,
    cache: var StateCache,
    eth1_data: Eth1Data = Eth1Data(),
    attestations: seq[phase0.Attestation] = newSeq[phase0.Attestation](),
    electraAttestations: seq[electra.Attestation] = newSeq[electra.Attestation](),
    deposits: seq[Deposit] = newSeq[Deposit](),
    validator_changes = BeaconBlockValidatorChanges(),
    sync_aggregate: SyncAggregate = SyncAggregate.init(),
    graffiti: GraffitiBytes = default(GraffitiBytes),
    flags: set[UpdateFlag] = {},
    nextSlot: bool = true,
    cfg: RuntimeConfig = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  # Create and add a block to state - state will advance by one slot!
  if nextSlot:
    var info = ForkedEpochInfo()
    process_slots(
      cfg, state, state.slot + 1, cache, info, flags).expect(
        "can advance 1")

  withState(state):
    ForkedSignedBeaconBlock.init(
      addTestEngineBlock(
        cfg, consensusFork, forkyState, cache, eth1_data, attestations,
        electraAttestations, deposits, validator_changes, sync_aggregate,
        graffiti, flags).blck)

proc makeTestBlock*(
    state: ForkedHashedBeaconState,
    cache: var StateCache,
    eth1_data = Eth1Data(),
    attestations = newSeq[phase0.Attestation](),
    electraAttestations = newSeq[electra.Attestation](),
    deposits = newSeq[Deposit](),
    validator_changes = BeaconBlockValidatorChanges(),
    sync_aggregate = SyncAggregate.init(),
    graffiti = default(GraffitiBytes),
    cfg = defaultRuntimeConfig): ForkedSignedBeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  let tmpState = assignClone(state)
  addTestBlock(
    tmpState[], cache, eth1_data, attestations, electraAttestations,
    deposits, validator_changes, sync_aggregate, graffiti, cfg = cfg)

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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/validator.md#attestation-data
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
    bits: CommitteeValidatorsBits | ElectraCommitteeValidatorsBits): ValidatorSig =
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

func makeSingleAttestation*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    committee: seq[ValidatorIndex], slot: Slot, committee_index: CommitteeIndex,
    validator_index: ValidatorIndex, cache: var StateCache,
    flags: UpdateFlags = {}): electra.SingleAttestation =
  let
    index_in_committee = committee.find(validator_index)
    data = makeAttestationData(state, slot, CommitteeIndex(0), beacon_block_root)

  doAssert index_in_committee != -1, "find_beacon_committee should guarantee this"

  var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
  aggregation_bits.setBit index_in_committee

  let sig = if skipBlsValidation in flags:
    ValidatorSig()
  else:
    makeAttestationSig(
      state.fork,
      state.genesis_validators_root,
      data, committee, aggregation_bits)

  electra.SingleAttestation(
    committee_index: uint64 committee_index,
    attester_index: uint64 validator_index,
    data: data,
    signature: sig
  )

func find_beacon_committee(
    state: ForkedHashedBeaconState, validator_index: ValidatorIndex,
    cache: var StateCache): auto =
  let epoch = epoch(state.slot)
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

func makeSingleAttestation*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, cache: var StateCache): electra.SingleAttestation =
  let (committee, slot, index) =
    find_beacon_committee(state, validator_index, cache)
  makeSingleAttestation(state, beacon_block_root, committee, slot, index,
    validator_index, cache)

func makeFullAttestations*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest, slot: Slot,
    cache: var StateCache,
    flags: UpdateFlags = {}): seq[phase0.Attestation] =
  # Create attestations in which the full committee participates for each shard
  # that should be attested to during a particular slot
  let committees_per_slot = get_committee_count_per_slot(
    state, slot.epoch, cache)
  for committee_index in get_committee_indices(committees_per_slot):
    let
      committee = get_beacon_committee(state, slot, committee_index, cache)
      data = makeAttestationData(state, slot, committee_index, beacon_block_root)

    doAssert committee.len() >= 1
    var attestation = phase0.Attestation(
      aggregation_bits: CommitteeValidatorsBits.init(committee.len),
      data: data)
    for i in 0..<committee.len:
      attestation.aggregation_bits.setBit(i)

    attestation.signature = makeAttestationSig(
        state.fork,
        state.genesis_validators_root, data, committee,
        attestation.aggregation_bits)

    result.add attestation

func makeElectraAttestation(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    committee: seq[ValidatorIndex], slot: Slot, committee_index: CommitteeIndex,
    validator_index: ValidatorIndex, cache: var StateCache,
    flags: UpdateFlags = {}): electra.Attestation =
  let
    index_in_committee = committee.find(validator_index)
    data = makeAttestationData(state, slot, CommitteeIndex(0), beacon_block_root)

  doAssert index_in_committee != -1, "find_beacon_committee should guarantee this"

  var aggregation_bits = ElectraCommitteeValidatorsBits.init(committee.len)
  aggregation_bits.setBit index_in_committee

  let sig = if skipBlsValidation in flags:
    ValidatorSig()
  else:
    makeAttestationSig(
      state.fork,
      state.genesis_validators_root,
      data, committee, aggregation_bits)

  var committee_bits: AttestationCommitteeBits
  committee_bits[int committee_index] = true

  electra.Attestation(
    data: data,
    committee_bits: committee_bits,
    aggregation_bits: aggregation_bits,
    signature: sig
  )

func makeElectraAttestation*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, cache: var StateCache): electra.Attestation =
  let (committee, slot, index) =
    find_beacon_committee(state, validator_index, cache)
  makeElectraAttestation(state, beacon_block_root, committee, slot, index,
    validator_index, cache)

func makeFullElectraAttestations*(
    state: ForkedHashedBeaconState, beacon_block_root: Eth2Digest, slot: Slot,
    cache: var StateCache,
    flags: UpdateFlags = {}): seq[electra.Attestation] =
  # Create attestations in which the full committee participates for each shard
  # that should be attested to during a particular slot
  let committees_per_slot = get_committee_count_per_slot(
    state, slot.epoch, cache)
  for committee_index in get_committee_indices(committees_per_slot):
    let
      committee = get_beacon_committee(state, slot, committee_index, cache)
      data = makeAttestationData(state, slot, CommitteeIndex(0), beacon_block_root)
    var
      committee_bits: AttestationCommitteeBits

    committee_bits[int committee_index] = true

    doAssert committee.len() >= 1
    var attestation = electra.Attestation(
      aggregation_bits: ElectraCommitteeValidatorsBits.init(committee.len),
      committee_bits: committee_bits,
      data: data)
    for i in 0..<committee.len:
      attestation.aggregation_bits.setBit(i)

    attestation.signature = makeAttestationSig(
        state.fork,
        state.genesis_validators_root, data, committee,
        attestation.aggregation_bits)

    result.add attestation

func makeElectraIndexedAttestation*(
    state: ForkedHashedBeaconState, slot: Slot,
    validator_indices: openArray[uint64],
    beacon_block_root: Eth2Digest): electra.IndexedAttestation =
  let
    data = AttestationData(slot: slot, beacon_block_root: beacon_block_root)
    committee = validator_indices.mapIt(it.ValidatorIndex)
  var bits = ElectraCommitteeValidatorsBits.init(committee.len)
  for i in 0 ..< committee.len:
    bits.setBit i
  electra.IndexedAttestation(
    data: data,
    attesting_indices:
      List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT](
        @validator_indices),
    signature: makeAttestationSig(
      state.fork, state.genesis_validators_root, data, committee, bits))

func makeElectraAttesterSlashing*(
    state: ForkedHashedBeaconState,
    validator_indices: openArray[uint64], slot: Slot,
    root_a = Eth2Digest.fromHex(
      "0x0100000000000000000000000000000000000000000000000000000000000000"),
    root_b = Eth2Digest.fromHex(
      "0x0200000000000000000000000000000000000000000000000000000000000000")
): electra.AttesterSlashing =
  electra.AttesterSlashing(
    attestation_1: makeElectraIndexedAttestation(
      state, slot, validator_indices, root_a),
    attestation_2: makeElectraIndexedAttestation(
      state, slot, validator_indices, root_b))

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
      state.fork
    genesis_validators_root =
      state.genesis_validators_root
    slot =
      state.slot
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
            for i, validator in state.validators:
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
        if attested and state.kind < ConsensusFork.Electra:
          makeFullAttestations(
            state[], parent_root, state[].slot, cache)
        else:
          @[]
      electraAttestations =
        if attested and state.kind >= ConsensusFork.Electra:
          makeFullElectraAttestations(
            state[], parent_root, state[].slot, cache)
        else:
          @[]
      stateEth1 = state[].eth1_data
      stateDepositIndex = state[].eth1_deposit_index
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
      electraAttestations = electraAttestations,
      deposits = deposits,
      sync_aggregate = sync_aggregate,
      graffiti = graffiti,
      cfg = cfg)

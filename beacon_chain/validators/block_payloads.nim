# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Utilities and logic for getting an execution payload from either engine or
## builder and then creating a block from the best one.
##
## In general, we ask both engine and builder for a payload then compare how
## much each would pay, selecting the most profitable one to proceed with.
##
## Once we have a payload, a consensus block is constructed that gets applied
## to a state to check that it's correct and to compute the post-state-root
## which is part of the block.
##
## With the state root in hand, we can go on to either sign the block when
## running a beacon validator or pass it to the validator client that will sign
## and then pass it back.
##
## Either way, signing is out of scope for this module.

# Implementation notes
#
# * Even though they are in theory redundant, we sometimes pass both
#   `consensusFork` and fork-specific `Forky*` types - this makes spelling the
#   return type slightly easier
# * Where support for earlier forks is dropped, we still accurately maintain
#   the fork where the feature was introduced - ie although at the time of
#   Deneb will have Deneb in their fork check.

{.push raises: [], gcsafe.}

import
  chronicles,
  results,
  ../consensus_object_pools/
    [attestation_pool, consensus_manager, payload_attestation_pool],
  ../spec/[forks, state_transition],
  ../spec/mev/rest_mev_calls,
  ../beacon_node

from eth/async_utils import awaitWithTimeout
from ../spec/beaconstate import get_expected_withdrawals

export results

type
  BuilderBidResult[BB: ForkyBuilderBid] = Result[BB, string]

  EngineBlock[BB: ForkyBeaconBlock, FB: ForkyBlobsBundle] = object
    blck*: BB
    executionValue*: Wei
    consensusValue*: UInt256
    blobsBundle*: FB

  BuilderBlock[BBB: ForkyBlindedBeaconBlock] = object
    blck*: BBB
    executionValue*: Wei
    consensusValue*: UInt256

  EngineBlockResult[BB: ForkyBeaconBlock, FB: ForkyBlobsBundle] =
    Result[EngineBlock[BB, FB], string]
  BuilderBlockResult[BBB: ForkyBlindedBeaconBlock] = Result[BuilderBlock[BBB], string]

  EngineBid*[EPS: ForkyExecutionPayloadForSigning] = object
    eps*: EPS
    execution_requests*: ExecutionRequests

  Bids[consensusFork: static ConsensusFork] = object
    engineBid*: Opt[EngineBid[consensusFork.ExecutionPayloadForSigning]]
    builderBid*: Opt[consensusFork.BuilderBid]

  BoostFactorKind {.pure.} = enum
    Local
    Builder

  BoostFactor* = object
    case kind: BoostFactorKind
    of BoostFactorKind.Local:
      value8: uint8
    of BoostFactorKind.Builder:
      value64: uint64

func init*(t: typedesc[BoostFactor], value: uint8): BoostFactor =
  BoostFactor(kind: BoostFactorKind.Local, value8: value)

func init*(t: typedesc[BoostFactor], value: uint64): BoostFactor =
  BoostFactor(kind: BoostFactorKind.Builder, value64: value)

func builderBetterBid(
    localBlockValueBoost: uint8, builderValue: UInt256, engineValue: Wei
): bool =
  # Scale down to ensure no overflows; if lower few bits would have been
  # otherwise decisive, was close enough not to matter. Calibrate to let
  # uint8-range percentages avoid overflowing.
  const scalingBits = 10
  static:
    doAssert 1 shl scalingBits > high(typeof(localBlockValueBoost)).uint16 + 100
  let
    scaledBuilderValue = (builderValue shr scalingBits) * 100
    scaledEngineValue = engineValue shr scalingBits
  scaledBuilderValue > scaledEngineValue * (localBlockValueBoost.uint16 + 100).u256

func builderBetterBid*(
    builderBoostFactor: uint64, builderValue: UInt256, engineValue: Wei
): bool =
  if builderBoostFactor == 0'u64:
    false
  elif builderBoostFactor == 100'u64:
    builderValue >= engineValue
  elif builderBoostFactor == high(uint64):
    true
  else:
    let
      multiplier = builderBoostFactor.u256
      multipledBuilderValue = builderValue * multiplier
      overflow =
        if builderValue == UInt256.zero:
          false
        else:
          builderValue != multipledBuilderValue div multiplier

    if overflow:
      # In case of overflow we will use `builderValue`.
      true
    else:
      (multipledBuilderValue div 100) >= engineValue

func builderBetterBid(
    boostFactor: BoostFactor, builderValue: UInt256, engineValue: Wei
): bool =
  case boostFactor.kind
  of BoostFactorKind.Local:
    builderBetterBid(boostFactor.value8, builderValue, engineValue)
  of BoostFactorKind.Builder:
    builderBetterBid(boostFactor.value64, builderValue, engineValue)

func decodePayloadRequests(
    eps:
      electra.ExecutionPayloadForSigning | fulu.ExecutionPayloadForSigning |
      gloas.ExecutionPayloadForSigning
): Result[ExecutionRequests, string] =
  try:
    var
      execution_requests_buffer: ExecutionRequests
      prev_type: Opt[byte]

    # TODO why aren't these decoded already?
    for request_type_and_payload in eps.executionRequests:
      if request_type_and_payload.len < 2:
        return err("Execution layer request too short")

      let request_type = request_type_and_payload[0]
      if prev_type.isSome:
        if request_type < prev_type.get:
          return err("Execution layer request types not sorted")
        if request_type == prev_type.get:
          return err("Execution layer request types duplicated")
      prev_type.ok request_type

      template request_payload(): untyped =
        request_type_and_payload.toOpenArray(1, request_type_and_payload.len - 1)

      case request_type_and_payload[0]
      of DEPOSIT_REQUEST_TYPE:
        execution_requests_buffer.deposits = SSZ.decode(
          request_payload, List[DepositRequest, Limit MAX_DEPOSIT_REQUESTS_PER_PAYLOAD]
        )
      of WITHDRAWAL_REQUEST_TYPE:
        execution_requests_buffer.withdrawals = SSZ.decode(
          request_payload,
          List[WithdrawalRequest, Limit MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD],
        )
      of CONSOLIDATION_REQUEST_TYPE:
        execution_requests_buffer.consolidations = SSZ.decode(
          request_payload,
          List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD],
        )
      else:
        return err("Execution layer invalid request type")

    ok execution_requests_buffer
  except SerializationError:
    err("Failed to deserialize execution requests")

func makeExecutionPayloadEnvelope*(
    eps: gloas.ExecutionPayloadForSigning,
    execution_requests: ExecutionRequests,
    beacon_block_root: Eth2Digest,
): gloas.ExecutionPayloadEnvelope =
  gloas.ExecutionPayloadEnvelope(
    payload: eps.executionPayload,
    execution_requests: execution_requests,
    builder_index: BUILDER_INDEX_SELF_BUILD,
    beacon_block_root: beacon_block_root,
  )

func makeSignedExecutionPayloadBid(
    T: type gloas.SignedExecutionPayloadBid,
    executionPayload: gloas.ExecutionPayload,
    execution_requests: ExecutionRequests,
    blob_kzg_commitments: KzgCommitments,
    parentBlockRoot: Eth2Digest,
    slot: Slot,
    _: BitArray[int INCLUSION_LIST_COMMITTEE_SIZE],
): gloas.SignedExecutionPayloadBid =
  let bid = gloas.ExecutionPayloadBid(
    parent_block_hash: executionPayload.parent_hash,
    parent_block_root: parentBlockRoot,
    block_hash: executionPayload.block_hash,
    prev_randao: executionPayload.prev_randao,
    fee_recipient: executionPayload.fee_recipient,
    gas_limit: executionPayload.gas_limit,
    builder_index: BUILDER_INDEX_SELF_BUILD,
    slot: slot,
    value: 0.Gwei,
    execution_payment: 0.Gwei,
    blob_kzg_commitments: blob_kzg_commitments,
    execution_requests_root: hash_tree_root(execution_requests),
  )
  gloas.SignedExecutionPayloadBid(
    message: bid,
    signature: ValidatorSig.infinity()
  )

func makeSignedExecutionPayloadBid(
    T: type heze.SignedExecutionPayloadBid,
    executionPayload: gloas.ExecutionPayload,
    execution_requests: ExecutionRequests,
    blob_kzg_commitments: KzgCommitments,
    parentBlockRoot: Eth2Digest,
    slot: Slot,
    inclusion_list_bits: BitArray[int INCLUSION_LIST_COMMITTEE_SIZE],
): heze.SignedExecutionPayloadBid =
  let bid = heze.ExecutionPayloadBid(
    parent_block_hash: executionPayload.parent_hash,
    parent_block_root: parentBlockRoot,
    block_hash: executionPayload.block_hash,
    prev_randao: executionPayload.prev_randao,
    fee_recipient: executionPayload.fee_recipient,
    gas_limit: executionPayload.gas_limit,
    builder_index: BUILDER_INDEX_SELF_BUILD,
    slot: slot,
    value: 0.Gwei,
    execution_payment: 0.Gwei,
    blob_kzg_commitments: blob_kzg_commitments,
    execution_requests_root: hash_tree_root(execution_requests),
    inclusion_list_bits: inclusion_list_bits)
  heze.SignedExecutionPayloadBid(
    message: bid,
    signature: ValidatorSig.infinity())

proc makeEngineBlock*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    state: var ForkyHashedBeaconState,
    cache: var StateCache,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
    eps: ForkyExecutionPayloadForSigning,
    execution_requests: ExecutionRequests,
): EngineBlockResult[consensusFork.BeaconBlock, consensusFork.BlobsBundle] =
  let
    attestations = node.attestationPool[].getAttestationsForBlock(state, cache)
    exits = node.validatorChangePool[].getBeaconBlockValidatorChanges(
      node.dag.cfg, state.data
    )
    sync_aggregate = node.syncCommitteeMsgPool[].produceSyncAggregate(head.bid, slot)
    signed_execution_payload_bid =
      when consensusFork >= ConsensusFork.Heze:
        debugHezeComment "set inclusion_list_bits with FOCIL information"
        makeSignedExecutionPayloadBid(
          heze.SignedExecutionPayloadBid,
          eps.executionPayload, execution_requests, eps.kzg_commitments,
          state.latest_block_root, slot,
          static(default(BitArray[int INCLUSION_LIST_COMMITTEE_SIZE])))
      elif consensusFork == ConsensusFork.Gloas:
        makeSignedExecutionPayloadBid(
          gloas.SignedExecutionPayloadBid,
          eps.executionPayload, execution_requests, eps.kzg_commitments,
          state.latest_block_root, slot,
          static(default(BitArray[int INCLUSION_LIST_COMMITTEE_SIZE])))
      else:
        default(gloas.SignedExecutionPayloadBid)
    payload_attestations =
      when consensusFork >= ConsensusFork.Gloas:
        node.payloadAttestationPool[].getPayloadAttestationsForBlock(
          slot, state.latest_block_root)
      else:
        default(seq[PayloadAttestation])
    # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/validator.md#parent-execution-requests
    parent_execution_requests =
      when consensusFork >= ConsensusFork.Gloas:
        block:
          let envelope = node.dag.db.getExecutionPayloadEnvelope(
              state.latest_block_root).valueOr:
            default(TrustedSignedExecutionPayloadEnvelope)
          envelope.message.execution_requests
      else:
        default(ExecutionRequests)

    blockAndRewards = makeBeaconBlockWithRewards(
      node.dag.cfg,
      consensusFork,
      state,
      cache,
      validator_index,
      randao_reveal,
      Eth1Data(),
      graffiti,
      attestations,
      @[],
      exits,
      sync_aggregate,
      eps.executionPayload,
      verificationFlags = {},
      eps.kzg_commitments,
      execution_requests,
      signed_execution_payload_bid,
      payload_attestations,
      parent_execution_requests,
    ).valueOr:
      # This is almost certainly a bug, but it's complex enough that there's a
      # small risk it might happen even when most proposals succeed - thus we
      # log instead of asserting
      warn "Cannot create block for proposal",
        slot, head = shortLog(head), error = error
      return err($error)

  ok EngineBlock[consensusFork.BeaconBlock, consensusFork.BlobsBundle](
    blck: blockAndRewards.blck,
    executionValue: eps.blockValue,
    consensusValue: blockAndRewards.rewards.blockConsensusValue(),
    blobsBundle: eps.blobsBundle,
  )

proc getExecutionPayload*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    head: BlockRef,
    proposalState: ref ForkedHashedBeaconState,
    validator_index: ValidatorIndex,
    validator_pubkey: ValidatorPubKey,
): Future[Opt[EngineBid[consensusFork.ExecutionPayloadForSigning]]] {.
    async: (raises: [CancelledError])
.} =
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/validator.md#executionpayload

  template forkyState(): untyped =
    proposalState[].forky(consensusFork)

  let
    slot = forkyState.data.slot
    feeRecipient = node.consensusManager[].getFeeRecipient(
      validator_pubkey, Opt.some(validator_index), slot.epoch
    )
    beaconHead = node.attestationPool[].getBeaconHead(head)
    executionHead =
      when consensusFork >= ConsensusFork.Gloas:
        debugGloasComment "this empirically matches a current testnet gloas provider behavior"
        # `latest_execution_payload_bid` is empty until the first Gloas block's
        # processed; for a Gloas genesis chain, a genesis state generator seeds
        # `latest_block_hash` with the EL genesis block hash.
        if forkyState.data.latest_execution_payload_bid.block_hash.isZero():
          forkyState.data.latest_block_hash
        else:
          forkyState.data.latest_execution_payload_bid.block_hash
      elif consensusFork >= ConsensusFork.Bellatrix:
        forkyState.data.latest_execution_payload_header.block_hash
      else:
        ZERO_HASH
    latestSafe = beaconHead.safeExecutionBlockHash
    latestFinalized = beaconHead.finalizedExecutionBlockHash
    timestamp = node.dag.timeParams.compute_timestamp_at_slot(forkyState.data, slot)
    prevRandao = get_randao_mix(forkyState.data, slot.epoch)
    withdrawals =
      when consensusFork >= ConsensusFork.Gloas:
        get_expected_withdrawals(forkyState.data).withdrawals
      elif consensusFork >= ConsensusFork.Capella:
        get_expected_withdrawals(forkyState.data)
      else:
        @[]

  # Block production happens rarely enough that we want to log request/response
  # as they become ready
  info "Requesting engine payload",
    slot,
    beaconHead = shortLog(beaconHead.blck),
    executionHead = shortLog(executionHead),
    latestSafe = shortLog(latestSafe),
    latestFinalized = shortLog(latestFinalized),
    feeRecipient = $feeRecipient

  type PayloadType = consensusFork.ExecutionPayloadForSigning
  let
    state = ForkchoiceStateV1.init(executionHead, latestSafe, latestFinalized)
    attributes =
      when consensusFork >= ConsensusFork.Gloas:
        PayloadAttributesV4.init(
          timestamp, prevRandao, feeRecipient, withdrawals,
          beaconHead.blck.bid.root, slot,
        )
      else:
        PayloadAttributesV3.init(
          timestamp, prevRandao, feeRecipient, withdrawals,
          beaconHead.blck.bid.root
        )
    eps = await(node.elManager.getPayload(PayloadType, state, attributes)).valueOr:
      if not proposalState[].is_merge_transition_complete():
        # Pre-merge, an all-zeroes execution payload is used and there are no
        # requests, so default is fine here
        return Opt.some(static(default(EngineBid[PayloadType])))
      return Opt.none(EngineBid[PayloadType])

    requests = decodePayloadRequests(eps).valueOr:
      warn "Cannot decode payload requests from engine", slot, err = error
      return Opt.none(EngineBid[PayloadType])

  # TODO errors are logged in elmanager but unlike most other things, we want
  #      success log here for getting the payload since they are so rare - it
  #      would be nice to have a more structured approach to the logging here
  info "Received engine payload",
    slot, value = shortLog(eps.blockValue), payload = shortLog(eps.executionPayload)

  ok EngineBid[PayloadType](eps: eps, execution_requests: requests)

proc getSignedBuilderBid(
    payloadBuilderClient: RestClientRef,
    SBB: type ForkySignedBuilderBid,
    slot: Slot,
    executionBlockHash: Eth2Digest,
    pubkey: ValidatorPubKey,
): Future[Result[SBB, string]] {.async: (raises: [CancelledError]).} =
  let response =
    try:
      await payloadBuilderClient.getHeader(slot, executionBlockHash, pubkey)
    except RestDecodingError as exc:
      return err("getSignedBuilderBid REST decoding error: " & exc.msg)
    except RestError as exc:
      return err("getSignedBuilderBid REST error: " & exc.msg)

  const httpOk = 200
  if response.status != httpOk:
    return err "getSignedBuilderBid: HTTP error " & $response.status

  let res = decodeBytesJsonOrSsz(
    DataVersionEnclosedObject[SBB],
    response.data,
    response.contentType,
    response.headers.getString("eth-consensus-version"),
  ).valueOr:
    return err(
      "Unable to decode blinded header: " & $error & " with HTTP status " &
        $response.status & ", Content-Type " & $response.contentType & " and content " &
        $response.data
    )
  ok res.data

proc getBuilderBid(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    payloadBuilderClient: RestClientRef,
    slot: Slot,
    executionBlockHash: Eth2Digest,
    pubkey: ValidatorPubKey,
    expected_withdrawals_root: Eth2Digest,
): Future[BuilderBidResult[consensusFork.BuilderBid]] {.
    async: (raises: [CancelledError])
.} =
  # Block production happens rarely enough that we want to log the request
  info "Requesting builder bid",
    slot, executionHead = shortLog(executionBlockHash), pubkey = shortLog(pubkey)

  let
    sbbRes = awaitWithTimeout(
      payloadBuilderClient.getSignedBuilderBid(
        consensusFork.SignedBuilderBid, slot, executionBlockHash, pubkey
      ),
      BUILDER_PROPOSAL_DELAY_TOLERANCE,
    ):
      return err "Timeout obtaining blinded header from builder"
    sbb = ?sbbRes

  if not verify_builder_signature(
    node.dag.cfg.GENESIS_FORK_VERSION, sbb.message, sbb.message.pubkey, sbb.signature
  ):
    return err "Builder signature verification failed"

  info "Received builder bid",
    slot, value = sbb.message.value, payload = shortLog(sbb.message.header)

  ok sbb.message

proc getBuilderBid(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    payloadBuilderClient: RestClientRef,
    head: BlockRef,
    slot: Slot,
    pubkey: ValidatorPubKey,
    expected_withdrawals_root: Eth2Digest,
): Future[BuilderBidResult[consensusFork.BuilderBid]] {.
    async: (raises: [CancelledError])
.} =
  let executionBlockHash = node.dag.loadExecutionBlockHash(head).valueOr:
    # With checkpoint sync, the checkpoint block may be unavailable,
    # and it could already be the parent of the new block before backfill.
    # Fallback to EL, hopefully the block is available on the local path.
    warn "Failed to load parent execution block hash, skipping block builder",
      slot, head = shortLog(head)
    return err("loadExecutionBlockHash failed")

  await node.getBuilderBid(
    consensusFork, payloadBuilderClient, slot, executionBlockHash, pubkey,
    expected_withdrawals_root,
  )

proc makeBuilderBlock*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    state: var ForkyHashedBeaconState,
    cache: var StateCache,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
    builderBid: ForkyBuilderBid,
): BuilderBlockResult[consensusFork.BlindedBeaconBlock] =
  let
    attestations = node.attestationPool[].getAttestationsForBlock(state, cache)
    exits = node.validatorChangePool[].getBeaconBlockValidatorChanges(
      node.dag.cfg, state.data
    )
    sync_aggregate = node.syncCommitteeMsgPool[].produceSyncAggregate(head.bid, slot)

  debugGloasComment "make signed bid from engine payload"
  let
    signed_execution_payload_bid = default(gloas.SignedExecutionPayloadBid)
    payload_attestations =
      when consensusFork >= ConsensusFork.Gloas:
        node.payloadAttestationPool[].getPayloadAttestationsForBlock(
          slot, state.latest_block_root)
      else:
        newSeq[PayloadAttestation]()

    blockAndRewards = makeBeaconBlockWithRewards(
      node.dag.cfg,
      consensusFork,
      state,
      cache,
      validator_index,
      randao_reveal,
      Eth1Data(),
      graffiti,
      attestations,
      @[],
      exits,
      sync_aggregate,
      builderBid.header,
      verificationFlags = {},
      builderBid.blob_kzg_commitments,
      builderBid.execution_requests,
      signed_execution_payload_bid,
      payload_attestations,
    ).valueOr:
      # This is almost certainly a bug, but it's complex enough that there's a
      # small risk it might happen even when most proposals succeed - thus we
      # log instead of asserting
      warn "Cannot create block for proposal",
        slot, head = shortLog(head), error = error
      return err($error)

  ok BuilderBlock[consensusFork.BlindedBeaconBlock](
    blck: blockAndRewards.blck,
    executionValue: builderBid.value,
    consensusValue: blockAndRewards.rewards.blockConsensusValue(),
  )

func isExcludedTestnet(cfg: RuntimeConfig): bool =
  ## Ensure that builder API testing can still occur in certain circumstances.
  cfg.DEPOSIT_CHAIN_ID == cfg.DEPOSIT_NETWORK_ID and cfg.DEPOSIT_CHAIN_ID == 560048'u64
    # Hoodi

proc collectBids*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    payloadBuilderClient: RestClientRef,
    validator_pubkey: ValidatorPubKey,
    validator_index: ValidatorIndex,
    head: BlockRef,
    slot: Slot,
    proposalState: ref ForkedHashedBeaconState,
): Future[Bids[consensusFork]] {.async: (raises: [CancelledError]).} =
  type BB = consensusFork.BuilderBid

  let
    usePayloadBuilder =
      if not payloadBuilderClient.isNil:
        withState(node.dag.headState):
          # Head slot, not proposal slot, matters here
          # TODO it might make some sense to allow use of builder API if local
          # EL fails -- i.e. it would change priorities, so any block from the
          # execution layer client would override builder API. But it seems an
          # odd requirement to produce no block at all in those conditions.
          (node.dag.cfg.isExcludedTestnet) or (
            not livenessFailsafeInEffect(
              forkyState.data.block_roots.data, forkyState.data.slot
            )
          )
      else:
        false

    builderBidFut =
      if usePayloadBuilder:
        debugGloasComment "handle different get_expected_withdrawals types"
        let
          withdrawals = List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](
            when consensusFork == ConsensusFork.Gloas:
              get_expected_withdrawals(proposalState[].forky(consensusFork).data)[0]
            else:
              get_expected_withdrawals(proposalState[].forky(consensusFork).data)
          )
          expected_withdrawals_root = hash_tree_root(withdrawals)
        node.getBuilderBid(
          consensusFork, payloadBuilderClient, head, slot, validator_pubkey,
          expected_withdrawals_root,
        )
      else:
        nil

    enginePayloadFut = node.getExecutionPayload(
      consensusFork, head, proposalState, validator_index, validator_pubkey
    )

  # getBuilderBid times out after BUILDER_PROPOSAL_DELAY_TOLERANCE, with 1 more
  # second for remote validators. getExecutionPayload times out after
  # 1 second.
  let
    builderBid =
      if builderBidFut.isNil:
        if not payloadBuilderClient.isNil:
          notice "Liveness failsafe in effect, ignoring builder"
        Opt.none(BB)
      else:
        let res = await builderBidFut
        if res.isErr:
          notice "Payload builder error",
            slot,
            head = shortLog(head),
            validator = shortLog(validator_pubkey),
            err = res.error
          Opt.none(BB)
        else:
          Opt.some res[]

    enginePayload = await enginePayloadFut

  Bids[consensusFork](engineBid: enginePayload, builderBid: builderBid)

func useBuilderPayload*(bids: Bids, boostFactor: BoostFactor): bool =
  bids.builderBid.isSome() and (
    bids.engineBid.isNone() or
    builderBetterBid(
      boostFactor, bids.builderBid.value().value, bids.engineBid.value().eps.blockValue
    )
  )

proc makeMaybeBlindedBeaconBlockForHeadAndSlot*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
    builderBoostFactor: uint64,
): Future[
    Result[
      tuple[
        blck: consensusFork.MaybeBlindedBeaconBlock,
        executionValue, consensusValue: UInt256,
      ],
      string,
    ]
] {.async: (raises: [CancelledError]).} =
  let
    proposerKey = node.dag.validatorKey(validator_index).get().toPubKey()

    payloadBuilderClient =
      node.getPayloadBuilderClient(validator_index.distinctBase).valueOr(nil)

    cache = new StateCache
    state = node.dag.getProposalState(head, slot, cache[]).valueOr:
      return err("Proposal state is not available")

    bids = await node.collectBids(
      consensusFork, payloadBuilderClient, proposerKey, validator_index, head, slot,
      state,
    )

    useBuilderPayload = bids.useBuilderPayload(BoostFactor.init(builderBoostFactor))

  if payloadBuilderClient != nil:
    info "Payload selected",
      builderBoostFactor,
      useBuilderPayload,
      hasBuilderPayload = bids.builderBid.isSome(),
      hasEnginePayload = bids.engineBid.isSome()

  if useBuilderPayload:
    let builderBlock = node.makeBuilderBlock(
      consensusFork,
      state[].forky(consensusFork),
      cache[],
      validator_index,
      randao_reveal,
      graffiti,
      head,
      slot,
      bids.builderBid.value(),
    ).valueOr:
      return err("Failed to create builder block")

    return ok(
      (
        blck: consensusFork.MaybeBlindedBeaconBlock(
          isBlinded: true, blindedData: builderBlock.blck
        ),
        executionValue: builderBlock.executionValue,
        consensusValue: builderBlock.consensusValue,
      )
    )

  if bids.engineBid.isNone:
    return err("Engine payload is not available")

  let engineBlock = ?node.makeEngineBlock(
    consensusFork,
    state[].forky(consensusFork),
    cache[],
    validator_index,
    randao_reveal,
    graffiti,
    head,
    slot,
    bids.engineBid[].eps,
    bids.engineBid[].execution_requests,
  )

  ok(
    (
      blck: consensusFork.MaybeBlindedBeaconBlock(
        isBlinded: false,
        data: consensusFork.BlockContents(
          `block`: engineBlock.blck,
          kzg_proofs: engineBlock.blobsBundle.proofs,
          blobs: engineBlock.blobsBundle.blobs,
        ),
      ),
      executionValue: engineBlock.executionValue,
      consensusValue: engineBlock.consensusValue,
    )
  )

# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
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
{.push raises: [], gcsafe.}

import
  stew/assign2,
  chronicles,
  results,
  ../consensus_object_pools/[attestation_pool, consensus_manager],
  ../spec/[forks, state_transition],
  ../spec/mev/rest_mev_calls,
  ../beacon_node

from eth/async_utils import awaitWithTimeout
from ../spec/beaconstate import get_expected_withdrawals
from ./message_router_mev import copyFields, getFieldNames

export results

type
  BuilderBidResult[BB: ForkyBuilderBid] = Result[BB, string]

  EngineBlock[BB: ForkyBeaconBlock] = object
    blck*: BB
    executionValue*: Wei
    consensusValue*: UInt256
    blobsBundle*: deneb.BlobsBundle

  BuilderBlock[BBB: ForkyBlindedBeaconBlock] = object
    blck*: BBB
    executionValue*: Wei
    consensusValue*: UInt256

  EngineBlockResult[BB: ForkyBeaconBlock] = Result[EngineBlock[BB], string]
  BuilderBlockResult[BBB: ForkyBlindedBeaconBlock] = Result[BuilderBlock[BBB], string]

  Bids[consensusFork: static ConsensusFork] = object
    engineBid*: Opt[consensusFork.ExecutionPayloadForSigning]
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

template toBlockContents(
    engineBlock: EngineBlock, consensusFork: static ConsensusFork
): untyped =
  when consensusFork >= ConsensusFork.Deneb:
    consensusFork.BlockContents(
      `block`: engineBlock.blck,
      kzg_proofs: engineBlock.blobsBundle.proofs,
      blobs: engineBlock.blobsBundle.blobs,
    )
  else:
    engineBlock.blck

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

proc makeEngineBlock*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    state: var ForkedHashedBeaconState,
    cache: var StateCache,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
    execution_payload: Opt[ForkyExecutionPayloadForSigning],

    # These parameters are for the builder API
    transactions_root = Opt.none(Eth2Digest),
    execution_payload_root = Opt.none(Eth2Digest),
    withdrawals_root = Opt.none(Eth2Digest),
    kzg_commitments = Opt.none(KzgCommitments),
    builder_execution_requests = Opt.none(ExecutionRequests),
): EngineBlockResult[consensusFork.BeaconBlock] =
  type BeaconBlockType = consensusFork.BeaconBlock

  let
    payload =
      if execution_payload.isNone():
        if state.is_merge_transition_complete():
          return err("Execution payload required post merge")
        default(typeof(execution_payload[]))
      elif withdrawals_root.isSome:
        # Builder API

        # In Capella, only get withdrawals root from relay.
        # The execution payload will be small enough to be safe to copy because
        # it won't have transactions (it's blinded)
        var modified_execution_payload = execution_payload[]
        when consensusFork >= ConsensusFork.Capella:
          let withdrawals = List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](
            get_expected_withdrawals(state.forky(consensusFork).data)
          )
          if hash_tree_root(withdrawals) != withdrawals_root.get:
            # If engine API returned a block, will use that
            return err("Builder relay provided incorrect withdrawals root")
          # Otherwise, the state transition function notices that there are
          # too few withdrawals.
          assign(modified_execution_payload.executionPayload.withdrawals, withdrawals)

        modified_execution_payload
      else:
        execution_payload[]
    attestations =
      when consensusFork >= ConsensusFork.Electra:
        node.attestationPool[].getElectraAttestationsForBlock(state, cache)
      else:
        node.attestationPool[].getAttestationsForBlock(state, cache)
    exits = node.validatorChangePool[].getBeaconBlockValidatorChanges(
      node.dag.cfg, state.forky(consensusFork).data
    )
    execution_requests = builder_execution_requests.valueOr:
      when consensusFork >= ConsensusFork.Electra:
        # Don't want un-decoded SSZ going any further/deeper
        var
          execution_requests_buffer: ExecutionRequests
          prev_type: Opt[byte]
        try:
          for request_type_and_payload in payload.executionRequests:
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
                request_payload,
                List[DepositRequest, Limit MAX_DEPOSIT_REQUESTS_PER_PAYLOAD],
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
        except CatchableError:
          return err("Unable to deserialize execution layer requests")

        execution_requests_buffer
      else:
        default(ExecutionRequests) # won't be used by block builder

    blockAndRewards = makeBeaconBlockWithRewards(
      node.dag.cfg,
      state,
      validator_index,
      randao_reveal,
      Eth1Data(),
      graffiti,
      attestations,
      @[],
      exits,
      node.syncCommitteeMsgPool[].produceSyncAggregate(head.bid, slot),
      payload,
      noRollback, # Temporary state - no need for rollback
      cache,
      verificationFlags = {},
      transactions_root = transactions_root,
      execution_payload_root = execution_payload_root,
      kzg_commitments = kzg_commitments,
      execution_requests = execution_requests,
    ).valueOr:
      # This is almost certainly a bug, but it's complex enough that there's a
      # small risk it might happen even when most proposals succeed - thus we
      # log instead of asserting
      warn "Cannot create block for proposal",
        slot, head = shortLog(head), error = error
      return err($error)

  ok EngineBlock[BeaconBlockType](
    blck: blockAndRewards.blck.forky(consensusFork),
    executionValue: payload.blockValue,
    consensusValue: blockAndRewards.rewards.blockConsensusValue(),
    blobsBundle:
      when consensusFork >= ConsensusFork.Deneb:
        payload.blobsBundle
      else:
        default(deneb.BlobsBundle),
  )

proc getExecutionPayload*(
    node: BeaconNode,
    PayloadType: type ForkyExecutionPayloadForSigning,
    head: BlockRef,
    proposalState: ref ForkedHashedBeaconState,
    validator_index: ValidatorIndex,
    validator_pubkey: ValidatorPubKey,
): Future[Opt[PayloadType]] {.async: (raises: [CancelledError]).} =
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/validator.md#executionpayload

  let
    slot = withState(proposalState[]):
      forkyState.data.slot
    feeRecipient = node.consensusManager[].getFeeRecipient(
      validator_pubkey, Opt.some(validator_index), slot.epoch
    )
    beaconHead = node.attestationPool[].getBeaconHead(head)
    executionHead = withState(proposalState[]):
      when consensusFork >= ConsensusFork.Bellatrix:
        forkyState.data.latest_execution_payload_header.block_hash
      else:
        (static(default(Eth2Digest)))
    latestSafe = beaconHead.safeExecutionBlockHash
    latestFinalized = beaconHead.finalizedExecutionBlockHash
    timestamp = withState(proposalState[]):
      compute_timestamp_at_slot(forkyState.data, forkyState.data.slot)
    random = withState(proposalState[]):
      get_randao_mix(forkyState.data, get_current_epoch(forkyState.data))
    withdrawals = withState(proposalState[]):
      when consensusFork >= ConsensusFork.Capella:
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

  let payload = await node.elManager.getPayload(
    PayloadType, beaconHead.blck.bid.root, executionHead, latestSafe, latestFinalized,
    timestamp, random, feeRecipient, withdrawals,
  )

  if payload.isSome():
    # TODO errors are logged in elmanager but unlike most other things, we want
    #      success log here for getting the payload since they are so rare - it
    #      would be nice to have a more structured approach to the logging here
    info "Received engine payload",
      slot,
      value = shortLog(payload[].blockValue),
      payload = shortLog(payload[].executionPayload)

  payload

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
    consensusFork, payloadBuilderClient, slot, executionBlockHash, pubkey
  )

func constructBlindedBeaconBlock(
    blck: ForkyBeaconBlock, builderBid: ForkyBuilderBid
): auto =
  # Leaves signature field default, to be filled in by caller
  const
    blckFields = getFieldNames(typeof(blck))
    blckBodyFields = getFieldNames(typeof(blck.body))

  var blindedBlock: type(blck).kind.BlindedBeaconBlock

  # https://github.com/ethereum/builder-specs/blob/v0.4.0/specs/bellatrix/validator.md#block-proposal
  copyFields(blindedBlock, blck, blckFields)
  copyFields(blindedBlock.body, blck.body, blckBodyFields)
  assign(blindedBlock.body.execution_payload_header, builderBid.header)
  assign(blindedBlock.body.blob_kzg_commitments, builderBid.blob_kzg_commitments)
  assign(blindedBlock.body.execution_requests, builderBid.execution_requests)

  blindedBlock

proc makeBuilderBlock*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    state: var ForkedHashedBeaconState,
    cache: var StateCache,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
    builderBid: ForkyBuilderBid,
): BuilderBlockResult[consensusFork.BlindedBeaconBlock] =
  # When creating this block, need to ensure it uses the MEV-provided execution
  # payload, both to avoid repeated calls to network services and to ensure the
  # consistency of this block (e.g., its state root being correct). Since block
  # processing does not work directly using blinded blocks, fix up transactions
  # root after running the state transition function on an otherwise equivalent
  # non-blinded block without transactions.
  #
  # This doesn't have withdrawals, which each node has regardless of engine or
  # builder API. makeEngineBlock fills it in later.

  var shimExecutionPayload: consensusFork.ExecutionPayloadForSigning
  copyFields(
    shimExecutionPayload.executionPayload,
    builderBid.header,
    getFieldNames(typeof(builderBid.header)),
  )

  let fakeBlock =
    ?node.makeEngineBlock(
      consensusFork,
      state,
      cache,
      validator_index,
      randao_reveal,
      graffiti,
      head,
      slot,
      execution_payload = Opt.some shimExecutionPayload,
      transactions_root = Opt.some builderBid.header.transactions_root,
      execution_payload_root = Opt.some hash_tree_root(builderBid.header),
      withdrawals_root = Opt.some builderBid.header.withdrawals_root,
      kzg_commitments = Opt.some builderBid.blob_kzg_commitments,
      builder_execution_requests = Opt.some builderBid.execution_requests,
    )

  ok BuilderBlock[consensusFork.BlindedBeaconBlock](
    blck: constructBlindedBeaconBlock(fakeBlock.blck, builderBid),
    executionValue: fakeBlock.executionValue,
    consensusValue: fakeBlock.consensusValue,
  )

func isExcludedTestnet(cfg: RuntimeConfig): bool =
  ## Ensure that builder API testing can still occur in certain circumstances.
  cfg.DEPOSIT_CHAIN_ID == cfg.DEPOSIT_NETWORK_ID and
    cfg.DEPOSIT_CHAIN_ID in [17000'u64, 560048] # Holesky and Hoodi, respectively

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
  type
    EPS = consensusFork.ExecutionPayloadForSigning
    BB = consensusFork.BuilderBid

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
        node.getBuilderBid(
          consensusFork, payloadBuilderClient, head, slot, validator_pubkey
        )
      else:
        nil

    enginePayloadFut = node.getExecutionPayload(
      EPS, head, proposalState, validator_index, validator_pubkey
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

proc useBuilderPayload*(bids: Bids, boostFactor: BoostFactor): bool =
  bids.builderBid.isSome() and (
    bids.engineBid.isNone() or
    builderBetterBid(
      boostFactor, bids.builderBid.value().value, bids.engineBid.value().blockValue
    )
  )

proc makeMaybeBlindedBeaconBlockForHeadAndSlotImpl[ResultType](
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
    builderBoostFactor: uint64,
): Future[ResultType] {.async: (raises: [CancelledError]).} =
  let
    proposerKey = node.dag.validatorKey(validator_index).get().toPubKey()

    payloadBuilderClient =
      node.getPayloadBuilderClient(validator_index.distinctBase).valueOr(nil)

    cache = new StateCache
    state = node.dag.getProposalState(head, slot, cache[]).valueOr:
      return ResultType.err("Proposal state is not available")

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
      state[],
      cache[],
      validator_index,
      randao_reveal,
      graffiti,
      head,
      slot,
      bids.builderBid.value(),
    ).valueOr:
      return ResultType.err("Failed to create builder block")

    return ResultType.ok(
      (
        blck: consensusFork.MaybeBlindedBeaconBlock(
          isBlinded: true, blindedData: builderBlock.blck
        ),
        executionValue: builderBlock.executionValue,
        consensusValue: builderBlock.consensusValue,
      )
    )

  let engineBlock =
    ?node.makeEngineBlock(
      consensusFork,
      state[],
      cache[],
      validator_index,
      randao_reveal,
      graffiti,
      head,
      slot,
      bids.engineBid,
    )

  ResultType.ok(
    (
      blck: consensusFork.MaybeBlindedBeaconBlock(
        isBlinded: false, data: engineBlock.toBlockContents(consensusFork)
      ),
      executionValue: engineBlock.executionValue,
      consensusValue: engineBlock.consensusValue,
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
): auto =
  type ResultType = Result[
    tuple[
      blck: consensusFork.MaybeBlindedBeaconBlock,
      executionValue: UInt256,
      consensusValue: UInt256,
    ],
    string,
  ]

  makeMaybeBlindedBeaconBlockForHeadAndSlotImpl[ResultType](
    node, consensusFork, validator_index, randao_reveal, graffiti, head, slot,
    builderBoostFactor,
  )

proc makeBeaconBlockForHeadAndSlotImpl[ResultType](
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
): Future[ResultType] {.async: (raises: [CancelledError]).} =
  type EPS = consensusFork.ExecutionPayloadForSigning

  let
    proposerKey = node.dag.validatorKey(validator_index).get().toPubKey()
    cache = new StateCache
    # TODO move the creation of this proposal state away from the hot path
    state = node.dag.getProposalState(head, slot, cache[]).valueOr:
      return ResultType.err("Proposal state is not available")
    enginePayload =
      await node.getExecutionPayload(EPS, head, state, validator_index, proposerKey)

    engineBlock =
      ?node.makeEngineBlock(
        consensusFork,
        state[],
        cache[],
        validator_index,
        randao_reveal,
        graffiti,
        head,
        slot,
        enginePayload,
      )

  ResultType.ok(
    (
      blck: engineBlock.toBlockContents(consensusFork),
      executionValue: engineBlock.executionValue,
      consensusValue: engineBlock.consensusValue,
    )
  )

proc makeBeaconBlockForHeadAndSlot*(
    node: BeaconNode,
    consensusFork: static ConsensusFork,
    validator_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    graffiti: GraffitiBytes,
    head: BlockRef,
    slot: Slot,
): auto =
  type ResultType = Result[
    tuple[
      blck: consensusFork.BlockContents,
      executionValue: UInt256,
      consensusValue: UInt256,
    ],
    string,
  ]

  makeBeaconBlockForHeadAndSlotImpl[ResultType](
    node, consensusFork, validator_index, randao_reveal, graffiti, head, slot
  )

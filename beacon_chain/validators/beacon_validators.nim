{.push raises: [].}

import
  std/[os, tables],

  stew/[assign2, byteutils],
  chronos,
  ../spec/[
    eth2_merkleization, forks, helpers, signatures, state_transition,
    validator],
  ../consensus_object_pools/blockchain_dag,
  ".."/[conf, beacon_clock, beacon_node],
  "."/[
    keystore_management, slashing_protection, validator_pool]

from std/sequtils import mapIt
import ".."/spec/mev/[capella_mev, deneb_mev]

type
  EngineBid = tuple[
    blck: ForkedBeaconBlock,
    blockValue: Wei,
    blobsBundleOpt: Opt[BlobsBundle]]

  BuilderBid[SBBB] = tuple[
    blindedBlckPart: SBBB, blockValue: UInt256]

  ForkedBlockResult =
    Result[EngineBid, string]
  BlindedBlockResult[SBBB] =
    Result[BuilderBid[SBBB], string]

  Bids[SBBB] = object
    engineBid: Opt[EngineBid]
    builderBid: Opt[BuilderBid[SBBB]]

proc getValidator*(validators: auto,
                   pubkey: ValidatorPubKey): Opt[ValidatorAndIndex] =
  let idx = validators.findIt(it.pubkey == pubkey)
  if idx == -1:
    # We allow adding a validator even if its key is not in the state registry:
    # it might be that the deposit for this validator has not yet been processed
    Opt.none ValidatorAndIndex
  else:
    Opt.some ValidatorAndIndex(index: ValidatorIndex(idx),
                               validator: validators[idx])

proc addValidators*(node: BeaconNode) {.async: (raises: [CancelledError]).} =
  for keystore in listLoadableKeystores(node.config, node.keystoreCache):
    let
      data = withState(node.genesisState[]):
        getValidator(forkyState.data.validators.asSeq(), keystore.pubkey)
      v = node.attachedValidators[].addValidator(keystore, default(Eth1Address), 30000000)
    v.updateValidator(data)

proc getValidator*(node: BeaconNode, idx: ValidatorIndex): Opt[AttachedValidator] =
  let key = ? node.dag.validatorKey(idx)
  node.attachedValidators[].getValidator(key.toPubKey())

proc getValidatorForDuties*(
    node: BeaconNode, idx: ValidatorIndex, slot: Slot,
    slashingSafe = false): Opt[AttachedValidator] =
  # TODO mock this
  let key = ? node.dag.validatorKey(idx)

  node.attachedValidators[].getValidatorForDuties(
    key.toPubKey(), slot, slashingSafe)

proc isSynced*(node: BeaconNode, head: BlockRef): bool = true

type
  BlockProposalEth1Data* = object
    vote*: Eth1Data
    deposits*: seq[Deposit]
    hasMissingDeposits*: bool

proc getBlockProposalEth1Data(node: BeaconNode,
                              state: ForkedHashedBeaconState):
                              BlockProposalEth1Data = default(BlockProposalEth1Data)

from ../spec/beaconstate import get_expected_withdrawals
import chronicles

proc makeBeaconBlockForHeadAndSlot(
    PayloadType: type ForkyExecutionPayloadForSigning,
    node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot,

    # These parameters are for the builder API
    execution_payload: Opt[PayloadType],
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest],
    withdrawals_root: Opt[Eth2Digest],
    kzg_commitments: Opt[KzgCommitments]):
    Future[ForkedBlockResult] {.async: (raises: [CancelledError]).} =
  var cache = StateCache()

  let
    # The clearance state already typically sits at the right slot per
    # `advanceClearanceState`
    # TODO mock this
    maybeState = node.dag.getProposalState(head, slot, cache)

  if maybeState.isErr:
    return err($maybeState.error)

  let
    state = maybeState.get
    payloadFut =
      if execution_payload.isSome:
        # Builder API

        # In Capella, only get withdrawals root from relay.
        # The execution payload will be small enough to be safe to copy because
        # it won't have transactions (it's blinded)
        var modified_execution_payload = execution_payload
        withState(state[]):
          when  consensusFork >= ConsensusFork.Capella and
                PayloadType.kind >= ConsensusFork.Capella:
            let withdrawals = List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD](
              get_expected_withdrawals(forkyState.data))
            if  withdrawals_root.isNone or
                hash_tree_root(withdrawals) != withdrawals_root.get:
              # If engine API returned a block, will use that
              return err("Builder relay provided incorrect withdrawals root")
            # Otherwise, the state transition function notices that there are
            # too few withdrawals.
            assign(modified_execution_payload.get.executionPayload.withdrawals,
                   withdrawals)

        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "given-payload")
        fut.complete(modified_execution_payload)
        fut
      elif slot.epoch < node.cfg.BELLATRIX_FORK_EPOCH or
           not state[].is_merge_transition_complete:
        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "empty-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut
      else:
        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "empty-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut

    eth1Proposal = node.getBlockProposalEth1Data(state[])

  if false:
    warn ""
    return err("Eth1 deposits not available")

  let
    # TODO workaround for https://github.com/arnetheduck/nim-results/issues/34
    payloadRes = await payloadFut
    payload = payloadRes.valueOr:
      warn "Unable to get execution payload. Skipping block proposal",
        slot, validator_index
      return err("Unable to get execution payload")

  let blck = makeBeaconBlock(
      node.cfg,
      state[],
      validator_index,
      randao_reveal,
      eth1Proposal.vote,
      graffiti,
      @[],
      eth1Proposal.deposits,
      default(BeaconBlockValidatorChanges),
      SyncAggregate.init(),
      payload,
      noRollback, # Temporary state - no need for rollback
      cache,
      verificationFlags = {},
      transactions_root = transactions_root,
      execution_payload_root = execution_payload_root,
      kzg_commitments = kzg_commitments).mapErr do (error: cstring) -> string:
    warn "Cannot create block for proposal",
      slot, head = shortLog(head), error
    $error

  var blobsBundleOpt = Opt.none(BlobsBundle)
  when payload is deneb.ExecutionPayloadForSigning:
    blobsBundleOpt = Opt.some(payload.blobsBundle)
  return if blck.isOk:
    ok((blck.get, payload.blockValue, blobsBundleOpt))
  else:
    err(blck.error)

proc makeBeaconBlockForHeadAndSlot(
    PayloadType: type ForkyExecutionPayloadForSigning, node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot):
    Future[ForkedBlockResult] =
  return makeBeaconBlockForHeadAndSlot(
    PayloadType, node, randao_reveal, validator_index, graffiti, head, slot,
    execution_payload = Opt.none(PayloadType),
    transactions_root = Opt.none(Eth2Digest),
    execution_payload_root = Opt.none(Eth2Digest),
    withdrawals_root = Opt.none(Eth2Digest),
    kzg_commitments = Opt.none(KzgCommitments))

proc blindedBlockCheckSlashingAndSign[
    T:
      capella_mev.SignedBlindedBeaconBlock |
      deneb_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, slot: Slot, validator: AttachedValidator,
    validator_index: ValidatorIndex, nonsignedBlindedBlock: T):
    Future[Result[T, string]] {.async: (raises: [CancelledError]).} =
  return err "foo"

proc getUnsignedBlindedBeaconBlock[
    T: capella_mev.SignedBlindedBeaconBlock |
       deneb_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, slot: Slot,
    validator_index: ValidatorIndex, forkedBlock: ForkedBeaconBlock,
    executionPayloadHeader: capella.ExecutionPayloadHeader |
                            deneb_mev.BlindedExecutionPayloadAndBlobsBundle):
    Result[T, string] =
  withBlck(forkedBlock):
    return err("")

proc getBlindedBlockParts[
    EPH: capella.ExecutionPayloadHeader |
         deneb_mev.BlindedExecutionPayloadAndBlobsBundle](
    node: BeaconNode, head: BlockRef,
    pubkey: ValidatorPubKey, slot: Slot, randao: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes):
    Future[Result[(EPH, UInt256, ForkedBeaconBlock), string]]
    {.async: (raises: [CancelledError]).} =
  return err("")

proc getBuilderBid[
    SBBB: capella_mev.SignedBlindedBeaconBlock |
          deneb_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, head: BlockRef,
    validator_pubkey: ValidatorPubKey, slot: Slot, randao: ValidatorSig,
    validator_index: ValidatorIndex):
    Future[BlindedBlockResult[SBBB]] {.async: (raises: [CancelledError]).} =
  when SBBB is capella_mev.SignedBlindedBeaconBlock:
    type EPH = capella.ExecutionPayloadHeader
  elif SBBB is deneb_mev.SignedBlindedBeaconBlock:
    type EPH = deneb_mev.BlindedExecutionPayloadAndBlobsBundle
  else:
    static: doAssert false

  let blindedBlockParts = await getBlindedBlockParts[EPH](
    node, head, validator_pubkey, slot, randao,
    validator_index, default(GraffitiBytes))
  if blindedBlockParts.isErr:
    # Not signed yet, fine to try to fall back on EL
    return err blindedBlockParts.error()

  let (executionPayloadHeader, bidValue, forkedBlck) = blindedBlockParts.get

  let unsignedBlindedBlock = getUnsignedBlindedBeaconBlock[SBBB](
    node, slot, validator_index, forkedBlck, executionPayloadHeader)

  if unsignedBlindedBlock.isErr:
    return err unsignedBlindedBlock.error()

  return ok (unsignedBlindedBlock.get, bidValue)

proc proposeBlockMEV(
    node: BeaconNode,
    blindedBlock: capella_mev.SignedBlindedBeaconBlock |
                  deneb_mev.SignedBlindedBeaconBlock):
    Future[Result[BlockRef, string]] {.async: (raises: [CancelledError]).} =
  err "foo"

proc collectBids(
    SBBB: typedesc, EPS: typedesc, node: BeaconNode,
    validator_pubkey: ValidatorPubKey,
    validator_index: ValidatorIndex, graffitiBytes: GraffitiBytes,
    head: BlockRef, slot: Slot,
    randao: ValidatorSig): Future[Bids[SBBB]] {.async: (raises: [CancelledError]).} =
  let usePayloadBuilder = false

  let
    payloadBuilderBidFut =
      if usePayloadBuilder:
        when not (EPS is bellatrix.ExecutionPayloadForSigning):
          getBuilderBid[SBBB](node, head,
                              validator_pubkey, slot, randao, validator_index)
        else:
          let fut = newFuture[BlindedBlockResult[SBBB]]("builder-bid")
          fut.complete(BlindedBlockResult[SBBB].err(
            "Bellatrix Builder API unsupported"))
          fut
      else:
        let fut = newFuture[BlindedBlockResult[SBBB]]("builder-bid")
        fut.complete(BlindedBlockResult[SBBB].err(
          "either payload builder disabled or liveness failsafe active"))
        fut
    engineBlockFut = makeBeaconBlockForHeadAndSlot(
      EPS, node, randao, validator_index, graffitiBytes, head, slot)

  await allFutures(payloadBuilderBidFut, engineBlockFut)
  doAssert payloadBuilderBidFut.finished and engineBlockFut.finished

  let builderBid =
    if payloadBuilderBidFut.completed:
      if payloadBuilderBidFut.value().isOk:
        Opt.some(payloadBuilderBidFut.value().value())
      elif usePayloadBuilder:
        notice "Payload builder error",
          slot, head = shortLog(head), validator = shortLog(validator_pubkey),
          err = payloadBuilderBidFut.value().error()
        Opt.none(BuilderBid[SBBB])
      else:
        # Effectively the same case, but without the log message
        Opt.none(BuilderBid[SBBB])
    else:
      notice "Payload builder bid request failed",
        slot, head = shortLog(head), validator = shortLog(validator_pubkey),
        err = payloadBuilderBidFut.error.msg
      Opt.none(BuilderBid[SBBB])

  let engineBid =
    if engineBlockFut.completed:
      if engineBlockFut.value.isOk:
        Opt.some(engineBlockFut.value().value())
      else:
        notice "Engine block building error",
          slot, head = shortLog(head), validator = shortLog(validator_pubkey),
          err = engineBlockFut.value.error()
        Opt.none(EngineBid)
    else:
      notice "Engine block building failed",
        slot, head = shortLog(head), validator = shortLog(validator_pubkey),
        err = engineBlockFut.error.msg
      Opt.none(EngineBid)

  Bids[SBBB](
    engineBid: engineBid,
    builderBid: builderBid)

func builderBetterBid(
    localBlockValueBoost: uint8, builderValue: UInt256, engineValue: Wei): bool =
  const scalingBits = 10
  static: doAssert 1 shl scalingBits >
    high(typeof(localBlockValueBoost)).uint16 + 100
  let
    scaledBuilderValue = (builderValue shr scalingBits) * 100
    scaledEngineValue = engineValue shr scalingBits
  scaledBuilderValue >
    scaledEngineValue * (localBlockValueBoost.uint16 + 100).u256

proc proposeBlockAux(
    SBBB: typedesc, EPS: typedesc, node: BeaconNode,
    validator: AttachedValidator, validator_pubkey: ValidatorPubKey, validator_index: ValidatorIndex,
    head: BlockRef, slot: Slot, randao: ValidatorSig, fork: Fork,
    genesis_validators_root: Eth2Digest,
    localBlockValueBoost: uint8): Future[BlockRef] {.async: (raises: [CancelledError]).} =
  let
    collectedBids = await collectBids(
      SBBB, EPS, node, validator_pubkey, validator_index,
      default(GraffitiBytes), head, slot, randao)

    useBuilderBlock =
      if collectedBids.builderBid.isSome():
        collectedBids.engineBid.isNone() or builderBetterBid(
          localBlockValueBoost,
          collectedBids.builderBid.value().blockValue,
          collectedBids.engineBid.value().blockValue)
      else:
        if not collectedBids.engineBid.isSome():
          return head   # errors logged in router
        false

  if collectedBids.engineBid.isSome():
    # Three cases: builder bid expected and absent, builder bid expected and
    # present, and builder bid not expected.
    if collectedBids.builderBid.isSome():
      info "Compared engine and builder block bids",
        localBlockValueBoost,
        useBuilderBlock,
        builderBlockValue =
          toString(collectedBids.builderBid.value().blockValue, 10),
        engineBlockValue =
          toString(collectedBids.engineBid.value().blockValue, 10)
    else:
      info "Did not receive expected builder bid; using engine block",
        engineBlockValue = collectedBids.engineBid.value().blockValue
  else:
    # Similar three cases: builder bid expected and absent, builder bid
    # expected and present, and builder bid not expected. However, only
    # the second is worth logging, because the other two result in this
    # block being missed altogether, and with details logged elsewhere.
    if collectedBids.builderBid.isSome:
      info "Did not receive expected engine bid; using builder block",
        builderBlockValue =
          collectedBids.builderBid.value().blockValue

  if useBuilderBlock:
    let
      blindedBlock = (await blindedBlockCheckSlashingAndSign(
        node, slot, validator, validator_index,
        collectedBids.builderBid.value().blindedBlckPart)).valueOr:
          return head
      maybeUnblindedBlock = await proposeBlockMEV(
        node, blindedBlock)

    return maybeUnblindedBlock.valueOr:
      warn "Blinded block proposal incomplete",
        head = shortLog(head), slot, validator_index,
        validator = shortLog(validator),
        err = maybeUnblindedBlock.error,
        blindedBlck = shortLog(blindedBlock)
      return head

  let engineBid = collectedBids.engineBid.value()

  withBlck(engineBid.blck):
    let
      blockRoot = hash_tree_root(forkyBlck)
      signingRoot = compute_block_signing_root(
        fork, genesis_validators_root, slot, blockRoot)

      notSlashable = registerBlock(validator_index, validator_pubkey, slot, signingRoot)

    if notSlashable.isErr:
      warn "Slashing protection activated for block proposal",
        blockRoot = shortLog(blockRoot), blck = shortLog(forkyBlck),
        signingRoot = shortLog(signingRoot),
        validator = validator_pubkey,
        slot = slot,
        existingProposal = notSlashable.error
      return head

    let
      signature =
        block:
          let res = await getBlockSignature(
            fork, genesis_validators_root, slot, blockRoot, engineBid.blck)
          if res.isErr():
            warn "Unable to sign block",
                 validator = shortLog(validator), error_msg = res.error()
            return head
          res.get()
      signedBlock = consensusFork.SignedBeaconBlock(
        message: forkyBlck, signature: signature, root: blockRoot)
      blobsOpt =
        when consensusFork >= ConsensusFork.Deneb:
          template blobsBundle: untyped =
            engineBid.blobsBundleOpt.get
          Opt.some(signedBlock.create_blob_sidecars(
            blobsBundle.proofs, blobsBundle.blobs))
        else:
          Opt.none(seq[BlobSidecar])

    # BIG BUG SOURCE: The `let` below cannot be combined with the others above!
    # If combined, there are sometimes `SIGSEGV` during `test_keymanager_api`.
    # This has only been observed on macOS (aarch64) in Jenkins, not on GitHub.
    #
    # - macOS 14.2.1 (23C71)
    # - Xcode 15.1 (15C65)
    # - Nim v1.6.18 (a749a8b742bd0a4272c26a65517275db4720e58a)
    let
      newBlockRef = (
        # I don't ... think this is used in a significant way? but probably first thing
        await node.router.routeSignedBeaconBlock(signedBlock, blobsOpt, node.dag)
      ).valueOr:
        return head # Errors logged in router

    if newBlockRef.isNone():
      return head # Validation errors logged in router

    notice "Block proposed",
      blockRoot = shortLog(blockRoot), blck = shortLog(forkyBlck),
      signature = shortLog(signature), validator = shortLog(validator)

    return newBlockRef.get()

proc proposeBlock(node: BeaconNode,
                  validator: AttachedValidator,
                  validator_pubkey: ValidatorPubKey,
                  validator_index: ValidatorIndex,
                  head: BlockRef,
                  slot: Slot) {.async: (raises: [CancelledError]).} =
  if head.slot >= slot:
    # We should normally not have a head newer than the slot we're proposing for
    # but this can happen if block proposal is delayed
    warn "Skipping proposal, have newer head already",
      headSlot = shortLog(head.slot),
      headBlockRoot = shortLog(head.root),
      slot = shortLog(slot)
    return

  let
    fork = node.cfg.forkAtEpoch(slot.epoch)
    genesis_validators_root = getStateField(node.genesisState[], genesis_validators_root)
    randao = block:
      let res = await validator.getEpochSignature(
        fork, genesis_validators_root, slot.epoch)
      if res.isErr():
        warn "Unable to generate randao reveal",
             validator = shortLog(validator), error_msg = res.error()
        return
      res.get()

  template proposeBlockContinuation(type1, type2: untyped): auto =
    await proposeBlockAux(
      type1, type2, node, validator, validator_pubkey, validator_index, head, slot, randao, fork,
        genesis_validators_root, node.config.localBlockValueBoost)

  discard withConsensusFork(node.cfg.consensusForkAtEpoch(slot.epoch)):
    when consensusFork >= ConsensusFork.Electra:
      debugRaiseAssert "proposeBlock; fill in Electra support"
      default(BlockRef)
    elif consensusFork >= ConsensusFork.Capella:
      proposeBlockContinuation(
        consensusFork.SignedBlindedBeaconBlock,
        consensusFork.ExecutionPayloadForSigning)
    else:
      proposeBlockContinuation(
        capella_mev.SignedBlindedBeaconBlock,
        bellatrix.ExecutionPayloadForSigning)

proc handleProposal*(node: BeaconNode, head: BlockRef, slot: Slot) {.async: (raises: [CancelledError]).} =
  let
    # TODO actual DAG stuff, but if can get rid of rest, can probably fake it, it's a ValidatorIndex
    proposer = node.dag.getProposer(head, slot).valueOr:
      return
    validator = node.getValidatorForDuties(proposer, slot).valueOr:
      return

  await proposeBlock(node, validator, validator.pubkey, proposer, head, slot)

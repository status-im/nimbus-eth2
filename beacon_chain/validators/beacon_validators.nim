import
  std/os,
  chronos,
  ../spec/forks,
  ".."/[conf, beacon_node],
  "."/[
    slashing_protection]

import ../spec/[datatypes/base, crypto]
type
  ValidatorKind {.pure.} = enum
    Local, Remote
  AttachedValidator = ref object
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      discard
    of ValidatorKind.Remote:
      discard
    index: Opt[ValidatorIndex]
    validator: Opt[Validator]
  SignatureResult = Result[ValidatorSig, string]
func shortLog*(v: AttachedValidator): string =
  case v.kind
  of ValidatorKind.Local:
    ""
  of ValidatorKind.Remote:
    ""
proc getBlockSignature(): Future[SignatureResult]
                       {.async: (raises: [CancelledError]).} =
  SignatureResult.ok(default(ValidatorSig))
import ".."/spec/mev/capella_mev
from ".."/spec/datatypes/deneb import
  BlobSidecar, Blobs, BlobsBundle, KzgCommitments, shortLog

type
  EngineBid = tuple[
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

import ".."/consensus_object_pools/block_dag
let pk = ValidatorPubKey.fromHex("891c64850444b66331ef7888c907b4af71ab6b2c883affe2cebd15d6c3644ac7ce6af96334192efdf95a64bab8ea425a")[]
proc getValidatorForDuties*(
    node: BeaconNode, idx: ValidatorIndex, slot: Slot,
    slashingSafe = false): Opt[AttachedValidator] =
  when false:
    let key = ? validatorKey2(0.ValidatorIndex)

    node.attachedValidators[].getValidatorForDuties(
      key.toPubKey(), slot, slashingSafe)
  else:
    ok AttachedValidator(
      kind: ValidatorKind.Local,
      index: Opt.some 0.ValidatorIndex,
      validator: Opt.some Validator(pubkey: ValidatorPubKey.fromHex("891c64850444b66331ef7888c907b4af71ab6b2c883affe2cebd15d6c3644ac7ce6af96334192efdf95a64bab8ea425a")[]))

from ".."/spec/datatypes/capella import shortLog
proc makeBeaconBlock(): Result[phase0.BeaconBlock, cstring] = ok(default(phase0.BeaconBlock))

proc makeBeaconBlockForHeadAndSlot(
    PayloadType: type ForkyExecutionPayloadForSigning,
    node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot,
    execution_payload: Opt[PayloadType]):
    Future[ForkedBlockResult] {.async: (raises: [CancelledError]).} =
  var cache = StateCache()

  let maybeState = node.getProposalState(head, slot, cache)

  if maybeState.isErr:
    return err($maybeState.error)

  let
    state = maybeState.get
    payloadFut =
      if execution_payload.isSome:
        var modified_execution_payload = execution_payload
        withState(state[]):
          discard
        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "given-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut
      elif slot.epoch < node.cfg.BELLATRIX_FORK_EPOCH:
        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "empty-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut
      else:
        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "empty-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut

  if false:
    return err("Eth1 deposits not available")

  let
    payloadRes = await payloadFut
    payload = payloadRes.valueOr:
      return err("Unable to get execution payload")

  let blck = makeBeaconBlock().mapErr do (error: cstring) -> string:
    $error

  var blobsBundleOpt = Opt.none(BlobsBundle)
  when payload is deneb.ExecutionPayloadForSigning:
    blobsBundleOpt = Opt.some(payload.blobsBundle)
  return if blck.isOk:
    ok((payload.blockValue, blobsBundleOpt))
  else:
    err(blck.error)

proc makeBeaconBlockForHeadAndSlot(
    PayloadType: type ForkyExecutionPayloadForSigning, node: BeaconNode, randao_reveal: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes, head: BlockRef,
    slot: Slot):
    Future[ForkedBlockResult] =
  return makeBeaconBlockForHeadAndSlot(
    PayloadType, node, randao_reveal, validator_index, graffiti, head, slot,
    execution_payload = Opt.none(PayloadType))

proc blindedBlockCheckSlashingAndSign[
    T: capella_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, slot: Slot, validator: AttachedValidator,
    validator_index: ValidatorIndex, nonsignedBlindedBlock: T):
    Future[Result[T, string]] {.async: (raises: [CancelledError]).} =
  return err "foo"

proc getUnsignedBlindedBeaconBlock[
    T: capella_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, slot: Slot,
    validator_index: ValidatorIndex, forkedBlock: ForkedBeaconBlock,
    executionPayloadHeader: capella.ExecutionPayloadHeader):
    Result[T, string] =
  withBlck(forkedBlock):
    return err("")

proc getBlindedBlockParts[
    EPH: capella.ExecutionPayloadHeader](
    node: BeaconNode, head: BlockRef,
    pubkey: ValidatorPubKey, slot: Slot, randao: ValidatorSig,
    validator_index: ValidatorIndex, graffiti: GraffitiBytes):
    Future[Result[(EPH, UInt256, ForkedBeaconBlock), string]]
    {.async: (raises: [CancelledError]).} =
  return err("")

proc getBuilderBid[
    SBBB: capella_mev.SignedBlindedBeaconBlock](
    node: BeaconNode, head: BlockRef,
    validator_pubkey: ValidatorPubKey, slot: Slot, randao: ValidatorSig,
    validator_index: ValidatorIndex):
    Future[BlindedBlockResult[SBBB]] {.async: (raises: [CancelledError]).} =
  when SBBB is capella_mev.SignedBlindedBeaconBlock:
    type EPH = capella.ExecutionPayloadHeader
  else:
    static: doAssert false

  let blindedBlockParts = await getBlindedBlockParts[EPH](
    node, head, validator_pubkey, slot, randao,
    validator_index, default(GraffitiBytes))
  if blindedBlockParts.isErr:
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
                  capella_mev.SignedBlindedBeaconBlock):
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
        when false:
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
        echo "Payload builder error"
        Opt.none(BuilderBid[SBBB])
      else:
        # Effectively the same case, but without the log message
        Opt.none(BuilderBid[SBBB])
    else:
      echo "Payload builder bid request failed"
      Opt.none(BuilderBid[SBBB])

  let engineBid =
    if engineBlockFut.completed:
      if engineBlockFut.value.isOk:
        Opt.some(engineBlockFut.value().value())
      else:
        echo "Engine block building error"
        Opt.none(EngineBid)
    else:
      echo "Engine block building failed"
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

from ".."/spec/datatypes/bellatrix import shortLog
import chronicles
from ".."/spec/datatypes/electra import shortLog
proc proposeBlockAux(
    SBBB: typedesc, EPS: typedesc, node: BeaconNode,
    validator: AttachedValidator, validator_pubkey: ValidatorPubKey, validator_index: ValidatorIndex,
    head: BlockRef, slot: Slot, randao: ValidatorSig, fork: Fork,
    genesis_validators_root: Eth2Digest): Future[BlockRef] {.async: (raises: [CancelledError]).} =
  let
    collectedBids = await collectBids(
      SBBB, EPS, node, validator_pubkey, validator_index,
      default(GraffitiBytes), head, slot, randao)

    useBuilderBlock =
      if collectedBids.builderBid.isSome():
        collectedBids.engineBid.isNone() or builderBetterBid(
          0,
          collectedBids.builderBid.value().blockValue,
          collectedBids.engineBid.value().blockValue)
      else:
        if not collectedBids.engineBid.isSome():
          return head   # errors logged in router
        false

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
       foo = maybeUnblindedBlock.error
      return head

  let engineBid_blck = default(ForkedBeaconBlock)
  let engineBid = collectedBids.engineBid.value()

  withBlck(engineBid_blck):
    let
      blockRoot = default(Eth2Digest)
      signingRoot = default(Eth2Digest)

      notSlashable = registerBlock(validator_index, validator_pubkey, slot, signingRoot)

    if notSlashable.isErr:
      warn "Slashing protection activated for block proposal",
        blockRoot = shortLog(blockRoot),
        blck = shortLog(forkyBlck),
        signingRoot = shortLog(signingRoot),
        existingProposal = notSlashable.error
      return head

    let
      signature =
        block:
          let res = await getBlockSignature()
          if res.isErr():
            return head
          res.get()
      signedBlock = consensusFork.SignedBeaconBlock(
        signature: signature, root: blockRoot)
      blobsOpt =
        when consensusFork >= ConsensusFork.Deneb:
          Opt.some(default(seq[BlobSidecar]))
        else:
          Opt.none(seq[BlobSidecar])

    # - macOS 14.2.1 (23C71)
    # - Xcode 15.1 (15C65)
    let
      newBlockRef = (
        await node.router.routeSignedBeaconBlock(signedBlock, blobsOpt)
      ).valueOr:
        return head # Errors logged in router

    if newBlockRef.isNone():
      return head # Validation errors logged in router

    echo "foo 1"
    notice "Block proposed",
      blockRoot = shortLog(blockRoot)

    echo "foo 2"

    return newBlockRef.get()

proc proposeBlock*(node: BeaconNode,
                   head: BlockRef,
                   slot: Slot) {.async: (raises: [CancelledError]).} =
  let
    validator_pubkey = pk
    validator_index = 0.ValidatorIndex
    validator = node.getValidatorForDuties(validator_index, slot).valueOr:
      return

  let
    fork = node.cfg.forkAtEpoch(slot.epoch)
    genesis_validators_root = getStateField(node.genesisState[], genesis_validators_root)
    randao = default(ValidatorSig)

  template proposeBlockContinuation(type1, type2: untyped): auto =
    await proposeBlockAux(
      type1, type2, node, validator, validator_pubkey, validator_index, head, slot, randao, fork,
        genesis_validators_root)

  discard withConsensusFork(node.cfg.consensusForkAtEpoch(slot.epoch)):
    when consensusFork >= ConsensusFork.Capella:
      default(BlockRef)
    else:
      proposeBlockContinuation(
        capella_mev.SignedBlindedBeaconBlock,
        bellatrix.ExecutionPayloadForSigning)

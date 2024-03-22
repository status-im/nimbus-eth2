import
  std/os,
  chronos,
  ../spec/forks,
  ".."/conf,
  "."/[
    slashing_protection]

import ../spec/crypto
type
  Validator = object
    pubkey: ValidatorPubKey
  ValidatorKind {.pure.} = enum
    Local, Remote
  AttachedValidator = ref object
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      discard
    of ValidatorKind.Remote:
      discard
    index: Opt[int32]
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

import stint

type
  KzgProofs = seq[int]
  Blobs = seq[int]

  BlobsBundle = object
    proofs: KzgProofs
    blobs: Blobs

  EngineBid = tuple[
    blockValue: UInt256,
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
proc getValidatorForDuties(
    idx: int32, slot: uint64,
    slashingSafe = false): Opt[AttachedValidator] =
  ok AttachedValidator(
    kind: ValidatorKind.Local,
    index: Opt.some 0.int32,
    validator: Opt.some Validator(pubkey: ValidatorPubKey.fromHex("891c64850444b66331ef7888c907b4af71ab6b2c883affe2cebd15d6c3644ac7ce6af96334192efdf95a64bab8ea425a")[]))

proc makeBeaconBlock(): Result[Mock, cstring] = ok(default(Mock))

template assignClone[T: not ref](x: T): ref T =
  mixin assign
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

proc getProposalState(
    head: BlockRef, slot: uint64):
    Result[ref ForkedHashedBeaconState, cstring] =
  let state = assignClone(default(ForkedHashedBeaconState))
  ok state

proc makeBeaconBlockForHeadAndSlot(
    PayloadType: type ForkyExecutionPayloadForSigning,
    validator_index: int32, head: BlockRef,
    slot: uint64,
    execution_payload: Opt[PayloadType]):
    Future[ForkedBlockResult] {.async: (raises: [CancelledError]).} =
  let maybeState = getProposalState(head, slot)
  let consensusFork = ConsensusFork.Bellatrix
  if maybeState.isErr:
    return err($maybeState.error)

  let
    payloadFut =
      if execution_payload.isSome:
        withConsensusFork(consensusFork):
          discard
        let fut = Future[Opt[PayloadType]].Raising([CancelledError]).init(
          "given-payload")
        fut.complete(Opt.some(default(PayloadType)))
        fut
      elif slot < 0:
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
  return if blck.isOk:
    ok((0.u256, blobsBundleOpt))
  else:
    err(blck.error)

proc makeBeaconBlockForHeadAndSlot(
    PayloadType: type ForkyExecutionPayloadForSigning,
    validator_index: int32, head: BlockRef,
    slot: uint64):
    Future[ForkedBlockResult] =
  return makeBeaconBlockForHeadAndSlot(
    PayloadType, validator_index, head, slot,
    execution_payload = Opt.none(PayloadType))

proc blindedBlockCheckSlashingAndSign[
    T: int](
    slot: uint64, validator: AttachedValidator,
    validator_index: int32, nonsignedBlindedBlock: T):
    Future[Result[T, string]] {.async: (raises: [CancelledError]).} =
  return err "foo"

proc getUnsignedBlindedBeaconBlock[
    T: int](
    slot: uint64,
    validator_index: int32, forkedBlock: ForkedBeaconBlock):
    Result[T, string] =
  var fork = ConsensusFork.Altair
  withConsensusFork(fork):
    return err("")

proc getBlindedBlockParts[EPH](
    head: BlockRef,
    pubkey: ValidatorPubKey, slot: uint64,
    validator_index: int32):
    Future[Result[(UInt256, ForkedBeaconBlock), string]]
    {.async: (raises: [CancelledError]).} =
  return err("")

proc getBuilderBid[
    SBBB: int](
    head: BlockRef,
    validator_pubkey: ValidatorPubKey, slot: uint64,
    validator_index: int32):
    Future[BlindedBlockResult[SBBB]] {.async: (raises: [CancelledError]).} =
  when SBBB is int:
    type EPH = capella.ExecutionPayloadHeader
  else:
    static: doAssert false

  let blindedBlockParts = await getBlindedBlockParts[EPH](
    node, head, validator_pubkey, slot,
    validator_index, default(GraffitiBytes))
  if blindedBlockParts.isErr:
    return err blindedBlockParts.error()

  let (executionPayloadHeader, bidValue, forkedBlck) = blindedBlockParts.get

  let unsignedBlindedBlock = getUnsignedBlindedBeaconBlock[SBBB](
    slot, validator_index, forkedBlck, executionPayloadHeader)

  if unsignedBlindedBlock.isErr:
    return err unsignedBlindedBlock.error()

  return ok (unsignedBlindedBlock.get, bidValue)

proc proposeBlockMEV(
    blindedBlock: int |
                  int):
    Future[Result[BlockRef, string]] {.async: (raises: [CancelledError]).} =
  err "foo"

proc collectBids(
    SBBB: typedesc, EPS: typedesc,
    validator_pubkey: ValidatorPubKey,
    validator_index: int32,
    head: BlockRef, slot: uint64): Future[Bids[SBBB]] {.async: (raises: [CancelledError]).} =
  let usePayloadBuilder = false

  let
    payloadBuilderBidFut =
      if usePayloadBuilder:
        when false:
          getBuilderBid[SBBB](node, head,
                              validator_pubkey, slot, validator_index)
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
      EPS, validator_index, head, slot)

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
    localBlockValueBoost: uint8, builderValue: UInt256, engineValue: UInt256): bool =
  const scalingBits = 10
  static: doAssert 1 shl scalingBits >
    high(typeof(localBlockValueBoost)).uint16 + 100
  let
    scaledBuilderValue = (builderValue shr scalingBits) * 100
    scaledEngineValue = engineValue shr scalingBits
  scaledBuilderValue >
    scaledEngineValue * (localBlockValueBoost.uint16 + 100).u256

import chronicles
import
  stew/results

type
  BlobSidecar = int
  BlobSidecars = seq[ref BlobSidecar]
  VerifierError {.pure.} = enum
    Invalid
    MissingParent
    UnviableFork
    Duplicate

import ".."/spec/digest
func getBlockRef(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0)
  return ok(newRef)
proc addBlock(
    blck: ForkedSignedBeaconBlock,
    blobs: Opt[BlobSidecars], maybeFinalized = false,
    validationDur = Duration()): Future[Result[void, VerifierError]] {.async: (raises: [CancelledError]).} =
  return ok()
type RouteBlockResult = Result[Opt[BlockRef], string]
proc routeSignedBeaconBlock*(
    blck: ForkySignedBeaconBlock,
    blobsOpt: Opt[seq[BlobSidecar]]):
    Future[RouteBlockResult] {.async: (raises: [CancelledError]).} =
  block:
    when typeof(blck).kind >= ConsensusFork.Deneb:
      if blobsOpt.isSome:
        let blobs = blobsOpt.get()
        let kzgCommits = blck.message.body.blob_kzg_commitments.asSeq
        if blobs.len > 0 or kzgCommits.len > 0:
          if false:
            warn "blobs failed validation",
              blockRoot = shortLog(blck.root),
              blobs = shortLog(blobs),
              blck = shortLog(blck.message),
              signature = shortLog(blck.signature),
              msg = ""
            return err("")

  var blobRefs = Opt.none(BlobSidecars)
  let added = await addBlock(
    ForkedSignedBeaconBlock.init(blck), blobRefs)

  if added.isErr():
    return if added.error() != VerifierError.Duplicate:
      warn "Unable to add routed block to block pool"
      ok(Opt.none(BlockRef))
    else:
      # If it's duplicate, there's an existing BlockRef to return. The block
      # shouldn't be finalized already because that requires a couple epochs
      # before occurring, so only check non-finalized resolved blockrefs.
      if false:
        warn "Unable to add routed duplicate block to block pool"
      ok(Opt.none(BlockRef))


  let blockRef = getBlockRef(default(Eth2Digest))
  if blockRef.isErr:
    warn "Block finalised while waiting for block processor"
  ok(blockRef)
proc proposeBlockAux(
    SBBB: typedesc, EPS: typedesc,
    validator: AttachedValidator, validator_pubkey: ValidatorPubKey, validator_index: int32,
    head: BlockRef, slot: uint64): Future[BlockRef] {.async: (raises: [CancelledError]).} =
  let
    collectedBids = await collectBids(
      SBBB, EPS, validator_pubkey, validator_index,
      head, slot)

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
        slot, validator, validator_index,
        collectedBids.builderBid.value().blindedBlckPart)).valueOr:
          return head
      maybeUnblindedBlock = await proposeBlockMEV(
        blindedBlock)

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
        blck = default(Mock),
        signingRoot = shortLog(signingRoot),
        existingProposal = notSlashable.error
      return head

    discard block:
      let res = await getBlockSignature()
      if res.isErr():
        return head
      res.get()
    let
      signedBlock = Mock()
      blobsOpt =
        when consensusFork >= ConsensusFork.Deneb:
          Opt.some(default(seq[BlobSidecar]))
        else:
          Opt.none(seq[BlobSidecar])

    # - macOS 14.2.1 (23C71)
    # - Xcode 15.1 (15C65)
    let
      newBlockRef = (
        await routeSignedBeaconBlock(signedBlock, blobsOpt)
      ).valueOr:
        return head # Errors logged in router

    if newBlockRef.isNone():
      return head # Validation errors logged in router

    echo "foo 1"
    notice "Block proposed",
      blockRoot = shortLog(blockRoot)

    echo "foo 2"

    return newBlockRef.get()

proc proposeBlock*(head: BlockRef,
                   slot: uint64) {.async: (raises: [CancelledError]).} =
  let
    validator_pubkey = pk
    validator_index = 0.int32
    validator = getValidatorForDuties(validator_index, slot).valueOr:
      return

  let
    cf = ConsensusFork.Bellatrix

  discard withConsensusFork(cf):
    when consensusFork >= ConsensusFork.Capella:
      default(BlockRef)
    else:
      await proposeBlockAux(
        int, int, validator, validator_pubkey, validator_index, head, slot)

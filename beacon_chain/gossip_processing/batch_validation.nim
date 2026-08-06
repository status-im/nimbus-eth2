# beacon_chain
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[atomics, deques, sequtils],
  stew/ptrops,
  metrics,
  # Status
  chronicles, chronos,
  ../spec/signatures_batch,
  ../consensus_object_pools/[blockchain_dag, spec_cache]

export signatures_batch, blockchain_dag

logScope:
  topics = "batch_validation"

declareCounter batch_verification_batches,
  "Total number of batches processed"
declareCounter batch_verification_signatures,
  "Total number of verified signatures before aggregation"
declareCounter batch_verification_aggregates,
  "Total number of verified signatures after aggregation"
declareCounter batch_verification_batches_skipped,
  "Total number of batches skipped"

# Batched gossip validation
# ----------------------------------------------------------------
# Batching in the context of BLS means collecting the signatures of several
# messages and verifying them all at once - this can be done more efficiently
# than verifying each message one by one, but the downside is that we get an
# all-or-nothing response - in case of an invalid signature, we must re-check
# each message separately.
#
# In addition to batching, we also perform lazy aggregation:
#
# * batching speeds up the verification of multiple signatures over different
#   messages, by a decent amount
# * lazy aggregation speeds up the verification of multiple signatures over the
#   same message, by a lot
#
# Due to the nature of gossip validation in eth2, it is common for messages
# to arrive in bursts - because most traffic on the network is valid (honest
# nodes don't re-broadcast invalid traffic and dishonest nodes quickly get
# disconnected), valid messages by far make up the bulk of traffic.
#
# Further, traffic is divided into topics - on a single topic it will be
# highly likely that the same message appears over and over again, but with
# different signatures, as most validators have the same view of the network -
# at least 2/3 or we're in deep trouble :)

const
  BatchAttAccumTime = 10.milliseconds
    ## Amount of time spent accumulating signatures from the network before
    ## performing verification

  BatchedCryptoSize = 72
    ## Threshold for immediate trigger of batch verification.
    ## A balance between throughput and worst case latency.
    ## At least 6 so that the constant factors
    ## (RNG for blinding and Final Exponentiation)
    ## are amortized, but not too big as we need to redo checks one-by-one if
    ## one failed.
    ## The current value is based on experiments, where 72 gives an average
    ## batch size of ~30 signatures per batch, or 2.5 signatures per aggregate
    ## (meaning an average of 12 verifications per batch which on a raspberry
    ## should be doable in less than 30ms). In the same experiment, a value of
    ## 36 resulted in 17-18 signatures per batch and 1.7-1.9 signatures per
    ## aggregate - this node was running on mainnet with
    ## `--subscribe-all-subnets` turned on - typical nodes will see smaller
    ## batches.

  InflightVerifications = 2
    ## Maximum number of concurrent in-flight verifications

  InflightKzgVerifications = 2
    ## Maximum number of concurrent in-flight KZG verifications

type
  BatchResult* {.pure.} = enum
    Invalid # Invalid by default
    Valid
    Timeout

  FutureBatchResult = Future[BatchResult].Raising([])
  FutureTask = Future[void].Raising([])

  Eager = proc(): bool {.gcsafe, raises: [].}
    ## Callback that returns true if eager processing should be done to lower
    ## latency at the expense of spending more cycles validating things,
    ## creating a crude timesharing priority mechanism.

  BatchItem* = object
    sigset: SignatureSet
    fut: FutureBatchResult

  Batch* = object
    ## A batch represents up to BatchedCryptoSize non-aggregated signatures
    created: Moment
    multiSets: Table[array[32, byte], MultiSignatureSet]
    items: seq[BatchItem]

  VerifierItem = object
    verifier: ref BatchVerifier
    inflight: Future[void].Raising([])

  BatchCrypto* = object
    batches: Deque[ref Batch]
    eager: Eager
      ## Eager is used to enable eager processing of attestations when it's
      ## prudent to do so (instead of leaving the CPU for other, presumably more
      ## important work like block processing)

    taskpool: Taskpool
    rng: ref HmacDrbgContext
    timeParams: TimeParams

    verifiers: array[InflightVerifications, VerifierItem]
      ## Each batch verification reqires a separate verifier
    verifier: int

    kzgLimit: AsyncSemaphore
    pruneTime: Moment ## last time we had to prune something

    counts: tuple[signatures, batches, aggregates: int64]
      # `nim-metrics` library is a bit too slow to update on every batch, so
      # we accumulate here instead

    genesis_validators_root: Eth2Digest
      # Most scheduled checks require this immutable value, so don't require it
      # to be provided separately each time

    processor: Future[void].Raising([CancelledError])

    disp: DispatcherHandle
      # Cached thread-local dispatcher handle

  BatchTask = object
    ok: Atomic[bool]
    setsPtr: ptr UncheckedArray[SignatureSet]
    numSets: int
    secureRandomBytes: array[32, byte]
    taskpool: Taskpool
    cache: ptr BatchedBLSVerifierCache
    future: FutureTask
    disp: DispatcherHandle

  KzgTask = object
    ok: Atomic[bool]
    commitmentsPtr: ptr UncheckedArray[KzgCommitment]
    cellIndicesPtr: ptr UncheckedArray[CellIndex]
    cellsPtr: ptr UncheckedArray[KzgCell]
    proofsPtr: ptr UncheckedArray[KzgProof]
    numCells: int
    future: FutureTask
    disp: DispatcherHandle

proc new*(
    T: type BatchCrypto,
    rng: ref HmacDrbgContext,
    timeParams: TimeParams,
    eager: Eager,
    genesis_validators_root: Eth2Digest,
    taskpool: Taskpool,
): ref BatchCrypto =
  let res = (ref BatchCrypto)(
    taskpool: taskpool,
    rng: rng,
    timeParams: timeParams,
    eager: eager,
    genesis_validators_root: genesis_validators_root,
    pruneTime: Moment.now(),
    kzgLimit: newAsyncSemaphore(InflightKzgVerifications),
    disp: getThreadDispatcher().handle(),
  )
  for i in 0 ..< res.verifiers.len:
    res.verifiers[i] = VerifierItem(verifier: BatchVerifier.new(rng, taskpool))
  res

func full(batch: Batch): bool =
  batch.items.len() >= BatchedCryptoSize

func half(batch: Batch): bool =
  batch.items.len() >= (BatchedCryptoSize div 2)

proc complete(batchItem: var BatchItem, v: BatchResult) =
  batchItem.fut.complete(v)
  batchItem.fut = nil

proc complete(batchItem: var BatchItem, ok: bool) =
  batchItem.fut.complete(if ok: BatchResult.Valid else: BatchResult.Invalid)
  batchItem.fut = nil

proc skip(batch: var Batch) =
  for res in batch.items.mitems():
    res.complete(BatchResult.Timeout)

proc complete(batchCrypto: var BatchCrypto, batch: var Batch, ok: bool) =
  if ok:
    for res in batch.items.mitems():
      res.complete(BatchResult.Valid)
  else:
    # Batched verification failed meaning that some of the signature checks
    # failed, but we don't know which ones - check each signature separately
    # instead
    debug "batch crypto - failure, falling back",
      items = batch.items.len()

    for item in batch.items.mitems():
      item.complete(blsVerify item.sigset)

  batchCrypto.counts.batches += 1
  batchCrypto.counts.signatures += batch.items.len()
  batchCrypto.counts.aggregates += batch.multiSets.len()

  if batchCrypto.counts.batches >= 256:
    # Not too often, so as not to overwhelm our metrics
    batch_verification_batches.inc(batchCrypto.counts.batches)
    batch_verification_signatures.inc(batchCrypto.counts.signatures)
    batch_verification_aggregates.inc(batchCrypto.counts.aggregates)

    reset(batchCrypto.counts)

proc completeTask[Task](udata: pointer) {.nimcall, gcsafe, raises: [].} =
  ## Completion callback for batchVerifyTask - completes the future on
  ## the async thread via callSoon
  let task = cast[ptr Task](udata)
  let fut = move(task[].future)
  if not fut.finished():
    fut.complete()

proc batchVerifyTask(task: ptr BatchTask) {.nimcall.} =
  # Task suitable for running in taskpools - look, no GC!
  let
    tp = task[].taskpool
    ok = tp.spawn batchVerify(
      tp, task[].cache, task[].setsPtr, task[].numSets,
      addr task[].secureRandomBytes)

  task[].ok.store(sync ok)

  # Signal completion on the async thread via callSoon
  callSoon(task[].disp, completeTask[BatchTask], task)

proc spawnBatchVerifyTask(tp: Taskpool, task: ptr BatchTask) =
  # Inlining this `proc` leads to compilation problems on Nim 2.0
  # - Error: cannot generate destructor for generic type: Isolated
  # Workaround: Ensure that `tp.spawn` is not used within an `{.async.}` proc
  # Possibly related to: https://github.com/nim-lang/Nim/issues/22305
  tp.spawn batchVerifyTask(task)

proc kzgProofsTask(task: ptr KzgTask) {.nimcall.} =
  # Task suitable for running in taskpools - look, no GC!
  let ok = verifyCellKzgProofBatch(
    task[].commitmentsPtr.toOpenArray(0, task[].numCells - 1),
    task[].cellIndicesPtr.toOpenArray(0, task[].numCells - 1),
    task[].cellsPtr.toOpenArray(0, task[].numCells - 1),
    task[].proofsPtr.toOpenArray(0, task[].numCells - 1)).get(false)

  task[].ok.store(ok)

  # Signal completion on the async thread via callSoon
  callSoon(task[].disp, completeTask[KzgTask], task)

proc spawnKzgTask(tp: Taskpool, task: ptr KzgTask) =
  # Keep `tp.spawn` out of `{.async.}` procs - see `spawnBatchVerifyTask`
  tp.spawn kzgProofsTask(task)

func combine(
    multiSet: MultiSignatureSet,
    verifier: ref BatchVerifier): SignatureSet =
  var secureRandomBytes: array[32, byte]
  verifier[].rng[].generate(secureRandomBytes)
  multiSet.combine(secureRandomBytes)

func combineAll(
    multiSets: Table[array[32, byte], MultiSignatureSet],
    verifier: ref BatchVerifier): seq[SignatureSet] =
  var sigsets = newSeqOfCap[SignatureSet](multiSets.len)
  for multiSet in multiSets.values():
    sigsets.add multiSet.combine(verifier)
  sigsets

proc batchVerifyAsync(
    verifier: ref BatchVerifier, batch: ref Batch, disp: DispatcherHandle
): Future[bool] {.async: (raises: []).} =
  let sigsets = batch[].multiSets.combineAll(verifier)
  let future = FutureTask.init("batch_verify", {FutureFlag.OwnCancelSchedule})
  var task = BatchTask(
    setsPtr: makeUncheckedArray(baseAddr sigsets),
    numSets: sigsets.len,
    taskpool: verifier[].taskpool,
    cache: addr verifier[].sigVerifCache,
    future: future,
    disp: disp,
  )
  verifier[].rng[].generate(task.secureRandomBytes)

  # The loop below never cancels tasks, thus the `task` instace stays alive
  # until after the task is finished
  let taskPtr = addr task
  doAssert verifier[].taskpool.numThreads > 1,
    "Must have at least one separate thread for task pool"
  verifier[].taskpool.spawnBatchVerifyTask(taskPtr)

  await future

  # `sigsets` must be used after the `await` or it is freed on suspension
  # while the worker still reads it through `task.setsPtr`:
  # https://github.com/nim-lang/Nim/issues/26041
  discard sigsets

  task.ok.load()

proc processBatch(
    batchCrypto: ref BatchCrypto, batch: ref Batch, verifier: ref BatchVerifier
) {.async: (raises: []).} =
  let numSets = batch[].multiSets.len

  if numSets == 0:
    # Nothing to do in this batch, can happen when a batch is created without
    # there being any signatures successfully added to it
    return

  let
    startTick = Moment.now()
    slotDuration = batchCrypto.timeParams.SLOT_DURATION

  # If the hardware is too slow to keep up or an event caused a temporary
  # buildup of signature verification tasks, the batch will be dropped so as to
  # recover and not cause even further buildup - this puts an (elastic) upper
  # bound on the amount of queued-up work
  if batch[].created + slotDuration < startTick:
    if batchCrypto.pruneTime + slotDuration < startTick:
      notice "Batch queue pruned, skipping attestation validation",
        batches = batchCrypto.batches.len()
      batchCrypto.pruneTime = startTick

    batch[].skip()

    batch_verification_batches_skipped.inc()

    return

  trace "batch crypto - starting", numSets, items = batch[].items.len

  let ok =
    # Depending on how many signatures there are in the batch, it may or
    # may not be beneficial to use batch verification:
    # https://github.com/status-im/nim-blscurve/blob/3956f63dd0ed5d7939f6195ee09e4c5c1ace9001/blscurve/bls_batch_verifier.nim#L390
    if numSets == 1:
      var r: bool
      for multiSet in batch[].multiSets.values():
        r = blsVerify(multiSet.combine(verifier))
        break
      r
    elif batchCrypto[].taskpool.numThreads > 1 and numSets > 3:
      await batchVerifyAsync(verifier, batch, batchCrypto.disp)
    else:
      let secureRandomBytes = verifier[].rng[].generate(array[32, byte])
      batchVerifySerial(
        verifier[].sigVerifCache,
        batch.multiSets.combineAll(verifier),
        secureRandomBytes)

  trace "batch crypto - finished",
    numSets, items = batch[].items.len(), ok,
    batchDur = Moment.now() - startTick

  batchCrypto[].complete(batch[], ok)

proc processLoop(batchCrypto: ref BatchCrypto) {.async: (raises: [CancelledError]).} =
  ## Process pending crypto check after some time has passed - the time is
  ## chosen such that there's time to fill the batch but not so long that
  ## latency across the network is negatively affected
  while batchCrypto[].batches.len() > 0:
    # When eager processing is enabled, we can start processing the next batch
    # as soon as it's full - otherwise, wait for more signatures to accumulate
    if not batchCrypto[].batches.peekFirst()[].full() or
        not batchCrypto[].eager():

      await sleepAsync(BatchAttAccumTime)

      # We still haven't filled even half the batch - wait a bit more (and give
      # chonos time to work its task queue)
      if not batchCrypto[].batches.peekFirst()[].half():
        await sleepAsync(BatchAttAccumTime div 2)

    # Pick the "next" verifier
    let verifier = (batchCrypto[].verifier + 1) mod batchCrypto.verifiers.len
    batchCrypto[].verifier = verifier

    # BatchVerifier:s may not be shared, so make sure the previous round
    # using this verifier is finished
    if batchCrypto[].verifiers[verifier].inflight != nil and
        not batchCrypto[].verifiers[verifier].inflight.finished():
      await batchCrypto[].verifiers[verifier].inflight

    batchCrypto[].verifiers[verifier].inflight = batchCrypto.processBatch(
      batchCrypto[].batches.popFirst(), batchCrypto[].verifiers[verifier].verifier
    )

proc getBatch(batchCrypto: var BatchCrypto): ref Batch =
  if batchCrypto.batches.len() == 0 or
      batchCrypto.batches.peekLast[].full():
    let batch = (ref Batch)(created: Moment.now())
    batchCrypto.batches.addLast(batch)
    batch
  else:
    batchCrypto.batches.peekLast()

proc scheduleProcessor(batchCrypto: ref BatchCrypto) =
  if batchCrypto.processor == nil or batchCrypto.processor.finished():
    batchCrypto.processor = batchCrypto.processLoop()

proc verifySoon(
    batchCrypto: ref BatchCrypto, name: static string, sigset: SignatureSet
): Future[BatchResult] {.async: (raises: [], raw: true).} =
  let
    batch = batchCrypto[].getBatch()
    fut = newFuture[BatchResult](name, {FutureFlag.OwnCancelSchedule})

  batch[].multiSets.withValue(sigset.message, multiSet):
    multiSet[].add sigset
  do:
    batch[].multiSets[sigset.message] = MultiSignatureSet.init sigset

  # We need to keep the "original" sigset to allow verifying each signature
  # one by one in the case the combined operation fails
  batch[].items.add(BatchItem(sigset: sigset, fut: fut))

  batchCrypto.scheduleProcessor()

  fut

# See also verify_attestation_signature
proc scheduleAttestationCheck*(
    batchCrypto: ref BatchCrypto,
    fork: Fork,
    attestationData: AttestationData,
    pubkey: CookedPubKey,
    sig: CookedSig,
): FutureBatchResult =
  ## Schedule crypto verification of an attestation
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns an error if crypto sanity checks failed
  ## and a future with the deferred attestation check otherwise.
  ##
  batchCrypto.verifySoon("batch_validation.scheduleAttestationCheck"):
    attestation_signature_set(
      fork, batchCrypto[].genesis_validators_root, attestationData, pubkey, sig
    )

proc scheduleAggregateChecks*(
    batchCrypto: ref BatchCrypto,
    fork: Fork,
    signedAggregateAndProof:
      electra.SignedAggregateAndProof | gloas.SignedAggregateAndProof,
    aggregateSig: CookedSig,
    dag: ChainDAGRef,
    attesting_indices: openArray[ValidatorIndex],
): Result[tuple[aggregatorFut, slotFut, aggregateFut: FutureBatchResult], cstring] =
  ## Schedule crypto verification of an aggregate
  ##
  ## This involves 3 checks:
  ## - verify_slot_signature
  ## - verify_aggregate_and_proof_signature
  ## - is_valid_indexed_attestation
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns None if the signatures could not be loaded.
  ## and 3 futures with the deferred aggregate checks otherwise.

  template aggregate_and_proof: untyped = signedAggregateAndProof.message
  template aggregate: untyped = aggregate_and_proof.aggregate

  # Do the eager steps first to avoid polluting batches with needlessly
  let
    aggregatorKey =
      dag.validatorKey(aggregate_and_proof.aggregator_index).valueOr:
        return err("SignedAggregateAndProof: invalid aggregator index")
    aggregatorSig = signedAggregateAndProof.signature.load().valueOr:
      return err("aggregateAndProof: invalid proof signature")
    slotSig = aggregate_and_proof.selection_proof.load().valueOr:
      return err("aggregateAndProof: invalid selection signature")
    aggregateKey = ? aggregateAll(dag, attesting_indices)

  let
    aggregatorFut = batchCrypto.verifySoon("scheduleAggregateChecks.aggregator"):
      aggregate_and_proof_signature_set(
        fork, batchCrypto[].genesis_validators_root, aggregate_and_proof,
        aggregatorKey, aggregatorSig)
    slotFut = batchCrypto.verifySoon("scheduleAggregateChecks.selection_proof"):
      slot_signature_set(
        fork, batchCrypto[].genesis_validators_root, aggregate.data.slot,
        aggregatorKey, slotSig)
    aggregateFut = batchCrypto.verifySoon("scheduleAggregateChecks.aggregate"):
      attestation_signature_set(
        fork, batchCrypto[].genesis_validators_root, aggregate.data,
        aggregateKey, aggregateSig)

  ok((aggregatorFut, slotFut, aggregateFut))

proc scheduleSyncCommitteeMessageCheck*(
      batchCrypto: ref BatchCrypto, fork: Fork, slot: Slot,
      beacon_block_root: Eth2Digest, pubkey: CookedPubKey,
      signature: ValidatorSig
     ): Result[tuple[fut: FutureBatchResult, sig: CookedSig], cstring] =
  ## Schedule crypto verification of an attestation
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns an error if crypto sanity checks failed
  ## and a future with the deferred attestation check otherwise.
  ##
  let
    sig = signature.load().valueOr:
      return err("SyncCommitteMessage: cannot load signature")
    fut = batchCrypto.verifySoon("scheduleSyncCommitteeMessageCheck"):
      sync_committee_message_signature_set(
        fork, batchCrypto[].genesis_validators_root, slot, beacon_block_root,
        pubkey, sig)

  ok((fut, sig))

proc scheduleContributionChecks*(
      batchCrypto: ref BatchCrypto,
      fork: Fork, signedContributionAndProof: SignedContributionAndProof,
      subcommitteeIdx: SyncSubcommitteeIndex, dag: ChainDAGRef): Result[tuple[
       aggregatorFut, proofFut, contributionFut: FutureBatchResult,
       sig: CookedSig], cstring] =
  ## Schedule crypto verification of all signatures in a
  ## SignedContributionAndProof message
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns an error if crypto sanity checks failed
  ## and a future with the deferred check otherwise.
  ##
  template contribution_and_proof: untyped = signedContributionAndProof.message
  template contribution: untyped = contribution_and_proof.contribution

  # Do the eager steps first to avoid polluting batches with needlessly
  let
    aggregatorKey =
      dag.validatorKey(contribution_and_proof.aggregator_index).valueOr:
        return err("SignedAggregateAndProof: invalid contributor index")
    aggregatorSig = signedContributionAndProof.signature.load().valueOr:
      return err("SignedContributionAndProof: invalid proof signature")
    proofSig = contribution_and_proof.selection_proof.load().valueOr:
      return err("SignedContributionAndProof: invalid selection signature")
    contributionSig = contribution.signature.load().valueOr:
      return err("SignedContributionAndProof: invalid contribution signature")

    contributionKey = ? aggregateAll(
      dag, dag.syncCommitteeParticipants(contribution.slot + 1, subcommitteeIdx),
      contribution.aggregation_bits)
  let
    aggregatorFut = batchCrypto.verifySoon("scheduleContributionAndProofChecks.aggregator"):
      contribution_and_proof_signature_set(
        fork, batchCrypto[].genesis_validators_root, contribution_and_proof,
        aggregatorKey, aggregatorSig)
    proofFut = batchCrypto.verifySoon("scheduleContributionAndProofChecks.selection_proof"):
      sync_committee_selection_proof_set(
        fork, batchCrypto[].genesis_validators_root, contribution.slot,
        subcommitteeIdx, aggregatorKey, proofSig)
    contributionFut = batchCrypto.verifySoon("scheduleContributionAndProofChecks.contribution"):
      sync_committee_message_signature_set(
        fork, batchCrypto[].genesis_validators_root, contribution.slot,
        contribution.beacon_block_root, contributionKey, contributionSig)

  ok((aggregatorFut, proofFut, contributionFut, contributionSig))

proc scheduleBlsToExecutionChangeCheck*(
    batchCrypto: ref BatchCrypto,
    genesis_fork_version: Version,
    signedBLSToExecutionChange: SignedBLSToExecutionChange):
    Result[tuple[fut: FutureBatchResult, sig: CookedSig], cstring] =
  ## Schedule crypto verification of all signatures in a
  ## SignedBLSToExecutionChange message
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns an error if crypto sanity checks failed
  ## and a future with the deferred check otherwise.

  let
    # Only called when matching already-known withdrawal credentials, so it's
    # resistant to allowing loadWithCache DoSing
    pubkey =
      signedBLSToExecutionChange.message.from_bls_pubkey.loadWithCache.valueOr:
        return err("scheduleBlsToExecutionChangeCheck: cannot load BLS to execution change pubkey")
    sig = signedBLSToExecutionChange.signature.load().valueOr:
      return err("scheduleBlsToExecutionChangeCheck: invalid validator change signature")
    fut = batchCrypto.verifySoon("scheduleContributionAndProofChecks.contribution"):
      bls_to_execution_change_signature_set(
        genesis_fork_version, batchCrypto[].genesis_validators_root,
        signedBLSToExecutionChange.message,
        pubkey, sig)

  ok((fut, sig))

proc schedulePayloadAttestationCheck*(
      batchCrypto: ref BatchCrypto, fork: Fork,
      genesis_validators_root: Eth2Digest,
      msg: PayloadAttestationMessage,
      pubkey: CookedPubKey,
      signature: ValidatorSig
    ): Result[tuple[fut: FutureBatchResult, sig: CookedSig], cstring] =
  ## Schedule crypto verification of a payload attestation
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns an error if crypto sanity checks failed
  ## and a future with the deferred payload attestation check otherwise.
  ##
  let
    sig = signature.load().valueOr:
      return err("payload attestation: cannot load signature")
    fut = batchCrypto.verifySoon("batch_validation.schedulePayloadAttestationCheck"):
      payload_attestation_signature_set(
        fork, genesis_validators_root, msg, pubkey, sig)

  ok((fut, sig))

func toBatchResult(valid: bool): BatchResult =
  if valid:
    BatchResult.Valid
  else:
    BatchResult.Invalid

proc scheduleKzgCheck(
    batchCrypto: ref BatchCrypto,
    commitments: seq[KzgCommitment], cellIndices: seq[CellIndex],
    cells: seq[KzgCell], proofs: seq[KzgProof]):
    Future[BatchResult] {.async: (raises: []).} =
  ## Verify the KZG proofs of a data column on the task pool
  if batchCrypto.taskpool.numThreads <= 1:
    return toBatchResult verifyCellKzgProofBatch(
      commitments, cellIndices, cells, proofs).get(false)

  let
    created = Moment.now()

  await noCancel batchCrypto.kzgLimit.acquire()
  defer:
    try:
      batchCrypto.kzgLimit.release()
    except AsyncError:
      raiseAssert "Unreachable"

  let
    startTick = Moment.now()
    slotDuration = batchCrypto.timeParams.SLOT_DURATION

  # If the hardware is too slow to keep up or an event caused a temporary
  # buildup of column checks, the check will be dropped so as to recover and
  # not cause even further buildup - this puts an (elastic) upper bound
  # on the amount of queued-up work
  if created + slotDuration < startTick:
    if batchCrypto[].pruneTime + slotDuration < startTick:
      notice "Column check queue pruned, skipping data column validation"
      batchCrypto[].pruneTime = startTick

    return BatchResult.Timeout

  let future = FutureTask.init("kzg_verify", {FutureFlag.OwnCancelSchedule})
  var task = KzgTask(
    commitmentsPtr: makeUncheckedArray(baseAddr commitments),
    cellIndicesPtr: makeUncheckedArray(baseAddr cellIndices),
    cellsPtr: makeUncheckedArray(baseAddr cells),
    proofsPtr: makeUncheckedArray(baseAddr proofs),
    numCells: cells.len,
    future: future,
    disp: batchCrypto.disp,
  )

  # task will stay allocated in the async environment at least until the
  # callSoon completion callback has fired
  let taskPtr = addr task
  batchCrypto[].taskpool.spawnKzgTask(taskPtr)

  await future

  # TODO https://github.com/nim-lang/Nim/issues/26041
  #      don't forget to touch task after await

  toBatchResult(task.ok.load())

proc scheduleDataColumnSidecarCheck*(
    batchCrypto: ref BatchCrypto,
    data_column_sidecar: ref fulu.DataColumnSidecar): FutureBatchResult =
  ## Schedule KZG proof verification of a fulu data column sidecar
  batchCrypto.scheduleKzgCheck(
    data_column_sidecar[].kzg_commitments.asSeq,
    repeat(CellIndex(data_column_sidecar[].index),
      data_column_sidecar[].column.len),
    data_column_sidecar[].column.asSeq,
    data_column_sidecar[].kzg_proofs.asSeq)

proc scheduleDataColumnSidecarCheck*(
    batchCrypto: ref BatchCrypto,
    data_column_sidecar: ref gloas.DataColumnSidecar,
    kzg_commitments: seq[KzgCommitment]): FutureBatchResult =
  ## Schedule KZG proof verification of a gloas data column sidecar against the
  ## commitments carried by the execution payload bid
  batchCrypto.scheduleKzgCheck(
    kzg_commitments,
    repeat(CellIndex(data_column_sidecar[].index),
      data_column_sidecar[].column.len),
    data_column_sidecar[].column.asSeq,
    data_column_sidecar[].kzg_proofs.asSeq)

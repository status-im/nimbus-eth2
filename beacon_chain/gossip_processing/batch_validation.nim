# beacon_chain
# Copyright (c) 2019-2023 Status Research & Development GmbH
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
  chronicles, chronos, chronos/threadsync,
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

type
  BatchResult* {.pure.} = enum
    Invalid # Invalid by default
    Valid
    Timeout

  Eager = proc(): bool {.gcsafe, raises: [].}
    ## Callback that returns true if eager processing should be done to lower
    ## latency at the expense of spending more cycles validating things,
    ## creating a crude timesharing priority mechanism.

  BatchItem* = object
    sigset: SignatureSet
    fut: Future[BatchResult]

  Batch* = object
    ## A batch represents up to BatchedCryptoSize non-aggregated signatures
    created: Moment
    sigsets: seq[SignatureSet]
    items: seq[BatchItem]

  VerifierItem = object
    verifier: ref BatchVerifier
    signal: ThreadSignalPtr
    inflight: Future[void]

  BatchCrypto* = object
    batches: Deque[ref Batch]
    eager: Eager
      ## Eager is used to enable eager processing of attestations when it's
      ## prudent to do so (instead of leaving the CPU for other, presumably more
      ## important work like block processing)

    taskpool: Taskpool
    rng: ref HmacDrbgContext

    verifiers: array[InflightVerifications, VerifierItem]
      ## Each batch verification reqires a separate verifier
    verifier: int

    pruneTime: Moment ## last time we had to prune something

    counts: tuple[signatures, batches, aggregates: int64]
      # `nim-metrics` library is a bit too slow to update on every batch, so
      # we accumulate here instead

    genesis_validators_root: Eth2Digest
      # Most scheduled checks require this immutable value, so don't require it
      # to be provided separately each time

    processor: Future[void]

  BatchTask = object
    ok: Atomic[bool]
    setsPtr: ptr UncheckedArray[SignatureSet]
    numSets: int
    secureRandomBytes: array[32, byte]
    taskpool: Taskpool
    cache: ptr BatchedBLSVerifierCache
    signal: ThreadSignalPtr

proc new*(
    T: type BatchCrypto, rng: ref HmacDrbgContext,
    eager: Eager, genesis_validators_root: Eth2Digest, taskpool: TaskPoolPtr):
    Result[ref BatchCrypto, string] =
  let res = (ref BatchCrypto)(
    rng: rng, taskpool: taskpool,
    eager: eager,
    genesis_validators_root: genesis_validators_root,
    pruneTime: Moment.now())

  for i in 0..<res.verifiers.len:
    res.verifiers[i] = VerifierItem(
      verifier: BatchVerifier.new(rng, taskpool),
      signal: block:
        let sig = ThreadSignalPtr.new()
        sig.valueOr:
          for j in 0..<i:
            discard res.verifiers[j].signal.close()
          return err(sig.error())
    )

  ok res

func full(batch: Batch): bool =
  batch.items.len() >= BatchedCryptoSize

func half(batch: Batch): bool =
  batch.items.len() >= (BatchedCryptoSize div 2)

proc complete(batchItem: var BatchItem, v: BatchResult) =
  batchItem.fut.complete(v)
  batchItem.fut = nil

proc complete(batchItem: var BatchItem, ok: bool) =
  batchItem.fut.complete(if ok: BatchResult.Valid else: BatchResult.Invalid)

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
  batchCrypto.counts.aggregates += batch.sigsets.len()

  if batchCrypto.counts.batches >= 256:
    # Not too often, so as not to overwhelm our metrics
    batch_verification_batches.inc(batchCrypto.counts.batches)
    batch_verification_signatures.inc(batchCrypto.counts.signatures)
    batch_verification_aggregates.inc(batchCrypto.counts.aggregates)

    reset(batchCrypto.counts)

func combine(a: var Signature, b: Signature) =
  var tmp = AggregateSignature.init(CookedSig(a))
  tmp.aggregate(b)
  a = Signature(tmp.finish())

func combine(a: var PublicKey, b: PublicKey) =
  var tmp = AggregatePublicKey.init(CookedPubKey(a))
  tmp.aggregate(b)
  a = PublicKey(tmp.finish())

proc batchVerifyTask(task: ptr BatchTask) {.nimcall.} =
  # Task suitable for running in taskpools - look, no GC!
  let
    tp = task[].taskpool
    ok = tp.spawn batchVerify(
      tp, task[].cache, task[].setsPtr, task[].numSets,
      addr task[].secureRandomBytes)

  task[].ok.store(sync ok)

  discard task[].signal.fireSync()

proc spawnBatchVerifyTask(tp: Taskpool, task: ptr BatchTask) =
  # Inlining this `proc` leads to compilation problems on Nim 2.0
  # - Error: cannot generate destructor for generic type: Isolated
  # Workaround: Ensure that `tp.spawn` is not used within an `{.async.}` proc
  # Possibly related to: https://github.com/nim-lang/Nim/issues/22305
  tp.spawn batchVerifyTask(task)

proc batchVerifyAsync*(
    verifier: ref BatchVerifier, signal: ThreadSignalPtr,
    batch: ref Batch): Future[bool] {.async.} =
  var task = BatchTask(
    setsPtr: makeUncheckedArray(baseAddr batch[].sigsets),
    numSets: batch[].sigsets.len,
    taskpool: verifier[].taskpool,
    cache: addr verifier[].sigVerifCache,
    signal: signal,
  )
  verifier[].rng[].generate(task.secureRandomBytes)

  # task will stay allocated in the async environment at least until the signal
  # has fired at which point it's safe to release it
  let taskPtr = addr task
  doAssert verifier[].taskpool.numThreads > 1,
    "Must have at least one separate thread or signal will never be fired"
  verifier[].taskpool.spawnBatchVerifyTask(taskPtr)
  await signal.wait()
  task.ok.load()

proc processBatch(
    batchCrypto: ref BatchCrypto, batch: ref Batch,
    verifier: ref BatchVerifier, signal: ThreadSignalPtr) {.async.} =
  let
    numSets = batch[].sigsets.len()

  if numSets == 0:
    # Nothing to do in this batch, can happen when a batch is created without
    # there being any signatures successfully added to it
    return

  let
    startTick = Moment.now()

  # If the hardware is too slow to keep up or an event caused a temporary
  # buildup of signature verification tasks, the batch will be dropped so as to
  # recover and not cause even further buildup - this puts an (elastic) upper
  # bound on the amount of queued-up work
  if batch[].created + SECONDS_PER_SLOT.int64.seconds < startTick:
    if batchCrypto.pruneTime + SECONDS_PER_SLOT.int64.seconds < startTick:
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
      blsVerify(batch[].sigsets[0])
    elif batchCrypto[].taskpool.numThreads > 1 and numSets > 3:
      await batchVerifyAsync(verifier, signal, batch)
    else:
      let secureRandomBytes = verifier[].rng[].generate(array[32, byte])
      batchVerifySerial(
        verifier[].sigVerifCache, batch.sigsets, secureRandomBytes)

  trace "batch crypto - finished",
    numSets, items = batch[].items.len(), ok,
    batchDur = Moment.now() - startTick

  batchCrypto[].complete(batch[], ok)

proc processLoop(batchCrypto: ref BatchCrypto) {.async.} =
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
      batchCrypto[].batches.popFirst(),
      batchCrypto[].verifiers[verifier].verifier,
      batchCrypto[].verifiers[verifier].signal)

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
    batchCrypto: ref BatchCrypto, name: static string,
    sigset: SignatureSet): Future[BatchResult] =
  let
    batch = batchCrypto[].getBatch()
    fut = newFuture[BatchResult](name)

  var found = false
  # Find existing signature sets with the same message - if we can verify an
  # aggregate instead of several signatures, that is _much_ faster
  for item in batch[].sigsets.mitems():
    if item.message == sigset.message:
      item.signature.combine(sigset.signature)
      item.pubkey.combine(sigset.pubkey)
      found = true
      break

  if not found:
    batch[].sigsets.add sigset

  # We need to keep the "original" sigset to allow verifying each signature
  # one by one in the case the combined operation fails
  batch[].items.add(BatchItem(sigset: sigset, fut: fut))

  batchCrypto.scheduleProcessor()

  fut

# See also verify_attestation_signature
proc scheduleAttestationCheck*(
      batchCrypto: ref BatchCrypto, fork: Fork,
      attestationData: AttestationData, pubkey: CookedPubKey,
      signature: ValidatorSig
     ): Result[tuple[fut: Future[BatchResult], sig: CookedSig], cstring] =
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
      return err("attestation: cannot load signature")
    fut = batchCrypto.verifySoon("batch_validation.scheduleAttestationCheck"):
      attestation_signature_set(
        fork, batchCrypto[].genesis_validators_root, attestationData, pubkey,
        sig)

  ok((fut, sig))

proc scheduleAggregateChecks*(
      batchCrypto: ref BatchCrypto, fork: Fork,
      signedAggregateAndProof: SignedAggregateAndProof, dag: ChainDAGRef,
      attesting_indices: openArray[ValidatorIndex]
     ): Result[tuple[
        aggregatorFut, slotFut, aggregateFut: Future[BatchResult],
        sig: CookedSig], cstring] =
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
    aggregateSig = aggregate.signature.load().valueOr:
      return err("aggregateAndProof: invalid aggregate signature")

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

  ok((aggregatorFut, slotFut, aggregateFut, aggregateSig))

proc scheduleSyncCommitteeMessageCheck*(
      batchCrypto: ref BatchCrypto, fork: Fork, slot: Slot,
      beacon_block_root: Eth2Digest, pubkey: CookedPubKey,
      signature: ValidatorSig
     ): Result[tuple[fut: Future[BatchResult], sig: CookedSig], cstring] =
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
       aggregatorFut, proofFut, contributionFut: Future[BatchResult],
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
    genesis_fork: Fork, signedBLSToExecutionChange: SignedBLSToExecutionChange):
    Result[tuple[fut: Future[BatchResult], sig: CookedSig], cstring] =
  ## Schedule crypto verification of all signatures in a
  ## SignedBLSToExecutionChange message
  ##
  ## The buffer is processed:
  ## - when eager processing is enabled and the batch is full
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns an error if crypto sanity checks failed
  ## and a future with the deferred check otherwise.

  # Must be genesis fork
  doAssert genesis_fork.previous_version == genesis_fork.current_version

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
        genesis_fork, batchCrypto[].genesis_validators_root,
        signedBLSToExecutionChange.message,
        pubkey, sig)

  ok((fut, sig))

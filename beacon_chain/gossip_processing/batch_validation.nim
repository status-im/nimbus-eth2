# beacon_chain
# Copyright (c) 2019-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[deques, sequtils],
  metrics,
  # Status
  chronicles, chronos,
  ../spec/signatures_batch,
  ../consensus_object_pools/[blockchain_dag, spec_cache]

export signatures_batch, blockchain_dag

logScope:
  topics = "gossip_checks"

declareCounter batch_verification_batches,
  "Total number of batches processed"
declareCounter batch_verification_signatures,
  "Total number of verified signatures before aggregation"
declareCounter batch_verification_aggregates,
  "Total number of verified signatures after aggregation"

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

type
  BatchResult* {.pure.} = enum
    Invalid # Invalid by default
    Valid
    Timeout

  Eager = proc(): bool {.gcsafe, raises: [Defect].} ##\
  ## Callback that returns true if eager processing should be done to lower
  ## latency at the expense of spending more cycles validating things, creating
  ## a crude timesharing priority mechanism.

  BatchItem* = object
    sigset: SignatureSet
    fut: Future[BatchResult]

  Batch* = object
    created: Moment
    sigsets: seq[SignatureSet]
    items: seq[BatchItem]

  BatchCrypto* = object
    # Each batch is bounded by BatchedCryptoSize which was chosen:
    # - based on "nimble bench" in nim-blscurve
    #   so that low power devices like Raspberry Pi 4 can process
    #   that many batched verifications within ~30ms on average
    # - based on the accumulation rate of attestations and aggregates
    #   in large instances which were 12000 per slot (12s)
    #   hence 1 per ms (but the pattern is bursty around the 4s mark)
    # The number of batches is bounded by time - batch validation is skipped if
    # we can't process them in the time that one slot takes, and we return
    # timeout instead which prevents the gossip layer from forwarding the
    # batch.
    batches: Deque[ref Batch]
    eager: Eager ##\
    ## Eager is used to enable eager processing of attestations when it's
    ## prudent to do so (instead of leaving the CPU for other, presumably more
    ## important work like block processing)
    ##
    verifier: BatchVerifier

    pruneTime: Moment ## last time we had to prune something

    # `nim-metrics` library is a bit too slow to update on every batch, so
    # we accumulate here instead
    counts: tuple[signatures, batches, aggregates: int64]

    # Most scheduled checks require this immutable value, so don't require it
    # to be provided separately each time
    genesis_validators_root: Eth2Digest

const
  # We cap waiting for an idle slot in case there's a lot of network traffic
  # taking up all CPU - we don't want to _completely_ stop processing
  # attestations - doing so also allows us to benefit from more batching /
  # larger network reads when under load.
  BatchAttAccumTime = 10.milliseconds

  # Threshold for immediate trigger of batch verification.
  # A balance between throughput and worst case latency.
  # At least 6 so that the constant factors
  # (RNG for blinding and Final Exponentiation)
  # are amortized, but not too big as we need to redo checks one-by-one if one
  # failed.
  # The current value is based on experiments, where 72 gives an average batch
  # size of ~30 signatures per batch, or 2.5 signatures per aggregate (meaning
  # an average of 12 verifications per batch which on a raspberry should be
  # doable in less than 30ms). In the same experiment, a value of 36 resulted
  # in 17-18 signatures per batch and 1.7-1.9 signatures per aggregate - this
  # node was running on mainnet with `--subscribe-all-subnets` turned on -
  # typical nodes will see smaller batches.
  BatchedCryptoSize = 72

proc new*(
    T: type BatchCrypto, rng: ref HmacDrbgContext,
    eager: Eager, genesis_validators_root: Eth2Digest, taskpool: TaskPoolPtr):
    ref BatchCrypto =
  (ref BatchCrypto)(
    verifier: BatchVerifier(rng: rng, taskpool: taskpool),
    eager: eager,
    genesis_validators_root: genesis_validators_root,
    pruneTime: Moment.now())

func len(batch: Batch): int =
  batch.items.len()

func full(batch: Batch): bool =
  batch.len() >= BatchedCryptoSize

proc complete(batchItem: var BatchItem, v: BatchResult) =
  batchItem.fut.complete(v)
  batchItem.fut = nil

proc complete(batchItem: var BatchItem, ok: bool) =
  batchItem.fut.complete(if ok: BatchResult.Valid else: BatchResult.Invalid)
  batchItem.fut = nil

proc skip(batch: var Batch) =
  for res in batch.items.mitems():
    res.complete(BatchResult.Timeout)

proc pruneBatchQueue(batchCrypto: ref BatchCrypto) =
  let
    now = Moment.now()

  # If batches haven't been processed for more than 12 seconds
  while batchCrypto.batches.len() > 0:
    if batchCrypto.batches[0][].created + SECONDS_PER_SLOT.int64.seconds > now:
      break
    if batchCrypto.pruneTime + SECONDS_PER_SLOT.int64.seconds > now:
      notice "Batch queue pruned, skipping attestation validation",
        batches = batchCrypto.batches.len()
      batchCrypto.pruneTime = Moment.now()

    batchCrypto.batches.popFirst()[].skip()

func combine(a: var Signature, b: Signature) =
  var tmp = AggregateSignature.init(CookedSig(a))
  tmp.aggregate(b)
  a = Signature(tmp.finish())

func combine(a: var PublicKey, b: PublicKey) =
  var tmp = AggregatePublicKey.init(CookedPubKey(a))
  tmp.aggregate(b)
  a = PublicKey(tmp.finish())

proc processBatch(batchCrypto: ref BatchCrypto) =
  ## Process one batch, if there is any

  # Pruning the queue here makes sure we catch up with processing if need be
  batchCrypto.pruneBatchQueue() # Skip old batches

  if batchCrypto[].batches.len() == 0:
    # No more batches left, they might have been eagerly processed or pruned
    return

  let
    batch = batchCrypto[].batches.popFirst()
    batchSize = batch[].sigsets.len()

  if batchSize == 0:
    # Nothing to do in this batch, can happen when a batch is created without
    # there being any signatures successfully added to it
    discard
  else:
    trace "batch crypto - starting",
      batchSize

    let
      startTick = Moment.now()
      ok =
        if batchSize == 1: blsVerify(batch[].sigsets[0])
        else: batchCrypto.verifier.batchVerify(batch[].sigsets)

    trace "batch crypto - finished",
      batchSize,
      cryptoVerified = ok,
      batchDur = Moment.now() - startTick

    if ok:
      for res in batch.items.mitems():
        res.complete(BatchResult.Valid)
    else:
      # Batched verification failed meaning that some of the signature checks
      # failed, but we don't know which ones - check each signature separately
      # instead
      debug "batch crypto - failure, falling back",
        items = batch[].items.len()

      for item in batch[].items.mitems():
        item.complete(blsVerify item.sigset)

  batchCrypto[].counts.batches += 1
  batchCrypto[].counts.signatures += batch[].items.len()
  batchCrypto[].counts.aggregates += batch[].sigsets.len()

  if batchCrypto[].counts.batches >= 256:
    # Not too often, so as not to overwhelm our metrics
    batch_verification_batches.inc(batchCrypto[].counts.batches)
    batch_verification_signatures.inc(batchCrypto[].counts.signatures)
    batch_verification_aggregates.inc(batchCrypto[].counts.aggregates)

    reset(batchCrypto[].counts)

proc deferCryptoProcessing(batchCrypto: ref BatchCrypto) {.async.} =
  ## Process pending crypto check after some time has passed - the time is
  ## chosen such that there's time to fill the batch but not so long that
  ## latency across the network is negatively affected
  await sleepAsync(BatchAttAccumTime)

  # Take the first batch in the queue and process it - if eager processing has
  # stolen it already, that's fine
  batchCrypto.processBatch()

proc getBatch(batchCrypto: ref BatchCrypto): (ref Batch, bool) =
  # Get a batch suitable for attestation processing - in particular, attestation
  # batches might be skipped
  batchCrypto.pruneBatchQueue()

  if batchCrypto.batches.len() == 0 or
      batchCrypto.batches.peekLast[].full():
    # There are no batches in progress - start a new batch and schedule a
    # deferred task to eventually handle it
    let batch = (ref Batch)(created: Moment.now())
    batchCrypto[].batches.addLast(batch)
    (batch, true)
  else:
    let batch = batchCrypto[].batches.peekLast()
    # len will be 0 when the batch was created but nothing added to it
    # because of early failures
    (batch, batch[].len() == 0)

proc scheduleBatch(batchCrypto: ref BatchCrypto, fresh: bool) =
  if fresh:
    # Every time we start a new round of batching, we need to launch a deferred
    # task that will compute the result of the batch eventually in case the
    # batch is never filled or eager processing is blocked
    asyncSpawn batchCrypto.deferCryptoProcessing()

  if batchCrypto.batches.len() > 0 and
      batchCrypto.batches.peekFirst()[].full() and
      batchCrypto.eager():
    # If there's a full batch, process it eagerly assuming the callback allows
    batchCrypto.processBatch()

template withBatch(
    batchCrypto: ref BatchCrypto, name: cstring,
    body: untyped): Future[BatchResult] =
  block:
    let
      (batch, fresh) = batchCrypto.getBatch()

    let
      fut = newFuture[BatchResult](name)
      sigset = body

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

    batchCrypto.scheduleBatch(fresh)
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
    fut = batchCrypto.withBatch("batch_validation.scheduleAttestationCheck"):
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
    aggregatorFut = batchCrypto.withBatch("scheduleAggregateChecks.aggregator"):
      aggregate_and_proof_signature_set(
        fork, batchCrypto[].genesis_validators_root, aggregate_and_proof,
        aggregatorKey, aggregatorSig)
    slotFut = batchCrypto.withBatch("scheduleAggregateChecks.selection_proof"):
      slot_signature_set(
        fork, batchCrypto[].genesis_validators_root, aggregate.data.slot,
        aggregatorKey, slotSig)
    aggregateFut = batchCrypto.withBatch("scheduleAggregateChecks.aggregate"):
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
    fut = batchCrypto.withBatch("scheduleSyncCommitteeMessageCheck"):
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
    aggregatorFut = batchCrypto.withBatch("scheduleContributionAndProofChecks.aggregator"):
      contribution_and_proof_signature_set(
        fork, batchCrypto[].genesis_validators_root, contribution_and_proof,
        aggregatorKey, aggregatorSig)
    proofFut = batchCrypto.withBatch("scheduleContributionAndProofChecks.selection_proof"):
      sync_committee_selection_proof_set(
        fork, batchCrypto[].genesis_validators_root, contribution.slot,
        subcommitteeIdx, aggregatorKey, proofSig)
    contributionFut = batchCrypto.withBatch("scheduleContributionAndProofChecks.contribution"):
      sync_committee_message_signature_set(
        fork, batchCrypto[].genesis_validators_root, contribution.slot,
        contribution.beacon_block_root, contributionKey, contributionSig)

  ok((aggregatorFut, proofFut, contributionFut, contributionSig))

proc scheduleBlsToExecutionChangeCheck*(
      batchCrypto: ref BatchCrypto,
      genesisFork: Fork,
      signedBLSToExecutionChange: SignedBLSToExecutionChange): Result[tuple[
       blsToExecutionFut: Future[BatchResult],
       sig: CookedSig], cstring] =
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
    validatorChangePubkey =
      signedBLSToExecutionChange.message.from_bls_pubkey.loadWithCache.valueOr:
        return err("scheduleBlsToExecutionChangeCheck: cannot load BLS to withdrawals pubkey")

    validatorChangeSig = signedBLSToExecutionChange.signature.load().valueOr:
      return err("scheduleBlsToExecutionChangeCheck: invalid validator change signature")
    validatorChangeFut = batchCrypto.withBatch("scheduleContributionAndProofChecks.contribution"):
      bls_to_execution_change_signature_set(
        genesis_fork, batchCrypto[].genesis_validators_root,
        signedBLSToExecutionChange.message,
        validatorChangePubkey, validatorChangeSig)

  ok((validatorChangeFut, validatorChangeSig))

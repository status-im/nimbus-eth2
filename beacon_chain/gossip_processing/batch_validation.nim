# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[sequtils, intsets],
  # Status
  chronicles, chronos,
  stew/results,
  eth/keys,
  # Internals
  ../spec/[
    beaconstate, state_transition_block,
    datatypes, crypto, digest, helpers, network, signatures, signatures_batch],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, block_quarantine, spec_cache,
    attestation_pool, exit_pool
  ],
  ".."/[beacon_node_types, ssz, beacon_clock],
  ../validators/attestation_aggregation,
  ../extras

export BrHmacDrbgContext

logScope:
  topics = "gossip_checks"

# Batched gossip validation
# ----------------------------------------------------------------
{.push raises: [Defect].}

type
  BatchCrypto* = object
    # The buffers are bounded by BatchedCryptoSize (16) which was chosen:
    # - based on "nimble bench" in nim-blscurve
    #   so that low power devices like Raspberry Pi 4 can process
    #   that many batched verifications within 20ms
    # - based on the accumulation rate of attestations and aggregates
    #   in large instances which were 12000 per slot (12s)
    #   hence 1 per ms (but the pattern is bursty around the 4s mark)
    pendingBuffer: seq[SignatureSet]
    resultsBuffer: seq[Future[Result[void, cstring]]]
    sigVerifCache: BatchedBLSVerifierCache ##\
    ## A cache for batch BLS signature verification contexts
    rng: ref BrHmacDrbgContext  ##\
    ## A reference to the Nimbus application-wide RNG

const
  # We cap waiting for an idle slot in case there's a lot of network traffic
  # taking up all CPU - we don't want to _completely_ stop processing blocks
  # in this case (attestations will get dropped) - doing so also allows us
  # to benefit from more batching / larger network reads when under load.
  BatchAttAccumTime = 10.milliseconds

  # Attestation processing is fairly quick and therefore done in batches to
  # avoid some of the `Future` overhead
  BatchedCryptoSize = 16

proc new*(T: type BatchCrypto, rng: ref BrHmacDrbgContext): ref BatchCrypto =
  (ref BatchCrypto)(rng: rng)

func clear(batchCrypto: ref BatchCrypto) =
  ## Empty the crypto-pending attestations & aggregate queues
  batchCrypto.pendingBuffer.setLen(0)
  batchCrypto.resultsBuffer.setLen(0)

proc done(batchCrypto: ref BatchCrypto, idx: int) =
  ## Send signal to [Attestation/Aggregate]Validator
  ## that the attestation was crypto-verified (and so gossip validated)
  ## with success
  batchCrypto.resultsBuffer[idx].complete(Result[void, cstring].ok())

proc fail(batchCrypto: ref BatchCrypto, idx: int, error: cstring) =
  ## Send signal to [Attestation/Aggregate]Validator
  ## that the attestation was NOT crypto-verified (and so NOT gossip validated)
  batchCrypto.resultsBuffer[idx].complete(Result[void, cstring].err(error))

proc complete(batchCrypto: ref BatchCrypto, idx: int, res: Result[void, cstring]) =
  ## Send signal to [Attestation/Aggregate]Validator
  batchCrypto.resultsBuffer[idx].complete(res)

proc processBufferedCrypto(self: ref BatchCrypto) =
  ## Drain all attestations waiting for crypto verifications

  doAssert self.pendingBuffer.len ==
             self.resultsBuffer.len

  if self.pendingBuffer.len == 0:
    return

  notice "Starting batch attestations & aggregate crypto verification",
    batchSize = self.pendingBuffer.len

  var secureRandomBytes: array[32, byte]
  self.rng[].brHmacDrbgGenerate(secureRandomBytes)

  # TODO: For now only enable serial batch verification
  let ok = batchVerifySerial(
    self.sigVerifCache,
    self.pendingBuffer,
    secureRandomBytes)

  notice "Finished batch attestations & aggregate crypto verification",
    batchSize = self.pendingBuffer.len,
    cryptoVerified = ok

  if ok:
    for i in 0 ..< self.resultsBuffer.len:
      self.done(i)
  else:
    notice "Batch verification failure - falling back",
      batchSize = self.pendingBuffer.len
    for i in 0 ..< self.pendingBuffer.len:
      let ok = blsVerify self.pendingBuffer[i]
      if ok:
        self.done(i)
      else:
        self.fail(i, "batch crypto verification: invalid signature")

  self.clear()

{.pop.} # async raising generic Exception

proc deferCryptoProcessing(self: ref BatchCrypto, idleTimeout: Duration) {.async.} =
  ## Process pending crypto check:
  ## - if time threshold is reached
  ## - or if networking is idle

  discard await idleAsync().withTimeout(idleTimeout)
  self.processBufferedCrypto()

proc schedule(batchCrypto: ref BatchCrypto, fut: Future[Result[void, cstring]], checkThreshold = true) =
  ## Schedule a cryptocheck for processing
  ##
  ## The buffer is processed:
  ## - when 16 or more attestations/aggregates are buffered (BatchedCryptoSize)
  ## - when there are no network events (idleAsync)
  ## - otherwise after 10ms (BatchAttAccumTime)
  batchCrypto.resultsBuffer.add fut

  if batchCrypto.pendingBuffer.len == 1:
    # First attestation to be scheduled in the batch
    # wait for an idle time or up to 10ms before processing
    asyncSpawn(
      try:
        batchCrypto.deferCryptoProcessing(BatchAttAccumTime)
      except Exception as e:
        # Chronos can in theory raise an untyped exception in `internalCheckComplete`
        # which asyncSpawn doesn't like.
        # Also in 1.2.6, Future and IOSelector errors don't inherit from CatchableError or Defect
        raiseAssert e.msg
    )
  elif checkThreshold and batchCrypto.pendingBuffer.len >= BatchedCryptoSize:
    # Reached the max buffer size, process immediately
    batchCrypto.processBufferedCrypto()

proc scheduleAttestationCheck*(
      batchCrypto: ref BatchCrypto,
      fork: Fork, genesis_validators_root: Eth2Digest,
      epochRef: auto,
      attestation: Attestation
     ): Option[Future[Result[void, cstring]]] =
  ## Schedule crypto verification of an attestation
  ##
  ## The buffer is processed:
  ## - when 16 or more attestations/aggregates are buffered (BatchedCryptoSize)
  ## - when there are no network events (idleAsync)
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns None if crypto sanity checks failed
  ## and a future with the deferred attestation check otherwise.
  doAssert batchCrypto.pendingBuffer.len < BatchedCryptoSize

  let sanity = batchCrypto
                .pendingBuffer
                .addAttestation(
                  fork, genesis_validators_root, epochRef,
                  attestation
                )
  if not sanity:
    return none(Future[Result[void, cstring]])

  let fut = newFuture[Result[void, cstring]](
    "batch_validation.scheduleAttestationCheck"
  )

  batchCrypto.schedule(fut)

  return some(fut)

proc scheduleAggregateChecks*(
      batchCrypto: ref BatchCrypto,
      fork: Fork, genesis_validators_root: Eth2Digest,
      epochRef: auto,
      signedAggregateAndProof: SignedAggregateAndProof
     ): Option[tuple[slotCheck, aggregatorCheck, aggregateCheck: Future[Result[void, cstring]]]] =
  ## Schedule crypto verification of an aggregate
  ##
  ## This involves 3 checks:
  ## - verify_slot_signature
  ## - verify_aggregate_and_proof_signature
  ## - is_valid_indexed_attestation
  ##
  ## The buffer is processed:
  ## - when 16 or more attestations/aggregates are buffered (BatchedCryptoSize)
  ## - when there are no network events (idleAsync)
  ## - otherwise after 10ms (BatchAttAccumTime)
  ##
  ## This returns None if crypto sanity checks failed
  ## and 2 futures with the deferred aggregate checks otherwise.
  doAssert batchCrypto.pendingBuffer.len < BatchedCryptoSize

  template aggregate_and_proof: untyped = signedAggregateAndProof.message
  template aggregate: untyped = aggregate_and_proof.aggregate

  type R = tuple[slotCheck, aggregatorCheck, aggregateCheck: Future[Result[void, cstring]]]

  # Enqueue in the buffer
  # ------------------------------------------------------
  let aggregator = epochRef.validator_keys[aggregate_and_proof.aggregator_index]
  block:
    let sanity = batchCrypto
                  .pendingBuffer
                  .addSlotSignature(
                    fork, genesis_validators_root,
                    aggregate.data.slot,
                    aggregator,
                    aggregate_and_proof.selection_proof
                  )
    if not sanity:
      return none(R)

  block:
    let sanity = batchCrypto
                  .pendingBuffer
                  .addAggregateAndProofSignature(
                    fork, genesis_validators_root,
                    aggregate_and_proof,
                    aggregator,
                    signed_aggregate_and_proof.signature
                  )
    if not sanity:
      return none(R)

  block:
    let sanity = batchCrypto
                  .pendingBuffer
                  .addAttestation(
                    fork, genesis_validators_root, epochRef,
                    aggregate
                  )
    if not sanity:
      return none(R)

  let futSlot = newFuture[Result[void, cstring]](
    "batch_validation.scheduleAggregateChecks.slotCheck"
  )
  let futAggregator = newFuture[Result[void, cstring]](
    "batch_validation.scheduleAggregateChecks.aggregatorCheck"
  )

  let futAggregate = newFuture[Result[void, cstring]](
    "batch_validation.scheduleAggregateChecks.aggregateCheck"
  )

  batchCrypto.schedule(futSlot, checkThreshold = false)
  batchCrypto.schedule(futAggregator, checkThreshold = false)
  batchCrypto.schedule(futAggregate)

  return some((futSlot, futAggregator, futAggregate))

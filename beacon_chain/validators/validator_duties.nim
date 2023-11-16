# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos,
  results,
  ../consensus_object_pools/block_dag,
  ../beacon_clock,
  "."/[validator_pool]

export chronos, results, block_dag, beacon_clock

## The validator_duties module contains logic and utilities related to performing
## validator duties that are shared between beacon node and validator client.

type
  RegisteredAttestation* = object
    # A registered attestation is one that has been successfully registered in
    # the slashing protection database and is therefore ready to be signed and
    # sent
    validator*: AttachedValidator
    index_in_committee*: uint64
    committee_len*: int
    data*: AttestationData

proc toAttestation*(
    registered: RegisteredAttestation, signature: ValidatorSig): Attestation =
  Attestation.init(
    [registered.index_in_committee], registered.committee_len,
    registered.data, signature).expect("valid data")

proc waitAfterBlockCutoff*(clock: BeaconClock, slot: Slot,
                           head: Opt[BlockRef] = Opt.none(BlockRef)) {.async.} =
  # The expected block arrived (or expectBlock was called again which
  # shouldn't happen as this is the only place we use it) - in our async
  # loop however, we might have been doing other processing that caused delays
  # here so we'll cap the waiting to the time when we would have sent out
  # attestations had the block not arrived.
  # An opposite case is that we received (or produced) a block that has
  # not yet reached our neighbours. To protect against our attestations
  # being dropped (because the others have not yet seen the block), we'll
  # impose a minimum delay of 2000ms. The delay is enforced only when we're
  # not hitting the "normal" cutoff time for sending out attestations.
  # An earlier delay of 250ms has proven to be not enough, increasing the
  # risk of losing attestations, and with growing block sizes, 1000ms
  # started to be risky as well.
  # Regardless, because we "just" received the block, we'll impose the
  # delay.

  # Take into consideration chains with a different slot time
  const afterBlockDelay = nanos(attestationSlotOffset.nanoseconds div 2)
  let
    afterBlockTime = clock.now() + afterBlockDelay
    afterBlockCutoff = clock.fromNow(
      min(afterBlockTime, slot.attestation_deadline() + afterBlockDelay))

  if afterBlockCutoff.inFuture:
    if head.isSome():
      debug "Got block, waiting to send attestations",
            head = shortLog(head.get()), slot = slot,
            afterBlockCutoff = shortLog(afterBlockCutoff.offset)
    else:
      debug "Got block, waiting to send attestations",
            slot = slot, afterBlockCutoff = shortLog(afterBlockCutoff.offset)

    await sleepAsync(afterBlockCutoff.offset)

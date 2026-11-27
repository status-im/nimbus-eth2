# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronos,
  results,
  ../consensus_object_pools/block_dag,
  ../beacon_clock,
  ./validator_pool

export chronos, results, block_dag, beacon_clock

## The validator_duties module contains logic and utilities related to performing
## validator duties that are shared between beacon node and validator client.

type
  RegisteredAttestation* = object
    # A registered attestation is one that has been successfully registered in
    # the slashing protection database and is therefore ready to be signed and
    # sent
    validator*: AttachedValidator
    validator_index*: ValidatorIndex
    committee_index*: CommitteeIndex
    index_in_committee*: uint64
    committee_len*: int
    data*: AttestationData

func toAttestation*(
    registered: RegisteredAttestation, signature: ValidatorSig):
    phase0.Attestation =
  phase0.Attestation.init(
    [registered.index_in_committee], registered.committee_len,
    registered.data, signature).expect("valid data")

func toSingleAttestation*(
    registered: RegisteredAttestation, signature: ValidatorSig): SingleAttestation =
  SingleAttestation(
    committee_index: registered.committee_index.distinctBase,
    attester_index: registered.validator_index.uint64, data: registered.data,
    signature: signature)

proc afterBlockDelay*(
    clock: BeaconClock, slot: Slot, consensusFork: ConsensusFork): Duration =
  ## How long from now the attestations to a block of ``slot`` that just
  ## arrived are held back.
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
  let
    extraDelay =
      if consensusFork == ConsensusFork.Pq:
        # A PQ block carries no payload and is imported in tens of
        # milliseconds. A sixth of the time to the attestation deadline is
        # half a second in a slot of 12: measured on a devnet of 16 nodes, 96%
        # of the other nodes had a block that long after this one did, and 97%
        # a quarter of a second later still.
        nanos(clock.timeParams.attestationSlotOffsetGloas.nanoseconds div 6)
      else:
        nanos(clock.timeParams.attestationSlotOffset.nanoseconds div 2)
    afterBlockCutoff = clock.fromNow(min(
      clock.now(),
      slot.attestation_deadline(clock.timeParams, consensusFork)) + extraDelay)

  if afterBlockCutoff.inFuture:
    afterBlockCutoff.offset
  else:
    ZeroDuration

proc waitAfterBlockCutoff*(clock: BeaconClock, slot: Slot,
                           consensusFork: ConsensusFork,
                           head: Opt[BlockRef] = Opt.none(BlockRef))
                           {.async: (raises: [CancelledError]).} =
  let delay = afterBlockDelay(clock, slot, consensusFork)
  if delay > ZeroDuration:
    if head.isSome():
      debug "Got block, waiting to send attestations",
            head = shortLog(head.get()), slot = slot,
            afterBlockCutoff = shortLog(delay)
    else:
      debug "Got block, waiting to send attestations",
            slot = slot, afterBlockCutoff = shortLog(delay)

    await sleepAsync(delay)

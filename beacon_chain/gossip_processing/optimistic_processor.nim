# beacon_chain
# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, chronos,
  ../spec/forks,
  ../beacon_clock,
  ./gossip_validation

from ./eth2_processor import ValidationRes

export gossip_validation

logScope:
  topics = "gossip_opt"

type
  OptimisticBlockVerifier* = proc(
      signedBlock: ForkedSignedBeaconBlock
    ): Future[void] {.async: (raises: [CancelledError]).}

  OptimisticProcessor* = ref object
    getBeaconTime: GetBeaconTimeFn
    optimisticVerifier: OptimisticBlockVerifier
    processFut: Future[void].Raising([CancelledError])

proc initOptimisticProcessor*(
    getBeaconTime: GetBeaconTimeFn,
    optimisticVerifier: OptimisticBlockVerifier): OptimisticProcessor =
  OptimisticProcessor(
    getBeaconTime: getBeaconTime,
    optimisticVerifier: optimisticVerifier)

proc validateBeaconBlock(
    self: OptimisticProcessor,
    signed_beacon_block: ForkySignedBeaconBlock,
    wallTime: BeaconTime): Result[void, ValidationError] =
  ## Minimally validate a block for potential relevance.
  if not (signed_beacon_block.message.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero):
    return errIgnore("BeaconBlock: slot too high")

  if not signed_beacon_block.message.is_execution_block():
    return errIgnore("BeaconBlock: no execution block")

  ok()

proc processSignedBeaconBlock*(
    self: OptimisticProcessor,
    signedBlock: ForkySignedBeaconBlock): ValidationRes =
  let
    wallTime = self.getBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot()

  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)
    wallSlot

  if not afterGenesis:
    notice "Optimistic block before genesis"
    return errIgnore("Block before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay = wallTime - signedBlock.message.slot.start_beacon_time

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Optimistic block received", delay

  let v = self.validateBeaconBlock(signedBlock, wallTime)
  if v.isErr:
    debug "Dropping optimistic block", error = v.error
    return err(v.error)

  # Only process one block at a time (backpressure)
  trace "Optimistic block validated"
  if self.processFut == nil:
    self.processFut = self.optimisticVerifier(
      ForkedSignedBeaconBlock.init(signedBlock))

    proc handleFinishedProcess(future: pointer) =
      self.processFut = nil

    self.processFut.addCallback(handleFinishedProcess)

  # Block validation is delegated to the sync committee and is done with delay.
  # If we forward invalid spam blocks, we may be disconnected + IP banned,
  # so we avoid accepting any blocks. Since we don't meaningfully contribute
  # to the blocks gossip, we may also accummulate negative peer score over time.
  # However, we are actively contributing to other topics, so some of the
  # negative peer score may be offset through those different topics.
  # The practical impact depends on the actually deployed scoring heuristics.
  return errIgnore("Validation delegated to sync committee")

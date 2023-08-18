# beacon_chain
# Copyright (c) 2019-2023 Status Research & Development GmbH
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

const
  # Maximum `blocks` to cache (not validated; deleted on new optimistic header)
  maxBlocks = 16  # <= `GOSSIP_MAX_SIZE_BELLATRIX` (10 MB) each

  # Minimum interval at which spam is logged
  minLogInterval = chronos.seconds(5)

type
  MsgTrustedBlockProcessor* =
    proc(signedBlock: ForkedMsgTrustedSignedBeaconBlock): Future[void] {.
      gcsafe, raises: [Defect].}

  OptimisticProcessor* = ref object
    getBeaconTime: GetBeaconTimeFn
    optimisticVerifier: MsgTrustedBlockProcessor
    blocks: Table[Eth2Digest, ref ForkedSignedBeaconBlock]
    latestOptimisticSlot: Slot
    processFut: Future[void]
    logMoment: Moment

proc initOptimisticProcessor*(
    getBeaconTime: GetBeaconTimeFn,
    optimisticVerifier: MsgTrustedBlockProcessor): OptimisticProcessor =
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

  if signed_beacon_block.message.slot <= self.latestOptimisticSlot:
    return errIgnore("BeaconBlock: no significant progress")

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

  # Note that validation of blocks is delayed by ~4/3 slots because we have to
  # wait for the sync committee to sign the correct block and for that signature
  # to be included in the next block. Therefore, we skip block validation here
  # and cache the block in memory. Because there is no validation, we have to
  # mitigate against bogus blocks, mostly by bounding the caches. Assuming that
  # any denial-of-service attacks eventually subside, care is taken to recover.
  template logWithSpamProtection(body: untyped): untyped =
    block:
      let now = Moment.now()
      if self.logMoment + minLogInterval <= now:
        logScope: minLogInterval
        body
        self.logMoment = now

  # Store block for later verification
  if not self.blocks.hasKey(signedBlock.root):
    # If `blocks` is full, we got spammed with multiple blocks for a slot,
    # of the optimistic header advancements have been all withheld from us.
    # Whenever the optimistic header advances, old blocks are cleared,
    # so we can simply ignore additional spam blocks until that happens.
    if self.blocks.len >= maxBlocks:
      logWithSpamProtection:
        error "`blocks` full - ignoring", maxBlocks
    else:
      self.blocks[signedBlock.root] =
        newClone(ForkedSignedBeaconBlock.init(signedBlock))

  # Block validation is delegated to the sync committee and is done with delay.
  # If we forward invalid spam blocks, we may be disconnected + IP banned,
  # so we avoid accepting any blocks. Since we don't meaningfully contribute
  # to the blocks gossip, we may also accummulate negative peer score over time.
  # However, we are actively contributing to other topics, so some of the
  # negative peer score may be offset through those different topics.
  # The practical impact depends on the actually deployed scoring heuristics.
  trace "Optimistic block cached"
  return errIgnore("Validation delegated to sync committee")

proc setOptimisticHeader*(
    self: OptimisticProcessor, optimisticHeader: BeaconBlockHeader) =
  # If irrelevant, skip processing
  if optimisticHeader.slot <= self.latestOptimisticSlot:
    return
  self.latestOptimisticSlot = optimisticHeader.slot

  # Delete blocks that are no longer of interest
  let blockRoot = optimisticHeader.hash_tree_root()
  var
    rootsToDelete: seq[Eth2Digest]
    signedBlock: ref ForkedMsgTrustedSignedBeaconBlock
  for root, blck in self.blocks:
    if root == blockRoot:
      signedBlock = blck.asMsgTrusted()
    if blck[].slot <= optimisticHeader.slot:
      rootsToDelete.add root
  for root in rootsToDelete:
    self.blocks.del root

  # Block must be known
  if signedBlock == nil:
    return

  # If a block is already being processed, skip (backpressure)
  if self.processFut != nil:
    return

  self.processFut = self.optimisticVerifier(signedBlock[])

  proc handleFinishedProcess(future: pointer) =
    self.processFut = nil

  self.processFut.addCallback(handleFinishedProcess)

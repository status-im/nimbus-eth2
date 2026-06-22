# beacon_chain
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, chronos,
  ../spec/forks,
  ../el/el_manager,
  ../beacon_clock,
  ./gossip_validation

from ./eth2_processor import ValidationRes

export gossip_validation

logScope:
  topics = "gossip_opt"

type
  LightBlockVerifier* = proc(
      signedBlock: ForkedSignedBeaconBlock
    ): Future[void] {.async: (raises: [CancelledError]).}

  LightEnvelopeVerifier* = proc(
      signedEnvelope: gloas.SignedExecutionPayloadEnvelope
    ): Future[void] {.async: (raises: [CancelledError]).}

  LightBlockProcessor* = ref object
    timeParams: TimeParams
    getBeaconTime: GetBeaconTimeFn
    lightBlockVerifier: LightBlockVerifier
    lightEnvelopeVerifier: LightEnvelopeVerifier
    processFut: Future[void].Raising([CancelledError])

proc initLightBlockProcessor*(
    timeParams: TimeParams,
    getBeaconTime: GetBeaconTimeFn,
    lightBlockVerifier: LightBlockVerifier,
    lightEnvelopeVerifier: LightEnvelopeVerifier): LightBlockProcessor =
  LightBlockProcessor(
    timeParams: timeParams,
    getBeaconTime: getBeaconTime,
    lightBlockVerifier: lightBlockVerifier,
    lightEnvelopeVerifier: lightEnvelopeVerifier)

proc validateBeaconBlock(
    self: LightBlockProcessor,
    signed_beacon_block: ForkySignedBeaconBlock,
    wallTime: BeaconTime): Result[void, ValidationError] =
  ## Minimally validate a block for potential relevance.
  if not (signed_beacon_block.message.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(self.timeParams)):
    return errIgnore("BeaconBlock: slot too high")

  if not signed_beacon_block.message.is_execution_block():
    return errIgnore("BeaconBlock: no execution block")

  ok()

proc processSignedBeaconBlock*(
    self: LightBlockProcessor,
    signedBlock: ForkySignedBeaconBlock): ValidationRes =
  let
    wallTime = self.getBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.timeParams)

  logScope:
    blockRoot = shortLog(signedBlock.root)
    blck = shortLog(signedBlock.message)
    signature = shortLog(signedBlock.signature)
    wallSlot

  if not afterGenesis:
    notice "Light client block before genesis"
    return errIgnore("Block before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay =
    wallTime - signedBlock.message.slot.start_beacon_time(self.timeParams)

  # Start of block processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Light client block received", delay

  let v = self.validateBeaconBlock(signedBlock, wallTime)
  if v.isErr:
    debug "Dropping light client block", error = v.error
    return err(v.error)

  # Only process one block at a time (backpressure)
  trace "Light client block validated"
  if self.processFut == nil:
    self.processFut = self.lightBlockVerifier(
      ForkedSignedBeaconBlock.init(signedBlock))

    proc handleFinishedProcess(future: pointer) =
      self.processFut = nil

    self.processFut.addCallback(handleFinishedProcess)

  # Block validation is delegated to the sync committee and is done with delay.
  # If we forward invalid spam blocks, we may be disconnected + IP banned,
  # so we avoid accepting any blocks. Since we don't meaningfully contribute
  # to the blocks gossip, we may also accumulate negative peer score over time.
  # However, we are actively contributing to other topics, so some of the
  # negative peer score may be offset through those different topics.
  # The practical impact depends on the actually deployed scoring heuristics.
  return errIgnore("Validation delegated to sync committee")

proc newExecutionPayload*(
    elManager: ELManager,
    envelope: gloas.ExecutionPayloadEnvelope
): Future[Opt[PayloadExecutionStatus]] {.async: (raises: [CancelledError]).} =
  debug "newPayload: inserting envelope into execution engine",
    payload = shortLog(envelope.payload)

  let payloadStatus = ? await elManager.newPayload(
    envelope, sleepAsync(NEWPAYLOAD_TIMEOUT), retry = true)

  debug "newPayload: succeeded",
    parentHash = envelope.payload.parent_hash,
    blockHash = envelope.payload.block_hash,
    blockNumber = envelope.payload.block_number,
    payloadStatus = payloadStatus

  Opt.some payloadStatus

proc validateExecutionPayload(
    self: LightBlockProcessor,
    signed_execution_payload_envelope: SignedExecutionPayloadEnvelope,
    wallTime: BeaconTime): Result[void, ValidationError] =
  ## Minimally validate an envelope for potential relevance.
  template envelope: untyped = signed_execution_payload_envelope.message
  if not (envelope.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero(self.timeParams)):
    return errIgnore("ExecutionPayload: slot too high")

  if envelope.payload.block_hash.isZero:
    return errIgnore("ExecutionPayload: no execution block")

  ok()

proc processExecutionPayloadEnvelope*(
    self: LightBlockProcessor,
    signedEnvelope: gloas.SignedExecutionPayloadEnvelope): ValidationRes =
  let
    wallTime = self.getBeaconTime()
    (afterGenesis, wallSlot) = wallTime.toSlot(self.timeParams)

  logScope:
    blockRoot = shortLog(signedEnvelope.message.beacon_block_root)
    payload = shortLog(signedEnvelope.message.payload)
    signature = shortLog(signedEnvelope.signature)
    wallSlot

  if not afterGenesis:
    notice "Light client envelope before genesis"
    return errIgnore("Envelope before genesis")

  # Potential under/overflows are fine; would just create odd metrics and logs
  let delay =
    wallTime - signedEnvelope.message.slot.start_beacon_time(self.timeParams)

  # Start of envelope processing - in reality, we have already gone through SSZ
  # decoding at this stage, which may be significant
  debug "Light client envelope received", delay

  let v = self.validateExecutionPayload(signedEnvelope, wallTime)
  if v.isErr:
    debug "Dropping light client envelope", error = v.error
    return err(v.error)

  # Only process one envelope at a time (backpressure)
  trace "Light client envelope validated"
  if self.processFut == nil:
    self.processFut = self.lightEnvelopeVerifier(signedEnvelope)

    proc handleFinishedProcess(future: pointer) =
      self.processFut = nil

    self.processFut.addCallback(handleFinishedProcess)

  return errIgnore("Validation delegated to sync committee")

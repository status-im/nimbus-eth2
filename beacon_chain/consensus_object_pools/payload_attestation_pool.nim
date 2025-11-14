# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Status libraries
  metrics,
  chronicles,
  # Internal
  ../spec/[eth2_merkleization, forks, validator],
  "."/[spec_cache, blockchain_dag],
  ../beacon_clock

from ../spec/beaconstate import get_ptc

logScope: topics = "payattpool"

declareGauge payload_attestation_pool_block_packing_time,
  "Time it took to create list of payload attestations for block"

type
  PayloadAttestationEntry = object
    data: PayloadAttestationData
    messages: Table[ValidatorIndex, PayloadAttestationMessage]
    aggregated: Opt[PayloadAttestation]

  PayloadAttestationPool* = object
    dag*: ChainDAGRef
    attestations: Table[Slot, Table[Eth2Digest, PayloadAttestationEntry]]

proc init*(T: type PayloadAttestationPool, dag: ChainDAGRef): T =
  T(dag: dag)

func pruneOldEntries(pool: var PayloadAttestationPool, wallTime: BeaconTime) =
  let current_slot = wallTime.slotOrZero(pool.dag.timeParams)

  # keep only recent slots - since payload attestations
  # are only valid for 1 slot
  var slotsToRemove: seq[Slot]
  for slot in pool.attestations.keys:
    if slot + 2 < current_slot:
      slotsToRemove.add(slot)

  for slot in slotsToRemove:
    pool.attestations.del(slot)

proc addPayloadAttestation*(
    pool: var PayloadAttestationPool, message: PayloadAttestationMessage,
    wallTime: BeaconTime): bool =
  let
    slot = message.data.slot
    beacon_block_root = message.data.beacon_block_root
    validator_index = message.validator_index

  pool.pruneOldEntries(wallTime)

  # create an entry for this block and slot
  let
    slotEntries = addr pool.attestations.mgetOrPut(
      slot, initTable[Eth2Digest, PayloadAttestationEntry]())
    entry = addr slotEntries[].mgetOrPut(
      beacon_block_root, PayloadAttestationEntry(data: message.data))

  # Check for duplicate
  let vidx = ValidatorIndex(validator_index)
  if vidx in entry[].messages:
    return false

  entry[].messages[vidx] = message

  entry[].aggregated = Opt.none(PayloadAttestation)

  true

func findAllPtcPositions(
    ptc: seq[ValidatorIndex], validator_index: ValidatorIndex
): seq[int] =
  # Find all positions where validator appears in the PTC
  var positions: seq[int]
  for i, ptc_member in ptc:
    if ptc_member == validator_index:
      positions.add(i)
  positions

proc aggregateMessages(
    pool: PayloadAttestationPool, slot: Slot,
    entry: ptr PayloadAttestationEntry, cache: var StateCache
): Opt[PayloadAttestation] =
  ## Aggregate individual messages into a single PayloadAttestation

  if entry[].messages.len == 0:
    return Opt.none(PayloadAttestation)

  withState(pool.dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      var ptc = newSeqOfCap[ValidatorIndex](PTC_SIZE)
      for validator_index in get_ptc(forkyState.data, slot, cache):
        ptc.add(validator_index)

      var
        aggregation_bits = BitArray[int(PTC_SIZE)].init()
        signatures: seq[CookedSig]

      for validator_index, message in entry.messages:
        # Find all positions where this validator appears in PTC,
        # a single member might appear multiple times in a committee
        let ptc_positions = findAllPtcPositions(ptc, validator_index)

        let cookedSig = message.signature.load().valueOr:
          continue

        # set the aggregation bits and add the signature for each position
        for ptc_index in ptc_positions:
          aggregation_bits[ptc_index] = true
          signatures.add(cookedSig)

      if signatures.len == 0:
        return Opt.none(PayloadAttestation)

      var aggregated_signature = AggregateSignature.init(signatures[0])
      for i in 1..<signatures.len:
        aggregated_signature.aggregate(signatures[i])

      return Opt.some(PayloadAttestation(
        aggregation_bits: aggregation_bits,
        data: entry.data,
        signature: aggregated_signature.finish().toValidatorSig()
      ))
    else:
      return Opt.none(PayloadAttestation)

proc getAggregatedPayloadAttestation*(
    pool: var PayloadAttestationPool, slot: Slot,
    beacon_block_root: Eth2Digest, cache: var StateCache
): Opt[PayloadAttestation] =
  ## Get aggregated payload attestation for a specific block and slot

  pool.attestations.withValue(slot, slotEntries):
    slotEntries[].withValue(beacon_block_root, entry):
      if entry[].aggregated.isNone():
        entry[].aggregated = pool.aggregateMessages(slot, entry, cache)
      return entry[].aggregated

  Opt.none(PayloadAttestation)

proc getPayloadAttestationsForBlock*(
    pool: var PayloadAttestationPool, target_slot: Slot,
    cache: var StateCache): seq[PayloadAttestation] =
  ## Get payload attestations to include in a block for a target slot
  let startPackingTick = Moment.now()

  if target_slot == 0:
    return @[]

  let attestation_slot = target_slot - 1
  var
    payload_attestations: seq[PayloadAttestation]
    totalCandidates = 0

  if attestation_slot notin pool.attestations:
    return @[]

  pool.attestations.withValue(attestation_slot, slotEntries):
    for beacon_block_root, entry in slotEntries[]:
      totalCandidates += 1
      let aggregated =
        pool.getAggregatedPayloadAttestation(
          attestation_slot, beacon_block_root, cache)
      if aggregated.isSome():
        payload_attestations.add(aggregated.get())

        if payload_attestations.len >= MAX_PAYLOAD_ATTESTATIONS.int:
          break

  let packingDur = Moment.now() - startPackingTick

  debug "Packed payload attestations for block",
    target_slot = target_slot, attestation_slot = attestation_slot,
    packingDur = packingDur, totalCandidates = totalCandidates,
    payload_attestations = payload_attestations.len()

  payload_attestation_pool_block_packing_time.set(packingDur.toFloatSeconds())

  payload_attestations

# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
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
  PayloadAttestationEntry* = object
    data*: PayloadAttestationData
    messages*: Table[ValidatorIndex, PayloadAttestationMessage]
    aggregated*: Opt[PayloadAttestation]

  PayloadAttestationPool* = object
    dag*: ChainDAGRef
    attestations*: Table[Slot,
      Table[(Eth2Digest, bool, bool), PayloadAttestationEntry]]

func init*(T: type PayloadAttestationPool, dag: ChainDAGRef): T =
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

func addPayloadAttestation*(
    pool: var PayloadAttestationPool, message: PayloadAttestationMessage,
    wallTime: BeaconTime): bool =
  template beacon_block_root: untyped = message.data.beacon_block_root

  let
    slot = message.data.slot
    validator_index = message.validator_index
    key = (beacon_block_root,
           message.data.payload_present,
           message.data.blob_data_available)

  pool.pruneOldEntries(wallTime)

  # create an entry for this attestation data
  let
    entry = addr pool.attestations.mgetOrPut(slot).mgetOrPut(
      key, PayloadAttestationEntry(data: message.data))

  # Check for duplicate
  let vidx = ValidatorIndex(validator_index)
  if vidx in entry[].messages:
    return false

  entry[].messages[vidx] = message

  entry[].aggregated = Opt.none(PayloadAttestation)

  true

func aggregateMessages(
    pool: PayloadAttestationPool, slot: Slot,
    entry: var PayloadAttestationEntry): Opt[PayloadAttestation] =
  if entry.messages.len == 0:
    return Opt.none(PayloadAttestation)

  withState(pool.dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      var
        aggregation_bits: BitArray[int(PTC_SIZE)]
        signatures: seq[CookedSig]
        ptc_index = 0

      for ptc_validator_index in get_ptc(forkyState.data, slot):
        entry.messages.withValue(ptc_validator_index, message):
          let cookedSig = message[].signature.load().valueOr:
            continue
          aggregation_bits[ptc_index] = true
          signatures.add(cookedSig)
        ptc_index += 1

      if signatures.len == 0:
        return Opt.none(PayloadAttestation)

      var aggregated_signature = AggregateSignature.init(signatures[0])
      for i in 1..<signatures.len:
        aggregated_signature.aggregate(signatures[i])

      Opt.some(PayloadAttestation(
        aggregation_bits: aggregation_bits,
        data: entry.data,
        signature: aggregated_signature.finish().toValidatorSig()
      ))
    else:
      Opt.none(PayloadAttestation)

func getAggregatedPayloadAttestation*(
    pool: var PayloadAttestationPool, slot: Slot,
    key: (Eth2Digest, bool, bool)): Opt[PayloadAttestation] =
  ## Get aggregated payload attestation for a specific attestation data

  pool.attestations.withValue(slot, slotEntries):
    slotEntries[].withValue(key, entry):
      if entry[].aggregated.isNone():
        entry[].aggregated = pool.aggregateMessages(slot, entry[])
      return entry[].aggregated

  Opt.none(PayloadAttestation)

proc getPayloadAttestationsForBlock*(
    pool: var PayloadAttestationPool, target_slot: Slot
): seq[PayloadAttestation] =
  ## Get payload attestations to include in a block for a target slot
  let startPackingTick = Moment.now()

  if target_slot == 0:
    return @[]

  let attestation_slot = target_slot - 1

  if attestation_slot notin pool.attestations:
    return @[]

  var
    payload_attestations: seq[PayloadAttestation]
    totalCandidates = 0

  pool.attestations.withValue(attestation_slot, slotEntries):
    for key, entry in slotEntries[]:
      totalCandidates += 1
      let aggregated =
        pool.getAggregatedPayloadAttestation(attestation_slot, key)
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

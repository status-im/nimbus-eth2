# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  results,
  chronicles,
  ../spec/[beaconstate, helpers, signatures, validator],
  ../spec/datatypes/base,
  ./block_pools_types, blockchain_dag

from std/sequtils import anyIt
from ../spec/datatypes/electra import shortLog
from ../spec/network import compute_subnet_for_attestation

export
  base, block_pools_types, results

logScope: topics = "spec_cache"

# Spec functions implemented based on cached values instead of the full state
func count_active_validators*(shufflingRef: ShufflingRef): uint64 =
  shufflingRef.shuffled_active_validator_indices.lenu64

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#get_committee_count_per_slot
func get_committee_count_per_slot*(shufflingRef: ShufflingRef): uint64 =
  get_committee_count_per_slot(count_active_validators(shufflingRef))

iterator get_committee_indices*(shufflingRef: ShufflingRef): CommitteeIndex =
  let committees_per_slot = get_committee_count_per_slot(shufflingRef)
  for committee_index in get_committee_indices(committees_per_slot):
    yield committee_index

func get_committee_index*(shufflingRef: ShufflingRef, index: uint64):
    Result[CommitteeIndex, cstring] =
  check_attestation_index(index, get_committee_count_per_slot(shufflingRef))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_beacon_committee
iterator get_beacon_committee*(
    shufflingRef: ShufflingRef, slot: Slot, committee_index: CommitteeIndex):
    (int, ValidatorIndex) =
  ## Return the beacon committee at ``slot`` for ``index``.
  doAssert slot.epoch == shufflingRef.epoch
  let committees_per_slot = get_committee_count_per_slot(shufflingRef)
  for index_in_committee, idx in compute_committee(
    shufflingRef.shuffled_active_validator_indices,
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot + committee_index.asUInt64,
    committees_per_slot * SLOTS_PER_EPOCH
  ): yield (index_in_committee, idx)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee*(
    shufflingRef: ShufflingRef, slot: Slot, committee_index: CommitteeIndex):
    seq[ValidatorIndex] =
  ## Return the beacon committee at ``slot`` for ``index``.
  doAssert slot.epoch == shufflingRef.epoch
  let committees_per_slot = get_committee_count_per_slot(shufflingRef)
  compute_committee(
    shufflingRef.shuffled_active_validator_indices,
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot + committee_index.asUInt64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee_len*(
    shufflingRef: ShufflingRef, slot: Slot, committee_index: CommitteeIndex): uint64 =
  ## Return the number of members in the beacon committee at ``slot`` for ``index``.
  doAssert slot.epoch == shufflingRef.epoch
  let committees_per_slot = get_committee_count_per_slot(shufflingRef)
  compute_committee_len(
    count_active_validators(shufflingRef),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot + committee_index.asUInt64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#get_attesting_indices
iterator get_attesting_indices*(
    shufflingRef: ShufflingRef,
    slot: Slot,
    index: CommitteeIndex,
    aggregation_bits: CommitteeValidatorsBits,
): ValidatorIndex =
  if slot.epoch == shufflingRef.epoch and
      aggregation_bits.lenu64 == get_beacon_committee_len(shufflingRef, slot, index):
    for index_in_committee, validator_index in get_beacon_committee(
      shufflingRef, slot, index
    ):
      if aggregation_bits[index_in_committee]:
        yield validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/electra/beacon-chain.md#modified-get_attesting_indices
iterator get_attesting_indices*(
    shufflingRef: ShufflingRef,
    slot: Slot,
    committee_bits: AttestationCommitteeBits,
    aggregation_bits: AggregationBits,
): ValidatorIndex =
  if slot.epoch == shufflingRef.epoch:
    var committee_offset = 0
    for index in get_committee_indices(committee_bits):
      let committee_len = get_beacon_committee_len(shufflingRef, slot, index).int
      if aggregation_bits.len < committee_offset + committee_len:
        # Would overflow, invalid attestation caught in check_attestation()
        break

      for i, attester_index in get_beacon_committee(shufflingRef, slot, index):
        if aggregation_bits[committee_offset + i]:
          yield attester_index

      committee_offset += committee_len

func get_attesting_indices*(
    shufflingRef: ShufflingRef,
    slot: Slot,
    committee_bits: AttestationCommitteeBits,
    aggregation_bits: AggregationBits,
): seq[ValidatorIndex] =
  for vidx in shufflingRef.get_attesting_indices(slot, committee_bits, aggregation_bits):
    result.add vidx

iterator get_attesting_indices*(
    shufflingRef: ShufflingRef,
    attestation: phase0.Attestation | phase0.TrustedAttestation,
): ValidatorIndex =
  block iter:
    let index = shufflingRef.get_committee_index(attestation.data.index).valueOr:
      break iter
    for vidx in shufflingRef.get_attesting_indices(
      attestation.data.slot, index, attestation.aggregation_bits
    ):
      yield vidx

iterator get_attesting_indices*(
    shufflingRef: ShufflingRef,
    attestation: electra.Attestation | electra.TrustedAttestation,
): ValidatorIndex =
  for vidx in shufflingRef.get_attesting_indices(
    attestation.data.slot, attestation.committee_bits, attestation.aggregation_bits
  ):
    yield vidx

iterator get_attesting_indices*(
    dag: ChainDAGRef,
    attestation:
      phase0.Attestation | phase0.TrustedAttestation | electra.Attestation |
      electra.TrustedAttestation,
): ValidatorIndex =
  ## Iterate over the attesting indices based on the target of the attestation -
  ## looks up the shuffling based on the attestation target which in the case
  ## of attestations in a block may differ from the shuffling of the block slot
  block gaiBlock: # `return` is not allowed in an inline iterator
    let
      slot =
        check_attestation_slot_target(attestation.data).valueOr:
          warn "Invalid attestation slot in trusted attestation",
            attestation = shortLog(attestation)
          doAssert strictVerification notin dag.updateFlags
          break gaiBlock
      blck =
        dag.getBlockRef(attestation.data.beacon_block_root).valueOr:
          # Attestation block unknown - this is fairly common because we
          # discard alternative histories on restart
          debug "Pruned block in trusted attestation",
            attestation = shortLog(attestation)
          break gaiBlock
      shufflingRef =
        dag.getShufflingRef(blck, slot.epoch, false).valueOr:
          warn "Attestation shuffling not found",
            blck = shortLog(blck),
            attestation = shortLog(attestation)

          doAssert strictVerification notin dag.updateFlags
          break gaiBlock

    for vidx in shufflingRef.get_attesting_indices(attestation):
      yield vidx

func makeAttestationData*(
    epochRef: EpochRef, bs: BlockSlot,
    committee_index: CommitteeIndex): AttestationData =
  ## Create an attestation / vote for the block `bs` using the
  ## data in `epochRef` to fill in the rest of the fields.
  ## `epochRef` is the epoch information corresponding to the `bs` advanced to
  ## the slot we're attesting to.

  let
    slot = bs.slot
    current_epoch = slot.epoch()
    epoch_boundary_slot = current_epoch.start_slot()
    epoch_boundary_block = bs.blck.atSlot(epoch_boundary_slot)

  doAssert current_epoch == epochRef.epoch

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index.asUInt64,
    beacon_block_root: bs.blck.root,
    source: epochRef.checkpoints.justified,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block.blck.root))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/validator.md#validator-assignments
iterator get_committee_assignments*(
    shufflingRef: ShufflingRef, validator_indices: HashSet[ValidatorIndex]):
    tuple[committee_index: CommitteeIndex,
      subnet_id: SubnetId, slot: Slot] =
  let
    committees_per_slot = get_committee_count_per_slot(shufflingRef)
    epoch = shufflingRef.epoch

  for slot in epoch.slots():
    for committee_index in get_committee_indices(committees_per_slot):
      if anyIt(get_beacon_committee(shufflingRef, slot, committee_index), it in validator_indices):
        yield (
          committee_index,
          compute_subnet_for_attestation(committees_per_slot, slot, committee_index),
          slot)

func is_aggregator*(shufflingRef: ShufflingRef, slot: Slot,
  index: CommitteeIndex, slot_signature: ValidatorSig): bool =
  let
    committee_len = get_beacon_committee_len(shufflingRef, slot, index)
  return is_aggregator(committee_len, slot_signature)

iterator get_ptc*(
  state: gloas.BeaconState | heze.BeaconState,
  shufflingRef: ShufflingRef, slot: Slot):
    ValidatorIndex {.closure.} =
  let epoch = slot.epoch()
  var buffer {.noinit.}: array[40, byte]
  buffer[0..31] = get_seed(state, epoch, DOMAIN_PTC_ATTESTER).data
  buffer[32..39] = uint_to_bytes(slot.uint64)
  let seed = eth2digest(buffer)

  var indices = newSeqOfCap[ValidatorIndex](PTC_SIZE)

  let committees_per_slot = get_committee_count_per_slot(shufflingRef)
  for committee_index in get_committee_indices(committees_per_slot):
    let committee = get_beacon_committee(shufflingRef, slot, committee_index)
    indices.add(committee)

  for candidate_index in compute_balance_weighted_selection(
      state, indices, seed, size=PTC_SIZE, shuffle_indices=false):
    yield candidate_index

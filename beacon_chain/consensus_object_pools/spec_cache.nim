# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/sequtils,
  stew/results,
  chronicles,
  ../extras,
  ../spec/[beaconstate, helpers, network, signatures, validator],
  ../spec/datatypes/base,
  ./block_pools_types, blockchain_dag

export
  base, extras, block_pools_types, results

logScope: topics = "spec_cache"

# Spec functions implemented based on cached values instead of the full state
func count_active_validators*(shufflingRef: ShufflingRef): uint64 =
  shufflingRef.shuffled_active_validator_indices.lenu64

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_committee_count_per_slot
func get_committee_count_per_slot*(shufflingRef: ShufflingRef): uint64 =
  get_committee_count_per_slot(count_active_validators(shufflingRef))

iterator get_committee_indices*(shufflingRef: ShufflingRef): CommitteeIndex =
  let committees_per_slot = get_committee_count_per_slot(shufflingRef)
  for committee_index in get_committee_indices(committees_per_slot):
    yield committee_index

func get_committee_index*(shufflingRef: ShufflingRef, index: uint64):
    Result[CommitteeIndex, cstring] =
  check_attestation_index(index, get_committee_count_per_slot(shufflingRef))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_committee
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_committee
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_beacon_committee
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_attesting_indices
func compatible_with_shuffling*(
    bits: CommitteeValidatorsBits,
    shufflingRef: ShufflingRef,
    slot: Slot,
    committee_index: CommitteeIndex): bool =
  bits.lenu64 == get_beacon_committee_len(shufflingRef, slot, committee_index)

iterator get_attesting_indices*(shufflingRef: ShufflingRef,
                                slot: Slot,
                                committee_index: CommitteeIndex,
                                bits: CommitteeValidatorsBits):
                                  ValidatorIndex =
  if not bits.compatible_with_shuffling(shufflingRef, slot, committee_index):
    trace "get_attesting_indices: inconsistent aggregation and committee length"
  else:
    for index_in_committee, validator_index in get_beacon_committee(
        shufflingRef, slot, committee_index):
      if bits[index_in_committee]:
        yield validator_index

iterator get_attesting_indices*(
    dag: ChainDAGRef, attestation: TrustedAttestation): ValidatorIndex =
  block: # `return` is not allowed in an inline iterator
    let
      slot =
        check_attestation_slot_target(attestation.data).valueOr:
          warn "Invalid attestation slot in trusted attestation",
            attestation = shortLog(attestation)
          doAssert strictVerification notin dag.updateFlags
          break
      blck =
        dag.getBlockRef(attestation.data.beacon_block_root).valueOr:
          # Attestation block unknown - this is fairly common because we
          # discard alternative histories on restart
          debug "Pruned block in trusted attestation",
            attestation = shortLog(attestation)
          break
      target =
        blck.atCheckpoint(attestation.data.target).valueOr:
          # This may happen when there's no block at the epoch boundary slot
          # leading to the case where the attestation block root is the
          # finalized head (exists as BlockRef) but its target vote has
          # already been pruned
          notice "Pruned target in trusted attestation",
            blck = shortLog(blck),
            attestation = shortLog(attestation)
          doAssert strictVerification notin dag.updateFlags
          break
      shufflingRef =
        dag.getShufflingRef(target.blck, target.slot.epoch, false).valueOr:
          warn "Attestation shuffling not found",
            blck = shortLog(blck),
            attestation = shortLog(attestation)

          doAssert strictVerification notin dag.updateFlags
          break

      committeesPerSlot = get_committee_count_per_slot(shufflingRef)
      committeeIndex =
        CommitteeIndex.init(attestation.data.index, committeesPerSlot).valueOr:
          warn "Unexpected committee index in trusted attestation",
            blck = shortLog(blck),
            attestation = shortLog(attestation)

          doAssert strictVerification notin dag.updateFlags
          break

    for validator in get_attesting_indices(
        shufflingRef, slot, committeeIndex, attestation.aggregation_bits):
      yield validator

func get_attesting_indices_one*(shufflingRef: ShufflingRef,
                                slot: Slot,
                                committee_index: CommitteeIndex,
                                bits: CommitteeValidatorsBits):
                                  Option[ValidatorIndex] =
  # A variation on get_attesting_indices that returns the validator index only
  # if only one validator index is set
  var res = none(ValidatorIndex)
  for validator_index in get_attesting_indices(
      shufflingRef, slot, committee_index, bits):
    if res.isSome(): return none(ValidatorIndex)
    res = some(validator_index)
  res

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(shufflingRef: ShufflingRef,
                            slot: Slot,
                            committee_index: CommitteeIndex,
                            bits: CommitteeValidatorsBits):
                              seq[ValidatorIndex] =
  # TODO sequtils2 mapIt
  for idx in get_attesting_indices(shufflingRef, slot, committee_index, bits):
    result.add(idx)

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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index.asUInt64,
    beacon_block_root: bs.blck.root,
    source: epochRef.checkpoints.justified,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block.blck.root))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#validator-assignments
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

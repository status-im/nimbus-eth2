# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/sequtils,
  chronicles,
  ../extras,
  ../spec/[helpers, network, signatures, validator],
  ../spec/datatypes/base,
  ./block_pools_types, blockchain_dag

export
  base, extras, block_pools_types

# Spec functions implemented based on cached values instead of the full state
func count_active_validators*(epochInfo: EpochRef): uint64 =
  epochInfo.shuffled_active_validator_indices.lenu64

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_committee_count_per_slot
func get_committee_count_per_slot*(epochInfo: EpochRef): uint64 =
  get_committee_count_per_slot(count_active_validators(epochInfo))

iterator get_committee_indices*(epochRef: EpochRef): CommitteeIndex =
  for i in 0'u64..<get_committee_count_per_slot(epochRef):
    yield CommitteeIndex(i)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_beacon_committee
iterator get_beacon_committee*(
    epochRef: EpochRef, slot: Slot, index: CommitteeIndex): ValidatorIndex =
  ## Return the beacon committee at ``slot`` for ``index``.
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)
  for idx in compute_committee(
    epochRef.shuffled_active_validator_indices,
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  ): yield idx

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee*(
    epochRef: EpochRef, slot: Slot, index: CommitteeIndex): seq[ValidatorIndex] =
  ## Return the beacon committee at ``slot`` for ``index``.
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)
  compute_committee(
    epochRef.shuffled_active_validator_indices,
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_beacon_committee
func get_beacon_committee_len*(
    epochRef: EpochRef, slot: Slot, index: CommitteeIndex): uint64 =
  ## Return the number of members in the beacon committee at ``slot`` for ``index``.
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)

  compute_committee_len(
    count_active_validators(epochRef),
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_attesting_indices
iterator get_attesting_indices*(epochRef: EpochRef,
                                data: AttestationData,
                                bits: CommitteeValidatorsBits):
                                  ValidatorIndex =
  if bits.lenu64 != get_beacon_committee_len(epochRef, data.slot, data.index.CommitteeIndex):
    trace "get_attesting_indices: inconsistent aggregation and committee length"
  else:
    var i = 0
    for index in get_beacon_committee(epochRef, data.slot, data.index.CommitteeIndex):
      if bits[i]:
        yield index
      inc i

func get_attesting_indices_one*(epochRef: EpochRef,
                                data: AttestationData,
                                bits: CommitteeValidatorsBits):
                                  Option[ValidatorIndex] =
  # A variation on get_attesting_indices that returns the validator index only
  # if only one validator index is set
  if bits.lenu64 != get_beacon_committee_len(epochRef, data.slot, data.index.CommitteeIndex):
    trace "get_attesting_indices: inconsistent aggregation and committee length"
    none(ValidatorIndex)
  else:
    var res = none(ValidatorIndex)
    var i = 0
    for index in get_beacon_committee(epochRef, data.slot, data.index.CommitteeIndex):
      if bits[i]:
        if res.isNone():
          res = some(index)
        else:
          return none(ValidatorIndex)
      inc i
    res

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(epochRef: EpochRef,
                            data: AttestationData,
                            bits: CommitteeValidatorsBits):
                              seq[ValidatorIndex] =
  # TODO sequtils2 mapIt
  for idx in get_attesting_indices(epochRef, data, bits):
    result.add(idx)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/beacon-chain.md#is_valid_indexed_attestation
proc is_valid_indexed_attestation*(
    fork: Fork, genesis_validators_root: Eth2Digest,
    epochRef: EpochRef,
    attestation: SomeAttestation, flags: UpdateFlags): Result[void, cstring] =
  # This is a variation on `is_valid_indexed_attestation` that works directly
  # with an attestation instead of first constructing an `IndexedAttestation`
  # and then validating it - for the purpose of validating the signature, the
  # order doesn't matter and we can proceed straight to validating the
  # signature instead
  let sigs = attestation.aggregation_bits.countOnes()
  if sigs == 0:
    return err("is_valid_indexed_attestation: no attesting indices")

  # Verify aggregate signature
  if not (skipBLSValidation in flags or attestation.signature is TrustedSig):
    var
      pubkeys = newSeqOfCap[CookedPubKey](sigs)
    for index in get_attesting_indices(
        epochRef, attestation.data, attestation.aggregation_bits):
      pubkeys.add(epochRef.validatorKey(index).get())

    if not verify_attestation_signature(
        fork, genesis_validators_root, attestation.data,
        pubkeys, attestation.signature):
      return err("is_valid_indexed_attestation: signature verification failure")

  ok()

func makeAttestationData*(
    epochRef: EpochRef, bs: BlockSlot,
    committee_index: CommitteeIndex): AttestationData =
  ## Create an attestation / vote for the block `bs` using the
  ## data in `epochRef` to fill in the rest of the fields.
  ## `epochRef` is the epoch information corresponding to the `bs` advanced to
  ## the slot we're attesting to.

  let
    slot = bs.slot
    current_epoch = slot.compute_epoch_at_slot()
    epoch_boundary_slot = compute_start_slot_at_epoch(current_epoch)
    epoch_boundary_block = bs.blck.atSlot(epoch_boundary_slot)

  doAssert current_epoch == epochRef.epoch

  # https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/validator.md#attestation-data
  AttestationData(
    slot: slot,
    index: committee_index.uint64,
    beacon_block_root: bs.blck.root,
    source: epochRef.current_justified_checkpoint,
    target: Checkpoint(
      epoch: current_epoch,
      root: epoch_boundary_block.blck.root
    )
  )

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/phase0/validator.md#validator-assignments
iterator get_committee_assignments*(
    epochRef: EpochRef, validator_indices: HashSet[ValidatorIndex]):
    tuple[committeeIndex: CommitteeIndex,
      subnet_id: SubnetId, slot: Slot] =
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)
    epoch = epochRef.epoch
    start_slot = compute_start_slot_at_epoch(epoch)

  for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
    for index in 0'u64 ..< committees_per_slot:
      let
        idx = index.CommitteeIndex
      if anyIt(
          get_beacon_committee(epochRef, slot, idx), it in validator_indices):
        yield (
          idx,
          compute_subnet_for_attestation(committees_per_slot, slot, idx),
          slot)

func is_aggregator*(epochRef: EpochRef, slot: Slot, index: CommitteeIndex,
    slot_signature: ValidatorSig): bool =
  let
    committee_len = get_beacon_committee_len(epochRef, slot, index)
  return is_aggregator(committee_len, slot_signature)
